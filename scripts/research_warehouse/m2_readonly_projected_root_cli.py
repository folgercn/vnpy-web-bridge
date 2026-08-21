"""Root-only issuer for one Docker named-volume read-only projection receipt."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from .canonical import canonical_json_line, sha256
from .errors import RegistryError
from .m2_isolation_contracts import load_isolation_policy
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import (
    BACKUP_SIGNER_KEY_ID,
    DEFAULT_BACKUP_PRIVATE_KEY,
    DEFAULT_CUSTODY_TRANSITION_RECEIPT,
    DEFAULT_READONLY_PROJECTED_ROOT_ATTESTATION,
)
from .m2_operator_state import _atomic_root_write
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .m2_signer_handoff import run_with_preloaded_private_key
from .readonly_projected_root import build_readonly_projected_root_attestation
from .signing import public_key_sha256

_VOLUME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}$")
_MAX_PROBE_BYTES = 4096


def _require_root() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RegistryError("projected root attestor must start as root")


def _probe_projection(*, image: str, volume: str, root: Path) -> os.stat_result:
    """Read stat through a bounded, no-network/no-socket container only."""
    if _VOLUME.fullmatch(volume) is None or _IMAGE.fullmatch(image) is None:
        raise RegistryError("projected root probe input is unsafe")
    if not root.is_absolute() or str(root) != os.path.normpath(str(root)):
        raise RegistryError("projected root path is unsafe")
    code = (
        "import json,os,stat; p=" + repr(str(root)) + "; s=os.lstat(p); "
        "print(json.dumps({'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,"
        "'mode':stat.S_IMODE(s.st_mode),'dir':stat.S_ISDIR(s.st_mode)},separators=(',',':')))"
    )
    completed = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--mount",
         f"type=volume,src={volume},dst={root},readonly", image, "python", "-c", code],
        check=False, capture_output=True, timeout=20,
    )
    if completed.returncode != 0 or len(completed.stdout) > _MAX_PROBE_BYTES:
        raise RegistryError("projected root Docker probe failed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError("projected root Docker probe is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"dev", "ino", "uid", "gid", "mode", "dir"}:
        raise RegistryError("projected root Docker probe schema mismatch")
    if value["dir"] is not True or any(
        not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0
        for key in ("dev", "ino", "uid", "gid", "mode")
    ):
        raise RegistryError("projected root Docker probe values are invalid")
    return SimpleNamespace(
        st_dev=value["dev"], st_ino=value["ino"], st_uid=value["uid"],
        st_gid=value["gid"], st_mode=stat.S_IFDIR | value["mode"],
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sign one read-only Docker Research root projection")
    parser.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--projection-volume", required=True)
    return parser


def run(args: argparse.Namespace) -> dict[str, str]:
    _require_root()
    if DEFAULT_READONLY_PROJECTED_ROOT_ATTESTATION.exists():
        raise RegistryError("projected root attestation already exists; refusing to re-sign")
    policy = load_isolation_policy(args.runtime_input.parent / "isolation-policy-v1.json")
    custody_root = Path(policy.payload["custody_root"])
    observed = _probe_projection(image=args.runner_image, volume=args.projection_volume, root=custody_root)

    def sign(private_key):
        # The existing signer handoff drops permanently to the evidence owner
        # before this callback; only that identity can open the private root.
        context = load_runtime_context(args.runtime_input)
        if context.paths.custody_transition is None or not DEFAULT_CUSTODY_TRANSITION_RECEIPT.exists():
            raise RegistryError("physical custody transition trust is unavailable")
        if public_key_sha256(private_key.public_key()) != context.runtime_input.payload["expected_backup_public_key_sha256"]:
            raise RegistryError("projected root private key is not the pinned backup key")
        payload = build_readonly_projected_root_attestation(
            physical_paths=context.paths, transition_trust=context.paths.custody_transition,
            projection_root=context.paths.root, projection_info=observed,
            signer_key_id=BACKUP_SIGNER_KEY_ID, private_key=private_key,
            attested_at=query_trusted_clock().trusted_now,
        )
        return {"payload": payload, "attestation_id": payload["attestation_id"]}

    signed = run_with_preloaded_private_key(
        private_key_path=DEFAULT_BACKUP_PRIVATE_KEY,
        service_uid=policy.payload["service_uid"], service_gid=policy.payload["service_gid"], operation=sign,
    )
    payload = signed.get("payload")
    if not isinstance(payload, dict):
        raise RegistryError("projected root signer returned no payload")
    raw = canonical_json_line(payload)
    _atomic_root_write(DEFAULT_READONLY_PROJECTED_ROOT_ATTESTATION, raw, create_only=True)
    return {
        "status": "READONLY_PROJECTED_ROOT_ATTESTED",
        "attestation_id": str(signed["attestation_id"]),
        "receipt": str(DEFAULT_READONLY_PROJECTED_ROOT_ATTESTATION),
        "receipt_raw_sha256": sha256(raw),
    }


def main() -> int:
    try:
        result = run(build_parser().parse_args())
    except (OSError, RegistryError, ValueError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    for key in sorted(result):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
