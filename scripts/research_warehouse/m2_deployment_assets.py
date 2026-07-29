"""Verify raw-pinned M2 LaunchDaemon and PF deployment assets."""

from __future__ import annotations

import plistlib
from pathlib import Path

from .canonical import sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import (
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    IsolationPolicy,
)


def _asset_raw(path: Path, label: str) -> bytes:
    return read_regular_strict(
        path,
        label,
        limit=1024 * 1024,
        private=False,
    )


def verify_deployment_assets(
    directory: Path,
    *,
    policy: IsolationPolicy,
) -> dict[str, str]:
    actual = {}
    for label, expected in PLIST_SHA256.items():
        path = directory / f"{label}.plist"
        raw = _asset_raw(path, f"{label} plist")
        if sha256(raw) != expected:
            raise RegistryError(f"{label} plist raw SHA256 mismatch")
        try:
            payload = plistlib.loads(raw)
        except plistlib.InvalidFileException as exc:
            raise RegistryError(f"{label} plist is invalid") from exc
        if (
            payload.get("Label") != label
            or payload.get("UserName") != policy.user
            or payload.get("GroupName") != policy.group
            or payload.get("Umask") != 0o77
            or payload.get("EnvironmentVariables")
            != policy.payload["allowed_environment"]
            or payload.get("WorkingDirectory") != policy.payload["runtime_root"]
            or len(payload.get("ProgramArguments", [])) != 1
            or not payload["ProgramArguments"][0].startswith(
                f"{policy.payload['runtime_root']}/"
            )
            or not payload.get("StandardOutPath", "").startswith(
                f"{policy.payload['runtime_root']}/"
            )
            or not payload.get("StandardErrorPath", "").startswith(
                f"{policy.payload['runtime_root']}/"
            )
        ):
            raise RegistryError(f"{label} plist isolation contract mismatch")
        actual[label] = expected
    pf_raw = _asset_raw(directory / "pf.vnpyresearch.conf", "PF anchor")
    if sha256(pf_raw) != PF_ANCHOR_SHA256:
        raise RegistryError("PF anchor raw SHA256 mismatch")
    text = pf_raw.decode("utf-8")
    required = (
        "block return out log quick user vnpyresearch",
        "port 53 user vnpyresearch",
        "port 123 user vnpyresearch",
        "port 443 user vnpyresearch",
    )
    if (
        any(item not in text for item in required)
        or "www.shfe.com.cn" in text
        or "www.ine.cn" in text
        or "192.168.100." in text
        or "127.0.0.1" in text
    ):
        raise RegistryError("PF anchor is not literal-table fail-closed policy")
    return {**actual, "pf_anchor": PF_ANCHOR_SHA256}
