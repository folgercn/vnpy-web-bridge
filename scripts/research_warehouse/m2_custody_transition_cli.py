"""Root-started one-shot signer for reviewed APFS custody device drift."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, sha256
from .custody_transition import build_custody_transition
from .errors import RegistryError
from .m2_isolation_contracts import load_isolation_policy
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import (
    BACKUP_SIGNER_KEY_ID,
    DEFAULT_BACKUP_PRIVATE_KEY,
    DEFAULT_CUSTODY_TRANSITION_RECEIPT,
)
from .m2_operator_state import _atomic_root_write
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .m2_signer_handoff import run_with_preloaded_private_key
from .signing import public_key_sha256


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign one reviewed legacy APFS custody identity transition"
    )
    parser.add_argument(
        "--runtime-input",
        type=Path,
        default=DEFAULT_RUNTIME_INPUT,
    )
    parser.add_argument("--source-st-dev", type=int, required=True)
    parser.add_argument("--expected-source-legacy-identity", required=True)
    parser.add_argument("--expected-destination-legacy-identity", required=True)
    return parser


def run(args: argparse.Namespace) -> dict[str, str]:
    if DEFAULT_CUSTODY_TRANSITION_RECEIPT.exists():
        raise RegistryError(
            "custody transition receipt already exists; refusing to re-sign"
        )
    policy = load_isolation_policy(
        args.runtime_input.parent / "isolation-policy-v1.json"
    )

    def sign(private_key) -> dict[str, Any]:
        # The root-only key has already been loaded; this callback runs only
        # after the existing irreversible handoff to vnpyresearch:503:503.
        context = load_runtime_context(args.runtime_input)
        expected_key_hash = context.runtime_input.payload[
            "expected_backup_public_key_sha256"
        ]
        if public_key_sha256(private_key.public_key()) != expected_key_hash:
            raise RegistryError(
                "custody transition private key is not the pinned backup key"
            )
        clock = query_trusted_clock()
        payload = build_custody_transition(
            paths=context.paths,
            source_st_dev=args.source_st_dev,
            expected_source_legacy_identity_sha256=(
                args.expected_source_legacy_identity
            ),
            expected_destination_legacy_identity_sha256=(
                args.expected_destination_legacy_identity
            ),
            signer_key_id=BACKUP_SIGNER_KEY_ID,
            private_key=private_key,
            attested_at=clock.trusted_now,
        )
        return {
            "payload": payload,
            "stable_identity_sha256": payload["stable_identity_sha256"],
            "transition_id": payload["transition_id"],
        }

    signed = run_with_preloaded_private_key(
        private_key_path=DEFAULT_BACKUP_PRIVATE_KEY,
        service_uid=policy.payload["service_uid"],
        service_gid=policy.payload["service_gid"],
        operation=sign,
    )
    payload = signed.get("payload")
    if not isinstance(payload, dict):
        raise RegistryError("custody transition signer returned no signed payload")
    raw = canonical_json_line(payload)

    # Only the root parent publishes the already-signed bytes into root-managed
    # libexec custody. The service child never regains root or writes this path.
    _atomic_root_write(
        DEFAULT_CUSTODY_TRANSITION_RECEIPT,
        raw,
        create_only=True,
    )
    return {
        "status": "CUSTODY_TRANSITION_ATTESTED",
        "transition_id": str(signed["transition_id"]),
        "receipt": str(DEFAULT_CUSTODY_TRANSITION_RECEIPT),
        "receipt_raw_sha256": sha256(raw),
        "stable_identity_sha256": str(signed["stable_identity_sha256"]),
    }


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = run(args)
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    for key in sorted(result):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
