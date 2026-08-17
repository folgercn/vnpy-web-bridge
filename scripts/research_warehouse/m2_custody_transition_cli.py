"""Root-only one-shot signer for reviewed APFS custody device drift."""

from __future__ import annotations

import argparse
from pathlib import Path

from .canonical import canonical_json_line, sha256
from .custody_paths import CustodyTransitionTrust, WarehousePaths
from .custody_transition import build_custody_transition, verify_custody_transition
from .errors import RegistryError
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import (
    BACKUP_SIGNER_KEY_ID,
    DEFAULT_BACKUP_PRIVATE_KEY,
    DEFAULT_CUSTODY_TRANSITION_RECEIPT,
)
from .m2_operator_state import _atomic_root_write
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .signing import load_private_key, public_key_sha256


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
    context = load_runtime_context(args.runtime_input)
    private_key = load_private_key(DEFAULT_BACKUP_PRIVATE_KEY)
    expected_key_hash = context.runtime_input.payload[
        "expected_backup_public_key_sha256"
    ]
    if public_key_sha256(private_key.public_key()) != expected_key_hash:
        raise RegistryError("custody transition private key is not the pinned backup key")
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
    raw = canonical_json_line(payload)
    _atomic_root_write(
        DEFAULT_CUSTODY_TRANSITION_RECEIPT,
        raw,
        create_only=True,
    )
    trust = CustodyTransitionTrust(
        receipt_path=DEFAULT_CUSTODY_TRANSITION_RECEIPT,
        public_key_path=Path(
            context.runtime_input.payload["backup_public_key_path"]
        ),
        expected_public_key_sha256=expected_key_hash,
    )
    verified_paths = WarehousePaths.open(
        context.paths.root,
        custody_transition=trust,
    )
    verified = verify_custody_transition(verified_paths, trust)
    return {
        "status": "CUSTODY_TRANSITION_ATTESTED",
        "transition_id": verified["transition_id"],
        "receipt": str(DEFAULT_CUSTODY_TRANSITION_RECEIPT),
        "receipt_raw_sha256": sha256(raw),
        "stable_identity_sha256": verified["stable_identity_sha256"],
    }


def main() -> int:
    args = build_parser().parse_args()
    result = run(args)
    for key in sorted(result):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
