"""Thin CLI for create-only sealed source export and read-only verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from commodity_c_fast_pure_producer_kernel import ARTIFACT_ROLES

from .errors import RegistryError
from .sealed_export import create_sealed_export, verify_sealed_export
from .timeutil import parse_utc


def _artifact_arguments(command: argparse.ArgumentParser) -> None:
    for role in ARTIFACT_ROLES:
        command.add_argument(f"--{role.replace('_', '-')}", type=Path, required=True)


def _artifact_paths(args) -> dict[str, Path]:
    return {role: getattr(args, role) for role in ARTIFACT_ROLES}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    _artifact_arguments(create)
    create.add_argument("--lineage", type=Path, required=True)
    create.add_argument("--expected-lineage-sha256", required=True)
    create.add_argument("--keyring", type=Path, required=True)
    create.add_argument("--expected-keyring-sha256", required=True)
    create.add_argument("--signer-key-id", required=True)
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--export-root", type=Path, required=True)
    create.add_argument("--now", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--export", type=Path, required=True)
    verify.add_argument("--keyring", type=Path, required=True)
    verify.add_argument("--expected-keyring-sha256", required=True)
    verify.add_argument("--expected-receipt-sha256", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "create":
            verified = create_sealed_export(
                artifact_paths=_artifact_paths(args),
                lineage_path=args.lineage,
                expected_lineage_raw_sha256=args.expected_lineage_sha256,
                keyring_path=args.keyring,
                expected_keyring_raw_sha256=args.expected_keyring_sha256,
                signer_key_id=args.signer_key_id,
                private_key_path=args.private_key,
                export_root=args.export_root,
                now=parse_utc(args.now, "sealed export now"),
            )
        else:
            verified = verify_sealed_export(
                output=args.export,
                keyring_path=args.keyring,
                expected_keyring_raw_sha256=args.expected_keyring_sha256,
                expected_receipt_raw_sha256=args.expected_receipt_sha256,
            )
    except RegistryError as exc:
        print(f"Sealed source export failed closed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "SEALED_SOURCE_EXPORT_VERIFIED_READ_ONLY",
                "export_id": verified.export_id,
                "export": str(verified.output),
                "receipt_raw_sha256": verified.receipt_raw_sha256,
                "manifest_raw_sha256": verified.manifest_raw_sha256,
                "artifact_index_sha256": verified.artifact_index_sha256,
                "authority": {
                    "control": False,
                    "execution": False,
                    "trading": False,
                    "production": False,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0
