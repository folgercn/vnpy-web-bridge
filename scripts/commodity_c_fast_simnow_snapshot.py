#!/usr/bin/env python3
"""Produce, verify, and create-only install C_FAST SimNow snapshots."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.config import Settings  # noqa: E402
from app.schemas.commodity_c_fast_shadow import (  # noqa: E402
    CommodityCFastShadowDTO,
)
from app.services.commodity_c_fast_research import (  # noqa: E402
    CFastResearchBundleInvalidError,
    load_research_bundle,
    produce_unsigned_snapshot,
    verify_evidence_files,
)
from app.services.commodity_c_fast_shadow import (  # noqa: E402
    CFastShadowInvalidError,
    CommodityCFastShadowService,
    normalize_rpc_contracts,
)
from app.services.commodity_c_fast_shadow_common import (  # noqa: E402
    sha256_json,
)


def load_json_object(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return raw


def create_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def pretty_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


def contract_loader(path: Path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("contracts") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError("contract catalog must be a list or {contracts: [...]}")

    def load(required: set[str]) -> dict[str, dict[str, Any]]:
        return normalize_rpc_contracts(rows, required)

    return load


def expected_snapshot(args: argparse.Namespace) -> CommodityCFastShadowDTO:
    bundle = load_research_bundle(args.bundle)
    manifest_hash = verify_evidence_files(bundle, args.evidence_root)
    return produce_unsigned_snapshot(
        bundle,
        evidence_manifest_sha256=manifest_hash,
    )


def verify_signed(
    args: argparse.Namespace,
) -> tuple[CommodityCFastShadowDTO, str]:
    expected = expected_snapshot(args)
    signed = CommodityCFastShadowDTO.model_validate(
        load_json_object(args.signed)
    )
    if (
        expected.model_dump(mode="json", exclude={"signature"})
        != signed.model_dump(mode="json", exclude={"signature"})
    ):
        raise ValueError("signed snapshot does not match verified Research bundle")
    trusted_keys_json = args.trusted_keys.read_text(encoding="utf-8")
    now = (
        datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        if args.now
        else datetime.now(timezone.utc)
    )
    service = CommodityCFastShadowService(
        settings=Settings(
            commodity_c_fast_shadow_trusted_public_keys_json=trusted_keys_json
        ),
        contract_loader=contract_loader(args.contract_catalog),
        clock=lambda: now,
    )
    snapshot_hash = service._verify_snapshot(signed)
    return signed, snapshot_hash


def run_produce(args: argparse.Namespace) -> int:
    snapshot = expected_snapshot(args)
    payload = snapshot.model_dump(mode="json", exclude={"signature"})
    create_private_file(args.output, pretty_json(payload))
    print(f"unsigned snapshot: {args.output}")
    print(
        "research_input_bundle_sha256: "
        f"{snapshot.research_bindings.research_input_bundle_sha256}"
    )
    return 0


def run_verify(args: argparse.Namespace) -> int:
    _snapshot, snapshot_hash = verify_signed(args)
    print("verification: VALID")
    print(f"snapshot_hash: {snapshot_hash}")
    return 0


def run_install(args: argparse.Namespace) -> int:
    snapshot, snapshot_hash = verify_signed(args)
    signed_bytes = pretty_json(snapshot.model_dump(mode="json"))
    receipt = {
        "schema_version": "commodity_c_fast_snapshot_install_receipt_v1",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_hash": snapshot_hash,
        "research_input_bundle_sha256": (
            snapshot.research_bindings.research_input_bundle_sha256
        ),
        "research_evidence_manifest_sha256": (
            snapshot.research_bindings.research_evidence_manifest_sha256
        ),
        "execution_lane": snapshot.execution_lane,
        "countable_forward": False,
        "production_allowed": False,
        "installed_at_utc": datetime.now(timezone.utc).isoformat(),
        "installed_path_sha256": sha256_json(
            {"path": str(args.output.resolve())}
        ),
    }
    receipt_path = args.receipt or args.output.with_suffix(
        f"{args.output.suffix}.receipt.json"
    )
    create_private_file(args.output, signed_bytes)
    try:
        create_private_file(receipt_path, pretty_json(receipt))
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(f"installed snapshot: {args.output}")
    print(f"install receipt: {receipt_path}")
    print(f"snapshot_hash: {snapshot_hash}")
    return 0


def add_bundle_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)


def add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    add_bundle_arguments(parser)
    parser.add_argument("--signed", required=True, type=Path)
    parser.add_argument("--trusted-keys", required=True, type=Path)
    parser.add_argument("--contract-catalog", required=True, type=Path)
    parser.add_argument("--now", help="verification clock as ISO-8601")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    produce = commands.add_parser("produce")
    add_bundle_arguments(produce)
    produce.add_argument("--output", required=True, type=Path)
    produce.set_defaults(handler=run_produce)
    verify = commands.add_parser("verify")
    add_verification_arguments(verify)
    verify.set_defaults(handler=run_verify)
    install = commands.add_parser("install")
    add_verification_arguments(install)
    install.add_argument("--output", required=True, type=Path)
    install.add_argument("--receipt", type=Path)
    install.set_defaults(handler=run_install)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return int(args.handler(args))
    except (
        CFastResearchBundleInvalidError,
        CFastShadowInvalidError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        code = getattr(exc, "code", exc.__class__.__name__)
        print(f"{args.command} failed: {code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
