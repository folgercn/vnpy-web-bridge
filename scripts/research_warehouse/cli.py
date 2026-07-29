"""Command-line policy checks for source-registry changes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .acquisition import acquire_daily
from .authority import assert_research_source_boundary
from .canonical import parse_json_strict, sha256
from .commit_anchors import load_commit_anchor_ledger
from .errors import RegistryError
from .filesystem import WarehousePaths, read_regular_strict
from .manifest_commits import commit_receipt_path
from .manifests import seal_daily_batch, verify_manifest_chain
from .pit import select_pit_revision
from .registry import load_registry
from .timeutil import parse_utc

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _parent_anchor(value: str) -> str | None:
    if value == "GENESIS":
        return None
    if SHA256_PATTERN.fullmatch(value) is None:
        raise RegistryError(
            "expected parent seal must be GENESIS or a lowercase SHA256"
        )
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    registry = commands.add_parser("verify-registry")
    registry.add_argument("--registry", type=Path, required=True)
    boundary = commands.add_parser("verify-boundary")
    boundary.add_argument("--source-root", type=Path, required=True)
    init = commands.add_parser("init-custody")
    init.add_argument("--root", type=Path, required=True)
    acquire = commands.add_parser("acquire")
    acquire.add_argument("--root", type=Path, required=True)
    acquire.add_argument("--registry", type=Path, required=True)
    acquire.add_argument("--source-id", required=True)
    acquire.add_argument("--trade-day", required=True)
    acquire.add_argument("--collector-version", required=True)
    seal = commands.add_parser("seal-day")
    seal.add_argument("--root", type=Path, required=True)
    seal.add_argument("--registry", type=Path, required=True)
    seal.add_argument("--trade-day", required=True)
    seal.add_argument("--private-key", type=Path, required=True)
    seal.add_argument("--signer-key-id", required=True)
    seal.add_argument("--expected-parent-seal", required=True)
    seal.add_argument("--expected-parent-commit-seal", required=True)
    verify = commands.add_parser("verify-chain")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--expected-genesis-seal", required=True)
    verify.add_argument("--expected-head-seal", required=True)
    verify.add_argument("--expected-head-commit-seal", required=True)
    select = commands.add_parser("select-pit")
    select.add_argument("--root", type=Path, required=True)
    select.add_argument("--registry", type=Path, required=True)
    select.add_argument("--public-key", type=Path, required=True)
    select.add_argument("--expected-genesis-seal", required=True)
    select.add_argument("--expected-head-seal", required=True)
    select.add_argument("--expected-head-commit-seal", required=True)
    select.add_argument("--commit-anchor-ledger", type=Path, required=True)
    select.add_argument("--expected-commit-anchor-ledger-sha256", required=True)
    select.add_argument("--source-id", required=True)
    select.add_argument("--trade-day", required=True)
    select.add_argument("--cutoff-at", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-registry":
            registry = load_registry(args.registry)
            output = {
                "authority": registry.authority.authority_class,
                "registry_id": registry.registry_id,
                "registry_raw_sha256": registry.raw_sha256,
                "sources": [source.source_id for source in registry.sources],
                "status": "VALID",
            }
        elif args.command == "verify-boundary":
            paths = list(args.source_root.rglob("*.py"))
            if not paths:
                raise RegistryError("Research source root contains no Python modules")
            assert_research_source_boundary(paths)
            output = {
                "checked_file_count": len(paths),
                "status": "RESEARCH_BOUNDARY_VALID",
            }
        elif args.command == "init-custody":
            paths = WarehousePaths.initialize(args.root)
            output = {"root": str(paths.root), "status": "CUSTODY_INITIALIZED"}
        elif args.command == "acquire":
            acquired = acquire_daily(
                paths=WarehousePaths.open(args.root),
                registry=load_registry(args.registry),
                source_id=args.source_id,
                trade_day=args.trade_day,
                collector_version=args.collector_version,
            )
            output = {
                "idempotent_raw": acquired.idempotent_raw,
                "object_id": acquired.object_id,
                "observation_id": acquired.observation_id,
                "raw_sha256": acquired.raw_sha256,
                "status": "RAW_OBSERVED_NOT_READY",
            }
        elif args.command == "seal-day":
            output_path = seal_daily_batch(
                paths=WarehousePaths.open(args.root),
                registry=load_registry(args.registry),
                trade_day=args.trade_day,
                private_key_path=args.private_key,
                signer_key_id=args.signer_key_id,
                expected_parent_batch_seal_sha256=_parent_anchor(
                    args.expected_parent_seal
                ),
                expected_parent_commit_seal_sha256=_parent_anchor(
                    args.expected_parent_commit_seal
                ),
            )
            manifest = parse_json_strict(
                read_regular_strict(
                    output_path,
                    "sealed daily manifest",
                    limit=16 * 1024 * 1024,
                ),
                "sealed daily manifest",
            )
            receipt_path = commit_receipt_path(
                output_path,
                manifest["batch_id"],
            )
            receipt_raw = read_regular_strict(
                receipt_path,
                "manifest commit receipt",
                limit=2 * 1024 * 1024,
            )
            receipt = parse_json_strict(
                receipt_raw,
                "manifest commit receipt",
            )
            output = {
                "batch_seal_sha256": manifest["batch_seal_sha256"],
                "commit_seal_sha256": sha256(receipt_raw),
                "commit_receipt": str(receipt_path),
                "committed_at": receipt["committed_at"],
                "manifest": str(output_path),
                "status": "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR",
            }
        elif args.command == "verify-chain":
            chain = verify_manifest_chain(
                paths=WarehousePaths.open(args.root),
                public_key_path=args.public_key,
                registry=load_registry(args.registry),
                expected_genesis_seal_sha256=args.expected_genesis_seal,
                expected_head_seal_sha256=args.expected_head_seal,
                expected_head_commit_seal_sha256=(args.expected_head_commit_seal),
            )
            output = {
                "batch_count": len(chain),
                "latest_batch_id": chain[-1]["batch_id"] if chain else None,
                "status": "MANIFEST_CHAIN_VALID",
            }
        elif args.command == "select-pit":
            selection = select_pit_revision(
                paths=WarehousePaths.open(args.root),
                public_key_path=args.public_key,
                registry=load_registry(args.registry),
                expected_genesis_seal_sha256=args.expected_genesis_seal,
                expected_head_seal_sha256=args.expected_head_seal,
                expected_head_commit_seal_sha256=(args.expected_head_commit_seal),
                commit_anchor_ledger=load_commit_anchor_ledger(
                    args.commit_anchor_ledger,
                    expected_raw_sha256=(args.expected_commit_anchor_ledger_sha256),
                ),
                source_id=args.source_id,
                trade_day=args.trade_day,
                cutoff_at=parse_utc(args.cutoff_at, "cutoff_at"),
            )
            output = {
                "batch_id": selection.batch_id,
                "object_id": selection.object_id,
                "revision_id": selection.revision_id,
                "raw_sha256": selection.raw_sha256,
                "status": "PIT_REVISION_SELECTED",
            }
        else:  # pragma: no cover
            raise RegistryError(f"unsupported command: {args.command}")
    except RegistryError as exc:
        print(f"Research source policy failed closed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0
