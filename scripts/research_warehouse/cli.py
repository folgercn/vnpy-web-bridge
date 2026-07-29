"""Command-line policy checks for source-registry changes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

from .acquisition import acquire_daily
from .acquisition_models import AuthoritativeAbsence
from .authority import assert_research_source_boundary
from .calendar_models import OfficialCalendar
from .canonical import parse_json_strict, sha256
from .clock_quality import TrustedClockSample
from .commit_anchors import load_commit_anchor_ledger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .filesystem import WarehousePaths, read_regular_strict
from .manifest_commits import commit_receipt_path
from .manifests import seal_daily_batch, verify_manifest_chain
from .official_calendar import load_official_calendar
from .pit import select_pit_revision
from .quality_gate import evaluate_history_quality
from .rebuild import rebuild_empty_catalog, verify_rebuilt_catalog
from .rebuild_binding import load_normalization_binding
from .registry import load_registry
from .signing import load_public_key
from .timeutil import parse_utc
from .trade_day_mapping import map_exchange_timestamp

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
    calendar_acquire = commands.add_parser("acquire-calendar-aware")
    calendar_acquire.add_argument("--root", type=Path, required=True)
    calendar_acquire.add_argument("--registry", type=Path, required=True)
    calendar_acquire.add_argument("--source-id", required=True)
    calendar_acquire.add_argument("--trade-day", required=True)
    calendar_acquire.add_argument("--collector-version", required=True)
    calendar_acquire.add_argument("--observed-at", required=True)
    _add_calendar_arguments(calendar_acquire)
    _add_clock_arguments(calendar_acquire)
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
    rebuild = commands.add_parser("rebuild-catalog")
    _add_rebuild_arguments(rebuild)
    verify_catalog = commands.add_parser("verify-catalog")
    _add_rebuild_arguments(verify_catalog)
    verify_calendar = commands.add_parser("verify-calendar")
    _add_calendar_arguments(verify_calendar)
    map_day = commands.add_parser("map-trade-day")
    _add_calendar_arguments(map_day)
    map_day.add_argument("--observed-at", required=True)
    map_day.add_argument("--exchange", choices=("INE", "SHFE"), required=True)
    map_day.add_argument("--session", choices=("DAY", "NIGHT"), required=True)
    quality = commands.add_parser("quality-gate")
    quality.add_argument("--root", type=Path, required=True)
    quality.add_argument("--registry", type=Path, required=True)
    quality.add_argument("--public-key", type=Path, required=True)
    quality.add_argument("--expected-genesis-seal", required=True)
    quality.add_argument("--expected-head-seal", required=True)
    quality.add_argument("--expected-head-commit-seal", required=True)
    quality.add_argument("--commit-anchor-ledger", type=Path, required=True)
    quality.add_argument(
        "--expected-commit-anchor-ledger-sha256",
        required=True,
    )
    quality.add_argument("--as-of-official-day", required=True)
    quality.add_argument("--execution-trade-day", required=True)
    quality.add_argument("--cutoff-at", required=True)
    _add_calendar_arguments(quality)
    _add_clock_arguments(quality)
    return result


def _add_calendar_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--calendar", type=Path, required=True)
    command.add_argument("--calendar-public-key", type=Path, required=True)
    command.add_argument("--expected-calendar-sha256", required=True)
    command.add_argument("--calendar-source-evidence-root", type=Path, required=True)


def _add_clock_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--trusted-now", required=True)
    command.add_argument("--ntp-sampled-at", required=True)
    command.add_argument("--ntp-offset-milliseconds", type=int, required=True)


def _add_rebuild_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--root", type=Path, required=True)
    command.add_argument("--derived-root", type=Path, required=True)
    command.add_argument("--registry", type=Path, required=True)
    command.add_argument("--public-key", type=Path, required=True)
    command.add_argument("--expected-genesis-seal", required=True)
    command.add_argument("--expected-head-seal", required=True)
    command.add_argument("--expected-head-commit-seal", required=True)
    command.add_argument("--commit-anchor-ledger", type=Path, required=True)
    command.add_argument(
        "--expected-commit-anchor-ledger-sha256",
        required=True,
    )
    command.add_argument("--tool-commit-sha", required=True)
    command.add_argument("--dependency-lock", type=Path, required=True)
    command.add_argument(
        "--expected-dependency-lock-sha256",
        required=True,
    )


def _calendar(args) -> OfficialCalendar:
    return load_official_calendar(
        args.calendar,
        public_key=load_public_key(args.calendar_public_key),
        expected_raw_sha256=args.expected_calendar_sha256,
        source_evidence_root=args.calendar_source_evidence_root,
    )


def _clock_sample(args) -> TrustedClockSample:
    return TrustedClockSample(
        trusted_now=parse_utc(args.trusted_now, "trusted_now"),
        sampled_at=parse_utc(args.ntp_sampled_at, "ntp_sampled_at"),
        ntp_offset_milliseconds=args.ntp_offset_milliseconds,
    )


def _canonical_date(value: str, label: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{label} must be canonical YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"{label} must be canonical YYYY-MM-DD")
    return parsed


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
        elif args.command == "acquire-calendar-aware":
            acquired = acquire_daily(
                paths=WarehousePaths.open(args.root),
                registry=load_registry(args.registry),
                source_id=args.source_id,
                trade_day=args.trade_day,
                collector_version=args.collector_version,
                observed_at=parse_utc(args.observed_at, "observed_at"),
                calendar=_calendar(args),
                clock_sample=_clock_sample(args),
            )
            if isinstance(acquired, AuthoritativeAbsence):
                output = {
                    "absence_id": acquired.absence_id,
                    "calendar_raw_sha256": acquired.calendar_raw_sha256,
                    "receipt": str(acquired.receipt_path),
                    "status": acquired.status,
                }
            else:
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
        elif args.command in {"rebuild-catalog", "verify-catalog"}:
            evidence = WarehousePaths.open(args.root)
            trusted_registry = load_registry(args.registry)
            ledger = load_commit_anchor_ledger(
                args.commit_anchor_ledger,
                expected_raw_sha256=(
                    args.expected_commit_anchor_ledger_sha256
                ),
            )
            binding = load_normalization_binding(
                tool_commit_sha=args.tool_commit_sha,
                dependency_lock_path=args.dependency_lock,
                expected_dependency_lock_sha256=(
                    args.expected_dependency_lock_sha256
                ),
                registry_raw_sha256=trusted_registry.raw_sha256,
            )
            common = {
                "evidence": evidence,
                "public_key_path": args.public_key,
                "registry": trusted_registry,
                "expected_genesis_seal_sha256": args.expected_genesis_seal,
                "expected_head_seal_sha256": args.expected_head_seal,
                "expected_head_commit_seal_sha256": (
                    args.expected_head_commit_seal
                ),
                "ledger": ledger,
                "binding": binding,
            }
            if args.command == "rebuild-catalog":
                output = rebuild_empty_catalog(
                    derived_root=args.derived_root,
                    **common,
                )
            else:
                output = verify_rebuilt_catalog(
                    derived=DerivedPaths.open(args.derived_root),
                    **common,
                )
        elif args.command == "verify-calendar":
            calendar = _calendar(args)
            output = {
                "calendar_id": calendar.calendar_id,
                "calendar_raw_sha256": calendar.raw_sha256,
                "official_day_count": sum(
                    item.is_official for item in calendar.days.values()
                ),
                "status": "OFFICIAL_CALENDAR_VALID",
            }
        elif args.command == "map-trade-day":
            mapping = map_exchange_timestamp(
                parse_utc(args.observed_at, "observed_at"),
                exchange=args.exchange,
                session=args.session,
                calendar=_calendar(args),
            )
            output = {
                "calendar_raw_sha256": mapping.calendar_raw_sha256,
                "exchange": mapping.exchange,
                "observed_at_shanghai": mapping.observed_at_shanghai.isoformat(),
                "session": mapping.session,
                "trade_day": mapping.trade_day.isoformat(),
                "status": "EXCHANGE_TRADE_DAY_MAPPED",
            }
        elif args.command == "quality-gate":
            evidence = WarehousePaths.open(args.root)
            registry = load_registry(args.registry)
            chain = verify_manifest_chain(
                paths=evidence,
                public_key_path=args.public_key,
                registry=registry,
                expected_genesis_seal_sha256=args.expected_genesis_seal,
                expected_head_seal_sha256=args.expected_head_seal,
                expected_head_commit_seal_sha256=(
                    args.expected_head_commit_seal
                ),
                offline=True,
            )
            output = evaluate_history_quality(
                paths=evidence,
                registry=registry,
                chain=chain,
                ledger=load_commit_anchor_ledger(
                    args.commit_anchor_ledger,
                    expected_raw_sha256=(
                        args.expected_commit_anchor_ledger_sha256
                    ),
                ),
                calendar=_calendar(args),
                as_of_official_day=_canonical_date(
                    args.as_of_official_day,
                    "as_of_official_day",
                ),
                execution_trade_day=_canonical_date(
                    args.execution_trade_day,
                    "execution_trade_day",
                ),
                cutoff_at=parse_utc(args.cutoff_at, "cutoff_at"),
                clock_sample=_clock_sample(args),
            )
        else:  # pragma: no cover
            raise RegistryError(f"unsupported command: {args.command}")
    except RegistryError as exc:
        print(f"Research source policy failed closed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0
