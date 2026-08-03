#!/usr/bin/env python3
"""Build four deterministic, duration-aware backend unit-test shards."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UNIT_TEST_ROOT = ROOT / "backend/tests/unit"
SHARD_COUNT = 4

# File-level timings captured from the 2026-08-03 local baseline. The allocator
# only needs explicit weights for material tests; fast and newly added files use a
# conservative default. Refresh these auditable weights from CI when the slow-file
# profile materially changes.
HISTORICAL_SECONDS = {
    "test_commodity_c_fast_execution_quality_collection_admission.py": 77.107,
    "test_commodity_c_fast_t1_query_v5_release.py": 68.504,
    "test_c_fast_t1_query_v5_image_attestation.py": 68.461,
    "test_commodity_c_fast_p0_acceptance_v2.py": 64.827,
    "test_c_fast_t1_image_attestation.py": 40.854,
    "test_commodity_static_core_equal_pure_producer.py": 36.214,
    "test_commodity_c_fast_execution_quality_p0_bundle_v6.py": 26.956,
    "test_research_warehouse_backup_migration.py": 26.126,
    "test_commodity_relative_vol_snapshot_producer.py": 21.183,
    "test_commodity_c_fast_simnow_research_acceptance.py": 11.940,
    "test_commodity_c_fast_p0_acceptance_script.py": 9.866,
    "test_c_fast_t1_query_v3_image_attestation.py": 9.450,
    "test_commodity_c_fast_t1_query_v6_executable_runtime.py": 7.734,
    "test_c_fast_t1_query_v4_image_attestation.py": 6.776,
    "test_research_warehouse_sealed_export.py": 6.024,
    "test_commodity_c_fast_execution_quality_production_verifier.py": 5.571,
    "test_research_warehouse_static_core_baseline.py": 5.182,
    "test_research_warehouse_pit_source_view.py": 4.604,
    "test_commodity_c_fast_simnow.py": 4.118,
    "test_commodity_c_fast_research_acceptance_evidence.py": 4.111,
    "test_commodity_c_fast_t1_query_v3.py": 3.217,
    "test_commodity_c_fast_readonly_deployment_outcome_script.py": 3.152,
    "test_research_warehouse_catalog.py": 3.105,
    "test_commodity_c_fast_t1_query_v6_authority.py": 2.726,
    "test_commodity_c_fast_fee_statement.py": 2.709,
    "test_commodity_c_fast_simnow_research_bundle.py": 2.676,
    "test_commodity_c_fast_execution_quality_production_assembly.py": 2.061,
    "test_research_warehouse_c_fast_source_view.py": 2.027,
    "test_commodity_c_fast_t1_readiness_v4_script.py": 1.728,
    "test_commodity_baseline_execution_permit_tool.py": 1.691,
    "test_c_fast_t1_build_registry_provenance_v2.py": 1.655,
    "test_commodity_c_fast_pure_producer_kernel.py": 1.533,
    "test_c_fast_t1_query_v6_preconnect_package.py": 1.441,
    "test_commodity_c_fast_t1_readiness_v3_script.py": 1.430,
    "test_commodity_simnow.py": 1.332,
    "test_commodity_c_fast_readonly_deployment_release_script.py": 1.133,
    "test_commodity_c_fast_pnl_ledger_repository.py": 1.124,
    "test_c_fast_t1_build_registry_provenance.py": 1.104,
    "test_commodity_c_fast_execution_quality_horizon_worker.py": 1.054,
    "test_c_fast_t1_build_registry_provenance_v3.py": 1.040,
    "test_research_warehouse_m2_release_bundle.py": 1.026,
    "test_commodity_c_fast_execution_quality_tick_fanout.py": 1.015,
}
REQUIRED_SEPARATED = (
    "test_commodity_c_fast_execution_quality_collection_admission.py",
    "test_commodity_c_fast_p0_acceptance_v2.py",
    "test_commodity_static_core_equal_pure_producer.py",
    "test_commodity_c_fast_execution_quality_p0_bundle_v6.py",
)
# This file performs fail-closed double-stat checks against newly written
# artifacts. Collect it before long stress files so local atime behaviour cannot
# create a false file-identity drift; GitHub jobs remain isolated either way.
COLLECT_FIRST = {"test_commodity_c_fast_execution_quality_production_verifier.py"}
DEFAULT_SECONDS = 0.1


def discover_tests() -> list[Path]:
    """Return the stable repository-relative list of backend unit-test files."""
    return sorted(
        path.relative_to(ROOT)
        for path in UNIT_TEST_ROOT.rglob("test_*.py")
        if path.is_file()
    )


def build_shards(files: list[Path] | None = None) -> list[list[Path]]:
    """Use deterministic longest-processing-time allocation across four shards."""
    discovered = discover_tests() if files is None else sorted(files)
    by_name = {path.name: path for path in discovered}
    required = [by_name[name] for name in REQUIRED_SEPARATED if name in by_name]
    ranked = sorted(
        [path for path in discovered if path not in required],
        key=lambda path: (-HISTORICAL_SECONDS.get(path.name, DEFAULT_SECONDS), path.as_posix()),
    )
    shards: list[list[Path]] = [[] for _ in range(SHARD_COUNT)]
    totals = [0.0] * SHARD_COUNT
    for shard, path in enumerate(required):
        shards[shard].append(path)
        totals[shard] += HISTORICAL_SECONDS[path.name]
    for path in ranked:
        shard = min(range(SHARD_COUNT), key=lambda index: (totals[index], index))
        shards[shard].append(path)
        totals[shard] += HISTORICAL_SECONDS.get(path.name, DEFAULT_SECONDS)
    return [
        sorted(shard, key=lambda path: (path.name not in COLLECT_FIRST, path.as_posix()))
        for shard in shards
    ]


def validate_shards(shards: list[list[Path]] | None = None) -> dict[str, object]:
    """Fail closed if coverage, uniqueness, or slow-file separation regresses."""
    assigned = build_shards() if shards is None else shards
    discovered = discover_tests()
    flattened = [path for shard in assigned for path in shard]
    if sorted(flattened) != discovered:
        missing = sorted(set(discovered) - set(flattened))
        duplicates = sorted({path for path in flattened if flattened.count(path) > 1})
        extra = sorted(set(flattened) - set(discovered))
        raise ValueError(
            f"invalid shard coverage: missing={missing}, duplicates={duplicates}, extra={extra}"
        )
    locations = {
        path.name: index
        for index, shard in enumerate(assigned, start=1)
        for path in shard
        if path.name in REQUIRED_SEPARATED
    }
    if set(locations) != set(REQUIRED_SEPARATED):
        raise ValueError("a required historically slow test file is absent")
    if len(set(locations.values())) != len(REQUIRED_SEPARATED):
        raise ValueError("historically slow test files must occupy different shards")
    totals = [
        sum(HISTORICAL_SECONDS.get(path.name, DEFAULT_SECONDS) for path in shard)
        for shard in assigned
    ]
    return {
        "test_file_count": len(discovered),
        "estimated_seconds": totals,
        "slow_file_shards": locations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    files_parser = subparsers.add_parser("files")
    files_parser.add_argument("--shard", type=int, choices=range(1, SHARD_COUNT + 1), required=True)
    manifest_parser = subparsers.add_parser("manifest")
    manifest_parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    shards = build_shards()
    summary = validate_shards(shards)
    if args.command == "validate":
        print(json.dumps(summary, sort_keys=True))
    elif args.command == "files":
        for path in shards[args.shard - 1]:
            print(path.as_posix())
    else:
        payload = {
            "shards": [[path.as_posix() for path in shard] for shard in shards],
            **summary,
        }
        print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
