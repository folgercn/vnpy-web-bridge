#!/usr/bin/env python3
"""Fail-closed verification for the archived C_FAST v1 research lineage."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE_DIR = (
    ROOT / "docs/research/commodity-c-fast-lineage-v1"
)
MANIFEST_NAME = "bundle_manifest.json"
SCHEMA_VERSION = "commodity_c_fast_lineage_bundle_v1"
STATUS = "SOURCE_AND_FREEZE_LINEAGE_ARCHIVE_ONLY"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
FROZEN_RULE_ID = "commodity_fast_tsmom_forward_freeze_v1"
FROZEN_RULE_SHA256 = (
    "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
)
CONSUMER_PATH = "scripts/commodity_c_fast_pure_producer_kernel.py"
AUDITED_MAIN_COMMIT = "d2ea96b514b0a43f02a211a463487ca4ce41f609"
CONSUMER_SOURCE_SHA256 = (
    "23539d801d6ee9ddccd0371c3793282eeedf63b13dd442f9447adc795bc1d995"
)
SECTOR_MAP_ID = "COMMODITY_FROZEN_SECTOR_MAP_V1"
SECTOR_MAP = {
    "ag": "precious",
    "al": "nonferrous",
    "au": "precious",
    "bu": "energy_chemical",
    "cu": "nonferrous",
    "rb": "ferrous",
    "ru": "energy_chemical",
    "sc": "energy",
    "sp": "light_industry",
    "zn": "nonferrous",
}
SECTOR_MAP_SHA256 = (
    "974a8eadcf947d18cc203e3c3c71f57a9b579fc556597df5bf9b3ea5b79945f7"
)
SOURCE_LINEAGE = {
    "market_only_curve_panel_source_sha256": (
        "sources/commodity_market_only_curve_panel_v1.py"
    ),
    "fast_tsmom_signal_source_sha256": (
        "sources/commodity_fast_tsmom_family_dev_v1.py"
    ),
    "self_financing_target_source_sha256": (
        "sources/commodity_fast_tsmom_self_financing_sidecar_v1.py"
    ),
    "integer_allocator_source_sha256": (
        "sources/commodity_candidate_lot_aware_safe_allocator_v1.py"
    ),
    "guardband_v2_source_sha256": (
        "sources/commodity_candidate_lot_aware_safe_allocator_guardband_v2.py"
    ),
}
AUTHORITY_FIELDS = {
    "acquisition_authorized",
    "network_authorized",
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "shadow_authorized",
    "simnow_authorized",
    "dispatch_authorized",
    "live_authorized",
    "production_authorized",
}
ARCHIVE_DIRECTORIES = ("sources", "tests", "freeze")


class LineageVerificationError(ValueError):
    """Raised when the lineage archive is incomplete or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_canonical_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LineageVerificationError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise LineageVerificationError(f"{label} must be an object")
    return value


def _safe_archive_path(bundle_dir: Path, raw: object) -> tuple[str, Path]:
    if not isinstance(raw, str) or not raw:
        raise LineageVerificationError("archive path must be a non-empty string")
    logical = PurePosixPath(raw)
    if logical.is_absolute() or ".." in logical.parts:
        raise LineageVerificationError(f"unsafe archive path: {raw}")
    if not logical.parts or logical.parts[0] not in ARCHIVE_DIRECTORIES:
        raise LineageVerificationError(f"archive path outside bound directories: {raw}")
    resolved = (bundle_dir / Path(*logical.parts)).resolve()
    try:
        resolved.relative_to(bundle_dir.resolve())
    except ValueError as exc:
        raise LineageVerificationError(f"archive path escapes bundle: {raw}") from exc
    return logical.as_posix(), resolved


def _consumer_constants(path: Path) -> dict[str, Any]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise LineageVerificationError("consumer source is unreadable") from exc
    required = {
        "CANDIDATE_ID",
        "FROZEN_RULE_ID",
        "FROZEN_RULE_SHA256",
        "LINEAGE",
        "SECTOR_MAP_ID",
        "SECTOR_MAP",
    }
    values: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in required:
            continue
        try:
            values[target.id] = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError) as exc:
            raise LineageVerificationError(
                f"consumer constant is not literal: {target.id}"
            ) from exc
    if set(values) != required:
        raise LineageVerificationError("consumer lineage constants are incomplete")
    return values


def verify_bundle(bundle_dir: Path = DEFAULT_BUNDLE_DIR) -> dict[str, Any]:
    bundle_dir = bundle_dir.resolve()
    manifest = _load_json(bundle_dir / MANIFEST_NAME, "bundle manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise LineageVerificationError("bundle schema version mismatch")
    if manifest.get("status") != STATUS:
        raise LineageVerificationError("bundle status mismatch")
    if manifest.get("candidate_id") != CANDIDATE_ID:
        raise LineageVerificationError("bundle candidate id mismatch")
    if manifest.get("frozen_rule_id") != FROZEN_RULE_ID:
        raise LineageVerificationError("bundle frozen rule id mismatch")
    if manifest.get("frozen_rule_sha256") != FROZEN_RULE_SHA256:
        raise LineageVerificationError("bundle frozen rule sha256 mismatch")

    authority = manifest.get("authority")
    if not isinstance(authority, dict) or set(authority) != AUTHORITY_FIELDS:
        raise LineageVerificationError("bundle authority fields are incomplete")
    if any(value is not False for value in authority.values()):
        raise LineageVerificationError("bundle authority must be explicitly all false")

    bindings = manifest.get("archive_bindings")
    if not isinstance(bindings, list) or len(bindings) != 15:
        raise LineageVerificationError("archive must contain exactly 15 bindings")

    observed: dict[str, str] = {}
    source_paths: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise LineageVerificationError("archive binding must be an object")
        logical, path = _safe_archive_path(bundle_dir, binding.get("path"))
        if logical in observed:
            raise LineageVerificationError(f"duplicate archive path: {logical}")
        source_path = binding.get("source_path")
        if not isinstance(source_path, str) or not source_path:
            raise LineageVerificationError(f"missing source path: {logical}")
        if source_path in source_paths:
            raise LineageVerificationError(f"duplicate source path: {source_path}")
        source_paths.add(source_path)
        if not path.is_file():
            raise LineageVerificationError(f"archive file missing: {logical}")
        if path.stat().st_size != binding.get("bytes"):
            raise LineageVerificationError(f"archive byte size mismatch: {logical}")
        digest = sha256_file(path)
        if digest != binding.get("sha256"):
            raise LineageVerificationError(f"archive sha256 mismatch: {logical}")
        observed[logical] = digest

    bound_files = {
        path.relative_to(bundle_dir).as_posix()
        for directory in ARCHIVE_DIRECTORIES
        for path in (bundle_dir / directory).rglob("*")
        if path.is_file()
    }
    if bound_files != set(observed):
        raise LineageVerificationError("archive contains missing or unbound files")

    consumer = manifest.get("consumer")
    if not isinstance(consumer, dict) or not isinstance(
        consumer.get("lineage"), dict
    ):
        raise LineageVerificationError("consumer lineage is missing")
    if consumer.get("path") != CONSUMER_PATH:
        raise LineageVerificationError("consumer path mismatch")
    if consumer.get("audited_main_commit") != AUDITED_MAIN_COMMIT:
        raise LineageVerificationError("consumer audited commit mismatch")
    if consumer.get("source_sha256") != CONSUMER_SOURCE_SHA256:
        raise LineageVerificationError("manifest consumer source sha256 mismatch")
    if consumer.get("sector_map_id") != SECTOR_MAP_ID:
        raise LineageVerificationError("manifest consumer sector map id mismatch")
    if consumer.get("sector_map_sha256") != SECTOR_MAP_SHA256:
        raise LineageVerificationError("manifest consumer sector map sha256 mismatch")
    remote_lineage = consumer["lineage"]
    if set(remote_lineage) != set(SOURCE_LINEAGE):
        raise LineageVerificationError("consumer lineage fields mismatch")
    for consumer_key, archive_path in SOURCE_LINEAGE.items():
        if observed[archive_path] != remote_lineage[consumer_key]:
            raise LineageVerificationError(
                f"consumer lineage mismatch: {consumer_key}"
            )
    consumer_path = ROOT / CONSUMER_PATH
    if consumer_path.is_symlink() or not consumer_path.is_file():
        raise LineageVerificationError("live consumer source is missing or unsafe")
    try:
        consumer_digest = sha256_file(consumer_path)
    except OSError as exc:
        raise LineageVerificationError("live consumer source is unreadable") from exc
    if consumer_digest != CONSUMER_SOURCE_SHA256:
        raise LineageVerificationError("live consumer source sha256 mismatch")
    live_consumer = _consumer_constants(consumer_path)
    if live_consumer["CANDIDATE_ID"] != CANDIDATE_ID:
        raise LineageVerificationError("live consumer candidate id mismatch")
    if live_consumer["FROZEN_RULE_ID"] != FROZEN_RULE_ID:
        raise LineageVerificationError("live consumer frozen rule id mismatch")
    if live_consumer["FROZEN_RULE_SHA256"] != FROZEN_RULE_SHA256:
        raise LineageVerificationError("live consumer frozen rule sha256 mismatch")
    if live_consumer["LINEAGE"] != remote_lineage:
        raise LineageVerificationError("live consumer lineage mismatch")
    if live_consumer["SECTOR_MAP_ID"] != SECTOR_MAP_ID:
        raise LineageVerificationError("live consumer sector map id mismatch")
    if live_consumer["SECTOR_MAP"] != SECTOR_MAP:
        raise LineageVerificationError("live consumer sector map mismatch")
    if sha256_canonical_json(live_consumer["SECTOR_MAP"]) != SECTOR_MAP_SHA256:
        raise LineageVerificationError("live consumer sector map sha256 mismatch")

    freeze = _load_json(
        bundle_dir / "freeze/freeze_contract.json",
        "freeze contract",
    )
    if freeze.get("contract_id") != manifest.get("frozen_rule_id"):
        raise LineageVerificationError("freeze contract id mismatch")
    if freeze.get("fixed_rule_sha256") != manifest.get("frozen_rule_sha256"):
        raise LineageVerificationError("frozen rule sha256 mismatch")
    if freeze.get("candidate_id") != manifest.get("candidate_id"):
        raise LineageVerificationError("freeze candidate id mismatch")
    for field in (
        "network_used",
        "tradable_authorized",
        "shadow_testnet_live_authorized",
        "production_authorized",
    ):
        if freeze.get(field) is not False:
            raise LineageVerificationError(
                f"freeze authority boundary failed: {field}"
            )

    freeze_manifest = _load_json(
        bundle_dir / "freeze/manifest.json",
        "freeze manifest",
    )
    for field in (
        "network_used",
        "tradable_authorized",
        "shadow_testnet_live_authorized",
        "production_authorized",
    ):
        if freeze_manifest.get(field) is not False:
            raise LineageVerificationError(
                f"freeze manifest authority boundary failed: {field}"
            )

    return {
        "status": "PASS",
        "archive_files": len(observed),
        "consumer_source_hashes": 1,
        "source_lineage_hashes": len(SOURCE_LINEAGE),
        "sector_map_products": len(SECTOR_MAP),
        "authority_fields_false": len(AUTHORITY_FIELDS),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=DEFAULT_BUNDLE_DIR,
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        result = verify_bundle(args.bundle_dir)
    except LineageVerificationError as exc:
        print(f"FAIL: {exc}")
        return 1
    print(
        "PASS: "
        f"{result['archive_files']} archived files; "
        f"{result['consumer_source_hashes']} consumer source hash; "
        f"{result['source_lineage_hashes']} consumer lineage hashes; "
        f"{result['sector_map_products']} sector-map products; "
        f"{result['authority_fields_false']} authority fields false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
