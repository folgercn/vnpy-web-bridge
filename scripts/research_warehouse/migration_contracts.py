"""Migration lineage digest preserving logical evidence, not host identities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .backup_contracts import (
    NON_PRESERVED_IDENTITIES,
    PRESERVED_MIGRATION_FIELDS,
    require_relative_path,
    require_sha256,
)
from .canonical import canonical_json, sha256
from .errors import RegistryError


@dataclass(frozen=True)
class MigrationLineage:
    record_count: int
    root_sha256: str
    records: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_count": self.record_count,
            "root_sha256": self.root_sha256,
            "preserved_fields": list(PRESERVED_MIGRATION_FIELDS),
            "non_preserved_identities": list(NON_PRESERVED_IDENTITIES),
            "records": list(self.records),
        }


def migration_lineage(chain: list[dict[str, Any]]) -> MigrationLineage:
    if not chain:
        raise RegistryError("migration requires a non-empty manifest chain")
    by_object: dict[str, dict[str, str]] = {}
    for manifest in chain:
        seal = manifest["batch_seal_sha256"]
        for revision in manifest["revisions"]:
            record = {
                "raw_object_id": revision["object_id"],
                "raw_relative_path": revision["raw_relative_path"],
                "raw_sha256": revision["raw_sha256"],
                "original_batch_seal_sha256": seal,
            }
            existing = by_object.get(revision["object_id"])
            if existing is None:
                by_object[revision["object_id"]] = record
            elif (
                existing["raw_relative_path"] != record["raw_relative_path"]
                or existing["raw_sha256"] != record["raw_sha256"]
            ):
                raise RegistryError("raw object identity changed across manifest chain")
    records = tuple(by_object[key] for key in sorted(by_object))
    root = sha256(
        canonical_json(
            {
                "domain": "vnpy-research-migration-lineage-v1",
                "records": records,
            }
        )
    )
    return MigrationLineage(
        record_count=len(records),
        root_sha256=root,
        records=records,
    )


def parse_migration_lineage(value: object) -> MigrationLineage:
    if not isinstance(value, dict) or set(value) != {
        "record_count",
        "root_sha256",
        "preserved_fields",
        "non_preserved_identities",
        "records",
    }:
        raise RegistryError("migration lineage fields do not match v1")
    if value["preserved_fields"] != list(PRESERVED_MIGRATION_FIELDS):
        raise RegistryError("migration preserved-field claim changed")
    if value["non_preserved_identities"] != list(NON_PRESERVED_IDENTITIES):
        raise RegistryError("migration non-preserved identity claim changed")
    records = value["records"]
    if not isinstance(records, list) or not records:
        raise RegistryError("migration lineage records are empty")
    parsed = []
    seen = set()
    for item in records:
        if not isinstance(item, dict) or set(item) != {
            "raw_object_id",
            "raw_relative_path",
            "raw_sha256",
            "original_batch_seal_sha256",
        }:
            raise RegistryError("migration lineage record is invalid")
        object_id = item["raw_object_id"]
        if not isinstance(object_id, str) or not object_id or object_id in seen:
            raise RegistryError("migration raw object ID is invalid or repeated")
        seen.add(object_id)
        require_relative_path(item["raw_relative_path"])
        if not item["raw_relative_path"].startswith("raw/"):
            raise RegistryError("migration lineage path is not a raw object")
        require_sha256(item["raw_sha256"], "migration raw object")
        require_sha256(
            item["original_batch_seal_sha256"],
            "migration original batch seal",
        )
        parsed.append(dict(item))
    if parsed != sorted(parsed, key=lambda item: item["raw_object_id"]):
        raise RegistryError("migration lineage records are not sorted")
    built_root = sha256(
        canonical_json(
            {
                "domain": "vnpy-research-migration-lineage-v1",
                "records": parsed,
            }
        )
    )
    if (
        value["record_count"] != len(parsed)
        or value["root_sha256"] != built_root
    ):
        raise RegistryError("migration lineage derived values mismatch")
    return MigrationLineage(
        record_count=len(parsed),
        root_sha256=built_root,
        records=tuple(parsed),
    )
