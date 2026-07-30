"""Typed contracts shared by Research backup, restore, and migration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json, sha256
from .errors import RegistryError
from .manifest_contracts import SHA256_PATTERN

BACKUP_ANCHOR_SCHEMA = "vnpy_research_backup_anchor_v1"
BACKUP_PURPOSE = "RESEARCH_EVIDENCE_APPEND_ONLY_BACKUP"
MIGRATION_RECEIPT_SCHEMA = "vnpy_research_migration_receipt_v1"
MIGRATION_PURPOSE = "RESEARCH_EVIDENCE_CUSTODY_MIGRATION"
ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
RELATIVE_PATTERN = re.compile(
    r"^(?:raw|manifests)/[A-Za-z0-9._/-]{1,900}$"
)
AUTHORITY_FIELDS = (
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "network_authorized",
    "rpc_authorized",
    "order_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "production_authorized",
)
PRESERVED_MIGRATION_FIELDS = (
    "raw_object_id",
    "raw_relative_path",
    "raw_sha256",
    "original_batch_seal_sha256",
)
NON_PRESERVED_IDENTITIES = (
    "absolute_path",
    "device",
    "host",
    "inode",
)


def false_authority() -> dict[str, bool]:
    return {field: False for field in AUTHORITY_FIELDS}


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise RegistryError(f"{label} must be a lowercase SHA256")
    return value


def require_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None:
        raise RegistryError(f"{label} is invalid")
    return value


def require_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or RELATIVE_PATTERN.fullmatch(value) is None
        or "//" in value
        or value.endswith("/")
        or any(component in {"", ".", ".."} for component in value.split("/"))
    ):
        raise RegistryError("backup relative path is unsafe")
    return value


@dataclass(frozen=True, order=True)
class InventoryEntry:
    relative_path: str
    kind: str
    byte_count: int
    raw_sha256: str

    def __post_init__(self) -> None:
        require_relative_path(self.relative_path)
        if self.kind not in {"manifest", "raw"}:
            raise RegistryError("backup object kind is invalid")
        if self.relative_path.split("/", 1)[0] != (
            "raw" if self.kind == "raw" else "manifests"
        ):
            raise RegistryError("backup object kind/path mismatch")
        if (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 1
        ):
            raise RegistryError("backup object byte count is invalid")
        require_sha256(self.raw_sha256, "backup object hash")

    def as_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "bytes": self.byte_count,
            "raw_sha256": self.raw_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> InventoryEntry:
        if not isinstance(value, dict) or set(value) != {
            "relative_path",
            "kind",
            "bytes",
            "raw_sha256",
        }:
            raise RegistryError("backup inventory entry fields do not match v1")
        return cls(
            relative_path=require_relative_path(value["relative_path"]),
            kind=value["kind"],
            byte_count=value["bytes"],
            raw_sha256=value["raw_sha256"],
        )


@dataclass(frozen=True)
class WarehouseSnapshot:
    entries: tuple[InventoryEntry, ...]
    root_sha256: str
    object_count: int
    total_bytes: int
    raw_object_count: int
    manifest_object_count: int

    @classmethod
    def build(cls, entries: tuple[InventoryEntry, ...]) -> WarehouseSnapshot:
        if not entries or tuple(sorted(entries)) != entries:
            raise RegistryError("backup inventory must be non-empty and sorted")
        paths = [entry.relative_path for entry in entries]
        if len(set(paths)) != len(paths):
            raise RegistryError("backup inventory repeats a relative path")
        raw_count = sum(entry.kind == "raw" for entry in entries)
        manifest_count = sum(entry.kind == "manifest" for entry in entries)
        if not raw_count or not manifest_count:
            raise RegistryError("backup snapshot requires raw and manifest objects")
        root = sha256(
            canonical_json(
                {
                    "domain": "vnpy-research-warehouse-snapshot-v1",
                    "objects": [entry.as_dict() for entry in entries],
                }
            )
        )
        return cls(
            entries=entries,
            root_sha256=root,
            object_count=len(entries),
            total_bytes=sum(entry.byte_count for entry in entries),
            raw_object_count=raw_count,
            manifest_object_count=manifest_count,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_sha256": self.root_sha256,
            "object_count": self.object_count,
            "total_bytes": self.total_bytes,
            "raw_object_count": self.raw_object_count,
            "manifest_object_count": self.manifest_object_count,
            "objects": [entry.as_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, value: object) -> WarehouseSnapshot:
        if not isinstance(value, dict) or set(value) != {
            "root_sha256",
            "object_count",
            "total_bytes",
            "raw_object_count",
            "manifest_object_count",
            "objects",
        }:
            raise RegistryError("backup snapshot fields do not match v1")
        objects = value["objects"]
        if not isinstance(objects, list):
            raise RegistryError("backup snapshot objects must be a list")
        built = cls.build(tuple(InventoryEntry.from_dict(item) for item in objects))
        if built.as_dict() != value:
            raise RegistryError("backup snapshot derived values mismatch")
        return built


@dataclass(frozen=True)
class RebuildFingerprint:
    registry_raw_sha256: str
    commit_anchor_ledger_sha256: str
    genesis_batch_seal_sha256: str
    head_batch_seal_sha256: str
    head_commit_seal_sha256: str
    tool_commit_sha: str
    dependency_lock_sha256: str
    catalog_logical_sha256: str
    partition_hashes: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("registry", self.registry_raw_sha256),
            ("commit anchor ledger", self.commit_anchor_ledger_sha256),
            ("genesis batch seal", self.genesis_batch_seal_sha256),
            ("head batch seal", self.head_batch_seal_sha256),
            ("head commit seal", self.head_commit_seal_sha256),
            ("dependency lock", self.dependency_lock_sha256),
            ("catalog logical", self.catalog_logical_sha256),
        ):
            require_sha256(value, f"rebuild {label}")
        if not re.fullmatch(r"[0-9a-f]{40}", self.tool_commit_sha):
            raise RegistryError("rebuild tool commit is invalid")
        if not self.partition_hashes:
            raise RegistryError("rebuild fingerprint requires Parquet partitions")
        if tuple(sorted(self.partition_hashes)) != self.partition_hashes:
            raise RegistryError("rebuild partition hashes must be sorted")
        paths = set()
        for path, digest in self.partition_hashes:
            if (
                not isinstance(path, str)
                or not path.startswith("parquet/")
                or ".." in path.split("/")
                or path in paths
            ):
                raise RegistryError("rebuild Parquet path is unsafe or repeated")
            paths.add(path)
            require_sha256(digest, "rebuild Parquet hash")

    def as_dict(self) -> dict[str, Any]:
        return {
            "registry_raw_sha256": self.registry_raw_sha256,
            "commit_anchor_ledger_sha256": self.commit_anchor_ledger_sha256,
            "genesis_batch_seal_sha256": self.genesis_batch_seal_sha256,
            "head_batch_seal_sha256": self.head_batch_seal_sha256,
            "head_commit_seal_sha256": self.head_commit_seal_sha256,
            "tool_commit_sha": self.tool_commit_sha,
            "dependency_lock_sha256": self.dependency_lock_sha256,
            "catalog_logical_sha256": self.catalog_logical_sha256,
            "partition_hashes": [
                {"relative_path": path, "raw_sha256": digest}
                for path, digest in self.partition_hashes
            ],
        }

    @classmethod
    def from_dict(cls, value: object) -> RebuildFingerprint:
        keys = {
            "registry_raw_sha256",
            "commit_anchor_ledger_sha256",
            "genesis_batch_seal_sha256",
            "head_batch_seal_sha256",
            "head_commit_seal_sha256",
            "tool_commit_sha",
            "dependency_lock_sha256",
            "catalog_logical_sha256",
            "partition_hashes",
        }
        if not isinstance(value, dict) or set(value) != keys:
            raise RegistryError("rebuild fingerprint fields do not match v1")
        partitions = value["partition_hashes"]
        if not isinstance(partitions, list):
            raise RegistryError("rebuild partition hashes must be a list")
        parsed: list[tuple[str, str]] = []
        for item in partitions:
            if not isinstance(item, dict) or set(item) != {
                "relative_path",
                "raw_sha256",
            }:
                raise RegistryError("rebuild partition entry is invalid")
            parsed.append((item["relative_path"], item["raw_sha256"]))
        result = cls(
            registry_raw_sha256=value["registry_raw_sha256"],
            commit_anchor_ledger_sha256=value["commit_anchor_ledger_sha256"],
            genesis_batch_seal_sha256=value["genesis_batch_seal_sha256"],
            head_batch_seal_sha256=value["head_batch_seal_sha256"],
            head_commit_seal_sha256=value["head_commit_seal_sha256"],
            tool_commit_sha=value["tool_commit_sha"],
            dependency_lock_sha256=value["dependency_lock_sha256"],
            catalog_logical_sha256=value["catalog_logical_sha256"],
            partition_hashes=tuple(parsed),
        )
        if result.as_dict() != value:
            raise RegistryError("rebuild fingerprint is not canonical")
        return result
