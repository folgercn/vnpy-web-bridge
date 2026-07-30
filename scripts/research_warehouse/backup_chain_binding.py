"""Bind a backup inventory to the complete committed manifest chain."""

from __future__ import annotations

from typing import Any

from .backup_contracts import InventoryEntry, WarehouseSnapshot
from .canonical import canonical_json_line, sha256
from .errors import RegistryError


def require_complete_chain_snapshot(
    snapshot: WarehouseSnapshot,
    chain: list[dict[str, Any]],
) -> None:
    if not chain:
        raise RegistryError("backup requires a non-empty committed chain")
    expected: dict[str, InventoryEntry] = {}
    for manifest in chain:
        for revision in manifest["revisions"]:
            entry = InventoryEntry(
                relative_path=revision["raw_relative_path"],
                kind="raw",
                byte_count=revision["raw_bytes"],
                raw_sha256=revision["raw_sha256"],
            )
            prior = expected.setdefault(entry.relative_path, entry)
            if prior != entry:
                raise RegistryError("sealed raw object binding changed in chain")
        manifest_payload = {
            key: value
            for key, value in manifest.items()
            if key not in {"commit_receipt", "commit_seal_sha256"}
        }
        manifest_raw = canonical_json_line(manifest_payload)
        manifest_path = (
            f"manifests/{manifest['trade_day']}/{manifest['batch_id']}.json"
        )
        expected[manifest_path] = InventoryEntry(
            relative_path=manifest_path,
            kind="manifest",
            byte_count=len(manifest_raw),
            raw_sha256=sha256(manifest_raw),
        )
        receipt_raw = canonical_json_line(manifest["commit_receipt"])
        receipt_path = (
            f"manifests/{manifest['trade_day']}/"
            f"commit-{manifest['batch_id']}.json"
        )
        if sha256(receipt_raw) != manifest["commit_seal_sha256"]:
            raise RegistryError("commit receipt raw binding changed in chain")
        expected[receipt_path] = InventoryEntry(
            relative_path=receipt_path,
            kind="manifest",
            byte_count=len(receipt_raw),
            raw_sha256=manifest["commit_seal_sha256"],
        )
    actual = {entry.relative_path: entry for entry in snapshot.entries}
    if actual != expected:
        raise RegistryError(
            "backup inventory is not the exact committed-chain byte union"
        )
