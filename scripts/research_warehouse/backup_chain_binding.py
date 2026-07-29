"""Bind a backup inventory to the complete committed manifest chain."""

from __future__ import annotations

from typing import Any

from .backup_contracts import WarehouseSnapshot
from .errors import RegistryError


def require_complete_chain_snapshot(
    snapshot: WarehouseSnapshot,
    chain: list[dict[str, Any]],
) -> None:
    if not chain:
        raise RegistryError("backup requires a non-empty committed chain")
    expected_raw = {
        revision["raw_relative_path"]
        for manifest in chain
        for revision in manifest["revisions"]
    }
    expected_manifests = {
        relative
        for manifest in chain
        for relative in (
            f"manifests/{manifest['trade_day']}/{manifest['batch_id']}.json",
            (
                f"manifests/{manifest['trade_day']}/"
                f"commit-{manifest['batch_id']}.json"
            ),
        )
    }
    actual_raw = {
        entry.relative_path for entry in snapshot.entries if entry.kind == "raw"
    }
    actual_manifests = {
        entry.relative_path
        for entry in snapshot.entries
        if entry.kind == "manifest"
    }
    if actual_raw != expected_raw:
        raise RegistryError("backup raw inventory is not the exact sealed-chain union")
    if actual_manifests != expected_manifests:
        raise RegistryError(
            "backup manifest inventory is not the exact committed chain"
        )
