"""Point-in-time source revision selection from verified batch seals."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .acquisition_models import PitSelection
from .canonical import sha256
from .errors import RegistryError
from .filesystem import WarehousePaths, read_regular_strict
from .manifests import verify_manifest_chain
from .models import SourceRegistry
from .timeutil import parse_utc, require_utc


def select_pit_revision(
    *,
    paths: WarehousePaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    source_id: str,
    trade_day: str,
    cutoff_at: datetime,
) -> PitSelection:
    cutoff = require_utc(cutoff_at, "PIT cutoff")
    chain = verify_manifest_chain(
        paths=paths,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
    )
    eligible_manifests = [
        item
        for item in chain
        if item["trade_day"] == trade_day
        and parse_utc(item["sealed_at"], "sealed_at") <= cutoff
    ]
    if not eligible_manifests:
        raise RegistryError("no verified daily batch existed at PIT cutoff")
    manifest = eligible_manifests[-1]
    candidates = []
    for item in manifest["revisions"]:
        if parse_utc(item["first_seen_at"], "first_seen_at") > cutoff:
            continue
        if (
            item["source_id"] != source_id
            or item["trade_day"] != trade_day
        ):
            continue
        candidates.append(item)
    if not candidates:
        raise RegistryError("no source revision existed at PIT cutoff")
    selected = max(
        candidates,
        key=lambda item: (item["revision_sequence"], item["revision_id"]),
    )
    raw_path = paths.root / selected["raw_relative_path"]
    raw = read_regular_strict(raw_path, "PIT selected raw object")
    if (
        len(raw) != selected["raw_bytes"]
        or sha256(raw) != selected["raw_sha256"]
    ):
        raise RegistryError("PIT selected raw object changed after verification")
    return PitSelection(
        object_id=selected["object_id"],
        revision_id=selected["revision_id"],
        raw_sha256=selected["raw_sha256"],
        raw_bytes=selected["raw_bytes"],
        raw_path=raw_path,
        raw_content=raw,
        first_seen_at=parse_utc(selected["first_seen_at"], "first_seen_at"),
        batch_id=manifest["batch_id"],
        batch_seal_sha256=manifest["batch_seal_sha256"],
    )
