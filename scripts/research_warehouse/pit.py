"""Point-in-time source revision selection from verified batch seals."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .acquisition_models import PitSelection
from .canonical import parse_json_strict
from .errors import RegistryError
from .filesystem import WarehousePaths, read_regular_strict
from .manifests import verify_manifest_chain
from .timeutil import parse_utc, require_utc


def select_pit_revision(
    *,
    paths: WarehousePaths,
    public_key_path: Path,
    source_id: str,
    trade_day: str,
    cutoff_at: datetime,
) -> PitSelection:
    cutoff = require_utc(cutoff_at, "PIT cutoff")
    chain = verify_manifest_chain(
        paths=paths,
        public_key_path=public_key_path,
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
    observations_by_id = set(manifest["observation_ids"])
    candidates = []
    for item in manifest["objects"]:
        if parse_utc(item["first_seen_at"], "first_seen_at") > cutoff:
            continue
        # Object IDs are source/day bound; the source is proven by observation.
        observation_paths = list(paths.observations.rglob(f"{item['observation_ids'][0]}.json"))
        if len(observation_paths) != 1:
            raise RegistryError("PIT object observation receipt is unavailable")
        observation = parse_json_strict(
            read_regular_strict(
                observation_paths[0], "PIT observation receipt", limit=2 * 1024 * 1024
            ),
            "PIT observation receipt",
        )
        if (
            observation["observation_id"] not in observations_by_id
            or observation["source_id"] != source_id
            or observation["trade_day"] != trade_day
        ):
            continue
        candidates.append(item)
    if not candidates:
        raise RegistryError("no source revision existed at PIT cutoff")
    selected = max(
        candidates,
        key=lambda item: (item["first_seen_at"], item["object_id"]),
    )
    raw_path = paths.root / selected["raw_relative_path"]
    return PitSelection(
        object_id=selected["object_id"],
        raw_sha256=selected["raw_sha256"],
        raw_bytes=selected["raw_bytes"],
        raw_path=raw_path,
        first_seen_at=parse_utc(selected["first_seen_at"], "first_seen_at"),
        batch_id=manifest["batch_id"],
        batch_seal_sha256=manifest["batch_seal_sha256"],
    )
