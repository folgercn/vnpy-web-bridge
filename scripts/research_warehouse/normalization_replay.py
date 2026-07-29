"""Normalize signed revision snapshots and independently replay expectations."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .derived_paths import DerivedPaths
from .errors import RegistryError
from .filesystem import WarehousePaths
from .models import SourceRegistry
from .normalization_models import NormalizationBinding, NormalizedArtifact
from .normalizer import normalize_revision
from .revision_snapshots import latest_revision_snapshots


def normalize_chain(
    *,
    evidence: WarehousePaths,
    derived: DerivedPaths,
    chain: list[dict[str, Any]],
    registry: SourceRegistry,
    binding: NormalizationBinding,
) -> list[NormalizedArtifact]:
    artifacts = []
    for snapshot in latest_revision_snapshots(chain):
        revision = snapshot.revision
        try:
            source = registry.source(revision["source_id"])
        except KeyError as exc:
            raise RegistryError("signed revision source is not trusted") from exc
        artifacts.append(
            normalize_revision(
                evidence_root=evidence.root,
                derived=derived,
                revision=revision,
                source=source,
                binding=binding,
            )
        )
    return artifacts


def replay_expected_artifacts(
    *,
    evidence: WarehousePaths,
    chain: list[dict[str, Any]],
    registry: SourceRegistry,
    binding: NormalizationBinding,
) -> list[NormalizedArtifact]:
    with tempfile.TemporaryDirectory(prefix="research-normalization-replay-") as root:
        derived = DerivedPaths.initialize(Path(root) / "derived")
        return normalize_chain(
            evidence=evidence,
            derived=derived,
            chain=chain,
            registry=registry,
            binding=binding,
        )
