from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ResearchLabConfig:
    """Filesystem locations owned by a local Research Lab installation."""

    root: Path

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def database_path(self) -> Path:
        return self.root / "research_lab.sqlite3"

    @property
    def feature_cache_dir(self) -> Path:
        return self.root / "feature_cache"
