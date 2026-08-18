"""Private M2 operational runtime paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .custody_paths import normalized_absolute, require_private_dir
from .errors import RegistryError


@dataclass(frozen=True)
class RuntimePaths:
    root: Path
    run_receipts: Path
    history_run_receipts: Path
    backfill_receipts: Path
    monitor_receipts: Path
    temporary: Path

    @classmethod
    def open(cls, root: Path) -> RuntimePaths:
        """Open the complete private runtime layout without creating it."""

        absolute = normalized_absolute(root)
        require_private_dir(absolute, "M2 runtime root")
        values = {
            name: absolute / name
            for name in (
                "run-receipts",
                "history-run-receipts",
                "backfill-receipts",
                "monitor-receipts",
                "tmp",
            )
        }
        root_device = absolute.lstat().st_dev
        for path in values.values():
            info = require_private_dir(path, "M2 runtime directory")
            if info.st_dev != root_device:
                raise RegistryError("M2 runtime paths must share one filesystem")
        return cls(
            root=absolute,
            run_receipts=values["run-receipts"],
            history_run_receipts=values["history-run-receipts"],
            backfill_receipts=values["backfill-receipts"],
            monitor_receipts=values["monitor-receipts"],
            temporary=values["tmp"],
        )

    @classmethod
    def ensure(cls, root: Path) -> RuntimePaths:
        absolute = normalized_absolute(root)
        if not absolute.exists():
            absolute.mkdir(mode=0o700)
        require_private_dir(absolute, "M2 runtime root")
        values = {
            name: absolute / name
            for name in (
                "run-receipts",
                "history-run-receipts",
                "backfill-receipts",
                "monitor-receipts",
                "tmp",
            )
        }
        for path in values.values():
            if not path.exists():
                path.mkdir(mode=0o700)
            require_private_dir(path, "M2 runtime directory")
            if path.lstat().st_dev != absolute.lstat().st_dev:
                raise RegistryError("M2 runtime paths must share one filesystem")
        return cls(
            root=absolute,
            run_receipts=values["run-receipts"],
            history_run_receipts=values["history-run-receipts"],
            backfill_receipts=values["backfill-receipts"],
            monitor_receipts=values["monitor-receipts"],
            temporary=values["tmp"],
        )
