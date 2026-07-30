"""Cross-process durable request-start limiter for official-source HTTP."""

from __future__ import annotations

import fcntl
import math
import os
import stat
import tempfile
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from .canonical import canonical_json_line, parse_json_strict
from .clock_quality import TrustedClockSample
from .custody_paths import require_private_dir
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all
from .timeutil import format_utc, parse_utc

LOCK_BYTES = b"vnpy-research-official-source-rate-limit-v1\n"
STATE_SCHEMA = "vnpy_research_official_source_rate_limit_v1"


class PersistentRequestGate:
    def __init__(
        self,
        runtime_root: Path,
        *,
        minimum_interval_seconds: float,
        clock_provider: Callable[[], TrustedClockSample],
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            isinstance(minimum_interval_seconds, bool)
            or not isinstance(minimum_interval_seconds, (int, float))
            or not math.isfinite(minimum_interval_seconds)
            or minimum_interval_seconds <= 0
            or minimum_interval_seconds > 3600
        ):
            raise RegistryError(
                "persistent request interval must be greater than 0 and at most 3600"
            )
        require_private_dir(runtime_root, "M2 request-gate runtime root")
        self.root = runtime_root
        self.minimum_interval_seconds = float(minimum_interval_seconds)
        self.clock_provider = clock_provider
        self.sleeper = sleeper
        self.lock_path = runtime_root / "official-source-rate-limit.lock"
        self.state_path = runtime_root / "official-source-rate-limit.json"
        self._ensure_lock()

    def _ensure_lock(self) -> None:
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            raw = read_regular_strict(
                self.lock_path,
                "M2 official-source rate lock",
            )
            if raw != LOCK_BYTES:
                raise RegistryError("M2 official-source rate lock mismatch")
            return
        try:
            write_all(descriptor, LOCK_BYTES)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_dir(self.root)

    def _state(self):
        if not self.state_path.exists():
            return None
        raw = read_regular_strict(
            self.state_path,
            "M2 official-source rate state",
        )
        payload = parse_json_strict(raw, "M2 official-source rate state")
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "last_request_started_at"}
            or payload["schema_version"] != STATE_SCHEMA
            or raw != canonical_json_line(payload)
        ):
            raise RegistryError("M2 official-source rate state mismatch")
        return parse_utc(
            payload["last_request_started_at"],
            "last official-source request start",
        )

    def _write_state(self, sample: TrustedClockSample) -> None:
        raw = canonical_json_line(
            {
                "schema_version": STATE_SCHEMA,
                "last_request_started_at": format_utc(
                    sample.trusted_now,
                    "official-source request start",
                ),
            }
        )
        descriptor, name = tempfile.mkstemp(
            prefix=".official-source-rate-limit-",
            suffix=".partial",
            dir=self.root,
        )
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            write_all(descriptor, raw)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if self.state_path.exists():
                read_regular_strict(
                    self.state_path,
                    "M2 official-source rate state",
                )
            os.replace(temporary, self.state_path)
            fsync_dir(self.root)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @contextmanager
    def request(self):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        path_before = self.lock_path.lstat()
        descriptor = os.open(self.lock_path, flags)
        try:
            facts = os.fstat(descriptor)
            path_after = self.lock_path.lstat()
            if (
                stat.S_ISLNK(path_before.st_mode)
                or not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or stat.S_IMODE(facts.st_mode) != 0o600
                or facts.st_nlink != 1
                or (path_before.st_dev, path_before.st_ino)
                != (facts.st_dev, facts.st_ino)
                or (path_after.st_dev, path_after.st_ino)
                != (facts.st_dev, facts.st_ino)
            ):
                raise RegistryError("M2 official-source rate lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            previous = self._state()
            while True:
                sample = self.clock_provider()
                if previous is None:
                    break
                elapsed = (sample.trusted_now - previous).total_seconds()
                if elapsed < 0:
                    raise RegistryError(
                        "official-source request clock moved backwards"
                    )
                remaining = self.minimum_interval_seconds - elapsed
                if remaining <= 0:
                    break
                self.sleeper(remaining)
            self._write_state(sample)
            yield sample
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
