from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_MARKER_BYTES = 64 * 1024


class CommodityCFastOneShotCustodyError(ValueError):
    pass


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass(frozen=True)
class OneShotCustodyPins:
    root_path_sha256: str
    identity_sha256: str


@dataclass(frozen=True)
class _RootFacts:
    root: Path
    root_metadata: os.stat_result
    parent_metadata: os.stat_result
    pins: OneShotCustodyPins


def _root_facts(root: Path, expected_owner_uid: int) -> _RootFacts:
    try:
        expanded = root.expanduser()
        if (
            not expanded.is_absolute()
            or Path(os.path.normpath(str(expanded))) != expanded
            or expanded.resolve(strict=True) != expanded
        ):
            raise ValueError
        parent = expanded.parent
        if parent.resolve(strict=True) != parent:
            raise ValueError
        root_metadata = expanded.lstat()
        parent_metadata = parent.lstat()
        root_mode = stat.S_IMODE(root_metadata.st_mode)
        parent_mode = stat.S_IMODE(parent_metadata.st_mode)
        if (
            stat.S_ISLNK(root_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != expected_owner_uid
            or root_mode != 0o700
            or stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != expected_owner_uid
            or parent_mode & 0o022
        ):
            raise ValueError
    except (OSError, ValueError) as exc:
        raise CommodityCFastOneShotCustodyError(
            "C_FAST_ONE_SHOT_CUSTODY_ROOT_INVALID"
        ) from exc
    root_path_sha256 = _sha256(str(expanded).encode("utf-8"))
    identity = {
        "schema_version": "commodity_c_fast_simnow_one_shot_custody_identity_v1",
        "root_path_sha256": root_path_sha256,
        "device": root_metadata.st_dev,
        "inode": root_metadata.st_ino,
        "owner_uid": root_metadata.st_uid,
        "mode": root_mode,
        "parent_device": parent_metadata.st_dev,
        "parent_inode": parent_metadata.st_ino,
        "parent_owner_uid": parent_metadata.st_uid,
        "parent_mode": parent_mode,
    }
    return _RootFacts(
        root=expanded,
        root_metadata=root_metadata,
        parent_metadata=parent_metadata,
        pins=OneShotCustodyPins(
            root_path_sha256=root_path_sha256,
            identity_sha256=_sha256(canonical_json(identity)),
        ),
    )


def one_shot_custody_pins(
    root: Path,
    *,
    expected_owner_uid: int,
) -> OneShotCustodyPins:
    return _root_facts(root, expected_owner_uid).pins


class CommodityCFastOneShotCustody:
    """Identity-pinned create-only marker custody.

    This is not a substitute for external WORM storage. It prevents path and
    directory replacement from silently resetting one-shot state and makes
    each accepted directory entry durable before returning success.
    """

    def __init__(
        self,
        *,
        root: Path,
        expected_root_path_sha256: str,
        expected_identity_sha256: str,
        expected_owner_uid: int,
    ) -> None:
        self.root = root
        self.expected_root_path_sha256 = expected_root_path_sha256
        self.expected_identity_sha256 = expected_identity_sha256
        self.expected_owner_uid = expected_owner_uid

    def path(self, filename: str) -> Path:
        self._validate_filename(filename)
        return self.root.expanduser() / filename

    def read_payload(self, filename: str) -> dict[str, Any] | None:
        self._validate_filename(filename)
        root_fd, opened = self._open_root()
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK
            try:
                file_fd = os.open(
                    filename,
                    flags,
                    dir_fd=root_fd,
                )
            except FileNotFoundError:
                self._assert_root_unchanged(root_fd, opened)
                return None
            try:
                before = os.fstat(file_fd)
                self._validate_marker_metadata(before)
                first = self._read_bounded(file_fd)
                os.lseek(file_fd, 0, os.SEEK_SET)
                second = self._read_bounded(file_fd)
                after = os.fstat(file_fd)
                path_after = os.stat(
                    filename,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                if (
                    len(
                        {
                            _file_identity(before),
                            _file_identity(after),
                            _file_identity(path_after),
                        }
                    )
                    != 1
                    or first != second
                    or len(first) != before.st_size
                ):
                    raise CommodityCFastOneShotCustodyError(
                        "C_FAST_ONE_SHOT_MARKER_CHANGED"
                    )
            finally:
                os.close(file_fd)
            try:
                payload = json.loads(first.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CommodityCFastOneShotCustodyError(
                    "C_FAST_ONE_SHOT_MARKER_BYTES_INVALID"
                ) from exc
            if (
                not isinstance(payload, dict)
                or first != canonical_json(payload) + b"\n"
            ):
                raise CommodityCFastOneShotCustodyError(
                    "C_FAST_ONE_SHOT_MARKER_BYTES_INVALID"
                )
            final_path = os.stat(
                filename,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            if _file_identity(final_path) != _file_identity(path_after):
                raise CommodityCFastOneShotCustodyError(
                    "C_FAST_ONE_SHOT_MARKER_CHANGED"
                )
            self._assert_root_unchanged(root_fd, opened)
            return payload
        except CommodityCFastOneShotCustodyError:
            raise
        except OSError as exc:
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_MARKER_READ_INVALID"
            ) from exc
        finally:
            os.close(root_fd)

    def create_payload(
        self,
        filename: str,
        payload: dict[str, Any],
    ) -> None:
        self._validate_filename(filename)
        raw = canonical_json(payload) + b"\n"
        if not raw or len(raw) > MAX_MARKER_BYTES:
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_MARKER_SIZE_INVALID"
            )
        root_fd, opened = self._open_root()
        file_fd: int | None = None
        try:
            file_fd = os.open(
                filename,
                (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC
                ),
                0o600,
                dir_fd=root_fd,
            )
            os.fchmod(file_fd, 0o600)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(file_fd, remaining)
                if written <= 0:
                    raise OSError("short marker write")
                remaining = remaining[written:]
            os.fsync(file_fd)
            metadata = os.fstat(file_fd)
            self._validate_marker_metadata(metadata)
            path_metadata = os.stat(
                filename,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            if (
                metadata.st_size != len(raw)
                or _file_identity(metadata)
                != _file_identity(path_metadata)
            ):
                raise OSError("marker size changed after write")
            os.close(file_fd)
            file_fd = None
            os.fsync(root_fd)
            durable_path_metadata = os.stat(
                filename,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            if _file_identity(durable_path_metadata) != _file_identity(
                path_metadata
            ):
                raise CommodityCFastOneShotCustodyError(
                    "C_FAST_ONE_SHOT_MARKER_CHANGED"
                )
            self._assert_root_unchanged(root_fd, opened)
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(root_fd)

    def _open_root(self) -> tuple[int, _RootFacts]:
        opened = _root_facts(self.root, self.expected_owner_uid)
        if (
            not hmac.compare_digest(
                opened.pins.root_path_sha256,
                self.expected_root_path_sha256,
            )
            or not hmac.compare_digest(
                opened.pins.identity_sha256,
                self.expected_identity_sha256,
            )
        ):
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_CUSTODY_PIN_MISMATCH"
            )
        try:
            root_fd = os.open(
                opened.root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as exc:
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_CUSTODY_OPEN_INVALID"
            ) from exc
        try:
            if _path_identity(os.fstat(root_fd)) != _path_identity(
                opened.root_metadata
            ):
                raise CommodityCFastOneShotCustodyError(
                    "C_FAST_ONE_SHOT_CUSTODY_CHANGED"
                )
        except (CommodityCFastOneShotCustodyError, OSError):
            os.close(root_fd)
            raise
        return root_fd, opened

    def _assert_root_unchanged(
        self,
        root_fd: int,
        opened: _RootFacts,
    ) -> None:
        current = _root_facts(self.root, self.expected_owner_uid)
        if (
            current.pins != opened.pins
            or _path_identity(os.fstat(root_fd))
            != _path_identity(opened.root_metadata)
            or not hmac.compare_digest(
                current.pins.root_path_sha256,
                self.expected_root_path_sha256,
            )
            or not hmac.compare_digest(
                current.pins.identity_sha256,
                self.expected_identity_sha256,
            )
        ):
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_CUSTODY_CHANGED"
            )

    def _validate_marker_metadata(self, metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.expected_owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_MARKER_BYTES
        ):
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_MARKER_CUSTODY_INVALID"
            )

    @staticmethod
    def _validate_filename(filename: str) -> None:
        if (
            isinstance(filename, str)
            and filename.startswith("acceptance-")
            and len(filename) == len("acceptance-") + 64 + len(".json")
            and filename.endswith(".json")
            and all(char in "0123456789abcdef" for char in filename[11:-5])
        ):
            return
        if (
            isinstance(filename, str)
            and filename.startswith("permit-")
            and len(filename) == len("permit-") + 64 + len(".json")
            and filename.endswith(".json")
            and all(char in "0123456789abcdef" for char in filename[7:-5])
        ):
            return
        raise CommodityCFastOneShotCustodyError(
            "C_FAST_ONE_SHOT_MARKER_FILENAME_INVALID"
        )

    @staticmethod
    def _read_bounded(fd: int) -> bytes:
        chunks: list[bytes] = []
        remaining = MAX_MARKER_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(16 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_MARKER_BYTES:
            raise CommodityCFastOneShotCustodyError(
                "C_FAST_ONE_SHOT_MARKER_SIZE_INVALID"
            )
        return raw
