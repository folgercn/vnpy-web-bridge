"""Root-owned shared/exclusive lock for M2 release verification and updates."""

from __future__ import annotations

import fcntl
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import RegistryError
from .file_integrity import file_identity


@dataclass(frozen=True)
class ReleaseLockIdentity:
    path: str
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: str
    nlink: int

    def as_dict(self) -> dict[str, int | str]:
        return asdict(self)


class HeldReleaseLock:
    def __init__(
        self,
        path: Path,
        *,
        exclusive: bool,
        expected_owner_uid: int = 0,
        expected_owner_gid: int = 0,
    ) -> None:
        self.path = path
        self.exclusive = exclusive
        self.expected_owner_uid = expected_owner_uid
        self.expected_owner_gid = expected_owner_gid
        self.fd: int | None = None
        self._identity: tuple[int, ...] | None = None
        self.identity: ReleaseLockIdentity | None = None

    def __enter__(self) -> HeldReleaseLock:  # noqa: PYI034
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            path_stat = self.path.lstat()
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise RegistryError("M2 release deployment lock is unavailable") from exc
        try:
            opened = os.fstat(descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise RegistryError("cannot stat M2 release deployment lock") from exc
        if (
            file_identity(path_stat) != file_identity(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != self.expected_owner_uid
            or opened.st_gid != self.expected_owner_gid
            or stat.S_IMODE(opened.st_mode) != 0o444
            or opened.st_nlink != 1
        ):
            os.close(descriptor)
            raise RegistryError("M2 release deployment lock custody mismatch")
        operation = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH | fcntl.LOCK_NB
        try:
            fcntl.flock(descriptor, operation)
        except OSError as exc:
            os.close(descriptor)
            raise RegistryError("cannot acquire M2 release deployment lock") from exc
        self.fd = descriptor
        self._identity = file_identity(opened)
        self.identity = ReleaseLockIdentity(
            path=str(self.path),
            device=opened.st_dev,
            inode=opened.st_ino,
            owner_uid=opened.st_uid,
            owner_gid=opened.st_gid,
            mode=f"{stat.S_IMODE(opened.st_mode):04o}",
            nlink=opened.st_nlink,
        )
        return self

    def revalidate(self) -> None:
        if self.fd is None or self._identity is None:
            raise RegistryError("M2 release deployment lock is not held")
        try:
            held = os.fstat(self.fd)
            path_stat = self.path.lstat()
        except OSError as exc:
            raise RegistryError("M2 release deployment lock disappeared") from exc
        if (
            file_identity(held) != self._identity
            or file_identity(path_stat) != self._identity
        ):
            raise RegistryError("M2 release deployment lock identity changed")

    def __exit__(self, *_args: object) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


def hold_release_verification_lock(
    path: Path,
    *,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
) -> HeldReleaseLock:
    return HeldReleaseLock(
        path,
        exclusive=False,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )


def hold_release_update_lock(
    path: Path,
    *,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
) -> HeldReleaseLock:
    return HeldReleaseLock(
        path,
        exclusive=True,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )
