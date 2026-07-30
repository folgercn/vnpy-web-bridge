"""Darwin extended-ACL custody checks for root-owned M2 release objects."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from pathlib import Path

from .errors import RegistryError
from .file_integrity import file_identity

ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0


def require_acl_free_fd(descriptor: int, label: str) -> None:
    """Reject every Darwin extended ACL entry on one already-open object."""
    if sys.platform != "darwin":
        return
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    acl_get_entry.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        error = ctypes.get_errno()
        if error == errno.ENOENT:
            return
        raise RegistryError(f"cannot inspect extended ACL: {label}") from OSError(
            error,
            os.strerror(error),
        )
    try:
        entry = ctypes.c_void_p()
        result = acl_get_entry(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise RegistryError(f"M2 release object has an extended ACL: {label}")
        if result != 1:
            error = ctypes.get_errno()
            raise RegistryError(
                f"cannot enumerate extended ACL: {label}"
            ) from OSError(error, os.strerror(error))
    finally:
        acl_free(acl)


def require_acl_free_path(path: Path, label: str) -> None:
    """Open without following links, bind identity, and require no Darwin ACL."""
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise RegistryError(f"M2 release ACL path is a symlink: {label}")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if stat.S_ISDIR(path_stat.st_mode):
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError(f"cannot open M2 release ACL path: {label}") from exc
    try:
        opened = os.fstat(descriptor)
        if file_identity(path_stat) != file_identity(opened):
            raise RegistryError(f"M2 release ACL path changed: {label}")
        require_acl_free_fd(descriptor, label)
    finally:
        os.close(descriptor)
