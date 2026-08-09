"""Handle-anchored filesystem facts for durable-fence store recovery."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self

MAX_FOUNDATION_STATE_BYTES = 1024 * 1024
_WINDOWS_MUTATING_ACCESS_MASK = 0x500D0116 | 0x40  # includes FILE_DELETE_CHILD


def _access_mask_can_mutate(mask: int) -> bool:
    return bool(mask & _WINDOWS_MUTATING_ACCESS_MASK)


@dataclass(frozen=True)
class PathSecurityFacts:
    path_sha256: str
    volume_serial: str
    volume_identity_sha256: str
    file_identity: str
    owner_sid_sha256: str
    acl_sddl_sha256: str
    unsafe_write_principals: tuple[str, ...]
    write_principal_sid_sha256s: tuple[str, ...]
    regular_file: bool
    directory: bool
    reparse_point: bool
    parent_chain_reparse_free: bool
    hardlink_count: int
    alternate_data_streams: bool
    dacl_protected: bool
    inherited_ace_count: int


@dataclass(frozen=True)
class SecureFileRead:
    raw: bytes
    facts: PathSecurityFacts


@dataclass(frozen=True)
class SecureDirectoryInventory:
    names: tuple[str, ...]
    facts: PathSecurityFacts


class FilesystemFactsAdapter(Protocol):
    """Facts and bytes captured through the same opened object handle."""

    def inspect(self, path: Path) -> PathSecurityFacts: ...

    def read_file(
        self, path: Path, *, maximum_bytes: int = MAX_FOUNDATION_STATE_BYTES
    ) -> SecureFileRead: ...

    def list_directory(self, path: Path) -> SecureDirectoryInventory: ...

    def resolve_service_sid_sha256(self, service_name: str) -> str: ...


class PortableFilesystemFactsAdapter:
    """Conservative non-Windows adapter used for diagnostics and tests.

    POSIX ownership/mode is never promoted to Windows SID/DACL evidence, so a
    production expectation cannot accidentally become ready with this class.
    """

    def inspect(self, path: Path) -> PathSecurityFacts:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        if path.is_dir():
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            return self._facts(path, os.fstat(descriptor))
        finally:
            os.close(descriptor)

    def read_file(
        self, path: Path, *, maximum_bytes: int = MAX_FOUNDATION_STATE_BYTES
    ) -> SecureFileRead:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if before.st_size > maximum_bytes:
                raise OSError("foundation state exceeds size bound")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                _stat_identity(before) != _stat_identity(after)
                or len(raw) > maximum_bytes
            ):
                raise OSError("foundation state changed during read or exceeds bound")
            return SecureFileRead(raw=raw, facts=self._facts(path, after))
        finally:
            os.close(descriptor)

    def list_directory(self, path: Path) -> SecureDirectoryInventory:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            before = os.fstat(descriptor)
            names = tuple(sorted(os.listdir(descriptor)))
            after = os.fstat(descriptor)
            if _stat_identity(before) != _stat_identity(after):
                raise OSError("foundation directory changed during inventory")
            return SecureDirectoryInventory(names=names, facts=self._facts(path, after))
        finally:
            os.close(descriptor)

    def resolve_service_sid_sha256(self, service_name: str) -> str:
        del service_name
        raise OSError("Windows service SID facts are unavailable")

    def _facts(self, path: Path, info: os.stat_result) -> PathSecurityFacts:
        absolute = path.absolute()
        reparse = stat.S_ISLNK(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        volume_serial = f"{info.st_dev & 0xFFFFFFFF:08X}"
        return PathSecurityFacts(
            path_sha256=_path_sha256(absolute),
            volume_serial=volume_serial,
            volume_identity_sha256=hashlib.sha256(
                f"portable-device:{info.st_dev}".encode("ascii")
            ).hexdigest(),
            file_identity=f"{info.st_dev}:{info.st_ino}",
            owner_sid_sha256="",
            acl_sddl_sha256="",
            unsafe_write_principals=("ACL_FACTS_UNAVAILABLE",),
            write_principal_sid_sha256s=(),
            regular_file=stat.S_ISREG(info.st_mode),
            directory=stat.S_ISDIR(info.st_mode),
            reparse_point=reparse,
            parent_chain_reparse_free=_parent_chain_reparse_free(absolute),
            hardlink_count=info.st_nlink,
            alternate_data_streams=False,
            dacl_protected=False,
            inherited_ace_count=-1,
        )


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns)


def _path_sha256(path: Path) -> str:
    return hashlib.sha256(str(path.absolute()).encode("utf-8")).hexdigest()


def _parent_chain_reparse_free(path: Path) -> bool:
    current = path
    while True:
        try:
            if current.is_symlink():
                return False
        except OSError:
            return False
        parent = current.parent
        if parent == current:
            return True
        current = parent


if os.name == "nt":  # pragma: win32 cover
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _INVALID_HANDLE = wintypes.HANDLE(-1).value
    _FILE_READ_ATTRIBUTES = 0x0080
    _READ_CONTROL = 0x00020000
    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_SHARE_ALL = 0x00000007
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _DELETE = 0x00010000
    _WRITE_DAC = 0x00040000
    _WRITE_OWNER = 0x00080000
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _OPEN_REPARSE_BACKUP = 0x02200000
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_DISPOSITION_INFO = 4
    _FILE_RENAME_INFO = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x10
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _OWNER_SECURITY_INFORMATION = 0x1
    _DACL_SECURITY_INFORMATION = 0x4
    _SE_FILE_OBJECT = 1
    _SE_DACL_PROTECTED = 0x1000
    _INHERITED_ACE = 0x10
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _ACCESS_ALLOWED_OBJECT_ACE_TYPE = 5
    _ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 9
    _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 11
    _ACCESS_ALLOWED_ACE_TYPES = {0, 4, 5, 9, 11}
    _ACE_OBJECT_TYPE_PRESENT = 0x1
    _ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
    _BROAD_WRITE_SIDS = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("access_time", wintypes.FILETIME),
            ("write_time", wintypes.FILETIME),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ace_count", wintypes.DWORD),
            ("acl_bytes_in_use", wintypes.DWORD),
            ("acl_bytes_free", wintypes.DWORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("ace_type", ctypes.c_ubyte),
            ("ace_flags", ctypes.c_ubyte),
            ("ace_size", wintypes.WORD),
        ]

    class _FILE_ID_BOTH_DIR_INFO(ctypes.Structure):
        _fields_ = [
            ("next_entry_offset", wintypes.DWORD),
            ("file_index", wintypes.DWORD),
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("end_of_file", ctypes.c_longlong),
            ("allocation_size", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
            ("file_name_length", wintypes.DWORD),
            ("ea_size", wintypes.DWORD),
            ("short_name_length", ctypes.c_ubyte),
            ("reserved", ctypes.c_ubyte),
            ("short_name", wintypes.WCHAR * 12),
            ("file_id", ctypes.c_longlong),
            ("file_name", wintypes.WCHAR * 1),
        ]

    class _FILE_STREAM_INFO(ctypes.Structure):
        _fields_ = [
            ("next_entry_offset", wintypes.DWORD),
            ("stream_name_length", wintypes.DWORD),
            ("stream_size", ctypes.c_longlong),
            ("stream_allocation_size", ctypes.c_longlong),
            ("stream_name", wintypes.WCHAR * 1),
        ]

    class _FILE_RENAME_INFO_V1(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", ctypes.c_ubyte),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL
    _kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetSecurityInfo.restype = wintypes.DWORD
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    _advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    _advapi32.GetAclInformation.restype = wintypes.BOOL
    _advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetAce.restype = wintypes.BOOL
    _advapi32.LookupAccountNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.LookupAccountNameW.restype = wintypes.BOOL


class WindowsFilesystemFactsAdapter:
    """Windows adapter using opened handles for bytes, identity, ACL and listing."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("WindowsFilesystemFactsAdapter requires Windows")

    def inspect(self, path: Path) -> PathSecurityFacts:
        handle = self._open(path, directory=False, read_data=False)
        try:
            return self._facts(handle, path)
        finally:
            _kernel32.CloseHandle(handle)

    def read_file(
        self, path: Path, *, maximum_bytes: int = MAX_FOUNDATION_STATE_BYTES
    ) -> SecureFileRead:
        handle = self._open(path, directory=False, read_data=True)
        try:
            before = self._handle_info(handle)
            size = (before.size_high << 32) | before.size_low
            if size > maximum_bytes:
                raise OSError("foundation state exceeds size bound")
            raw = self._read_exact(handle, size)
            after = self._handle_info(handle)
            if self._identity(before) != self._identity(after):
                raise OSError("foundation state changed during handle read")
            return SecureFileRead(raw=raw, facts=self._facts(handle, path, info=after))
        finally:
            _kernel32.CloseHandle(handle)

    def list_directory(self, path: Path) -> SecureDirectoryInventory:
        handle = self._open(path, directory=True, read_data=True)
        try:
            before = self._handle_info(handle)
            names = self._directory_names(handle)
            after = self._handle_info(handle)
            if self._identity(before) != self._identity(after):
                raise OSError("foundation directory changed during handle inventory")
            return SecureDirectoryInventory(
                names=tuple(sorted(names)), facts=self._facts(handle, path, info=after)
            )
        finally:
            _kernel32.CloseHandle(handle)

    def open_directory_anchor(self, path: Path) -> WindowsOpenedDirectoryAnchorV1:
        """Keep an opened parent handle and reject path substitution on use.

        Windows mutating APIs used by the legacy Python surface still take a
        pathname.  Callers therefore retain this parent handle throughout a
        publish and prove the named parent is the same object immediately
        before and after every mutating boundary.  A caller may not treat a
        successful pathname operation as safe without these identity checks.
        """
        return WindowsOpenedDirectoryAnchorV1(self, path)

    def write_file_create_only(
        self, path: Path, *, raw: bytes, protected_sddl: str
    ) -> SecureFileRead:
        """Write once through CreateFileW and read/fact-check that same handle."""
        if not raw:
            raise OSError("empty create-only file is not allowed")
        handle = _kernel32.CreateFileW(
            str(path.absolute()),
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            0,
            None,
            _CREATE_NEW,
            _OPEN_REPARSE_BACKUP | _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == _INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            buffer = ctypes.create_string_buffer(raw)
            written = wintypes.DWORD()
            if not _kernel32.WriteFile(
                handle, buffer, len(raw), ctypes.byref(written), None
            ) or written.value != len(raw):
                raise ctypes.WinError(ctypes.get_last_error())
            if not _kernel32.FlushFileBuffers(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                import win32security  # type: ignore[import-not-found]

                descriptor = (
                    win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                        protected_sddl, 1
                    )
                )
                win32security.SetSecurityInfo(
                    handle,
                    win32security.SE_FILE_OBJECT,
                    win32security.OWNER_SECURITY_INFORMATION
                    | win32security.DACL_SECURITY_INFORMATION
                    | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor.GetSecurityDescriptorOwner(),
                    None,
                    descriptor.GetSecurityDescriptorDacl(),
                    None,
                )
            except Exception as exc:
                raise OSError("protected handle ACL apply failed") from exc
            before = self._handle_info(handle)
            size = (before.size_high << 32) | before.size_low
            raw_readback = self._read_exact(handle, size)
            after = self._handle_info(handle)
            if self._identity(before) != self._identity(after):
                raise OSError("created file changed during handle readback")
            return SecureFileRead(
                raw=raw_readback, facts=self._facts(handle, path, info=after)
            )
        finally:
            _kernel32.CloseHandle(handle)

    @staticmethod
    def apply_protected_security_by_handle(
        path: Path, *, sddl: str, directory: bool
    ) -> None:
        """Apply owner/protected DACL to the object opened without reparse follow."""
        attributes = _OPEN_REPARSE_BACKUP
        if directory:
            attributes |= _FILE_ATTRIBUTE_DIRECTORY
        handle = _kernel32.CreateFileW(
            str(path.absolute()),
            _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER | _FILE_READ_ATTRIBUTES,
            0,
            None,
            _OPEN_EXISTING,
            attributes,
            None,
        )
        if handle == _INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            import win32security  # type: ignore[import-not-found]

            descriptor = (
                win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, 1
                )
            )
            win32security.SetSecurityInfo(
                handle,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.GetSecurityDescriptorOwner(),
                None,
                descriptor.GetSecurityDescriptorDacl(),
                None,
            )
        finally:
            _kernel32.CloseHandle(handle)

    @staticmethod
    def delete_empty_object_by_handle(path: Path, *, directory: bool) -> None:
        """Delete only the object opened without following a reparse point."""
        attributes = _OPEN_REPARSE_BACKUP
        if directory:
            attributes |= _FILE_ATTRIBUTE_DIRECTORY
        handle = _kernel32.CreateFileW(
            str(path.absolute()),
            _DELETE | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            0,
            None,
            _OPEN_EXISTING,
            attributes,
            None,
        )
        if handle == _INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            delete = wintypes.BOOL(True)
            if not _kernel32.SetFileInformationByHandle(
                handle,
                _FILE_DISPOSITION_INFO,
                ctypes.byref(delete),
                ctypes.sizeof(delete),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _kernel32.CloseHandle(handle)

    @staticmethod
    def rename_create_only_to_opened_parent(
        source: Path, *, target_name: str, parent: WindowsOpenedDirectoryAnchorV1
    ) -> None:
        """Publish via FileRenameInfo rooted at the retained parent handle."""
        if (
            not target_name
            or "\\" in target_name
            or "/" in target_name
            or parent._handle is None
        ):
            raise OSError("invalid handle-rooted rename target")
        handle = _kernel32.CreateFileW(
            str(source.absolute()),
            _DELETE | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            0,
            None,
            _OPEN_EXISTING,
            _OPEN_REPARSE_BACKUP | _FILE_ATTRIBUTE_DIRECTORY,
            None,
        )
        if handle == _INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            encoded = target_name.encode("utf-16-le")
            size = _FILE_RENAME_INFO_V1.file_name.offset + len(encoded) + 2
            buffer = ctypes.create_string_buffer(size)
            info = _FILE_RENAME_INFO_V1.from_buffer(buffer)
            info.replace_if_exists = False
            info.root_directory = parent._handle
            info.file_name_length = len(encoded)
            ctypes.memmove(
                ctypes.addressof(buffer) + _FILE_RENAME_INFO_V1.file_name.offset,
                encoded,
                len(encoded),
            )
            if not _kernel32.SetFileInformationByHandle(
                handle, _FILE_RENAME_INFO, buffer, size
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _kernel32.CloseHandle(handle)

    def resolve_service_sid_sha256(self, service_name: str) -> str:
        account_name = f"NT SERVICE\\{service_name}"
        sid_size = wintypes.DWORD()
        domain_size = wintypes.DWORD()
        sid_type = wintypes.DWORD()
        _advapi32.LookupAccountNameW(
            None,
            account_name,
            None,
            ctypes.byref(sid_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        )
        error = ctypes.get_last_error()
        if error != 122 or not sid_size.value:
            raise ctypes.WinError(error)
        sid = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        if not _advapi32.LookupAccountNameW(
            None,
            account_name,
            sid,
            ctypes.byref(sid_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_text = self._sid_text(ctypes.cast(sid, ctypes.c_void_p))
        return hashlib.sha256(sid_text.encode("ascii")).hexdigest()

    def _open(self, path: Path, *, directory: bool, read_data: bool) -> int:
        access = _READ_CONTROL | _FILE_READ_ATTRIBUTES
        if read_data:
            access |= _FILE_LIST_DIRECTORY if directory else 0x80000000
        handle = _kernel32.CreateFileW(
            str(path.absolute()),
            access,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _OPEN_REPARSE_BACKUP,
            None,
        )
        if handle == _INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def _handle_info(self, handle: int) -> _BY_HANDLE_FILE_INFORMATION:
        info = _BY_HANDLE_FILE_INFORMATION()
        if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return info

    @staticmethod
    def _identity(
        info: _BY_HANDLE_FILE_INFORMATION,
    ) -> tuple[int, int, int, int, int, int]:
        return (
            info.volume_serial,
            info.file_index_high,
            info.file_index_low,
            info.number_of_links,
            (info.size_high << 32) | info.size_low,
            (info.write_time.dwHighDateTime << 32) | info.write_time.dwLowDateTime,
        )

    def _read_exact(self, handle: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        read = wintypes.DWORD()
        if size and not _kernel32.ReadFile(
            handle, buffer, size, ctypes.byref(read), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if read.value != size:
            raise OSError("short foundation state handle read")
        return buffer.raw[: read.value]

    def _directory_names(self, handle: int) -> list[str]:
        names: list[str] = []
        buffer = ctypes.create_string_buffer(65536)
        while True:
            if not _kernel32.GetFileInformationByHandleEx(
                handle, 10, buffer, len(buffer)
            ):
                error = ctypes.get_last_error()
                if error == 18:
                    return names
                raise ctypes.WinError(error)
            offset = 0
            while True:
                item = _FILE_ID_BOTH_DIR_INFO.from_buffer(buffer, offset)
                name_address = (
                    ctypes.addressof(buffer) + offset + type(item).file_name.offset
                )
                name = ctypes.wstring_at(name_address, item.file_name_length // 2)
                if name not in {".", ".."}:
                    names.append(name)
                if item.next_entry_offset == 0:
                    break
                offset += item.next_entry_offset

    def _facts(
        self,
        handle: int,
        path: Path,
        *,
        info: _BY_HANDLE_FILE_INFORMATION | None = None,
    ) -> PathSecurityFacts:
        info = info or self._handle_info(handle)
        owner, sddl, protected, inherited, unsafe, writers = self._security(handle)
        attributes = info.attributes
        volume_serial = f"{info.volume_serial:08X}"
        return PathSecurityFacts(
            path_sha256=_path_sha256(path),
            volume_serial=volume_serial,
            volume_identity_sha256=hashlib.sha256(
                self._volume_identity(handle).encode("utf-8")
            ).hexdigest(),
            file_identity=(
                f"{volume_serial}:{info.file_index_high:08X}{info.file_index_low:08X}"
            ),
            owner_sid_sha256=hashlib.sha256(owner.encode("ascii")).hexdigest(),
            acl_sddl_sha256=hashlib.sha256(sddl.encode("utf-8")).hexdigest(),
            unsafe_write_principals=tuple(sorted(unsafe)),
            write_principal_sid_sha256s=tuple(
                sorted(
                    hashlib.sha256(sid.encode("ascii")).hexdigest() for sid in writers
                )
            ),
            regular_file=not bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
            directory=bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
            reparse_point=bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT),
            parent_chain_reparse_free=self._parents_reparse_free(path),
            hardlink_count=info.number_of_links,
            alternate_data_streams=self._has_alternate_streams(handle),
            dacl_protected=protected,
            inherited_ace_count=inherited,
        )

    def _has_alternate_streams(self, handle: int) -> bool:
        buffer = ctypes.create_string_buffer(65536)
        if not _kernel32.GetFileInformationByHandleEx(handle, 7, buffer, len(buffer)):
            error = ctypes.get_last_error()
            if error in {1, 38}:  # unsupported for this object/filesystem
                return False
            raise ctypes.WinError(error)
        offset = 0
        while True:
            item = _FILE_STREAM_INFO.from_buffer(buffer, offset)
            name_address = (
                ctypes.addressof(buffer) + offset + type(item).stream_name.offset
            )
            name = ctypes.wstring_at(name_address, item.stream_name_length // 2)
            if name != "::$DATA":
                return True
            if item.next_entry_offset == 0:
                return False
            offset += item.next_entry_offset

    def _parents_reparse_free(self, path: Path) -> bool:
        current = path.absolute().parent
        while current != current.parent:
            handle = self._open(current, directory=True, read_data=False)
            try:
                if self._handle_info(handle).attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                    return False
            finally:
                _kernel32.CloseHandle(handle)
            current = current.parent
        return True

    def _volume_identity(self, handle: int) -> str:
        # VOLUME_NAME_GUID makes the final path begin with the volume GUID of
        # this exact opened handle. No mutable textual path is consulted.
        size = 32768
        final_path = ctypes.create_unicode_buffer(size)
        length = _kernel32.GetFinalPathNameByHandleW(handle, final_path, size, 0x1)
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())
        if length >= size:
            size = length + 1
            final_path = ctypes.create_unicode_buffer(size)
            length = _kernel32.GetFinalPathNameByHandleW(handle, final_path, size, 0x1)
            if not length or length >= size:
                raise ctypes.WinError(ctypes.get_last_error())
        match = re.match(r"^(\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\)", final_path.value)
        if match is None:
            raise OSError("opened store handle is not on a local volume GUID path")
        return f"windows-volume-guid-v1:{match.group(1).upper()}"

    def _security(self, handle: int) -> tuple[str, str, bool, int, set[str], set[str]]:
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = _advapi32.GetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if result:
            raise ctypes.WinError(result)
        try:
            owner_text = self._sid_text(owner)
            sddl_pointer = wintypes.LPWSTR()
            if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                1,
                _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                ctypes.byref(sddl_pointer),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                sddl = sddl_pointer.value
            finally:
                _kernel32.LocalFree(ctypes.cast(sddl_pointer, ctypes.c_void_p))
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not _advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            inherited, unsafe, writers = self._acl_facts(dacl)
            return (
                owner_text,
                sddl,
                bool(control.value & _SE_DACL_PROTECTED),
                inherited,
                unsafe,
                writers,
            )
        finally:
            _kernel32.LocalFree(descriptor)

    def _sid_text(self, sid: ctypes.c_void_p) -> str:
        pointer = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(pointer)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return pointer.value
        finally:
            _kernel32.LocalFree(ctypes.cast(pointer, ctypes.c_void_p))

    def _acl_facts(self, dacl: ctypes.c_void_p) -> tuple[int, set[str], set[str]]:
        if not dacl:
            return 0, {"NULL_DACL"}, set()
        size = _ACL_SIZE_INFORMATION()
        if not _advapi32.GetAclInformation(
            dacl, ctypes.byref(size), ctypes.sizeof(size), 2
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        inherited = 0
        unsafe: set[str] = set()
        writers: set[str] = set()
        for index in range(size.ace_count):
            pointer = ctypes.c_void_p()
            if not _advapi32.GetAce(dacl, index, ctypes.byref(pointer)):
                raise ctypes.WinError(ctypes.get_last_error())
            header = _ACE_HEADER.from_address(pointer.value)
            inherited += bool(header.ace_flags & _INHERITED_ACE)
            if header.ace_type not in _ACCESS_ALLOWED_ACE_TYPES:
                continue
            mask = wintypes.DWORD.from_address(pointer.value + 4).value
            if not _access_mask_can_mutate(mask):
                continue
            sid_pointer = self._allowed_ace_sid(pointer, header.ace_type)
            if sid_pointer is None:
                unsafe.add(f"UNPARSED_WRITE_ACE_TYPE_{header.ace_type}")
                continue
            sid = self._sid_text(sid_pointer)
            writers.add(sid)
            if sid in _BROAD_WRITE_SIDS:
                unsafe.add(sid)
        return inherited, unsafe, writers

    @staticmethod
    def _allowed_ace_sid(
        pointer: ctypes.c_void_p, ace_type: int
    ) -> ctypes.c_void_p | None:
        if ace_type in {_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_ALLOWED_CALLBACK_ACE_TYPE}:
            return ctypes.c_void_p(pointer.value + 8)
        if ace_type not in {
            _ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        }:
            return None
        flags = wintypes.DWORD.from_address(pointer.value + 8).value
        offset = 12
        if flags & _ACE_OBJECT_TYPE_PRESENT:
            offset += 16
        if flags & _ACE_INHERITED_OBJECT_TYPE_PRESENT:
            offset += 16
        return ctypes.c_void_p(pointer.value + offset)


class WindowsOpenedDirectoryAnchorV1:
    """Lifetime-bound opened parent directory identity guard for publishing."""

    def __init__(self, filesystem: WindowsFilesystemFactsAdapter, path: Path) -> None:
        self._filesystem = filesystem
        self.path = path
        self._handle = filesystem._open(path, directory=True, read_data=False)
        self._initial = filesystem._facts(self._handle, path)
        if (
            not self._initial.directory
            or self._initial.reparse_point
            or not self._initial.parent_chain_reparse_free
        ):
            self.close()
            raise OSError("unsafe opened parent directory")

    def assert_named_path_is_opened_parent(self) -> PathSecurityFacts:
        """Compare the current named parent against the original open handle."""
        current = self._filesystem.inspect(self.path)
        if (
            current.file_identity != self._initial.file_identity
            or current.volume_serial != self._initial.volume_serial
            or current.volume_identity_sha256 != self._initial.volume_identity_sha256
            or current.reparse_point
            or not current.parent_chain_reparse_free
        ):
            raise OSError("parent directory path substitution detected")
        return current

    def close(self) -> None:
        if self._handle is not None:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


__all__ = [
    "MAX_FOUNDATION_STATE_BYTES",
    "FilesystemFactsAdapter",
    "PathSecurityFacts",
    "PortableFilesystemFactsAdapter",
    "SecureDirectoryInventory",
    "SecureFileRead",
    "WindowsFilesystemFactsAdapter",
]
