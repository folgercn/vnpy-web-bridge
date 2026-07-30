"""Prepare the one approved standalone M2 Python archive."""

from __future__ import annotations

import io
import os
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from .canonical import sha256
from .errors import RegistryError
from .file_integrity import MAX_RAW_BYTES, read_regular_strict
from .m2_python_runtime import (
    PYTHON_RUNTIME_SOURCE_ARCHIVE_SHA256,
    RUNTIME_EXECUTABLE,
    verify_runtime_execution,
)

MAX_RUNTIME_ENTRIES = 10_000
MAX_RUNTIME_BYTES = 256 * 1024 * 1024


def prepare_python_runtime(source_archive: Path, output_root: Path) -> None:
    """Extract the pinned archive into a normalized symlink-free tree."""
    archive_raw = read_regular_strict(
        source_archive,
        "M2 Python runtime source archive",
    )
    if sha256(archive_raw) != PYTHON_RUNTIME_SOURCE_ARCHIVE_SHA256:
        raise RegistryError("M2 Python runtime source archive SHA256 mismatch")
    if output_root.exists():
        raise RegistryError("M2 prepared Python runtime already exists")
    output_root.mkdir(mode=0o700)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as archive:
            members = sorted(archive.getmembers(), key=lambda item: item.name)
            if (
                len(members) > MAX_RUNTIME_ENTRIES
                or sum(item.size for item in members) > MAX_RUNTIME_BYTES
            ):
                raise RegistryError("M2 Python runtime archive exceeds limits")
            for member in members:
                _extract_member(archive, member, output_root)
        for directory in sorted(
            (path for path in output_root.rglob("*") if path.is_dir()),
            reverse=True,
        ):
            directory.chmod(0o755)
        output_root.chmod(0o755)
        verify_runtime_execution(output_root)
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _extract_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    output_root: Path,
) -> None:
    archive_path = PurePosixPath(member.name)
    if (
        archive_path.is_absolute()
        or ".." in archive_path.parts
        or not archive_path.parts
        or archive_path.parts[0] != "python"
    ):
        raise RegistryError("M2 Python runtime archive path is unsafe")
    relative = PurePosixPath(*archive_path.parts[1:])
    if not relative.parts or member.issym() or member.islnk():
        return
    destination = output_root.joinpath(*relative.parts)
    if member.isdir():
        destination.mkdir(mode=0o755, parents=True, exist_ok=True)
        return
    if not member.isfile():
        raise RegistryError("M2 Python runtime archive entry type is forbidden")
    if member.size > MAX_RAW_BYTES:
        raise RegistryError("M2 Python runtime archive entry exceeds limit")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    extracted = archive.extractfile(member)
    if extracted is None:
        raise RegistryError("cannot read M2 Python runtime archive entry")
    raw = extracted.read()
    if len(raw) != member.size:
        raise RegistryError("M2 Python runtime archive entry is truncated")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fchmod(
            descriptor,
            0o555 if relative.as_posix() == RUNTIME_EXECUTABLE else 0o444,
        )
    finally:
        os.close(descriptor)
