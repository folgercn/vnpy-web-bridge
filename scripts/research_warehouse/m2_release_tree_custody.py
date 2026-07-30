"""Hold and revalidate one fd-relative M2 release-tree snapshot."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import sha256
from .errors import RegistryError
from .file_integrity import MAX_RAW_BYTES, file_identity

REQUIRED_RELEASE_PROGRAMS = {
    "bin/research-warehouse-job",
    "bin/research-warehouse-monitor",
}


def mode_string(value: int) -> str:
    return f"{stat.S_IMODE(value):04o}"


@dataclass
class _HeldNode:
    relative_path: str
    name: str | None
    parent_fd: int | None
    fd: int | None
    identity: tuple[int, ...]
    stat_result: os.stat_result
    child_names: tuple[str, ...] | None
    raw_sha256: str | None


class HeldReleaseTree:
    def __init__(
        self,
        root: Path,
        *,
        expected_owner_uid: int,
        expected_owner_gid: int,
        scan_hook: Callable[[str, str], None] | None = None,
    ) -> None:
        self.root = root
        self.expected_owner_uid = expected_owner_uid
        self.expected_owner_gid = expected_owner_gid
        self.scan_hook = scan_hook
        self.nodes: list[_HeldNode] = []
        self.entries: list[dict[str, Any]] = []

    def __enter__(self) -> HeldReleaseTree:  # noqa: PYI034
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            path_stat = self.root.lstat()
            root_fd = os.open(self.root, flags)
            root_stat = os.fstat(root_fd)
            if file_identity(path_stat) != file_identity(root_stat):
                os.close(root_fd)
                raise RegistryError("M2 release root pathname identity mismatch")
            try:
                self._validate_custody(root_stat, ".", directory=True)
            except RegistryError:
                os.close(root_fd)
                raise
            self.nodes.append(
                _HeldNode(
                    relative_path=".",
                    name=None,
                    parent_fd=None,
                    fd=root_fd,
                    identity=file_identity(root_stat),
                    stat_result=root_stat,
                    child_names=None,
                    raw_sha256=None,
                )
            )
            self._walk_directory(self.nodes[0])
            self._validate_required_programs()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        for node in reversed(self.nodes):
            if node.fd is None:
                continue
            try:
                os.close(node.fd)
            except OSError:
                pass
        self.nodes.clear()

    def _hook(self, event: str, relative_path: str) -> None:
        if self.scan_hook is not None:
            self.scan_hook(event, relative_path)

    def _validate_custody(
        self,
        value: os.stat_result,
        relative_path: str,
        *,
        directory: bool,
    ) -> None:
        correct_type = (
            stat.S_ISDIR(value.st_mode)
            if directory
            else stat.S_ISREG(value.st_mode)
        )
        if (
            not correct_type
            or value.st_uid != self.expected_owner_uid
            or value.st_gid != self.expected_owner_gid
            or stat.S_IMODE(value.st_mode) & 0o022
            or (not directory and value.st_nlink != 1)
        ):
            raise RegistryError(
                f"M2 release entry custody mismatch: {relative_path}"
            )

    def _walk_directory(self, directory: _HeldNode) -> None:
        try:
            names = tuple(sorted(os.listdir(directory.fd)))
        except OSError as exc:
            raise RegistryError("cannot enumerate M2 release directory") from exc
        if any(
            not name
            or name in {".", ".."}
            or "/" in name
            or "\x00" in name
            for name in names
        ):
            raise RegistryError("M2 release directory contains an unsafe name")
        directory.child_names = names
        self._hook("after_enumerate", directory.relative_path)
        for name in names:
            prefix = (
                ""
                if directory.relative_path == "."
                else f"{directory.relative_path}/"
            )
            self._open_child(directory, name, f"{prefix}{name}")

    def _open_child(
        self,
        parent: _HeldNode,
        name: str,
        relative: str,
    ) -> None:
        try:
            path_stat = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except OSError as exc:
            raise RegistryError(f"M2 release entry disappeared: {relative}") from exc
        if stat.S_ISLNK(path_stat.st_mode):
            raise RegistryError(f"M2 release symlink is forbidden: {relative}")
        directory = stat.S_ISDIR(path_stat.st_mode)
        if not directory and not stat.S_ISREG(path_stat.st_mode):
            raise RegistryError(f"M2 release entry type is forbidden: {relative}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        try:
            child_fd = os.open(name, flags, dir_fd=parent.fd)
        except OSError as exc:
            raise RegistryError(f"cannot open M2 release entry: {relative}") from exc
        try:
            opened = os.fstat(child_fd)
        except OSError as exc:
            os.close(child_fd)
            raise RegistryError(f"cannot stat M2 release entry: {relative}") from exc
        if file_identity(path_stat) != file_identity(opened):
            os.close(child_fd)
            raise RegistryError(f"M2 release entry changed while opening: {relative}")
        try:
            self._validate_custody(opened, relative, directory=directory)
        except RegistryError:
            os.close(child_fd)
            raise
        node = _HeldNode(
            relative_path=relative,
            name=name,
            parent_fd=parent.fd,
            fd=child_fd,
            identity=file_identity(opened),
            stat_result=opened,
            child_names=None,
            raw_sha256=None,
        )
        self.nodes.append(node)
        if directory:
            raw = None
            size_bytes = 0
            self._walk_directory(node)
        else:
            raw = self._read_file(node)
            size_bytes = len(raw)
            node.raw_sha256 = sha256(raw)
            os.close(child_fd)
            node.fd = None
        self.entries.append(
            {
                "relative_path": relative,
                "kind": "directory" if directory else "file",
                "size_bytes": size_bytes,
                "raw_sha256": None if raw is None else sha256(raw),
                "device": opened.st_dev,
                "inode": opened.st_ino,
                "owner_uid": opened.st_uid,
                "owner_gid": opened.st_gid,
                "mode": mode_string(opened.st_mode),
                "nlink": opened.st_nlink,
            }
        )
        self._hook("after_entry", relative)

    def _read_file(self, node: _HeldNode) -> bytes:
        if node.fd is None:
            raise RegistryError("M2 release file descriptor is missing")
        return self._read_descriptor(
            node.fd,
            relative_path=node.relative_path,
            identity=node.identity,
        )

    def _read_descriptor(
        self,
        descriptor: int,
        *,
        relative_path: str,
        identity: tuple[int, ...],
    ) -> bytes:
        def read_once() -> bytes:
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_RAW_BYTES:
                    raise RegistryError(
                        f"M2 release file exceeds limit: {relative_path}"
                    )
                chunks.append(chunk)
            return b"".join(chunks)

        first = read_once()
        second = read_once()
        after = os.fstat(descriptor)
        if first != second or file_identity(after) != identity:
            raise RegistryError(
                f"M2 release file changed while reading: {relative_path}"
            )
        return first

    def _validate_required_programs(self) -> None:
        by_path = {entry["relative_path"]: entry for entry in self.entries}
        if not REQUIRED_RELEASE_PROGRAMS <= set(by_path) or any(
            by_path[path]["kind"] != "file"
            or int(by_path[path]["mode"], 8) & 0o111 == 0
            for path in REQUIRED_RELEASE_PROGRAMS
        ):
            raise RegistryError(
                "M2 release tree is missing an executable entrypoint"
            )

    def revalidate(self) -> None:
        for node in self.nodes:
            reopened = None
            try:
                if node.parent_fd is None:
                    path_stat = self.root.lstat()
                else:
                    path_stat = os.stat(
                        node.name,
                        dir_fd=node.parent_fd,
                        follow_symlinks=False,
                    )
                if node.fd is None:
                    reopened = os.open(
                        node.name,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=node.parent_fd,
                    )
                    held = os.fstat(reopened)
                else:
                    held = os.fstat(node.fd)
            except OSError as exc:
                if reopened is not None:
                    os.close(reopened)
                raise RegistryError(
                    f"M2 release entry unavailable: {node.relative_path}"
                ) from exc
            try:
                if file_identity(held) != node.identity:
                    raise RegistryError(
                        f"M2 held release entry changed: {node.relative_path}"
                    )
                if file_identity(path_stat) != node.identity:
                    raise RegistryError(
                        f"M2 release pathname changed: {node.relative_path}"
                    )
                if reopened is not None:
                    raw = self._read_descriptor(
                        reopened,
                        relative_path=node.relative_path,
                        identity=node.identity,
                    )
                    if sha256(raw) != node.raw_sha256:
                        raise RegistryError(
                            f"M2 release file content changed: "
                            f"{node.relative_path}"
                        )
                if node.child_names is not None:
                    try:
                        final_names = tuple(sorted(os.listdir(node.fd)))
                    except OSError as exc:
                        raise RegistryError(
                            f"M2 release directory unavailable: "
                            f"{node.relative_path}"
                        ) from exc
                    if final_names != node.child_names:
                        raise RegistryError(
                            f"M2 release directory membership changed: "
                            f"{node.relative_path}"
                        )
            finally:
                if reopened is not None:
                    os.close(reopened)

    def snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        root_stat = self.nodes[0].stat_result
        root_identity = {
            "device": root_stat.st_dev,
            "inode": root_stat.st_ino,
            "owner_uid": root_stat.st_uid,
            "owner_gid": root_stat.st_gid,
            "mode": mode_string(root_stat.st_mode),
        }
        return root_identity, sorted(
            self.entries,
            key=lambda entry: entry["relative_path"],
        )


def snapshot_release_tree(
    root: Path,
    *,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with HeldReleaseTree(
        root,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    ) as held:
        held.revalidate()
        return held.snapshot()
