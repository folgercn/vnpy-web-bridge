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
        self.nodes_by_path: dict[str, _HeldNode] = {}
        self.entries: list[dict[str, Any]] = []
        self.root_fd: int | None = None

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
            self.root_fd = root_fd
            root_node = _HeldNode(
                relative_path=".",
                identity=file_identity(root_stat),
                stat_result=root_stat,
                child_names=None,
                raw_sha256=None,
            )
            self._remember(root_node)
            self._walk_directory(root_node, root_fd)
            self._validate_required_programs()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self.root_fd is not None:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            self.root_fd = None
        self.nodes.clear()
        self.nodes_by_path.clear()

    def _remember(self, node: _HeldNode) -> None:
        self.nodes.append(node)
        self.nodes_by_path[node.relative_path] = node

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

    def _walk_directory(self, directory: _HeldNode, directory_fd: int) -> None:
        try:
            names = tuple(sorted(os.listdir(directory_fd)))
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
            self._open_child(directory_fd, name, f"{prefix}{name}")

    def _open_child(
        self,
        parent_fd: int,
        name: str,
        relative: str,
    ) -> None:
        try:
            path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
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
            child_fd = os.open(name, flags, dir_fd=parent_fd)
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
            identity=file_identity(opened),
            stat_result=opened,
            child_names=None,
            raw_sha256=None,
        )
        self._remember(node)
        try:
            if directory:
                raw = None
                size_bytes = 0
                self._walk_directory(node, child_fd)
            else:
                raw = self._read_descriptor(
                    child_fd,
                    relative_path=relative,
                    identity=node.identity,
                )
                size_bytes = len(raw)
                node.raw_sha256 = sha256(raw)
        finally:
            os.close(child_fd)
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
        if self.root_fd is None:
            raise RegistryError("M2 release root descriptor is missing")
        for node in self.nodes:
            reopened: int | None = None
            try:
                if node.relative_path == ".":
                    path_stat = self.root.lstat()
                    held = os.fstat(self.root_fd)
                else:
                    reopened = self._reopen_relative(
                        node.relative_path,
                        directory=node.child_names is not None,
                    )
                    held = os.fstat(reopened)
                    path_stat = held
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
                if node.child_names is None and reopened is not None:
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
                        directory_fd = (
                            self.root_fd
                            if node.relative_path == "."
                            else reopened
                        )
                        final_names = tuple(sorted(os.listdir(directory_fd)))
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

    def _reopen_relative(self, relative_path: str, *, directory: bool) -> int:
        if self.root_fd is None:
            raise RegistryError("M2 release root descriptor is missing")
        current = os.dup(self.root_fd)
        parts = relative_path.split("/")
        prefix: list[str] = []
        try:
            for index, part in enumerate(parts):
                prefix.append(part)
                final = index == len(parts) - 1
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                if not final or directory:
                    flags |= getattr(os, "O_DIRECTORY", 0)
                path_stat = os.stat(part, dir_fd=current, follow_symlinks=False)
                opened = os.open(part, flags, dir_fd=current)
                opened_stat = os.fstat(opened)
                node = self.nodes_by_path["/".join(prefix)]
                if (
                    file_identity(path_stat) != node.identity
                    or file_identity(opened_stat) != node.identity
                ):
                    os.close(opened)
                    raise RegistryError(
                        f"M2 release pathname changed: {'/'.join(prefix)}"
                    )
                os.close(current)
                current = opened
            return current
        except Exception:
            os.close(current)
            raise

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
