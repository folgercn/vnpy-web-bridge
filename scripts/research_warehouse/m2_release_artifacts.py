"""Verify the installed M2 release tree and successful output bytes."""

from __future__ import annotations

import stat
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import file_identity, read_regular_strict
from .m2_isolation_contracts import IsolationPolicy, require_sha

MANIFEST_SCHEMA = "vnpy_research_m2_release_tree_manifest_v1"
CONTENT_SCHEMA = "vnpy_research_m2_release_tree_content_v1"
MANIFEST_KEYS = {
    "schema_version",
    "logical_release_root",
    "root_identity",
    "entries",
    "tree_content_sha256",
}
ROOT_KEYS = {"device", "inode", "owner_uid", "owner_gid", "mode"}
ENTRY_KEYS = {
    "relative_path",
    "kind",
    "size_bytes",
    "raw_sha256",
    "device",
    "inode",
    "owner_uid",
    "owner_gid",
    "mode",
    "nlink",
}
REQUIRED_RELEASE_PROGRAMS = {
    "bin/research-warehouse-job",
    "bin/research-warehouse-monitor",
}


@dataclass(frozen=True)
class VerifiedReleaseArtifacts:
    release_tree_manifest_raw_sha256: str
    release_tree_content_sha256: str
    release_root_identity: dict[str, Any]
    output_path: str
    output_raw_sha256: str
    output_device: int
    output_inode: int
    output_owner_uid: int
    output_mode: str
    output_nlink: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _mode(value: int) -> str:
    return f"{stat.S_IMODE(value):04o}"


def _root_identity(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
) -> VerifiedReleaseArtifacts:
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != expected_owner_uid
        or before.st_gid != expected_owner_gid
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise RegistryError("M2 release root custody mismatch")
    after = path.lstat()
    if file_identity(before) != file_identity(after):
        raise RegistryError("M2 release root changed during verification")
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "owner_uid": before.st_uid,
        "owner_gid": before.st_gid,
        "mode": _mode(before.st_mode),
    }


def _entry(
    root: Path,
    path: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    if (
        not relative
        or PurePosixPath(relative).is_absolute()
        or ".." in PurePosixPath(relative).parts
    ):
        raise RegistryError("M2 release entry path is unsafe")
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or before.st_uid != expected_owner_uid
        or before.st_gid != expected_owner_gid
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise RegistryError(f"M2 release entry custody mismatch: {relative}")
    if stat.S_ISDIR(before.st_mode):
        kind = "directory"
        size_bytes = 0
        raw_sha256 = None
    elif stat.S_ISREG(before.st_mode):
        if before.st_nlink != 1:
            raise RegistryError(f"M2 release file has multiple links: {relative}")
        raw = read_regular_strict(
            path,
            f"M2 release file {relative}",
            private=False,
        )
        kind = "file"
        size_bytes = len(raw)
        raw_sha256 = sha256(raw)
    else:
        raise RegistryError(f"M2 release entry type is forbidden: {relative}")
    after = path.lstat()
    if file_identity(before) != file_identity(after):
        raise RegistryError(f"M2 release entry changed: {relative}")
    return {
        "relative_path": relative,
        "kind": kind,
        "size_bytes": size_bytes,
        "raw_sha256": raw_sha256,
        "device": before.st_dev,
        "inode": before.st_ino,
        "owner_uid": before.st_uid,
        "owner_gid": before.st_gid,
        "mode": _mode(before.st_mode),
        "nlink": before.st_nlink,
    }


def snapshot_release_tree(
    root: Path,
    *,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    root_before = root.lstat()
    root_identity = _root_identity(
        root,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )
    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    entries = [
        _entry(
            root,
            path,
            expected_owner_uid=expected_owner_uid,
            expected_owner_gid=expected_owner_gid,
        )
        for path in paths
    ]
    root_after = root.lstat()
    if file_identity(root_before) != file_identity(root_after):
        raise RegistryError("M2 release root changed during tree scan")
    by_path = {entry["relative_path"]: entry for entry in entries}
    if not REQUIRED_RELEASE_PROGRAMS <= set(by_path) or any(
        by_path[path]["kind"] != "file"
        or int(by_path[path]["mode"], 8) & 0o111 == 0
        for path in REQUIRED_RELEASE_PROGRAMS
    ):
        raise RegistryError("M2 release tree is missing an executable entrypoint")
    return root_identity, entries


def release_tree_content_sha256(entries: list[dict[str, Any]]) -> str:
    return sha256(
        canonical_json_line(
            {
                "schema_version": CONTENT_SCHEMA,
                "entries": entries,
            }
        )
    )


def build_release_tree_manifest(
    root: Path,
    *,
    logical_release_root: str,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
) -> dict[str, Any]:
    root_identity, entries = snapshot_release_tree(
        root,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )
    return {
        "schema_version": MANIFEST_SCHEMA,
        "logical_release_root": logical_release_root,
        "root_identity": root_identity,
        "entries": entries,
        "tree_content_sha256": release_tree_content_sha256(entries),
    }


def _load_manifest(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> tuple[dict[str, Any], str]:
    require_sha(expected_raw_sha256, "expected M2 release manifest SHA256")
    raw = read_regular_strict(path, "M2 release tree manifest")
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("M2 release tree manifest raw SHA256 mismatch")
    value = parse_json_strict(raw, "M2 release tree manifest")
    if (
        not isinstance(value, dict)
        or set(value) != MANIFEST_KEYS
        or value["schema_version"] != MANIFEST_SCHEMA
        or canonical_json_line(value) != raw
        or not isinstance(value["root_identity"], dict)
        or set(value["root_identity"]) != ROOT_KEYS
        or not isinstance(value["entries"], list)
    ):
        raise RegistryError("M2 release tree manifest contract mismatch")
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise RegistryError("M2 release tree manifest entry mismatch")
    require_sha(value["tree_content_sha256"], "M2 release tree content")
    return value, expected_raw_sha256


def verify_release_artifacts(
    *,
    policy: IsolationPolicy,
    release_root: Path,
    manifest_path: Path,
    expected_manifest_raw_sha256: str,
    output_path: Path,
    expected_output_raw_sha256: str,
    output_owner_uid: int,
    expected_release_owner_uid: int = 0,
    expected_release_owner_gid: int = 0,
) -> dict[str, Any]:
    if (
        isinstance(output_owner_uid, bool)
        or not isinstance(output_owner_uid, int)
        or output_owner_uid <= 0
    ):
        raise RegistryError("M2 successful output owner UID is invalid")
    manifest, manifest_raw_sha256 = _load_manifest(
        manifest_path,
        expected_raw_sha256=expected_manifest_raw_sha256,
    )
    try:
        actual = build_release_tree_manifest(
            release_root,
            logical_release_root=policy.payload["release_root"],
            expected_owner_uid=expected_release_owner_uid,
            expected_owner_gid=expected_release_owner_gid,
        )
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError("installed M2 release tree is unavailable") from exc
    if actual != manifest:
        raise RegistryError("installed M2 release tree/manifest mismatch")
    require_sha(expected_output_raw_sha256, "expected M2 success output SHA256")
    try:
        output_before = output_path.lstat()
        output_raw = read_regular_strict(
            output_path,
            "M2 successful output",
            private=False,
        )
        output_after = output_path.lstat()
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError("M2 successful output is unavailable") from exc
    if (
        sha256(output_raw) != expected_output_raw_sha256
        or file_identity(output_before) != file_identity(output_after)
        or output_before.st_uid != output_owner_uid
        or output_before.st_nlink != 1
        or stat.S_IMODE(output_before.st_mode) != 0o600
    ):
        raise RegistryError("M2 successful output custody/hash mismatch")
    return VerifiedReleaseArtifacts(
        release_tree_manifest_raw_sha256=manifest_raw_sha256,
        release_tree_content_sha256=manifest["tree_content_sha256"],
        release_root_identity=manifest["root_identity"],
        output_path=str(output_path),
        output_raw_sha256=expected_output_raw_sha256,
        output_device=output_before.st_dev,
        output_inode=output_before.st_ino,
        output_owner_uid=output_before.st_uid,
        output_mode=_mode(output_before.st_mode),
        output_nlink=output_before.st_nlink,
    )
