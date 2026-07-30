"""Verify the installed M2 release tree and successful output bytes."""

from __future__ import annotations

import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import file_identity, read_regular_strict
from .m2_isolation_contracts import IsolationPolicy, require_sha
from .m2_release_lock import ReleaseLockIdentity
from .m2_release_tree_custody import (
    HeldReleaseTree,
    mode_string,
    snapshot_release_tree,
)

MANIFEST_SCHEMA = "vnpy_research_m2_release_tree_manifest_v2"
CONTENT_SCHEMA = "vnpy_research_m2_release_tree_content_v2"
MANIFEST_KEYS = {
    "schema_version",
    "logical_release_root",
    "root_identity",
    "entries",
    "tree_content_sha256",
}
ROOT_KEYS = {"device", "inode", "owner_uid", "owner_gid", "mode", "acl_free"}
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
    "acl_free",
}


@dataclass(frozen=True)
class VerifiedReleaseArtifacts:
    release_lock_identity: dict[str, int | str]
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
    return _manifest_from_snapshot(
        root_identity,
        entries,
        logical_release_root=logical_release_root,
    )


def _manifest_from_snapshot(
    root_identity: dict[str, Any],
    entries: list[dict[str, Any]],
    *,
    logical_release_root: str,
) -> dict[str, Any]:
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
    release_lock_identity: ReleaseLockIdentity,
    expected_release_owner_uid: int = 0,
    expected_release_owner_gid: int = 0,
    _scan_hook: Callable[[str, str], None] | None = None,
) -> VerifiedReleaseArtifacts:
    if (
        isinstance(output_owner_uid, bool)
        or not isinstance(output_owner_uid, int)
        or output_owner_uid <= 0
    ):
        raise RegistryError("M2 successful output owner UID is invalid")
    if not isinstance(release_lock_identity, ReleaseLockIdentity):
        raise RegistryError("M2 release lock was not independently verified")
    manifest, manifest_raw_sha256 = _load_manifest(
        manifest_path,
        expected_raw_sha256=expected_manifest_raw_sha256,
    )
    require_sha(expected_output_raw_sha256, "expected M2 success output SHA256")
    try:
        with HeldReleaseTree(
            release_root,
            expected_owner_uid=expected_release_owner_uid,
            expected_owner_gid=expected_release_owner_gid,
            scan_hook=_scan_hook,
        ) as held:
            root_identity, entries = held.snapshot()
            actual = _manifest_from_snapshot(
                root_identity,
                entries,
                logical_release_root=policy.payload["release_root"],
            )
            if actual != manifest:
                raise RegistryError("installed M2 release tree/manifest mismatch")
            output_before = output_path.lstat()
            output_raw = read_regular_strict(
                output_path,
                "M2 successful output",
                private=False,
            )
            output_after = output_path.lstat()
            if (
                sha256(output_raw) != expected_output_raw_sha256
                or file_identity(output_before) != file_identity(output_after)
                or output_before.st_uid != output_owner_uid
                or output_before.st_nlink != 1
                or stat.S_IMODE(output_before.st_mode) != 0o600
            ):
                raise RegistryError("M2 successful output custody/hash mismatch")
            held.revalidate()
            return VerifiedReleaseArtifacts(
                release_lock_identity=release_lock_identity.as_dict(),
                release_tree_manifest_raw_sha256=manifest_raw_sha256,
                release_tree_content_sha256=manifest["tree_content_sha256"],
                release_root_identity=manifest["root_identity"],
                output_path=str(output_path),
                output_raw_sha256=expected_output_raw_sha256,
                output_device=output_before.st_dev,
                output_inode=output_before.st_ino,
                output_owner_uid=output_before.st_uid,
                output_mode=mode_string(output_before.st_mode),
                output_nlink=output_before.st_nlink,
            )
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError("M2 release/output artifact is unavailable") from exc
