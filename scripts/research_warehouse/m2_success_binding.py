"""Bind verified release/output artifacts to one post-activation success."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import RegistryError
from .m2_isolation_contracts import (
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    IsolationPolicy,
    require_sha,
)
from .m2_release_artifacts import VerifiedReleaseArtifacts
from .timeutil import parse_utc

SUCCESS_RECEIPT_KEYS = {
    "schema_version",
    "host_identity",
    "service_uid",
    "service_gid",
    "policy_raw_sha256",
    "plist_raw_sha256s",
    "pf_anchor_raw_sha256",
    "release_tree_raw_sha256",
    "release_tree_manifest_raw_sha256",
    "release_lock_identity",
    "started_at",
    "completed_at",
    "output_path",
    "output_raw_sha256",
    "output_device",
    "output_inode",
    "output_owner_uid",
    "output_mode",
    "create_only",
    "regular",
    "nlink",
}
RELEASE_ARTIFACT_KEYS = {
    "release_lock_identity",
    "release_tree_manifest_raw_sha256",
    "release_tree_content_sha256",
    "release_root_identity",
    "output_path",
    "output_raw_sha256",
    "output_device",
    "output_inode",
    "output_owner_uid",
    "output_mode",
    "output_nlink",
    "output_acl_free",
}


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def _verified_artifact_values(
    evidence: dict[str, Any],
    *,
    policy: IsolationPolicy,
    release_artifacts: VerifiedReleaseArtifacts,
) -> dict[str, Any]:
    if not isinstance(release_artifacts, VerifiedReleaseArtifacts):
        raise RegistryError("M2 release artifacts were not independently verified")
    artifacts = _exact(
        release_artifacts.as_dict(),
        RELEASE_ARTIFACT_KEYS,
        "M2 verified release artifacts",
    )
    lock = _exact(
        artifacts["release_lock_identity"],
        {
            "path",
            "device",
            "inode",
            "owner_uid",
            "owner_gid",
            "mode",
            "nlink",
        },
        "M2 release deployment lock identity",
    )
    if (
        require_sha(
            artifacts["release_tree_content_sha256"],
            "verified M2 release tree content",
        )
        != evidence["release_tree_raw_sha256"]
        or require_sha(
            artifacts["release_tree_manifest_raw_sha256"],
            "verified M2 release tree manifest",
        )
        != evidence["release_tree_manifest_raw_sha256"]
        or lock != evidence["release_lock_identity"]
    ):
        raise RegistryError("M2 verified release artifact binding mismatch")
    if (
        lock["path"] != policy.payload["release_lock_path"]
        or lock["owner_uid"] != 0
        or lock["owner_gid"] != 0
        or lock["mode"] != "0444"
        or lock["nlink"] != 1
        or any(
            isinstance(lock[field], bool)
            or not isinstance(lock[field], int)
            or lock[field] <= 0
            for field in ("device", "inode")
        )
    ):
        raise RegistryError("M2 release deployment lock custody mismatch")
    root = _exact(
        artifacts["release_root_identity"],
        {"device", "inode", "owner_uid", "owner_gid", "mode", "acl_free"},
        "M2 verified release root identity",
    )
    output_path = Path(artifacts["output_path"])
    if (
        root["owner_uid"] != 0
        or root["owner_gid"] != 0
        or root["mode"] != "0755"
        or root["acl_free"] is not True
        or any(
            isinstance(root[field], bool)
            or not isinstance(root[field], int)
            or root[field] <= 0
            for field in ("device", "inode")
        )
        or not output_path.is_absolute()
        or not output_path.is_relative_to(Path(policy.payload["runtime_root"]))
        or require_sha(
            artifacts["output_raw_sha256"],
            "verified M2 successful output",
        )
        == "0" * 64
        or artifacts["output_mode"] != "0600"
        or artifacts["output_nlink"] != 1
        or artifacts["output_acl_free"] is not True
        or any(
            isinstance(artifacts[field], bool)
            or not isinstance(artifacts[field], int)
            or artifacts[field] <= 0
            for field in (
                "output_device",
                "output_inode",
                "output_owner_uid",
            )
        )
    ):
        raise RegistryError("M2 verified release artifact custody mismatch")
    return artifacts


def verify_release_success_binding(
    evidence: dict[str, Any],
    *,
    policy: IsolationPolicy,
    release_artifacts: VerifiedReleaseArtifacts,
    identity: dict[str, Any],
    activated: datetime,
    captured: datetime,
) -> dict[str, Any]:
    artifacts = _verified_artifact_values(
        evidence,
        policy=policy,
        release_artifacts=release_artifacts,
    )
    receipt = _exact(
        evidence["success_receipt"],
        SUCCESS_RECEIPT_KEYS,
        "M2 success receipt",
    )
    started = parse_utc(receipt["started_at"], "M2 receipt started_at")
    completed = parse_utc(receipt["completed_at"], "M2 receipt completed_at")
    if (
        receipt["schema_version"] != "vnpy_research_m2_success_receipt_v1"
        or receipt["host_identity"] != evidence["host_identity"]
        or receipt["service_uid"] != identity["uid"]
        or receipt["service_gid"] != identity["gid"]
        or receipt["policy_raw_sha256"] != policy.raw_sha256
        or receipt["plist_raw_sha256s"] != PLIST_SHA256
        or receipt["pf_anchor_raw_sha256"] != PF_ANCHOR_SHA256
        or receipt["release_tree_raw_sha256"] != evidence["release_tree_raw_sha256"]
        or receipt["release_tree_manifest_raw_sha256"]
        != evidence["release_tree_manifest_raw_sha256"]
        or receipt["release_lock_identity"] != artifacts["release_lock_identity"]
        or started < activated
        or completed < started
        or completed > captured
        or receipt["output_path"] != artifacts["output_path"]
        or receipt["output_raw_sha256"] != artifacts["output_raw_sha256"]
        or receipt["output_device"] != artifacts["output_device"]
        or receipt["output_inode"] != artifacts["output_inode"]
        or receipt["output_owner_uid"] != artifacts["output_owner_uid"]
        or receipt["output_owner_uid"] != identity["uid"]
        or receipt["output_mode"] != artifacts["output_mode"]
        or receipt["output_mode"] != "0600"
        or receipt["create_only"] is not True
        or receipt["regular"] is not True
        or receipt["nlink"] != artifacts["output_nlink"]
        or receipt["nlink"] != 1
        or evidence["monitor_input"]["last_success_at"] != receipt["completed_at"]
        or parse_utc(
            evidence["monitor_input"]["last_backup_at"],
            "M2 last backup",
        )
        < activated
    ):
        raise RegistryError("M2 success receipt activation binding mismatch")
    return artifacts
