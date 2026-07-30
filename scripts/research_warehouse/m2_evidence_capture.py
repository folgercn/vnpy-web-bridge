"""Assemble create-only M2 isolation artifacts from live host probes."""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import (
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    IsolationPolicy,
    false_authority,
)
from .m2_release_contracts import write_create_only
from .timeutil import format_utc


def _release_manifest(path: Path, expected_sha256: str) -> dict[str, Any]:
    raw = read_regular_strict(
        path,
        "M2 installed release tree manifest",
        private=False,
    )
    if sha256(raw) != expected_sha256:
        raise RegistryError("M2 installed release tree manifest SHA256 mismatch")
    value = parse_json_strict(raw, "M2 installed release tree manifest")
    if (
        canonical_json_line(value) != raw
        or value.get("schema_version") != "vnpy_research_m2_release_tree_manifest_v2"
    ):
        raise RegistryError("M2 installed release tree manifest is invalid")
    return value


def _output_facts(path: Path, policy: IsolationPolicy) -> dict[str, Any]:
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_uid != policy.uid
        or value.st_gid != policy.gid
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
    ):
        raise RegistryError("M2 success output custody mismatch")
    return {
        "output_path": str(path),
        "output_raw_sha256": sha256(path.read_bytes()),
        "output_device": value.st_dev,
        "output_inode": value.st_ino,
        "output_owner_uid": value.st_uid,
        "output_mode": "0600",
        "create_only": True,
        "regular": True,
        "nlink": value.st_nlink,
    }


def publish_success_output(
    path: Path,
    *,
    policy: IsolationPolicy,
    completed_at: str,
    monitor_input: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": "vnpy_research_m2_success_output_v1",
        "status": "M2_RESEARCH_RUNTIME_CHAIN_SUCCEEDED",
        "completed_at": completed_at,
        "monitor_input": monitor_input,
        "authority": false_authority(),
    }
    write_create_only(path, value)
    try:
        os.chown(path, policy.uid, policy.gid)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RegistryError("cannot transfer M2 success output custody") from exc
    return _output_facts(path, policy)


def publish_evidence(
    path: Path,
    *,
    policy: IsolationPolicy,
    probes: dict[str, Any],
    activation: dict[str, str],
    monitor_input: dict[str, Any],
    release_tree_manifest_path: Path,
    expected_release_tree_manifest_sha256: str,
    release_lock_identity: dict[str, Any],
    success_output_path: Path,
    captured_at: datetime,
) -> dict[str, str]:
    manifest = _release_manifest(
        release_tree_manifest_path,
        expected_release_tree_manifest_sha256,
    )
    completed_at = monitor_input["last_success_at"]
    if not isinstance(completed_at, str):
        raise RegistryError("M2 success completion is unavailable")
    output = publish_success_output(
        success_output_path,
        policy=policy,
        completed_at=completed_at,
        monitor_input=monitor_input,
    )
    started_at = max(activation.values())
    success_receipt = {
        "schema_version": "vnpy_research_m2_success_receipt_v1",
        "host_identity": probes["host_identity"],
        "service_uid": policy.uid,
        "service_gid": policy.gid,
        "policy_raw_sha256": policy.raw_sha256,
        "plist_raw_sha256s": PLIST_SHA256,
        "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
        "release_tree_raw_sha256": manifest["tree_content_sha256"],
        "release_tree_manifest_raw_sha256": (expected_release_tree_manifest_sha256),
        "release_lock_identity": release_lock_identity,
        "started_at": started_at,
        "completed_at": completed_at,
        **output,
    }
    evidence = {
        "schema_version": "vnpy_research_m2_isolation_evidence_v1",
        "captured_at": format_utc(captured_at, "M2 evidence captured_at"),
        "host_identity": probes["host_identity"],
        "policy_raw_sha256": policy.raw_sha256,
        "registry_raw_sha256": policy.payload["registry_raw_sha256"],
        "release_tree_raw_sha256": manifest["tree_content_sha256"],
        "release_tree_manifest_raw_sha256": (expected_release_tree_manifest_sha256),
        "release_lock_identity": release_lock_identity,
        "activation": {
            **activation,
            "policy_raw_sha256": policy.raw_sha256,
            "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
            "plist_raw_sha256s": PLIST_SHA256,
        },
        "identity": probes["identity"],
        "launchd": probes["launchd"],
        "environment": probes["environment"],
        "filesystem": probes["filesystem"],
        "network": probes["network"],
        "process": probes["process"],
        "monitor_input": monitor_input,
        "success_receipt": success_receipt,
        "authority": false_authority(),
    }
    evidence_sha = write_create_only(path, evidence)
    return {
        "evidence_raw_sha256": evidence_sha,
        "release_tree_manifest_raw_sha256": (expected_release_tree_manifest_sha256),
        "success_output_raw_sha256": output["output_raw_sha256"],
    }
