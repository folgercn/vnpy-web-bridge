from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from research_warehouse.canonical import canonical_json_line, parse_json_strict, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_evidence_capture import publish_evidence
from research_warehouse.m2_isolation_contracts import (
    IsolationPolicy,
    load_isolation_policy,
)
from research_warehouse.m2_release_artifacts import build_release_tree_manifest
from research_warehouse.m2_release_contracts import write_create_only

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "deployments/research-warehouse/m2/isolation-policy-v1.json"


def local_policy() -> IsolationPolicy:
    frozen = load_isolation_policy(POLICY)
    payload = dict(frozen.payload)
    payload["service_uid"] = os.getuid()
    payload["service_gid"] = os.getgid()
    return IsolationPolicy(raw_sha256=frozen.raw_sha256, payload=payload)


def probes() -> dict:
    empty = {
        "observed_at": "2026-07-30T12:30:00.000000Z",
        "probe_result_sha256": "1" * 64,
    }
    return {
        "host_identity": "2" * 64,
        "identity": dict(empty),
        "launchd": dict(empty),
        "environment": dict(empty),
        "filesystem": dict(empty),
        "network": dict(empty),
        "process": dict(empty),
    }


def test_publish_evidence_creates_three_bound_artifacts(tmp_path: Path) -> None:
    policy = local_policy()
    release = tmp_path / "release"
    (release / "bin").mkdir(parents=True)
    for name in ("research-warehouse-job", "research-warehouse-monitor"):
        executable = release / "bin" / name
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
    manifest = build_release_tree_manifest(
        release,
        logical_release_root=policy.payload["release_root"],
        expected_owner_uid=os.getuid(),
        expected_owner_gid=os.getgid(),
    )
    manifest_path = tmp_path / "release-tree.json"
    manifest_sha = write_create_only(manifest_path, manifest)
    output_path = tmp_path / "success-output.json"
    evidence_path = tmp_path / "evidence.json"
    activation = {
        "policy_activated_at": "2026-07-30T12:00:00.000000Z",
        "pf_loaded_at": "2026-07-30T12:01:00.000000Z",
        "launchd_loaded_at": "2026-07-30T12:02:00.000000Z",
    }
    monitor = {
        "last_success_at": "2026-07-30T12:20:00.000000Z",
        "expected_official_day": "2026-07-30",
        "latest_official_day": "2026-07-30",
        "missing_official_days": [],
        "unreviewed_revision_count": 0,
        "hash_mismatch_count": 0,
        "disk_free_bytes": 100_000_000_000,
        "last_backup_at": "2026-07-30T12:25:00.000000Z",
        "backup_verified": True,
    }
    lock = {
        "path": policy.payload["release_lock_path"],
        "device": 1,
        "inode": 2,
        "owner_uid": 0,
        "owner_gid": 0,
        "mode": "0444",
        "nlink": 1,
    }

    result = publish_evidence(
        evidence_path,
        policy=policy,
        probes=probes(),
        activation=activation,
        monitor_input=monitor,
        release_tree_manifest_path=manifest_path,
        expected_release_tree_manifest_sha256=manifest_sha,
        release_lock_identity=lock,
        success_output_path=output_path,
        captured_at=datetime(2026, 7, 30, 12, 30, tzinfo=timezone.utc),
    )

    evidence_raw = evidence_path.read_bytes()
    evidence = parse_json_strict(evidence_raw, "test evidence")
    assert canonical_json_line(evidence) == evidence_raw
    assert result == {
        "evidence_raw_sha256": sha256(evidence_raw),
        "release_tree_manifest_raw_sha256": manifest_sha,
        "success_output_raw_sha256": sha256(output_path.read_bytes()),
    }
    assert evidence["success_receipt"]["completed_at"] == monitor["last_success_at"]
    assert evidence["success_receipt"]["output_owner_uid"] == os.getuid()
    assert evidence["release_tree_raw_sha256"] == manifest["tree_content_sha256"]
    assert output_path.stat().st_mode & 0o777 == 0o600


def test_publish_evidence_refuses_existing_success_output(tmp_path: Path) -> None:
    output = tmp_path / "success-output.json"
    output.write_text("existing")
    policy = local_policy()
    with pytest.raises(RegistryError, match="already exists"):
        from research_warehouse.m2_evidence_capture import publish_success_output

        publish_success_output(
            output,
            policy=policy,
            completed_at="2026-07-30T12:20:00.000000Z",
            monitor_input={},
        )
