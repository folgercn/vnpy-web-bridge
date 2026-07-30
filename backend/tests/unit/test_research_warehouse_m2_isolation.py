from __future__ import annotations

import ast
import fcntl
import inspect
import json
import os
import pwd
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import m2_isolation_cli
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_deployment_assets import verify_deployment_assets
from research_warehouse.m2_isolation_audit import (
    verify_isolation_evidence_semantics,
)
from research_warehouse.m2_isolation_contracts import (
    LOCK_RUNNER_SHA256,
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    WRAPPER_SHA256,
    load_isolation_evidence,
    load_isolation_policy,
)
from research_warehouse.m2_monitor import evaluate_monitor
from research_warehouse.m2_probe_binding import probe_result_sha256
from research_warehouse.m2_release_artifacts import (
    VerifiedReleaseArtifacts,
    build_release_tree_manifest,
    verify_release_artifacts,
)
from research_warehouse.m2_release_lock import (
    ReleaseLockIdentity,
    hold_release_update_lock,
    hold_release_verification_lock,
)
from research_warehouse.m2_verifier import verify_m2_isolation_files

M2_DIR = ROOT / "deployments/research-warehouse/m2"
POLICY_PATH = M2_DIR / "isolation-policy-v1.json"
UTC = timezone.utc
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
RELEASE_TREE_SHA256 = "2" * 64
RELEASE_MANIFEST_SHA256 = "3" * 64
OUTPUT_SHA256 = "4" * 64
OUTPUT_PATH = "/Users/Shared/vnpy-research/runtime/success-output.json"
LOCK_IDENTITY = {
    "path": "/usr/local/libexec/vnpyresearch/release.lock",
    "device": 13,
    "inode": 14,
    "owner_uid": 0,
    "owner_gid": 0,
    "mode": "0444",
    "nlink": 1,
}


def probed(values: dict, probe_class: str) -> dict:
    result = {
        "observed_at": "2026-07-29T10:30:00.000000Z",
        "probe_result_sha256": "0" * 64,
        **values,
    }
    result["probe_result_sha256"] = probe_result_sha256(
        result,
        probe_class=probe_class,
        host_identity="1" * 64,
    )
    return result


def rebind_probe(item: dict, probe_class: str) -> None:
    item[probe_class]["probe_result_sha256"] = probe_result_sha256(
        item[probe_class],
        probe_class=probe_class,
        host_identity=item["host_identity"],
    )


def verified_release_artifacts() -> VerifiedReleaseArtifacts:
    return VerifiedReleaseArtifacts(
        release_lock_identity=LOCK_IDENTITY,
        release_tree_manifest_raw_sha256=RELEASE_MANIFEST_SHA256,
        release_tree_content_sha256=RELEASE_TREE_SHA256,
        release_root_identity={
            "device": 9,
            "inode": 10,
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": "0755",
            "acl_free": True,
        },
        output_path=OUTPUT_PATH,
        output_raw_sha256=OUTPUT_SHA256,
        output_device=11,
        output_inode=12,
        output_owner_uid=503,
        output_mode="0600",
        output_nlink=1,
        output_acl_free=True,
    )


def verified_lock_identity() -> ReleaseLockIdentity:
    return ReleaseLockIdentity(**LOCK_IDENTITY)


def policy():
    return load_isolation_policy(POLICY_PATH)


def monitor_input() -> dict:
    return {
        "last_success_at": "2026-07-29T11:00:00.000000Z",
        "expected_official_day": "2026-07-29",
        "latest_official_day": "2026-07-29",
        "missing_official_days": [],
        "unreviewed_revision_count": 0,
        "hash_mismatch_count": 0,
        "disk_free_bytes": 100_000_000_000,
        "last_backup_at": "2026-07-29T10:00:00.000000Z",
        "backup_verified": True,
    }


def evidence() -> dict:
    value = policy()
    roots = {
        value.payload[field]: {
            "owner_uid": 503,
            "owner_gid": 503,
            "mode": "0700",
            "device": 1,
        }
        for field in ("home", "custody_root", "runtime_root", "backup_root")
    }
    return {
        "schema_version": "vnpy_research_m2_isolation_evidence_v1",
        "captured_at": "2026-07-29T11:55:00.000000Z",
        "host_identity": "1" * 64,
        "policy_raw_sha256": value.raw_sha256,
        "registry_raw_sha256": value.payload["registry_raw_sha256"],
        "release_tree_raw_sha256": RELEASE_TREE_SHA256,
        "release_tree_manifest_raw_sha256": RELEASE_MANIFEST_SHA256,
        "release_lock_identity": LOCK_IDENTITY,
        "activation": {
            "policy_activated_at": "2026-07-29T09:00:00.000000Z",
            "pf_loaded_at": "2026-07-29T09:01:00.000000Z",
            "launchd_loaded_at": "2026-07-29T09:02:00.000000Z",
            "policy_raw_sha256": value.raw_sha256,
            "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
            "plist_raw_sha256s": PLIST_SHA256,
        },
        "identity": probed(
            {
                "user": "vnpyresearch",
                "group": "vnpyresearch",
                "uid": 503,
                "gid": 503,
                "supplementary_gids": [12, 61, 100, 503],
                "home": value.payload["home"],
                "inherited_fujun_home_acl": False,
                "web_bridge_uid": 501,
                "web_bridge_gid": 20,
            },
            "identity",
        ),
        "launchd": probed(
            {
                "loaded_labels": value.payload["launchd_labels"],
                "plist_raw_sha256s": PLIST_SHA256,
                "jobs_run_as_user": {
                    label: value.user for label in value.payload["launchd_labels"]
                },
                "program_arguments": {
                    label: [value.payload["program_paths"][label]]
                    for label in value.payload["launchd_labels"]
                },
            },
            "launchd",
        ),
        "environment": probed(
            {
                "values": value.payload["allowed_environment"],
            },
            "environment",
        ),
        "filesystem": probed(
            {
                "root_facts": roots,
                "code_root_facts": {
                    path: {
                        "owner_uid": 0,
                        "owner_gid": 0,
                        "mode": "0755",
                        "service_user_writable": False,
                        "symlink_free": True,
                    }
                    for path in (
                        value.payload["libexec_root"],
                        value.payload["release_root"],
                    )
                },
                "executable_facts": {
                    path: {
                        "raw_sha256": digest,
                        "owner_uid": 0,
                        "owner_gid": 0,
                        "mode": "0555",
                        "regular": True,
                        "symlink": False,
                        "nlink": 1,
                        "device": 1,
                        "inode": index,
                        "parent_chain_service_writable": False,
                    }
                    for index, (path, digest) in enumerate(
                        {
                            **WRAPPER_SHA256,
                            f"{value.payload['libexec_root']}/release-lock-runner": (
                                LOCK_RUNNER_SHA256
                            ),
                        }.items(),
                        start=1,
                    )
                },
                "forbidden_path_reads": {
                    path: False for path in value.payload["forbidden_paths"]
                },
                "fujun_home_traversable": False,
                "writable_paths": sorted(roots),
                "shared_writable_mount": False,
            },
            "filesystem",
        ),
        "network": probed(
            {
                "pf_enabled": True,
                "pf_anchor_loaded": True,
                "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
                "default_block_for_service_user": True,
                "literal_ip_tables_only": True,
                "pf_table_entries": {
                    "DNS": ["192.168.100.1"],
                    "NTP": ["192.168.100.1"],
                    "REGISTRY_HTTPS": ["1.1.1.1", "8.8.8.8"],
                },
                "resolved_registry_hosts": {
                    "www.ine.cn": ["1.1.1.1"],
                    "www.shfe.com.cn": ["8.8.8.8"],
                },
                "allowed_egress_classes_observed": value.payload[
                    "allowed_egress_classes"
                ],
                "forbidden_target_connectivity": {
                    target: False
                    for target in value.payload["forbidden_network_targets"]
                },
                "docker_socket_connectivity": False,
                "docker_network_membership": False,
                "unexpected_egress": [],
            },
            "network",
        ),
        "process": probed(
            {
                "service_process_uid": 503,
                "service_process_gid": 503,
                "shared_process_identity": False,
                "shared_credential_scope": False,
                "shared_network_namespace": False,
            },
            "process",
        ),
        "monitor_input": monitor_input(),
        "success_receipt": {
            "schema_version": "vnpy_research_m2_success_receipt_v1",
            "host_identity": "1" * 64,
            "service_uid": 503,
            "service_gid": 503,
            "policy_raw_sha256": value.raw_sha256,
            "plist_raw_sha256s": PLIST_SHA256,
            "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
            "release_tree_raw_sha256": RELEASE_TREE_SHA256,
            "release_tree_manifest_raw_sha256": RELEASE_MANIFEST_SHA256,
            "release_lock_identity": LOCK_IDENTITY,
            "started_at": "2026-07-29T10:45:00.000000Z",
            "completed_at": "2026-07-29T11:00:00.000000Z",
            "output_path": OUTPUT_PATH,
            "output_raw_sha256": OUTPUT_SHA256,
            "output_device": 11,
            "output_inode": 12,
            "output_owner_uid": 503,
            "output_mode": "0600",
            "create_only": True,
            "regular": True,
            "nlink": 1,
        },
        "authority": {
            "account_data_read": False,
            "control_authorized": False,
            "deployment_authorized": False,
            "execution_authorized": False,
            "network_beyond_allowlist_authorized": False,
            "order_authorized": False,
            "permit_authorized": False,
            "position_mutation_authorized": False,
            "production_authorized": False,
            "rpc_authorized": False,
            "trading_authorized": False,
        },
    }


def private_evidence(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "evidence.json"
    path.write_bytes(canonical_json_line(payload))
    path.chmod(0o600)
    return path


def build_private_manifest(
    tmp_path: Path,
    release: Path,
    owner_uid: int,
    owner_gid: int,
) -> Path:
    value = build_release_tree_manifest(
        release,
        logical_release_root=policy().payload["release_root"],
        expected_owner_uid=owner_uid,
        expected_owner_gid=owner_gid,
    )
    path = tmp_path / "current-release-manifest.json"
    path.write_bytes(canonical_json_line(value))
    path.chmod(0o600)
    return path


def release_artifact_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, int, int]:
    release = tmp_path / "release"
    binary_dir = release / "bin"
    binary_dir.mkdir(parents=True)
    release.chmod(0o755)
    binary_dir.chmod(0o755)
    executable = binary_dir / "research-warehouse-job"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o555)
    monitor_executable = binary_dir / "research-warehouse-monitor"
    monitor_executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    monitor_executable.chmod(0o555)
    owner_uid = os.geteuid()
    owner_gid = os.getegid()
    manifest_path = build_private_manifest(
        tmp_path,
        release,
        owner_uid,
        owner_gid,
    )
    output_path = tmp_path / "success-output.json"
    output_path.write_bytes(b'{"status":"ok"}\n')
    output_path.chmod(0o600)
    return (
        release,
        executable,
        manifest_path,
        output_path,
        owner_uid,
        owner_gid,
    )


def test_policy_assets_and_healthy_evidence(tmp_path: Path) -> None:
    value = policy()
    assets = verify_deployment_assets(M2_DIR, policy=value)
    assert assets == {
        **PLIST_SHA256,
        **WRAPPER_SHA256,
        f"{value.payload['libexec_root']}/release-lock-runner": (LOCK_RUNNER_SHA256),
        "pf_anchor": PF_ANCHOR_SHA256,
    }
    evidence_path = private_evidence(tmp_path, evidence())
    loaded = load_isolation_evidence(
        evidence_path,
        expected_raw_sha256=sha256(evidence_path.read_bytes()),
    )
    result = verify_isolation_evidence_semantics(
        loaded,
        policy=value,
        now=NOW,
        release_artifacts=verified_release_artifacts(),
    )
    assert result["status"] == "M2_RESEARCH_ISOLATION_SEMANTICS_VERIFIED"
    assert result["status"] != "M2_RESEARCH_ISOLATION_VERIFIED"
    assert result["monitor"]["status"] == "HEALTHY"
    assert set(result["authority"].values()) == {False}
    with pytest.raises(RegistryError, match="not independently verified"):
        verify_isolation_evidence_semantics(
            loaded,
            policy=value,
            now=NOW,
            release_artifacts=asdict(verified_release_artifacts()),  # type: ignore[arg-type]
        )
    with pytest.raises(RegistryError, match="raw SHA256 mismatch"):
        load_isolation_evidence(
            evidence_path,
            expected_raw_sha256="f" * 64,
        )


def test_policy_and_pf_tables_are_exactly_pinned(tmp_path: Path) -> None:
    copied = tmp_path / "policy.json"
    copied.write_bytes(
        POLICY_PATH.read_bytes().replace(b"vnpyresearch", b"evilresearch")
    )
    copied.chmod(0o600)
    with pytest.raises(RegistryError, match="raw SHA256 mismatch"):
        load_isolation_policy(copied)
    item = evidence()
    item["network"]["pf_table_entries"]["REGISTRY_HTTPS"].append("127.0.0.1")
    rebind_probe(item, "network")
    with pytest.raises(RegistryError, match="forbidden IP"):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda item: item["filesystem"]["executable_facts"][
                "/usr/local/libexec/vnpyresearch/run-warehouse"
            ].__setitem__("parent_chain_service_writable", True),
            "executable custody",
        ),
        (
            lambda item: item["filesystem"]["executable_facts"][
                "/usr/local/libexec/vnpyresearch/run-warehouse"
            ].__setitem__("raw_sha256", "f" * 64),
            "executable custody",
        ),
        (
            lambda item: item["identity"].__setitem__(
                "observed_at",
                "2026-07-29T08:59:59.000000Z",
            ),
            "predates active policy",
        ),
        (
            lambda item: item["success_receipt"].__setitem__(
                "started_at",
                "2026-07-29T08:59:59.000000Z",
            ),
            "receipt activation binding",
        ),
        (
            lambda item: item["monitor_input"].__setitem__(
                "last_success_at",
                "2026-07-29T10:59:59.000000Z",
            ),
            "receipt activation binding",
        ),
    ],
)
def test_activation_and_root_owned_entrypoint_failures_close(
    mutate,
    message: str,
) -> None:
    item = evidence()
    mutate(item)
    if "executable custody" in message:
        rebind_probe(item, "filesystem")
    with pytest.raises(RegistryError, match=message):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda item: item["identity"].__setitem__(
                "inherited_fujun_home_acl",
                True,
            ),
            "identity",
        ),
        (
            lambda item: item["identity"].__setitem__(
                "supplementary_gids",
                [12, 61, 80, 100, 503],
            ),
            "identity",
        ),
        (
            lambda item: item["identity"].__setitem__(
                "supplementary_gids",
                [12, 61, 503],
            ),
            "identity",
        ),
        (
            lambda item: item["identity"].__setitem__(
                "supplementary_gids",
                [12, 61, 100, "503"],
            ),
            "identity",
        ),
        (
            lambda item: item["filesystem"]["forbidden_path_reads"].__setitem__(
                "/var/run/docker.sock",
                True,
            ),
            "filesystem",
        ),
        (
            lambda item: item["network"]["forbidden_target_connectivity"].__setitem__(
                "192.168.100.187:2014",
                True,
            ),
            "egress",
        ),
        (
            lambda item: item["network"].__setitem__(
                "docker_socket_connectivity",
                True,
            ),
            "egress",
        ),
        (
            lambda item: item["process"].__setitem__(
                "shared_network_namespace",
                True,
            ),
            "process",
        ),
        (
            lambda item: item["environment"]["values"].__setitem__(
                "HTTP_PROXY",
                "http://proxy.invalid",
            ),
            "environment",
        ),
    ],
)
def test_isolation_threat_model_failures_close(mutate, message: str) -> None:
    item = evidence()
    mutate(item)
    section = {
        "identity": "identity",
        "filesystem": "filesystem",
        "egress": "network",
        "process": "process",
        "environment": "environment",
    }[message]
    rebind_probe(item, section)
    with pytest.raises(RegistryError, match=message):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )


def test_admin_primary_gid_cannot_be_rebound_as_service_group() -> None:
    item = evidence()
    item["identity"]["gid"] = 80
    item["identity"]["supplementary_gids"] = [12, 61, 80, 100]
    for facts in item["filesystem"]["root_facts"].values():
        facts["owner_gid"] = 80
    item["process"]["service_process_gid"] = 80
    item["success_receipt"]["service_gid"] = 80
    for probe_class in ("identity", "filesystem", "process"):
        rebind_probe(item, probe_class)

    with pytest.raises(RegistryError, match="identity"):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )


def test_probe_hash_binds_class_host_time_and_normalized_result() -> None:
    item = evidence()
    item["network"]["docker_socket_connectivity"] = True
    with pytest.raises(RegistryError, match="network probe result SHA256 mismatch"):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )
    item = evidence()
    item["identity"]["probe_result_sha256"] = item["launchd"]["probe_result_sha256"]
    with pytest.raises(RegistryError, match="identity probe result SHA256 mismatch"):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )
    item = evidence()
    item["identity"]["observed_at"] = "2026-07-29T10:31:00.000000Z"
    with pytest.raises(RegistryError, match="identity probe result SHA256 mismatch"):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )
    item = evidence()
    item["host_identity"] = "9" * 64
    with pytest.raises(RegistryError, match="identity probe result SHA256 mismatch"):
        verify_isolation_evidence_semantics(
            item,
            policy=policy(),
            now=NOW,
            release_artifacts=verified_release_artifacts(),
        )


def test_release_manifest_and_output_are_recomputed_from_files(
    tmp_path: Path,
) -> None:
    (
        release,
        executable,
        manifest_path,
        output_path,
        owner_uid,
        owner_gid,
    ) = release_artifact_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_bytes())
    result = verify_release_artifacts(
        policy=policy(),
        release_root=release,
        manifest_path=manifest_path,
        expected_manifest_raw_sha256=sha256(manifest_path.read_bytes()),
        output_path=output_path,
        expected_output_raw_sha256=sha256(output_path.read_bytes()),
        output_owner_uid=owner_uid,
        release_lock_identity=verified_lock_identity(),
        expected_release_owner_uid=owner_uid,
        expected_release_owner_gid=owner_gid,
    )
    assert result.release_tree_content_sha256 == (manifest["tree_content_sha256"])
    assert result.output_raw_sha256 == sha256(output_path.read_bytes())
    manifest_raw = manifest_path.read_bytes()
    manifest_path.write_bytes(manifest_raw + b" ")
    manifest_path.chmod(0o600)
    with pytest.raises(RegistryError, match="manifest raw SHA256 mismatch"):
        verify_release_artifacts(
            policy=policy(),
            release_root=release,
            manifest_path=manifest_path,
            expected_manifest_raw_sha256=sha256(manifest_raw),
            output_path=output_path,
            expected_output_raw_sha256=sha256(output_path.read_bytes()),
            output_owner_uid=owner_uid,
            release_lock_identity=verified_lock_identity(),
            expected_release_owner_uid=owner_uid,
            expected_release_owner_gid=owner_gid,
        )
    manifest_path.write_bytes(manifest_raw)
    manifest_path.chmod(0o600)
    executable.chmod(0o755)
    executable.write_bytes(b"#!/bin/sh\nexit 1\n")
    executable.chmod(0o555)
    with pytest.raises(RegistryError, match="tree/manifest mismatch"):
        verify_release_artifacts(
            policy=policy(),
            release_root=release,
            manifest_path=manifest_path,
            expected_manifest_raw_sha256=sha256(manifest_path.read_bytes()),
            output_path=output_path,
            expected_output_raw_sha256=sha256(output_path.read_bytes()),
            output_owner_uid=owner_uid,
            release_lock_identity=verified_lock_identity(),
            expected_release_owner_uid=owner_uid,
            expected_release_owner_gid=owner_gid,
        )
    output_path.write_bytes(b'{"status":"forged"}\n')
    output_path.chmod(0o600)
    current_manifest = build_private_manifest(
        tmp_path,
        release,
        owner_uid,
        owner_gid,
    )
    with pytest.raises(RegistryError, match="output custody/hash mismatch"):
        verify_release_artifacts(
            policy=policy(),
            release_root=release,
            manifest_path=current_manifest,
            expected_manifest_raw_sha256=sha256(current_manifest.read_bytes()),
            output_path=output_path,
            expected_output_raw_sha256=OUTPUT_SHA256,
            output_owner_uid=owner_uid,
            release_lock_identity=verified_lock_identity(),
            expected_release_owner_uid=owner_uid,
            expected_release_owner_gid=owner_gid,
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL")
def test_final_release_verifier_rejects_descendant_acl(tmp_path: Path) -> None:
    (
        release,
        executable,
        manifest_path,
        output_path,
        owner_uid,
        owner_gid,
    ) = release_artifact_fixture(tmp_path)
    account = pwd.getpwuid(os.getuid()).pw_name
    subprocess.check_call(
        ["chmod", "+a", f"user:{account} allow write", str(executable)]
    )

    with pytest.raises(RegistryError, match="extended ACL"):
        verify_release_artifacts(
            policy=policy(),
            release_root=release,
            manifest_path=manifest_path,
            expected_manifest_raw_sha256=sha256(manifest_path.read_bytes()),
            output_path=output_path,
            expected_output_raw_sha256=sha256(output_path.read_bytes()),
            output_owner_uid=owner_uid,
            release_lock_identity=verified_lock_identity(),
            expected_release_owner_uid=owner_uid,
            expected_release_owner_gid=owner_gid,
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL")
def test_final_release_verifier_rejects_success_output_acl(
    tmp_path: Path,
) -> None:
    (
        release,
        _executable,
        manifest_path,
        output_path,
        owner_uid,
        owner_gid,
    ) = release_artifact_fixture(tmp_path)
    account = pwd.getpwuid(os.getuid()).pw_name
    subprocess.check_call(
        ["chmod", "+a", f"user:{account} allow write", str(output_path)]
    )

    with pytest.raises(RegistryError, match="extended ACL"):
        verify_release_artifacts(
            policy=policy(),
            release_root=release,
            manifest_path=manifest_path,
            expected_manifest_raw_sha256=sha256(manifest_path.read_bytes()),
            output_path=output_path,
            expected_output_raw_sha256=sha256(output_path.read_bytes()),
            output_owner_uid=owner_uid,
            release_lock_identity=verified_lock_identity(),
            expected_release_owner_uid=owner_uid,
            expected_release_owner_gid=owner_gid,
        )


@pytest.mark.parametrize("race", ["add-after-enumerate", "replace-after-entry"])
def test_release_tree_concurrent_membership_and_entry_races_fail_closed(
    tmp_path: Path,
    race: str,
) -> None:
    (
        release,
        executable,
        manifest_path,
        output_path,
        owner_uid,
        owner_gid,
    ) = release_artifact_fixture(tmp_path)
    fired = False

    def race_hook(event: str, relative_path: str) -> None:
        nonlocal fired
        if fired:
            return
        if (
            race == "add-after-enumerate"
            and event == "after_enumerate"
            and relative_path == "bin"
        ):
            added = release / "bin/unpinned-tool"
            added.write_bytes(b"unpinned\n")
            added.chmod(0o555)
            fired = True
        elif (
            race == "replace-after-entry"
            and event == "after_entry"
            and relative_path == "bin/research-warehouse-job"
        ):
            replacement = tmp_path / "replacement-job"
            replacement.write_bytes(b"#!/bin/sh\nexit 9\n")
            replacement.chmod(0o555)
            os.replace(replacement, executable)
            fired = True

    with pytest.raises(RegistryError, match="release .*changed"):
        verify_release_artifacts(
            policy=policy(),
            release_root=release,
            manifest_path=manifest_path,
            expected_manifest_raw_sha256=sha256(manifest_path.read_bytes()),
            output_path=output_path,
            expected_output_raw_sha256=sha256(output_path.read_bytes()),
            output_owner_uid=owner_uid,
            release_lock_identity=verified_lock_identity(),
            expected_release_owner_uid=owner_uid,
            expected_release_owner_gid=owner_gid,
            _scan_hook=race_hook,
        )
    assert fired is True


def test_release_lock_blocks_concurrent_exclusive_update(tmp_path: Path) -> None:
    lock_path = tmp_path / "release.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o444)
    with hold_release_verification_lock(
        lock_path,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
    ) as held:
        held.revalidate()
        competing = os.open(lock_path, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(
                    competing,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
        finally:
            os.close(competing)
    with (
        hold_release_update_lock(
            lock_path,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
        ),
        pytest.raises(
            RegistryError,
            match="cannot acquire",
        ),
        hold_release_verification_lock(
            lock_path,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
        ),
    ):
        pytest.fail("shared verification lock bypassed update lock")


def test_only_file_verifier_can_issue_final_verified_status() -> None:
    assert (
        "release_artifacts"
        not in inspect.signature(verify_m2_isolation_files).parameters
    )
    issuers = {
        path.name
        for path in (ROOT / "scripts/research_warehouse").glob("m2_*.py")
        if '"M2_RESEARCH_ISOLATION_VERIFIED"' in path.read_text()
    }
    assert issuers == {"m2_verifier.py"}


@pytest.mark.parametrize(
    ("field", "value", "incident"),
    [
        (
            "last_success_at",
            "2026-07-20T00:00:00.000000Z",
            "LAST_SUCCESS_STALE",
        ),
        ("missing_official_days", ["2026-07-29"], "OFFICIAL_DAY_MISSING"),
        ("unreviewed_revision_count", 1, "UNREVIEWED_REVISION"),
        ("hash_mismatch_count", 1, "HASH_MISMATCH"),
        ("disk_free_bytes", 1, "DISK_FREE_LOW"),
        ("backup_verified", False, "BACKUP_STALE_OR_UNVERIFIED"),
    ],
)
def test_monitor_covers_required_failure_classes(
    field: str,
    value,
    incident: str,
) -> None:
    item = monitor_input()
    item[field] = value
    result = evaluate_monitor(item, policy=policy(), now=NOW)
    assert result["status"] == "DEGRADED"
    assert incident in result["incidents"]
    assert set(result["authority"].values()) == {False}


def test_cli_and_research_only_import_boundary(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    evidence_path = private_evidence(tmp_path, evidence())
    monkeypatch.setattr(
        m2_isolation_cli,
        "verify_m2_isolation_files",
        lambda **_kwargs: {
            "schema_version": "vnpy_research_m2_isolation_result_v1",
            "status": "M2_RESEARCH_ISOLATION_VERIFIED",
        },
    )
    assert (
        m2_isolation_cli.main(
            [
                "--policy",
                str(POLICY_PATH),
                "--deployment-dir",
                str(M2_DIR),
                "--evidence",
                str(evidence_path),
                "--expected-evidence-sha256",
                sha256(evidence_path.read_bytes()),
                "--release-root",
                policy().payload["release_root"],
                "--release-tree-manifest",
                str(tmp_path / "release-manifest.json"),
                "--expected-release-tree-manifest-sha256",
                RELEASE_MANIFEST_SHA256,
                "--success-output",
                OUTPUT_PATH,
                "--expected-success-output-sha256",
                OUTPUT_SHA256,
                "--now",
                "2026-07-29T12:00:00.000000Z",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == (
        "M2_RESEARCH_ISOLATION_VERIFIED"
    )
    forbidden = {"app", "vnpy", "rpc", "questdb", "docker", "sqlalchemy"}
    for name in (
        "m2_isolation_contracts.py",
        "m2_deployment_assets.py",
        "m2_isolation_audit.py",
        "m2_probe_binding.py",
        "m2_release_artifacts.py",
        "m2_release_lock.py",
        "m2_release_tree_custody.py",
        "m2_success_binding.py",
        "m2_verifier.py",
        "m2_monitor.py",
        "m2_isolation_cli.py",
    ):
        tree = ast.parse((ROOT / "scripts/research_warehouse" / name).read_text())
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden)
