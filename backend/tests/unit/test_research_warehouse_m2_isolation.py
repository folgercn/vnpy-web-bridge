from __future__ import annotations

import ast
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_deployment_assets import verify_deployment_assets
from research_warehouse.m2_isolation_audit import verify_isolation_evidence
from research_warehouse.m2_isolation_contracts import (
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    WRAPPER_SHA256,
    load_isolation_evidence,
    load_isolation_policy,
)
from research_warehouse.m2_monitor import evaluate_monitor

M2_DIR = ROOT / "deployments/research-warehouse/m2"
POLICY_PATH = M2_DIR / "isolation-policy-v1.json"
UTC = timezone.utc
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
RELEASE_TREE_SHA256 = "2" * 64
PROBE_SHA256 = "3" * 64


def probed(values: dict) -> dict:
    return {
        "observed_at": "2026-07-29T10:30:00.000000Z",
        "probe_result_sha256": PROBE_SHA256,
        **values,
    }


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
            "owner_uid": 510,
            "owner_gid": 510,
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
        "activation": {
            "policy_activated_at": "2026-07-29T09:00:00.000000Z",
            "pf_loaded_at": "2026-07-29T09:01:00.000000Z",
            "launchd_loaded_at": "2026-07-29T09:02:00.000000Z",
            "policy_raw_sha256": value.raw_sha256,
            "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
            "plist_raw_sha256s": PLIST_SHA256,
        },
        "identity": probed({
            "user": "vnpyresearch",
            "group": "vnpyresearch",
            "uid": 510,
            "gid": 510,
            "supplementary_gids": [510],
            "home": value.payload["home"],
            "inherited_fujun_home_acl": False,
            "web_bridge_uid": 501,
            "web_bridge_gid": 20,
        }),
        "launchd": probed({
            "loaded_labels": value.payload["launchd_labels"],
            "plist_raw_sha256s": PLIST_SHA256,
            "jobs_run_as_user": {
                label: value.user
                for label in value.payload["launchd_labels"]
            },
            "program_arguments": {
                label: [value.payload["program_paths"][label]]
                for label in value.payload["launchd_labels"]
            },
        }),
        "environment": probed({
            "values": value.payload["allowed_environment"],
        }),
        "filesystem": probed({
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
                    WRAPPER_SHA256.items(),
                    start=1,
                )
            },
            "forbidden_path_reads": {
                path: False for path in value.payload["forbidden_paths"]
            },
            "fujun_home_traversable": False,
            "writable_paths": sorted(roots),
            "shared_writable_mount": False,
        }),
        "network": probed({
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
        }),
        "process": probed({
            "service_process_uid": 510,
            "service_process_gid": 510,
            "shared_process_identity": False,
            "shared_credential_scope": False,
            "shared_network_namespace": False,
        }),
        "monitor_input": monitor_input(),
        "success_receipt": {
            "schema_version": "vnpy_research_m2_success_receipt_v1",
            "host_identity": "1" * 64,
            "service_uid": 510,
            "service_gid": 510,
            "policy_raw_sha256": value.raw_sha256,
            "plist_raw_sha256s": PLIST_SHA256,
            "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
            "release_tree_raw_sha256": RELEASE_TREE_SHA256,
            "started_at": "2026-07-29T10:45:00.000000Z",
            "completed_at": "2026-07-29T11:00:00.000000Z",
            "output_raw_sha256": "4" * 64,
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


def test_policy_assets_and_healthy_evidence(tmp_path: Path) -> None:
    value = policy()
    assets = verify_deployment_assets(M2_DIR, policy=value)
    assert assets == {
        **PLIST_SHA256,
        **WRAPPER_SHA256,
        "pf_anchor": PF_ANCHOR_SHA256,
    }
    evidence_path = private_evidence(tmp_path, evidence())
    loaded = load_isolation_evidence(
        evidence_path,
        expected_raw_sha256=sha256(evidence_path.read_bytes()),
    )
    result = verify_isolation_evidence(
        loaded,
        policy=value,
        now=NOW,
        expected_release_tree_sha256=RELEASE_TREE_SHA256,
    )
    assert result["status"] == "M2_RESEARCH_ISOLATION_VERIFIED"
    assert result["monitor"]["status"] == "HEALTHY"
    assert set(result["authority"].values()) == {False}
    with pytest.raises(RegistryError, match="raw SHA256 mismatch"):
        load_isolation_evidence(
            evidence_path,
            expected_raw_sha256="f" * 64,
        )


def test_policy_and_pf_tables_are_exactly_pinned(tmp_path: Path) -> None:
    copied = tmp_path / "policy.json"
    copied.write_bytes(POLICY_PATH.read_bytes().replace(b"vnpyresearch", b"evilresearch"))
    copied.chmod(0o600)
    with pytest.raises(RegistryError, match="raw SHA256 mismatch"):
        load_isolation_policy(copied)
    item = evidence()
    item["network"]["pf_table_entries"]["REGISTRY_HTTPS"].append(
        "127.0.0.1"
    )
    with pytest.raises(RegistryError, match="forbidden IP"):
        verify_isolation_evidence(
            item,
            policy=policy(),
            now=NOW,
            expected_release_tree_sha256=RELEASE_TREE_SHA256,
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
    with pytest.raises(RegistryError, match=message):
        verify_isolation_evidence(
            item,
            policy=policy(),
            now=NOW,
            expected_release_tree_sha256=RELEASE_TREE_SHA256,
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
    with pytest.raises(RegistryError, match=message):
        verify_isolation_evidence(
            item,
            policy=policy(),
            now=NOW,
            expected_release_tree_sha256=RELEASE_TREE_SHA256,
        )


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


def test_cli_and_research_only_import_boundary(tmp_path: Path) -> None:
    evidence_path = private_evidence(tmp_path, evidence())
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/research_warehouse_m2_isolation_cli.py"),
            "--policy",
            str(POLICY_PATH),
            "--deployment-dir",
            str(M2_DIR),
            "--evidence",
            str(evidence_path),
            "--expected-evidence-sha256",
            sha256(evidence_path.read_bytes()),
            "--expected-release-tree-sha256",
            RELEASE_TREE_SHA256,
            "--now",
            "2026-07-29T12:00:00.000000Z",
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "scripts"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(completed.stdout)["status"] == (
        "M2_RESEARCH_ISOLATION_VERIFIED"
    )
    forbidden = {"app", "vnpy", "rpc", "questdb", "docker", "sqlalchemy"}
    for name in (
        "m2_isolation_contracts.py",
        "m2_deployment_assets.py",
        "m2_isolation_audit.py",
        "m2_monitor.py",
        "m2_isolation_cli.py",
    ):
        tree = ast.parse(
            (ROOT / "scripts/research_warehouse" / name).read_text()
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden)
