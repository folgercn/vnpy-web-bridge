from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.verify_safe_restart_gate import _sha256_json

ROOT = Path(__file__).resolve().parents[3]
SOURCE_SHA = "b" * 40
HASH = "a" * 64
IMAGE_DIGEST = f"sha256:{HASH}"
PLAN_ID = f"release-plan-{'c' * 64}"
NOW = datetime(2026, 8, 4, 1, 0, 20, tzinfo=timezone.utc)


def _schema(name: str) -> dict[str, object]:
    return json.loads(
        (ROOT / f"docs/schemas/{name}").read_text(encoding="utf-8")
    )


def _snapshot() -> dict[str, object]:
    return {
        "schema_version": "web_bridge_deployment_safety_snapshot_v1",
        "captured_at": "2026-08-04T01:00:00Z",
        "execution_plan_status": "IDLE",
        "execution_plan_hash": None,
        "plan_version": 7,
        "state_version": "state-v3",
        "state_sha256": HASH,
        "active_orders_snapshot_sha256": "e" * 64,
        "positions_snapshot_sha256": "7" * 64,
        "checkpoint_sha256": "f" * 64,
        "rpc_generation": 3,
        "web_trade_enabled": False,
        "execution_authority_revoked": True,
        "auto_dispatch_stopped": True,
        "active_orders": 0,
        "unknown_outcome": False,
        "reconcile_required": False,
        "checkpoint_durable": True,
    }


def _receipt() -> dict[str, object]:
    receipt = {
        "schema_version": "web_bridge_safe_restart_receipt_v1",
        "purpose": "authorize_one_bound_web_bridge_restart_attempt",
        "request_id": "request_00000001",
        "deployment_attempt_id": "deployment_00000001",
        "release_plan_id": PLAN_ID,
        "release_plan_core_sha256": "1" * 64,
        "restart_action_sha256": "2" * 64,
        "unit": "web-bridge",
        "issued_at": "2026-08-04T01:00:00Z",
        "expires_at": "2026-08-04T01:01:00Z",
        "ttl_seconds": 60,
        "drain_epoch": 4,
        "execution_epoch": 7,
        "issuer_source_commit_sha": "c" * 40,
        "issuer_image_digest": IMAGE_DIGEST,
        "issuer_config_sha256": "3" * 64,
        "issuer_runtime_instance_id": "runtime_00000001",
        "target_source_commit_sha": SOURCE_SHA,
        "target_image_digest": IMAGE_DIGEST,
        "target_config_sha256": "4" * 64,
        "rollback_image_digest": IMAGE_DIGEST,
        "rollback_config_sha256": "5" * 64,
        "nonce": "restart_nonce_0001",
        "snapshot": _snapshot(),
        "safe_to_restart": True,
        "one_shot": True,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
    }
    core_sha = _sha256_json(receipt)
    receipt["receipt_id"] = f"safe-restart-{core_sha}"
    receipt["receipt_core_sha256"] = core_sha
    return receipt


def _recheck(receipt: dict[str, object]) -> dict[str, object]:
    snapshot = dict(receipt["snapshot"])
    snapshot["captured_at"] = "2026-08-04T01:00:15Z"
    return {
        "schema_version": "web_bridge_safe_restart_recheck_v1",
        "receipt_id": receipt["receipt_id"],
        "receipt_raw_sha256": hashlib.sha256(
            json.dumps(
                receipt,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        ).hexdigest(),
        "deployment_attempt_id": receipt["deployment_attempt_id"],
        "release_plan_core_sha256": receipt["release_plan_core_sha256"],
        "restart_action_sha256": receipt["restart_action_sha256"],
        "drain_epoch": receipt["drain_epoch"],
        "execution_epoch": receipt["execution_epoch"],
        "checked_at": "2026-08-04T01:00:15Z",
        "snapshot": snapshot,
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def _run_gate(
    tmp_path: Path,
    *,
    receipt: dict[str, object] | None = None,
    recheck: dict[str, object] | None = None,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    receipt = receipt or _receipt()
    recheck = recheck or _recheck(receipt)
    receipt_path = tmp_path / "receipt.json"
    recheck_path = tmp_path / "recheck.json"
    receipt_schema_path = tmp_path / "receipt.schema.json"
    recheck_schema_path = tmp_path / "recheck.schema.json"
    _write_json(receipt_path, receipt)
    _write_json(recheck_path, recheck)
    receipt_path.chmod(0o600)
    recheck_path.chmod(0o600)
    _write_json(
        receipt_schema_path,
        _schema("web-bridge-safe-restart-receipt-v1.schema.json"),
    )
    _write_json(
        recheck_schema_path,
        _schema("web-bridge-safe-restart-recheck-v1.schema.json"),
    )
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/verify_safe_restart_gate.py"),
            "--receipt",
            str(receipt_path),
            "--recheck",
            str(recheck_path),
            "--receipt-schema",
            str(receipt_schema_path),
            "--recheck-schema",
            str(recheck_schema_path),
            "--expected-plan-id",
            PLAN_ID,
            "--expected-source-commit",
            SOURCE_SHA,
            "--expected-unit",
            "web-bridge",
            "--now",
            NOW.isoformat(),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_gate_validates_fresh_bound_evidence_without_consuming_it(
    tmp_path: Path,
) -> None:
    first = _run_gate(tmp_path)
    second = _run_gate(tmp_path)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert not (tmp_path / "consumed.json").exists()


def test_gate_rejects_stale_or_changed_recheck_evidence(tmp_path: Path) -> None:
    receipt = _receipt()
    stale = _recheck(receipt)
    stale["checked_at"] = (NOW - timedelta(seconds=31)).isoformat().replace(
        "+00:00", "Z"
    )
    stale_result = _run_gate(tmp_path / "stale", receipt=receipt, recheck=stale)

    changed = _recheck(receipt)
    changed["snapshot"] = {**changed["snapshot"], "state_sha256": "9" * 64}
    changed_result = _run_gate(
        tmp_path / "changed", receipt=receipt, recheck=changed
    )

    assert stale_result.returncode == 2
    assert "not currently fresh" in stale_result.stderr
    assert changed_result.returncode == 2
    assert "snapshot changed after receipt issuance" in changed_result.stderr


def test_gate_rejects_receipt_hash_or_source_binding_tampering(
    tmp_path: Path,
) -> None:
    tampered = _receipt()
    tampered["snapshot"] = {
        **tampered["snapshot"],
        "checkpoint_sha256": "8" * 64,
    }
    hash_result = _run_gate(tmp_path / "hash", receipt=tampered)

    receipt = _receipt()
    recheck = _recheck(receipt)
    receipt["target_source_commit_sha"] = "7" * 40
    binding_result = _run_gate(
        tmp_path / "binding", receipt=receipt, recheck=recheck
    )

    assert hash_result.returncode == 2
    assert "receipt core hash mismatch" in hash_result.stderr
    assert binding_result.returncode == 2
    assert "target_source_commit_sha binding mismatch" in binding_result.stderr


def test_gate_rejects_expired_or_unsafe_recheck(tmp_path: Path) -> None:
    expired = _receipt()
    expired["expires_at"] = "2026-08-04T01:00:10Z"
    expired["ttl_seconds"] = 10
    expired_core = {
        key: value
        for key, value in expired.items()
        if key not in {"receipt_id", "receipt_core_sha256"}
    }
    expired_sha = _sha256_json(expired_core)
    expired["receipt_id"] = f"safe-restart-{expired_sha}"
    expired["receipt_core_sha256"] = expired_sha
    expired_recheck = _recheck(expired)
    expired_recheck["checked_at"] = "2026-08-04T01:00:05Z"
    expired_result = _run_gate(
        tmp_path / "expired", receipt=expired, recheck=expired_recheck
    )

    receipt = _receipt()
    failed = _recheck(receipt)
    failed["snapshot"] = {**failed["snapshot"], "active_orders": 1}
    failed_result = _run_gate(
        tmp_path / "failed", receipt=receipt, recheck=failed
    )

    assert expired_result.returncode == 2
    assert "not currently fresh" in expired_result.stderr
    assert failed_result.returncode == 2
    assert "recheck schema validation failed" in failed_result.stderr


def test_deploy_defaults_fail_before_fake_docker_or_maintenance_write(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "docker-called"
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 99\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    deploy_path = tmp_path / "deploy"
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(fake_bin),
            "DEPLOY_PATH": str(deploy_path),
            "DEPLOY_SERVICES": "web-bridge",
        }
    )
    for key in (
        "SAFE_RESTART_RECEIPT_PATH",
        "SAFE_RESTART_RECHECK_PATH",
        "DEPLOY_RELEASE_PLAN_ID",
        "DEPLOY_SOURCE_COMMIT_SHA",
    ):
        env.pop(key, None)

    completed = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/deploy.sh")],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "SAFE_RESTART_RECEIPT_PATH is required" in completed.stderr
    assert not marker.exists()
    assert not deploy_path.exists()


def test_deploy_rejects_unknown_or_multi_service_input_before_side_effects(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "docker-called"
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 99\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    deploy_path = tmp_path / "deploy"
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(fake_bin),
            "DEPLOY_PATH": str(deploy_path),
            "DEPLOY_SERVICES": "web-bridge postgres",
        }
    )

    completed = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/deploy.sh")],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "Unsupported DEPLOY_SERVICES value" in completed.stderr
    assert not marker.exists()
    assert not deploy_path.exists()


def test_production_custody_bootstrap_is_explicit_frozen_and_one_time(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "production-drain"
    command = [
        sys.executable,
        str(ROOT / "scripts/bootstrap_deployment_drain.py"),
        "--state-root",
        str(state_root),
        "--operator",
        "release-operator",
        "--reason",
        "initial issue 267 custody migration",
    ]
    missing_confirmation = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing_confirmation.returncode != 0
    assert not state_root.exists()

    first = subprocess.run(
        [*command, "--confirm-offline-trading-disabled"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [*command, "--confirm-offline-trading-disabled"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert first.returncode == 0, first.stderr
    evidence = json.loads(first.stdout)
    assert evidence["state"] == "RESTARTED_FROZEN"
    assert evidence["production_allowed"] is False
    assert evidence["live_trading_authorized"] is False
    assert second.returncode == 2
    assert "already exists" in second.stderr
    state = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert state["state"] == "RESTARTED_FROZEN"
    assert state["freeze_reason"] == "initial_bootstrap_requires_reconciliation"

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY backend ./backend" in dockerfile
    assert "python -m py_compile" in dockerfile
    assert "backend/app/services/deployment_drain_bootstrap.py" in dockerfile
    assert "python -m app.services.deployment_drain_bootstrap" in dockerfile
    assert "--state-root /tmp/issue267-bootstrap-smoke" in dockerfile
    assert "payload['state'] == 'RESTARTED_FROZEN'" in dockerfile
