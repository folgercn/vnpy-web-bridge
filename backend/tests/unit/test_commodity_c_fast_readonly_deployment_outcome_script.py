from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_readonly_deployment_outcome as outcome_module  # noqa: E402
import commodity_c_fast_readonly_deployment_release as release_module  # noqa: E402
import commodity_c_fast_readonly_deployment_sign_outcome as signer_module  # noqa: E402


HELPER_PATH = (
    ROOT
    / "backend/tests/unit/"
    "test_commodity_c_fast_readonly_deployment_release_script.py"
)
SPEC = importlib.util.spec_from_file_location("deployment_release_helpers", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
release_helpers = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_helpers
SPEC.loader.exec_module(release_helpers)

NOW = release_helpers.NOW
SOURCE_COMMIT_SHA = release_helpers.SOURCE_COMMIT_SHA
OUTCOME_SOURCE_COMMIT_SHA = "f" * 40
QUESTDB_IMAGE_DIGEST = release_helpers.QUESTDB_IMAGE_DIGEST


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def write_keyring(
    path: Path,
    *,
    version: str,
    key_id: str,
    purpose: str,
    private_key: Ed25519PrivateKey,
) -> tuple[Path, str]:
    payload = {
        "schema_version": version,
        "keys": [
            {
                "key_id": key_id,
                "purpose": purpose,
                "public_key_base64": public_key_base64(private_key),
            }
        ],
    }
    release_helpers.write_json(path, payload)
    digest = hashlib.sha256(
        release_module.canonical_json(payload)
    ).hexdigest()
    return path, digest


def build_source(
    tmp_path: Path,
) -> tuple[
    release_helpers.Fixture,
    outcome_module.OutcomeSourcePaths,
    dict,
]:
    (tmp_path / "release").mkdir(parents=True)
    fixture = release_helpers.build_fixture(tmp_path / "release")
    signed = release_helpers.sign_fixture(fixture)
    release_path = release_helpers.write_json(
        tmp_path / "signed-release.json",
        signed,
    )
    args = release_helpers.execution_args(fixture, release_path)
    release_module.consume_release(
        args,
        now=NOW,
        pinned_keyring_sha256=fixture.keyring_sha256,
        pinned_custody_path=fixture.custody_dir,
    )
    consume = fixture.custody_dir / (
        f"{signed['attempt_id']}.deployment-consumed.json"
    )
    receipt = fixture.custody_dir / (
        f"{signed['attempt_id']}.deployment-receipt.json"
    )
    paths = outcome_module.OutcomeSourcePaths(
        release=release_path,
        release_keyring=fixture.keyring_path,
        consume_marker=consume,
        receipt=receipt,
        pre_evidence=fixture.evidence_paths,
    )
    return fixture, paths, signed


def build_post(
    tmp_path: Path,
    source_paths: outcome_module.OutcomeSourcePaths,
    signed: dict,
) -> outcome_module.PostEvidencePaths:
    release_raw_sha256 = hashlib.sha256(
        source_paths.release.read_bytes()
    ).hexdigest()
    consume_raw_sha256 = hashlib.sha256(
        source_paths.consume_marker.read_bytes()
    ).hexdigest()
    receipt_raw_sha256 = hashlib.sha256(
        source_paths.receipt.read_bytes()
    ).hexdigest()
    common = {
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "release_id": signed["release_id"],
        "attempt_id": signed["attempt_id"],
        "release_raw_sha256": release_raw_sha256,
        "consume_marker_raw_sha256": consume_raw_sha256,
        "receipt_raw_sha256": receipt_raw_sha256,
    }
    start = NOW + timedelta(minutes=1)
    restart_done = NOW + timedelta(minutes=4)
    captured = (NOW + timedelta(minutes=5)).isoformat()
    writer_pre = json.loads(
        source_paths.pre_evidence.writer_continuity_pre_evidence.read_text()
    )
    execution = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_execution_v1"
        ),
        "record_id": "readonly-deployment-execution-a01",
        **common,
        "contract_source_commit_sha": SOURCE_COMMIT_SHA,
        "deployment_plan_raw_sha256": hashlib.sha256(
            source_paths.pre_evidence.deployment_plan.read_bytes()
        ).hexdigest(),
        "questdb_target_identity_sha256": "c" * 64,
        "questdb_image_digest_before": QUESTDB_IMAGE_DIGEST,
        "questdb_image_digest_after": QUESTDB_IMAGE_DIGEST,
        "questdb_container_identity_sha256_before": "6" * 64,
        "questdb_container_identity_sha256_after": "6" * 64,
        "deployment_started_at": start.isoformat(),
        "secret_installed_at": (NOW + timedelta(minutes=2)).isoformat(),
        "restart_started_at": (NOW + timedelta(minutes=3)).isoformat(),
        "restart_completed_at": restart_done.isoformat(),
        "deployment_ended_at": (NOW + timedelta(minutes=6)).isoformat(),
        "restart_method": "exact_existing_questdb_service_restart_v1",
        "restart_count": 1,
        "restart_exit_code": 0,
        "readonly_principal_configuration_installed": True,
        "readonly_secret_file_installed": True,
        "questdb_recreated": False,
        "questdb_image_changed": False,
        "questdb_container_identity_changed": False,
        "rollback_invoked": False,
        "production_queries_executed": 0,
        "readonly_queries_executed": 0,
        "write_probes_attempted": 0,
        "database_mutations": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "secret_content_included": False,
    }
    writer_post = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_writer_post_v1"
        ),
        "evidence_id": "readonly-writer-post-evidence-a01",
        **common,
        "writer_continuity_pre_evidence_raw_sha256": hashlib.sha256(
            source_paths.pre_evidence.writer_continuity_pre_evidence.read_bytes()
        ).hexdigest(),
        "writer_continuity_post_contract_raw_sha256": hashlib.sha256(
            source_paths.pre_evidence.writer_continuity_post_evidence.read_bytes()
        ).hexdigest(),
        "questdb_target_identity_sha256": "c" * 64,
        "captured_at": captured,
        "capture_method": "same_writer_identity_and_non_regressing_commit_v1",
        "writer_identity_sha256": "4" * 64,
        "writer_last_commit_id_sha256": "5" * 64,
        "commit_progress_state": "SAME",
        "writer_last_commit_lag_seconds": 1,
        "writer_queue_depth": writer_pre["writer_queue_depth"],
        "writer_queue_depth_delta": 0,
        "writer_state": "HEALTHY",
        "secret_content_included": False,
    }
    health_post = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_health_post_v1"
        ),
        "evidence_id": "readonly-health-post-evidence-a01",
        **common,
        "questdb_target_identity_sha256": "c" * 64,
        "captured_at": captured,
        "capture_method": "questdb_http_health_post_restart_v1",
        "health_state": "HEALTHY",
        "http_status_code": 200,
        "recovery_seconds": 60,
        "consecutive_successes": 3,
        "secret_content_included": False,
    }
    backlog_post = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_backlog_post_v1"
        ),
        "evidence_id": "readonly-backlog-post-evidence-a01",
        **common,
        "backlog_pre_evidence_raw_sha256": hashlib.sha256(
            source_paths.pre_evidence.backlog_evidence.read_bytes()
        ).hexdigest(),
        "questdb_target_identity_sha256": "c" * 64,
        "captured_at": captured,
        "capture_method": "tick_writer_backlog_post_restart_snapshot_v1",
        "pending_rows": 0,
        "corrupt_spool_files": 0,
        "dropped_total": 0,
        "backlog_drained": True,
        "secret_content_included": False,
    }
    principal_secret_post = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_principal_secret_post_v1"
        ),
        "attestation_id": "readonly-principal-secret-post-a01",
        **common,
        "captured_at": captured,
        "capture_method": (
            "lstat_and_questdb_config_identity_post_restart_v1"
        ),
        "questdb_target_identity_sha256": "c" * 64,
        "readonly_principal_identity_sha256": (
            signed["readonly_principal_identity_sha256"]
        ),
        "principal_differs_from_admin": True,
        "readonly_password_value_source": "file",
        "global_pgwire_readonly": False,
        "instance_readonly": False,
        "secret_file_path_sha256": signed["secret_file_path_sha256"],
        "owner_uid": 65532,
        "owner_gid": 65532,
        "mode": "0600",
        "regular_file": True,
        "symlink": False,
        "secret_content_read": False,
        "principal_name_included": False,
        "secret_content_included": False,
    }
    network_post = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_network_post_v1"
        ),
        "attestation_id": "readonly-network-post-a01",
        **common,
        "captured_at": captured,
        "capture_method": "isolated_network_post_restart_inspection_v1",
        "isolated_network_identity_sha256": (
            signed["isolated_network_identity_sha256"]
        ),
        "driver": "bridge",
        "internal": True,
        "runner_member_identity_sha256": (
            signed["isolated_network_runner_member_identity_sha256"]
        ),
        "questdb_member_identity_sha256": (
            signed["isolated_network_questdb_member_identity_sha256"]
        ),
        "member_count": 2,
        "unexpected_member_identity_sha256s": [],
        "docker_socket_connectivity": False,
        "rpc_connectivity": False,
        "trading_connectivity": False,
        "secret_content_included": False,
    }
    values = {
        "execution": execution,
        "writer_post": writer_post,
        "health_post": health_post,
        "backlog_post": backlog_post,
        "principal_secret_post": principal_secret_post,
        "network_post": network_post,
    }
    return outcome_module.PostEvidencePaths(
        **{
            name: release_helpers.write_json(tmp_path / f"{name}.json", value)
            for name, value in values.items()
        }
    )


def build_all(tmp_path: Path) -> dict:
    fixture, source_paths, signed_release = build_source(tmp_path)
    post_paths = build_post(tmp_path, source_paths, signed_release)
    outcome_private = Ed25519PrivateKey.generate()
    t1_private = Ed25519PrivateKey.generate()
    outcome_keyring, outcome_pin = write_keyring(
        tmp_path / "outcome-keyring.json",
        version=outcome_module.OUTCOME_KEYRING_VERSION,
        key_id="c-fast-readonly-outcome-key-a01",
        purpose=outcome_module.OUTCOME_KEY_PURPOSE,
        private_key=outcome_private,
    )
    t1_keyring, t1_pin = write_keyring(
        tmp_path / "t1-keyring.json",
        version=outcome_module.T1_KEYRING_VERSION,
        key_id="c-fast-t1-key-a01",
        purpose=outcome_module.T1_KEY_PURPOSE,
        private_key=t1_private,
    )
    draft = {
        "issued_at": (NOW + timedelta(minutes=7)).isoformat(),
        "signer_key_id": "c-fast-readonly-outcome-key-a01",
        "signer_key_purpose": outcome_module.OUTCOME_KEY_PURPOSE,
        "signer_type": "human",
        "reviewer_role": "human_l3_readonly_deployment_outcome_reviewer",
        "human_signature": "Verified exact post-deployment evidence.",
    }
    return {
        "fixture": fixture,
        "source": source_paths,
        "post": post_paths,
        "outcome_private": outcome_private,
        "outcome_keyring": outcome_keyring,
        "outcome_pin": outcome_pin,
        "t1_keyring": t1_keyring,
        "t1_pin": t1_pin,
        "draft": draft,
    }


def sign(values: dict) -> dict:
    return signer_module.sign_outcome(
        values["draft"],
        values["outcome_private"],
        values["outcome_keyring"],
        values["t1_keyring"],
        values["source"],
        values["post"],
        expected_outcome_keyring_sha256=values["outcome_pin"],
        expected_release_keyring_sha256=values["fixture"].keyring_sha256,
        expected_t1_keyring_sha256=values["t1_pin"],
        expected_outcome_source_commit_sha=OUTCOME_SOURCE_COMMIT_SHA,
        expected_release_source_commit_sha=SOURCE_COMMIT_SHA,
        expected_questdb_image_digest=QUESTDB_IMAGE_DIGEST,
        now=NOW + timedelta(minutes=8),
    )


def verify(values: dict, signed: dict) -> outcome_module.VerifiedDeploymentOutcome:
    attempt_id = signed["attempt_id"]
    path = release_helpers.write_json(
        values["source"].consume_marker.parent
        / f"{attempt_id}.deployment-outcome.json",
        signed,
    )
    return outcome_module.verify_signed_outcome(
        path,
        values["outcome_keyring"],
        values["t1_keyring"],
        values["source"],
        values["post"],
        expected_outcome_keyring_sha256=values["outcome_pin"],
        expected_release_keyring_sha256=values["fixture"].keyring_sha256,
        expected_t1_keyring_sha256=values["t1_pin"],
        expected_outcome_source_commit_sha=OUTCOME_SOURCE_COMMIT_SHA,
        expected_release_source_commit_sha=SOURCE_COMMIT_SHA,
        expected_questdb_image_digest=QUESTDB_IMAGE_DIGEST,
        now=NOW + timedelta(minutes=8),
    )


def test_independent_signed_success_outcome_verifies_and_grants_nothing(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    signed = sign(values)
    verified = verify(values, signed)
    outcome_path = values["source"].consume_marker.parent / (
        f"{signed['attempt_id']}.deployment-outcome.json"
    )

    assert verified.payload["deployment_outcome_state"] == (
        "SUCCEEDED_POSTCHECKS_VERIFIED"
    )
    assert verified.raw_sha256 == hashlib.sha256(
        outcome_path.read_bytes()
    ).hexdigest()
    assert verified.payload["deployment_executed"] is True
    assert verified.payload["restart_count"] == 1
    for field in outcome_module.OUTCOME_FALSE_FIELDS:
        assert verified.payload[field] is False
    for field in outcome_module.OUTCOME_ZERO_FIELDS:
        assert verified.payload[field] == 0


def test_outcome_signer_must_differ_from_release_and_t1(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    release_private = values["fixture"].private_key
    reused_keyring, reused_pin = write_keyring(
        tmp_path / "reused-outcome-keyring.json",
        version=outcome_module.OUTCOME_KEYRING_VERSION,
        key_id="c-fast-readonly-outcome-key-a01",
        purpose=outcome_module.OUTCOME_KEY_PURPOSE,
        private_key=release_private,
    )
    values["outcome_private"] = release_private
    values["outcome_keyring"] = reused_keyring
    values["outcome_pin"] = reused_pin
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="independent from release and T1",
    ):
        sign(values)

    values = build_all(tmp_path / "t1")
    t1_payload = json.loads(values["t1_keyring"].read_text())
    reused_t1_private = values["outcome_private"]
    t1_payload["keys"][0]["public_key_base64"] = public_key_base64(
        reused_t1_private
    )
    release_helpers.write_json(values["t1_keyring"], t1_payload)
    values["t1_pin"] = hashlib.sha256(
        release_module.canonical_json(t1_payload)
    ).hexdigest()
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="independent from release and T1",
    ):
        sign(values)


def test_exact_receipt_and_post_evidence_bytes_are_required(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    signed = sign(values)
    receipt = values["source"].receipt
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="receipt_raw_sha256 binding",
    ):
        verify(values, signed)


def test_execution_time_chain_and_duration_fail_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    execution_path = values["post"].execution
    execution = json.loads(execution_path.read_text())
    execution["restart_completed_at"] = (
        NOW + timedelta(minutes=7)
    ).isoformat()
    release_helpers.write_json(execution_path, execution)
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="time chain",
    ):
        sign(values)


def test_writer_delta_and_commit_relation_fail_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    writer_path = values["post"].writer_post
    writer = json.loads(writer_path.read_text())
    writer["writer_queue_depth"] = 5
    writer["writer_queue_depth_delta"] = 0
    release_helpers.write_json(writer_path, writer)
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="writer post evidence bindings",
    ):
        sign(values)

    values = build_all(tmp_path / "commit")
    writer_path = values["post"].writer_post
    writer = json.loads(writer_path.read_text())
    writer["writer_last_commit_id_sha256"] = "9" * 64
    release_helpers.write_json(writer_path, writer)
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="SAME commit relation",
    ):
        sign(values)


def test_post_schema_extra_field_and_sensitive_value_fail_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    health_path = values["post"].health_post
    health = json.loads(health_path.read_text())
    health["optimistic_override"] = True
    release_helpers.write_json(health_path, health)
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="schema validation failed",
    ):
        sign(values)

    values = build_all(tmp_path / "sensitive")
    network_path = values["post"].network_post
    network = json.loads(network_path.read_text())
    network["attestation_id"] = "password=plaintext"
    release_helpers.write_json(network_path, network)
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="schema validation failed",
    ):
        sign(values)


def test_outcome_authority_tamper_fails_schema_before_signature(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    signed = sign(values)
    signed["collection_authorized"] = True
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="schema validation failed",
    ):
        verify(values, signed)


def test_signature_tamper_fails_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    signed = sign(values)
    signature = bytearray(base64.b64decode(signed["signature"]))
    signature[0] ^= 1
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="signature is invalid",
    ):
        verify(values, signed)


def test_mixed_or_wrong_key_purpose_fails_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    keyring = json.loads(values["outcome_keyring"].read_text())
    keyring["keys"].append(
        {
            "key_id": "hidden-release-purpose-key-a01",
            "purpose": "readonly_deployment_release_signer",
            "public_key_base64": public_key_base64(
                Ed25519PrivateKey.generate()
            ),
        }
    )
    release_helpers.write_json(values["outcome_keyring"], keyring)
    values["outcome_pin"] = hashlib.sha256(
        release_module.canonical_json(keyring)
    ).hexdigest()
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="wrong-purpose",
    ):
        sign(values)


def test_naive_verification_time_fails_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="timezone",
    ):
        signer_module.sign_outcome(
            values["draft"],
            values["outcome_private"],
            values["outcome_keyring"],
            values["t1_keyring"],
            values["source"],
            values["post"],
            expected_outcome_keyring_sha256=values["outcome_pin"],
            expected_release_keyring_sha256=(
                values["fixture"].keyring_sha256
            ),
            expected_t1_keyring_sha256=values["t1_pin"],
            expected_outcome_source_commit_sha=OUTCOME_SOURCE_COMMIT_SHA,
            expected_release_source_commit_sha=SOURCE_COMMIT_SHA,
            expected_questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            now=datetime(2026, 9, 1, 0, 8),
        )


def test_copied_consume_receipt_outside_signed_custody_fail_closed(
    tmp_path: Path,
) -> None:
    values = build_all(tmp_path)
    copied = tmp_path / "copied-custody"
    copied.mkdir(mode=0o700)
    source = values["source"]
    shutil.copy2(
        source.consume_marker.parent
        / release_module.CUSTODY_IDENTITY_FILENAME,
        copied / release_module.CUSTODY_IDENTITY_FILENAME,
    )
    copied_consume = copied / source.consume_marker.name
    copied_receipt = copied / source.receipt.name
    shutil.copy2(source.consume_marker, copied_consume)
    shutil.copy2(source.receipt, copied_receipt)
    values["source"] = outcome_module.OutcomeSourcePaths(
        release=source.release,
        release_keyring=source.release_keyring,
        consume_marker=copied_consume,
        receipt=copied_receipt,
        pre_evidence=source.pre_evidence,
    )
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="custody path",
    ):
        sign(values)


def test_pre_contract_reread_change_after_release_verify_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_all(tmp_path)
    original_verify = release_module.verify_release

    def verify_then_change(*args, **kwargs):
        verified = original_verify(*args, **kwargs)
        contract = values[
            "source"
        ].pre_evidence.writer_continuity_post_evidence
        contract.write_bytes(contract.read_bytes() + b" ")
        return verified

    monkeypatch.setattr(
        outcome_module.release_module,
        "verify_release",
        verify_then_change,
    )
    with pytest.raises(
        outcome_module.DeploymentOutcomeError,
        match="changed after release verification",
    ):
        sign(values)
