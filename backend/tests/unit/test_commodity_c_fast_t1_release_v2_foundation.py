from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_release_v2_foundation as release_module  # noqa: E402
from commodity_c_fast_t1_one_shot import (  # noqa: E402
    OneShotError,
    canonical_json,
    custody_path_sha256,
    validate_json_schema,
)
from commodity_c_fast_t1_readiness_v2 import (  # noqa: E402
    ReadinessPins,
    ReadinessV2Error,
    VerifiedReadinessPacket,
)


NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
H = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, payload: dict, *, mode: int = 0o600) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


def readiness() -> VerifiedReadinessPacket:
    payload = {
        "packet_id": f"readiness-v2-{H}",
        "generated_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=9)).isoformat(),
        "pin_root_path_sha256": H2,
        "source_namespaces": {
            "t1_runtime_source_commit_sha": "1" * 40,
            "l3_contract_source_commit_sha": "2" * 40,
            "outcome_contract_source_commit_assertion": "3" * 40,
        },
        "digest_namespaces": {
            "t1_runtime_image_digest": f"sha256:{H3}",
            "questdb_image_digest": f"sha256:{H4}",
        },
        "t1_runtime": {
            "content_attestation_raw_sha256": H,
            "content_attestation_canonical_sha256": H2,
            "external_image_evidence_raw_sha256": H3,
            "oci_layout_archive_raw_sha256": H4,
            "image_reference": f"registry.invalid/c-fast@sha256:{H3}",
            "image_id": f"sha256:{H3}",
            "runtime_bundle_index_sha256": H5,
            "content_verifier_sha256": H,
        },
        "build_registry_provenance": {
            "signed_provenance_raw_sha256": H2,
            "signed_provenance_canonical_sha256": H3,
            "provenance_keyring_sha256": H,
            "t1_authority_keyring_sha256": H2,
            "l3_authority_keyring_sha256": H3,
            "signer_key_id": "provenance-key",
            "signer_public_key_sha256": H4,
            "signed_build_assertion_verified": True,
            "signed_registry_assertion_verified": True,
            "external_facts_independently_reverified": False,
        },
        "readonly_deployment_outcome": {
            "signed_outcome_raw_sha256": H3,
            "signed_outcome_canonical_sha256": H4,
            "outcome_keyring_sha256": H5,
            "signer_key_id": "outcome-key",
            "signer_public_key_sha256": H5,
            "release_raw_sha256": H,
            "release_canonical_sha256": H2,
            "consume_marker_raw_sha256": H3,
            "receipt_raw_sha256": H4,
            "pre_evidence_bundle_index_sha256": H5,
            "post_evidence_bundle_index_sha256": H,
            "release_id": "deployment-release",
            "attempt_id": f"attempt-{H}",
            "questdb_target_identity_sha256": H4,
            "outcome_issued_at": (NOW - timedelta(minutes=2)).isoformat(),
            "deployment_ended_at": (NOW - timedelta(minutes=3)).isoformat(),
            "deployment_executed": True,
            "restart_count": 1,
        },
    }
    return VerifiedReadinessPacket(
        payload=payload,
        raw_sha256=H4,
        canonical_sha256=H5,
    )


def release_draft(
    current_readiness: VerifiedReadinessPacket,
) -> dict:
    release_id = "release-v2-test-0001"
    payload = {
        "schema_version": release_module.RELEASE_SCHEMA_VERSION,
        "purpose": release_module.RELEASE_PURPOSE,
        "candidate_id": release_module.CANDIDATE_ID,
        "issue_number": 114,
        "release_id": release_id,
        "attempt_id": release_module.release_attempt_id(release_id),
        "issued_at": (NOW - timedelta(seconds=30)).isoformat(),
        "not_before": (NOW - timedelta(seconds=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "signer_key_id": "t1-release-key",
        "signer_type": "human",
        "reviewer_role": "human-risk-reviewer",
        "human_signature": "approved foundation no-query test",
        "trusted_keyring_sha256": H2,
        "pin_root_path_sha256": H2,
        "custody_identity_sha256": H3,
        "custody_path_sha256": H4,
        "runner_sha256": file_sha256(release_module.RUNNER_PATH),
        "release_schema_sha256": file_sha256(
            release_module.RELEASE_SCHEMA_PATH
        ),
        "consume_schema_sha256": file_sha256(
            release_module.CONSUME_SCHEMA_PATH
        ),
        "harness_terminal_schema_sha256": file_sha256(
            release_module.HARNESS_TERMINAL_SCHEMA_PATH
        ),
        "readiness_verifier_sha256": file_sha256(
            release_module.READINESS_VERIFIER_PATH
        ),
        "readiness_schema_sha256": file_sha256(
            release_module.READINESS_SCHEMA_PATH
        ),
        "readiness": release_module._readiness_binding(current_readiness),
        "namespaces": {
            **current_readiness.payload["source_namespaces"],
            **current_readiness.payload["digest_namespaces"],
        },
        "readiness_source_bundle_index_sha256": (
            release_module.readiness_source_bundle_index(current_readiness)
        ),
        "manifest_raw_sha256": H,
        "manifest_canonical_sha256": H2,
        "snapshot_id": "snapshot-test-0001",
        "audit_window": {
            "start": (NOW - timedelta(days=1)).isoformat(),
            "end_exclusive": NOW.isoformat(),
            "trading_day": "20260725",
        },
        "endpoint_identity_sha256": H4,
        "questdb_build_sha256": H5,
        "connect_timeout_seconds": 10,
        "statement_timeout_ms": 60000,
        "max_rows_per_contract": 500000,
        "max_runtime_seconds": 600,
        "minimum_launch_margin_seconds": 30,
        "query_plan_scope": (
            "FUTURE_EXACT_SIGNED_MANIFEST_ONE_SHOT_PLANNED_ONLY"
        ),
        "t1_one_shot_child_launch_planned": True,
        "network_query_planned": True,
        "readonly_production_query_planned": True,
        "local_audit_artifact_write_planned": True,
    }
    payload.update(
        {field: False for field in release_module.ACTUAL_AUTHORITY_FIELDS}
    )
    return payload


def verified_release(
    current_readiness: VerifiedReadinessPacket,
) -> release_module.VerifiedReleaseV2:
    payload = release_draft(current_readiness)
    payload["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    return release_module.VerifiedReleaseV2(
        payload=payload,
        raw_sha256=H,
        canonical_sha256=H2,
        readiness=current_readiness,
    )


def sign_for_test(
    draft: dict,
    private_key: Ed25519PrivateKey,
    current_readiness: VerifiedReadinessPacket,
) -> dict:
    payload = dict(draft)
    payload["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    release_module.validate_release_semantics(
        payload,
        current_readiness,
        now=NOW,
    )
    payload["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(release_module.unsigned_release_payload(payload))
        )
    ).decode("ascii")
    return payload


def custody_pins(path: Path) -> ReadinessPins:
    path.mkdir(mode=0o700)
    return ReadinessPins(
        provenance_keyring_sha256=H,
        t1_authority_keyring_sha256=H2,
        l3_authority_keyring_sha256=H3,
        outcome_keyring_sha256=H5,
        packet_custody_path=path,
    )


def keep_active_pins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        release_module,
        "verify_active_readiness_pins",
        lambda _pins: None,
    )


def assert_zero_query_effects(terminal: dict) -> None:
    assert terminal["query_execution_state"] == "NOT_STARTED"
    assert terminal["child_launched"] is False
    assert terminal["production_queried"] is False
    assert terminal["write_probe_attempted"] is False
    assert terminal["database_mutations"] == 0
    assert terminal["web_bridge_rpc_calls"] == 0
    assert terminal["orders_sent"] == 0
    assert terminal["positions_modified"] == 0
    assert terminal["dispatch_changed"] is False


def test_schema_keeps_plans_separate_from_actual_authority() -> None:
    current_readiness = readiness()
    signed = sign_for_test(
        release_draft(current_readiness),
        Ed25519PrivateKey.generate(),
        current_readiness,
    )
    assert all(
        signed[field] is False
        for field in release_module.ACTUAL_AUTHORITY_FIELDS
    )
    assert signed["network_query_planned"] is True
    assert len(base64.b64decode(signed["signature"], validate=True)) == 64

    signed["network_query_authorized"] = True
    with pytest.raises(
        (OneShotError, release_module.ReleaseV2FoundationError)
    ):
        release_module.validate_release_semantics(
            signed,
            current_readiness,
            now=NOW,
        )


def test_release_cannot_outlive_exact_readiness() -> None:
    current_readiness = readiness()
    payload = release_draft(current_readiness)
    payload["expires_at"] = (
        parse_time(current_readiness.payload["expires_at"])
        + timedelta(seconds=1)
    ).isoformat()
    payload["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    with pytest.raises(
        release_module.ReleaseV2FoundationError,
        match="cannot outlive",
    ):
        release_module.validate_release_semantics(
            payload,
            current_readiness,
            now=NOW,
        )


def test_verify_release_binds_exact_keyring_manifest_and_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_readiness = readiness()
    custody = tmp_path / "custody"
    pins = custody_pins(custody)
    identity = {
        "schema_version": "commodity_c_fast_t1_custody_identity_v1",
        "custody_id": "custody-test-0001",
    }
    write_json(custody / "custody-identity.json", identity)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    keyring = {
        "schema_version": "commodity_c_fast_t1_trusted_keys_v1",
        "keys": [
            {
                "key_id": "t1-release-key",
                "purpose": "t1_audit_release_signer",
                "public_key_base64": base64.b64encode(public_key).decode(
                    "ascii"
                ),
            }
        ],
    }
    keyring_path = tmp_path / "keyring.json"
    write_json(keyring_path, keyring)
    keyring_sha256 = hashlib.sha256(canonical_json(keyring)).hexdigest()
    pins = ReadinessPins(
        provenance_keyring_sha256=pins.provenance_keyring_sha256,
        t1_authority_keyring_sha256=keyring_sha256,
        l3_authority_keyring_sha256=pins.l3_authority_keyring_sha256,
        outcome_keyring_sha256=pins.outcome_keyring_sha256,
        packet_custody_path=custody,
    )
    products = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
    manifest = {
        "schema_version": "commodity_c_fast_l1_l5_audit_manifest_v2",
        "candidate_id": release_module.CANDIDATE_ID,
        "snapshot_id": "snapshot-test-0001",
        "audit_window": {
            "start": (NOW - timedelta(days=1)).isoformat(),
            "end_exclusive": NOW.isoformat(),
            "trading_day": "20260725",
        },
        "session_windows": {
            name: {
                "start": (NOW - timedelta(hours=1)).isoformat(),
                "end_exclusive": NOW.isoformat(),
            }
            for name in (
                "night_open",
                "night_session",
                "day_open",
                "day_session",
            )
        },
        "targets": [
            {
                "product": product,
                "exact_contract": f"SHFE.{product}2609",
                "previous_exact_contract": None,
                "roll_expected": False,
            }
            for product in products
        ],
        "execution_windows": [],
    }
    manifest_path = tmp_path / "manifest.json"
    write_json(manifest_path, manifest, mode=0o644)
    l3_release_path = tmp_path / "l3-release.json"
    write_json(
        l3_release_path,
        {
            "questdb_target_identity_sha256": H4,
            "questdb_build_sha256": H5,
        },
        mode=0o644,
    )
    draft = release_draft(current_readiness)
    draft.update(
        {
            "trusted_keyring_sha256": keyring_sha256,
            "custody_identity_sha256": hashlib.sha256(
                canonical_json(identity)
            ).hexdigest(),
            "custody_path_sha256": custody_path_sha256(custody),
            "manifest_raw_sha256": file_sha256(manifest_path),
            "manifest_canonical_sha256": hashlib.sha256(
                canonical_json(manifest)
            ).hexdigest(),
        }
    )
    signed = sign_for_test(
        draft,
        private_key,
        current_readiness,
    )
    release_path = custody / "release-v2-test-0001.signed.json"
    write_json(release_path, signed)
    monkeypatch.setattr(
        release_module,
        "verify_existing_readiness_packet",
        lambda *_args, **_kwargs: current_readiness,
    )
    inputs = SimpleNamespace(
        outcome_source=SimpleNamespace(release=l3_release_path)
    )
    result = release_module.verify_release(
        release_path,
        keyring_path,
        manifest_path,
        custody / f"{current_readiness.payload['packet_id']}.json",
        inputs,
        pins,
        now=NOW,
        require_root_owned_parent=False,
    )
    assert result.payload == signed
    assert result.raw_sha256 == file_sha256(release_path)

    manifest["snapshot_id"] = "snapshot-tampered"
    write_json(manifest_path, manifest, mode=0o644)
    with pytest.raises(
        release_module.ReleaseV2FoundationError,
        match="exact audit manifest",
    ):
        release_module.verify_release(
            release_path,
            keyring_path,
            manifest_path,
            custody / f"{current_readiness.payload['packet_id']}.json",
            inputs,
            pins,
            now=NOW,
            require_root_owned_parent=False,
        )


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def test_consume_is_durable_before_final_revalidation_and_cannot_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_readiness = readiness()
    pins = custody_pins(tmp_path / "custody")
    verified = verified_release(current_readiness)
    attempt_id = verified.payload["attempt_id"]
    calls: list[str] = []
    keep_active_pins(monkeypatch)

    def preconsume_revalidate(_: datetime) -> release_module.VerifiedReleaseV2:
        calls.append("revalidate_before_consume")
        return verified

    def final_revalidate(at: datetime) -> release_module.VerifiedReleaseV2:
        consume_path = pins.packet_custody_path / (
            f"{attempt_id}.consumed-v2.json"
        )
        marker = json.loads(consume_path.read_text(encoding="utf-8"))
        assert marker["consumed_at"] <= at.isoformat()
        calls.append("revalidate_after_consume")
        return verified

    times = iter(
        (
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
        )
    )
    exit_code, terminal = release_module._execute_no_query_harness(
        verified,
        pins,
        preconsume_revalidate,
        final_revalidate,
        clock=lambda: next(times),
        require_root_owned_parent=False,
    )
    assert exit_code == 0
    assert calls == [
        "revalidate_before_consume",
        "revalidate_after_consume",
    ]
    assert terminal["terminal_state"] == "HARNESS_REVALIDATED_NO_QUERY"
    assert terminal["query_execution_state"] == "NOT_STARTED"
    assert terminal["harness_result_is_t1_success"] is False
    assert terminal["harness_result_is_p0_success"] is False
    assert terminal["p0_acceptance_authorized"] is False

    with pytest.raises(
        release_module.ReleaseV2FoundationError,
        match="already consumed",
    ):
        release_module._execute_no_query_harness(
            verified,
            pins,
            preconsume_revalidate,
            final_revalidate,
            clock=lambda: NOW,
            require_root_owned_parent=False,
        )


def test_public_harness_path_verifies_before_and_after_consume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_readiness = readiness()
    pins = custody_pins(tmp_path / "custody")
    verified = verified_release(current_readiness)
    verification_times: list[datetime] = []

    def verify(*_args, now: datetime, **_kwargs):
        verification_times.append(now)
        return verified

    monkeypatch.setattr(release_module, "verify_release", verify)
    keep_active_pins(monkeypatch)
    times = iter(
        (
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(seconds=4),
        )
    )
    exit_code, terminal = (
        release_module.verify_and_execute_no_query_harness(
            tmp_path / "release.json",
            tmp_path / "keyring.json",
            tmp_path / "manifest.json",
            tmp_path / "readiness.json",
            SimpleNamespace(),
            pins,
            clock=lambda: next(times),
            require_root_owned_parent=False,
        )
    )
    assert exit_code == 0
    assert terminal["terminal_state"] == "HARNESS_REVALIDATED_NO_QUERY"
    assert terminal["started_at"] == (
        NOW + timedelta(seconds=2)
    ).isoformat()
    assert terminal["final_revalidation_completed_at"] == (
        NOW + timedelta(seconds=3)
    ).isoformat()
    assert terminal["ended_at"] == (
        NOW + timedelta(seconds=4)
    ).isoformat()
    assert verification_times == [
        NOW,
        NOW + timedelta(seconds=1),
        NOW + timedelta(seconds=3),
    ]


def test_release_expiring_at_actual_consume_time_is_not_consumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_readiness = readiness()
    pins = custody_pins(tmp_path / "custody")
    verified = verified_release(current_readiness)
    expiry = parse_time(verified.payload["expires_at"])
    verification_times: list[datetime] = []

    def verify(*_args, now: datetime, **_kwargs):
        verification_times.append(now)
        return verified

    monkeypatch.setattr(release_module, "verify_release", verify)
    times = iter((NOW, NOW + timedelta(seconds=1), expiry))

    with pytest.raises(
        release_module.ReleaseV2FoundationError,
        match="release is not currently active",
    ):
        release_module.verify_and_execute_no_query_harness(
            tmp_path / "release.json",
            tmp_path / "keyring.json",
            tmp_path / "manifest.json",
            tmp_path / "readiness.json",
            SimpleNamespace(),
            pins,
            clock=lambda: next(times),
            require_root_owned_parent=False,
        )

    attempt_id = verified.payload["attempt_id"]
    assert verification_times == [
        NOW,
        NOW + timedelta(seconds=1),
    ]
    assert not (
        pins.packet_custody_path / f"{attempt_id}.consumed-v2.json"
    ).exists()
    assert not (
        pins.packet_custody_path
        / f"{attempt_id}.harness-terminal-v2.json"
    ).exists()


def test_active_pin_rotation_before_consume_does_not_burn_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_readiness = readiness()
    pins = custody_pins(tmp_path / "custody")
    verified = verified_release(current_readiness)

    monkeypatch.setattr(
        release_module,
        "verify_release",
        lambda *_args, **_kwargs: verified,
    )

    def reject_rotated_pins(_pins: ReadinessPins) -> None:
        raise ReadinessV2Error(
            "active readiness pins changed before protected use"
        )

    monkeypatch.setattr(
        release_module,
        "verify_active_readiness_pins",
        reject_rotated_pins,
    )
    times = iter(
        (
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
        )
    )

    with pytest.raises(
        release_module.ReleaseV2FoundationError,
        match="active readiness pins changed",
    ):
        release_module.verify_and_execute_no_query_harness(
            tmp_path / "release.json",
            tmp_path / "keyring.json",
            tmp_path / "manifest.json",
            tmp_path / "readiness.json",
            SimpleNamespace(),
            pins,
            clock=lambda: next(times),
            require_root_owned_parent=False,
        )

    attempt_id = verified.payload["attempt_id"]
    assert not (
        pins.packet_custody_path / f"{attempt_id}.consumed-v2.json"
    ).exists()
    assert not (
        pins.packet_custody_path
        / f"{attempt_id}.harness-terminal-v2.json"
    ).exists()


@pytest.mark.parametrize(
    ("final_offset", "ended_offset"),
    (
        (1, 3),
        (3, 1),
    ),
)
def test_inverse_clock_after_consume_fails_without_query_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    final_offset: int,
    ended_offset: int,
) -> None:
    current_readiness = readiness()
    pins = custody_pins(tmp_path / "custody")
    verified = verified_release(current_readiness)
    verification_times: list[datetime] = []

    def verify(*_args, now: datetime, **_kwargs):
        verification_times.append(now)
        return verified

    monkeypatch.setattr(release_module, "verify_release", verify)
    keep_active_pins(monkeypatch)
    times = iter(
        (
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=final_offset),
            NOW + timedelta(seconds=ended_offset),
        )
    )

    exit_code, terminal = (
        release_module.verify_and_execute_no_query_harness(
            tmp_path / "release.json",
            tmp_path / "keyring.json",
            tmp_path / "manifest.json",
            tmp_path / "readiness.json",
            SimpleNamespace(),
            pins,
            clock=lambda: next(times),
            require_root_owned_parent=False,
        )
    )

    assert exit_code == 2
    assert terminal["terminal_state"] == (
        "FAILED_FINAL_READINESS_REVALIDATION_NO_QUERY"
    )
    assert terminal["error_code"] == "NON_MONOTONIC_CLOCK"
    assert terminal["final_revalidation_completed_at"] is None
    assert parse_time(terminal["started_at"]) <= parse_time(
        terminal["ended_at"]
    )
    assert_zero_query_effects(terminal)
    if final_offset < 2:
        assert verification_times == [
            NOW,
            NOW + timedelta(seconds=1),
        ]
    else:
        assert verification_times == [
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=3),
        ]


def test_failed_final_revalidation_burns_attempt_without_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_readiness = readiness()
    pins = custody_pins(tmp_path / "custody")
    verified = verified_release(current_readiness)
    keep_active_pins(monkeypatch)

    def fail_revalidation(_: datetime) -> release_module.VerifiedReleaseV2:
        raise ReadinessV2Error("readiness expired")

    times = iter(
        (
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
        )
    )
    exit_code, terminal = release_module._execute_no_query_harness(
        verified,
        pins,
        lambda _at: verified,
        fail_revalidation,
        clock=lambda: next(times),
        require_root_owned_parent=False,
    )
    assert exit_code == 2
    assert terminal["terminal_state"] == (
        "FAILED_FINAL_READINESS_REVALIDATION_NO_QUERY"
    )
    assert terminal["error_code"] == "READINESS_REVALIDATION_FAILED"
    assert terminal["child_launched"] is False
    assert terminal["production_queried"] is False
    assert terminal["database_mutations"] == 0
    assert terminal["orders_sent"] == 0


def test_harness_terminal_cannot_claim_p0_success() -> None:
    current_readiness = readiness()
    terminal = release_module._terminal_payload(
        verified_release(current_readiness),
        H3,
        H4,
        started_at=NOW,
        ended_at=NOW + timedelta(seconds=1),
        final_revalidation_at=NOW + timedelta(milliseconds=500),
        success=True,
    )
    validate_json_schema(
        terminal,
        release_module.HARNESS_TERMINAL_SCHEMA_PATH,
        "harness terminal",
    )
    terminal["p0_acceptance_authorized"] = True
    with pytest.raises(OneShotError):
        validate_json_schema(
            terminal,
            release_module.HARNESS_TERMINAL_SCHEMA_PATH,
            "harness terminal",
        )
