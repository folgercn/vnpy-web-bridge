from __future__ import annotations

import json
from pathlib import Path

from app.execution.gateway import ExecutionGateway, GatewaySnapshot
from app.execution.models import sha256_json
from jsonschema import Draft202012Validator, RefResolver

from scripts.phase_c_faults import run_fault_acceptance
from scripts.phase_c_faults.process_runner import _LoopbackGateway

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = ROOT / "docs" / "schemas"
SCENARIO_SCHEMA = json.loads(
    (SCHEMA_DIR / "issue-291-phase-c-fault-scenario-v1.schema.json").read_text()
)
BUNDLE_SCHEMA = json.loads(
    (SCHEMA_DIR / "issue-291-phase-c-fault-evidence-bundle-v1.schema.json").read_text()
)


def _validator() -> Draft202012Validator:
    resolver = RefResolver(
        base_uri=f"{SCHEMA_DIR.as_uri()}/",
        referrer=BUNDLE_SCHEMA,
        store={SCENARIO_SCHEMA["$id"]: SCENARIO_SCHEMA},
    )
    return Draft202012Validator(BUNDLE_SCHEMA, resolver=resolver)


def test_loopback_gateway_satisfies_readiness_snapshot_contract(monkeypatch) -> None:
    gateway = _LoopbackGateway(1)
    snapshot = GatewaySnapshot(
        snapshot_id="snapshot-loopback-contract",
        generation=1,
        connected=True,
    )
    monkeypatch.setattr(gateway, "snapshot", lambda: snapshot)

    assert isinstance(gateway, ExecutionGateway)
    assert gateway.readiness_snapshot() is snapshot
    assert gateway.readiness_snapshot_uses_durable_generation() is True


def test_phase_c_fault_schemas_are_strict_draft202012_contracts() -> None:
    Draft202012Validator.check_schema(SCENARIO_SCHEMA)
    Draft202012Validator.check_schema(BUNDLE_SCHEMA)
    assert BUNDLE_SCHEMA["properties"]["production"] == {"const": False}
    assert BUNDLE_SCHEMA["properties"]["live"] == {"const": False}
    assert BUNDLE_SCHEMA["properties"]["countable_forward"] == {"const": False}


def test_phase_c_fault_harness_is_offline_deterministic_and_covers_required_faults(
    tmp_path: Path,
) -> None:
    bundle = run_fault_acceptance(tmp_path)
    assert list(_validator().iter_errors(bundle)) == []
    assert bundle["execution_mode"] == "offline_deterministic"
    assert bundle["production"] is False
    assert bundle["live"] is False
    assert bundle["countable_forward"] is False
    assert {item["case_id"] for item in bundle["scenarios"]} == {
        "double_leader_pause_expiry_partition_rejoin",
        "stale_token_send_cancel_final_fence",
        "rpc_timeout_unknown_same_intent_no_replay",
        "crash_before_after_gateway_and_restart_reconcile",
        "delayed_duplicate_callback_idempotent",
        "custody_tamper_replay_toctou_receipts",
        "process_pause_lease_expiry_kill_restart",
        "loopback_partition_reset_unknown_restart_reconcile",
        "loopback_send_cancel_crash_boundaries",
    }
    assert all(item["status"] == "passed" for item in bundle["scenarios"])
    for item in bundle["scenarios"]:
        evidence = item["evidence"]
        assert evidence["timeline"] == [
            record["sha256"] for record in evidence["records"]
        ]
        assert evidence["derived_sha256"] == sha256_json(
            {
                "case_id": item["case_id"],
                "timeline": evidence["timeline"],
                "unique_intent_ids": evidence["unique_intent_ids"],
                "unique_receipt_ids": evidence["unique_receipt_ids"],
                "gateway_event_count": evidence["gateway_event_count"],
            }
        )
        assert all(
            record["sha256"]
            == sha256_json(
                {
                    "record_type": record["record_type"],
                    "sequence": record["sequence"],
                    "payload": record["payload"],
                }
            )
            for record in evidence["records"]
        )

    process_cases = {item["case_id"]: item for item in bundle["scenarios"]}
    leader_types = {
        record["record_type"]
        for record in process_cases["process_pause_lease_expiry_kill_restart"][
            "evidence"
        ]["records"]
    }
    assert {
        "leader_process_paused",
        "leader_process_killed",
        "durable_leader_state",
    } <= leader_types

    reset_records = process_cases["loopback_partition_reset_unknown_restart_reconcile"][
        "evidence"
    ]["records"]
    reset_types = {record["record_type"] for record in reset_records}
    assert {
        "loopback_gateway_reset_connection",
        "same_intent_query",
        "reconcile_receipt",
    } <= reset_types
    reset_state = next(
        record["payload"]["payload"]
        for record in reset_records
        if record["record_type"] == "durable_state_after_reset"
    )
    assert reset_state["unknown_outcomes"]

    crash_records = process_cases["loopback_send_cancel_crash_boundaries"]["evidence"][
        "records"
    ]
    crash_types = [record["record_type"] for record in crash_records]
    assert crash_types.count("loopback_gateway_killed_at_boundary") == 2
    assert next(
        record["payload"]["payload"]
        for record in crash_records
        if record["record_type"] == "durable_state_after_send_kill"
    )["unknown_outcomes"]
    assert next(
        record["payload"]["payload"]
        for record in crash_records
        if record["record_type"] == "durable_state_after_cancel_kill"
    )["unknown_outcomes"]
