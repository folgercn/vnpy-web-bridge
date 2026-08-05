from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = ROOT / "docs/architecture/issue-291-phase-a-ownership-v1.json"
COMMAND_SCHEMA_PATH = (
    ROOT / "docs/schemas/web-bridge-control-execution-command-v1.schema.json"
)
STATUS_SCHEMA_PATH = ROOT / "docs/schemas/web-bridge-execution-status-v1.schema.json"
DOC_PATH = ROOT / "docs/architecture/issue-291-phase-a-contract-v1.md"

MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
COMMAND_SCHEMA = json.loads(COMMAND_SCHEMA_PATH.read_text(encoding="utf-8"))
STATUS_SCHEMA = json.loads(STATUS_SCHEMA_PATH.read_text(encoding="utf-8"))


def _by_id(items: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    result = {str(item["id"]): item for item in items}
    assert len(result) == len(items)
    return result


def _hash(char: str = "a") -> str:
    return char * 64


def _command(command: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": "cmd-20260805-0001",
        "idempotency_key": "idem-20260805-command-0001",
        "correlation_id": "corr-20260805-0001",
        "issued_at": "2026-08-05T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "control-api-instance-a",
            "operator": "operator@example",
            "role": "admin",
        },
        "command": command,
        "expected": {
            "state_version": 7,
            "leader_epoch": 3,
            "fencing_token": 11,
        },
        "payload": payload,
    }


def test_manifest_is_issue291_phase_a_final_state_contract() -> None:
    assert MANIFEST["schema_version"] == "web_bridge_issue_291_phase_a_ownership_v1"
    assert MANIFEST["issue"] == 291
    assert MANIFEST["phase"] == "A"
    assert MANIFEST["status"] == "contract_frozen_not_implemented"
    assert MANIFEST["decision"] == "final_state_separation"
    assert "issue_267_progressive_migration_route" in MANIFEST["supersedes"]
    assert "old_web_bridge_compatibility_layer" in MANIFEST["scope"]["forbidden"]
    assert MANIFEST["safety_defaults"]["production_allowed"] is False
    assert MANIFEST["safety_defaults"]["live_trading_authorized"] is False
    assert MANIFEST["safety_defaults"]["countable_forward"] is False


def test_process_entries_freeze_final_entrypoints_and_private_ports() -> None:
    entries = MANIFEST["process_entries"]
    assert entries["frontend-edge"]["entrypoint"].startswith("nginx ")
    assert entries["frontend-edge"]["listen"] == "0.0.0.0:8080"
    assert entries["control-api"]["entrypoint"].startswith(
        "uvicorn app.control_api:app"
    )
    assert entries["execution-orchestrator"]["entrypoint"] == (
        "python -m app.execution_orchestrator"
    )
    assert entries["control-api"]["listen"] == "0.0.0.0:8081"
    assert entries["execution-orchestrator"]["listen"] == "0.0.0.0:8090"
    assert entries["gateway-rpc-request-proxy"]["entrypoint"].startswith("socat ")
    assert entries["gateway-rpc-publish-proxy"]["entrypoint"].startswith("socat ")


def test_phase_a_units_have_unique_state_and_order_ownership() -> None:
    units = _by_id(MANIFEST["deployment_units"])
    assert set(units) == {
        "frontend-edge",
        "control-api",
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
        "questdb",
        "postgres",
        "windows-ctp-gateway",
    }
    order_capable = {
        unit_id for unit_id, unit in units.items() if unit["order_rpc"]["allowed"]
    }
    assert order_capable == {"execution-orchestrator"}
    assert units["execution-orchestrator"]["order_rpc"]["methods"] == [
        "send_order",
        "cancel_order",
    ]
    assert units["windows-ctp-gateway"]["order_rpc"]["provides_methods"] == [
        "send_order",
        "cancel_order",
    ]
    assert units["windows-ctp-gateway"]["order_rpc"]["caller"] == (
        "execution-orchestrator"
    )
    owners: dict[str, str] = {}
    for unit in units.values():
        for state in unit["state_owner"]:
            assert state not in owners, f"duplicate state writer: {state}"
            owners[state] = unit["id"]


def test_control_frontend_and_execution_network_boundaries_are_fail_closed() -> None:
    units = _by_id(MANIFEST["deployment_units"])
    frontend = units["frontend-edge"]
    control = units["control-api"]
    execution = units["execution-orchestrator"]
    assert frontend["network"]["published_ports"] == ["8080:8080"]
    assert control["network"]["published_ports"] == []
    assert execution["network"]["published_ports"] == []
    assert control["order_rpc"]["allowed"] is False
    assert control["private_key"]["allowed"] is False
    assert execution["private_key"]["allowed"] is False
    assert (
        "gateway-rpc-request-proxy:$GATEWAY_RPC_REQ_PROXY_PORT"
        in execution["network"]["outbound"]
    )
    assert (
        "gateway-rpc-publish-proxy:$GATEWAY_RPC_PUB_PROXY_PORT"
        in execution["network"]["outbound"]
    )
    assert "gateway-egress" in execution["network"]["denied"]
    assert "windows-ctp-gateway:direct" in execution["network"]["denied"]
    assert "windows-ctp-gateway" in control["network"]["denied"]
    assert "private_custody" in frontend["network"]["denied"]

    request_proxy = units["gateway-rpc-request-proxy"]
    publish_proxy = units["gateway-rpc-publish-proxy"]
    assert request_proxy["network"]["networks"] == [
        "gateway-proxy",
        "gateway-egress",
    ]
    assert publish_proxy["network"]["networks"] == [
        "gateway-proxy",
        "gateway-egress",
    ]
    assert request_proxy["network"]["outbound"] == ["windows-ctp-gateway:2014"]
    assert publish_proxy["network"]["outbound"] == ["windows-ctp-gateway:4102"]


def test_current_monolith_lifecycle_is_complete_and_each_call_has_one_target() -> None:
    lifecycle = MANIFEST["current_app_main_lifecycle"]
    entries = lifecycle["entries"]
    calls = [entry["call"] for entry in entries]
    assert len(calls) == len(set(calls))
    assert lifecycle["current_owner"] == "web-bridge"
    known_target_owners = {unit["id"] for unit in MANIFEST["deployment_units"]} | set(
        MANIFEST["reserved_phase_b_owners"]
    )
    valid_transitions = {
        "move_after_contract",
        "retire_replace",
        "retire_replace_no_rpc_dependency",
        "retire_replace_phase_b",
        "remove_research_provider_binding",
        "consume_verified_artifact_only",
    }
    for entry in entries:
        assert entry["target_owner"] in known_target_owners
        assert entry["transition"] in valid_transitions
        assert entry["call"].endswith((".start", ".stop")) or ".bind_" in entry["call"]
    assert {
        "rpc_service.bind_loop",
        "rpc_service.start",
        "rpc_service.stop",
        "commodity_simnow_service.start",
        "commodity_simnow_service.stop",
    } <= set(calls)


def test_leader_fencing_contract_covers_send_cancel_and_restart() -> None:
    contract = MANIFEST["leader_fencing_contract"]
    assert contract["epoch"] == "strictly_monotonic_never_reused"
    assert contract["fencing_token"] == "strictly_monotonic_account_scoped_never_reused"
    assert {
        "leader_epoch",
        "fencing_token",
        "plan_id",
        "plan_hash",
        "intent_id",
        "idempotency_key",
    } <= set(contract["mutation_binding"])
    assert "send_and_cancel" in contract["final_admission"]
    assert contract["rpc_timeout"] == "unknown_outcome_query_same_intent_no_new_send"
    assert contract["restart"].startswith("HALTED_RECONCILE_REQUIRED")


def test_execution_fencing_is_owned_by_json_durable_state_not_postgres_lease() -> None:
    state = MANIFEST["state_ownership"]["leader_lease_and_fencing"]
    assert state["owner"] == "execution-orchestrator"
    assert state["store"] == "execution_durable_state"
    assert "JSON" in state["format"]
    assert "Postgres is not a lease owner" in state["non_owner_behavior"]
    assert MANIFEST["leader_fencing_contract"]["lease_store"] == (
        "execution_durable_state_json"
    )


def test_parallel_work_packages_do_not_share_owned_path_prefixes() -> None:
    packages = MANIFEST["parallel_work_packages"]
    seen: dict[str, str] = {}
    for package in packages:
        for path in package["paths"]:
            assert path not in seen, f"path is owned twice: {path}"
            seen[path] = package["id"]
    assert {package["id"] for package in packages} == {
        "contract-schema",
        "frontend-edge",
        "control-api",
        "execution-orchestrator",
        "compose-integration",
    }


def test_compose_contract_matches_actual_proxy_and_questdb_data_networks() -> None:
    compose = MANIFEST["compose_contract"]
    assert compose["networks"]["edge"]["members"] == ["frontend-edge"]
    assert compose["networks"]["edge-control"]["members"] == [
        "frontend-edge",
        "control-api",
    ]
    assert compose["networks"]["gateway-proxy"]["members"] == [
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    ]
    assert compose["networks"]["gateway-egress"]["members"] == [
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    ]
    assert compose["networks"]["data-private"]["members"] == ["questdb"]


def test_command_and_status_schemas_are_valid_draft202012_schemas() -> None:
    Draft202012Validator.check_schema(COMMAND_SCHEMA)
    Draft202012Validator.check_schema(STATUS_SCHEMA)
    assert COMMAND_SCHEMA["properties"]["command"]["enum"] == [
        "status",
        "overview",
        "preview",
        "enable",
        "revoke",
        "start",
        "stop",
        "reconcile",
        "drain",
        "safe_to_restart",
    ]
    assert "send_order" not in COMMAND_SCHEMA["properties"]["command"]["enum"]
    assert "cancel_order" not in COMMAND_SCHEMA["properties"]["command"]["enum"]
    assert set(COMMAND_SCHEMA["required"]) >= {
        "idempotency_key",
        "correlation_id",
        "expected",
    }
    assert set(STATUS_SCHEMA["required"]) >= {
        "leader",
        "authority",
        "plan",
        "send_intents",
        "reconciliation",
        "safe_to_restart",
    }


def test_command_schema_accepts_typed_preview_and_rejects_unknown_or_mismatched_data() -> (
    None
):
    validator = Draft202012Validator(COMMAND_SCHEMA)
    valid = _command(
        "preview",
        {
            "plan_hash": _hash(),
            "artifact_hash": _hash("b"),
            "mode": "offline_preview",
        },
    )
    assert list(validator.iter_errors(valid)) == []

    unknown_field = dict(valid)
    unknown_field["unexpected"] = True
    assert list(validator.iter_errors(unknown_field))

    mismatched = _command("preview", {"reason": "wrong payload for preview"})
    assert list(validator.iter_errors(mismatched))

    forbidden_rpc = _command("send_order", {})
    assert list(validator.iter_errors(forbidden_rpc))


def test_status_schema_requires_durable_state_projection() -> None:
    validator = Draft202012Validator(STATUS_SCHEMA)
    status = {
        "schema_version": "web_bridge_execution_status_v1",
        "service": "execution-orchestrator",
        "service_version": "phase-a-dev",
        "observed_at": "2026-08-05T00:00:00Z",
        "lifecycle": "HALTED_RECONCILE_REQUIRED",
        "state_version": 7,
        "leader": {
            "scope": "account:simnow",
            "owner_id": "execution-instance-a",
            "held": True,
            "epoch": 3,
            "fencing_token": 11,
            "lease_expires_at": "2026-08-05T00:01:00Z",
        },
        "authority": {
            "state": "DISABLED",
            "artifact_id": "authority-disabled",
            "artifact_hash": _hash(),
            "expires_at": "2026-08-05T00:01:00Z",
        },
        "plan": {
            "state": "IDLE",
            "plan_id": "plan-none",
            "plan_hash": _hash("b"),
            "version": 0,
        },
        "send_intents": [],
        "reconciliation": {
            "state": "REQUIRED",
            "run_id": "reconcile-20260805",
            "last_completed_at": "2026-08-04T23:59:00Z",
            "unknown_outcomes": 0,
            "fresh_snapshot_id": "snapshot-20260805",
        },
        "safe_to_restart": False,
        "broker": {
            "connected": True,
            "generation": 10,
            "active_order_count": 0,
            "position_snapshot_hash": _hash("c"),
            "last_snapshot_at": "2026-08-05T00:00:00Z",
        },
    }
    assert list(validator.iter_errors(status)) == []
    missing_intents = dict(status)
    del missing_intents["send_intents"]
    assert list(validator.iter_errors(missing_intents))


def test_phase_a_document_explicitly_supersedes_progressive_route() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    assert "取代 #267 的渐进迁移路线" in text
    assert "不做：" in text
    assert "旧 `web-bridge` 单体兼容层" in text
    assert "HALTED_RECONCILE_REQUIRED" in text
