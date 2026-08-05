from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = ROOT / "docs/architecture/web-bridge-deployment-ownership-v1.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _units(scope: str) -> dict[str, dict[str, object]]:
    units = MANIFEST[scope]
    assert isinstance(units, list)
    by_id = {unit["id"]: unit for unit in units}
    assert len(by_id) == len(units), f"duplicate deployment unit in {scope}"
    return by_id


def test_manifest_freezes_issue267_scope_and_safe_defaults() -> None:
    assert MANIFEST["schema_version"] == "web_bridge_deployment_ownership_v1"
    assert MANIFEST["issue"] == 267
    assert MANIFEST["defaults"] == {
        "live_trading_authorized": False,
        "production_allowed": False,
        "automatic_deploy_allowed": False,
        "private_keys_in_repository_or_runtime_images": False,
        "unspecified_network_access": "deny",
        "artifact_overwrite": "deny",
    }
    assert MANIFEST["target_contract_status"] == "planned_not_implemented"
    assert (
        MANIFEST["release_trigger_contract"]["classifier_consumption_allowed"] is False
    )
    assert MANIFEST["release_trigger_contract"]["unknown_path"] == "block"


def test_manifest_records_current_monolith_startup_ownership() -> None:
    current = _units("current_deployment_units")
    assert {
        "web-bridge",
        "questdb",
        "postgres",
        "windows-ctp-gateway",
        "offline-signing-tools",
    } <= current.keys()

    tasks = set(current["web-bridge"]["startup_tasks"])
    assert {
        "vue_static",
        "fastapi_rest",
        "fastapi_websocket",
        "tick_persistence",
        "windows_rpc",
        "c_fast_shadow",
        "execution_quality",
        "monitor_worker",
        "commodity_simnow",
    } <= tasks


def test_every_unit_uses_the_same_auditable_field_contract() -> None:
    required = {
        "id",
        "deployment_mode",
        "code_paths",
        "startup_tasks",
        "state_owner",
        "order_rpc",
        "private_key",
        "artifact_write",
        "network_access",
        "durability",
        "release_trigger",
        "restart_policy",
        "phase",
    }
    for scope in ("current_deployment_units", "target_deployment_units"):
        for unit in MANIFEST[scope]:
            assert set(unit) == required, f"field drift for {scope}:{unit['id']}"


def test_app_main_service_lifecycle_has_an_exact_target_owner() -> None:
    # Phase A removes the monolith lifecycle entirely.  The old inventory is
    # retained as historical ownership evidence, while the actual entrypoint
    # is a pure Control alias; workers and RPC bind only in their new owners.
    source = (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    assert "from app.control_api import app" in source
    assert "@app.on_event" not in source
    assert "def startup" not in source
    assert "def shutdown" not in source

    phase_a = json.loads(
        (ROOT / "docs/architecture/issue-291-phase-a-ownership-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert phase_a["current_app_main_lifecycle"]["current_owner"] == "web-bridge"
    assert len(phase_a["current_app_main_lifecycle"]["entries"]) == 20
    assert {unit["id"] for unit in phase_a["deployment_units"]} >= {
        "control-api",
        "execution-orchestrator",
    }


def test_target_units_cover_every_issue267_deployment_boundary() -> None:
    target = _units("target_deployment_units")
    assert {
        "frontend",
        "control-api",
        "map-producer",
        "c-fast-producer",
        "signing-authority",
        "artifact-registry",
        "execution-orchestrator",
        "execution-quality-worker",
        "monitor-worker",
        "market-data-worker",
        "questdb",
        "postgres",
        "windows-ctp-gateway",
    } == target.keys()
    assert {unit["phase"] for unit in target.values()} == {
        "phase_0",
        "phase_1",
        "phase_2",
        "phase_3",
        "phase_4",
        "phase_5",
    }


def test_target_state_has_one_authoritative_owner() -> None:
    owners = [
        state
        for unit in _units("target_deployment_units").values()
        for state in unit["state_owner"]
    ]
    duplicates = sorted(state for state, count in Counter(owners).items() if count > 1)
    assert duplicates == []


def test_only_execution_boundaries_have_order_rpc_authority() -> None:
    target = _units("target_deployment_units")
    allowed = {
        unit_id for unit_id, unit in target.items() if unit["order_rpc"]["allowed"]
    }
    assert allowed == {"execution-orchestrator"}
    for unit_id, unit in target.items():
        if unit_id not in allowed:
            assert unit["order_rpc"]["methods"] == []
    providers = {
        unit_id
        for unit_id, unit in target.items()
        if unit["order_rpc"].get("provides_methods")
    }
    assert providers == {"windows-ctp-gateway"}
    gateway = target["windows-ctp-gateway"]["order_rpc"]
    assert gateway["provides_methods"] == ["send_order", "cancel_order"]
    assert gateway["caller"] == "execution-orchestrator"
    assert gateway["requires_account_scoped_fencing"] is True

    current = _units("current_deployment_units")
    assert {
        unit_id for unit_id, unit in current.items() if unit["order_rpc"]["allowed"]
    } == {"web-bridge"}
    assert current["windows-ctp-gateway"]["order_rpc"]["provides_methods"] == [
        "send_order",
        "cancel_order",
    ]


def test_only_signing_authority_can_read_private_keys() -> None:
    target = _units("target_deployment_units")
    allowed = {
        unit_id for unit_id, unit in target.items() if unit["private_key"]["allowed"]
    }
    assert allowed == {"signing-authority"}
    assert set(target["signing-authority"]["artifact_write"]) == {
        "signed_acceptance",
        "signed_execution_permit",
        "signed_research",
        "signed_runtime_authorization",
    }
    key_policy = target["signing-authority"]["private_key"]
    assert set(key_policy["domains"]) == {
        "research",
        "map_acceptance",
        "c_fast_acceptance",
        "runtime_authorization",
        "execution_permit",
    }
    assert key_policy["separate_runtime_identity_per_domain"] is True
    assert key_policy["cross_domain_key_reuse"] == "deny"
    signer_network = target["signing-authority"]["network_access"]
    assert signer_network["outbound"] == ["artifact-registry:submit_signed_artifact"]
    assert {"install", "enable", "revoke", "control_command", "order_rpc"} <= set(
        signer_network["denied_capabilities"]
    )


def test_frontend_and_control_api_cannot_restart_or_command_execution() -> None:
    target = _units("target_deployment_units")
    frontend = target["frontend"]
    control = target["control-api"]

    assert frontend["phase"] == "phase_1"
    assert frontend["state_owner"] == []
    assert frontend["restart_policy"] == (
        "independent_replace_without_dependency_recreate"
    )
    assert frontend["network_access"]["outbound"] == [
        "phase_1:web-bridge:8080",
        "phase_2_plus:control-api:8080",
    ]
    assert all(
        not trigger.startswith("backend/") for trigger in frontend["release_trigger"]
    )
    assert control["order_rpc"]["allowed"] is False
    assert control["private_key"]["allowed"] is False
    assert "execution-orchestrator" in control["network_access"]["outbound"]


def test_execution_requires_durable_fencing_and_safe_restart() -> None:
    execution = _units("target_deployment_units")["execution-orchestrator"]
    assert execution["phase"] == "phase_2"
    assert execution["restart_policy"] == (
        "safe_to_restart_then_drain_checkpoint_replace_reconcile_with_fencing"
    )
    assert "acquire_fenced_lease" in execution["startup_tasks"]
    assert "fencing_token" in execution["state_owner"]
    assert execution["durability"]["implementation_status"] == "planned_phase_2"
    assert execution["durability"]["write_before_send"] is True
    assert set(execution["durability"]["required_state"]) == {
        "active_plan",
        "authority_effective_state",
        "send_intent",
        "unknown_outcome",
        "callback_facts",
        "recovery_state",
        "rpc_generation",
        "leader_epoch",
        "fencing_token",
    }
    assert execution["durability"]["restart_loss_risk"] == [
        "unproven_until_phase_2_cutover_evidence"
    ]
    assert "postgres_execution_state" in execution["durability"]["stores"]


def test_runtime_authorization_and_consume_receipts_have_unique_writers() -> None:
    ownership = MANIFEST["target_runtime_authorization_ownership"]
    assert ownership == {
        "immutable_artifact_creator": "signing-authority",
        "artifact_and_install_receipt_writer": "artifact-registry",
        "revoke_receipt_writer": "artifact-registry",
        "enable_revoke_command_issuer": "control-api",
        "effective_enabled_expired_revoked_state_writer": "execution-orchestrator",
        "revoke_protocol": "control-api issues idempotent command; execution first persists fail-closed effective revoke, then requests artifact-registry receipt with authorization hash, actor, idempotency key and fencing epoch; receipt failures retry without re-enabling",
        "control_api_role": "idempotent_command_and_readonly_projection_only",
    }
    target = _units("target_deployment_units")
    assert "consume_receipt" in target["artifact-registry"]["artifact_write"]
    assert "consume_receipt" not in target["execution-orchestrator"]["artifact_write"]
    assert (
        "consume_request_journal" in target["execution-orchestrator"]["artifact_write"]
    )

    revoke_edge = next(
        edge
        for edge in MANIFEST["target_network_policy"]["edges"]
        if edge["phase"] == "phase_4"
        and edge["source"] == "execution-orchestrator"
        and edge["target"] == "artifact-registry"
    )
    assert {"request_revoke", "read_revoke_receipt"} <= set(revoke_edge["capabilities"])


def test_critical_network_edges_are_scoped_and_default_deny() -> None:
    policy = MANIFEST["target_network_policy"]
    assert policy["default"] == "deny"
    assert policy["authoritative"] is True
    assert policy["unit_network_access_fields_authoritative"] is False
    edges = {
        (edge["phase"], edge["source"], edge["target"]): set(edge["capabilities"])
        for edge in policy["edges"]
    }
    assert edges[("phase_1", "frontend", "web-bridge")] == {
        "api_proxy",
        "websocket_proxy",
    }
    assert edges[("phase_2", "frontend", "control-api")] == {
        "api_proxy",
        "websocket_proxy",
    }
    assert edges[("phase_2", "execution-orchestrator", "windows-ctp-gateway")] == {
        "query",
        "subscribe",
        "send_order",
        "cancel_order",
    }
    assert {
        "authorization_status",
        "enable_authorization",
        "revoke_authorization",
        "revalidate_authorization",
        "safe_to_restart",
    } <= edges[("phase_2", "control-api", "execution-orchestrator")]
    assert edges[("phase_4", "control-api", "artifact-registry")] == {
        "metadata",
        "submit_uploaded_signed_artifact",
        "verify_request",
        "install_request",
        "read_install_consume_revoke_receipt",
    }
    assert edges[("phase_3", "map-producer", "legacy-candidate-custody-adapter")] == {
        "create_unsigned_map_candidate"
    }
    assert edges[
        ("phase_3", "c-fast-producer", "legacy-candidate-custody-adapter")
    ] == {"create_unsigned_c_fast_candidate"}
    assert edges[("phase_5", "market-data-worker", "windows-ctp-gateway")] == {
        "query",
        "subscribe",
    }
    assert edges[("phase_5", "market-data-worker", "execution-quality-worker")] == {
        "publish_verified_tick"
    }
    forbidden = {
        ("frontend", "execution-orchestrator"),
        ("frontend", "windows-ctp-gateway"),
        ("control-api", "windows-ctp-gateway"),
        ("map-producer", "windows-ctp-gateway"),
        ("c-fast-producer", "windows-ctp-gateway"),
        ("signing-authority", "execution-orchestrator"),
    }
    actual = {(edge["source"], edge["target"]) for edge in policy["edges"]}
    assert actual.isdisjoint(forbidden)

    market = _units("target_deployment_units")["market-data-worker"]
    assert "windows-gateway:2014:readonly_query" in market["network_access"]["outbound"]
    assert "windows-gateway:4102:subscribe" in market["network_access"]["outbound"]


def test_producer_and_signer_code_closures_are_fail_closed() -> None:
    target = _units("target_deployment_units")
    producer_paths = target["c-fast-producer"]["code_paths"]
    forbidden_producer_terms = {
        "sign",
        "permit",
        "execution_policy",
        "preconnect",
        "executable",
        "rpc",
        "trade_service",
    }
    for path in producer_paths:
        assert not any(term in path.lower() for term in forbidden_producer_terms), path

    signer_paths = target["signing-authority"]["code_paths"]
    assert signer_paths == [
        "future:scripts/signing/**",
        "shared/artifact-contracts/**",
    ]


def test_execution_quality_fanout_has_one_target_owner() -> None:
    target = _units("target_deployment_units")
    market = target["market-data-worker"]
    quality = target["execution-quality-worker"]
    fanout = "backend/app/services/commodity_c_fast_execution_quality_tick_fanout.py"

    assert fanout not in market["code_paths"]
    assert "execution_quality_fanout" not in market["startup_tasks"]
    assert "tick_fanout" in quality["startup_tasks"]
    assert (
        "backend/app/services/commodity_c_fast_execution_quality_*.py"
        in quality["code_paths"]
    )
