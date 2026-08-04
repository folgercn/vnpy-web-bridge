from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.schemas.deployment_drain import (
    DeploymentReconciliationActivationHeadDTO,
    DeploymentReconciliationActivationHeadV2DTO,
    DeploymentReconciliationActivationIntentDTO,
    DeploymentReconciliationActivationMarkerDTO,
    DeploymentReconciliationOwnerBindingDTO,
    DeploymentReconciliationOwnerCapturePairDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    DeploymentRpcRecheckServedProofDTO,
    deployment_rpc_execution_facts_sha256,
)
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_CASES = (
    (
        DeploymentReconciliationOwnerBindingDTO,
        "web-bridge-deployment-reconciliation-owner-binding-v1.schema.json",
    ),
    (
        DeploymentReconciliationActivationIntentDTO,
        "web-bridge-deployment-reconciliation-intent-v1.schema.json",
    ),
    (
        DeploymentReconciliationOwnerCapturePairDTO,
        "web-bridge-deployment-reconciliation-capture-pair-v1.schema.json",
    ),
    (
        DeploymentReconciliationActivationMarkerDTO,
        "web-bridge-deployment-reconciliation-activation-marker-v1.schema.json",
    ),
    (
        DeploymentReconciliationActivationHeadDTO,
        "web-bridge-deployment-reconciliation-activation-head-v1.schema.json",
    ),
    (
        DeploymentRpcRecheckServedProofDTO,
        "web-bridge-deployment-rpc-recheck-served-proof-v1.schema.json",
    ),
    (
        DeploymentReconciliationActivationHeadV2DTO,
        "web-bridge-deployment-reconciliation-activation-head-v2.schema.json",
    ),
)
FALSE_FIELDS = (
    "external_high_water_verified",
    "target_runtime_verified",
    "reconciliation_completed",
    "windows_fence_released",
    "authority_restore_allowed",
    "consume_authorized",
    "reconciliation_authorized",
    "deployment_authorized",
    "automatic_deploy_allowed",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _core(value: object) -> str:
    return hashlib.sha256(_canonical(value)[:-1]).hexdigest()


def _raw(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _false_boundary(*, include_external: bool = True) -> dict[str, bool]:
    fields = FALSE_FIELDS if include_external else FALSE_FIELDS[7:]
    return {field: False for field in fields}


def _owner() -> DeploymentReconciliationOwnerBindingDTO:
    account = "a" * 64
    allowlist = [account, "b" * 64]
    payload = {
        "schema_version": "web_bridge_deployment_reconciliation_owner_binding_v1",
        "purpose": "bind_unique_frozen_commodity_owner_for_reconciliation",
        "owner_kind": "COMMODITY_SIMNOW",
        "deployment_runtime_instance_id": "runtime-c2b-current",
        "deployment_execution_epoch": 8,
        "deployment_state_generation": 9,
        "deployment_state_commitment_raw_sha256": "c" * 64,
        "custody_root_path_sha256": "d" * 64,
        "custody_root_device": 1,
        "custody_root_inode": 2,
        "deployment_lock_device": 1,
        "deployment_lock_inode": 3,
        "commodity_state_version": "commodity-simnow-v1",
        "commodity_state_path_sha256": "e" * 64,
        "commodity_state_file_present": True,
        "commodity_state_device": 1,
        "commodity_state_inode": 4,
        "commodity_state_uid": 501,
        "commodity_state_gid": 20,
        "commodity_state_mode": 0o600,
        "commodity_state_nlink": 1,
        "commodity_state_raw_sha256": "f" * 64,
        "commodity_state_checkpoint_sha256": "1" * 64,
        "gateway_name": "SIMNOW01",
        "rpc_request_endpoint_sha256": "2" * 64,
        "rpc_publish_endpoint_sha256": "3" * 64,
        "expected_account_hash": account,
        "account_allowlist": allowlist,
        "account_allowlist_sha256": _core(allowlist),
        "expected_account_allowlisted": True,
        "web_trade_enabled": False,
        "execution_authority_revoked": True,
        "auto_dispatch_stopped": True,
        **_false_boundary(include_external=False),
    }
    digest = _core(payload)
    return DeploymentReconciliationOwnerBindingDTO.model_validate(
        {
            **payload,
            "owner_binding_id": f"deployment-reconciliation-owner-binding-{digest}",
            "owner_binding_core_sha256": digest,
        }
    )


def _intent() -> DeploymentReconciliationActivationIntentDTO:
    owner = _owner()
    payload = {
        "schema_version": "web_bridge_deployment_reconciliation_intent_v1",
        "purpose": "prepare_deterministic_owner_reconciliation_capture",
        "mode": "PLANNED_RESTART",
        "operator": "c2b-schema-test",
        "reason": "bind exact non-authorizing C2b reconciliation evidence",
        "custody_inventory_id": (
            "deployment-reconciliation-custody-inventory-" + "4" * 64
        ),
        "custody_inventory_core_sha256": "4" * 64,
        "custody_inventory_raw_sha256": "5" * 64,
        "custody_inventory_digest_sha256": "6" * 64,
        "genesis_commitment_raw_sha256": "7" * 64,
        "current_state_commitment_raw_sha256": "c" * 64,
        "current_state_raw_sha256": "8" * 64,
        "current_epoch_anchor_raw_sha256": "9" * 64,
        "current_state_generation": 9,
        "current_runtime_instance_id": "runtime-c2b-current",
        "current_execution_epoch": 8,
        "owner_binding_raw_sha256": _raw(owner.model_dump(mode="json")),
        "owner_binding": owner.model_dump(mode="json"),
        "activation_sequence": 1,
        "previous_activation_head_id": None,
        "previous_activation_head_raw_sha256": None,
        "previous_activation_head_core_sha256": None,
        "rpc_request_id": "request-c2b-planned",
        "owner_challenge": "owner-challenge-c2b-planned",
        "initial_capture_id": "deployment-recheck-" + "1" * 64,
        "initial_challenge": "consumed-fresh-challenge-c2b",
        "fresh_capture_id": "deployment-recheck-" + "2" * 64,
        "fresh_challenge": "post-restart-fresh-challenge-c2b",
        **_false_boundary(),
    }
    stable_slot = {
        "domain": "issue267-c2b-intent-slot-v1",
        "mode": payload["mode"],
        "custody_inventory_digest_sha256": (payload["custody_inventory_digest_sha256"]),
        "genesis_commitment_raw_sha256": payload["genesis_commitment_raw_sha256"],
        "current_state_commitment_raw_sha256": (
            payload["current_state_commitment_raw_sha256"]
        ),
        "current_state_raw_sha256": payload["current_state_raw_sha256"],
        "current_epoch_anchor_raw_sha256": (payload["current_epoch_anchor_raw_sha256"]),
        "current_state_generation": payload["current_state_generation"],
        "current_runtime_instance_id": payload["current_runtime_instance_id"],
        "current_execution_epoch": payload["current_execution_epoch"],
        "owner_binding_core_sha256": owner.owner_binding_core_sha256,
        "expected_account_hash": owner.expected_account_hash,
        "activation_sequence": 1,
        "previous_activation_head_raw_sha256": None,
    }
    slot = _core(stable_slot)
    payload.update(
        intent_slot_sha256=slot,
        reconciliation_run_id=f"deployment-c2b-run-{slot}",
    )
    digest = _core(payload)
    intent_id = f"deployment-reconciliation-intent-{slot}"
    return DeploymentReconciliationActivationIntentDTO.model_validate(
        {
            **payload,
            "intent_id": intent_id,
            "intent_core_sha256": digest,
            "intent_path": f"reconciliation-intents/{intent_id}.json",
        }
    )


def _capture_pair() -> DeploymentReconciliationOwnerCapturePairDTO:
    intent = _intent()
    observed = datetime(2026, 8, 5, 1, tzinfo=timezone.utc)
    initial_projection = DeploymentRpcFactsDTO.model_validate(
        {
            "schema_version": "windows_rpc_deployment_safety_snapshot_v1",
            "request_id": intent.rpc_request_id,
            "challenge": intent.owner_challenge,
            "server_instance_id": "windows-rpc-c2b",
            "fact_generation": 12,
            "captured_at": observed,
            "execution_admission_frozen": True,
            "pending_send_outcomes": 0,
            "strategy_execution_enabled": False,
            "account_hashes": [intent.owner_binding.expected_account_hash],
            "orders": [],
            "active_orders": [],
            "trades": [],
            "positions": [{"symbol": "RB2610", "volume": 1}],
        }
    )
    execution_sha = deployment_rpc_execution_facts_sha256(initial_projection)
    initial = DeploymentRpcRecheckFactsDTO.model_validate(
        {
            "schema_version": "windows_rpc_deployment_safety_recheck_v1",
            "request_id": intent.rpc_request_id,
            "owner_challenge": intent.owner_challenge,
            "recheck_id": intent.initial_capture_id,
            "fresh_challenge": intent.initial_challenge,
            "original_server_instance_id": initial_projection.server_instance_id,
            "original_fact_generation": initial_projection.fact_generation,
            "original_execution_facts_canonical_sha256": execution_sha,
            "server_instance_id": initial_projection.server_instance_id,
            "fact_generation": initial_projection.fact_generation,
            "execution_facts_canonical_sha256": execution_sha,
            "captured_at": observed,
            "execution_admission_frozen": True,
            "pending_send_outcomes": 0,
            "strategy_execution_enabled": False,
            "account_hashes": initial_projection.account_hashes,
            "orders": initial_projection.orders,
            "active_orders": initial_projection.active_orders,
            "trades": initial_projection.trades,
            "positions": initial_projection.positions,
        }
    )
    fresh = DeploymentRpcRecheckFactsDTO.model_validate(
        {
            "schema_version": "windows_rpc_deployment_safety_recheck_v1",
            "request_id": intent.rpc_request_id,
            "owner_challenge": intent.owner_challenge,
            "recheck_id": intent.fresh_capture_id,
            "fresh_challenge": intent.fresh_challenge,
            "original_server_instance_id": initial.server_instance_id,
            "original_fact_generation": initial.fact_generation,
            "original_execution_facts_canonical_sha256": execution_sha,
            "server_instance_id": initial.server_instance_id,
            "fact_generation": initial.fact_generation,
            "execution_facts_canonical_sha256": execution_sha,
            "captured_at": observed + timedelta(seconds=1),
            "execution_admission_frozen": True,
            "pending_send_outcomes": 0,
            "strategy_execution_enabled": False,
            "account_hashes": initial.account_hashes,
            "orders": initial.orders,
            "active_orders": initial.active_orders,
            "trades": initial.trades,
            "positions": initial.positions,
        }
    )
    payload = {
        "schema_version": "web_bridge_deployment_reconciliation_capture_pair_v1",
        "purpose": "record_two_stable_frozen_owner_rpc_captures",
        "mode": intent.mode,
        "intent_id": intent.intent_id,
        "intent_raw_sha256": _raw(intent.model_dump(mode="json")),
        "intent_core_sha256": intent.intent_core_sha256,
        "owner_binding_id": intent.owner_binding.owner_binding_id,
        "owner_binding_core_sha256": intent.owner_binding.owner_binding_core_sha256,
        "expected_account_hash": intent.owner_binding.expected_account_hash,
        "rpc_request_id": intent.rpc_request_id,
        "owner_challenge": intent.owner_challenge,
        "initial_capture_id": intent.initial_capture_id,
        "initial_challenge": intent.initial_challenge,
        "fresh_capture_id": intent.fresh_capture_id,
        "fresh_challenge": intent.fresh_challenge,
        "commodity_state_raw_sha256": (intent.owner_binding.commodity_state_raw_sha256),
        "commodity_state_checkpoint_sha256": (
            intent.owner_binding.commodity_state_checkpoint_sha256
        ),
        "initial_rpc_raw_sha256": _raw(initial.model_dump(mode="json")),
        "initial_rpc": initial.model_dump(mode="json"),
        "fresh_rpc_raw_sha256": _raw(fresh.model_dump(mode="json")),
        "fresh_rpc": fresh.model_dump(mode="json"),
        "initial_execution_facts_canonical_sha256": execution_sha,
        "fresh_execution_facts_canonical_sha256": execution_sha,
        "captured_at": observed + timedelta(seconds=2),
        "same_owner_cycle_verified": True,
        "two_capture_facts_verified": True,
        **_false_boundary(),
    }
    digest = _core(
        {
            **payload,
            "captured_at": payload["captured_at"].isoformat().replace("+00:00", "Z"),
        }
    )
    return DeploymentReconciliationOwnerCapturePairDTO.model_validate(
        {
            **payload,
            "capture_pair_id": f"deployment-reconciliation-capture-pair-{digest}",
            "capture_pair_core_sha256": digest,
        }
    )


def _head(tmp_path: Path) -> DeploymentReconciliationActivationHeadV2DTO:
    from test_issue267_reconciliation_c2b_activation import _owner

    owner, _rpc, _root = _owner(tmp_path / "schema-activation")
    return owner.reconcile_deployment_custody(
        operator="c2b-schema-closure",
        reason="build exact self-contained marker dependencies",
    )


def _v1_head(tmp_path: Path) -> DeploymentReconciliationActivationHeadDTO:
    payload = _head(tmp_path).model_dump(mode="json")
    payload["schema_version"] = (
        "web_bridge_deployment_reconciliation_activation_head_v1"
    )
    payload["purpose"] = "commit_non_authorizing_owner_reconciliation_activation"
    for field in (
        "fresh_rpc_served_proof_id",
        "fresh_rpc_served_proof_raw_sha256",
        "fresh_rpc_served_proof_core_sha256",
        "fresh_rpc_served_proof_blob_path",
        "gateway_name",
        "rpc_request_endpoint_sha256",
        "rpc_publish_endpoint_sha256",
        "owner_binding_raw_sha256",
        "owner_binding",
        "intent_raw_sha256",
        "intent",
        "fresh_rpc_served_proof",
        "served_proof_closure_verified",
    ):
        payload.pop(field)
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    return DeploymentReconciliationActivationHeadDTO.model_validate(payload)


def _marker(tmp_path: Path) -> DeploymentReconciliationActivationMarkerDTO:
    return _head(tmp_path).marker


def _rehash(payload: dict[str, object], prefix: str, *identity: str) -> None:
    core = dict(payload)
    for field in identity:
        core.pop(field)
    digest = _core(core)
    payload[identity[0]] = f"{prefix}{digest}"
    payload[identity[1]] = digest


def test_c2b_schema_happy_path_and_fail_closed_boundaries(tmp_path: Path) -> None:
    head = _head(tmp_path)
    artifacts = (_owner(), _intent(), _capture_pair(), head.marker, head)
    for artifact in artifacts:
        for field in FALSE_FIELDS:
            if hasattr(artifact, field):
                assert getattr(artifact, field) is False


def test_c2b_intent_is_time_free_and_deterministic() -> None:
    first = _intent()
    second = _intent()
    assert first == second
    assert "created_at" not in DeploymentReconciliationActivationIntentDTO.model_fields
    assert "captured_at" not in DeploymentReconciliationActivationIntentDTO.model_fields


def test_c2b_intent_slot_ignores_inventory_capture_raw_and_audit_text() -> None:
    original = _intent()
    payload = original.model_dump(mode="json")
    payload.update(
        operator="second-operator",
        reason="same stable slot, different create-only audit content",
        custody_inventory_id=(
            "deployment-reconciliation-custody-inventory-" + "a" * 64
        ),
        custody_inventory_core_sha256="b" * 64,
        custody_inventory_raw_sha256="d" * 64,
    )
    core = dict(payload)
    for field in ("intent_id", "intent_core_sha256", "intent_path"):
        core.pop(field)
    payload["intent_core_sha256"] = _core(core)
    changed = DeploymentReconciliationActivationIntentDTO.model_validate(payload)
    assert changed.intent_id == original.intent_id
    assert changed.intent_slot_sha256 == original.intent_slot_sha256
    assert changed.intent_core_sha256 != original.intent_core_sha256

    blank = changed.model_dump(mode="json")
    blank["operator"] = "   "
    core = dict(blank)
    for field in ("intent_id", "intent_core_sha256", "intent_path"):
        core.pop(field)
    blank["intent_core_sha256"] = _core(core)
    with pytest.raises(ValueError, match="binding is inconsistent"):
        DeploymentReconciliationActivationIntentDTO.model_validate(blank)


def test_c2b_owner_binding_supports_pristine_absent_state_file() -> None:
    payload = _owner().model_dump(mode="json")
    payload["commodity_state_file_present"] = False
    for field in (
        "commodity_state_device",
        "commodity_state_inode",
        "commodity_state_uid",
        "commodity_state_gid",
        "commodity_state_mode",
        "commodity_state_nlink",
        "commodity_state_raw_sha256",
    ):
        payload[field] = None
    _rehash(
        payload,
        "deployment-reconciliation-owner-binding-",
        "owner_binding_id",
        "owner_binding_core_sha256",
    )
    assert not DeploymentReconciliationOwnerBindingDTO.model_validate(
        payload
    ).commodity_state_file_present


def test_c2b_planned_pair_accepts_historical_consumed_recheck() -> None:
    payload = _capture_pair().model_dump(mode="json")
    initial_rpc = payload["initial_rpc"]
    assert isinstance(initial_rpc, dict)
    initial_rpc["captured_at"] = "2026-08-04T01:00:00Z"
    payload["initial_rpc_raw_sha256"] = _raw(initial_rpc)
    _rehash(
        payload,
        "deployment-reconciliation-capture-pair-",
        "capture_pair_id",
        "capture_pair_core_sha256",
    )
    pair = DeploymentReconciliationOwnerCapturePairDTO.model_validate(payload)
    assert pair.captured_at - pair.initial_rpc.captured_at > timedelta(seconds=30)


def test_c2b_capture_pair_rejects_coherently_rehashed_fact_drift() -> None:
    payload = _capture_pair().model_dump(mode="json")
    payload["fresh_rpc"]["positions"] = []  # type: ignore[index]
    fresh_rpc = payload["fresh_rpc"]
    assert isinstance(fresh_rpc, dict)
    fresh_rpc["execution_facts_canonical_sha256"] = _core(
        {
            field: fresh_rpc[field]
            for field in (
                "execution_admission_frozen",
                "pending_send_outcomes",
                "strategy_execution_enabled",
                "account_hashes",
                "orders",
                "active_orders",
                "trades",
                "positions",
            )
        }
    )
    payload["fresh_execution_facts_canonical_sha256"] = fresh_rpc[
        "execution_facts_canonical_sha256"
    ]
    payload["fresh_rpc_raw_sha256"] = _raw(payload["fresh_rpc"])
    _rehash(
        payload,
        "deployment-reconciliation-capture-pair-",
        "capture_pair_id",
        "capture_pair_core_sha256",
    )
    with pytest.raises(ValueError, match="not stable and frozen"):
        DeploymentReconciliationOwnerCapturePairDTO.model_validate(payload)


def test_c2b_marker_rejects_coherently_rehashed_cross_mode_evidence(
    tmp_path: Path,
) -> None:
    payload = _marker(tmp_path).model_dump(mode="json")
    payload["mode"] = "PLANNED_RESTART"
    _rehash(
        payload,
        "deployment-reconciliation-activation-marker-",
        "marker_id",
        "marker_core_sha256",
        "marker_path",
    )
    payload["marker_path"] = (
        f"reconciliation-blobs/activation-marker-{payload['marker_core_sha256']}.json"
    )
    with pytest.raises(ValueError, match="mode evidence mismatch"):
        DeploymentReconciliationActivationMarkerDTO.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        (
            "capture_pair_id",
            "deployment-reconciliation-capture-pair-" + "a" * 64,
        ),
        (
            "mode_evidence_id",
            "safe-restart-reconciliation-" + "a" * 64,
        ),
        (
            "mode_checkpoint_id",
            "deployment-post-restart-checkpoint-" + "a" * 64,
        ),
    ),
)
def test_c2b_marker_rejects_coherently_rehashed_dependency_splice(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    payload = _marker(tmp_path).model_dump(mode="json")
    payload[field] = replacement
    _rehash(
        payload,
        "deployment-reconciliation-activation-marker-",
        "marker_id",
        "marker_core_sha256",
        "marker_path",
    )
    payload["marker_path"] = (
        f"reconciliation-blobs/activation-marker-{payload['marker_core_sha256']}.json"
    )
    with pytest.raises(ValueError, match="mode evidence mismatch"):
        DeploymentReconciliationActivationMarkerDTO.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    (
        "capture_pair_raw_sha256",
        "mode_checkpoint_raw_sha256",
        "mode_evidence_raw_sha256",
    ),
)
def test_c2b_marker_rejects_coherently_rehashed_raw_dependency_splice(
    tmp_path: Path,
    field: str,
) -> None:
    payload = _marker(tmp_path).model_dump(mode="json")
    payload[field] = "a" * 64
    if field == "mode_evidence_raw_sha256":
        payload["mode_evidence_blob_path"] = (
            f"reconciliation-blobs/{payload[field]}.json"
        )
    _rehash(
        payload,
        "deployment-reconciliation-activation-marker-",
        "marker_id",
        "marker_core_sha256",
        "marker_path",
    )
    payload["marker_path"] = (
        f"reconciliation-blobs/activation-marker-{payload['marker_core_sha256']}.json"
    )
    with pytest.raises(ValueError, match="mode evidence mismatch"):
        DeploymentReconciliationActivationMarkerDTO.model_validate(payload)


def test_c2b_head_rejects_coherently_rehashed_marker_mismatch(
    tmp_path: Path,
) -> None:
    payload = _head(tmp_path).model_dump(mode="json")
    payload["intent_id"] = "deployment-reconciliation-intent-" + "f" * 64
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    with pytest.raises(ValueError, match="head binding mismatch"):
        DeploymentReconciliationActivationHeadV2DTO.model_validate(payload)


def test_c2b_head_v1_rejects_coherently_rehashed_predecessor_splice(
    tmp_path: Path,
) -> None:
    payload = _v1_head(tmp_path).model_dump(mode="json")
    payload.update(
        activation_sequence=2,
        previous_activation_head_id=(
            "deployment-reconciliation-activation-head-" + "a" * 64
        ),
        previous_activation_head_raw_sha256="b" * 64,
        previous_activation_head_core_sha256="c" * 64,
    )
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    with pytest.raises(ValueError):
        DeploymentReconciliationActivationHeadDTO.model_validate(payload)


def test_c2b_v2_head_closes_exact_served_proof_and_keeps_v1_unchanged(
    tmp_path: Path,
) -> None:
    head = _head(tmp_path)
    assert head.schema_version == (
        "web_bridge_deployment_reconciliation_activation_head_v2"
    )
    assert head.served_proof_closure_verified is True
    assert head.fresh_rpc_served_proof.fresh_rpc_raw_sha256 == _raw(
        head.marker.capture_pair.fresh_rpc.model_dump(mode="json")
    )
    assert "fresh_rpc" not in type(head.fresh_rpc_served_proof).model_fields
    assert head.fresh_rpc_served_proof_blob_path == (
        f"reconciliation-blobs/{head.fresh_rpc_served_proof_raw_sha256}.json"
    )
    for field in FALSE_FIELDS:
        assert getattr(head, field) is False
        assert getattr(head.fresh_rpc_served_proof, field) is False

    v1_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-deployment-reconciliation-activation-head-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert "fresh_rpc_served_proof" not in v1_schema["properties"]
    assert v1_schema["properties"]["schema_version"]["const"].endswith(
        "activation_head_v1"
    )


def test_c2b_served_proof_rejects_coherently_rehashed_generation_drift(
    tmp_path: Path,
) -> None:
    payload = _head(tmp_path).fresh_rpc_served_proof.model_dump(mode="json")
    payload["served_fact_generation"] += 1
    _rehash(
        payload,
        "deployment-rpc-recheck-served-proof-",
        "proof_id",
        "proof_core_sha256",
    )
    with pytest.raises(ValueError, match="binding is invalid"):
        DeploymentRpcRecheckServedProofDTO.model_validate(payload)


def test_c2b_v2_head_rejects_coherently_rehashed_cross_intent_proof_splice(
    tmp_path: Path,
) -> None:
    head = _head(tmp_path / "first")
    other = _head(tmp_path / "other").fresh_rpc_served_proof
    payload = head.model_dump(mode="json")
    other_payload = other.model_dump(mode="json")
    other_raw = _canonical(other_payload)
    payload.update(
        fresh_rpc_served_proof_id=other.proof_id,
        fresh_rpc_served_proof_raw_sha256=hashlib.sha256(other_raw).hexdigest(),
        fresh_rpc_served_proof_core_sha256=other.proof_core_sha256,
        fresh_rpc_served_proof_blob_path=(
            f"reconciliation-blobs/{hashlib.sha256(other_raw).hexdigest()}.json"
        ),
        fresh_rpc_served_proof=other_payload,
    )
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    with pytest.raises(ValueError, match="served proof closure mismatch"):
        DeploymentReconciliationActivationHeadV2DTO.model_validate(payload)


def test_c2b_v2_head_rejects_coherently_rehashed_proof_original_tuple_drift(
    tmp_path: Path,
) -> None:
    payload = _head(tmp_path).model_dump(mode="json")
    proof = payload["fresh_rpc_served_proof"]
    proof.update(
        original_server_instance_id="forged-original-server",
        original_fact_generation=0,
        original_execution_facts_canonical_sha256="a" * 64,
    )
    _rehash(
        proof,
        "deployment-rpc-recheck-served-proof-",
        "proof_id",
        "proof_core_sha256",
    )
    proof_raw = _canonical(proof)
    payload.update(
        fresh_rpc_served_proof_id=proof["proof_id"],
        fresh_rpc_served_proof_raw_sha256=hashlib.sha256(proof_raw).hexdigest(),
        fresh_rpc_served_proof_core_sha256=proof["proof_core_sha256"],
        fresh_rpc_served_proof_blob_path=(
            f"reconciliation-blobs/{hashlib.sha256(proof_raw).hexdigest()}.json"
        ),
    )
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    with pytest.raises(ValueError, match="served proof closure mismatch"):
        DeploymentReconciliationActivationHeadV2DTO.model_validate(payload)


def test_c2b_v2_head_rejects_coherently_rehashed_endpoint_drift(
    tmp_path: Path,
) -> None:
    payload = _head(tmp_path).model_dump(mode="json")
    proof = payload["fresh_rpc_served_proof"]
    proof.update(
        gateway_name="ATTACKER",
        rpc_request_endpoint_sha256="a" * 64,
        rpc_publish_endpoint_sha256="b" * 64,
    )
    _rehash(
        proof,
        "deployment-rpc-recheck-served-proof-",
        "proof_id",
        "proof_core_sha256",
    )
    proof_raw = _canonical(proof)
    payload.update(
        gateway_name=proof["gateway_name"],
        rpc_request_endpoint_sha256=proof["rpc_request_endpoint_sha256"],
        rpc_publish_endpoint_sha256=proof["rpc_publish_endpoint_sha256"],
        fresh_rpc_served_proof_id=proof["proof_id"],
        fresh_rpc_served_proof_raw_sha256=hashlib.sha256(proof_raw).hexdigest(),
        fresh_rpc_served_proof_core_sha256=proof["proof_core_sha256"],
        fresh_rpc_served_proof_blob_path=(
            f"reconciliation-blobs/{hashlib.sha256(proof_raw).hexdigest()}.json"
        ),
    )
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    with pytest.raises(ValueError, match="served proof closure mismatch"):
        DeploymentReconciliationActivationHeadV2DTO.model_validate(payload)


def test_c2b_v2_head_rejects_rehashed_owner_chain_that_conflicts_with_intent(
    tmp_path: Path,
) -> None:
    payload = _head(tmp_path).model_dump(mode="json")
    binding = payload["owner_binding"]
    binding.update(
        gateway_name="ATTACKER",
        rpc_request_endpoint_sha256="a" * 64,
        rpc_publish_endpoint_sha256="b" * 64,
    )
    _rehash(
        binding,
        "deployment-reconciliation-owner-binding-",
        "owner_binding_id",
        "owner_binding_core_sha256",
    )
    payload.update(
        owner_binding_raw_sha256=_raw(binding),
        gateway_name=binding["gateway_name"],
        rpc_request_endpoint_sha256=binding["rpc_request_endpoint_sha256"],
        rpc_publish_endpoint_sha256=binding["rpc_publish_endpoint_sha256"],
    )

    proof = payload["fresh_rpc_served_proof"]
    proof.update(
        gateway_name=binding["gateway_name"],
        rpc_request_endpoint_sha256=binding["rpc_request_endpoint_sha256"],
        rpc_publish_endpoint_sha256=binding["rpc_publish_endpoint_sha256"],
    )
    _rehash(
        proof,
        "deployment-rpc-recheck-served-proof-",
        "proof_id",
        "proof_core_sha256",
    )
    proof_raw = _canonical(proof)
    payload.update(
        fresh_rpc_served_proof_id=proof["proof_id"],
        fresh_rpc_served_proof_raw_sha256=hashlib.sha256(proof_raw).hexdigest(),
        fresh_rpc_served_proof_core_sha256=proof["proof_core_sha256"],
        fresh_rpc_served_proof_blob_path=(
            f"reconciliation-blobs/{hashlib.sha256(proof_raw).hexdigest()}.json"
        ),
    )

    marker = payload["marker"]
    pair = marker["capture_pair"]
    pair.update(
        owner_binding_id=binding["owner_binding_id"],
        owner_binding_core_sha256=binding["owner_binding_core_sha256"],
    )
    _rehash(
        pair,
        "deployment-reconciliation-capture-pair-",
        "capture_pair_id",
        "capture_pair_core_sha256",
    )
    pair_raw = _canonical(pair)
    marker.update(
        capture_pair_id=pair["capture_pair_id"],
        capture_pair_raw_sha256=hashlib.sha256(pair_raw).hexdigest(),
        capture_pair_core_sha256=pair["capture_pair_core_sha256"],
    )
    _rehash(
        marker,
        "deployment-reconciliation-activation-marker-",
        "marker_id",
        "marker_core_sha256",
        "marker_path",
    )
    marker["marker_path"] = (
        f"reconciliation-blobs/activation-marker-{marker['marker_core_sha256']}.json"
    )
    marker_raw = _canonical(marker)
    payload.update(
        marker_id=marker["marker_id"],
        marker_raw_sha256=hashlib.sha256(marker_raw).hexdigest(),
        marker_core_sha256=marker["marker_core_sha256"],
    )
    _rehash(
        payload,
        "deployment-reconciliation-activation-head-",
        "activation_head_id",
        "activation_head_core_sha256",
        "activation_head_path",
    )
    with pytest.raises(ValueError, match="served proof closure mismatch"):
        DeploymentReconciliationActivationHeadV2DTO.model_validate(payload)


@pytest.mark.parametrize(("model", "filename"), SCHEMA_CASES)
def test_c2b_json_schema_matches_model(model: type, filename: str) -> None:
    schema_path = ROOT / "docs" / "schemas" / filename
    actual = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(actual)
    expected = model.model_json_schema()
    expected.update(
        {
            "$schema": actual["$schema"],
            "$id": actual["$id"],
            "title": actual["title"],
        }
    )
    assert actual == expected
