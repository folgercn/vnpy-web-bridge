from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.phase_c.adapters import (
    ExpectedVersionError,
    IdempotencyConflictError,
    UnknownOutcomeError,
    WorkflowAdapterError,
)
from app.phase_c.client import PhaseCRemoteSettings, RemotePhaseCWorkflowClient
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyEvidenceReadError,
    CustodySettings,
    create_app,
)
from app.phase_c.models import (
    ContinuousEventHeadDTO,
    ContinuousEventPublicationProjectionDTO,
    TrustedKeylessCustodyReceiptDTO,
    TrustedKeylessContinuousEventArtifactDTO,
    TrustedKeylessContinuousEventInstallContinuationDTO,
    TrustedKeylessContinuousEventUploadDTO,
)
from fastapi.testclient import TestClient

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import target_position_projection_hash
from shared.phase_c_workflow import continuous_event_v1 as event_contract
from shared.trust_contracts.v1 import canonical_json_line
from research_warehouse import continuous_event_selector as canonical_selector


CORRELATION = "continuous-event-correlation-0001"
HEAD_NONCE = "f" * 64
HEADERS = {
    "X-Phase-C-Principal": "control-api",
    "X-Phase-C-Custody-Secret": "continuous-event-control-secret",
    "X-Phase-C-Request-Nonce": HEAD_NONCE,
}
AUTHORITY_FIELDS = (
    "account_data_read",
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "network_beyond_allowlist_authorized",
    "order_authorized",
    "permit_authorized",
    "position_mutation_authorized",
    "production_authorized",
    "rpc_authorized",
    "trading_authorized",
)
STRUCTURAL_FALSE = {
    "production_allowed": False,
    "live_trading_authorized": False,
    "countable_forward": False,
    "official_forward_claimed": False,
    "dispatch_authorized": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "authority": {field: False for field in AUTHORITY_FIELDS},
}
READY_FALSE = {
    **STRUCTURAL_FALSE,
    "target_plan_authorized": False,
}


def _contract(product: str, month: str) -> str:
    exchange = "INE" if product == "sc" else "SHFE"
    return f"{exchange}.{product}26{month}"


def _final_target(
    quantities: dict[str, int],
    *,
    source_month: str = "2026-07",
    execution_day: str = "2026-07-31",
    contract_month: str = "09",
) -> dict[str, Any]:
    return {
        "schema_version": event_contract.FINAL_TARGET_SCHEMA_VERSION,
        "strategy_id": "STATIC_CORE_EQUAL",
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "c_sleeve_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "c_map_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "d_sleeve_id": "D_DONCHIAN20_EXIT10_NEUTRAL",
        "sector_map_id": "COMMODITY_FROZEN_SECTOR_MAP_V1",
        "position_manager_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
        "source_month": source_month,
        "execution_day": execution_day,
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "targets": [
            {
                "product": product,
                "sector": event_contract.SECTORS[product],
                "exact_contract": _contract(product, contract_month),
                "target_quantity": quantities[product],
                "reference_open_price": float(1000 + index),
                "multiplier": 10,
                "price_tick": 1.0,
            }
            for index, product in enumerate(event_contract.PRODUCTS)
        ],
    }


def _target_positions(
    quantities: dict[str, int], contracts: dict[str, str]
) -> dict[str, dict[str, object]]:
    positions: dict[str, dict[str, object]] = {}
    for product in event_contract.PRODUCTS:
        quantity = quantities[product]
        if not quantity:
            continue
        exchange, symbol = contracts[product].split(".", 1)
        direction = "LONG" if quantity > 0 else "SHORT"
        positions[f"{symbol}.{exchange}.{direction}.CTP.continuous"] = {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": exchange,
            "direction": direction,
            "volume": abs(quantity),
        }
    return positions


def _account_facts_v2(
    *,
    positions: dict[str, dict[str, object]],
    now: datetime,
    suffix: str,
    plan_state: str,
) -> dict[str, Any]:
    timestamp = now.isoformat().replace("+00:00", "Z")
    position_hash = event_contract.sha256_json(positions)
    snapshot_id = "snapshot-peek-" + event_contract.sha256_json(
        {"positions": positions, "suffix": suffix}
    )
    preimage = {
        "schema_version": "web_bridge_execution_account_facts_v2",
        "service": "execution-orchestrator",
        "service_version": "test-v1",
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "snapshot_id": snapshot_id,
        "generation": int(suffix),
        "observed_at": timestamp,
        "connected": True,
        "fresh": True,
        "position_snapshot_hash": position_hash,
        "positions": positions,
        "active_order_count": 0,
        "active_orders_sha256": event_contract.sha256_json({}),
        "active_orders": {},
        "status_binding": {
            "status_schema_version": "web_bridge_execution_status_v1",
            "state_version": int(suffix),
            "status_observed_at": timestamp,
            "lifecycle": "READY",
            "reconciliation": {
                "state": "RECONCILED",
                "run_id": "continuous-event-reconcile-0001",
                "last_completed_at": timestamp,
                "unknown_outcomes": 0,
                "fresh_snapshot_id": snapshot_id,
            },
            "broker": {
                "connected": True,
                "generation": int(suffix),
                "active_order_count": 0,
                "position_snapshot_hash": position_hash,
                "last_snapshot_at": timestamp,
            },
            "durable_active_orders_sha256": event_contract.sha256_json({}),
            "durable_positions_sha256": position_hash,
            "snapshot_identity_mode": "EXACT",
        },
        "execution_binding": {
            "state_version": int(suffix),
            "plan_state": plan_state,
            "send_intents": {},
            "send_intents_sha256": event_contract.sha256_json({}),
            "nonterminal_send_intent_count": 0,
        },
    }
    return {**preimage, "account_facts_sha256": event_contract.sha256_json(preimage)}


def _completion(
    *,
    phase: str,
    target_position_hash: str,
    final_target_sha256: str,
    archived_at: str,
    schema_version: int = 2,
) -> dict[str, Any]:
    completion = {
        "plan_id": f"predecessor-{phase.lower()}-plan-0001",
        "plan_hash": "a" * 64,
        "schema_version": f"web-bridge-simnow-keyless-target-plan-v{schema_version}",
        "phase": phase,
        "lineage": {
            "static_core_equal_sha256": "1" * 64,
            "position_manager_sha256": "2" * 64,
            "final_target_sha256": final_target_sha256,
        },
        "expected_after_position_hash": target_position_hash,
        "target_position_hash": target_position_hash,
        "archived_at": archived_at,
    }
    if schema_version == 3:
        completion.update(
            {
                "execution_run_id": "execution-run-issue362-0001",
                "creation_quote_proof_sha256": "8" * 64,
                "start_quote_proof_sha256": "9" * 64,
            }
        )
    return completion


def _artifact(
    *,
    trigger: str = "MONTHLY_REBALANCE",
    now: datetime | None = None,
    suffix: str = "1",
    roll_previous_quantity_delta: int = 0,
    completion_phase: str | None = None,
    completion_schema_version: int = 2,
    official_day: str = "2026-07-31",
    execution_day: str = "2026-08-03",
    source_month: str = "2026-07",
    monthly_contract_month: str = "09",
    previous_contract_month: str = "09",
    previous_ag_contract_month: str | None = None,
    current_contract_month: str = "10",
) -> dict[str, Any]:
    if now is None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
    quantities = {
        product: (1 if product == "ag" else 0) for product in event_contract.PRODUCTS
    }
    final = _final_target(
        quantities,
        source_month=source_month,
        execution_day=official_day,
        contract_month=monthly_contract_month,
    )
    final_raw = canonical_json_line(final)
    final_sha = event_contract.sha256_json(final)
    monthly_contracts = {
        product: _contract(product, monthly_contract_month)
        for product in event_contract.PRODUCTS
    }
    previous_contracts = {
        product: _contract(product, previous_contract_month)
        for product in event_contract.PRODUCTS
    }
    if previous_ag_contract_month is not None:
        previous_contracts["ag"] = _contract("ag", previous_ag_contract_month)
    current_contracts = dict(previous_contracts)
    current_contracts["ag"] = _contract("ag", current_contract_month)
    quantity_sha = event_contract._quantity_sha(quantities)
    monthly_map_sha = event_contract._map_sha(monthly_contracts)
    previous_map_sha = event_contract._map_sha(previous_contracts)
    current_map_sha = event_contract._map_sha(current_contracts)
    has_completion = trigger == "ROLL_ONLY" or completion_phase is not None
    terminal_id = "terminal-target-issue362-0001" if has_completion else None
    terminal_sha = "7" * 64 if has_completion else None
    candidate = {
        "candidate_id": "",
        "trigger_kind": trigger,
        "strategy_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "execution_day": execution_day,
        "source_month": source_month,
        "verified_daily_artifact_id": "verified-daily-" + "3" * 64,
        "verified_daily_artifact_raw_sha256": "4" * 64,
        "verified_daily_continuity_mode": (
            "LINKED_ROOT_CATALOG"
            if trigger == "ROLL_ONLY"
            else "GENESIS_STATIC_CORE_EQUAL"
        ),
        "static_core_equal_sha256": "1" * 64,
        "position_manager_sha256": "2" * 64,
        "monthly_final_target_sha256": final_sha,
        "baseline_batch_raw_sha256": "5" * 64,
        "quantity_vector_sha256": quantity_sha,
        "monthly_target_exact_contract_map_sha256": monthly_map_sha,
        "previous_exact_contract_map_sha256": previous_map_sha,
        "exact_contract_map_sha256": current_map_sha,
        "roll_preserves_integer_lots": trigger == "ROLL_ONLY",
        "predecessor_terminal_target_id": (
            terminal_id if trigger == "ROLL_ONLY" else None
        ),
        "predecessor_terminal_target_raw_sha256": (
            terminal_sha if trigger == "ROLL_ONLY" else None
        ),
        "targets": [
            {
                "product": product,
                "monthly_target_exact_contract": monthly_contracts[product],
                "previous_exact_contract": previous_contracts[product],
                "exact_contract": current_contracts[product],
                "previous_target_quantity": (
                    quantities[product]
                    + (roll_previous_quantity_delta if product == "ag" else 0)
                    if trigger == "ROLL_ONLY"
                    else None
                ),
                "target_quantity": quantities[product],
                "exact_contract_changed": (
                    previous_contracts[product] != current_contracts[product]
                ),
            }
            for product in event_contract.PRODUCTS
        ],
    }
    candidate["candidate_id"] = event_contract._candidate_id(candidate)
    candidates = [candidate]
    candidate_set_sha = event_contract.sha256_json(candidates)
    monthly_precedence = trigger == "MONTHLY_REBALANCE"
    observed = (
        ["MONTHLY_REBALANCE", "ROLL_ONLY"] if monthly_precedence else ["ROLL_ONLY"]
    )
    suppressed = ["ROLL_ONLY"] if monthly_precedence else []
    selection_core = {
        "strategy_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "execution_day": execution_day,
        "precedence_rule_id": event_contract.PRECEDENCE_RULE_ID,
        "verified_daily_artifact_id": candidate["verified_daily_artifact_id"],
        "verified_daily_artifact_raw_sha256": candidate[
            "verified_daily_artifact_raw_sha256"
        ],
        "candidate_set_sha256": candidate_set_sha,
        "candidate_ids": [candidate["candidate_id"]],
        "observed_trigger_kinds": observed,
        "selected_candidate_id": candidate["candidate_id"],
        "selected_trigger_kind": trigger,
        "suppressed_trigger_kinds": suppressed,
        "monthly_precedence_applied": monthly_precedence,
    }
    selection_sha = event_contract.sha256_json(selection_core)
    selection_id = f"continuous-selection-{selection_sha}"
    source_event = {
        "schema_version": event_contract.STRUCTURAL_EVENT_SCHEMA_VERSION,
        "event_id": "",
        "selection_id": selection_id,
        "selection_sha256": selection_sha,
        "candidate_set_sha256": candidate_set_sha,
        "candidate": candidate,
        "verification_status": event_contract.VERIFICATION_STATUS,
        "event_ready": False,
        "installable": False,
        **STRUCTURAL_FALSE,
    }
    source_event["event_id"] = event_contract._event_id(source_event)
    source_event_raw = canonical_json_line(source_event)
    selection = {
        "schema_version": event_contract.STRUCTURAL_SELECTION_SCHEMA_VERSION,
        "selection_id": selection_id,
        "selection_sha256": selection_sha,
        **selection_core,
        "candidates": candidates,
        "event_candidate_id": source_event["event_id"],
        "event_candidate_raw_sha256": event_contract.sha256_bytes(source_event_raw),
        "verification_status": event_contract.VERIFICATION_STATUS,
        "event_ready": False,
        "installable": False,
        **STRUCTURAL_FALSE,
    }
    selection_raw = canonical_json_line(selection)
    desired_positions = _target_positions(quantities, current_contracts)
    desired_hash = target_position_projection_hash(
        desired_positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    current_positions = (
        _target_positions(quantities, previous_contracts)
        if trigger == "ROLL_ONLY"
        else (desired_positions if has_completion else {})
    )
    current_hash = target_position_projection_hash(
        current_positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    verified_at = now.isoformat().replace("+00:00", "Z")
    phase = completion_phase or ("OPEN" if trigger == "ROLL_ONLY" else None)
    completion = (
        _completion(
            phase=str(phase),
            target_position_hash=current_hash,
            final_target_sha256=final_sha,
            archived_at=verified_at,
            schema_version=completion_schema_version,
        )
        if has_completion
        else None
    )
    completion_raw = canonical_json_line(completion) if completion is not None else None
    predecessor = {
        "mode": "COMPLETION" if has_completion else "GENESIS_FLAT",
        "completion_raw": completion_raw.decode()
        if completion_raw is not None
        else None,
        "completion_raw_sha256": (
            event_contract.sha256_bytes(completion_raw)
            if completion_raw is not None
            else None
        ),
        "completion_plan_id": completion["plan_id"] if completion is not None else None,
        "completion_plan_hash": completion["plan_hash"]
        if completion is not None
        else None,
        "completion_phase": completion["phase"] if completion is not None else None,
        "completion_target_position_hash": (
            completion["target_position_hash"] if completion is not None else None
        ),
        "terminal_target_id": terminal_id,
        "terminal_target_raw_sha256": terminal_sha,
        "static_core_equal_sha256": "1" * 64 if has_completion else None,
        "position_manager_sha256": "2" * 64 if has_completion else None,
        "final_target_sha256": final_sha if has_completion else None,
    }
    account_facts = _account_facts_v2(
        positions=current_positions,
        now=now,
        suffix=suffix,
        plan_state="TERMINAL" if has_completion else "IDLE",
    )
    account_facts_raw = canonical_json_line(account_facts)
    payload = {
        "schema_version": event_contract.CONTINUOUS_EVENT_SCHEMA_VERSION,
        "event_id": source_event["event_id"],
        "source_event_raw": source_event_raw.decode(),
        "source_event_raw_sha256": event_contract.sha256_bytes(source_event_raw),
        "selection_id": selection_id,
        "selection_sha256": selection_sha,
        "selection_raw": selection_raw.decode(),
        "selection_raw_sha256": event_contract.sha256_bytes(selection_raw),
        "candidate_id": candidate["candidate_id"],
        "trigger_kind": trigger,
        "strategy_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "precedence_rule_id": event_contract.PRECEDENCE_RULE_ID,
        "monthly_precedence_applied": monthly_precedence,
        "verified_at": verified_at,
        "monthly": {
            "final_target_raw": final_raw.decode(),
            "final_target_raw_sha256": event_contract.sha256_bytes(final_raw),
            "final_target_sha256": final_sha,
            "static_core_equal_sha256": "1" * 64,
            "position_manager_sha256": "2" * 64,
            "baseline_batch_raw_sha256": "5" * 64,
            "source_month": source_month,
            "execution_day": official_day,
            "quantity_vector_sha256": quantity_sha,
            "monthly_exact_contract_map_sha256": monthly_map_sha,
        },
        "daily": {
            "artifact_id": candidate["verified_daily_artifact_id"],
            "artifact_raw_sha256": candidate["verified_daily_artifact_raw_sha256"],
            "official_day": official_day,
            "execution_day": execution_day,
            "continuity_mode": candidate["verified_daily_continuity_mode"],
            "previous_exact_contract_map_sha256": previous_map_sha,
            "exact_contract_map_sha256": current_map_sha,
            "catalog_receipt_raw_sha256": "b" * 64,
            "catalog_artifact_raw_sha256": "c" * 64,
            "operator_state_raw_sha256": "d" * 64,
            "operator_manifest_sequence": 42,
            "manifest_genesis_seal_sha256": "e" * 64,
            "manifest_head_seal_sha256": "f" * 64,
            "manifest_head_commit_seal_sha256": "0" * 64,
            "commit_anchor_ledger_raw_sha256": "6" * 64,
            "catalog_last_trade_day": execution_day,
        },
        "desired_target": {
            "target_position_hash": desired_hash,
            "quantity_vector_sha256": quantity_sha,
            "exact_contract_map_sha256": current_map_sha,
        },
        "account_facts": {
            "account_facts_raw": account_facts_raw.decode(),
            "account_facts_raw_sha256": event_contract.sha256_bytes(account_facts_raw),
            "snapshot_id": account_facts["snapshot_id"],
            "account_facts_sha256": account_facts["account_facts_sha256"],
            "observed_at": account_facts["observed_at"],
            "state_version": account_facts["execution_binding"]["state_version"],
            "position_snapshot_hash": account_facts["position_snapshot_hash"],
            "current_target_position_hash": current_hash,
            "active_order_count": account_facts["active_order_count"],
            "active_orders_sha256": account_facts["active_orders_sha256"],
            "lifecycle": account_facts["status_binding"]["lifecycle"],
            "reconciliation_state": account_facts["status_binding"]["reconciliation"][
                "state"
            ],
            "unknown_outcomes": account_facts["status_binding"]["reconciliation"][
                "unknown_outcomes"
            ],
            "plan_state": account_facts["execution_binding"]["plan_state"],
            "nonterminal_send_intent_count": account_facts["execution_binding"][
                "nonterminal_send_intent_count"
            ],
        },
        "predecessor": predecessor,
        "event_ready": True,
        "installable": True,
        **READY_FALSE,
    }
    return new_artifact_envelope(
        artifact_type=event_contract.CONTINUOUS_EVENT_ARTIFACT_TYPE,
        trust_domain=event_contract.CONTINUOUS_EVENT_TRUST_DOMAIN,
        producer_id="static-core-equal-continuous-event-installer",
        producer_version="v1",
        schema_ref=event_contract.CONTINUOUS_EVENT_SCHEMA_VERSION,
        payload=payload,
        generated_at=verified_at,
        scope=event_contract.CONTINUOUS_EVENT_SCOPE,
        predecessor_refs=[],
        lineage=[],
    )


def _service(
    tmp_path: Path,
    *,
    allowed_principals: frozenset[str] = frozenset({"control-api"}),
) -> ArtifactCustodyService:
    return ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            HEADERS["X-Phase-C-Custody-Secret"],
            allowed_principals,
            {},
            "continuous-event-execution-read-secret",
            None,
            True,
        )
    )


def _reenvelope(payload: dict[str, Any]) -> dict[str, Any]:
    return new_artifact_envelope(
        artifact_type=event_contract.CONTINUOUS_EVENT_ARTIFACT_TYPE,
        trust_domain=event_contract.CONTINUOUS_EVENT_TRUST_DOMAIN,
        producer_id="static-core-equal-continuous-event-installer",
        producer_version="v1",
        schema_ref=event_contract.CONTINUOUS_EVENT_SCHEMA_VERSION,
        payload=payload,
        generated_at=payload["verified_at"],
        scope=event_contract.CONTINUOUS_EVENT_SCOPE,
        predecessor_refs=[],
        lineage=[],
    )


def _rehash_structural_candidate(
    payload: dict[str, Any], candidate: dict[str, Any]
) -> None:
    selection = json.loads(payload["selection_raw"])
    event = json.loads(payload["source_event_raw"])
    candidate["candidate_id"] = ""
    candidate["candidate_id"] = event_contract._candidate_id(candidate)
    candidates = [candidate]
    candidate_set_sha = event_contract.sha256_json(candidates)
    selection["candidates"] = candidates
    selection["candidate_set_sha256"] = candidate_set_sha
    selection["candidate_ids"] = [candidate["candidate_id"]]
    selection["selected_candidate_id"] = candidate["candidate_id"]
    selection_core = {
        key: selection[key]
        for key in (
            "strategy_id",
            "execution_lane",
            "execution_day",
            "precedence_rule_id",
            "verified_daily_artifact_id",
            "verified_daily_artifact_raw_sha256",
            "candidate_set_sha256",
            "candidate_ids",
            "observed_trigger_kinds",
            "selected_candidate_id",
            "selected_trigger_kind",
            "suppressed_trigger_kinds",
            "monthly_precedence_applied",
        )
    }
    selection_sha = event_contract.sha256_json(selection_core)
    selection_id = f"continuous-selection-{selection_sha}"
    selection["selection_id"] = selection_id
    selection["selection_sha256"] = selection_sha
    event["selection_id"] = selection_id
    event["selection_sha256"] = selection_sha
    event["candidate_set_sha256"] = candidate_set_sha
    event["candidate"] = candidate
    event["event_id"] = ""
    event["event_id"] = event_contract._event_id(event)
    event_raw = canonical_json_line(event)
    selection["event_candidate_id"] = event["event_id"]
    selection["event_candidate_raw_sha256"] = event_contract.sha256_bytes(event_raw)
    selection_raw = canonical_json_line(selection)
    payload.update(
        event_id=event["event_id"],
        source_event_raw=event_raw.decode(),
        source_event_raw_sha256=event_contract.sha256_bytes(event_raw),
        selection_id=selection_id,
        selection_sha256=selection_sha,
        selection_raw=selection_raw.decode(),
        selection_raw_sha256=event_contract.sha256_bytes(selection_raw),
        candidate_id=candidate["candidate_id"],
    )


def _replace_monthly_final_target(
    payload: dict[str, Any], final_target: dict[str, Any]
) -> dict[str, Any]:
    final_raw = canonical_json_line(final_target)
    final_sha = event_contract.sha256_json(final_target)
    monthly = payload["monthly"]
    monthly.update(
        final_target_raw=final_raw.decode(),
        final_target_raw_sha256=event_contract.sha256_bytes(final_raw),
        final_target_sha256=final_sha,
        execution_day=final_target["execution_day"],
    )
    candidate = json.loads(payload["source_event_raw"])["candidate"]
    candidate["monthly_final_target_sha256"] = final_sha
    _rehash_structural_candidate(payload, candidate)
    return candidate


def _tree(root: Path) -> dict[str, bytes | None]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): None if path.is_dir() else path.read_bytes()
        for path in sorted(root.rglob("*"))
    }


def _upload(artifact: dict[str, Any], *, version: int = 0, key: str | None = None):
    return TrustedKeylessContinuousEventUploadDTO(
        idempotency_key=key or artifact["payload"]["event_id"],
        expected_custody_version=version,
        correlation_id=CORRELATION,
        artifact=artifact,
    )


def _publish_only(
    service: ArtifactCustodyService,
    artifact: dict[str, Any],
    *,
    key: str | None = None,
    version: int = 0,
) -> dict[str, Any]:
    with service._custody() as custody:
        return custody.publish(
            artifact,
            actor_id="control-api",
            idempotency_key=key or artifact["payload"]["event_id"],
            correlation_id=CORRELATION,
            expected_version=version,
        )


def _publish_unrelated_artifact(
    service: ArtifactCustodyService,
    *,
    version: int,
) -> None:
    artifact = new_artifact_envelope(
        artifact_type="map-acceptance",
        trust_domain="map_acceptance",
        producer_id="unrelated-control-artifact",
        producer_version="v1",
        schema_ref="phase-c-map-acceptance-v1",
        payload={"unrelated": True},
        generated_at=datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        scope={},
        predecessor_refs=[],
        lineage=[],
    )
    with service._custody() as custody:
        custody.publish(
            artifact,
            actor_id="control-api",
            idempotency_key="unrelated-artifact-0001",
            correlation_id="unrelated-correlation-0001",
            expected_version=version,
        )


def _continuation(projection, artifact: dict[str, Any], **changes: Any):
    value = {
        "idempotency_key": projection.idempotency_key,
        "correlation_id": projection.correlation_id,
        "publish_receipt_id": projection.publish_receipt_id,
        "publish_receipt_sha256": projection.publish_receipt_sha256,
        "publish_expected_custody_version": (
            projection.publish_expected_custody_version
        ),
        "publish_resulting_custody_version": (
            projection.publish_resulting_custody_version
        ),
        "artifact": artifact,
    }
    value.update(changes)
    return TrustedKeylessContinuousEventInstallContinuationDTO.model_validate(value)


def test_contract_accepts_monthly_and_roll_but_rejects_authority_and_splices() -> None:
    monthly = _artifact()
    roll = _artifact(trigger="ROLL_ONLY")
    assert (
        event_contract.validate_simnow_continuous_event_v1(monthly["payload"])[
            "event_ready"
        ]
        is True
    )
    assert (
        event_contract.validate_simnow_continuous_event_v1(roll["payload"])[
            "trigger_kind"
        ]
        == "ROLL_ONLY"
    )

    authoritative = deepcopy(monthly["payload"])
    authoritative["target_plan_authorized"] = True
    with pytest.raises(event_contract.ContinuousEventContractError, match="boundary"):
        event_contract.validate_simnow_continuous_event_v1(authoritative)

    cross_spliced = deepcopy(monthly["payload"])
    cross_spliced["daily"]["artifact_raw_sha256"] = "f" * 64
    with pytest.raises(event_contract.ContinuousEventContractError, match="daily"):
        event_contract.validate_simnow_continuous_event_v1(cross_spliced)

    selection_day_splice = deepcopy(monthly["payload"])
    selection = json.loads(selection_day_splice["selection_raw"])
    event = json.loads(selection_day_splice["source_event_raw"])
    selection["execution_day"] = "2099-12-31"
    selection_core = {
        key: selection[key]
        for key in (
            "strategy_id",
            "execution_lane",
            "execution_day",
            "precedence_rule_id",
            "verified_daily_artifact_id",
            "verified_daily_artifact_raw_sha256",
            "candidate_set_sha256",
            "candidate_ids",
            "observed_trigger_kinds",
            "selected_candidate_id",
            "selected_trigger_kind",
            "suppressed_trigger_kinds",
            "monthly_precedence_applied",
        )
    }
    selection_sha = event_contract.sha256_json(selection_core)
    selection_id = f"continuous-selection-{selection_sha}"
    selection["selection_id"] = selection_id
    selection["selection_sha256"] = selection_sha
    event["selection_id"] = selection_id
    event["selection_sha256"] = selection_sha
    event["event_id"] = ""
    event["event_id"] = event_contract._event_id(event)
    event_raw = canonical_json_line(event)
    selection["event_candidate_id"] = event["event_id"]
    selection["event_candidate_raw_sha256"] = event_contract.sha256_bytes(event_raw)
    selection_raw = canonical_json_line(selection)
    selection_day_splice.update(
        event_id=event["event_id"],
        source_event_raw=event_raw.decode(),
        source_event_raw_sha256=event_contract.sha256_bytes(event_raw),
        selection_id=selection_id,
        selection_sha256=selection_sha,
        selection_raw=selection_raw.decode(),
        selection_raw_sha256=event_contract.sha256_bytes(selection_raw),
    )
    fully_rehashed = _reenvelope(selection_day_splice)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="selection identity",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    final_day_splice = deepcopy(monthly["payload"])
    final_target = json.loads(final_day_splice["monthly"]["final_target_raw"])
    final_target["execution_day"] = "not-a-day"
    _replace_monthly_final_target(final_day_splice, final_target)
    fully_rehashed = _reenvelope(final_day_splice)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="monthly final target execution day",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    monthly_official_splice = deepcopy(monthly["payload"])
    final_target = json.loads(monthly_official_splice["monthly"]["final_target_raw"])
    final_target["execution_day"] = "2026-07-30"
    _replace_monthly_final_target(monthly_official_splice, final_target)
    fully_rehashed = _reenvelope(monthly_official_splice)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="official execution-day ordering",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    invalid_official_day = deepcopy(monthly["payload"])
    invalid_official_day["daily"]["official_day"] = "2026-7-31"
    fully_rehashed = _reenvelope(invalid_official_day)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="daily official day",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    invalid_official_order = deepcopy(monthly["payload"])
    invalid_official_order["daily"]["official_day"] = "2026-08-03"
    fully_rehashed = _reenvelope(invalid_official_order)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="official execution-day ordering",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    uppercase_contract_splice = deepcopy(monthly["payload"])
    final_target = json.loads(uppercase_contract_splice["monthly"]["final_target_raw"])
    final_target["targets"][0]["exact_contract"] = "SHFE.AG2609"
    candidate = _replace_monthly_final_target(uppercase_contract_splice, final_target)
    candidate["targets"][0]["monthly_target_exact_contract"] = "SHFE.AG2609"
    monthly_contracts = {
        row["product"]: row["monthly_target_exact_contract"]
        for row in candidate["targets"]
    }
    monthly_map_sha = event_contract._map_sha(monthly_contracts)
    candidate["monthly_target_exact_contract_map_sha256"] = monthly_map_sha
    uppercase_contract_splice["monthly"]["monthly_exact_contract_map_sha256"] = (
        monthly_map_sha
    )
    _rehash_structural_candidate(uppercase_contract_splice, candidate)
    fully_rehashed = _reenvelope(uppercase_contract_splice)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="exact contract is outside frozen universe",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    daily_id_splices: list[dict[str, Any]] = []
    for invalid_daily_id in ("verified:daily:issue362:0001", "d" * 129):
        daily_id_splice = deepcopy(monthly["payload"])
        selection = json.loads(daily_id_splice["selection_raw"])
        selection["verified_daily_artifact_id"] = invalid_daily_id
        daily_id_splice["selection_raw"] = canonical_json_line(selection).decode()
        candidate = json.loads(daily_id_splice["source_event_raw"])["candidate"]
        candidate["verified_daily_artifact_id"] = invalid_daily_id
        daily_id_splice["daily"]["artifact_id"] = invalid_daily_id
        _rehash_structural_candidate(daily_id_splice, candidate)
        fully_rehashed = _reenvelope(daily_id_splice)
        with pytest.raises(
            event_contract.ContinuousEventContractError,
            match="daily.*ID",
        ):
            event_contract.validate_simnow_continuous_event_v1(
                fully_rehashed["payload"]
            )
        daily_id_splices.append(daily_id_splice)

    terminal_id_splice = deepcopy(roll["payload"])
    candidate = json.loads(terminal_id_splice["source_event_raw"])["candidate"]
    candidate["predecessor_terminal_target_id"] = "terminal:target:issue362:0001"
    terminal_id_splice["predecessor"]["terminal_target_id"] = (
        "terminal:target:issue362:0001"
    )
    _rehash_structural_candidate(terminal_id_splice, candidate)
    fully_rehashed = _reenvelope(terminal_id_splice)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="terminal target ID",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    for selector_splice in (
        selection_day_splice,
        uppercase_contract_splice,
        *daily_id_splices,
        terminal_id_splice,
    ):
        with pytest.raises(canonical_selector.ContinuousEventSelectorError):
            canonical_selector.validate_continuous_event_selection(
                selector_splice["selection_raw"].encode("utf-8")
            )
        with pytest.raises(event_contract.ContinuousEventContractError):
            event_contract.validate_simnow_continuous_event_v1(selector_splice)

    stale = deepcopy(monthly["payload"])
    stale["account_facts"]["observed_at"] = (
        (datetime.now(timezone.utc) - timedelta(seconds=61))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    with pytest.raises(event_contract.ContinuousEventContractError, match="fresh"):
        event_contract.validate_simnow_continuous_event_v1(stale)

    incoherent_roll = _artifact(
        trigger="ROLL_ONLY",
        roll_previous_quantity_delta=1,
    )
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="quantity continuity",
    ):
        event_contract.validate_simnow_continuous_event_v1(incoherent_roll["payload"])

    desired_rehash = deepcopy(monthly["payload"])
    desired_rehash["desired_target"]["target_position_hash"] = "f" * 64
    fully_rehashed = _reenvelope(desired_rehash)
    with pytest.raises(
        event_contract.ContinuousEventContractError, match="desired target"
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])

    opaque_facts_rehash = deepcopy(monthly["payload"])
    opaque_facts_rehash["account_facts"]["account_facts_sha256"] = "e" * 64
    fully_rehashed = _reenvelope(opaque_facts_rehash)
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="account facts",
    ):
        event_contract.validate_simnow_continuous_event_v1(fully_rehashed["payload"])


def test_terminal_close_completion_is_accepted_but_close_boundary_is_rejected() -> None:
    terminal_close = _artifact(completion_phase="CLOSE")
    accepted = event_contract.validate_simnow_continuous_event_v1(
        terminal_close["payload"]
    )
    assert accepted["predecessor"]["completion_phase"] == "CLOSE"
    assert (
        accepted["predecessor"]["completion_target_position_hash"]
        == accepted["desired_target"]["target_position_hash"]
        == accepted["account_facts"]["current_target_position_hash"]
    )

    boundary_close = _artifact(trigger="ROLL_ONLY", completion_phase="CLOSE")
    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="terminal/current",
    ):
        event_contract.validate_simnow_continuous_event_v1(boundary_close["payload"])


def test_target_plan_v3_terminal_completion_is_accepted() -> None:
    artifact = _artifact(
        completion_phase="OPEN",
        completion_schema_version=3,
    )

    accepted = event_contract.validate_simnow_continuous_event_v1(artifact["payload"])

    completion = json.loads(accepted["predecessor"]["completion_raw"])
    assert completion["schema_version"] == "web-bridge-simnow-keyless-target-plan-v3"
    assert completion["execution_run_id"] == "execution-run-issue362-0001"


def test_target_plan_v3_completion_requires_exact_quote_proof_fields() -> None:
    artifact = _artifact(
        completion_phase="OPEN",
        completion_schema_version=3,
    )
    payload = artifact["payload"]
    completion = json.loads(payload["predecessor"]["completion_raw"])
    completion.pop("start_quote_proof_sha256")
    completion_raw = canonical_json_line(completion)
    payload["predecessor"]["completion_raw"] = completion_raw.decode()
    payload["predecessor"]["completion_raw_sha256"] = event_contract.sha256_bytes(
        completion_raw
    )

    with pytest.raises(
        event_contract.ContinuousEventContractError,
        match="completion fields are not exact",
    ):
        event_contract.validate_simnow_continuous_event_v1(payload)


def test_same_structural_event_cannot_install_under_an_alternate_key(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _artifact()
    receipt = service.publish_trusted_keyless_continuous_event(
        _upload(first), principal="control-api"
    )
    after = _tree(service.settings.root)
    refreshed = _artifact(
        now=datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1),
        suffix="2",
    )
    assert refreshed["payload"]["event_id"] == first["payload"]["event_id"]

    with pytest.raises(IdempotencyConflictError):
        service.publish_trusted_keyless_continuous_event(
            _upload(
                refreshed,
                version=receipt.custody_version,
                key="continuous-event-alternate-issue362-0001",
            ),
            principal="control-api",
        )
    assert _tree(service.settings.root) == after


def test_publish_install_exact_retry_readback_and_execution_raw_denial(
    tmp_path: Path,
) -> None:
    service = _service(
        tmp_path,
        allowed_principals=frozenset({"control-api", "phase-c-execution"}),
    )
    artifact = _artifact()
    request = _upload(artifact)
    first = service.publish_trusted_keyless_continuous_event(
        request, principal="control-api"
    )
    second = service.publish_trusted_keyless_continuous_event(
        request, principal="control-api"
    )
    assert first == second
    assert first.artifact_type == "simnow-continuous-event"
    assert first.target_plan_authorized is False
    assert first.daily_official_day == "2026-07-31"
    with pytest.raises(ValueError):
        TrustedKeylessCustodyReceiptDTO.model_validate(first.model_dump(mode="json"))
    assert service.current_version().version == 2

    key = artifact["payload"]["event_id"]
    projection = service.continuous_event_publication(key)
    assert projection.state == "INSTALLED"
    assert projection.event_id == artifact["payload"]["event_id"]
    assert projection.daily_official_day == "2026-07-31"
    assert projection.target_plan_authorized is False
    installed = service.installed_continuous_event(key)
    assert installed is not None
    assert installed.artifact == artifact
    foreign_event_id = "continuous-event-" + "9" * 64
    projection_splice = projection.model_dump(mode="json")
    projection_splice["event_id"] = foreign_event_id
    with pytest.raises(ValueError, match="event ID"):
        ContinuousEventPublicationProjectionDTO.model_validate(projection_splice)
    projection_day_splice = projection.model_dump(mode="json")
    projection_day_splice["daily_official_day"] = "2026-99-99"
    with pytest.raises(ValueError, match="daily official day"):
        ContinuousEventPublicationProjectionDTO.model_validate(projection_day_splice)
    installed_splice = installed.model_dump(mode="json")
    installed_splice["idempotency_key"] = foreign_event_id
    with pytest.raises(ValueError, match="artifact identity"):
        TrustedKeylessContinuousEventArtifactDTO.model_validate(installed_splice)
    generic = service.receipt_by_idempotency(key)
    assert generic == first

    with TestClient(create_app(service)) as client:
        execution = client.get(
            f"/internal/v1/artifacts/{artifact['artifact_id']}",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("continuous-event-execution-read-secret"),
            },
        )
        execution_event_read = client.get(
            f"/internal/v1/continuous-events/by-idempotency/{key}",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("continuous-event-execution-read-secret"),
            },
        )
        execution_target_plan_receipt = client.get(
            f"/internal/v1/target-plan-receipts/{first.receipt_id}",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("continuous-event-execution-read-secret"),
            },
        )
        execution_generic_receipt = client.get(
            f"/internal/v1/receipts/{first.receipt_id}",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("continuous-event-execution-read-secret"),
            },
        )
        execution_generic_idempotency = client.get(
            f"/internal/v1/receipts-by-idempotency/{key}",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("continuous-event-execution-read-secret"),
            },
        )
    assert execution.status_code == 503
    assert execution_event_read.status_code == 401
    assert execution_target_plan_receipt.status_code == 503
    assert execution_target_plan_receipt.json()["detail"]["retryable"] is False
    assert execution_generic_receipt.status_code == 404
    assert execution_generic_idempotency.status_code == 404


def test_absent_projection_is_authenticated_zero_write(tmp_path: Path) -> None:
    service = _service(tmp_path)
    root = service.settings.root
    path = (
        "/internal/v1/continuous-event-publications/by-idempotency/"
        "continuous-event-missing-0001"
    )
    with TestClient(create_app(service)) as client:
        assert client.get(path).status_code == 401
        response = client.get(path, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["state"] == "NOT_PUBLISHED"
    assert response.json()["target_plan_authorized"] is False
    assert not root.exists()


def test_event_routes_require_control_principal_and_initial_facts_are_fresh(
    tmp_path: Path,
) -> None:
    service = _service(
        tmp_path,
        allowed_principals=frozenset({"control-api", "phase-c-execution"}),
    )
    artifact = _artifact()
    phase_c_execution_headers = {
        "X-Phase-C-Principal": "phase-c-execution",
        "X-Phase-C-Custody-Secret": HEADERS["X-Phase-C-Custody-Secret"],
    }
    with TestClient(create_app(service)) as client:
        denied = client.post(
            "/internal/v1/publish-keyless-simnow-continuous-event",
            headers=phase_c_execution_headers,
            json=_upload(artifact).model_dump(mode="json"),
        )
    assert denied.status_code == 401
    assert not service.settings.root.exists()

    stale = _artifact(
        now=datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=61)
    )
    with pytest.raises(WorkflowAdapterError) as raised:
        service.publish_trusted_keyless_continuous_event(
            _upload(stale),
            principal="control-api",
        )
    assert raised.value.code == "PHASE_C_CONTINUOUS_EVENT_FACTS_STALE"
    assert raised.value.retryable is False
    assert not service.settings.root.exists()


def test_publish_crash_install_only_and_exact_retry_are_create_only(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    before_lookup = _tree(service.settings.root)
    projection = service.continuous_event_publication(artifact["payload"]["event_id"])
    assert projection.state == "PUBLISHED_NOT_INSTALLED"
    projection_splice = projection.model_dump(mode="json")
    projection_splice["event_id"] = "continuous-event-" + "6" * 64
    with pytest.raises(ValueError, match="event ID"):
        ContinuousEventPublicationProjectionDTO.model_validate(projection_splice)
    assert _tree(service.settings.root) == before_lookup
    request = _continuation(projection, artifact)
    first = service.install_published_trusted_keyless_continuous_event(
        request,
        principal="control-api",
    )
    after = _tree(service.settings.root)
    second = service.install_published_trusted_keyless_continuous_event(
        request,
        principal="control-api",
    )
    assert first == second
    assert _tree(service.settings.root) == after
    assert service.current_version().version == 2


def test_install_only_rejects_cross_splice_and_version_drift(tmp_path: Path) -> None:
    service = _service(tmp_path)
    first_artifact = _artifact()
    _publish_only(service, first_artifact)
    projection = service.continuous_event_publication(
        first_artifact["payload"]["event_id"]
    )
    foreign = _artifact(
        trigger="ROLL_ONLY",
        now=datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1),
        suffix="2",
    )
    with pytest.raises(IdempotencyConflictError):
        service.install_published_trusted_keyless_continuous_event(
            _continuation(projection, foreign),
            principal="control-api",
        )
    _publish_only(
        service,
        foreign,
        key=foreign["payload"]["event_id"],
        version=1,
    )
    before = _tree(service.settings.root)
    with pytest.raises(ExpectedVersionError):
        service.install_published_trusted_keyless_continuous_event(
            _continuation(projection, first_artifact),
            principal="control-api",
        )
    assert _tree(service.settings.root) == before


def test_remote_client_closes_event_response_and_malformed_2xx_is_unknown(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    request = _upload(artifact)

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url.path == (
            "/internal/v1/publish-keyless-simnow-continuous-event"
        )
        return httpx.Response(200, json={"malformed": True})

    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings(
            "http://custody",
            "http://execution",
            "secret",
            "execution-secret",
        ),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(UnknownOutcomeError) as raised:
        client.install_trusted_keyless_continuous_event(request)
    assert raised.value.detail == {
        "query_path": (
            "/internal/v1/continuous-event-publications/by-idempotency/"
            + request.idempotency_key
        ),
        "query_same_intent_only": True,
    }

    service = _service(tmp_path)
    receipt = service.publish_trusted_keyless_continuous_event(
        request, principal="control-api"
    ).model_dump(mode="json")
    official_day_splice = deepcopy(receipt)
    official_day_splice["daily_official_day"] = "2026-07-30"

    def official_day_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=official_day_splice)

    official_day_client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings(
            "http://custody",
            "http://execution",
            "secret",
            "execution-secret",
        ),
        transport=httpx.MockTransport(official_day_handler),
    )
    with pytest.raises(UnknownOutcomeError):
        official_day_client.install_trusted_keyless_continuous_event(request)

    foreign_key = "continuous-event-" + "8" * 64
    foreign_request = _upload(artifact, key=foreign_key)
    receipt["idempotency_key"] = f"install-{foreign_key}"

    def cross_event_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=receipt)

    cross_event_client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings(
            "http://custody",
            "http://execution",
            "secret",
            "execution-secret",
        ),
        transport=httpx.MockTransport(cross_event_handler),
    )
    with pytest.raises(UnknownOutcomeError) as raised:
        cross_event_client.install_trusted_keyless_continuous_event(foreign_request)
    assert raised.value.detail == {
        "query_path": (
            "/internal/v1/continuous-event-publications/by-idempotency/" + foreign_key
        ),
        "query_same_intent_only": True,
    }


def test_remote_publication_and_read_reject_foreign_idempotency(
    tmp_path: Path,
) -> None:
    projection = {
        "schema_version": "phase-c-continuous-event-publication-v1",
        "state": "NOT_PUBLISHED",
        "idempotency_key": "continuous-event-foreign-0001",
        "install_idempotency_key": "install-continuous-event-foreign-0001",
        "observed_custody_version": 0,
        "custody_state_owner": "artifact-custody",
        **READY_FALSE,
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=projection)

    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings(
            "http://custody",
            "http://execution",
            "secret",
            "execution-secret",
        ),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(WorkflowAdapterError) as raised:
        client.continuous_event_publication(
            "continuous-event-expected-foreign-binding-0001"
        )
    assert raised.value.retryable is False
    assert raised.value.code == "PHASE_C_RESPONSE_BINDING_INVALID"

    service = _service(tmp_path)
    artifact = _artifact()
    service.publish_trusted_keyless_continuous_event(
        _upload(artifact), principal="control-api"
    )
    key = artifact["payload"]["event_id"]
    event_splice = service.continuous_event_publication(key).model_dump(mode="json")
    event_splice["event_id"] = "continuous-event-" + "7" * 64

    def event_splice_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=event_splice)

    event_splice_client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings(
            "http://custody",
            "http://execution",
            "secret",
            "execution-secret",
        ),
        transport=httpx.MockTransport(event_splice_handler),
    )
    with pytest.raises(WorkflowAdapterError) as raised:
        event_splice_client.continuous_event_publication(key)
    assert raised.value.retryable is False
    assert raised.value.code == "PHASE_C_RESPONSE_BINDING_INVALID"


def _next_roll_artifact(*, now: datetime, previous_month: str = "10"):
    return _artifact(
        trigger="ROLL_ONLY",
        now=now,
        suffix="2",
        official_day="2026-08-28",
        execution_day="2026-08-31",
        source_month="2026-08",
        previous_ag_contract_month=previous_month,
        current_contract_month="11",
    )


def test_continuous_event_head_absent_is_control_only_zero_write(
    tmp_path: Path,
) -> None:
    service = _service(
        tmp_path,
        allowed_principals=frozenset({"control-api", "phase-c-execution"}),
    )
    root = service.settings.root
    assert service.continuous_event_head(request_nonce=HEAD_NONCE).state == "NO_EVENT"
    assert not root.exists()
    with TestClient(create_app(service)) as client:
        assert client.get("/internal/v1/continuous-event-head").status_code == 401
        missing_nonce = client.get(
            "/internal/v1/continuous-event-head",
            headers={
                "X-Phase-C-Principal": "control-api",
                "X-Phase-C-Custody-Secret": HEADERS["X-Phase-C-Custody-Secret"],
            },
        )
        invalid_nonce = client.get(
            "/internal/v1/continuous-event-head",
            headers={**HEADERS, "X-Phase-C-Request-Nonce": "not-a-valid-nonce"},
        )
        phase_c_execution = client.get(
            "/internal/v1/continuous-event-head",
            headers={
                "X-Phase-C-Principal": "phase-c-execution",
                "X-Phase-C-Custody-Secret": HEADERS["X-Phase-C-Custody-Secret"],
            },
        )
        execution = client.get(
            "/internal/v1/continuous-event-head",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("continuous-event-execution-read-secret"),
            },
        )
        accepted = client.get("/internal/v1/continuous-event-head", headers=HEADERS)
    assert phase_c_execution.status_code == 401
    assert execution.status_code == 401
    assert missing_nonce.status_code == 422
    assert missing_nonce.json()["detail"]["code"] == (
        "PHASE_C_RESPONSE_BINDING_INVALID"
    )
    assert invalid_nonce.status_code == 422
    assert accepted.status_code == 200
    assert accepted.json()["state"] == "NO_EVENT"
    assert accepted.json()["request_nonce"] == HEAD_NONCE
    assert accepted.json()["target_plan_authorized"] is False
    assert not root.exists()


def test_continuous_event_head_rejects_incomplete_existing_custody_root(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    root = service.settings.root
    root.mkdir(mode=0o700)
    (root / ".writer.lock").touch(mode=0o600)
    for name in (".tmp", "artifacts", "epochs", "receipts"):
        (root / name).mkdir(mode=0o700)

    with pytest.raises(CustodyEvidenceReadError, match="evidence is invalid"):
        service.continuous_event_head(request_nonce=HEAD_NONCE)


def test_continuous_event_head_folds_publish_install_and_returns_exact_raw(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    before = _tree(service.settings.root)

    published = service.continuous_event_head(request_nonce=HEAD_NONCE)

    assert published.state == "PUBLISHED_NOT_INSTALLED"
    assert published.observed_custody_version == 1
    assert published.publication is not None
    assert published.publication.event_id == artifact["payload"]["event_id"]
    assert published.current_event is not None
    assert published.current_event.artifact == artifact
    assert published.ledger_record_sha256 is not None
    assert _tree(service.settings.root) == before

    request = _continuation(published.publication, artifact)
    service.install_published_trusted_keyless_continuous_event(
        request,
        principal="control-api",
    )
    after_install = _tree(service.settings.root)
    installed = service.continuous_event_head(request_nonce=HEAD_NONCE)
    assert installed.state == "INSTALLED"
    assert installed.observed_custody_version == 2
    assert installed.publication is not None
    assert installed.publication.install_resulting_custody_version == 2
    assert _tree(service.settings.root) == after_install

    service.install_published_trusted_keyless_continuous_event(
        request,
        principal="control-api",
    )
    assert _tree(service.settings.root) == after_install
    assert service.continuous_event_head(request_nonce=HEAD_NONCE) == installed


def test_continuous_event_head_accepts_strict_cross_day_map_chain(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _artifact()
    service.publish_trusted_keyless_continuous_event(
        _upload(first), principal="control-api"
    )
    second = _next_roll_artifact(
        now=datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
    )
    service.publish_trusted_keyless_continuous_event(
        _upload(second, version=2), principal="control-api"
    )

    head = service.continuous_event_head(request_nonce=HEAD_NONCE)

    assert head.state == "INSTALLED"
    assert head.current_event is not None
    assert head.current_event.idempotency_key == second["payload"]["event_id"]
    assert head.current_event.artifact == second
    assert head.observed_custody_version == 4


def test_continuous_event_head_rejects_unfinished_before_unrelated_ledger_tail(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    _publish_only(service, _artifact())
    _publish_unrelated_artifact(service, version=1)

    with pytest.raises(CustodyEvidenceReadError, match="custody ledger tail"):
        service.continuous_event_head(request_nonce=HEAD_NONCE)


def test_continuous_event_head_rejects_multiple_unfinished_events(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _artifact()
    second = _next_roll_artifact(
        now=datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
    )
    _publish_only(service, first)
    _publish_only(service, second, version=1)

    with pytest.raises(CustodyEvidenceReadError, match="multiple unfinished"):
        service.continuous_event_head(request_nonce=HEAD_NONCE)

    second_projection = service.continuous_event_publication(
        second["payload"]["event_id"]
    )
    service.install_published_trusted_keyless_continuous_event(
        _continuation(second_projection, second),
        principal="control-api",
    )
    with pytest.raises(CustodyEvidenceReadError, match="not current"):
        service.continuous_event_head(request_nonce=HEAD_NONCE)


def test_continuous_event_head_rejects_distinct_same_day_events(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _artifact()
    service.publish_trusted_keyless_continuous_event(
        _upload(first), principal="control-api"
    )
    second = _artifact(
        trigger="ROLL_ONLY",
        now=datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1),
        suffix="2",
    )
    service.publish_trusted_keyless_continuous_event(
        _upload(second, version=2), principal="control-api"
    )

    with pytest.raises(CustodyEvidenceReadError, match="same-day conflict"):
        service.continuous_event_head(request_nonce=HEAD_NONCE)


def test_continuous_event_head_rejects_day_rollback_and_cross_event_splice(
    tmp_path: Path,
) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    (tmp_path / "rollback").mkdir()
    rollback_service = _service(tmp_path / "rollback")
    newer = _artifact(
        now=now,
        official_day="2026-08-28",
        execution_day="2026-08-31",
        source_month="2026-08",
    )
    rollback_service.publish_trusted_keyless_continuous_event(
        _upload(newer), principal="control-api"
    )
    older = _artifact(trigger="ROLL_ONLY", now=now + timedelta(seconds=1), suffix="2")
    rollback_service.publish_trusted_keyless_continuous_event(
        _upload(older, version=2), principal="control-api"
    )
    with pytest.raises(CustodyEvidenceReadError, match="rolled back"):
        rollback_service.continuous_event_head(request_nonce=HEAD_NONCE)

    (tmp_path / "splice").mkdir()
    splice_service = _service(tmp_path / "splice")
    first = _artifact(now=now)
    splice_service.publish_trusted_keyless_continuous_event(
        _upload(first), principal="control-api"
    )
    spliced = _next_roll_artifact(now=now + timedelta(seconds=1), previous_month="09")
    splice_service.publish_trusted_keyless_continuous_event(
        _upload(spliced, version=2), principal="control-api"
    )
    with pytest.raises(CustodyEvidenceReadError, match="cross-spliced"):
        splice_service.continuous_event_head(request_nonce=HEAD_NONCE)


def test_continuous_event_head_rejects_tamper_and_remote_splice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    service.publish_trusted_keyless_continuous_event(
        _upload(artifact), principal="control-api"
    )
    receipt_path = sorted((service.settings.root / "receipts").iterdir())[0]
    receipt_path.write_bytes(
        receipt_path.read_bytes().replace(
            b'"actor_id":"control-api"', b'"actor_id":"control-apx"'
        )
    )
    with pytest.raises(CustodyEvidenceReadError, match="evidence is invalid"):
        service.continuous_event_head(request_nonce=HEAD_NONCE)

    (tmp_path / "remote").mkdir()
    valid_service = _service(tmp_path / "remote")
    valid_service.publish_trusted_keyless_continuous_event(
        _upload(artifact), principal="control-api"
    )
    valid = valid_service.continuous_event_head(request_nonce=HEAD_NONCE)
    valid_response = valid.model_dump(mode="json")
    monkeypatch.setattr(
        "app.phase_c.client.secrets.token_hex", lambda _size: HEAD_NONCE
    )

    def remote_head(response: dict[str, Any]) -> ContinuousEventHeadDTO:
        return RemotePhaseCWorkflowClient(
            PhaseCRemoteSettings(
                "http://custody",
                "http://execution",
                HEADERS["X-Phase-C-Custody-Secret"],
                "execution-secret",
            ),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=response)
            ),
        ).continuous_event_head()

    def reseal(response: dict[str, Any], *, secret: str) -> None:
        preimage = {
            key: value
            for key, value in response.items()
            if key not in {"head_sha256", "custody_hmac_sha256"}
        }
        raw = canonical_json_line(preimage)
        response["head_sha256"] = hashlib.sha256(raw).hexdigest()
        response["custody_hmac_sha256"] = hmac.new(
            secret.encode(), raw, hashlib.sha256
        ).hexdigest()

    assert remote_head(valid_response) == valid

    projection_splices = {
        "publisher_principal": "phase-c-execution",
        "event_id": "continuous-event-" + "9" * 64,
        "source_event_raw_sha256": "8" * 64,
        "selection_id": "continuous-selection-" + "7" * 64,
        "selection_sha256": "6" * 64,
        "selection_raw_sha256": "5" * 64,
        "candidate_id": "continuous-candidate-" + "4" * 64,
        "trigger_kind": "ROLL_ONLY",
        "monthly_final_target_sha256": "3" * 64,
        "daily_artifact_id": "verified-daily-" + "2" * 64,
        "daily_artifact_raw_sha256": "1" * 64,
        "daily_official_day": "2026-07-30",
        "desired_target_position_hash": "a" * 64,
        "account_facts_id": "snapshot-peek-" + "b" * 64,
        "account_facts_sha256": "c" * 64,
    }
    for field, value in projection_splices.items():
        response = deepcopy(valid_response)
        response["publication"][field] = value
        reseal(response, secret=HEADERS["X-Phase-C-Custody-Secret"])
        with pytest.raises(WorkflowAdapterError) as raised:
            remote_head(response)
        assert raised.value.code == "PHASE_C_RESPONSE_BINDING_INVALID", field
        assert raised.value.retryable is False

    predecessor_splice = deepcopy(valid_response)
    predecessor_splice["publication"].update(
        predecessor_mode="COMPLETION",
        predecessor_terminal_target_id="terminal-target-foreign-0001",
        predecessor_terminal_target_raw_sha256="e" * 64,
    )
    reseal(
        predecessor_splice,
        secret=HEADERS["X-Phase-C-Custody-Secret"],
    )
    with pytest.raises(WorkflowAdapterError) as raised:
        remote_head(predecessor_splice)
    assert raised.value.code == "PHASE_C_RESPONSE_BINDING_INVALID"
    assert raised.value.retryable is False

    forged_ledger_pin = deepcopy(valid_response)
    forged_ledger_pin["ledger_record_sha256"] = "d" * 64
    reseal(forged_ledger_pin, secret="attacker-does-not-know-custody-secret")
    with pytest.raises(WorkflowAdapterError) as raised:
        remote_head(forged_ledger_pin)
    assert raised.value.code == "PHASE_C_RESPONSE_BINDING_INVALID"
    assert raised.value.retryable is False


def test_remote_continuous_event_head_rejects_old_valid_nonce_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    first = _artifact()
    service.publish_trusted_keyless_continuous_event(
        _upload(first), principal="control-api"
    )
    first_nonce = "1" * 64
    replay = service.continuous_event_head(request_nonce=first_nonce).model_dump(
        mode="json"
    )
    second = _next_roll_artifact(
        now=datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
    )
    service.publish_trusted_keyless_continuous_event(
        _upload(second, version=2), principal="control-api"
    )
    second_nonce = "2" * 64
    current = service.continuous_event_head(request_nonce=second_nonce)
    assert current.observed_custody_version == 4
    assert current.current_event is not None
    assert current.current_event.idempotency_key == second["payload"]["event_id"]

    monkeypatch.setattr(
        "app.phase_c.client.secrets.token_hex", lambda _size: second_nonce
    )
    before = _tree(service.settings.root)
    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings(
            "http://custody",
            "http://execution",
            HEADERS["X-Phase-C-Custody-Secret"],
            "execution-secret",
        ),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=replay)),
    )
    with pytest.raises(WorkflowAdapterError) as raised:
        client.continuous_event_head()
    assert raised.value.code == "PHASE_C_RESPONSE_BINDING_INVALID"
    assert raised.value.retryable is False
    assert _tree(service.settings.root) == before
