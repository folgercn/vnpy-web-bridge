"""One-shot ``simnow-experimental-target-v1`` lifecycle adapter.

The runner crosses the private Execution and Phase-C clients only.  It has no
Gateway/CTP import and owns no send/cancel logic: every mutation is driven by
the existing TargetPlan-v3 lifecycle.  The default invocation is dry-run;
``--execute`` continues only the exact recovered/new TargetPlan identity.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientError,
)
from app.execution.executable_target_adapter import (
    _position_manager_final_projection,
    _static_core_equal_outputs,
    build_full_portfolio_quote_requests,
    build_static_core_equal_full_portfolio_keyless_decision,
)
from app.execution.formal_tick_reader import (
    read_simnow_continuous_v3_formal_tick_bindings,
)
from app.execution.gateway_contracts import GatewaySnapshot
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.client import RemotePhaseCWorkflowClient
from simnow_continuous_run_once import ContinuousRunError, _ProductionBackend
from simnow_experimental_materialize_target import (
    ExperimentalTargetError,
    read_json_stable,
    validate_planner_bundle,
    validate_target,
)

from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    sha256_json,
)


class ExperimentalRunError(RuntimeError):
    """A fresh Execution fact does not admit a new experimental action."""


class _ExperimentalBackend(_ProductionBackend):
    """Reuse only the existing TargetPlan custody/Execution lifecycle.

    No audited warehouse/event method is called.  Phase-C credentials remain
    in the established environment-backed client settings, never in CLI args.
    """

    def __init__(
        self, *, execution: ExecutionClient | None = None,
        phase_c: RemotePhaseCWorkflowClient | None = None,
    ) -> None:
        self.config = SimpleNamespace(raw={
            "simnow_execution_enabled": True,
            "leader_owner_id": os.getenv("SIMNOW_EXPERIMENTAL_LEADER_OWNER", "simnow-experimental-runner"),
            "principal": os.getenv("SIMNOW_EXPERIMENTAL_PRINCIPAL", "control-api"),
            "operator": os.getenv("SIMNOW_EXPERIMENTAL_OPERATOR", "simnow-experimental-runner"),
            "completion_timeout_seconds": float(os.getenv("SIMNOW_EXPERIMENTAL_COMPLETION_TIMEOUT_SECONDS", "60")),
            "completion_poll_seconds": float(os.getenv("SIMNOW_EXPERIMENTAL_COMPLETION_POLL_SECONDS", "1")),
        })
        self.execution = execution or ExecutionClient()
        self.phase_c = phase_c or RemotePhaseCWorkflowClient()


def _require_fresh_clear_facts(facts: Mapping[str, Any]) -> None:
    if (
        facts.get("account_scope") != "account:windows"
        or facts.get("environment") != "SIMNOW"
        or facts.get("connected") is not True
        or facts.get("fresh") is not True
        or facts.get("active_order_count") != 0
        or facts.get("active_orders") != {}
    ):
        raise ExperimentalRunError("fresh broker facts are not ready")
    binding = facts.get("execution_binding")
    status_binding = facts.get("status_binding")
    reconciliation = (
        status_binding.get("reconciliation")
        if isinstance(status_binding, Mapping)
        else None
    )
    if (
        not isinstance(binding, Mapping)
        or binding.get("nonterminal_send_intent_count") != 0
        or not isinstance(reconciliation, Mapping)
        or reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("unknown_outcomes") != 0
    ):
        raise ExperimentalRunError("active, pending, or unknown execution state blocks mutation")


def _snapshot(facts: Mapping[str, Any]) -> GatewaySnapshot:
    try:
        return GatewaySnapshot(
            snapshot_id=str(facts["snapshot_id"]), generation=int(facts["generation"]),
            connected=facts["connected"] is True, active_order_count=int(facts["active_order_count"]),
            position_snapshot_hash=str(facts["position_snapshot_hash"]), observed_at=str(facts["observed_at"]),
            orders=dict(facts["active_orders"]), positions=dict(facts["positions"]),
            account_scope=str(facts["account_scope"]), environment=str(facts["environment"]),
            fresh=facts["fresh"] is True,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ExperimentalRunError("Execution fresh broker snapshot is invalid") from exc


def _planner_inputs(target: Mapping[str, Any], bundle: Mapping[str, Any]) -> dict[str, Any]:
    target_rows = {row["product"]: row for row in target["targets"]}
    projection = copy.deepcopy(bundle["static_core_equal_projection"])
    evidence = copy.deepcopy(bundle["static_core_equal_target_evidence"])
    snapshot = copy.deepcopy(bundle["position_manager_snapshot"])
    for evidence_row, snapshot_row in zip(
        evidence["targets"], snapshot["targets"], strict=True
    ):
        product = snapshot_row["product"]
        expected = target_rows.get(product)
        if evidence_row.get("product") != product or expected is None:
            raise ExperimentalRunError("monthly planner bundle products are invalid")
        if snapshot_row.get("shadow_target_quantity") != expected["quantity"]:
            raise ExperimentalRunError("target quantity does not bind monthly planner bundle")
        # DAILY PIT is the only source of the current exact contract.  Preserve
        # all monthly quantities, prices, weights and product specifications.
        evidence_row["exact_contract"] = expected["exact_contract"]
        snapshot_row["exact_contract"] = expected["exact_contract"]
    for digest in projection["artifact_digests"]:
        if digest.get("role") == "target_evidence":
            digest["sha256"] = sha256_json(evidence)
            break
    else:
        raise ExperimentalRunError("monthly planner projection lacks target evidence")
    for row in snapshot["targets"]:
        product = row["product"]
        expected = target_rows.get(product)
        if expected is None or row.get("shadow_target_quantity") != expected["quantity"]:
            raise ExperimentalRunError("target quantity does not bind monthly planner bundle")
    return {
        "static_core_equal_projection": projection,
        "static_core_equal_freeze_contract": bundle["static_core_equal_freeze_contract"],
        "static_core_equal_target_evidence": evidence,
        "position_manager_snapshot": snapshot,
    }


async def preview_once(
    target: Mapping[str, Any], planner_bundle: Mapping[str, Any], *, execution: ExecutionClient,
    formal_state_dir: Path, formal_projection_dir: Path, expires_at: str, _return_decision: bool = False,
) -> Any:
    """Build one existing TargetPlan-v3 decision without mutating Execution."""

    target = validate_target(dict(target))
    bundle = validate_planner_bundle(dict(planner_bundle))
    planner_inputs = _planner_inputs(target, bundle)
    try:
        facts = (await execution.account_facts()).as_dict()
    except ExecutionClientError as exc:
        raise ExperimentalRunError("Execution fresh broker facts are unavailable") from exc
    _require_fresh_clear_facts(facts)
    current = _snapshot(facts)
    run_id = f"simnow-experimental-{target['target_id'][:48]}"
    generated_at = str(target["generated_at"])
    now = datetime.now(timezone.utc)
    reconciliation = {"state": "RECONCILED", "unknown_outcomes": 0}
    requirements = build_full_portfolio_quote_requests(
        **planner_inputs, position_manager_sha256=hashlib.sha256(
            json.dumps(planner_inputs["position_manager_snapshot"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest(), current_facts=current, reconciliation=reconciliation,
        run_id=run_id, event_generated_at=generated_at, now=now, target_plan_version=3,
    )
    bindings: tuple[Any, ...] = ()
    if requirements.requests:
        try:
            bindings = read_simnow_continuous_v3_formal_tick_bindings(
                requirements.requests, state_dir=formal_state_dir, projection_dir=formal_projection_dir
            )
        except Exception as exc:  # formal reader's typed errors all fail closed here
            raise ExperimentalRunError("fresh formal bid/ask evidence is unavailable") from exc
    quotes = {
        requirement.exact_contract: binding.as_dict()
        for requirement, binding in zip(requirements.requirements, bindings, strict=True)
    }
    try:
        decision = build_static_core_equal_full_portfolio_keyless_decision(
            **planner_inputs, position_manager_sha256=hashlib.sha256(
                json.dumps(planner_inputs["position_manager_snapshot"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest(), current_facts=current, reconciliation=reconciliation,
            quote_requirements=requirements, formal_quotes_by_exact_contract=quotes,
            run_id=run_id, event_generated_at=generated_at, expires_at=expires_at,
            now=now, target_plan_version=3,
        )
    except Exception as exc:
        raise ExperimentalRunError("existing TargetPlan v3 planner rejected experimental bundle") from exc
    if decision.noop:
        result = {"status": "NOOP", "target_id": target["target_id"], "new_intents": 0, "execution_mutated": False, "gateway_mutated": False}
        return (result, decision) if _return_decision else result
    handoff = decision.close_handoff or decision.open_handoff
    if handoff is None:
        raise ExperimentalRunError("existing TargetPlan v3 planner lacks immediate handoff")
    result = {
        "status": "TARGET_PLAN_V3_DRY_RUN", "target_id": target["target_id"],
        "phase": handoff.target_plan["phase"], "plan_id": handoff.target_plan["plan_id"],
        "plan_hash": handoff.target_plan["plan_hash"], "formal_quote_count": len(bindings),
        "new_intents": len(handoff.target_plan["orders"]), "execution_mutated": False, "gateway_mutated": False,
    }
    return (result, decision) if _return_decision else result


async def execute_once(
    target: Mapping[str, Any], planner_bundle: Mapping[str, Any], *, backend: _ExperimentalBackend,
    formal_state_dir: Path, formal_projection_dir: Path, expires_at: str,
) -> dict[str, Any]:
    """Install and drive one existing lifecycle phase; no second dispatcher."""

    target = validate_target(dict(target))
    bundle = validate_planner_bundle(dict(planner_bundle))
    planner_inputs = _planner_inputs(target, bundle)
    run_id = f"simnow-experimental-{target['target_id'][:48]}"
    position_manager_sha256 = sha256_json(planner_inputs["position_manager_snapshot"])
    try:
        _static_sha, static_rows, execution_day = _static_core_equal_outputs(
            producer_projection=planner_inputs["static_core_equal_projection"],
            freeze_contract=planner_inputs["static_core_equal_freeze_contract"],
            target_evidence=planner_inputs["static_core_equal_target_evidence"],
        )
        final_projection, _final_rows = _position_manager_final_projection(
            snapshot=planner_inputs["position_manager_snapshot"],
            expected_sha256=position_manager_sha256,
            static_rows=static_rows,
            static_execution_day=execution_day,
        )
    except Exception as exc:
        raise ExperimentalRunError("experimental target planner bundle is invalid") from exc
    final_target_sha256 = sha256_json(final_projection)

    def phase_key(phase: str) -> str:
        return hashlib.sha256(
            json.dumps(
                {"domain": "simnow-experimental-target-v1", "target_id": target["target_id"], "phase": phase},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def require_binding(recovery: Mapping[str, Any], phase: str) -> None:
        lineage = recovery.get("lineage")
        if (
            recovery.get("target_plan_schema_version") != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            or recovery.get("custody_idempotency_key") != phase_key(phase)
            or recovery.get("phase") != phase
            or recovery.get("execution_run_id") != run_id
            or not isinstance(lineage, Mapping)
            or lineage.get("static_core_equal_sha256") != sha256_json(planner_inputs["static_core_equal_projection"])
            or lineage.get("position_manager_sha256") != position_manager_sha256
            or lineage.get("final_target_sha256") != final_target_sha256
        ):
            raise ExperimentalRunError("existing recovery does not bind experimental target")

    # Recovery always wins over fresh planning.  An existing same-identity
    # TargetPlan may be ACTIVE/pending/UNKNOWN and must be queried/driven by
    # Execution rather than rejected by the new-plan admission gate.
    for existing_phase in ("CLOSE", "OPEN"):
        recovery = (await backend.execution.target_plan_recovery(phase_key(existing_phase))).as_dict()
        if recovery.get("state") == "BEFORE_CUSTODY":
            continue
        require_binding(recovery, existing_phase)
        installed = await backend._install_or_recover_plan(
            phase_key=phase_key(existing_phase), handoff=None
        )
        require_binding(installed, existing_phase)
        lifecycle = await backend._drive_installed_plan(installed)
        if lifecycle.get("state") != "COMPLETED":
            return {"status": "RECOVERY", "target_id": target["target_id"], "phase": existing_phase, "lifecycle": lifecycle}

    for _phase_attempt in range(2):
        preview, decision = await preview_once(
            target, planner_bundle, execution=backend.execution, formal_state_dir=formal_state_dir,
            formal_projection_dir=formal_projection_dir, expires_at=expires_at, _return_decision=True,
        )
        if preview["status"] == "NOOP":
            return preview
        handoff = decision.close_handoff or decision.open_handoff
        if handoff is None:
            raise ExperimentalRunError("existing planner has no lifecycle handoff")
        phase = str(handoff.target_plan["phase"])
        recovery = await backend._install_or_recover_plan(phase_key=phase_key(phase), handoff=handoff)
        lifecycle = await backend._drive_installed_plan(recovery)
        if lifecycle.get("state") != "COMPLETED" or phase != "CLOSE":
            return {**preview, "lifecycle": lifecycle}
        # A completed CLOSE must re-enter via fresh Execution facts, formal
        # quotes and a newly produced OPEN TargetPlan, never a deferred plan.
    raise ExperimentalRunError("CLOSE completed but fresh OPEN was not produced")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="one SIMNOW_EXPERIMENTAL TargetPlan-v3 pass")
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--monthly-planner-bundle", required=True, type=Path)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--formal-state-dir", type=Path, default=Path("/run/market-data"))
    parser.add_argument("--formal-projection-dir", type=Path, default=Path("/run/market-projection"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        target, raw = read_json_stable(args.target, label="experimental target")
        validate_target(target, raw=raw)
        bundle, bundle_raw = read_json_stable(args.monthly_planner_bundle, label="monthly planner bundle")
        if hashlib.sha256(bundle_raw).hexdigest() != target["monthly_quantity_sha256"]:
            raise ExperimentalRunError("monthly planner bundle hash does not bind target")
        if args.execute:
            result = asyncio.run(execute_once(target, bundle, backend=_ExperimentalBackend(), formal_state_dir=args.formal_state_dir, formal_projection_dir=args.formal_projection_dir, expires_at=args.expires_at))
        else:
            result = asyncio.run(preview_once(target, bundle, execution=ExecutionClient(), formal_state_dir=args.formal_state_dir, formal_projection_dir=args.formal_projection_dir, expires_at=args.expires_at))
    except (
        ContinuousRunError,
        ExecutionClientError,
        ExperimentalTargetError,
        ExperimentalRunError,
        WorkflowAdapterError,
    ) as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
