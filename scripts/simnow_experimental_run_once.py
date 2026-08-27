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
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.control_execution_client import (  # noqa: E402
    ExecutionClient,
    ExecutionClientError,
)
from app.execution.executable_target_adapter import (  # noqa: E402
    _position_manager_final_projection,
    _static_core_equal_outputs,
    build_full_portfolio_quote_requests,
    build_static_core_equal_full_portfolio_keyless_decision,
)
from app.execution.formal_tick_reader import (  # noqa: E402
    read_simnow_continuous_v3_formal_tick_bindings,
)
from app.execution.gateway_contracts import GatewaySnapshot  # noqa: E402
from app.phase_c.adapters import WorkflowAdapterError  # noqa: E402
from app.phase_c.client import RemotePhaseCWorkflowClient  # noqa: E402
from simnow_continuous_run_once import (  # noqa: E402
    ContinuousRunError,
    _ProductionBackend,
    _command,
    _completed,
    _completion_state,
    _submit_reconcile_with_ready_snapshot,
)
from simnow_experimental_materialize_target import (  # noqa: E402
    ExperimentalTargetError,
    NOT_OFFICIAL_STRATEGY_OUTPUT,
    SIMNOW_EXPERIMENTAL_TEST,
    read_json_stable,
    validate_planner_bundle,
    validate_test_target_bundle_binding,
    validate_target,
)

from shared.commodity_execution import (  # noqa: E402
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    sha256_json,
)


class ExperimentalRunError(RuntimeError):
    """A fresh Execution fact does not admit a new experimental action."""


_CUSTODY_KEY_DOMAIN = "simnow-experimental-target-v1"
_CUSTODY_SUCCESSOR_KEY_DOMAIN = "simnow-experimental-target-v1-successor"
_MAX_CUSTODY_SUCCESSOR_DEPTH = 32


def _custody_phase_key(*, target_id: str, phase: str) -> str:
    """Return the unchanged first-incarnation Custody key for one phase."""

    return hashlib.sha256(
        json.dumps(
            {
                "domain": _CUSTODY_KEY_DOMAIN,
                "target_id": target_id,
                "phase": phase,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _custody_successor_phase_key(
    *, target_id: str, phase: str, predecessor_plan_id: str, predecessor_plan_hash: str
) -> str:
    """Bind a later same-target incarnation to its exact retired predecessor."""

    return hashlib.sha256(
        json.dumps(
            {
                "domain": _CUSTODY_SUCCESSOR_KEY_DOMAIN,
                "target_id": target_id,
                "phase": phase,
                "predecessor_plan_id": predecessor_plan_id,
                "predecessor_plan_hash": predecessor_plan_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


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

    def _allows_retired_plan_replacement(self) -> bool:
        """Admit Execution's documented TERMINAL/REVOKED zero-work boundary."""

        return True


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
        if target.get("target_mode") == SIMNOW_EXPERIMENTAL_TEST:
            # The original monthly row remains the immutable baseline.  This
            # declared overlay is intentionally visible only in the shadow
            # quantity consumed by the existing TargetPlan-v3 planner.
            snapshot_row["shadow_target_quantity"] = expected["quantity"]
        elif snapshot_row.get("shadow_target_quantity") != expected["quantity"]:
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


def _checkpoint(target: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    """Keep TEST semantics explicit in every runner checkpoint."""

    checkpoint = dict(result)
    if target.get("target_mode") == SIMNOW_EXPERIMENTAL_TEST:
        checkpoint.update({
            "target_mode": SIMNOW_EXPERIMENTAL_TEST,
            "strategy_output_claim": NOT_OFFICIAL_STRATEGY_OUTPUT,
        })
    return checkpoint


async def preview_once(
    target: Mapping[str, Any], planner_bundle: Mapping[str, Any], *, execution: ExecutionClient,
    formal_state_dir: Path, formal_projection_dir: Path, expires_at: str,
    formal_binding_reader: Callable[..., tuple[Any, ...]] | None = None,
    _return_decision: bool = False,
) -> Any:
    """Build one existing TargetPlan-v3 decision without mutating Execution."""

    bundle = validate_planner_bundle(dict(planner_bundle))
    target = validate_test_target_bundle_binding(dict(target), bundle)
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
            bindings = (formal_binding_reader or read_simnow_continuous_v3_formal_tick_bindings)(
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
        result = _checkpoint(target, {"status": "NOOP", "target_id": target["target_id"], "new_intents": 0, "execution_mutated": False, "gateway_mutated": False})
        return (result, decision) if _return_decision else result
    handoff = decision.close_handoff or decision.open_handoff
    if handoff is None:
        raise ExperimentalRunError("existing TargetPlan v3 planner lacks immediate handoff")
    result = _checkpoint(target, {
        "status": "TARGET_PLAN_V3_DRY_RUN", "target_id": target["target_id"],
        "phase": handoff.target_plan["phase"], "plan_id": handoff.target_plan["plan_id"],
        "plan_hash": handoff.target_plan["plan_hash"], "formal_quote_count": len(bindings),
        "new_intents": len(handoff.target_plan["orders"]), "execution_mutated": False, "gateway_mutated": False,
    })
    return (result, decision) if _return_decision else result


async def _advance_current_execution_identity(
    backend: _ExperimentalBackend,
) -> dict[str, Any] | None:
    """Advance Execution's current identity before deriving a new target key.

    ``target_plan_recovery`` is intentionally keyed by a custody idempotency
    key.  A newly materialized target cannot know the previous target's key,
    so a nonterminal plan must first be recovered through Execution's existing
    current-plan status/resume API.  This keeps pending and UNKNOWN outcomes
    on their original plan identity and never derives a replacement plan.
    """

    async def terminal_completion_matches(
        current_status: Mapping[str, Any],
        *,
        plan_id: str,
        plan_hash: str,
    ) -> bool:
        if not _completed(dict(current_status), plan_id=plan_id, plan_hash=plan_hash):
            return False
        completion = await backend.execution.completion(plan_id)
        if completion is None:
            return False
        completed = completion.as_dict()
        return (
            completed.get("plan_id") == plan_id
            and completed.get("plan_hash") == plan_hash
        )

    def blocked(
        *, plan_id: str, plan_hash: str, plan_state: Any,
        new_intents: int = 0, execution_mutated: bool = False,
        reason: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "status": "CURRENT_IDENTITY_RECOVERY",
            "plan_id": plan_id,
            "plan_hash": plan_hash,
            "plan_state": plan_state,
            "new_intents": new_intents,
            "execution_mutated": execution_mutated,
            "gateway_mutated": new_intents > 0,
        }
        if reason is not None:
            result["reason"] = reason
        return result

    def expired_retirement_boundary(
        current_status: Mapping[str, Any],
        *,
        recovery: Mapping[str, Any],
        leader_token: Any,
    ) -> bool:
        """Recognize the one retired ACTIVE boundary that cannot resume.

        ``authority.expires_at`` is the immutable TargetPlan expiry carried by
        the already-enabled authority.  Status deliberately does not expose
        custody provenance; the stop command below additionally binds the
        exact plan/authority hashes and leader fence.
        """

        plan_state = current_status.get("plan")
        authority = current_status.get("authority")
        leader = current_status.get("leader")
        reconciliation = current_status.get("reconciliation")
        broker = current_status.get("broker")
        intents = current_status.get("send_intents")
        if not all(
            isinstance(value, Mapping)
            for value in (plan_state, authority, leader, reconciliation, broker)
        ) or not isinstance(intents, list):
            return False
        try:
            expires_at = datetime.fromisoformat(
                str(authority["expires_at"]).removesuffix("Z") + "+00:00"
            )
        except (KeyError, TypeError, ValueError):
            return False
        terminal_intent_states = {"RECONCILED", "CANCELLED", "TERMINAL"}
        return bool(
            plan_state.get("state") == "ACTIVE"
            and plan_state.get("plan_id") == recovery["plan_id"]
            and plan_state.get("plan_hash") == recovery["plan_hash"]
            and authority.get("state") == "REVOKED"
            and authority.get("artifact_id") == recovery["plan_id"]
            and authority.get("artifact_hash") == recovery["plan_hash"]
            and expires_at <= datetime.now(timezone.utc)
            and current_status.get("lifecycle") == "READY"
            and reconciliation.get("state") == "RECONCILED"
            and reconciliation.get("unknown_outcomes") == 0
            and broker.get("active_order_count") == 0
            and leader.get("held") is True
            and leader.get("epoch") == leader_token.epoch
            and leader.get("fencing_token") == leader_token.fencing_token
            and all(
                isinstance(intent, Mapping)
                and intent.get("state") in terminal_intent_states
                for intent in intents
            )
        )

    async def retire_expired_active_plan(
        current_status: Mapping[str, Any],
        *,
        recovery: Mapping[str, Any],
        leader_token: Any,
    ) -> dict[str, Any] | None:
        """Retire, never resume, an expired exact ACTIVE identity.

        This uses the normal fenced ``stop`` command.  It is intentionally the
        final mutation in this invocation; a later invocation must derive a
        new TargetPlan from fresh broker positions.
        """

        if not expired_retirement_boundary(
            current_status, recovery=recovery, leader_token=leader_token
        ):
            return None
        snapshot = (await backend.execution.reconciliation_snapshot()).as_dict()
        binding = snapshot.get("state_binding")
        if (
            not isinstance(binding, Mapping)
            or binding.get("state_version") != current_status.get("state_version")
            or binding.get("durable_broker_generation")
            != current_status.get("broker", {}).get("generation")
            or snapshot.get("active_order_count") != 0
            or snapshot.get("active_orders") != {}
        ):
            return None
        authority = current_status["authority"]
        command = _command(
            name="stop",
            suffix=(
                f"experimental-expired-retire-{recovery['plan_hash'][:24]}-"
                f"{current_status['state_version']}"
            ),
            version=int(current_status["state_version"]),
            actor=backend._actor(),
            now=datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            payload={
                "reason": "retire expired reconciled SIMNOW ACTIVE TargetPlan",
            },
            fence={
                "leader_epoch": leader_token.epoch,
                "fencing_token": leader_token.fencing_token,
            },
        )
        command["expected"].update(
            {
                "plan_hash": recovery["plan_hash"],
                "authority_hash": authority["artifact_hash"],
            }
        )
        try:
            await backend.execution.submit(command)
        except (ExecutionClientError, ValueError):
            return blocked(
                plan_id=str(recovery["plan_id"]),
                plan_hash=str(recovery["plan_hash"]),
                plan_state="ACTIVE",
                execution_mutated=True,
                reason="expired_retirement_outcome_unknown",
            )
        after_stop = (await backend.execution.status()).as_dict()
        after_plan = after_stop.get("plan")
        after_authority = after_stop.get("authority")
        if (
            isinstance(after_plan, Mapping)
            and after_plan.get("state") == "TERMINAL"
            and after_plan.get("plan_id") == recovery["plan_id"]
            and after_plan.get("plan_hash") == recovery["plan_hash"]
            and isinstance(after_authority, Mapping)
            and after_authority.get("state") == "REVOKED"
        ):
            return blocked(
                plan_id=str(recovery["plan_id"]),
                plan_hash=str(recovery["plan_hash"]),
                plan_state="TERMINAL",
                execution_mutated=True,
                reason="expired_active_plan_retired",
            )
        return blocked(
            plan_id=str(recovery["plan_id"]),
            plan_hash=str(recovery["plan_hash"]),
            plan_state="ACTIVE",
            execution_mutated=True,
            reason="expired_retirement_did_not_reach_terminal",
        )

    status = (await backend.execution.status()).as_dict()
    plan = status.get("plan")
    if not isinstance(plan, Mapping):
        raise ExperimentalRunError("Execution current plan projection is invalid")
    state = plan.get("state")
    if state == "IDLE":
        return None
    plan_id = plan.get("plan_id")
    plan_hash = plan.get("plan_hash")
    if not isinstance(plan_id, str) or not isinstance(plan_hash, str):
        raise ExperimentalRunError("Execution current plan identity is invalid")
    if state == "TERMINAL":
        if backend._is_retired_execution_boundary(
            status, require_leader_clear=True
        ):
            return None
        if await terminal_completion_matches(
            status, plan_id=plan_id, plan_hash=plan_hash
        ):
            return None
        return blocked(
            plan_id=plan_id,
            plan_hash=plan_hash,
            plan_state=state,
            reason="terminal_completion_unavailable",
        )
    if state != "ACTIVE":
        return blocked(plan_id=plan_id, plan_hash=plan_hash, plan_state=state)
    leader = status.get("leader")
    if not isinstance(leader, Mapping) or leader.get("held") is True:
        return blocked(
            plan_id=plan_id,
            plan_hash=plan_hash,
            plan_state="ACTIVE",
            reason="existing_execution_leader",
        )

    token = None
    try:
        token = await backend.execution.acquire_leader(
            backend.config.raw["leader_owner_id"]
        )
        token = await backend.execution.renew_leader(token)
        recovery = {"plan_id": plan_id, "plan_hash": plan_hash}
        status = (await backend.execution.status()).as_dict()
        if status.get("reconciliation", {}).get("state") != "RECONCILED":
            backend._require_active_reconcile_status(status, recovery, token)
            await _submit_reconcile_with_ready_snapshot(
                backend.execution,
                suffix=(
                    f"experimental-current-recovery-{plan_hash[:24]}-"
                    f"{status['state_version']}"
                ),
                version=status["state_version"],
                actor=backend._actor(),
                now=datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                reconciliation_run_id=(
                    f"simnow-experimental-current-recovery-{plan_hash[:32]}"
                ),
                reason="query-only reconcile exact existing SIMNOW TargetPlan",
            )
            status = (await backend.execution.status()).as_dict()
        backend._require_post_renew_status(status, recovery, allow_active=True)
        retired = await retire_expired_active_plan(
            status, recovery=recovery, leader_token=token
        )
        if retired is not None:
            return retired
        snapshot = await backend.execution.reconciliation_snapshot()
        resumed = await backend.execution.resume_active_plan(
            plan_id=plan_id,
            plan_hash=plan_hash,
            leader_token=token,
            reconciliation_snapshot=snapshot,
        )
        resume = resumed.as_dict()
        new_intents = int(resume["new_intent_count"])
        after = (await backend.execution.status()).as_dict()
        after_plan = after.get("plan")
        if not isinstance(after_plan, Mapping):
            raise ExperimentalRunError("Execution current plan projection is invalid")
        if (
            after_plan.get("state") == "TERMINAL"
            and after_plan.get("plan_id") == plan_id
            and after_plan.get("plan_hash") == plan_hash
        ):
            if await terminal_completion_matches(
                after, plan_id=plan_id, plan_hash=plan_hash
            ):
                return None
            return blocked(
                plan_id=plan_id,
                plan_hash=plan_hash,
                plan_state="TERMINAL",
                new_intents=new_intents,
                execution_mutated=True,
                reason="terminal_completion_unavailable",
            )
        completion_state = _completion_state(
            after, plan_id=plan_id, plan_hash=plan_hash
        )
        if completion_state != "ready_for_final_reconcile":
            return blocked(
                plan_id=plan_id,
                plan_hash=plan_hash,
                plan_state=after_plan.get("state", "UNKNOWN"),
                new_intents=new_intents,
                execution_mutated=True,
                reason=completion_state,
            )
        token = await backend.execution.renew_leader(token)
        try:
            await _submit_reconcile_with_ready_snapshot(
                backend.execution,
                suffix=f"experimental-current-final-{plan_hash[:24]}-{after['state_version']}",
                version=after["state_version"],
                actor=backend._actor(),
                now=datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                reconciliation_run_id=(
                    f"simnow-experimental-current-final-{plan_hash[:32]}"
                ),
                reason="final reconcile exact existing SIMNOW TargetPlan",
            )
        except (ExecutionClientError, ValueError):
            return blocked(
                plan_id=plan_id,
                plan_hash=plan_hash,
                plan_state="ACTIVE",
                new_intents=new_intents,
                execution_mutated=True,
                reason="final_reconcile_outcome_unknown",
            )
        final_status = (await backend.execution.status()).as_dict()
        if await terminal_completion_matches(
            final_status, plan_id=plan_id, plan_hash=plan_hash
        ):
            return None
        return blocked(
            plan_id=plan_id,
            plan_hash=plan_hash,
            plan_state=(
                final_status.get("plan", {}).get("state")
                if isinstance(final_status.get("plan"), Mapping)
                else "UNKNOWN"
            ),
            new_intents=new_intents,
            execution_mutated=True,
            reason="final_reconcile_did_not_archive",
        )
    finally:
        if token is not None:
            await backend._release_leader(token)


async def execute_once(
    target: Mapping[str, Any], planner_bundle: Mapping[str, Any], *, backend: _ExperimentalBackend,
    formal_state_dir: Path, formal_projection_dir: Path, expires_at: str,
) -> dict[str, Any]:
    """Install and drive one existing lifecycle phase; no second dispatcher."""

    bundle = validate_planner_bundle(dict(planner_bundle))
    target = validate_test_target_bundle_binding(dict(target), bundle)
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
        return _custody_phase_key(target_id=str(target["target_id"]), phase=phase)

    def require_binding(
        recovery: Mapping[str, Any], phase: str, exact_phase_key: str
    ) -> None:
        lineage = recovery.get("lineage")
        if (
            recovery.get("target_plan_schema_version") != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            or recovery.get("custody_idempotency_key") != exact_phase_key
            or recovery.get("phase") != phase
            or recovery.get("execution_run_id") != run_id
            or not isinstance(lineage, Mapping)
            or lineage.get("static_core_equal_sha256") != sha256_json(planner_inputs["static_core_equal_projection"])
            or lineage.get("position_manager_sha256") != position_manager_sha256
            or lineage.get("final_target_sha256") != final_target_sha256
        ):
            raise ExperimentalRunError("existing recovery does not bind experimental target")

    async def completion_matches(recovery: Mapping[str, Any]) -> bool:
        """Read the immutable completion archive for one exact predecessor."""

        completion = await backend.execution.completion(str(recovery["plan_id"]))
        if completion is None:
            return False
        archived = completion.as_dict()
        if (
            archived.get("plan_id") != recovery.get("plan_id")
            or archived.get("plan_hash") != recovery.get("plan_hash")
        ):
            raise ExperimentalRunError(
                "completion archive does not bind custody predecessor"
            )
        return True

    def retired_predecessor_boundary(
        status: Mapping[str, Any], recovery: Mapping[str, Any]
    ) -> bool:
        """Recognize only #456's fully retired, expired, zero-work plan."""

        plan = status.get("plan")
        authority = status.get("authority")
        if not isinstance(plan, Mapping) or not isinstance(authority, Mapping):
            return False
        try:
            expires_at = datetime.fromisoformat(
                str(recovery["expires_at"]).removesuffix("Z") + "+00:00"
            )
        except (KeyError, TypeError, ValueError):
            return False
        return bool(
            backend._is_retired_execution_boundary(
                status, require_leader_clear=True
            )
            and plan.get("plan_id") == recovery.get("plan_id")
            and plan.get("plan_hash") == recovery.get("plan_hash")
            and authority.get("artifact_id") == recovery.get("plan_id")
            and authority.get("artifact_hash") == recovery.get("plan_hash")
            and expires_at <= datetime.now(timezone.utc)
        )

    async def successor_kind(recovery: Mapping[str, Any]) -> str | None:
        """Classify a custody incarnation without writing any state.

        Completed plans can be successors only through their exact immutable
        completion archive.  A #456 retirement has no completion archive, so
        it additionally requires the current Execution projection to be the
        same expired TERMINAL/REVOKED, leader-clear, zero-work boundary.
        """

        # Completion is immutable, exact, and sufficient even after a later
        # same-target incarnation became Execution's current plan.  This is
        # what permits NORMAL -> TEST -> restore NORMAL to traverse K0 -> K1.
        if await completion_matches(recovery):
            return "COMPLETED"
        status = (await backend.execution.status()).as_dict()
        plan = status.get("plan")
        if (
            isinstance(plan, Mapping)
            and plan.get("state") == "TERMINAL"
            and plan.get("plan_id") == recovery.get("plan_id")
            and plan.get("plan_hash") == recovery.get("plan_hash")
        ):
            if retired_predecessor_boundary(status, recovery):
                return "RETIRED"
            raise ExperimentalRunError(
                "terminal custody predecessor is not completed or safely retired"
            )
        return None

    async def resolve_phase_recovery(
        phase: str,
    ) -> tuple[str, dict[str, Any]]:
        """Follow K0 -> K1 -> ... until the exact live custody incarnation.

        Looking up a successor is read-only.  A new key is only published
        later, after the planner has proved a non-NOOP delta.
        """

        exact_key = phase_key(phase)
        seen: set[str] = set()
        for _depth in range(_MAX_CUSTODY_SUCCESSOR_DEPTH):
            if exact_key in seen:
                raise ExperimentalRunError("custody successor key chain cycles")
            seen.add(exact_key)
            recovery = (
                await backend.execution.target_plan_recovery(exact_key)
            ).as_dict()
            if recovery.get("state") == "BEFORE_CUSTODY":
                return exact_key, recovery
            require_binding(recovery, phase, exact_key)
            plan_id = recovery.get("plan_id")
            plan_hash = recovery.get("plan_hash")
            if not isinstance(plan_id, str) or not isinstance(plan_hash, str):
                raise ExperimentalRunError("custody predecessor identity is invalid")
            successor_key = _custody_successor_phase_key(
                target_id=str(target["target_id"]),
                phase=phase,
                predecessor_plan_id=plan_id,
                predecessor_plan_hash=plan_hash,
            )
            # Probe a deterministic successor before looking at current
            # Execution state.  K0 may no longer be current once K1 was
            # installed, so status cannot be used to rediscover an already
            # published successor.  Its own strict binding remains required.
            successor = (
                await backend.execution.target_plan_recovery(successor_key)
            ).as_dict()
            if successor.get("state") != "BEFORE_CUSTODY":
                exact_key = successor_key
                continue
            # Only a missing successor needs predecessor eligibility.  This
            # read-only result is used later, after a fresh non-NOOP preview,
            # to publish exactly successor_key.
            kind = await successor_kind(recovery)
            if kind is None:
                return exact_key, recovery
            return successor_key, successor
        raise ExperimentalRunError("custody successor key chain exceeds depth limit")

    # Recovery of Execution's current identity always wins over fresh planning.
    # This covers a previous experimental target whose phase key is not
    # derivable from the newly materialized target.
    current_recovery = await _advance_current_execution_identity(backend)
    if current_recovery is not None:
        return _checkpoint(target, current_recovery)

    # A recovered same-target TargetPlan may still have an installed custody
    # identity even when it is no longer the active Execution plan.
    for existing_phase in ("CLOSE", "OPEN"):
        exact_key, recovery = await resolve_phase_recovery(existing_phase)
        if recovery.get("state") == "BEFORE_CUSTODY":
            continue
        installed = await backend._install_or_recover_plan(
            phase_key=exact_key, handoff=None, recovery=recovery
        )
        require_binding(installed, existing_phase, exact_key)
        lifecycle = await backend._drive_installed_plan(installed)
        if lifecycle.get("state") != "COMPLETED":
            return _checkpoint(target, {"status": "RECOVERY", "target_id": target["target_id"], "phase": existing_phase, "lifecycle": lifecycle})

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
        exact_key, recovery = await resolve_phase_recovery(phase)
        if recovery.get("state") != "BEFORE_CUSTODY":
            # A concurrent/restarted invocation may have already published this
            # exact incarnation.  Recover it; never jump to another successor.
            installed = await backend._install_or_recover_plan(
                phase_key=exact_key, handoff=None, recovery=recovery
            )
            require_binding(installed, phase, exact_key)
            lifecycle = await backend._drive_installed_plan(installed)
            return _checkpoint(
                target, {**preview, "lifecycle": lifecycle, "recovered": True}
            )
        recovery = await backend._install_or_recover_plan(
            phase_key=exact_key, handoff=handoff
        )
        require_binding(recovery, phase, exact_key)
        lifecycle = await backend._drive_installed_plan(
            recovery, expected_intent_count=len(handoff.target_plan["orders"])
        )
        if lifecycle.get("state") != "COMPLETED" or phase != "CLOSE":
            return _checkpoint(target, {**preview, "lifecycle": lifecycle})
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
