from __future__ import annotations

from research_lab.schemas.sol import ExperimentPlan, PlanStatus


class SolStateError(ValueError):
    """Raised when a lifecycle transition is not supported by the local contract."""


INITIAL_STATES: tuple[PlanStatus, ...] = ("received", "planning", "pending_approval")
ALLOWED_TRANSITIONS: dict[PlanStatus, frozenset[PlanStatus]] = {
    "received": frozenset({"planning"}),
    "planning": frozenset({"pending_approval"}),
    "pending_approval": frozenset({"queued"}),
    "queued": frozenset({"running"}),
    "running": frozenset({"review", "failed"}),
    "failed": frozenset({"retry"}),
    "retry": frozenset({"queued"}),
    "review": frozenset({"review", "archived"}),
    "archived": frozenset(),
}


def require_transition(previous: PlanStatus, current: PlanStatus) -> None:
    if current not in ALLOWED_TRANSITIONS[previous]:
        raise SolStateError(f"illegal Sol transition: {previous} -> {current}")


def retry_permitted(retry_count: int, max_retries: int) -> bool:
    """Whether a failed plan may record one further explicit retry."""
    return retry_count < max_retries


def validate_state_chain(plan: ExperimentPlan) -> None:
    states = [event.status for event in plan.events]
    if tuple(states[:3]) != INITIAL_STATES or plan.status != states[-1]:
        raise SolStateError(f"plan state chain is not reachable: {plan.plan_id}")
    for prior, current in zip(states, states[1:]):
        require_transition(prior, current)
    approval_required = {"queued", "running", "retry", "failed", "review", "archived"}
    if any(state in approval_required for state in states):
        if not plan.approved_by or plan.approved_at is None:
            raise SolStateError(f"approved state lacks an approval record: {plan.plan_id}")
