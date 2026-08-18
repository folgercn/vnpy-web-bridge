"""Issue #291 Phase A execution boundary public API.

The package initializer keeps the contract DTOs (``models``) import-only and
loads the state owner/gateway modules lazily.  Control API can therefore import
``app.execution.models.CommandEnvelope`` without importing or constructing the
Execution Orchestrator state owner.
"""

from .errors import (
    ActiveResumeFreshSnapshotRequired,
    AuthorityRejected,
    ClockRollbackError,
    CommandValidationError,
    DurableStateCorrupt,
    ExecutionError,
    ExpectedVersionConflict,
    FencingError,
    GatewayConfigurationError,
    GatewayTimeout,
    GatewayUnavailable,
    IdempotencyConflictError,
    LeaseNotHeldError,
    MutationRejected,
    PlanRejected,
    RepositoryUnavailableError,
    RestartReconciliationRequired,
    SnapshotRejected,
    StartQuoteEvidenceInvalid,
    StartQuoteReplanRequired,
    StartQuoteSourceUnavailable,
    UnknownCommandError,
    UnknownOutcomeError,
)
from .models import (
    Actor,
    AuthorityState,
    BrokerState,
    CommandEnvelope,
    CommandReceipt,
    ExpectedVersion,
    LeaderToken,
    PlanState,
    ReconciliationState,
    SendIntent,
)

_LAZY_EXPORTS = {
    "CommandResponse": (".orchestrator", "CommandResponse"),
    "ExecutionOrchestrator": (".orchestrator", "ExecutionOrchestrator"),
    "LeaderFencer": (".fencing", "LeaderFencer"),
    "SingleLeaderFencer": (".fencing", "SingleLeaderFencer"),
    "ExecutionGateway": (".gateway", "ExecutionGateway"),
    "GatewaySnapshot": (".gateway", "GatewaySnapshot"),
    "InMemoryGateway": (".gateway", "InMemoryGateway"),
    "MutationContext": (".gateway", "MutationContext"),
    "NullGateway": (".gateway", "NullGateway"),
    "RpcTransport": (".gateway", "RpcTransport"),
    "ZmqRpcTransport": (".gateway", "ZmqRpcTransport"),
    "VnpyWindowsGateway": (".gateway", "VnpyWindowsGateway"),
    "DurableExecutionRepository": (".repository", "DurableExecutionRepository"),
    "DurableStateRepository": (".repository", "DurableStateRepository"),
    "ExecutionStateRepository": (".repository", "ExecutionStateRepository"),
    "InMemoryExecutionRepository": (".repository", "InMemoryExecutionRepository"),
    "JsonExecutionRepository": (".repository", "JsonExecutionRepository"),
    "DurableTargetPlanRepository": (".final_runtime", "DurableTargetPlanRepository"),
    "FinalExecutionRuntime": (".final_runtime", "FinalExecutionRuntime"),
    "InMemoryTargetPlanRepository": (".final_runtime", "InMemoryTargetPlanRepository"),
    "TargetPlanRepository": (".final_runtime", "TargetPlanRepository"),
}


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    from importlib import import_module

    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


__all__ = [
    "Actor",
    "ActiveResumeFreshSnapshotRequired",
    "AuthorityRejected",
    "AuthorityState",
    "BrokerState",
    "ClockRollbackError",
    "CommandEnvelope",
    "CommandReceipt",
    "CommandResponse",
    "CommandValidationError",
    "DurableExecutionRepository",
    "DurableStateCorrupt",
    "DurableStateRepository",
    "DurableTargetPlanRepository",
    "ExecutionError",
    "ExecutionGateway",
    "ExecutionOrchestrator",
    "ExecutionStateRepository",
    "ExpectedVersion",
    "ExpectedVersionConflict",
    "FencingError",
    "FinalExecutionRuntime",
    "GatewayConfigurationError",
    "GatewaySnapshot",
    "GatewayTimeout",
    "GatewayUnavailable",
    "IdempotencyConflictError",
    "InMemoryExecutionRepository",
    "InMemoryGateway",
    "InMemoryTargetPlanRepository",
    "JsonExecutionRepository",
    "LeaderFencer",
    "LeaderToken",
    "LeaseNotHeldError",
    "MutationContext",
    "MutationRejected",
    "NullGateway",
    "PlanRejected",
    "PlanState",
    "ReconciliationState",
    "RepositoryUnavailableError",
    "RestartReconciliationRequired",
    "RpcTransport",
    "SendIntent",
    "SingleLeaderFencer",
    "SnapshotRejected",
    "StartQuoteEvidenceInvalid",
    "StartQuoteReplanRequired",
    "StartQuoteSourceUnavailable",
    "TargetPlanRepository",
    "UnknownCommandError",
    "UnknownOutcomeError",
    "VnpyWindowsGateway",
    "ZmqRpcTransport",
]
