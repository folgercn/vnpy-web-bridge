"""Errors raised by the Issue #291 Phase A execution boundary.

The execution package intentionally has no dependency on the legacy web bridge
services.  Callers can use these small, typed errors to distinguish a rejected
command from an unavailable durable store or an unknown broker outcome.
"""

from __future__ import annotations


class ExecutionError(Exception):
    """Base class for all execution-boundary errors."""


class CommandValidationError(ExecutionError, ValueError):
    """The command envelope or command payload is not contract compliant."""


class UnknownCommandError(CommandValidationError):
    """An unsupported command name was supplied."""


class IdempotencyConflictError(ExecutionError):
    """An idempotency key was reused with a different command fingerprint."""


class ExpectedVersionConflict(ExecutionError):
    """The caller's expected durable state version is stale."""

    def __init__(self, expected: int, actual: int) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"state version conflict: expected {expected}, actual {actual}"
        )


class RepositoryUnavailableError(ExecutionError):
    """The durable store could not establish a determinate result."""


class FencingError(ExecutionError):
    """A leader lease or fencing token is missing, stale, or foreign."""


class LeaseNotHeldError(FencingError):
    """The process does not hold the account/environment lease."""


class ClockRollbackError(FencingError):
    """Wall-clock time moved backwards; mutations stay fail closed."""


class MutationRejected(ExecutionError):
    """A broker mutation was rejected before the gateway boundary."""


class AuthorityRejected(MutationRejected):
    """No currently effective, unexpired authority admits mutation."""


class PlanRejected(MutationRejected):
    """The requested plan is not the durable active plan."""


class UnknownOutcomeError(MutationRejected):
    """A previous timeout/connection failure is unresolved."""


class RestartReconciliationRequired(MutationRejected):
    """The process has not completed the mandatory post-restart snapshot."""


class GatewayTimeout(ExecutionError):
    """The gateway call timed out; outcome is deliberately unknown."""


class GatewayUnavailable(ExecutionError):
    """The gateway could not be reached and no mutation was admitted."""


class GatewayConfigurationError(GatewayUnavailable):
    """Production gateway configuration is missing or unsafe."""


class SnapshotRejected(MutationRejected):
    """A broker snapshot is disconnected, stale, foreign, or not closed."""


class DurableStateCorrupt(RepositoryUnavailableError):
    """Durable state failed schema/hash/high-water validation."""
