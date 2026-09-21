"""Provider error taxonomy and fail-closed exception hierarchy (#573 Milestone 0).

Strict fail-closed error classification. Any provider/infrastructure failure must
NEVER be mapped directly to:
- Alpha REJECT
- Alpha PROMOTE
- CriticDecision
- Research Memory scientific conclusion
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class ProviderErrorCode(str, Enum):
    """Canonical error codes for Agent Provider and Access Control failure conditions."""

    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    QUOTA_UNAVAILABLE = "QUOTA_UNAVAILABLE"
    PROJECT_BINDING_FAILED = "PROJECT_BINDING_FAILED"
    SUBMISSION_FAILED = "SUBMISSION_FAILED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_UNCERTAIN = "EXECUTION_UNCERTAIN"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCEL_CONFIRMED = "CANCEL_CONFIRMED"
    RESULT_REJECTED_BY_ACCEPTANCE = "RESULT_REJECTED_BY_ACCEPTANCE"
    PERMISSION_DENIED = "PERMISSION_DENIED"


class ProviderError(Exception):
    """Base exception for all agent provider, access control, and routing errors."""

    def __init__(
        self,
        code: ProviderErrorCode | str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = ProviderErrorCode(code) if isinstance(code, str) else code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_code": self.code.value,
            "message": self.message,
            "details": self.details,
        }


class PermissionDeniedError(ProviderError):
    """Raised when access control policy or hard invariants deny a requested action."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(ProviderErrorCode.PERMISSION_DENIED, message, details)


class ProjectBindingError(ProviderError):
    """Raised when project ID or workspace identity does not strictly match."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(ProviderErrorCode.PROJECT_BINDING_FAILED, message, details)


class QuotaUnavailableError(ProviderError):
    """Raised when quota is exhausted or rate limit prohibits execution."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(ProviderErrorCode.QUOTA_UNAVAILABLE, message, details)


class ProviderUnavailableError(ProviderError):
    """Raised when requested provider or model is not registered, offline, or unavailable."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(ProviderErrorCode.PROVIDER_UNAVAILABLE, message, details)


class ResultAcceptanceError(ProviderError):
    """Raised when provider returned output that violates acceptance criteria or schema."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(ProviderErrorCode.RESULT_REJECTED_BY_ACCEPTANCE, message, details)


class TamperDetectionError(ProviderError):
    """Raised when a content hash does not match canonical payload bytes."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(ProviderErrorCode.EXECUTION_FAILED, message, details)


def assert_provider_error_does_not_pollute_scientific_decision(error: Exception) -> None:
    """Verify and enforce that provider error cannot be converted to a scientific decision.

    Provider errors indicate infrastructure / operational failures, not research rejection
    or promotion of an alpha hypothesis proposition.
    """
    if isinstance(error, ProviderError):
        # Explicit guard against mapping to scientific verdicts
        forbidden_verdicts = {"REJECT", "PROMOTE", "ADMISSION_FAILED", "NEED_MORE_EVIDENCE"}
        for k, v in error.details.items():
            if str(v).upper() in forbidden_verdicts or k in ("decision", "scientific_verdict"):
                raise ValueError(
                    f"Violation: ProviderError details contain forbidden scientific verdict: {k}={v}"
                )


class ResearchMemoryAccessError(ProviderError):
    """Base error for Controlled Research Memory View access control failure."""

    def __init__(
        self,
        message: str,
        reason_code: str = "MEMORY_PERMISSION_DENIED",
        details: dict[str, Any] | None = None,
    ) -> None:
        det = dict(details or {})
        det["reason_code"] = reason_code
        super().__init__(ProviderErrorCode.PERMISSION_DENIED, message, det)
        self.reason_code = reason_code


class ResearchMemoryPermissionError(ResearchMemoryAccessError):
    """Raised when role or authorization scope lacks read_research_memory permission."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, reason_code="MEMORY_PERMISSION_DENIED", details=details)


class ResearchMemoryCategoryError(ResearchMemoryAccessError):
    """Raised when query requests an unknown or unauthorized memory category."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, reason_code="MEMORY_CATEGORY_DENIED", details=details)


class ResearchMemoryLimitError(ResearchMemoryAccessError):
    """Raised when requested query limit exceeds bounded policy maximum."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, reason_code="MEMORY_LIMIT_EXCEEDED", details=details)


class ResearchMemorySourceCorruptionError(ResearchMemoryAccessError):
    """Raised when source research record content/decision/evidence hash is corrupted."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, reason_code="MEMORY_SOURCE_CORRUPT", details=details)
