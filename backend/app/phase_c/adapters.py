"""Offline fakes used to exercise Phase C service boundaries.

They are intentionally *not* a custody implementation or an execution
runtime.  Their state is private to the fake adapters, which lets Control
exercise RBAC, expected-version, idempotency, retry and unknown-outcome rules
without gaining a writable production state store.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from shared.phase_c_workflow.v1 import (
    FALSE_AUTHORITY_FLAGS,
    PhaseCWorkflowError,
    assert_false_authority_flags,
    sha256,
)

from .models import (
    AuthorizationCommandDTO,
    AuthorizationStatusDTO,
    CustodyReceiptDTO,
    ExecutionProjectionDTO,
    SignedArtifactUploadDTO,
)


class WorkflowAdapterError(RuntimeError):
    code = "PHASE_C_ADAPTER_REJECTED"
    status_code = 409


class ExpectedVersionError(WorkflowAdapterError):
    code = "PHASE_C_EXPECTED_VERSION_CONFLICT"


class IdempotencyConflictError(WorkflowAdapterError):
    code = "PHASE_C_IDEMPOTENCY_CONFLICT"


class UnknownOutcomeError(WorkflowAdapterError):
    code = "PHASE_C_UNKNOWN_OUTCOME"
    status_code = 503


def _ensure_signed_artifact(value: dict[str, Any]) -> tuple[str, str]:
    """Shape-check a pre-signed handoff without accessing keys or signing."""
    required = {
        "schema_version",
        "request_id",
        "domain",
        "signer_key_id",
        "signer_key_version",
        "requested_at",
        "expires_at",
        "artifact",
        "signature",
    }
    if (
        set(value) != required
        or value.get("schema_version") != "web-bridge-signed-artifact-v1"
    ):
        raise WorkflowAdapterError(
            "signed artifact does not match the offline handoff contract"
        )
    artifact = value.get("artifact")
    if not isinstance(artifact, dict):
        raise WorkflowAdapterError("signed artifact envelope is required")
    try:
        assert_false_authority_flags(artifact.get("payload", artifact))
    except PhaseCWorkflowError as exc:
        raise WorkflowAdapterError(
            "signed artifact attempts to grant authority"
        ) from exc
    artifact_id = artifact.get("artifact_id")
    if not isinstance(artifact_id, str) or not artifact_id:
        raise WorkflowAdapterError("signed artifact envelope lacks artifact_id")
    if not isinstance(value.get("signature"), str) or not value["signature"]:
        raise WorkflowAdapterError("signed artifact signature is required")
    return artifact_id, sha256(value)


@dataclass
class OfflineFakeCustodyAdapter:
    """Test-only substitute for the external custody service."""

    version: int = 0
    receipts_by_key: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    receipts: dict[str, dict[str, Any]] = field(default_factory=dict)

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        fingerprint = sha256(request.model_dump(mode="json"))
        existing = self.receipts_by_key.get(request.idempotency_key)
        if existing:
            if existing[0] != fingerprint:
                raise IdempotencyConflictError(
                    "idempotency key is bound to a different custody request"
                )
            return CustodyReceiptDTO.model_validate(existing[1])
        if request.expected_custody_version != self.version:
            raise ExpectedVersionError("custody expected version is stale")
        artifact_id, artifact_sha256 = _ensure_signed_artifact(request.signed_artifact)
        self.version += 1
        receipt = CustodyReceiptDTO(
            receipt_id=f"custody-install-{self.version}",
            receipt_type="install",
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            custody_version=self.version,
            idempotency_key=request.idempotency_key,
        ).model_dump(mode="json")
        self.receipts_by_key[request.idempotency_key] = (fingerprint, receipt)
        self.receipts[receipt["receipt_id"]] = receipt
        return CustodyReceiptDTO.model_validate(receipt)

    def receipt(self, receipt_id: str) -> CustodyReceiptDTO | None:
        value = self.receipts.get(receipt_id)
        return CustodyReceiptDTO.model_validate(value) if value else None


@dataclass
class OfflineFakeExecutionAdapter:
    """Test-only typed authorization/execution projection endpoint."""

    version: int = 0
    requested_state: str = "DISABLED"
    artifact_id: str | None = None
    receipt_id: str | None = None
    commands_by_key: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    audit_log: list[dict[str, Any]] = field(default_factory=list)
    archive_log: list[dict[str, Any]] = field(default_factory=list)
    unknown_outcome_once: bool = False

    def status(self) -> AuthorizationStatusDTO:
        return AuthorizationStatusDTO(
            version=self.version,
            requested_state=self.requested_state,
            artifact_id=self.artifact_id,
            receipt_id=self.receipt_id,
        )

    def command(
        self,
        request: AuthorizationCommandDTO,
        *,
        custody_receipt: CustodyReceiptDTO | None,
    ) -> AuthorizationStatusDTO:
        fingerprint = sha256(request.model_dump(mode="json"))
        existing = self.commands_by_key.get(request.idempotency_key)
        if existing:
            if existing[0] != fingerprint:
                raise IdempotencyConflictError(
                    "idempotency key is bound to a different authorization command"
                )
            return AuthorizationStatusDTO.model_validate(existing[1])
        if request.expected_version != self.version:
            raise ExpectedVersionError(
                "execution authorization expected version is stale"
            )
        if (
            custody_receipt is None
            or custody_receipt.receipt_id != request.custody_receipt_id
        ):
            raise WorkflowAdapterError(
                "authorization command is not bound to a custody receipt"
            )
        if custody_receipt.artifact_id != request.authorization_artifact_id:
            raise WorkflowAdapterError(
                "authorization artifact and custody receipt do not match"
            )
        if request.action == "enable" and (
            custody_receipt.artifact_type,
            custody_receipt.trust_domain,
            custody_receipt.schema_ref,
        ) != (
            "runtime-authorization",
            "runtime_authorization",
            "phase-c-runtime-authorization-v1",
        ):
            raise WorkflowAdapterError(
                "enable authorization requires a runtime-authorization custody receipt"
            )
        # Model a network ambiguity after durable acceptance.  The caller must
        # retry/query with exactly the same idempotency key, never create a new one.
        self.version += 1
        self.requested_state = (
            "ENABLE_REQUESTED" if request.action == "enable" else "REVOKED"
        )
        self.artifact_id = request.authorization_artifact_id
        self.receipt_id = request.custody_receipt_id
        status = self.status().model_dump(mode="json")
        self.commands_by_key[request.idempotency_key] = (fingerprint, status)
        event = {
            "command_id": request.command_id,
            "idempotency_key": request.idempotency_key,
            "action": request.action,
            "version": self.version,
            "runtime_mutation_allowed": False,
            **FALSE_AUTHORITY_FLAGS,
        }
        self.audit_log.append(event)
        self.archive_log.append({"kind": "authorization-command", **event})
        if self.unknown_outcome_once:
            self.unknown_outcome_once = False
            raise UnknownOutcomeError(
                "authorization result is unknown; retry/query only with same idempotency key"
            )
        return AuthorizationStatusDTO.model_validate(status)

    def by_key(self, idempotency_key: str) -> AuthorizationStatusDTO | None:
        item = self.commands_by_key.get(idempotency_key)
        return AuthorizationStatusDTO.model_validate(item[1]) if item else None

    def projection(self) -> ExecutionProjectionDTO:
        return ExecutionProjectionDTO(
            status="ARCHIVED" if self.archive_log else "OFFLINE",
            audit=deepcopy(self.audit_log),
            archive=deepcopy(self.archive_log),
        )


@dataclass
class OfflineFakeWorkflowAdapter:
    custody: OfflineFakeCustodyAdapter = field(
        default_factory=OfflineFakeCustodyAdapter
    )
    execution: OfflineFakeExecutionAdapter = field(
        default_factory=OfflineFakeExecutionAdapter
    )


__all__ = [
    "ExpectedVersionError",
    "IdempotencyConflictError",
    "OfflineFakeWorkflowAdapter",
    "UnknownOutcomeError",
    "WorkflowAdapterError",
]
