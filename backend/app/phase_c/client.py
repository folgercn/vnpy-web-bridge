"""Control-side client for the Phase C workflow dependencies.

The default exists only for test/local offline workflows.  Production must
inject remote custody/execution clients; this module never becomes their state
owner and has no signing, RPC or trading imports.
"""

from __future__ import annotations

import os
from typing import Protocol

from .adapters import OfflineFakeWorkflowAdapter, WorkflowAdapterError
from .models import (
    AuthorizationCommandDTO,
    AuthorizationStatusDTO,
    CustodyReceiptDTO,
    ExecutionProjectionDTO,
    SignedArtifactUploadDTO,
)


class PhaseCWorkflowClient(Protocol):
    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO: ...
    def custody_receipt(self, receipt_id: str) -> CustodyReceiptDTO | None: ...
    def authorization_status(self) -> AuthorizationStatusDTO: ...
    def authorization_command(self, request: AuthorizationCommandDTO) -> AuthorizationStatusDTO: ...
    def authorization_receipt(self, idempotency_key: str) -> AuthorizationStatusDTO | None: ...
    def execution_projection(self) -> ExecutionProjectionDTO: ...


class OfflineFakeWorkflowClient:
    def __init__(self, adapter: OfflineFakeWorkflowAdapter | None = None) -> None:
        self.adapter = adapter or OfflineFakeWorkflowAdapter()

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        return self.adapter.custody.install(request)

    def custody_receipt(self, receipt_id: str) -> CustodyReceiptDTO | None:
        return self.adapter.custody.receipt(receipt_id)

    def authorization_status(self) -> AuthorizationStatusDTO:
        return self.adapter.execution.status()

    def authorization_command(self, request: AuthorizationCommandDTO) -> AuthorizationStatusDTO:
        return self.adapter.execution.command(
            request, custody_receipt=self.adapter.custody.receipt(request.custody_receipt_id)
        )

    def authorization_receipt(self, idempotency_key: str) -> AuthorizationStatusDTO | None:
        return self.adapter.execution.by_key(idempotency_key)

    def execution_projection(self) -> ExecutionProjectionDTO:
        return self.adapter.execution.projection()


class UnconfiguredPhaseCWorkflowClient:
    """Fail closed until a real private custody/execution client is injected."""

    @staticmethod
    def _unavailable() -> None:
        raise WorkflowAdapterError("Phase C custody/execution dependency is not configured")

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        del request
        self._unavailable()

    def custody_receipt(self, receipt_id: str) -> CustodyReceiptDTO | None:
        del receipt_id
        self._unavailable()

    def authorization_status(self) -> AuthorizationStatusDTO:
        self._unavailable()

    def authorization_command(self, request: AuthorizationCommandDTO) -> AuthorizationStatusDTO:
        del request
        self._unavailable()

    def authorization_receipt(self, idempotency_key: str) -> AuthorizationStatusDTO | None:
        del idempotency_key
        self._unavailable()

    def execution_projection(self) -> ExecutionProjectionDTO:
        self._unavailable()


# A fake is enabled only by a deliberate test/local flag.  A normal Control
# process otherwise fails closed rather than silently becoming a state owner.
phase_c_workflow_client: PhaseCWorkflowClient
if os.getenv("PHASE_C_OFFLINE_FAKE_ADAPTER_ENABLED", "").strip().lower() == "true":
    phase_c_workflow_client = OfflineFakeWorkflowClient()
else:
    phase_c_workflow_client = UnconfiguredPhaseCWorkflowClient()
