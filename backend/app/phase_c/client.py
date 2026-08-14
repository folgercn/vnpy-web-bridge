"""Narrow Control clients for private custody and execution services."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .adapters import (
    OfflineFakeWorkflowAdapter,
    UnknownOutcomeError,
    WorkflowAdapterError,
)
from .models import (
    AuthorizationCommandDTO,
    AuthorizationStatusDTO,
    CustodyReceiptDTO,
    ExecutionProjectionDTO,
    SignedArtifactUploadDTO,
    TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS,
    TrustedKeylessCustodyReceiptDTO,
    TrustedKeylessTargetPlanUploadDTO,
)

CustodyInstallReceipt = CustodyReceiptDTO | TrustedKeylessCustodyReceiptDTO


class PhaseCWorkflowClient(Protocol):
    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO: ...
    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO: ...
    def custody_receipt(self, receipt_id: str) -> CustodyInstallReceipt | None: ...
    def custody_receipt_by_idempotency(
        self, idempotency_key: str
    ) -> CustodyInstallReceipt | None: ...
    def authorization_status(self) -> AuthorizationStatusDTO: ...
    def authorization_command(
        self, request: AuthorizationCommandDTO
    ) -> AuthorizationStatusDTO: ...
    def authorization_receipt(
        self, idempotency_key: str
    ) -> AuthorizationStatusDTO | None: ...
    def execution_projection(self) -> ExecutionProjectionDTO: ...


class OfflineFakeWorkflowClient:
    """Test dependency injection only; never selected from runtime environment."""

    def __init__(self, adapter: OfflineFakeWorkflowAdapter | None = None) -> None:
        self.adapter = adapter or OfflineFakeWorkflowAdapter()

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        return self.adapter.custody.install(request)

    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        del request
        raise WorkflowAdapterError("trusted keyless custody is unavailable in offline fake")

    def custody_receipt(self, receipt_id: str) -> CustodyInstallReceipt | None:
        return self.adapter.custody.receipt(receipt_id)

    def custody_receipt_by_idempotency(
        self, idempotency_key: str
    ) -> CustodyInstallReceipt | None:
        return None

    def authorization_status(self) -> AuthorizationStatusDTO:
        return self.adapter.execution.status()

    def authorization_command(
        self, request: AuthorizationCommandDTO
    ) -> AuthorizationStatusDTO:
        return self.adapter.execution.command(
            request,
            custody_receipt=self.adapter.custody.receipt(request.custody_receipt_id),
        )

    def authorization_receipt(
        self, idempotency_key: str
    ) -> AuthorizationStatusDTO | None:
        return self.adapter.execution.by_key(idempotency_key)

    def execution_projection(self) -> ExecutionProjectionDTO:
        return self.adapter.execution.projection()


@dataclass(frozen=True)
class PhaseCRemoteSettings:
    custody_url: str
    execution_url: str
    custody_secret: str
    execution_secret: str
    timeout_seconds: float = 3.0

    @classmethod
    def from_env(cls) -> PhaseCRemoteSettings:
        try:
            timeout = min(
                15.0, max(0.1, float(os.getenv("PHASE_C_PRIVATE_TIMEOUT_SECONDS", "3")))
            )
        except ValueError as exc:
            raise ValueError("PHASE_C_PRIVATE_TIMEOUT_SECONDS is invalid") from exc
        return cls(
            os.environ["PHASE_C_CUSTODY_URL"].rstrip("/"),
            os.environ["PHASE_C_EXECUTION_URL"].rstrip("/"),
            os.environ["PHASE_C_CUSTODY_SHARED_SECRET"],
            os.environ["PHASE_C_EXECUTION_SHARED_SECRET"],
            timeout,
        )


class RemotePhaseCWorkflowClient:
    """No retry is performed for mutations; timeout means unknown outcome."""

    def __init__(
        self,
        settings: PhaseCRemoteSettings | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings or PhaseCRemoteSettings.from_env()
        self.transport = transport

    def _request(
        self,
        base: str,
        secret: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        mutation: bool = False,
    ) -> dict[str, Any] | None:
        try:
            with httpx.Client(
                timeout=self.settings.timeout_seconds,
                transport=self.transport,
                headers={
                    "X-Phase-C-Principal": "control-api",
                    "X-Phase-C-Custody-Secret": secret,
                    "X-Phase-C-Execution-Secret": secret,
                },
            ) as client:
                response = client.request(method, f"{base}{path}", json=payload)
        except (
            httpx.TimeoutException,
            asyncio.TimeoutError,
            httpx.NetworkError,
        ) as exc:
            if mutation:
                raise UnknownOutcomeError(
                    "private mutation outcome unknown; query same idempotency key"
                ) from exc
            raise WorkflowAdapterError(
                "private Phase C dependency is unavailable"
            ) from exc
        except httpx.HTTPError as exc:
            raise WorkflowAdapterError(
                "private Phase C dependency is unavailable"
            ) from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise WorkflowAdapterError("private Phase C request was rejected")
        try:
            body = response.json()
        except ValueError as exc:
            raise WorkflowAdapterError("private Phase C response is invalid") from exc
        return body if isinstance(body, dict) else None

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "POST",
            "/internal/v1/publish-install",
            request.model_dump(mode="json"),
            mutation=True,
        )
        return CustodyReceiptDTO.model_validate(raw)

    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "POST",
            "/internal/v1/publish-keyless-simnow-target-plan",
            request.model_dump(mode="json"),
            mutation=True,
        )
        return TrustedKeylessCustodyReceiptDTO.model_validate(raw)

    @staticmethod
    def _custody_receipt(raw: dict[str, Any] | None) -> CustodyInstallReceipt | None:
        if raw is None:
            return None
        if raw.get("schema_ref") in TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS:
            return TrustedKeylessCustodyReceiptDTO.model_validate(raw)
        return CustodyReceiptDTO.model_validate(raw)

    def custody_receipt(self, receipt_id: str) -> CustodyInstallReceipt | None:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "GET",
            f"/internal/v1/receipts/{receipt_id}",
        )
        return self._custody_receipt(raw)

    def custody_receipt_by_idempotency(
        self, idempotency_key: str
    ) -> CustodyInstallReceipt | None:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "GET",
            f"/internal/v1/receipts-by-idempotency/{idempotency_key}",
        )
        return self._custody_receipt(raw)

    def authorization_status(self) -> AuthorizationStatusDTO:
        return AuthorizationStatusDTO.model_validate(
            self._request(
                self.settings.execution_url,
                self.settings.execution_secret,
                "GET",
                "/internal/v1/phase-c/internal/v1/authorization/status",
            )
        )

    def authorization_command(
        self, request: AuthorizationCommandDTO
    ) -> AuthorizationStatusDTO:
        raw = self._request(
            self.settings.execution_url,
            self.settings.execution_secret,
            "POST",
            "/internal/v1/phase-c/internal/v1/authorization/commands",
            request.model_dump(mode="json"),
            mutation=True,
        )
        return AuthorizationStatusDTO.model_validate(raw)

    def authorization_receipt(
        self, idempotency_key: str
    ) -> AuthorizationStatusDTO | None:
        raw = self._request(
            self.settings.execution_url,
            self.settings.execution_secret,
            "GET",
            f"/internal/v1/phase-c/internal/v1/authorization/receipts/{idempotency_key}",
        )
        return AuthorizationStatusDTO.model_validate(raw) if raw else None

    def execution_projection(self) -> ExecutionProjectionDTO:
        return ExecutionProjectionDTO.model_validate(
            self._request(
                self.settings.execution_url,
                self.settings.execution_secret,
                "GET",
                "/internal/v1/phase-c/internal/v1/projection",
            )
        )


class UnconfiguredPhaseCWorkflowClient:
    @staticmethod
    def _unavailable() -> None:
        raise WorkflowAdapterError(
            "Phase C custody/execution dependency is not configured"
        )

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        del request
        self._unavailable()

    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        del request
        self._unavailable()

    def custody_receipt(self, receipt_id: str) -> CustodyInstallReceipt | None:
        del receipt_id
        self._unavailable()

    def custody_receipt_by_idempotency(
        self, idempotency_key: str
    ) -> CustodyInstallReceipt | None:
        del idempotency_key
        self._unavailable()

    def authorization_status(self) -> AuthorizationStatusDTO:
        self._unavailable()

    def authorization_command(
        self, request: AuthorizationCommandDTO
    ) -> AuthorizationStatusDTO:
        del request
        self._unavailable()

    def authorization_receipt(
        self, idempotency_key: str
    ) -> AuthorizationStatusDTO | None:
        del idempotency_key
        self._unavailable()

    def execution_projection(self) -> ExecutionProjectionDTO:
        self._unavailable()


try:
    phase_c_workflow_client: PhaseCWorkflowClient = RemotePhaseCWorkflowClient()
except (KeyError, ValueError):
    phase_c_workflow_client = UnconfiguredPhaseCWorkflowClient()
