"""Narrow Control clients for private custody and execution services."""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from shared.artifact_contracts.v1 import (
    ContractError as ArtifactContractError,
)
from shared.artifact_contracts.v1 import validate_artifact_envelope
from shared.phase_c_workflow.continuous_event_v1 import (
    CONTINUOUS_EVENT_ARTIFACT_TYPE,
    CONTINUOUS_EVENT_SCHEMA_VERSION,
    CONTINUOUS_EVENT_SCOPE,
    CONTINUOUS_EVENT_TRUST_DOMAIN,
    ContinuousEventContractError,
    validate_simnow_continuous_event_v1,
)

from .adapters import (
    OfflineFakeWorkflowAdapter,
    UnknownOutcomeError,
    WorkflowAdapterError,
)
from .models import (
    AuthorizationCommandDTO,
    AuthorizationStatusDTO,
    ContinuousEventHeadDTO,
    ContinuousEventPublicationProjectionDTO,
    CustodyCurrentVersionDTO,
    CustodyReceiptDTO,
    ExecutionProjectionDTO,
    SignedArtifactUploadDTO,
    TargetPlanPublicationProjectionDTO,
    TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS,
    TrustedKeylessContinuousEventArtifactDTO,
    TrustedKeylessContinuousEventInstallContinuationDTO,
    TrustedKeylessContinuousEventReceiptDTO,
    TrustedKeylessContinuousEventUploadDTO,
    TrustedKeylessCustodyReceiptDTO,
    TrustedKeylessTargetPlanInstallContinuationDTO,
    TrustedKeylessTargetPlanUploadDTO,
)

CustodyInstallReceipt = (
    CustodyReceiptDTO
    | TrustedKeylessCustodyReceiptDTO
    | TrustedKeylessContinuousEventReceiptDTO
)


class PhaseCWorkflowClient(Protocol):
    def custody_current_version(self) -> CustodyCurrentVersionDTO: ...
    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO: ...
    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO: ...
    def target_plan_publication(
        self, idempotency_key: str
    ) -> TargetPlanPublicationProjectionDTO: ...
    def install_published_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanInstallContinuationDTO
    ) -> TrustedKeylessCustodyReceiptDTO: ...
    def install_trusted_keyless_continuous_event(
        self, request: TrustedKeylessContinuousEventUploadDTO
    ) -> TrustedKeylessContinuousEventReceiptDTO: ...
    def continuous_event_publication(
        self, idempotency_key: str
    ) -> ContinuousEventPublicationProjectionDTO: ...
    def continuous_event_head(self) -> ContinuousEventHeadDTO: ...
    def install_published_trusted_keyless_continuous_event(
        self, request: TrustedKeylessContinuousEventInstallContinuationDTO
    ) -> TrustedKeylessContinuousEventReceiptDTO: ...
    def installed_continuous_event(
        self, idempotency_key: str
    ) -> TrustedKeylessContinuousEventArtifactDTO | None: ...
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

    def custody_current_version(self) -> CustodyCurrentVersionDTO:
        return CustodyCurrentVersionDTO(version=self.adapter.custody.version)

    def install(self, request: SignedArtifactUploadDTO) -> CustodyReceiptDTO:
        return self.adapter.custody.install(request)

    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        del request
        raise WorkflowAdapterError(
            "trusted keyless custody is unavailable in offline fake"
        )

    def target_plan_publication(
        self, idempotency_key: str
    ) -> TargetPlanPublicationProjectionDTO:
        return TargetPlanPublicationProjectionDTO(
            state="NOT_PUBLISHED",
            idempotency_key=idempotency_key,
            install_idempotency_key=f"install-{idempotency_key}",
            observed_custody_version=self.adapter.custody.version,
        )

    def install_published_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanInstallContinuationDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        del request
        raise WorkflowAdapterError(
            "trusted keyless custody continuation is unavailable in offline fake"
        )

    def install_trusted_keyless_continuous_event(
        self, request: TrustedKeylessContinuousEventUploadDTO
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        del request
        raise WorkflowAdapterError(
            "trusted keyless continuous event custody is unavailable in offline fake"
        )

    def continuous_event_publication(
        self, idempotency_key: str
    ) -> ContinuousEventPublicationProjectionDTO:
        return ContinuousEventPublicationProjectionDTO(
            state="NOT_PUBLISHED",
            idempotency_key=idempotency_key,
            install_idempotency_key=f"install-{idempotency_key}",
            observed_custody_version=self.adapter.custody.version,
        )

    def continuous_event_head(self) -> ContinuousEventHeadDTO:
        raise WorkflowAdapterError(
            "authenticated continuous event head is unavailable in offline fake"
        )

    def install_published_trusted_keyless_continuous_event(
        self, request: TrustedKeylessContinuousEventInstallContinuationDTO
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        del request
        raise WorkflowAdapterError(
            "continuous event continuation is unavailable in offline fake"
        )

    def installed_continuous_event(
        self, idempotency_key: str
    ) -> TrustedKeylessContinuousEventArtifactDTO | None:
        del idempotency_key
        return None

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
        unknown_query_path: str | None = None,
        request_headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any] | None:
        headers = dict(request_headers or {})
        headers.update(
            {
                "X-Phase-C-Principal": "control-api",
                "X-Phase-C-Custody-Secret": secret,
                "X-Phase-C-Execution-Secret": secret,
            }
        )
        try:
            with httpx.Client(
                timeout=self.settings.timeout_seconds,
                transport=self.transport,
                headers=headers,
            ) as client:
                response = client.request(method, f"{base}{path}", json=payload)
        except (
            httpx.TimeoutException,
            asyncio.TimeoutError,
            httpx.NetworkError,
        ) as exc:
            if mutation:
                raise UnknownOutcomeError(
                    "private mutation outcome unknown; query same idempotency key",
                    detail={
                        "query_path": unknown_query_path,
                        "query_same_intent_only": True,
                    },
                    retryable=False,
                ) from exc
            raise WorkflowAdapterError(
                "private Phase C dependency is unavailable"
            ) from exc
        except httpx.HTTPError as exc:
            if mutation:
                raise UnknownOutcomeError(
                    "private mutation outcome unknown; query same idempotency key",
                    detail={
                        "query_path": unknown_query_path,
                        "query_same_intent_only": True,
                    },
                    retryable=False,
                ) from exc
            raise WorkflowAdapterError(
                "private Phase C dependency is unavailable"
            ) from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            try:
                error = response.json()
            except ValueError:
                error = None
            detail = error.get("detail") if isinstance(error, dict) else None
            if isinstance(detail, dict):
                code = detail.get("code")
                message = detail.get("message")
                retryable = detail.get("retryable")
                raise WorkflowAdapterError(
                    message
                    if isinstance(message, str) and message
                    else "private Phase C request was rejected",
                    code=code if isinstance(code, str) and code else None,
                    detail=detail,
                    status_code=response.status_code,
                    retryable=retryable if isinstance(retryable, bool) else None,
                )
            raise WorkflowAdapterError(
                "private Phase C request was rejected",
                detail=detail,
                status_code=response.status_code,
            )
        try:
            body = response.json()
        except ValueError as exc:
            if mutation:
                raise UnknownOutcomeError(
                    "private mutation returned an unclassifiable response; query exact intent",
                    detail={
                        "query_path": unknown_query_path,
                        "query_same_intent_only": True,
                    },
                    retryable=False,
                ) from exc
            raise WorkflowAdapterError("private Phase C response is invalid") from exc
        if not isinstance(body, dict):
            if mutation:
                raise UnknownOutcomeError(
                    "private mutation returned an unclassifiable response; query exact intent",
                    detail={
                        "query_path": unknown_query_path,
                        "query_same_intent_only": True,
                    },
                    retryable=False,
                )
            return None
        return body

    @staticmethod
    def _unknown_mutation_response(*, query_path: str) -> UnknownOutcomeError:
        return UnknownOutcomeError(
            "private mutation response does not bind the exact request; query exact intent",
            detail={
                "query_path": query_path,
                "query_same_intent_only": True,
            },
            retryable=False,
        )

    @classmethod
    def _keyless_receipt_for_request(
        cls,
        raw: dict[str, Any] | None,
        *,
        request: TrustedKeylessTargetPlanUploadDTO
        | TrustedKeylessTargetPlanInstallContinuationDTO,
        query_path: str,
        custody_version: int,
    ) -> TrustedKeylessCustodyReceiptDTO:
        try:
            receipt = TrustedKeylessCustodyReceiptDTO.model_validate(raw)
            if isinstance(request, TrustedKeylessTargetPlanUploadDTO):
                artifact = validate_artifact_envelope(request.artifact)
                payload = artifact["payload"]
                artifact_id = artifact["artifact_id"]
                artifact_raw_sha256 = artifact["raw_sha256"]
                artifact_schema_ref = artifact["schema_ref"]
                scope = artifact["scope"]
                payload_schema_ref = (
                    payload.get("schema_version")
                    if isinstance(payload, Mapping)
                    else None
                )
                expires_at = (
                    payload.get("expires_at") if isinstance(payload, Mapping) else None
                )
            else:
                artifact_id = request.artifact_id
                artifact_raw_sha256 = request.artifact_raw_sha256
                artifact_schema_ref = request.artifact_schema_ref
                payload_schema_ref = request.plan_schema_version
                scope = request.scope.model_dump(mode="json")
                expires_at = request.plan_expires_at
            if (
                receipt.idempotency_key != f"install-{request.idempotency_key}"
                or artifact_schema_ref != payload_schema_ref
                or receipt.artifact_id != artifact_id
                or receipt.artifact_sha256 != artifact_raw_sha256
                or receipt.schema_ref != artifact_schema_ref
                or receipt.scope != scope
                or receipt.expires_at != expires_at
                or receipt.custody_version != custody_version
            ):
                raise ValueError("trusted keyless receipt identity mismatches")
            return receipt
        except (
            ArtifactContractError,
            TypeError,
            ValueError,
        ) as exc:
            raise cls._unknown_mutation_response(query_path=query_path) from exc

    @classmethod
    def _event_receipt_for_request(
        cls,
        raw: dict[str, Any] | None,
        *,
        request: TrustedKeylessContinuousEventUploadDTO
        | TrustedKeylessContinuousEventInstallContinuationDTO,
        query_path: str,
        custody_version: int,
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        try:
            receipt = TrustedKeylessContinuousEventReceiptDTO.model_validate(raw)
            artifact = validate_artifact_envelope(request.artifact)
            event = validate_simnow_continuous_event_v1(artifact["payload"])
            if (
                artifact["artifact_type"] != CONTINUOUS_EVENT_ARTIFACT_TYPE
                or artifact["trust_domain"] != CONTINUOUS_EVENT_TRUST_DOMAIN
                or artifact["schema_ref"] != CONTINUOUS_EVENT_SCHEMA_VERSION
                or artifact["scope"] != CONTINUOUS_EVENT_SCOPE
                or receipt.idempotency_key != f"install-{request.idempotency_key}"
                or receipt.artifact_id != artifact["artifact_id"]
                or receipt.artifact_sha256 != artifact["raw_sha256"]
                or request.idempotency_key != event["event_id"]
                or receipt.event_id != event["event_id"]
                or receipt.trigger_kind != event["trigger_kind"]
                or receipt.daily_official_day != event["daily"]["official_day"]
                or receipt.custody_version != custody_version
            ):
                raise ValueError("continuous event receipt identity mismatches")
            return receipt
        except (
            ArtifactContractError,
            ContinuousEventContractError,
            TypeError,
            ValueError,
        ) as exc:
            raise cls._unknown_mutation_response(query_path=query_path) from exc

    def custody_current_version(self) -> CustodyCurrentVersionDTO:
        try:
            with httpx.Client(
                timeout=self.settings.timeout_seconds,
                transport=self.transport,
                headers={
                    "X-Phase-C-Principal": "control-api",
                    "X-Phase-C-Custody-Secret": self.settings.custody_secret,
                },
            ) as client:
                response = client.get(
                    f"{self.settings.custody_url}/internal/v1/current-version"
                )
        except (
            httpx.TimeoutException,
            asyncio.TimeoutError,
            httpx.NetworkError,
            httpx.HTTPError,
        ) as exc:
            raise WorkflowAdapterError(
                "private Phase C custody version is unavailable",
                status_code=503,
            ) from exc
        try:
            raw = response.json()
        except ValueError as exc:
            raise WorkflowAdapterError(
                "private Phase C custody version response is invalid",
                detail={"status_code": response.status_code},
                status_code=502,
            ) from exc
        if response.status_code >= 400:
            detail = (
                raw.get("detail", raw.get("error", raw))
                if isinstance(raw, dict)
                else raw
            )
            raise WorkflowAdapterError(
                "private Phase C custody version request was rejected",
                detail=detail,
                status_code=response.status_code,
            )
        try:
            return CustodyCurrentVersionDTO.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise WorkflowAdapterError(
                "private Phase C custody version response is invalid",
                status_code=502,
            ) from exc

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
        query_path = (
            "/internal/v1/target-plan-publications/by-idempotency/"
            f"{request.idempotency_key}"
        )
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "POST",
            "/internal/v1/publish-keyless-simnow-target-plan",
            request.model_dump(mode="json"),
            mutation=True,
            unknown_query_path=query_path,
        )
        return self._keyless_receipt_for_request(
            raw,
            request=request,
            query_path=query_path,
            custody_version=request.expected_custody_version + 2,
        )

    def target_plan_publication(
        self, idempotency_key: str
    ) -> TargetPlanPublicationProjectionDTO:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "GET",
            f"/internal/v1/target-plan-publications/by-idempotency/{idempotency_key}",
        )
        try:
            projection = TargetPlanPublicationProjectionDTO.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise WorkflowAdapterError(
                "private Phase C publication response is invalid",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            ) from exc
        if projection.idempotency_key != idempotency_key:
            raise WorkflowAdapterError(
                "private Phase C publication response key mismatches",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            )
        return projection

    def install_published_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanInstallContinuationDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        query_path = (
            "/internal/v1/target-plan-publications/by-idempotency/"
            f"{request.idempotency_key}"
        )
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "POST",
            "/internal/v1/install-published-keyless-simnow-target-plan",
            request.model_dump(mode="json"),
            mutation=True,
            unknown_query_path=query_path,
        )
        return self._keyless_receipt_for_request(
            raw,
            request=request,
            query_path=query_path,
            custody_version=request.publish_resulting_custody_version + 1,
        )

    def install_trusted_keyless_continuous_event(
        self,
        request: TrustedKeylessContinuousEventUploadDTO,
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        query_path = (
            "/internal/v1/continuous-event-publications/by-idempotency/"
            f"{request.idempotency_key}"
        )
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "POST",
            "/internal/v1/publish-keyless-simnow-continuous-event",
            request.model_dump(mode="json"),
            mutation=True,
            unknown_query_path=query_path,
        )
        return self._event_receipt_for_request(
            raw,
            request=request,
            query_path=query_path,
            custody_version=request.expected_custody_version + 2,
        )

    def continuous_event_publication(
        self,
        idempotency_key: str,
    ) -> ContinuousEventPublicationProjectionDTO:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "GET",
            "/internal/v1/continuous-event-publications/by-idempotency/"
            f"{idempotency_key}",
        )
        try:
            projection = ContinuousEventPublicationProjectionDTO.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise WorkflowAdapterError(
                "private Phase C continuous event publication response is invalid",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            ) from exc
        if projection.idempotency_key != idempotency_key or (
            projection.state != "NOT_PUBLISHED"
            and projection.event_id != idempotency_key
        ):
            raise WorkflowAdapterError(
                "private Phase C continuous event publication key mismatches",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            )
        return projection

    def continuous_event_head(self) -> ContinuousEventHeadDTO:
        request_nonce = secrets.token_hex(32)
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "GET",
            "/internal/v1/continuous-event-head",
            request_headers={"X-Phase-C-Request-Nonce": request_nonce},
        )
        try:
            result = ContinuousEventHeadDTO.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise WorkflowAdapterError(
                "private Phase C continuous event head response is invalid",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            ) from exc
        if result.request_nonce != request_nonce or not result.verify_custody_hmac(
            self.settings.custody_secret
        ):
            raise WorkflowAdapterError(
                "private Phase C continuous event head authentication failed",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            )
        return result

    def install_published_trusted_keyless_continuous_event(
        self,
        request: TrustedKeylessContinuousEventInstallContinuationDTO,
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        query_path = (
            "/internal/v1/continuous-event-publications/by-idempotency/"
            f"{request.idempotency_key}"
        )
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "POST",
            "/internal/v1/install-published-keyless-simnow-continuous-event",
            request.model_dump(mode="json"),
            mutation=True,
            unknown_query_path=query_path,
        )
        return self._event_receipt_for_request(
            raw,
            request=request,
            query_path=query_path,
            custody_version=request.publish_resulting_custody_version + 1,
        )

    def installed_continuous_event(
        self,
        idempotency_key: str,
    ) -> TrustedKeylessContinuousEventArtifactDTO | None:
        raw = self._request(
            self.settings.custody_url,
            self.settings.custody_secret,
            "GET",
            f"/internal/v1/continuous-events/by-idempotency/{idempotency_key}",
        )
        if raw is None:
            return None
        try:
            result = TrustedKeylessContinuousEventArtifactDTO.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise WorkflowAdapterError(
                "private Phase C continuous event response is invalid",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            ) from exc
        if (
            result.idempotency_key != idempotency_key
            or result.artifact["payload"]["event_id"] != idempotency_key
        ):
            raise WorkflowAdapterError(
                "private Phase C continuous event key mismatches",
                code="PHASE_C_RESPONSE_BINDING_INVALID",
                status_code=502,
                retryable=False,
            )
        return result

    @staticmethod
    def _custody_receipt(raw: dict[str, Any] | None) -> CustodyInstallReceipt | None:
        if raw is None:
            return None
        if raw.get("schema_ref") in TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS:
            return TrustedKeylessCustodyReceiptDTO.model_validate(raw)
        if raw.get("schema_ref") == CONTINUOUS_EVENT_SCHEMA_VERSION:
            return TrustedKeylessContinuousEventReceiptDTO.model_validate(raw)
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

    def custody_current_version(self) -> CustodyCurrentVersionDTO:
        self._unavailable()

    def install_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanUploadDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        del request
        self._unavailable()

    def target_plan_publication(
        self, idempotency_key: str
    ) -> TargetPlanPublicationProjectionDTO:
        del idempotency_key
        self._unavailable()

    def install_published_trusted_keyless_target_plan(
        self, request: TrustedKeylessTargetPlanInstallContinuationDTO
    ) -> TrustedKeylessCustodyReceiptDTO:
        del request
        self._unavailable()

    def install_trusted_keyless_continuous_event(
        self, request: TrustedKeylessContinuousEventUploadDTO
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        del request
        self._unavailable()

    def continuous_event_publication(
        self, idempotency_key: str
    ) -> ContinuousEventPublicationProjectionDTO:
        del idempotency_key
        self._unavailable()

    def continuous_event_head(self) -> ContinuousEventHeadDTO:
        self._unavailable()

    def install_published_trusted_keyless_continuous_event(
        self, request: TrustedKeylessContinuousEventInstallContinuationDTO
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        del request
        self._unavailable()

    def installed_continuous_event(
        self, idempotency_key: str
    ) -> TrustedKeylessContinuousEventArtifactDTO | None:
        del idempotency_key
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
