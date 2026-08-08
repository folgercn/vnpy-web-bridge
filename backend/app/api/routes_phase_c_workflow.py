"""Browser-safe Phase C MAP/C_FAST → custody → execution workflow routes.

This router is a Control projection and command issuer only.  Signing remains
an offline export, custody owns artifact/receipt state, and execution owns its
authorization/audit/archive state.  The bundled adapter is an explicit fake
for contract tests; every authority flag stays false.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.core.errors import AppError, ok
from app.core.security import CurrentUser, require_roles
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.client import phase_c_workflow_client
from app.phase_c.models import (
    AuthorizationCommandDTO,
    SignedArtifactUploadDTO,
    SigningRequestCreateDTO,
    WorkflowStatusDTO,
)
from shared.phase_c_workflow.v1 import PhaseCWorkflowError, build_signing_request

router = APIRouter(prefix="/api/phase-c", tags=["phase-c-workflow"])
Reader = Annotated[CurrentUser, Depends(require_roles("viewer", "trader", "admin"))]
Admin = Annotated[CurrentUser, Depends(require_roles("admin"))]


def _adapter_error(exc: WorkflowAdapterError) -> AppError:
    return AppError(
        str(exc),
        code=exc.code,
        status_code=exc.status_code,
        detail={"fail_closed": True},
    )


@router.get("/workflow/status")
def workflow_status(_: Reader) -> dict[str, Any]:
    return ok(
        WorkflowStatusDTO(
            map_status="PENDING",
            c_fast_status="PENDING",
        ).model_dump(mode="json")
    )


@router.post("/signing-requests/export")
def export_signing_request(
    payload: SigningRequestCreateDTO, _: Admin
) -> dict[str, Any]:
    """Export canonical bytes for an offline signer; never sign in-browser."""
    try:
        request = build_signing_request(
            artifact=payload.artifact,
            domain=payload.domain,
            request_id=payload.request_id,
            key_id=payload.key_id,
            key_version=payload.key_version,
            requested_at=payload.requested_at,
            expires_at=payload.expires_at,
        )
    except PhaseCWorkflowError as exc:
        raise AppError(
            str(exc),
            code="PHASE_C_SIGNING_REQUEST_INVALID",
            status_code=422,
            detail={"fail_closed": True},
        ) from exc
    return ok(request)


@router.post("/artifacts/upload-install")
def upload_and_install_signed_artifact(
    payload: SignedArtifactUploadDTO, _: Admin
) -> dict[str, Any]:
    """Forward a pre-signed offline handoff to custody; Control does not retain it."""
    try:
        return ok(phase_c_workflow_client.install(payload).model_dump(mode="json"))
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc


@router.get("/custody/receipts/{receipt_id}")
def custody_receipt(receipt_id: str, _: Reader) -> dict[str, Any]:
    try:
        receipt = phase_c_workflow_client.custody_receipt(receipt_id)
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc
    if receipt is None:
        raise AppError(
            "custody receipt 不存在或不在 Control projection 中",
            code="PHASE_C_CUSTODY_RECEIPT_NOT_FOUND",
            status_code=404,
            detail={"fail_closed": True},
        )
    return ok(receipt.model_dump(mode="json"))


@router.get("/custody/receipts-by-idempotency/{idempotency_key}")
def custody_receipt_by_idempotency(idempotency_key: str, _: Reader) -> dict[str, Any]:
    try:
        receipt = phase_c_workflow_client.custody_receipt_by_idempotency(
            idempotency_key
        )
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc
    if receipt is None:
        raise AppError(
            "custody receipt 尚不可判定",
            code="PHASE_C_UNKNOWN_OUTCOME",
            status_code=404,
            detail={"idempotency_key": idempotency_key, "query_same_intent_only": True},
        )
    return ok(receipt.model_dump(mode="json"))


@router.get("/authorization/status")
def authorization_status(_: Reader) -> dict[str, Any]:
    try:
        return ok(
            phase_c_workflow_client.authorization_status().model_dump(mode="json")
        )
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc


@router.post("/authorization/commands")
def authorization_command(payload: AuthorizationCommandDTO, _: Admin) -> dict[str, Any]:
    try:
        return ok(
            phase_c_workflow_client.authorization_command(payload).model_dump(
                mode="json"
            )
        )
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc


@router.get("/authorization/receipts/{idempotency_key}")
def authorization_receipt(idempotency_key: str, _: Reader) -> dict[str, Any]:
    try:
        result = phase_c_workflow_client.authorization_receipt(idempotency_key)
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc
    if result is None:
        raise AppError(
            "authorization result 未知；只能以相同 idempotency key 重试或查询",
            code="PHASE_C_UNKNOWN_OUTCOME",
            status_code=404,
            detail={"idempotency_key": idempotency_key, "query_same_intent_only": True},
        )
    return ok(result.model_dump(mode="json"))


@router.get("/execution/preview")
@router.get("/execution/status")
@router.get("/execution/audit")
@router.get("/execution/archive")
def execution_projection(_: Reader) -> dict[str, Any]:
    try:
        return ok(
            phase_c_workflow_client.execution_projection().model_dump(mode="json")
        )
    except WorkflowAdapterError as exc:
        raise _adapter_error(exc) from exc


__all__ = ["router"]
