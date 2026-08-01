from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.services.commodity_c_fast_execution_quality_runtime import (
    commodity_c_fast_execution_quality_runtime,
)


router = APIRouter(prefix="/commodity-c-fast/execution-quality")


@router.get("/status")
def status(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    """Return the default-off Research Plane lifecycle projection."""

    return ok(commodity_c_fast_execution_quality_runtime.status())


@router.post("/reload")
def reload(
    _: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    """Revalidate only this isolated runtime; never start or dispatch it."""

    return ok(commodity_c_fast_execution_quality_runtime.reload())


@router.post("/recover")
def recover(
    _: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    """Replay only this runtime's revalidation lifecycle boundary."""

    return ok(commodity_c_fast_execution_quality_runtime.recover())
