"""GET-only HTTP projection for the isolated SIMNOW_LAB dashboard."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.services.simnow_lab_dashboard import simnow_lab_dashboard_service

router = APIRouter(prefix="/api/v1/simnow-lab", tags=["simnow-lab-dashboard"])
Reader = Annotated[CurrentUser, Depends(require_roles("viewer", "trader", "admin"))]


@router.get("/dashboard")
def dashboard(_: Reader) -> dict:
    return ok(simnow_lab_dashboard_service.dashboard().model_dump(mode="json"))


@router.get("/runs")
def runs(_: Reader) -> dict:
    return ok(simnow_lab_dashboard_service.runs().model_dump(mode="json"))


@router.get("/runs/{run_id}")
def run(run_id: str, _: Reader) -> dict:
    return ok(simnow_lab_dashboard_service.run(run_id).model_dump(mode="json"))
