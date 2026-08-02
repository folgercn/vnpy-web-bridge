from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.errors import AppError, ok
from app.core.security import CurrentUser, require_roles
from app.services.commodity_c_fast_execution_quality_production_assembly import (
    commodity_c_fast_execution_quality_production_assembly,
)
from app.services.commodity_c_fast_execution_quality_readonly_repository import (
    CFastExecutionQualityReadonlyRepositoryError,
)
from app.services.commodity_c_fast_execution_quality_tick_fanout import (
    commodity_c_fast_execution_quality_tick_fanout,
)

router = APIRouter(prefix="/commodity-c-fast/execution-quality")


def _readonly_projection(operation) -> dict:
    try:
        return ok(operation())
    except (CFastExecutionQualityReadonlyRepositoryError, ValueError) as exc:
        code = str(getattr(exc, "code", type(exc).__name__))
        raise AppError(
            "C_FAST execution-quality readonly projection unavailable",
            code=code,
            status_code=503,
        ) from exc


@router.get("/status")
def status(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    """Return the default-off Research Plane lifecycle projection."""

    return ok(
        {
            **commodity_c_fast_execution_quality_production_assembly.status(),
            "tick_fanout": commodity_c_fast_execution_quality_tick_fanout.status(),
        }
    )


@router.get("/intents")
def intents(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    """Read the exact typed intent projection from the fixed sidecar replay."""

    def projection() -> dict:
        items = commodity_c_fast_execution_quality_production_assembly.intents()
        return {"count": len(items), "items": list(items)}

    return _readonly_projection(projection)


@router.get("/execution-quality")
def execution_quality(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    """Read sealed exact evidence; never query or mutate an execution venue."""

    def projection() -> dict:
        items = (
            commodity_c_fast_execution_quality_production_assembly.execution_quality()
        )
        return {"count": len(items), "items": list(items)}

    return _readonly_projection(projection)


@router.get("/evidence-export")
def evidence_export(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    """Reload and verify the immutable artifact published by lifecycle recovery."""

    return _readonly_projection(
        commodity_c_fast_execution_quality_production_assembly.evidence_export
    )


@router.post("/reload")
def reload(
    _: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    """Revalidate only this isolated runtime; never start or dispatch it."""

    return ok(commodity_c_fast_execution_quality_production_assembly.reload())


@router.post("/recover")
def recover(
    _: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    """Replay only this runtime's revalidation lifecycle boundary."""

    return ok(commodity_c_fast_execution_quality_production_assembly.recover())
