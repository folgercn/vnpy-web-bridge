"""One-method, read-only Windows RPC adapter for the SIMNOW_LAB dashboard."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timezone
from threading import RLock
from time import monotonic
from typing import Any

try:
    from vnpy.rpc import RpcClient
except ImportError:  # pragma: no cover - deployment dependency
    RpcClient = None  # type: ignore[assignment,misc]

from app.core.errors import AppError
from app.schemas.simnow_lab_dashboard import (
    SimNowLabDashboardDTO,
    SimNowLabDashboardResponseDTO,
    SimNowLabRunDetailDTO,
    SimNowLabRunResponseDTO,
    SimNowLabRunsResponseDTO,
)

RPC_METHOD = "simnow_lab_get_run_v1"
RPC_REQUEST_ADDRESS = os.getenv(
    "SIMNOW_LAB_RPC_REQ_ADDRESS", "tcp://192.168.100.187:2014"
)
RPC_PUBLISH_ADDRESS = os.getenv(
    "SIMNOW_LAB_RPC_PUB_ADDRESS", "tcp://192.168.100.187:4102"
)
RPC_TIMEOUT_MS = int(os.getenv("SIMNOW_LAB_RPC_TIMEOUT_MS", "10000"))
CACHE_SECONDS = 8.0


class _CachedValue:
    def __init__(self, value: Any, succeeded_at: datetime, cached_at: float) -> None:
        self.value = value
        self.succeeded_at = succeeded_at
        self.cached_at = cached_at


class SimNowLabDashboardService:
    """Cache successful read models; never retry or issue a Lab mutation."""

    def __init__(
        self,
        rpc_call: Callable[[str], Any] | None = None,
        *,
        cache_seconds: float = CACHE_SECONDS,
        web_version: str | None = None,
    ) -> None:
        self._rpc_call = rpc_call or _call_windows_readonly_rpc
        self._cache_seconds = cache_seconds
        self._web_version = web_version or os.getenv("CONTROL_API_VERSION", "phase-a-dev")
        self._cache: dict[str, _CachedValue] = {}
        self._lock = RLock()

    def dashboard(self) -> SimNowLabDashboardResponseDTO:
        dashboard, stale, succeeded_at = self._read(
            "DASHBOARD", SimNowLabDashboardDTO.model_validate
        )
        return SimNowLabDashboardResponseDTO(
            stale=stale,
            last_success_at=succeeded_at,
            web_version=self._web_version,
            dashboard=dashboard,
        )

    def runs(self) -> SimNowLabRunsResponseDTO:
        dashboard, stale, succeeded_at = self._read(
            "DASHBOARD", SimNowLabDashboardDTO.model_validate
        )
        return SimNowLabRunsResponseDTO(
            stale=stale,
            last_success_at=succeeded_at,
            runs=dashboard.runs,
        )

    def run(self, run_id: str) -> SimNowLabRunResponseDTO:
        if len(run_id) != 32 or any(char not in "0123456789abcdef" for char in run_id):
            raise AppError(
                "SIMNOW_LAB run_id 非法",
                code="SIMNOW_LAB_RUN_ID_INVALID",
                status_code=422,
            )
        dashboard, stale, succeeded_at = self._read(
            "DASHBOARD", SimNowLabDashboardDTO.model_validate
        )
        selected = next((row for row in dashboard.runs if row.run_id == run_id), None)
        if selected is None:
            raise AppError(
                "SIMNOW_LAB run 不存在",
                code="SIMNOW_LAB_RUN_NOT_FOUND",
                status_code=404,
            )
        detail = SimNowLabRunDetailDTO(
            run=selected,
            orders=[row for row in dashboard.orders if row.run_id == run_id],
            trades=[row for row in dashboard.trades if row.run_id == run_id],
            snapshots=[row for row in dashboard.snapshots if row.run_id == run_id],
        )
        return SimNowLabRunResponseDTO(
            stale=stale,
            last_success_at=succeeded_at,
            run=detail,
        )

    def _read(
        self,
        cache_key: str,
        parser: Callable[[Any], Any],
    ) -> tuple[Any, bool, datetime]:
        cached = self._cached_fresh(cache_key)
        if cached is not None:
            return cached.value, False, cached.succeeded_at
        try:
            parsed = parser(self._rpc_call("DASHBOARD"))
        except Exception as exc:
            cached = self._cached_any(cache_key)
            if cached is not None:
                return cached.value, True, cached.succeeded_at
            raise AppError(
                "SIMNOW_LAB 只读数据暂不可用",
                code="SIMNOW_LAB_DASHBOARD_UNAVAILABLE",
                status_code=503,
                detail={"read_only": True, "rpc_method": RPC_METHOD},
            ) from exc
        succeeded_at = datetime.now(timezone.utc)
        value = _CachedValue(parsed, succeeded_at, monotonic())
        with self._lock:
            self._cache[cache_key] = value
        return parsed, False, succeeded_at

    def _cached_fresh(self, cache_key: str) -> _CachedValue | None:
        cached = self._cached_any(cache_key)
        if cached is not None and monotonic() - cached.cached_at < self._cache_seconds:
            return cached
        return None

    def _cached_any(self, cache_key: str) -> _CachedValue | None:
        with self._lock:
            return self._cache.get(cache_key)


def _call_windows_readonly_rpc(argument: str) -> Any:
    """Make one isolated RPC call without importing the frozen RPC service."""

    if RpcClient is None:  # pragma: no cover - deployment dependency
        raise RuntimeError("VNPY_RPC_CLIENT_UNAVAILABLE")
    client = RpcClient()
    client.start(RPC_REQUEST_ADDRESS, RPC_PUBLISH_ADDRESS)
    try:
        return getattr(client, RPC_METHOD)(argument, timeout=RPC_TIMEOUT_MS)
    finally:
        client.stop()
        client.join()


simnow_lab_dashboard_service = SimNowLabDashboardService()
