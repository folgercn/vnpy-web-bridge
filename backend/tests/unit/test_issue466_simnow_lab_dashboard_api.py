from __future__ import annotations

import inspect

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.simnow_lab_dashboard import SimNowLabDashboardService
from fastapi.testclient import TestClient

RUN_ID = "a" * 32


def _headers() -> dict[str, str]:
    token = create_access_token(CurrentUser("viewer", "viewer"))
    return {"Authorization": f"Bearer {token}"}


def _dashboard() -> dict:
    return {
        "schema_version": "simnow_lab_dashboard_v1",
        "generated_at": "2026-08-28T01:02:03Z",
        "runtime_version": "runtime-466",
        "summary": {
            "status": "DONE",
            "blocker": None,
            "last_run_id": RUN_ID,
            "target_id": "target-466",
            "started_at": "2026-08-28T01:00:00Z",
            "ended_at": "2026-08-28T01:01:00Z",
            "active_order_count": 0,
            "unknown_order_count": 0,
            "aligned_products": 10,
            "total_products": 10,
        },
        "metrics": {
            "equity": 100000.0,
            "available": 90000.0,
            "margin": 10000.0,
            "unrealized_pnl": 1.0,
            "realized_pnl": 2.0,
            "cumulative_pnl": 3.0,
            "daily_pnl": 3.0,
            "max_drawdown": -4.0,
            "slippage": 0.5,
            "trade_count": 1,
        },
        "series": {
            key: [{"time": "2026-08-28T01:00:00Z", "value": 1.0}]
            for key in ("equity", "cumulative_pnl", "drawdown", "daily_pnl")
        },
        "portfolio": [
            {
                "product": "rb",
                "vt_symbol": "rb2610.SHFE",
                "target_quantity": 1,
                "current_quantity": 1,
                "delta": 0,
                "unrealized_pnl": 1.0,
                "status": "ALIGNED",
            }
        ],
        "runs": [
            {
                "run_id": RUN_ID,
                "target_id": "target-466",
                "status": "DONE",
                "started_at": "2026-08-28T01:00:00Z",
                "ended_at": "2026-08-28T01:01:00Z",
                "error": None,
            }
        ],
        "orders": [],
        "trades": [],
        "snapshots": [
            {
                "snapshot_id": "snapshot-466",
                "run_id": RUN_ID,
                "phase": "AFTER",
                "observed_at": "2026-08-28T01:01:00Z",
                "equity": 100000.0,
                "available": 90000.0,
                "margin": 10000.0,
                "unrealized_pnl": 1.0,
            }
        ],
        "incidents": [],
    }


def _install(monkeypatch, rpc_call, *, cache_seconds: float = 8.0) -> None:
    from app.api import routes_simnow_lab_dashboard

    monkeypatch.setattr(
        routes_simnow_lab_dashboard,
        "simnow_lab_dashboard_service",
        SimNowLabDashboardService(
            rpc_call, cache_seconds=cache_seconds, web_version="control-466"
        ),
    )


def test_dashboard_is_get_only_typed_and_cached(monkeypatch) -> None:
    calls: list[str] = []

    def rpc_call(argument: str) -> dict:
        calls.append(argument)
        return _dashboard()

    _install(monkeypatch, rpc_call)
    with TestClient(app) as client:
        first = client.get("/api/v1/simnow-lab/dashboard", headers=_headers())
        cached = client.get("/api/v1/simnow-lab/dashboard", headers=_headers())
        forbidden = client.post("/api/v1/simnow-lab/dashboard", headers=_headers())

    assert first.status_code == cached.status_code == 200
    assert first.json()["data"] == {
        "stale": False,
        "last_success_at": first.json()["data"]["last_success_at"],
        "web_version": "control-466",
        "dashboard": first.json()["data"]["dashboard"],
    }
    assert first.json()["data"]["dashboard"]["summary"]["aligned_products"] == 10
    assert calls == ["DASHBOARD"]
    assert forbidden.status_code == 503
    assert forbidden.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_runs_and_detail_use_only_dashboard_projection(monkeypatch) -> None:
    calls: list[str] = []

    def rpc_call(argument: str) -> dict:
        calls.append(argument)
        return _dashboard()

    _install(monkeypatch, rpc_call)
    with TestClient(app) as client:
        runs = client.get("/api/v1/simnow-lab/runs", headers=_headers())
        detail = client.get(f"/api/v1/simnow-lab/runs/{RUN_ID}", headers=_headers())
        invalid = client.get("/api/v1/simnow-lab/runs/not-a-run", headers=_headers())
        missing = client.get(f"/api/v1/simnow-lab/runs/{'b' * 32}", headers=_headers())

    assert runs.status_code == detail.status_code == 200
    assert runs.json()["data"]["runs"][0]["run_id"] == RUN_ID
    assert detail.json()["data"]["run"]["run"]["run_id"] == RUN_ID
    assert detail.json()["data"]["run"]["snapshots"][0]["snapshot_id"] == "snapshot-466"
    assert calls == ["DASHBOARD"]
    assert invalid.status_code == 422
    assert missing.status_code == 404


def test_rpc_failure_returns_stale_last_success_without_a_second_action(monkeypatch) -> None:
    calls: list[str] = []

    def rpc_call(argument: str) -> dict:
        calls.append(argument)
        if len(calls) == 1:
            return _dashboard()
        raise TimeoutError("windows offline")

    _install(monkeypatch, rpc_call, cache_seconds=0)
    with TestClient(app) as client:
        first = client.get("/api/v1/simnow-lab/dashboard", headers=_headers())
        stale = client.get("/api/v1/simnow-lab/dashboard", headers=_headers())

    assert first.status_code == stale.status_code == 200
    assert stale.json()["data"]["stale"] is True
    assert stale.json()["data"]["last_success_at"] == first.json()["data"]["last_success_at"]
    assert calls == ["DASHBOARD", "DASHBOARD"]


def test_vnpy_rpc_is_preloaded_before_fastapi_worker_threads() -> None:
    from app.services import simnow_lab_dashboard

    source = inspect.getsource(simnow_lab_dashboard._call_windows_readonly_rpc)
    assert "from vnpy.rpc import RpcClient" not in source
    assert simnow_lab_dashboard.RpcClient is not None


def test_readonly_rpc_does_not_block_http_on_subscriber_join(monkeypatch) -> None:
    from app.services import simnow_lab_dashboard

    events: list[str] = []

    class FakeClient:
        def start(self, request: str, publish: str) -> None:
            events.append(f"start:{request}:{publish}")

        def stop(self) -> None:
            events.append("stop")

        def join(self) -> None:
            raise AssertionError("subscriber join must not block the HTTP response")

        def simnow_lab_get_run_v1(self, argument: str, *, timeout: int) -> dict:
            events.append(f"get:{argument}:{timeout}")
            return {"status": "ok"}

    monkeypatch.setattr(simnow_lab_dashboard, "RpcClient", FakeClient)
    assert simnow_lab_dashboard._call_windows_readonly_rpc("DASHBOARD") == {"status": "ok"}
    assert events[-1] == "stop"
