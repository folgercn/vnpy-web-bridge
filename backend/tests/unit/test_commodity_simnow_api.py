from __future__ import annotations

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.vnpy_rpc_service import rpc_service
from fastapi.testclient import TestClient


class FakeCommoditySimNowService:
    def __init__(self) -> None:
        self.enabled = False
        self.preview_calls = 0
        self.template_start_calls = 0

    def status(self) -> dict:
        return {
            "configured": True,
            "enabled": self.enabled,
            "production_allowed": False,
        }

    def plan(self) -> dict:
        return {}

    def position_manager_shadow(self) -> dict:
        return {
            "configured": True,
            "valid": True,
            "mode": "shadow_only",
            "authority_granted": False,
            "dispatch_allowed": False,
        }

    def position_manager_shakedown_status(self) -> dict:
        return {"configured": True, "execution_enabled": False, "session": None}

    def preview_position_manager_shakedown(self, selected_products, **kwargs) -> dict:
        return {
            "configured": True,
            "execution_enabled": False,
            "preview": {
                "status": "PREVIEW_READY",
                "selected_products": selected_products,
                "countable_forward": False,
            },
        }

    def start_position_manager_shakedown(self, plan_hash, **kwargs) -> dict:
        return {
            "execution_enabled": True,
            "action": "open_submitted",
            "session": {"plan_hash": plan_hash},
        }

    def stop_position_manager_shakedown(self, reason, **kwargs) -> dict:
        return {
            "execution_enabled": True,
            "halt": {"reason": reason, "status": "CANCEL_PENDING"},
        }

    def c_fast_shakedown_status(self) -> dict:
        return {
            "configured": True,
            "execution_enabled": False,
            "countable_forward": False,
            "production_allowed": False,
            "session": None,
        }

    def c_fast_shakedown_events(self, limit: int) -> list[dict]:
        return []

    def c_fast_shakedown_history(self, limit: int) -> list[dict]:
        return []

    def c_fast_shakedown_pnl(self) -> dict:
        return {
            "status": "UNAVAILABLE",
            "countable_forward": False,
        }

    def preview_c_fast_shakedown(self, selected_products, **kwargs) -> dict:
        return {
            "preview": {
                "status": "PREVIEW_READY",
                "selected_products": selected_products,
                "countable_forward": False,
            }
        }

    def start_c_fast_shakedown(self, plan_hash, **kwargs) -> dict:
        return {
            "action": "open_submitted",
            "session": {"plan_hash": plan_hash},
        }

    def stop_c_fast_shakedown(self, reason, **kwargs) -> dict:
        return {
            "halt": {
                "reason": reason,
                "status": "CANCEL_PENDING",
            }
        }

    def enable_c_fast_continuous(self, payload, **kwargs) -> dict:
        return {
            "action": "continuous_authorization_enabled",
            "selected_products": payload.selected_products,
            "production_allowed": False,
        }

    def c_fast_runtime_authorization_status(self) -> dict:
        return {
            "map_strategy_acceptance": {"state": "ACCEPTED"},
            "c_fast_allocation_acceptance": {"state": "ACCEPTED"},
            "runtime_authorization": {
                "authorization_id": "runtime-auth-262",
                "state": "ACTIVE",
                "expires_at_utc": "2026-09-01T00:00:00+00:00",
                "revoked_at_utc": None,
                "revoke_reason": None,
            },
            "current_snapshot": {"state": "COMPLETE"},
            "operational_state": "WAITING_NEW_SNAPSHOT",
            "waiting": True,
            "hard_blocked": False,
            "production_allowed": False,
        }

    def enable_c_fast_runtime_authorization(self, payload, **kwargs) -> dict:
        return {
            "action": "runtime_authorization_enabled",
            "authorization_id": "runtime-auth-262",
            "state": "ACTIVE",
            "production_allowed": False,
        }

    def revoke_c_fast_runtime_authorization(self, payload, **kwargs) -> dict:
        return {
            "action": "runtime_authorization_revoked",
            "authorization_id": "runtime-auth-262",
            "state": "REVOKED",
            "revoke_reason": payload.reason,
            "production_allowed": False,
        }

    def list_events(self, limit: int) -> list[dict]:
        return []

    def enable(self, payload, **kwargs) -> dict:
        self.enabled = True
        return self.status()

    def disable(self, payload, **kwargs) -> dict:
        self.enabled = False
        return self.status()

    def start_template(self, payload, **kwargs) -> dict:
        self.enabled = True
        self.template_start_calls += 1
        return {"action": "strategy_template_started", **self.status()}

    def preview(self, batch, **kwargs) -> dict:
        self.preview_calls += 1
        return {"status": "READY_OPEN", "batch_id": batch.batch_id}

    def execute(self, payload, **kwargs) -> dict:
        return {"status": f"{payload.phase.upper()}_SUBMITTED"}

    def reconcile(self, plan_hash, **kwargs) -> dict:
        return {"status": "COMPLETE", "plan_hash": plan_hash}

    def auto_advance(self, **kwargs) -> dict:
        return {"action": "open_submitted", "auto_dispatch_allowed": True}


def auth_headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    return TestClient(app)


def install_service(monkeypatch) -> FakeCommoditySimNowService:
    from app.api import routes_commodity_simnow

    service = FakeCommoditySimNowService()
    monkeypatch.setattr(routes_commodity_simnow, "commodity_simnow_service", service)
    return service


def enable_payload() -> dict:
    return {
        "manual_approval": True,
        "simnow_mode": True,
        "reason": "manual SimNow route test",
        "confirm_simnow_only": True,
        "confirm_no_production": True,
        "confirm_cold_start_or_reconciled_state": True,
        "confirm_manual_two_phase_dispatch": True,
        "confirm_auto_dispatch": True,
        "confirm_no_auto_promotion": True,
    }


def test_viewer_can_read_status_but_cannot_enable(monkeypatch) -> None:
    """Commodity SimNow is Execution-owned and removed from Control."""
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        status = client.get(
            "/api/commodity-simnow/status", headers=auth_headers("viewer")
        )
        forbidden = client.post(
            "/api/commodity-simnow/enable",
            headers=auth_headers("viewer"),
            json=enable_payload(),
        )

    for response in (status, forbidden):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_viewer_can_read_position_manager_shadow(monkeypatch) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.get(
            "/api/commodity-simnow/position-manager-shadow",
            headers=auth_headers("viewer"),
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_position_manager_shakedown_preview_is_admin_only(monkeypatch) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        status = client.get(
            "/api/commodity-simnow/position-manager-shakedown/status",
            headers=auth_headers("viewer"),
        )
        forbidden = client.post(
            "/api/commodity-simnow/position-manager-shakedown/preview",
            headers=auth_headers("trader"),
            json={"selected_products": ["ag"]},
        )
        response = client.post(
            "/api/commodity-simnow/position-manager-shakedown/preview",
            headers=auth_headers("admin"),
            json={"selected_products": ["ag"]},
        )

    for result in (status, forbidden, response):
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_position_manager_shakedown_start_and_stop_are_admin_only(monkeypatch) -> None:
    install_service(monkeypatch)
    plan_hash = "a" * 64
    with client_without_rpc(monkeypatch) as client:
        forbidden = client.post(
            "/api/commodity-simnow/position-manager-shakedown/start",
            headers=auth_headers("trader"),
            json={"plan_hash": plan_hash},
        )
        started = client.post(
            "/api/commodity-simnow/position-manager-shakedown/start",
            headers=auth_headers("admin"),
            json={"plan_hash": plan_hash},
        )
        stopped = client.post(
            "/api/commodity-simnow/position-manager-shakedown/stop",
            headers=auth_headers("admin"),
            json={"reason": "operator requested stop"},
        )

    for response in (forbidden, started, stopped):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_c_fast_shakedown_reads_and_mutations_use_expected_rbac(
    monkeypatch,
) -> None:
    install_service(monkeypatch)
    plan_hash = "b" * 64
    with client_without_rpc(monkeypatch) as client:
        status = client.get(
            "/api/commodity-simnow/c-fast-shakedown/status",
            headers=auth_headers("viewer"),
        )
        pnl = client.get(
            "/api/commodity-simnow/c-fast-shakedown/pnl",
            headers=auth_headers("trader"),
        )
        sessions = client.get(
            "/api/commodity-simnow/c-fast-shakedown/sessions",
            headers=auth_headers("viewer"),
        )
        forbidden = client.post(
            "/api/commodity-simnow/c-fast-shakedown/preview",
            headers=auth_headers("trader"),
            json={"selected_products": ["ag"]},
        )
        preview = client.post(
            "/api/commodity-simnow/c-fast-shakedown/preview",
            headers=auth_headers("admin"),
            json={"selected_products": ["ag"]},
        )
        started = client.post(
            "/api/commodity-simnow/c-fast-shakedown/start",
            headers=auth_headers("admin"),
            json={"plan_hash": plan_hash},
        )
        stopped = client.post(
            "/api/commodity-simnow/c-fast-shakedown/stop",
            headers=auth_headers("admin"),
            json={"reason": "operator requested stop"},
        )
        continuous_payload = {
            "reason": "operator approved continuous SimNow pilot",
            "selected_products": ["ag"],
            "confirm_simnow_only": True,
            "confirm_signed_snapshots_only": True,
            "confirm_independent_execution_permit": True,
            "confirm_no_production": True,
            "confirm_fail_closed_on_drift": True,
        }
        continuous_forbidden = client.post(
            "/api/commodity-simnow/c-fast-shakedown/continuous/enable",
            headers=auth_headers("trader"),
            json=continuous_payload,
        )
        continuous_enabled = client.post(
            "/api/commodity-simnow/c-fast-shakedown/continuous/enable",
            headers=auth_headers("admin"),
            json=continuous_payload,
        )

    for response in (
        status,
        pnl,
        sessions,
        forbidden,
        preview,
        started,
        stopped,
        continuous_forbidden,
        continuous_enabled,
    ):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_admin_can_enable_controller(monkeypatch) -> None:
    service = install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/commodity-simnow/enable",
            headers=auth_headers("admin"),
            json=enable_payload(),
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert service.enabled is False


def test_runtime_authorization_status_is_read_only_for_viewer_and_trader(
    monkeypatch,
) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        viewer = client.get(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/status",
            headers=auth_headers("viewer"),
        )
        trader = client.get(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/status",
            headers=auth_headers("trader"),
        )
        admin = client.get(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/status",
            headers=auth_headers("admin"),
        )
        unauthenticated = client.get(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/status",
        )

    for response in (viewer, trader, admin):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert unauthenticated.status_code == 401


def test_runtime_authorization_enable_and_revoke_are_admin_only(
    monkeypatch,
) -> None:
    install_service(monkeypatch)
    enable_payload = {
        "reason": "approve persistent SimNow runtime",
        "confirm_simnow_only": True,
        "confirm_signed_snapshots_only": True,
        "confirm_continuous": True,
        "confirm_no_production": True,
        "confirm_fail_closed_on_drift": True,
    }
    revoke_payload = {
        "reason": "operator revoked runtime authorization",
    }
    with client_without_rpc(monkeypatch) as client:
        viewer_forbidden = client.post(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/enable",
            headers=auth_headers("viewer"),
            json=enable_payload,
        )
        trader_forbidden = client.post(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/revoke",
            headers=auth_headers("trader"),
            json=revoke_payload,
        )
        enabled = client.post(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/enable",
            headers=auth_headers("admin"),
            json=enable_payload,
        )
        revoked = client.post(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/revoke",
            headers=auth_headers("admin"),
            json=revoke_payload,
        )

    for response in (viewer_forbidden, trader_forbidden, enabled, revoked):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_runtime_authorization_enable_requires_all_safety_confirmations(
    monkeypatch,
) -> None:
    install_service(monkeypatch)
    payload = {
        "reason": "approve persistent SimNow runtime",
        "confirm_simnow_only": True,
        "confirm_signed_snapshots_only": True,
        "confirm_continuous": True,
        "confirm_no_production": False,
        "confirm_fail_closed_on_drift": True,
    }
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/commodity-simnow/c-fast-shakedown/runtime-authorization/enable",
            headers=auth_headers("admin"),
            json=payload,
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_one_click_template_start_requires_admin(monkeypatch) -> None:
    service = install_service(monkeypatch)
    payload = {
        "reason": "one-click STATIC_CORE_EQUAL route test",
        "confirm_strategy_template": True,
        "confirm_simnow_only": True,
        "confirm_auto_dispatch": True,
        "confirm_no_production": True,
    }
    with client_without_rpc(monkeypatch) as client:
        forbidden = client.post(
            "/api/commodity-simnow/template/start",
            headers=auth_headers("trader"),
            json=payload,
        )
        response = client.post(
            "/api/commodity-simnow/template/start",
            headers=auth_headers("admin"),
            json=payload,
        )

    for result in (forbidden, response):
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert service.template_start_calls == 0


def test_commodity_routes_require_authentication(monkeypatch) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        status = client.get("/api/commodity-simnow/status")
        plan = client.get("/api/commodity-simnow/plan")

    assert status.status_code == 401
    assert plan.status_code == 401


def test_auto_advance_requires_admin(monkeypatch) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        forbidden = client.post(
            "/api/commodity-simnow/auto-advance",
            headers=auth_headers("trader"),
        )
        result = client.post(
            "/api/commodity-simnow/auto-advance",
            headers=auth_headers("admin"),
        )

    for response in (forbidden, result):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
