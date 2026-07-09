from __future__ import annotations

from app.schemas.mak_v2_observer import MakV2SafetyAuditRequestDTO
from app.services.mak_v2_testnet_observer.event_store import MakV2ObserverEventStore
from app.services.mak_v2_testnet_observer.safety_audit import MakV2SafetyAuditService
from app.services.mak_v2_testnet_observer.service import MakV2TestnetObserverService


class FakeRisk:
    def status(self) -> dict:
        return {"risk_enabled": True, "web_trade_enabled": False, "emergency_stopped": False, "rules_version": 1}


class FakeTrade:
    def config_status(self) -> dict:
        return {
            "web_trade_enabled": False,
            "default_gateway_name": "CTP",
            "order_confirm_required": True,
            "trade_reference_prefix": "web_bridge",
        }


class FakeRpc:
    def __init__(self, *, connected: bool = True, accounts: list[dict] | None = None, positions: list[dict] | None = None) -> None:
        self.connected = connected
        self.accounts = accounts or [{"accountid": "simnow-testnet-001", "gateway_name": "CTP"}]
        self.positions = positions or []
        self.contracts = [
            {"symbol": "ps2609", "exchange": "GFEX", "vt_symbol": "ps2609.GFEX", "pricetick": 5, "size": 60},
            {"symbol": "lc2609", "exchange": "GFEX", "vt_symbol": "lc2609.GFEX", "pricetick": 20, "size": 1},
        ]

    def status(self, *, probe: bool = False) -> dict:
        return {
            "connected": self.connected,
            "req_address": "tcp://secret-req",
            "pub_address": "tcp://secret-pub",
            "gateway_name": "CTP",
            "last_connected_at": None,
            "last_error": None,
        }

    def get_accounts(self) -> list[dict]:
        return self.accounts

    def get_contracts(self) -> list[dict]:
        return self.contracts

    def get_positions(self) -> list[dict]:
        return self.positions


class FakeAudit:
    def record(self, **kwargs) -> None:
        return None


def make_observer(*, rpc: FakeRpc) -> MakV2TestnetObserverService:
    safety = MakV2SafetyAuditService(risk=FakeRisk(), trade=FakeTrade(), rpc=rpc)  # type: ignore[arg-type]
    return MakV2TestnetObserverService(store=MakV2ObserverEventStore(), risk=FakeRisk(), audit=FakeAudit(), safety_audit=safety)  # type: ignore[arg-type]


def test_safety_audit_passes_with_testnet_account_contracts_and_flat_positions() -> None:
    service = make_observer(rpc=FakeRpc())

    result = service.safety_audit(
        MakV2SafetyAuditRequestDTO(
            collect_rpc_snapshot=True,
            require_rpc_connected=True,
            expected_exact_contracts=["GFEX.ps2609", "GFEX.lc2609"],
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert result["overall"] == "PASS"
    assert result["single_order_smoke_allowed"] is True
    assert result["rpc"]["addresses_redacted"] is True
    assert result["snapshot"]["accounts"][0]["account_tail"] == "-001"


def test_safety_audit_fails_when_production_marker_is_seen() -> None:
    service = make_observer(rpc=FakeRpc(accounts=[{"accountid": "prod-mainnet-001", "gateway_name": "CTP"}]))

    result = service.safety_audit(
        MakV2SafetyAuditRequestDTO(collect_rpc_snapshot=True, require_rpc_connected=True),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    failed = {row["name"] for row in result["checks"] if row["status"] == "FAIL"}
    assert result["overall"] == "FAIL"
    assert "production_account_absent" in failed


def test_safety_audit_without_snapshot_is_watch_not_pass() -> None:
    service = make_observer(rpc=FakeRpc(connected=False))

    result = service.safety_audit(
        MakV2SafetyAuditRequestDTO(),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    watched = {row["name"] for row in result["checks"] if row["status"] == "WATCH"}
    assert result["overall"] == "WATCH"
    assert "rpc_connected" in watched
    assert "testnet_account_identified" in watched
