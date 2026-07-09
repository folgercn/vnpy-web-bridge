from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from app.schemas.mak_v2_observer import MakV2SafetyAuditRequestDTO
from app.services.risk_service import RiskService, risk_service
from app.services.trade_service import TradeService, trade_service
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service

TCP_ADDRESS_RE = re.compile(r"tcp://[^\s,}]+")


class MakV2SafetyAuditService:
    def __init__(
        self,
        *,
        risk: RiskService | None = None,
        trade: TradeService | None = None,
        rpc: VnpyRpcService | None = None,
    ) -> None:
        self.risk = risk or risk_service
        self.trade = trade or trade_service
        self.rpc = rpc or rpc_service

    def audit(self, payload: MakV2SafetyAuditRequestDTO, observer_status: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(timezone.utc)
        risk_status = self.risk.status()
        trade_config = self.trade.config_status()
        rpc_status = self.rpc.status(probe=payload.probe_rpc)
        snapshot, snapshot_errors = self._collect_snapshot(payload.collect_rpc_snapshot)
        checks: list[dict[str, Any]] = []

        checks.append(_check("observer_dry_run_only", observer_status.get("dry_run_only") is True, observer_status.get("dry_run_only")))
        checks.append(_check("observer_production_blocked", observer_status.get("production_allowed") is False, observer_status.get("production_allowed")))
        checks.append(_check("observer_max_one_lot", observer_status.get("max_order_lots") == 1, observer_status.get("max_order_lots")))
        checks.append(_check("order_endpoint_untouched", observer_status.get("order_endpoint_touched") is False, observer_status.get("order_endpoint_touched")))
        checks.append(_check("order_confirmation_required", trade_config.get("order_confirm_required") is True, trade_config.get("order_confirm_required")))
        checks.append(_check("risk_status_readable", bool(risk_status), "readable"))
        checks.append(_check("emergency_stop_clear", risk_status.get("emergency_stopped") is False, risk_status.get("emergency_stopped")))
        checks.append(_check("rpc_connected", bool(rpc_status.get("connected")), rpc_status.get("connected"), fail_if_false=payload.require_rpc_connected))

        if payload.collect_rpc_snapshot:
            checks.extend(
                [
                    self._testnet_account_check(snapshot["accounts"], payload.testnet_account_markers),
                    self._production_account_check(snapshot["accounts"], payload.forbidden_production_account_markers),
                    self._contracts_check(snapshot["contracts"], payload.expected_exact_contracts),
                    self._positions_check(snapshot["positions"]),
                ]
            )
        else:
            checks.extend(
                [
                    _watch("testnet_account_identified", "RPC snapshot not collected"),
                    _watch("production_account_absent", "RPC snapshot not collected"),
                    _watch("gfex_contracts_available", "RPC snapshot not collected"),
                    _watch("no_active_mak_positions", "RPC snapshot not collected"),
                ]
            )

        for name, error in snapshot_errors.items():
            checks.append(_check(f"rpc_snapshot_{name}", False, error, fail_if_false=payload.require_rpc_connected))

        summary = _summary(checks)
        return {
            "audit_time_utc": started_at.isoformat(),
            "mode": "MAK_V2_PRB_SAFETY_AUDIT",
            "overall": summary["overall"],
            "single_order_smoke_allowed": summary["overall"] == "PASS",
            "checks": checks,
            "observer": {
                "enabled": observer_status.get("enabled"),
                "manual_approval": observer_status.get("manual_approval"),
                "testnet_mode": observer_status.get("testnet_mode"),
                "dry_run_only": observer_status.get("dry_run_only"),
                "production_allowed": observer_status.get("production_allowed"),
                "order_endpoint_touched": observer_status.get("order_endpoint_touched"),
            },
            "risk": risk_status,
            "trade_config": {
                "web_trade_enabled_default": trade_config.get("web_trade_enabled"),
                "default_gateway_name": trade_config.get("default_gateway_name"),
                "order_confirm_required": trade_config.get("order_confirm_required"),
                "trade_reference_prefix": trade_config.get("trade_reference_prefix"),
            },
            "rpc": _safe_rpc_status(rpc_status),
            "snapshot": {
                "accounts": [_account_summary(row) for row in snapshot["accounts"]],
                "mak_positions": [_position_summary(row) for row in snapshot["positions"] if _is_mak_symbol(row)],
                "gfex_contracts": [_contract_summary(row) for row in snapshot["contracts"] if _is_mak_contract(row)],
                "errors": snapshot_errors,
            },
            "next_actions": _next_actions(summary["overall"], checks),
        }

    def _collect_snapshot(self, enabled: bool) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
        snapshot = {"accounts": [], "contracts": [], "positions": []}
        errors: dict[str, str] = {}
        if not enabled:
            return snapshot, errors
        for key, getter in (
            ("accounts", self.rpc.get_accounts),
            ("contracts", self.rpc.get_contracts),
            ("positions", self.rpc.get_positions),
        ):
            try:
                snapshot[key] = list(getter() or [])
            except Exception as exc:
                errors[key] = _safe_text(str(getattr(exc, "message", str(exc))))
        return snapshot, errors

    def _testnet_account_check(self, accounts: list[dict[str, Any]], markers: list[str]) -> dict[str, Any]:
        account_text = "\n".join(_account_identity(row).lower() for row in accounts)
        matched = any(marker.lower() in account_text for marker in markers if marker)
        return _check("testnet_account_identified", matched, {"accounts_seen": len(accounts), "markers": markers})

    def _production_account_check(self, accounts: list[dict[str, Any]], markers: list[str]) -> dict[str, Any]:
        account_text = "\n".join(_account_identity(row).lower() for row in accounts)
        matched = any(marker.lower() in account_text for marker in markers if marker)
        return _check("production_account_absent", not matched, {"accounts_seen": len(accounts), "markers": markers})

    def _contracts_check(self, contracts: list[dict[str, Any]], expected_exact_contracts: list[str]) -> dict[str, Any]:
        vt_symbols = {_contract_vt_symbol(row) for row in contracts}
        if expected_exact_contracts:
            missing = [symbol for symbol in expected_exact_contracts if _normalize_contract(symbol) not in vt_symbols]
            return _check("expected_exact_contracts_available", not missing, {"missing": missing})
        found = sorted(symbol for symbol in vt_symbols if symbol.startswith(("lc", "ps")) and symbol.endswith(".GFEX"))
        return _check("gfex_contracts_available", bool(found), {"found": found[:20]})

    def _positions_check(self, positions: list[dict[str, Any]]) -> dict[str, Any]:
        active = [_position_summary(row) for row in positions if _is_mak_symbol(row) and float(row.get("volume") or 0) > 0]
        return _check("no_active_mak_positions", not active, {"active_positions": active})


def _check(name: str, passed: bool, observed: Any, *, fail_if_false: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "status": "PASS" if passed else "FAIL" if fail_if_false else "WATCH",
        "observed": observed,
    }


def _watch(name: str, observed: Any) -> dict[str, Any]:
    return {"name": name, "status": "WATCH", "observed": observed}


def _summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = {row["status"] for row in checks}
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "WATCH" in statuses:
        overall = "WATCH"
    else:
        overall = "PASS"
    return {"overall": overall}


def _next_actions(overall: str, checks: list[dict[str, Any]]) -> list[str]:
    if overall == "PASS":
        return ["Manual approval may proceed to single-order smoke PR-B wiring."]
    failed = [row["name"] for row in checks if row["status"] == "FAIL"]
    watched = [row["name"] for row in checks if row["status"] == "WATCH"]
    actions: list[str] = []
    if failed:
        actions.append(f"Resolve failed checks before wiring testnet execution: {', '.join(failed)}.")
    if watched:
        actions.append(f"Collect remote RPC snapshot evidence for watched checks: {', '.join(watched)}.")
    return actions


def _safe_rpc_status(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "connected": status.get("connected"),
        "gateway_name": status.get("gateway_name"),
        "last_connected_at": status.get("last_connected_at"),
        "last_error": _safe_text(str(status.get("last_error"))) if status.get("last_error") else None,
        "addresses_redacted": bool(status.get("req_address") or status.get("pub_address")),
    }


def _account_summary(row: dict[str, Any]) -> dict[str, Any]:
    account_id = str(row.get("accountid") or row.get("account_id") or row.get("vt_accountid") or row.get("id") or "")
    return {
        "account_hash": _hash(account_id),
        "account_tail": account_id[-4:] if account_id else "",
        "gateway_name": row.get("gateway_name"),
        "balance": row.get("balance"),
        "available": row.get("available"),
    }


def _position_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "vt_symbol": row.get("vt_symbol") or f"{row.get('symbol')}.{row.get('exchange')}",
        "direction": row.get("direction"),
        "volume": row.get("volume"),
        "frozen": row.get("frozen"),
        "pnl": row.get("pnl"),
        "gateway_name": row.get("gateway_name"),
    }


def _contract_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "vt_symbol": _contract_vt_symbol(row),
        "symbol": row.get("symbol"),
        "exchange": row.get("exchange"),
        "pricetick": row.get("pricetick") or row.get("price_tick"),
        "size": row.get("size") or row.get("contract_size"),
        "gateway_name": row.get("gateway_name"),
    }


def _account_identity(row: dict[str, Any]) -> str:
    return " ".join(
        str(row.get(key) or "")
        for key in ("accountid", "account_id", "vt_accountid", "id", "gateway_name", "name", "comment")
    )


def _contract_vt_symbol(row: dict[str, Any]) -> str:
    vt_symbol = str(row.get("vt_symbol") or "")
    if vt_symbol:
        return _normalize_contract(vt_symbol)
    return _normalize_contract(f"{row.get('symbol')}.{row.get('exchange')}")


def _normalize_contract(symbol: str) -> str:
    value = symbol.removeprefix("GFEX.")
    if value.endswith(".GFEX"):
        return value
    if value.startswith(("lc", "ps")):
        return f"{value}.GFEX"
    return value


def _is_mak_contract(row: dict[str, Any]) -> bool:
    symbol = _contract_vt_symbol(row)
    return symbol.startswith(("lc", "ps")) and symbol.endswith(".GFEX")


def _is_mak_symbol(row: dict[str, Any]) -> bool:
    vt_symbol = str(row.get("vt_symbol") or f"{row.get('symbol')}.{row.get('exchange')}")
    return vt_symbol.startswith(("lc", "ps", "GFEX.lc", "GFEX.ps"))


def _hash(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _safe_text(value: str) -> str:
    return TCP_ADDRESS_RE.sub("tcp://***", value)[:240]


mak_v2_safety_audit_service = MakV2SafetyAuditService()
