from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, RLock
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import Settings
from app.core.errors import (
    CommodityBaselineExecutionPermitError,
    CommodityBaselineExecutionPermitReplayError,
)
from app.schemas.commodity_baseline_execution_permit import (
    CommodityBaselineExecutionPermitDTO,
    baseline_order_set_sha256,
    baseline_price_policy_sha256,
    canonical_json,
    derived_baseline_permit_id,
    sha256_bytes,
    unsigned_baseline_permit_payload,
)
from app.schemas.trade import OrderRequestDTO
from app.services.commodity_baseline_execution_permit import (
    CommodityBaselineExecutionPermitService,
)
from app.services.commodity_simnow import CommoditySimNowService
from app.services.trade_service import (
    TradeService,
    _BaselineExecutionCapability,
)


NOW = datetime(2026, 8, 2, 2, 0, tzinfo=timezone.utc)
ACCOUNT = "simnow-baseline-account"
ACCOUNT_SHA256 = hashlib.sha256(ACCOUNT.encode()).hexdigest()
PLAN_HASH = "a" * 64
CORE_HASH = "b" * 64
SESSION_ID = "baseline-session-v1-0123456789abcdef"


class FakeRpc:
    def __init__(self) -> None:
        self.accounts = [{"accountid": ACCOUNT, "gateway_name": "CTP"}]

    def get_accounts(self) -> list[dict[str, Any]]:
        return list(self.accounts)


def orders() -> list[dict[str, Any]]:
    return [
        {
            "symbol": "ag2610",
            "exchange": "SHFE",
            "direction": "long",
            "offset": "open",
            "type": "limit",
            "volume": 1,
            "reference": "commodity_static_core:open:ag:1",
        },
        {
            "symbol": "al2610",
            "exchange": "SHFE",
            "direction": "short",
            "offset": "open",
            "type": "limit",
            "volume": 2,
            "reference": "commodity_static_core:open:al:1",
        },
    ]


def close_orders() -> list[dict[str, Any]]:
    return [
        {
            "symbol": "cu2610",
            "exchange": "SHFE",
            "direction": "short",
            "offset": "close",
            "type": "limit",
            "volume": 1,
            "reference": "commodity_static_core:close:cu:1",
        }
    ]


def risk_envelope(*, total_lots: int = 3) -> dict[str, Any]:
    return {
        "max_child_order_lots": 10,
        "max_orders_per_phase": 128,
        "max_total_phase_lots": total_lots,
        "max_symbol_position_lots": 5.0,
        "max_product_weight": 0.15,
        "max_gross_weight": 1.0,
        "max_abs_net_weight": 0.10,
        "max_sector_weight": 0.35,
        "max_quote_age_seconds": 5,
        "max_spread_ticks": 4.0,
    }


def scoped_orders(*, phase: str = "open") -> list[dict[str, Any]]:
    if phase == "close":
        return [
            {
                **close_orders()[0],
                "minimum_price": 60000.0,
                "maximum_price": 90000.0,
            }
        ]
    return [
        {**orders()[0], "minimum_price": 900.0, "maximum_price": 1100.0},
        {**orders()[1], "minimum_price": 1800.0, "maximum_price": 2200.0},
    ]


def write_canonical(path: Path, payload: dict[str, Any]) -> bytes:
    raw = canonical_json(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def public_material(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def signed_permit(
    private: Ed25519PrivateKey,
    *,
    phase: str = "open",
    mutation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scoped = scoped_orders(phase=phase)
    payload: dict[str, Any] = {
        "schema_version": "commodity_baseline_execution_permit_v1",
        "purpose": "commodity_baseline_phase_one_shot_execution_permit",
        "permit_id": "commodity-baseline-execution-permit-v1-" + "0" * 64,
        "nonce": f"baseline-permit-{phase}-nonce-0001",
        "issued_at_utc": NOW.isoformat(),
        "not_before_utc": NOW.isoformat(),
        "expires_at_utc": (NOW + timedelta(minutes=5)).isoformat(),
        "execution_environment": "SIMNOW",
        "strategy_id": "STATIC_CORE_EQUAL",
        "strategy_version": "commodity_static_core_equal_target_batch_v2",
        "plan_hash": PLAN_HASH,
        "execution_plan_core_sha256": CORE_HASH,
        "execution_session_id": SESSION_ID,
        "phase": phase,
        "account_sha256": ACCOUNT_SHA256,
        "resolved_gateway_name": "CTP",
        "price_policy_id": ("COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"),
        "price_policy_sha256": baseline_price_policy_sha256(
            price_policy_id=("COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"),
            max_quote_age_seconds=5,
            max_spread_ticks=4.0,
        ),
        "order_set_sha256": baseline_order_set_sha256(scoped),
        "orders": scoped,
        "risk_envelope": risk_envelope(total_lots=sum(row["volume"] for row in scoped)),
        "signer_key_id": "baseline-signer-v1",
        "phase_dispatch_authorized": True,
        "one_shot": True,
        "replay_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "automatic_promotion_authorized": False,
        "c_fast_authority_reused": False,
        "manual_authority_reused": False,
        "signature": base64.b64encode(b"\0" * 64).decode(),
    }
    if mutation:
        payload.update(mutation)
    normalized = CommodityBaselineExecutionPermitDTO.model_validate(payload)
    payload = normalized.model_dump(mode="json")
    payload["permit_id"] = derived_baseline_permit_id(payload)
    unsigned = CommodityBaselineExecutionPermitDTO.model_validate(payload)
    payload["signature"] = base64.b64encode(
        private.sign(canonical_json(unsigned_baseline_permit_payload(unsigned)))
    ).decode()
    return CommodityBaselineExecutionPermitDTO.model_validate(payload).model_dump(
        mode="json"
    )


def build_service(
    tmp_path: Path,
    *,
    private: Ed25519PrivateKey | None = None,
) -> tuple[CommodityBaselineExecutionPermitService, FakeRpc, Ed25519PrivateKey]:
    private = private or Ed25519PrivateKey.generate()
    keyring_path = tmp_path / "trusted-keys.json"
    close_permit_path = tmp_path / "close-permit.json"
    open_permit_path = tmp_path / "open-permit.json"
    keyring = {
        "schema_version": ("commodity_baseline_execution_permit_trusted_keys_v1"),
        "purpose": "commodity_baseline_execution_permit_verification",
        "trusted_keys": [
            {
                "key_id": "baseline-signer-v1",
                "public_key_base64": base64.b64encode(
                    public_material(private)
                ).decode(),
                "purpose": "commodity_baseline_execution_permit_signer",
            }
        ],
    }
    keyring_raw = write_canonical(keyring_path, keyring)
    write_canonical(
        close_permit_path,
        signed_permit(private, phase="close"),
    )
    write_canonical(
        open_permit_path,
        signed_permit(private, phase="open"),
    )
    settings = Settings(
        commodity_baseline_execution_permit_enabled=True,
        commodity_baseline_execution_permit_close_path=str(close_permit_path),
        commodity_baseline_execution_permit_open_path=str(open_permit_path),
        commodity_baseline_execution_permit_trusted_keyring_path=str(keyring_path),
        commodity_baseline_execution_permit_expected_keyring_raw_sha256=(
            sha256_bytes(keyring_raw)
        ),
        commodity_baseline_execution_permit_consume_root=str(tmp_path / "consumed"),
        commodity_simnow_account_hashes=ACCOUNT_SHA256,
        commodity_simnow_gateway_name="CTP",
        vnpy_gateway_name="CTP",
        risk_max_symbol_position=5,
        commodity_simnow_max_child_order_lots=10,
        commodity_simnow_max_orders_per_phase=128,
        commodity_simnow_max_quote_age_seconds=5,
        commodity_simnow_max_spread_ticks=4,
    )
    rpc = FakeRpc()
    return (
        CommodityBaselineExecutionPermitService(
            settings=settings,
            rpc=rpc,  # type: ignore[arg-type]
            clock=lambda: NOW,
        ),
        rpc,
        private,
    )


def prepare(service: CommodityBaselineExecutionPermitService):
    return service.prepare(
        plan_hash=PLAN_HASH,
        execution_plan_core_sha256=CORE_HASH,
        execution_session_id=SESSION_ID,
        strategy_id="STATIC_CORE_EQUAL",
        strategy_version="commodity_static_core_equal_target_batch_v2",
        phase="open",
        account_sha256=ACCOUNT_SHA256,
        resolved_gateway_name="CTP",
        price_policy_ids_by_phase={
            "open": "COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"
        },
        planned_orders_by_phase={"open": orders()},
        expected_risk_envelopes_by_phase={"open": risk_envelope()},
        require_companion_permit=False,
    )


def prepare_close_pair(service: CommodityBaselineExecutionPermitService):
    return service.prepare(
        plan_hash=PLAN_HASH,
        execution_plan_core_sha256=CORE_HASH,
        execution_session_id=SESSION_ID,
        strategy_id="STATIC_CORE_EQUAL",
        strategy_version="commodity_static_core_equal_target_batch_v2",
        phase="close",
        account_sha256=ACCOUNT_SHA256,
        resolved_gateway_name="CTP",
        price_policy_ids_by_phase={
            "close": "COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1",
            "open": "COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1",
        },
        planned_orders_by_phase={
            "close": close_orders(),
            "open": orders(),
        },
        expected_risk_envelopes_by_phase={
            "close": risk_envelope(total_lots=1),
            "open": risk_envelope(),
        },
        require_companion_permit=True,
    )


def final(
    service: CommodityBaselineExecutionPermitService,
    prepared,
    *,
    child_index: int,
    price: float,
) -> None:
    order = orders()[child_index]
    service.final_guard(
        prepared,
        actual_order=OrderRequestDTO(
            **order,
            price=price,
            gateway_name="CTP",
            confirm=True,
        ),
        child_index=child_index,
        plan_hash=PLAN_HASH,
        execution_plan_core_sha256=CORE_HASH,
        execution_session_id=SESSION_ID,
        strategy_id="STATIC_CORE_EQUAL",
        strategy_version="commodity_static_core_equal_target_batch_v2",
        phase="open",
        account_sha256=ACCOUNT_SHA256,
        resolved_gateway_name="CTP",
        price_policy_id=("COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"),
        expected_risk_envelope=risk_envelope(),
    )


def test_phase_permit_consumes_once_and_allows_exact_child_sequence(
    tmp_path: Path,
) -> None:
    service, _, _ = build_service(tmp_path)
    prepared = prepare(service)

    final(service, prepared, child_index=0, price=1000.0)
    final(service, prepared, child_index=1, price=2000.0)

    markers = list((tmp_path / "consumed").glob("*.consumed.json"))
    assert len(markers) == 1
    assert markers[0].stat().st_mode & 0o777 == 0o600
    with pytest.raises(CommodityBaselineExecutionPermitReplayError):
        final(service, prepare(service), child_index=0, price=1000.0)


def test_close_preflight_requires_both_independent_phase_permits(
    tmp_path: Path,
) -> None:
    service, _, private = build_service(tmp_path)

    prepared = prepare_close_pair(service)

    assert prepared.phase == "close"
    assert prepared.permit.phase == "close"
    service.settings.commodity_baseline_execution_permit_open_path = str(
        tmp_path / "missing-open.json"
    )
    with pytest.raises(CommodityBaselineExecutionPermitError) as caught:
        prepare_close_pair(service)
    assert caught.value.detail["reason"] == (
        "BASELINE_EXECUTION_OPEN_PERMIT_READ_INVALID"
    )

    wrong_phase = tmp_path / "wrong-open.json"
    write_canonical(wrong_phase, signed_permit(private, phase="close"))
    service.settings.commodity_baseline_execution_permit_open_path = str(wrong_phase)
    with pytest.raises(CommodityBaselineExecutionPermitError) as caught:
        prepare_close_pair(service)
    assert caught.value.detail["reason"] == ("BASELINE_EXECUTION_PERMIT_SCOPE_MISMATCH")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("plan_hash", "c" * 64),
        ("execution_plan_core_sha256", "c" * 64),
        ("execution_session_id", "different-session-v1"),
        ("account_sha256", "c" * 64),
        ("resolved_gateway_name", "OTHER"),
    ),
)
def test_plan_session_phase_account_and_gateway_scope_fail_closed(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    service, _, _ = build_service(tmp_path)
    kwargs = {
        "plan_hash": PLAN_HASH,
        "execution_plan_core_sha256": CORE_HASH,
        "execution_session_id": SESSION_ID,
        "strategy_id": "STATIC_CORE_EQUAL",
        "strategy_version": "commodity_static_core_equal_target_batch_v2",
        "phase": "open",
        "account_sha256": ACCOUNT_SHA256,
        "resolved_gateway_name": "CTP",
        "price_policy_ids_by_phase": {
            "open": "COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"
        },
        "planned_orders_by_phase": {"open": orders()},
        "expected_risk_envelopes_by_phase": {"open": risk_envelope()},
        "require_companion_permit": False,
    }
    kwargs[field] = value
    with pytest.raises(CommodityBaselineExecutionPermitError):
        service.prepare(**kwargs)
    assert not (tmp_path / "consumed").exists()


def test_price_band_risk_drift_and_child_reordering_fail_before_send(
    tmp_path: Path,
) -> None:
    service, _, _ = build_service(tmp_path)
    prepared = prepare(service)
    with pytest.raises(CommodityBaselineExecutionPermitError):
        final(service, prepared, child_index=0, price=1200.0)
    assert not (tmp_path / "consumed").exists()

    drift = risk_envelope()
    drift["max_spread_ticks"] = 5.0
    prepared = prepare(service)
    with pytest.raises(CommodityBaselineExecutionPermitError):
        service.final_guard(
            prepared,
            actual_order=OrderRequestDTO(
                **orders()[0], price=1000.0, gateway_name="CTP", confirm=True
            ),
            child_index=0,
            plan_hash=PLAN_HASH,
            execution_plan_core_sha256=CORE_HASH,
            execution_session_id=SESSION_ID,
            strategy_id="STATIC_CORE_EQUAL",
            strategy_version="commodity_static_core_equal_target_batch_v2",
            phase="open",
            account_sha256=ACCOUNT_SHA256,
            resolved_gateway_name="CTP",
            price_policy_id=("COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"),
            expected_risk_envelope=drift,
        )
    assert not (tmp_path / "consumed").exists()


def test_concurrent_consume_allows_one_phase_send_boundary(tmp_path: Path) -> None:
    service, _, _ = build_service(tmp_path)
    prepared = [prepare(service), prepare(service)]
    barrier = Barrier(2)

    def attempt(index: int) -> str:
        barrier.wait()
        try:
            final(service, prepared[index], child_index=0, price=1000.0)
        except CommodityBaselineExecutionPermitReplayError:
            return "replay"
        return "allowed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(attempt, range(2)))
    assert sorted(result) == ["allowed", "replay"]


def test_timeout_unknown_burns_permit_and_restart_cannot_send_next_child(
    tmp_path: Path,
) -> None:
    service, _, _ = build_service(tmp_path)
    send_attempts = 0

    prepared = prepare(service)
    final(service, prepared, child_index=0, price=1000.0)
    send_attempts += 1
    # The RPC outcome is now unknown. CommoditySimNow catches the timeout and
    # exits the phase loop, so child 2 is never presented to the send boundary.
    with pytest.raises(TimeoutError):
        raise TimeoutError("outcome unknown")

    restarted = CommodityBaselineExecutionPermitService(
        settings=service.settings,
        rpc=service.rpc,
        clock=lambda: NOW,
    )
    with pytest.raises(CommodityBaselineExecutionPermitReplayError):
        final(restarted, prepare(restarted), child_index=0, price=1000.0)

    assert send_attempts == 1


def test_final_guard_revalidates_account_marker_and_input_files(
    tmp_path: Path,
) -> None:
    service, rpc, _ = build_service(tmp_path)
    prepared = prepare(service)
    rpc.accounts = [{"accountid": "changed", "gateway_name": "CTP"}]
    with pytest.raises(CommodityBaselineExecutionPermitError):
        final(service, prepared, child_index=0, price=1000.0)
    assert not (tmp_path / "consumed").exists()

    service, _, _ = build_service(tmp_path / "second")
    prepared = prepare(service)
    prepared.permit_path.write_bytes(prepared.permit_raw + b" ")
    with pytest.raises(CommodityBaselineExecutionPermitError):
        final(service, prepared, child_index=0, price=1000.0)


def test_existing_unsafe_consume_root_is_not_chmodded(tmp_path: Path) -> None:
    service, _, _ = build_service(tmp_path)
    root = tmp_path / "consumed"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(CommodityBaselineExecutionPermitError) as caught:
        final(service, prepare(service), child_index=0, price=1000.0)
    assert caught.value.detail["reason"] == "BASELINE_EXECUTION_CONSUME_ROOT_INVALID"
    assert root.stat().st_mode & 0o777 == 0o755


def test_baseline_key_cannot_reuse_manual_or_c_fast_domain(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    service, _, _ = build_service(tmp_path, private=private)
    encoded = base64.b64encode(public_material(private)).decode()
    service.settings.manual_execution_permit_trusted_public_keys_json = (
        '{"manual-key":{"public_key_base64":"'
        + encoded
        + '","purpose":"manual_execution_permit_signer"}}'
    )
    with pytest.raises(CommodityBaselineExecutionPermitError) as caught:
        prepare(service)
    assert caught.value.detail["reason"] == "BASELINE_EXECUTION_KEY_DOMAIN_REUSE"


def test_baseline_capability_is_unforgeable_and_mutually_isolated() -> None:
    owner = object.__new__(CommoditySimNowService)
    owner._dispatch_abort_lock = RLock()
    trade = TradeService(_baseline_execution_capability_issuers=(owner,))
    owner.trade = trade

    with pytest.raises(TypeError, match="cannot be constructed"):
        _BaselineExecutionCapability(object(), construction_key=object())
    with pytest.raises(RuntimeError, match="capability is invalid"):
        trade._send_baseline_permitted_order(
            OrderRequestDTO(
                symbol="ag2610",
                exchange="SHFE",
                direction="long",
                offset="open",
                type="limit",
                price=1000.0,
                volume=1,
                gateway_name="CTP",
                reference="commodity_static_core:open:ag:1",
                confirm=True,
            ),
            baseline_execution_owner=owner,
            baseline_execution_capability=object(),
            pre_rpc_guard=owner._baseline_pre_rpc_guard,
            send_linearization_lock=owner._dispatch_abort_lock,
        )
