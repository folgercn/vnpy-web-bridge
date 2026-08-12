from __future__ import annotations

import ast
import math
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    build_executable_target_plan,
    build_trusted_keyless_executable_target_plan,
)
from app.execution.gateway import GatewaySnapshot

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    before_position_projection_hash,
    sha256_json,
    target_position_projection_hash,
)

SCOPE = "account:simnow-adapter"
GATEWAY = "gateway-adapter"
ROOT = Path(__file__).resolve().parents[3]

FALSE_FLAGS = {
    "control_authorized": False,
    "deployment_authorized": False,
    "runtime_activation_authorized": False,
    "network_authorized": False,
    "web_bridge_rpc_authorized": False,
    "production_authorized": False,
    "automatic_promotion_authorized": False,
    "production_allowed": False,
    "live_allowed": False,
    "countable_forward": False,
    "authority_granted": False,
    "signing_requested": False,
    "custody_published": False,
    "execution_authorized": False,
    "simnow_execution_authorized": False,
    "order_authorized": False,
    "order_submission_authorized": False,
    "position_mutation_authorized": False,
    "dispatch_authorized": False,
    "trading_authorized": False,
}


def candidates(
    *,
    target_quantity: int = 1,
    product: str = "rb",
    exact_contract: str = "SHFE.rb2601",
    reference_open_price: float = 3500.0,
    price_tick: float = 5.0,
) -> tuple[dict, dict]:
    map_candidate = {
        "schema_version": "commodity_map_signal_candidate_v1",
        "artifact_role": "unsigned_map_signal_candidate",
        "status": "UNSIGNED_MAP_SIGNAL_CANDIDATE",
        "candidate_id": "map-signal-v1-" + "a" * 64,
        "lineage": {
            "source_view_canonical_sha256": "b" * 64,
            "source_receipt_sha256": "c" * 64,
        },
        **FALSE_FLAGS,
    }
    map_hash = sha256_json(map_candidate)
    c_fast_candidate = {
        "schema_version": "commodity_c_fast_target_candidate_v1",
        "artifact_role": "unsigned_c_fast_target_candidate",
        "status": "UNSIGNED_C_FAST_TARGET_CANDIDATE",
        "candidate_id": "c-fast-target-v1-" + "d" * 64,
        "predecessor": {
            "artifact_sha256": map_hash,
            "candidate_id": map_candidate["candidate_id"],
        },
        "lineage": {
            "map_predecessor_sha256": map_hash,
            "map_candidate_id": map_candidate["candidate_id"],
            "source_view_canonical_sha256": "b" * 64,
            "source_receipt_sha256": "c" * 64,
        },
        "targets": [
            {
                "product": product,
                "exact_contract": exact_contract,
                "target_quantity": target_quantity,
                "reference_open_price": reference_open_price,
                "price_tick": price_tick,
            }
        ],
        **FALSE_FLAGS,
    }
    return map_candidate, c_fast_candidate


def authority(*, scope: dict | None = None) -> dict:
    return {
        "receipt_id": "custody-install-adapter-0001",
        "receipt_type": "install",
        "artifact_id": "artifact-runtime-adapter-0001",
        "artifact_type": "runtime-authorization",
        "trust_domain": "runtime_authorization",
        "schema_ref": "phase-c-runtime-authorization-v1",
        "artifact_sha256": "a" * 64,
        "signer_key_id": "offline-adapter-key",
        "signer_key_version": "v1",
        "keyring_raw_sha256": "b" * 64,
        "signed_artifact_sha256": "c" * 64,
        "scope": scope
        or {
            "account_scope": SCOPE,
            "environment": "SIMNOW",
            "gateway_name": GATEWAY,
        },
        "expires_at": "2099-01-01T00:00:00Z",
        "custody_version": 2,
        "idempotency_key": "custody-adapter-key-0001",
        "verified": True,
        "installed": True,
        "custody_writer": "artifact-custody",
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }


def positions(
    *,
    long: int = 0,
    short: int = 0,
    yd_long: int | None = 0,
    yd_short: int | None = 0,
    dynamic: bool = False,
) -> dict:
    result: dict[str, dict] = {}
    if long:
        result["RB2601.SHFE.LONG"] = {
            "gateway_name": GATEWAY,
            "symbol": "RB2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": long,
            "price": 3500.0 if not dynamic else 3701.0,
            "pnl": 0.0 if not dynamic else 123.45,
            "frozen": 0 if not dynamic else 7,
            "commission": 0.0 if not dynamic else 9.0,
        }
        if yd_long is not None:
            result["RB2601.SHFE.LONG"]["yd_volume"] = yd_long
    if short:
        result["RB2601.SHFE.SHORT"] = {
            "gateway_name": GATEWAY,
            "symbol": "RB2601",
            "exchange": "SHFE",
            "direction": "SHORT",
            "volume": short,
        }
        if yd_short is not None:
            result["RB2601.SHFE.SHORT"]["yd_volume"] = yd_short
    return result


def snapshot(
    values: dict | None = None, *, active_orders: dict | None = None, scope: str = SCOPE
) -> GatewaySnapshot:
    values = positions() if values is None else values
    active_orders = active_orders or {}
    return GatewaySnapshot(
        snapshot_id="snapshot-peek-adapter-0001",
        generation=1,
        connected=True,
        active_order_count=len(active_orders),
        position_snapshot_hash=sha256_json(values),
        orders=active_orders,
        positions=values,
        account_scope=scope,
        environment="SIMNOW",
        fresh=True,
    )


def adapt(
    *,
    target_quantity: int = 1,
    current: GatewaySnapshot | None = None,
    receipt: dict | None = None,
    reconciliation: dict | None = None,
    product: str = "rb",
    exact_contract: str = "SHFE.rb2601",
    reduce_only_close: bool = False,
    reduce_only_close_limit_price: float | None = None,
    reference_open_price: float = 3500.0,
    price_tick: float = 5.0,
) -> object:
    map_candidate, c_fast_candidate = candidates(
        target_quantity=target_quantity,
        product=product,
        exact_contract=exact_contract,
        reference_open_price=reference_open_price,
        price_tick=price_tick,
    )
    return build_executable_target_plan(
        map_candidate=map_candidate,
        c_fast_candidate=c_fast_candidate,
        authority_receipt=authority() if receipt is None else receipt,
        current_facts=snapshot() if current is None else current,
        reconciliation=reconciliation or {"state": "RECONCILED", "unknown_outcomes": 0},
        product=product,
        account_scope=SCOPE,
        environment="SIMNOW",
        gateway_name=GATEWAY,
        reduce_only_close=reduce_only_close,
        reduce_only_close_limit_price=reduce_only_close_limit_price,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )


def test_trusted_keyless_adapter_requires_fixed_tuple_and_preserves_lineage() -> None:
    map_candidate, c_fast_candidate = candidates()
    handoff = build_trusted_keyless_executable_target_plan(
        map_candidate=map_candidate,
        c_fast_candidate=c_fast_candidate,
        current_facts=snapshot(scope="account:windows"),
        reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
        product="rb",
        expires_at="2099-01-01T00:00:00Z",
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert handoff.target_plan["scope"] == {
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "gateway_name": "CTP",
    }
    assert set(handoff.target_plan["lineage"]) == {"map_sha256", "c_fast_sha256"}
    assert handoff.trusted_keyless_custody_artifact()["payload"] == handoff.target_plan
    with pytest.raises(ExecutableTargetAdapterError, match="active orders"):
        build_trusted_keyless_executable_target_plan(
            map_candidate=map_candidate,
            c_fast_candidate=c_fast_candidate,
            current_facts=snapshot(
                active_orders={"working-order": {}}, scope="account:windows"
            ),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
            product="rb",
            expires_at="2099-01-01T00:00:00Z",
            now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
    for reconciliation in (
        {"state": "PENDING", "unknown_outcomes": 0},
        {"state": "RECONCILED", "unknown_outcomes": 1},
    ):
        with pytest.raises(ExecutableTargetAdapterError, match="unknown or unreconciled"):
            build_trusted_keyless_executable_target_plan(
                map_candidate=map_candidate,
                c_fast_candidate=c_fast_candidate,
                current_facts=snapshot(scope="account:windows"),
                reconciliation=reconciliation,
                product="rb",
                expires_at="2099-01-01T00:00:00Z",
                now=datetime(2030, 1, 1, tzinfo=timezone.utc),
            )


def test_adapter_preserves_map_cfast_lineage_scope_expiry_and_delta() -> None:
    map_candidate, c_fast_candidate = candidates()
    authority_artifact = new_artifact_envelope(
        artifact_type="runtime-authorization",
        trust_domain="runtime_authorization",
        producer_id="runtime-authority-fixture",
        producer_version="v1",
        schema_ref="phase-c-runtime-authorization-v1",
        payload={
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        generated_at="2020-01-01T00:00:00Z",
        scope=authority()["scope"],
        predecessor_refs=[],
        lineage=[],
    )
    authority_receipt = authority()
    authority_receipt["artifact_id"] = authority_artifact["artifact_id"]
    authority_receipt["artifact_sha256"] = authority_artifact["raw_sha256"]
    handoff = build_executable_target_plan(
        map_candidate=map_candidate,
        c_fast_candidate=c_fast_candidate,
        authority_receipt=authority_receipt,
        current_facts=snapshot(),
        reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
        product="rb",
        account_scope=SCOPE,
        environment="SIMNOW",
        gateway_name=GATEWAY,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )

    plan = handoff.target_plan
    expected_before = before_position_projection_hash(
        {}, account_scope=SCOPE, environment="SIMNOW"
    )
    assert plan["expected_before_position_hash"] == expected_before
    identity = sha256_json(
        {
            "map_sha256": sha256_json(map_candidate),
            "c_fast_sha256": sha256_json(c_fast_candidate),
            "expected_before_position_hash": expected_before,
            "product": "rb",
            "gateway_name": GATEWAY,
        }
    )
    assert plan["plan_id"] == f"cfast-target-plan-v1-{identity}"
    assert plan["orders"][0]["reference"] == identity
    assert len(plan["orders"][0]["reference"]) == 64
    assert adapt().target_plan["orders"][0]["reference"] == identity
    assert plan["orders"] == [
        {
            "symbol": "rb2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "type": "LIMIT",
            "volume": 1,
            "price": 3500.0,
            "offset": "OPEN",
            "reference": plan["orders"][0]["reference"],
            "gateway_name": GATEWAY,
        }
    ]
    assert handoff.lineage == (
        sha256_json(map_candidate),
        sha256_json(c_fast_candidate),
    )
    assert handoff.scope == authority()["scope"]
    assert handoff.expires_at == authority()["expires_at"]
    envelope = handoff.artifact_envelope(
        generated_at="2030-01-01T00:00:00Z",
        authority_artifact=authority_artifact,
    )
    assert envelope["predecessor_refs"] == [
        {
            "artifact_id": authority_artifact["artifact_id"],
            "canonical_sha256": authority_artifact["canonical_sha256"],
        }
    ]
    assert envelope["lineage"] == [authority_artifact["canonical_sha256"]]
    assert envelope["scope"] == handoff.scope


@pytest.mark.parametrize(
    ("target_quantity", "current_positions", "direction", "offset"),
    [
        (1, positions(), "LONG", "OPEN"),
        (0, positions(long=1), "SHORT", "CLOSETODAY"),
        (0, positions(short=1), "LONG", "CLOSETODAY"),
        (-1, positions(), "SHORT", "OPEN"),
    ],
)
def test_adapter_derives_direction_and_open_close_from_target_minus_current(
    target_quantity: int, current_positions: dict, direction: str, offset: str
) -> None:
    handoff = adapt(
        target_quantity=target_quantity,
        current=snapshot(current_positions),
    )
    assert handoff.target_plan["orders"][0]["direction"] == direction
    assert handoff.target_plan["orders"][0]["offset"] == offset


@pytest.mark.parametrize(
    ("current_positions", "direction"),
    [
        (positions(short=1), "LONG"),
        (positions(long=1), "SHORT"),
    ],
)
def test_reduce_only_close_derives_zero_target_and_opposite_close(
    current_positions: dict, direction: str
) -> None:
    handoff = adapt(
        target_quantity=-1,
        current=snapshot(current_positions),
        reduce_only_close=True,
        reduce_only_close_limit_price=3500.0,
    )

    order = handoff.target_plan["orders"][0]
    assert order["direction"] == direction
    assert order["offset"] == "CLOSETODAY"
    assert order["volume"] == 1
    assert handoff.target_plan["phase"] == "CLOSE"
    assert handoff.target_plan["production_allowed"] is False
    assert handoff.target_plan["live_trading_authorized"] is False
    assert handoff.target_plan["countable_forward"] is False
    assert handoff.target_plan["expected_after_position_hash"] == (
        target_position_projection_hash({}, account_scope=SCOPE, environment="SIMNOW")
    )


@pytest.mark.parametrize(
    ("current_positions", "product", "exact_contract", "message"),
    [
        (positions(), "rb", "SHFE.rb2601", "exactly one C_FAST contract position"),
        (positions(short=2), "rb", "SHFE.rb2601", "one-lot"),
        (
            positions(long=1, short=1),
            "rb",
            "SHFE.rb2601",
            "exactly one C_FAST contract position",
        ),
        (
            {
                "RB2601.SHFE.LONG": {
                    "gateway_name": GATEWAY,
                    "symbol": "RB2601",
                    "exchange": "SHFE",
                    "direction": "LONG",
                    "volume": 1,
                    "yd_volume": 0,
                }
            },
            "ru",
            "SHFE.ru2609",
            "exactly one C_FAST contract position",
        ),
    ],
)
def test_reduce_only_close_rejects_zero_multi_direction_and_symbol_mismatch(
    current_positions: dict, product: str, exact_contract: str, message: str
) -> None:
    with pytest.raises(ExecutableTargetAdapterError, match=message):
        adapt(
            target_quantity=-1,
            current=snapshot(current_positions),
            product=product,
            exact_contract=exact_contract,
            reduce_only_close=True,
            reduce_only_close_limit_price=3500.0,
        )


@pytest.mark.parametrize(
    ("current", "reconciliation", "message"),
    [
        (
            snapshot(positions(short=1), active_orders={"active-1": {}}),
            None,
            "active orders",
        ),
        (
            snapshot(positions(short=1)),
            {"state": "RECONCILED", "unknown_outcomes": 1},
            "unknown",
        ),
        (snapshot(positions(short=1), scope="account:other"), None, "scope/freshness"),
    ],
)
def test_reduce_only_close_rejects_active_unknown_and_scope_mismatch(
    current: GatewaySnapshot, reconciliation: dict | None, message: str
) -> None:
    with pytest.raises(ExecutableTargetAdapterError, match=message):
        adapt(
            target_quantity=-1,
            current=current,
            reconciliation=reconciliation,
            reduce_only_close=True,
            reduce_only_close_limit_price=3500.0,
        )


def test_reduce_only_close_requires_existing_cfast_short_target() -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="C_FAST target to be -1"):
        adapt(
            target_quantity=0,
            current=snapshot(positions(short=1)),
            reduce_only_close=True,
            reduce_only_close_limit_price=3500.0,
        )


def test_reduce_only_close_requires_explicit_aligned_operator_limit_price() -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="limit price is invalid"):
        adapt(
            target_quantity=-1,
            current=snapshot(positions(short=1)),
            reduce_only_close=True,
        )

    current = snapshot(
        {
            "RU2609.SHFE.SHORT": {
                "gateway_name": GATEWAY,
                "symbol": "RU2609",
                "exchange": "SHFE",
                "direction": "SHORT",
                "volume": 1,
                "yd_volume": 0,
            }
        }
    )
    at_17100 = adapt(
        target_quantity=-1,
        current=current,
        product="ru",
        exact_contract="SHFE.ru2609",
        reference_open_price=16950.0,
        price_tick=5.0,
        reduce_only_close=True,
        reduce_only_close_limit_price=17100.0,
    )
    at_17105 = adapt(
        target_quantity=-1,
        current=current,
        product="ru",
        exact_contract="SHFE.ru2609",
        reference_open_price=16950.0,
        price_tick=5.0,
        reduce_only_close=True,
        reduce_only_close_limit_price=17105.0,
    )
    assert at_17100.target_plan["orders"][0]["price"] == 17100.0
    assert at_17100.target_plan["orders"][0]["price"] != 16950.0
    assert at_17100.target_plan["plan_hash"] != at_17105.target_plan["plan_hash"]


@pytest.mark.parametrize("limit_price", (17102.0, math.nan, 0.0, -5.0))
def test_reduce_only_close_rejects_invalid_operator_limit_price(
    limit_price: float,
) -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="limit price"):
        adapt(
            target_quantity=-1,
            current=snapshot(positions(short=1)),
            reduce_only_close=True,
            reduce_only_close_limit_price=limit_price,
        )


def test_normal_mode_rejects_reduce_only_limit_price() -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="requires reduce-only"):
        adapt(reduce_only_close_limit_price=3500.0)


@pytest.mark.parametrize(
    ("product", "exact_contract"),
    [
        ("ag", "SHFE.ag2609"),
        ("au", "SHFE.au2609"),
        ("ru", "SHFE.ru2609"),
    ],
)
def test_adapter_preserves_vnpy_native_symbol_case_from_exact_contract(
    product: str, exact_contract: str
) -> None:
    handoff = adapt(product=product, exact_contract=exact_contract)

    order = handoff.target_plan["orders"][0]
    assert order["symbol"] == exact_contract.split(".", 1)[1]
    assert order["exchange"] == "SHFE"


def test_adapter_matches_existing_position_case_insensitively_and_emits_native_symbol() -> (
    None
):
    handoff = adapt(
        product="ru",
        exact_contract="SHFE.ru2609",
        target_quantity=0,
        current=snapshot(
            {
                "RU2609.SHFE.LONG": {
                    "gateway_name": GATEWAY,
                    "symbol": "RU2609",
                    "exchange": "SHFE",
                    "direction": "LONG",
                    "volume": 1,
                    "yd_volume": 0,
                }
            }
        ),
    )

    assert handoff.target_plan["orders"][0]["symbol"] == "ru2609"
    assert handoff.target_plan["orders"][0]["direction"] == "SHORT"
    assert handoff.target_plan["orders"][0]["offset"] == "CLOSETODAY"


@pytest.mark.parametrize(
    ("exact_contract", "product", "current_positions", "expected_offset"),
    [
        ("SHFE.rb2601", "rb", positions(short=1, yd_short=0), "CLOSETODAY"),
        (
            "SHFE.rb2601",
            "rb",
            positions(short=1, yd_short=1),
            "CLOSEYESTERDAY",
        ),
        (
            "INE.sc2601",
            "sc",
            {
                "SC2601.INE.SHORT": {
                    "gateway_name": GATEWAY,
                    "symbol": "SC2601",
                    "exchange": "INE",
                    "direction": "SHORT",
                    "volume": 1,
                    "yd_volume": 0,
                }
            },
            "CLOSETODAY",
        ),
    ],
)
def test_adapter_selects_shfe_ine_close_offset_from_authoritative_yd_volume(
    exact_contract: str,
    product: str,
    current_positions: dict,
    expected_offset: str,
) -> None:
    handoff = adapt(
        target_quantity=0,
        current=snapshot(current_positions),
        product=product,
        exact_contract=exact_contract,
    )

    assert handoff.target_plan["phase"] == "CLOSE"
    assert handoff.target_plan["orders"][0]["offset"] == expected_offset


@pytest.mark.parametrize(
    "current_positions",
    [
        positions(short=1, yd_short=None),
        positions(short=1, yd_short=2),
    ],
)
def test_adapter_rejects_missing_or_inconsistent_shfe_yd_volume(
    current_positions: dict,
) -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="yd_volume"):
        adapt(target_quantity=0, current=snapshot(current_positions))


def test_adapter_keeps_generic_close_for_non_shfe_ine() -> None:
    handoff = adapt(
        target_quantity=0,
        current=snapshot(
            {
                "I2601.DCE.SHORT": {
                    "gateway_name": GATEWAY,
                    "symbol": "I2601",
                    "exchange": "DCE",
                    "direction": "SHORT",
                    "volume": 1,
                }
            }
        ),
        product="i",
        exact_contract="DCE.i2601",
    )

    assert handoff.target_plan["phase"] == "CLOSE"
    assert handoff.target_plan["orders"][0]["offset"] == "CLOSE"


def test_dynamic_broker_fields_do_not_change_target_position_projections() -> None:
    static = adapt(target_quantity=2, current=snapshot(positions(long=1)))
    dynamic = adapt(
        target_quantity=2, current=snapshot(positions(long=1, dynamic=True))
    )
    assert (
        static.target_plan["expected_after_position_hash"]
        == dynamic.target_plan["expected_after_position_hash"]
        == target_position_projection_hash(
            positions(long=2), account_scope=SCOPE, environment="SIMNOW"
        )
    )
    assert (
        static.target_plan["expected_before_position_hash"]
        == dynamic.target_plan["expected_before_position_hash"]
        == before_position_projection_hash(
            positions(long=1), account_scope=SCOPE, environment="SIMNOW"
        )
    )


def test_adapter_before_hash_binds_shfe_yd_volume() -> None:
    today = adapt(target_quantity=0, current=snapshot(positions(short=1, yd_short=0)))
    yesterday = adapt(
        target_quantity=0, current=snapshot(positions(short=1, yd_short=1))
    )

    assert (
        today.target_plan["expected_before_position_hash"]
        != yesterday.target_plan["expected_before_position_hash"]
    )


@pytest.mark.parametrize(
    ("current", "receipt", "message"),
    [
        (snapshot(scope="account:other"), None, "scope/freshness"),
        (
            None,
            authority(
                scope={
                    "account_scope": SCOPE,
                    "environment": "SIMNOW",
                    "gateway_name": "other",
                }
            ),
            "scope/gateway",
        ),
        (
            snapshot(
                {
                    "RB2601.SHFE.LONG": {
                        "gateway_name": "gateway-other",
                        "symbol": "RB2601",
                        "exchange": "SHFE",
                        "direction": "LONG",
                        "volume": 1,
                        "yd_volume": 0,
                    }
                }
            ),
            None,
            "gateway mismatch",
        ),
    ],
)
def test_adapter_scope_gateway_and_account_mismatch_fail_closed(
    current: GatewaySnapshot | None, receipt: dict | None, message: str
) -> None:
    with pytest.raises(ExecutableTargetAdapterError, match=message):
        adapt(current=current, receipt=receipt)


@pytest.mark.parametrize(
    ("target_quantity", "current", "reconciliation", "message"),
    [
        (0, snapshot(), None, "delta is zero"),
        (2, snapshot(), None, "one-lot"),
        (
            1,
            snapshot(active_orders={"active-1": {"state": "SUBMITTED"}}),
            None,
            "active orders",
        ),
        (1, snapshot(), {"state": "RECONCILED", "unknown_outcomes": 1}, "unknown"),
    ],
)
def test_adapter_blocks_zero_multi_lot_active_and_unknown_inputs(
    target_quantity: int,
    current: GatewaySnapshot,
    reconciliation: dict | None,
    message: str,
) -> None:
    with pytest.raises(ExecutableTargetAdapterError, match=message):
        adapt(
            target_quantity=target_quantity,
            current=current,
            reconciliation=reconciliation,
        )


def test_adapter_has_no_direct_rpc_or_execution_mutation_bypass() -> None:
    source = (ROOT / "backend/app/execution/executable_target_adapter.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert not any("rpc" in module.lower() for module in imported_modules)
    assert not {"ExecutionOrchestrator", "FinalExecutionRuntime"} & {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    assert not any(
        isinstance(node, ast.Attribute)
        and node.attr in {"send_order", "cancel_order", "call"}
        for node in ast.walk(tree)
    )


def test_adapter_rejects_broken_map_lineage() -> None:
    map_candidate, c_fast_candidate = candidates()
    broken = deepcopy(c_fast_candidate)
    broken["lineage"]["map_predecessor_sha256"] = "0" * 64
    with pytest.raises(ExecutableTargetAdapterError, match="lineage"):
        build_executable_target_plan(
            map_candidate=map_candidate,
            c_fast_candidate=broken,
            authority_receipt=authority(),
            current_facts=snapshot(),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
            product="rb",
            account_scope=SCOPE,
            environment="SIMNOW",
            gateway_name=GATEWAY,
            now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )


def test_adapter_requires_exact_complete_false_authority_contract() -> None:
    map_candidate, c_fast_candidate = candidates()
    for field in FALSE_FLAGS:
        broken = deepcopy(map_candidate)
        broken.pop(field)
        with pytest.raises(ExecutableTargetAdapterError, match="authority field set"):
            build_executable_target_plan(
                map_candidate=broken,
                c_fast_candidate=c_fast_candidate,
                authority_receipt=authority(),
                current_facts=snapshot(),
                reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
                product="rb",
                account_scope=SCOPE,
                environment="SIMNOW",
                gateway_name=GATEWAY,
            )
    for field in ("control_authorized", "signing_requested", "custody_published"):
        broken = deepcopy(c_fast_candidate)
        broken[field] = True
        with pytest.raises(
            ExecutableTargetAdapterError, match="attempts to grant authority"
        ):
            build_executable_target_plan(
                map_candidate=map_candidate,
                c_fast_candidate=broken,
                authority_receipt=authority(),
                current_facts=snapshot(),
                reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
                product="rb",
                account_scope=SCOPE,
                environment="SIMNOW",
                gateway_name=GATEWAY,
            )
    broken = deepcopy(c_fast_candidate)
    broken["operator_authorized"] = False
    with pytest.raises(ExecutableTargetAdapterError, match="authority field set"):
        build_executable_target_plan(
            map_candidate=map_candidate,
            c_fast_candidate=broken,
            authority_receipt=authority(),
            current_facts=snapshot(),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
            product="rb",
            account_scope=SCOPE,
            environment="SIMNOW",
            gateway_name=GATEWAY,
        )
