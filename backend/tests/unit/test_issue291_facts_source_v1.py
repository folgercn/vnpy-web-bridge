from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceError
from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.final_admission_v1 import (
    WindowsRpcFencedAdmissionV1,
)
from scripts.windows_fence_foundation.final_store_v1 import DurableFinalAdmissionStoreV1
from scripts.windows_rpc_durable_fence_v1 import (
    WindowsRpcRuntimeConfigV1,
    _execution_fact_value,
    _WindowsExecutionFactsV1,
)


class _Facts:
    def get_all_accounts(self):
        return [
            {
                "accountid": "sim-account",
                "vt_accountid": "CTP.sim-account",
                "balance": 100,
                "available": 90,
                "gateway_name": "CTP",
            }
        ]

    def get_all_orders(self):
        return [{"vt_orderid": "CTP.1", "symbol": "rb", "status": "NOTTRADED"}]

    def get_all_active_orders(self):
        return [{"vt_orderid": "CTP.1", "symbol": "rb", "status": "NOTTRADED"}]

    def get_all_positions(self):
        return [{"vt_positionid": "rb-long", "symbol": "rb", "volume": 2}]


class _NumericFacts:
    def __init__(self, numeric_type: type[float | Decimal]) -> None:
        self._numeric_type = numeric_type

    def _number(self, value: str) -> float | Decimal:
        return self._numeric_type(value)

    def get_all_accounts(self):
        return [
            {
                "accountid": "sim-account",
                "vt_accountid": "CTP.sim-account",
                "balance": self._number("100.50"),
                "frozen": self._number("10.25"),
                "available": self._number("90.0"),
                "gateway_name": "CTP",
            }
        ]

    def get_all_orders(self):
        return [
            {
                "vt_orderid": "CTP.1",
                "symbol": "rb",
                "price": self._number("3901.25"),
                "volume": self._number("2.0"),
                "traded": self._number("0.1"),
                "status": "NOTTRADED",
            }
        ]

    def get_all_active_orders(self):
        return self.get_all_orders()

    def get_all_positions(self):
        return [
            {
                "vt_positionid": "rb-long",
                "symbol": "rb",
                "volume": self._number("2.0"),
                "frozen": self._number("0.5"),
                "price": self._number("3901.25"),
                "pnl": self._number("-3.75"),
            }
        ]


def _source(
    tmp_path: Path, fact_source: object | None = None
) -> tuple[_WindowsExecutionFactsV1, Path, Path]:
    state_path = tmp_path / "final-store.json"
    store = DurableFinalAdmissionStoreV1.bootstrap(
        state_path, account_scope="account:sim", environment="simnow"
    )
    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:sim",
        environment="simnow",
        send_handler=lambda _request, _context: {"state": "REJECTED"},
        cancel_handler=lambda _request, _context: {"state": "REJECTED"},
        durable_store=store,
    )
    runtime = SimpleNamespace(
        fact_source=fact_source or _Facts(),
        config=WindowsRpcRuntimeConfigV1(
            gateway_setting={"probe": "only"},
            account_scope="account:sim",
            environment="simnow",
        ),
    )
    facts = _WindowsExecutionFactsV1(runtime)
    facts.bind_admission(admission)
    return facts, state_path, state_path.with_name(f"{state_path.name}.ledger")


def test_m2_peek_current_facts_is_canonical_and_never_allocates_or_writes(
    tmp_path: Path,
) -> None:
    facts, state_path, ledger_path = _source(tmp_path)
    before_state = state_path.read_bytes()
    before_ledger = ledger_path.read_bytes()

    raw = facts.peek_current_facts(
        {"account_scope": "account:sim", "environment": "simnow"}
    )
    value = json.loads(raw)

    assert canonical_json_bytes(value) == raw
    assert value["admission"]["snapshot_generation"] == 0
    assert value["admission"]["durable_state_version"] == 0
    assert value["account"]["CTP.sim-account"]["available"] == 90
    assert value["positions"]["rb-long"]["volume"] == 2
    assert list(value["active_orders"]) == ["CTP.1"]
    assert value["gateway"] == {
        "gateway_name": "CTP",
        "account_scope": "account:sim",
        "environment": "simnow",
        "connected": True,
    }
    assert state_path.read_bytes() == before_state
    assert ledger_path.read_bytes() == before_ledger


def test_m2_peek_current_facts_is_repeatable_without_durable_mutation(
    tmp_path: Path,
) -> None:
    facts, state_path, ledger_path = _source(tmp_path)
    before_state = state_path.read_bytes()
    before_ledger = ledger_path.read_bytes()
    request = {"account_scope": "account:sim", "environment": "simnow"}

    assert facts.peek_current_facts(request) == facts.peek_current_facts(request)
    assert state_path.read_bytes() == before_state
    assert ledger_path.read_bytes() == before_ledger


@pytest.mark.parametrize("numeric_type", [float, Decimal])
def test_m2_peek_projects_finite_oms_numbers_without_float_json(
    tmp_path: Path, numeric_type: type[float | Decimal]
) -> None:
    facts, state_path, ledger_path = _source(tmp_path, _NumericFacts(numeric_type))
    before_state = state_path.read_bytes()
    before_ledger = ledger_path.read_bytes()

    raw = facts.peek_current_facts(
        {"account_scope": "account:sim", "environment": "simnow"}
    )
    value = json.loads(raw)

    assert canonical_json_bytes(value) == raw
    assert value["account"]["CTP.sim-account"] == {
        "accountid": "sim-account",
        "vt_accountid": "CTP.sim-account",
        "balance": "100.5",
        "frozen": "10.25",
        "available": 90,
        "gateway_name": "CTP",
    }
    assert value["positions"]["rb-long"] == {
        "vt_positionid": "rb-long",
        "symbol": "rb",
        "volume": 2,
        "frozen": "0.5",
        "price": "3901.25",
        "pnl": "-3.75",
    }
    for orders in (value["execution"]["orders"], value["active_orders"]):
        assert orders["CTP.1"] == {
            "vt_orderid": "CTP.1",
            "symbol": "rb",
            "price": "3901.25",
            "volume": 2,
            "traded": "0.1",
            "status": "NOTTRADED",
        }
    assert state_path.read_bytes() == before_state
    assert ledger_path.read_bytes() == before_ledger


def test_execution_fact_numeric_projection_preserves_decimal_text() -> None:
    assert _execution_fact_value(0.1) == "0.1"
    assert (
        _execution_fact_value(Decimal("1.123456789012345678901234567890"))
        == "1.12345678901234567890123456789"
    )


@pytest.mark.parametrize(
    "numeric_type,value",
    [
        (float, float("nan")),
        (float, float("inf")),
        (float, -float("inf")),
        (Decimal, Decimal("NaN")),
        (Decimal, Decimal("Infinity")),
    ],
)
def test_m2_peek_rejects_nonfinite_oms_numbers(
    tmp_path: Path, numeric_type: type[float | Decimal], value: float | Decimal
) -> None:
    facts, state_path, ledger_path = _source(tmp_path, _NumericFacts(numeric_type))
    before_state = state_path.read_bytes()
    before_ledger = ledger_path.read_bytes()
    facts.runtime.fact_source._number = lambda _text: value

    with pytest.raises(
        WindowsRpcDurableFenceError, match="execution fact number is non-finite"
    ) as raised:
        facts.peek_current_facts(
            {"account_scope": "account:sim", "environment": "simnow"}
        )

    assert raised.value.code == "WINDOWS_EXECUTION_FACT_INVALID"
    assert state_path.read_bytes() == before_state
    assert ledger_path.read_bytes() == before_ledger
