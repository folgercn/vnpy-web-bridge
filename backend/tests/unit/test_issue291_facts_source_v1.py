from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.final_admission_v1 import (
    WindowsRpcFencedAdmissionV1,
)
from scripts.windows_fence_foundation.final_store_v1 import DurableFinalAdmissionStoreV1
from scripts.windows_rpc_durable_fence_v1 import (
    WindowsRpcRuntimeConfigV1,
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


def _source(tmp_path: Path) -> tuple[_WindowsExecutionFactsV1, Path, Path]:
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
        fact_source=_Facts(),
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
    assert value["pending_send_outcomes"] == []
    assert value["gateway"] == {
        "gateway_name": "CTP",
        "account_scope": "account:sim",
        "environment": "simnow",
        "connected": True,
    }
    assert state_path.read_bytes() == before_state
    assert ledger_path.read_bytes() == before_ledger


def test_m2_peek_current_facts_exposes_only_actual_pending_send_outcomes(
    tmp_path: Path,
) -> None:
    facts, _state_path, _ledger_path = _source(tmp_path)
    context = {"intent_id": "intent-0001"}
    facts.begin_pending_send(context)
    try:
        value = json.loads(
            facts.peek_current_facts(
                {"account_scope": "account:sim", "environment": "simnow"}
            )
        )
    finally:
        facts.settle_pending_send(context)

    assert value["pending_send_outcomes"] == ["intent-0001"]
