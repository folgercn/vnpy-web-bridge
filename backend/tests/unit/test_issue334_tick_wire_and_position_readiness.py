from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    peek_current_facts_to_snapshot,
)

from scripts.windows_position_readiness_v1 import (
    PositionQueryReadinessTrackerV1,
    attach_ctp_position_readiness_v1,
)
from scripts.windows_tick_wire_v1 import (
    TICK_WIRE_PREFIX,
    TickWireError,
    decode_tick_wire_v1,
    tick_wire_payload,
)


def test_position_false_is_explicit_and_snapshot_requires_completion() -> None:
    """The Windows facts layer exposes false; allocation itself stays closed."""

    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceDenied
    from scripts.windows_rpc_durable_fence_v1 import _WindowsExecutionFactsV1

    runtime = type(
        "Runtime",
        (),
        {
            "config": type(
                "Config",
                (),
                {
                    "account_scope": "account:windows",
                    "environment": "simnow",
                    "gateway_name": "CTP",
                },
            )(),
            "position_readiness": PositionQueryReadinessTrackerV1(),
        },
    )()
    facts = _WindowsExecutionFactsV1(runtime)
    with pytest.raises(WindowsRpcDurableFenceDenied, match="position"):
        facts.get_execution_snapshot_v1(
            {"account_scope": "account:windows", "environment": "simnow"}
        )


def _facts(*, complete: bool) -> dict[str, object]:
    return {
        "schema_version": "windows_execution_current_facts_v1",
        "position_query_complete": complete,
        "account": {"CTP.sim": {"gateway_name": "CTP"}},
        "positions": {},
        "active_orders": {},
        "gateway": {
            "gateway_name": "CTP",
            "account_scope": "account:windows",
            "environment": "simnow",
            "connected": True,
        },
        "execution": {"orders": {}},
        "admission": {
            "account_scope": "account:windows",
            "environment": "simnow",
            "durable_state_version": 0,
            "durable_state_hash": "0" * 64,
            "snapshot_generation": 0,
            "fence": {
                "active": False,
                "current_epoch": 0,
                "current_fencing_token": 0,
                "high_water_epoch": 0,
                "high_water_fencing_token": 0,
            },
            "receipt_intents": [],
        },
    }


def test_tick_wire_rejects_noncanonical_version_mismatch_and_oversize() -> None:
    payload = tick_wire_payload(
        {
            "vt_symbol": "rb2610.SHFE",
            "datetime": datetime(2026, 8, 13, tzinfo=timezone.utc),
            "last_price": 3500,
            "last_volume": 1,
            "bid_price_1": 3499,
            "ask_price_1": 3501,
            "bid_volume_1": 2,
            "ask_volume_1": 3,
        }
    )
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    topic = f"{TICK_WIRE_PREFIX}rb2610.SHFE".encode("ascii")
    assert decode_tick_wire_v1(topic, raw)["vt_symbol"] == "rb2610.SHFE"
    with pytest.raises(TickWireError):
        decode_tick_wire_v1(b"eOrder.rb2610.SHFE", raw)
    with pytest.raises(TickWireError):
        decode_tick_wire_v1(topic, raw + b" ")
    with pytest.raises(TickWireError):
        decode_tick_wire_v1(topic, b"x" * 4097)
    with pytest.raises(TickWireError):
        decode_tick_wire_v1(f"{TICK_WIRE_PREFIX}au2401.SHFE".encode(), raw)


def test_position_tracker_rejects_stale_and_error_last_callbacks() -> None:
    tracker = PositionQueryReadinessTrackerV1()
    tracker.begin_query(7)
    tracker.on_rsp_qry_investor_position({"ErrorID": 0}, 6, True)
    assert not tracker.is_ready()
    tracker.on_rsp_qry_investor_position({"ErrorID": 1}, 7, True)
    assert not tracker.is_ready()
    tracker.begin_query(8)
    tracker.on_rsp_qry_investor_position({"ErrorID": 0}, 8, False)
    assert not tracker.is_ready()
    tracker.on_rsp_qry_investor_position({"ErrorID": 0}, 8, True)
    assert tracker.is_ready()
    tracker.reset()
    assert not tracker.is_ready()


def test_position_query_observability_logs_only_allowed_ctp_fields() -> None:
    class Gateway:
        def __init__(self) -> None:
            self.messages: list[str] = []

        def write_log(self, message: str) -> None:
            self.messages.append(message)

    class TdApi:
        def __init__(self) -> None:
            self.gateway = Gateway()
            self.calls: list[tuple[object, ...]] = []

        def reqQryInvestorPosition(self, request: object, request_id: int) -> int:
            self.calls.append(("request", request, request_id))
            return 0

        def onRspQryInvestorPosition(
            self,
            data: object,
            error: object,
            request_id: int,
            b_is_last: bool,
        ) -> None:
            self.calls.append(("callback", data, error, request_id, b_is_last))

    api = TdApi()
    tracker = attach_ctp_position_readiness_v1(api)
    assert api.reqQryInvestorPosition({"secret": "must-not-log"}, 7) == 0
    api.onRspQryInvestorPosition(
        {"position": "must-not-log"}, {"ErrorID": 0, "detail": "must-not-log"}, 7, False
    )
    api.onRspQryInvestorPosition(
        {"position": "must-not-log"}, {"ErrorID": 0, "detail": "must-not-log"}, 7, True
    )

    assert api.gateway.messages == [
        "CTP_POSITION_QUERY_REQUEST request_id=7 req_return=0 "
        + "tracker_generation=1 tracker_active_request_id=7 "
        + "tracker_failed_request_id=None tracker_ready=False",
        "CTP_POSITION_QUERY_CALLBACK callback_count=1 request_id=7 ErrorID=0 "
        + "b_is_last=False tracker_generation=1 tracker_active_request_id=7 "
        + "tracker_failed_request_id=None tracker_ready=False",
        "CTP_POSITION_QUERY_CALLBACK callback_count=2 request_id=7 ErrorID=0 "
        + "b_is_last=True tracker_generation=1 tracker_active_request_id=7 "
        + "tracker_failed_request_id=None tracker_ready=True",
    ]
    assert tracker.observability_state_v1() == {
        "generation": 1,
        "active_request_id": 7,
        "failed_request_id": None,
        "ready": True,
        "callback_count": 2,
    }
    assert all("must-not-log" not in message for message in api.gateway.messages)


def test_executable_adapter_requires_explicit_completed_position_query() -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="schema"):
        peek_current_facts_to_snapshot(_facts(complete=False), account_scope="account:windows")
    snapshot = peek_current_facts_to_snapshot(
        _facts(complete=True), account_scope="account:windows"
    )
    assert snapshot.snapshot.positions == {}
