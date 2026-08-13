"""Fail-closed CTP investor-position query completion tracking."""

from __future__ import annotations

from collections.abc import Mapping
from threading import RLock
from types import MethodType
from typing import Any


class PositionQueryReadinessTrackerV1:
    """A position snapshot is usable only after a successful final CTP row."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._generation = 0
        self._ready = False
        self._active_request_id: int | None = None
        self._failed_request_id: int | None = None
        self._callback_count = 0

    def reset(self) -> None:
        with self._lock:
            self._generation += 1
            self._ready = False
            self._active_request_id = None
            self._failed_request_id = None
            self._callback_count = 0

    def begin_query(self, request_id: Any) -> None:
        if type(request_id) is not int or request_id < 0:
            self.reset()
            return
        with self._lock:
            self._generation += 1
            self._ready = False
            self._active_request_id = request_id
            self._failed_request_id = None
            self._callback_count = 0

    def on_rsp_qry_investor_position(
        self, error: Any, request_id: Any, b_is_last: Any
    ) -> None:
        # A partial successful response is deliberately not enough; an error
        # on the last row cannot turn a previous query ready.
        error_id = error.get("ErrorID", 0) if isinstance(error, Mapping) else None
        with self._lock:
            self._callback_count += 1
            if request_id != self._active_request_id:
                return
            if type(error_id) is not int or error_id != 0:
                self._ready = False
                self._failed_request_id = request_id
            elif self._failed_request_id == request_id:
                self._ready = False
            elif b_is_last is True:
                self._ready = True

    def is_ready(self) -> bool:
        with self._lock:
            return self._ready

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def observability_state_v1(self) -> dict[str, int | bool | None]:
        """Return only the non-sensitive readiness state for runtime logs."""

        with self._lock:
            return {
                "generation": self._generation,
                "active_request_id": self._active_request_id,
                "failed_request_id": self._failed_request_id,
                "ready": self._ready,
                "callback_count": self._callback_count,
            }


def _observation_value(value: Any) -> str:
    """Avoid rendering arbitrary request, callback, or gateway objects in logs."""

    if value is None or type(value) in {bool, int}:
        return str(value)
    return type(value).__name__


def _write_position_query_observation_v1(
    ctp_td_api: Any, event: str, **fields: Any
) -> None:
    """Use the CTP gateway log while preserving query and callback behavior."""

    write_log = getattr(getattr(ctp_td_api, "gateway", None), "write_log", None)
    if not callable(write_log):
        return
    message = " ".join(
        [event, *(f"{name}={_observation_value(value)}" for name, value in fields.items())]
    )
    try:
        write_log(message)
    except Exception:  # noqa: BLE001 - observation must not change CTP callback behavior
        # Diagnostics must never turn an otherwise normal CTP response into a
        # callback failure.
        return


def attach_ctp_position_readiness_v1(ctp_td_api: Any) -> PositionQueryReadinessTrackerV1:
    """Wrap the CTP callbacks before connect; returns the facts readiness gate."""

    marker = getattr(ctp_td_api, "_vnpy_position_readiness_v1", None)
    if marker is not None:
        if isinstance(marker, PositionQueryReadinessTrackerV1):
            return marker
        raise TypeError("CTP position readiness marker is invalid")
    query = getattr(ctp_td_api, "reqQryInvestorPosition", None)
    response = getattr(ctp_td_api, "onRspQryInvestorPosition", None)
    if not callable(query) or not callable(response):
        raise TypeError("CTP position query callbacks are unavailable")
    tracker = PositionQueryReadinessTrackerV1()

    def wrapped_query(subject: Any, request: Any, request_id: Any) -> Any:
        tracker.begin_query(request_id)
        result = query(request, request_id)
        state = tracker.observability_state_v1()
        _write_position_query_observation_v1(
            subject,
            "CTP_POSITION_QUERY_REQUEST",
            request_id=request_id,
            req_return=result,
            tracker_generation=state["generation"],
            tracker_active_request_id=state["active_request_id"],
            tracker_failed_request_id=state["failed_request_id"],
            tracker_ready=state["ready"],
        )
        return result

    def wrapped_response(
        subject: Any, data: Any, error: Any, request_id: Any, b_is_last: Any
    ) -> Any:
        result = response(data, error, request_id, b_is_last)
        tracker.on_rsp_qry_investor_position(error, request_id, b_is_last)
        state = tracker.observability_state_v1()
        error_id = error.get("ErrorID", 0) if isinstance(error, Mapping) else None
        _write_position_query_observation_v1(
            subject,
            "CTP_POSITION_QUERY_CALLBACK",
            callback_count=state["callback_count"],
            request_id=request_id,
            ErrorID=error_id,
            b_is_last=b_is_last,
            tracker_generation=state["generation"],
            tracker_active_request_id=state["active_request_id"],
            tracker_failed_request_id=state["failed_request_id"],
            tracker_ready=state["ready"],
        )
        return result

    ctp_td_api.reqQryInvestorPosition = MethodType(wrapped_query, ctp_td_api)
    ctp_td_api.onRspQryInvestorPosition = MethodType(wrapped_response, ctp_td_api)
    for name in ("onFrontConnected", "onFrontDisconnected", "onRspUserLogin"):
        original = getattr(ctp_td_api, name, None)
        if callable(original):
            def reset_wrapper(subject: Any, *args: Any, _original: Any = original, **kwargs: Any) -> Any:
                tracker.reset()
                return _original(*args, **kwargs)

            setattr(ctp_td_api, name, MethodType(reset_wrapper, ctp_td_api))
    ctp_td_api._vnpy_position_readiness_v1 = tracker
    return tracker
