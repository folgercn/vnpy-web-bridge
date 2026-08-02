from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread
from typing import Any, Callable, Mapping
from uuid import uuid4

from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastL1L5BookSnapshotDTO,
)
from app.services.commodity_c_fast_execution_quality_horizon_worker import (
    CFastExecutionQualityHorizonWorkerError,
    PreverifiedTickHorizonWorker,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


_EXACT_CONTRACT_RE = re.compile(r"^[A-Z]+\.[A-Za-z]+[0-9]{3,4}$")
_SYMBOL_RE = re.compile(r"^[A-Za-z]+[0-9]{3,4}$")
_EXCHANGE_RE = re.compile(r"^[A-Z]+$")
_FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


class CFastExecutionQualityTickFanoutError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _QueuedTick:
    payload: dict[str, Any]
    exact_contract: str
    received_at_utc: datetime
    ingest_seq: int
    ingest_id: str


class CommodityCFastExecutionQualityTickFanout:
    """Default-off local Tick subscriber for one preverified horizon worker.

    The component receives copies from an existing market-data publication
    path.  It owns no source connection and has no external subscribe, storage,
    execution or trading handle.  One bounded thread isolates sidecar work from
    the publisher thread; any queue or worker failure blocks only this fan-out.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
        queue_size: int = 4_096,
        session_id: str | None = None,
    ) -> None:
        if type(queue_size) is not int or not 1 <= queue_size <= 1_000_000:
            raise CFastExecutionQualityTickFanoutError("TICK_FANOUT_QUEUE_SIZE_INVALID")
        candidate_session_id = session_id or uuid4().hex
        if re.fullmatch(r"[A-Za-z0-9._-]{8,128}", candidate_session_id) is None:
            raise CFastExecutionQualityTickFanoutError("TICK_FANOUT_SESSION_ID_INVALID")
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._queue: Queue[_QueuedTick] = Queue(maxsize=queue_size)
        self._session_id = candidate_session_id
        self._lock = RLock()
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._accepting = False
        self._worker: PreverifiedTickHorizonWorker | None = None
        self._receipt: CFastExecutionQualityRuntimeRevalidationDTO | None = None
        self._exact_contracts: frozenset[str] = frozenset()
        self._subscription_generation = 0
        self._state = (
            "DISABLED_DEFAULT_OFF"
            if not self.settings.commodity_c_fast_execution_quality_runtime_enabled
            else "CREATED_ENABLED_UNBOUND"
        )
        self._blocked = False
        self._last_error: str | None = None
        self._next_ingest_seq = 0
        self._offered = 0
        self._enqueued = 0
        self._delivered = 0
        self._ignored_outside_contracts = 0
        self._ignored_unroutable = 0
        self._rejected_after_block = 0

    def bind_preverified_subscription(
        self,
        *,
        worker: PreverifiedTickHorizonWorker,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> dict[str, object]:
        receipt = self._validate_subscription_candidate(
            worker,
            revalidation_receipt,
            require_frozen=False,
        )
        with self._lock:
            if self._thread is not None:
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_BIND_AFTER_START_FORBIDDEN"
                )
            if self._worker is not None:
                if (
                    self._worker is worker
                    and self._receipt is not None
                    and self._receipt.receipt_sha256 == receipt.receipt_sha256
                ):
                    return self._status_locked()
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_ALREADY_BOUND"
                )
            try:
                freeze_receipt = worker.freeze_preverified_exact_contracts(
                    receipt.exact_contracts
                )
            except CFastExecutionQualityHorizonWorkerError as exc:
                raise CFastExecutionQualityTickFanoutError(
                    "PREVERIFIED_EXACT_CONTRACT_FREEZE_FAILED"
                ) from exc
            if (
                freeze_receipt["tick_subscription_frozen"] is not True
                or tuple(freeze_receipt["frozen_exact_contracts"])
                != receipt.exact_contracts
            ):
                raise CFastExecutionQualityTickFanoutError(
                    "PREVERIFIED_EXACT_CONTRACT_FREEZE_INVALID"
                )
            self._worker = worker
            self._receipt = receipt
            self._exact_contracts = frozenset(receipt.exact_contracts)
            self._subscription_generation = 1
            self._state = "PREVERIFIED_EXACT_CONTRACT_SUBSCRIPTION_BOUND_NOT_STARTED"
            self._last_error = None
            return self._status_locked()

    def refresh_preverified_subscription(
        self,
        *,
        worker: PreverifiedTickHorizonWorker,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> dict[str, object]:
        """Explicitly recover one stopped binding with a fresh exact receipt.

        The worker and its frozen contract set are immutable for the process.
        Refresh exists only so startup/reload/recovery can replace the
        short-lived revalidation receipt after the queue was drained.  It is
        also the sole operation allowed to clear a fanout-local blocker.
        """

        receipt = self._validate_subscription_candidate(
            worker,
            revalidation_receipt,
            require_frozen=True,
        )
        with self._lock:
            if self._thread is not None or self._accepting:
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_REFRESH_REQUIRES_STOPPED_FANOUT"
                )
            if not self._queue.empty():
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_REFRESH_REQUIRES_DRAINED_QUEUE"
                )
            if self._worker is None or self._receipt is None:
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_REFRESH_REQUIRES_EXISTING_BINDING"
                )
            if self._worker is not worker:
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_WORKER_REPLACEMENT_FORBIDDEN"
                )
            if frozenset(receipt.exact_contracts) != self._exact_contracts:
                raise CFastExecutionQualityTickFanoutError(
                    "TICK_SUBSCRIPTION_CONTRACT_REFRESH_DRIFT"
                )
            self._receipt = receipt
            self._subscription_generation += 1
            self._blocked = False
            self._last_error = None
            self._stop_event.clear()
            self._state = "PREVERIFIED_EXACT_CONTRACT_SUBSCRIPTION_REFRESHED_NOT_STARTED"
            return self._status_locked()

    def start(self) -> dict[str, object]:
        with self._lock:
            if not self.settings.commodity_c_fast_execution_quality_runtime_enabled:
                self._state = "DISABLED_DEFAULT_OFF"
                self._last_error = None
                return self._status_locked()
            if self._blocked:
                return self._status_locked()
            if self._worker is None or self._receipt is None:
                self._block_locked("PREVERIFIED_TICK_SUBSCRIPTION_NOT_BOUND")
                return self._status_locked()
            if self._thread is not None and self._thread.is_alive():
                return self._status_locked()
            try:
                now = self._utc_now()
            except CFastExecutionQualityTickFanoutError as exc:
                self._block_locked(exc.code)
                return self._status_locked()
            if not self._receipt_active_locked(now):
                self._block_locked("REVALIDATION_RECEIPT_EXPIRED")
                return self._status_locked()
            self._stop_event.clear()
            self._thread = Thread(
                target=self._run,
                name="c-fast-execution-quality-tick-fanout",
                daemon=True,
            )
            self._state = "RUNNING_READONLY_PREVERIFIED_EXACT_CONTRACTS"
            try:
                self._thread.start()
            except Exception as exc:
                self._thread = None
                self._block_locked(
                    f"TICK_FANOUT_THREAD_START_FAILED_{type(exc).__name__}"
                )
                return self._status_locked()
            self._accepting = True
            return self._status_locked()

    def stop(self, timeout: float = 5.0) -> dict[str, object]:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise CFastExecutionQualityTickFanoutError(
                "TICK_FANOUT_STOP_TIMEOUT_INVALID"
            )
        with self._lock:
            thread = self._thread
            self._accepting = False
            if not self._blocked:
                self._state = "STOPPING_DRAINING_ACCEPTED_TICKS"
            self._stop_event.set()
        if thread is not None:
            thread.join(timeout=timeout)
        with self._lock:
            if thread is not None and thread.is_alive():
                self._block_locked("TICK_FANOUT_THREAD_DID_NOT_STOP")
            else:
                self._thread = None
                if not self._blocked:
                    self._state = "STOPPED_NO_TICK_CAPABILITY"
            return self._status_locked()

    def offer_tick(self, payload: Mapping[str, Any]) -> dict[str, object]:
        """Offer one copied publication without blocking the source thread."""

        with self._lock:
            self._offered += 1
            if (
                not self.settings.commodity_c_fast_execution_quality_runtime_enabled
                or self._state == "DISABLED_DEFAULT_OFF"
            ):
                return self._offer_result_locked("IGNORED_DEFAULT_OFF")
            if self._blocked:
                self._rejected_after_block += 1
                return self._offer_result_locked("REJECTED_BLOCKED_FAIL_CLOSED")
            if not self._accepting:
                return self._offer_result_locked("REJECTED_FANOUT_NOT_RUNNING")
        if not isinstance(payload, Mapping):
            with self._lock:
                self._ignored_unroutable += 1
            return self._offer_result("IGNORED_UNROUTABLE_TICK")
        if len(payload) > 256:
            with self._lock:
                self._block_locked("TICK_PAYLOAD_TOO_LARGE")
            return self._offer_result("BLOCKED_FAIL_CLOSED")
        copied = dict(payload)
        try:
            route = self._route_exact_contract(copied)
        except CFastExecutionQualityTickFanoutError as exc:
            with self._lock:
                self._block_locked(exc.code)
            return self._offer_result("BLOCKED_FAIL_CLOSED")
        with self._lock:
            if self._blocked:
                self._rejected_after_block += 1
                return self._offer_result_locked("REJECTED_BLOCKED_FAIL_CLOSED")
            if not self._accepting or self._stop_event.is_set():
                return self._offer_result_locked("REJECTED_FANOUT_NOT_RUNNING")
            if self._thread is None or not self._thread.is_alive():
                self._accepting = False
                return self._offer_result_locked("REJECTED_FANOUT_NOT_RUNNING")
            if route is None:
                self._ignored_unroutable += 1
                return self._offer_result_locked("IGNORED_UNROUTABLE_TICK")
            if route not in self._exact_contracts:
                self._ignored_outside_contracts += 1
                return self._offer_result_locked("IGNORED_OUTSIDE_EXACT_CONTRACTS")
            try:
                now = self._utc_now()
            except CFastExecutionQualityTickFanoutError as exc:
                self._block_locked(exc.code)
                return self._offer_result_locked("BLOCKED_FAIL_CLOSED")
            if not self._receipt_active_locked(now):
                self._block_locked("REVALIDATION_RECEIPT_EXPIRED")
                return self._offer_result_locked("BLOCKED_FAIL_CLOSED")
            self._next_ingest_seq += 1
            sequence = self._next_ingest_seq
            queued = _QueuedTick(
                payload=copied,
                exact_contract=route,
                received_at_utc=now,
                ingest_seq=sequence,
                ingest_id=(f"cfast-tick-{self._session_id}-{sequence}"),
            )
            try:
                self._queue.put_nowait(queued)
            except Full:
                self._block_locked("TICK_FANOUT_QUEUE_FULL")
                return self._offer_result_locked("BLOCKED_FAIL_CLOSED")
            self._enqueued += 1
            return self._offer_result_locked("ENQUEUED_PREVERIFIED_EXACT_CONTRACT")

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._status_locked()

    def wait_until_idle(self) -> None:
        """Wait until all already enqueued work completes; used on shutdown/tests."""

        self._queue.join()

    def _run(self) -> None:
        while not (self._stop_event.is_set() and self._queue.empty()):
            try:
                item = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                with self._lock:
                    if self._blocked:
                        continue
                    worker = self._worker
                    receipt = self._receipt
                    receipt_active = self._receipt_active_locked(self._utc_now())
                if worker is None or receipt is None or not receipt_active:
                    raise CFastExecutionQualityTickFanoutError(
                        "REVALIDATION_RECEIPT_EXPIRED"
                    )
                worker_status = worker.status()
                if (
                    worker_status["blocked_fail_closed"] is not False
                    or tuple(worker_status["accepted_exact_contracts"])
                    != receipt.exact_contracts
                    or worker_status["exact_contract_subscription_frozen"] is not True
                    or tuple(worker_status["frozen_exact_contracts"])
                    != receipt.exact_contracts
                ):
                    raise CFastExecutionQualityTickFanoutError(
                        "PREVERIFIED_WORKER_CONTRACT_SET_DRIFT"
                    )
                snapshot = self._to_snapshot(item)
                if not self._receipt_active_locked(self._utc_now()):
                    raise CFastExecutionQualityTickFanoutError(
                        "REVALIDATION_RECEIPT_EXPIRED"
                    )
                result = worker.accept_preverified_tick(snapshot)
                if result["tick_state"] != "PREVERIFIED_TICK_DURABLY_PROCESSED":
                    raise CFastExecutionQualityTickFanoutError(
                        "HORIZON_WORKER_REJECTED_SUBSCRIBED_CONTRACT"
                    )
                with self._lock:
                    self._delivered += 1
            except Exception as exc:
                with self._lock:
                    self._block_locked(getattr(exc, "code", type(exc).__name__))
            finally:
                self._queue.task_done()

    def _to_snapshot(self, item: _QueuedTick) -> CFastL1L5BookSnapshotDTO:
        raw = item.payload
        exchange_timestamp = self._parse_utc_datetime(
            raw.get("datetime") or raw.get("ts"),
            "TICK_EXCHANGE_TIMESTAMP_INVALID",
        )
        bid_prices, bid_sizes = self._book_side(raw, "bid")
        ask_prices, ask_sizes = self._book_side(raw, "ask")
        cumulative_volume = self._decimal_text(
            raw.get("volume", raw.get("cumulative_volume")),
            allow_none=True,
        )
        if cumulative_volume is not None and Decimal(cumulative_volume) < 0:
            raise CFastExecutionQualityTickFanoutError("TICK_CUMULATIVE_VOLUME_INVALID")
        core = {
            "schema_version": "commodity_c_fast_l1_l5_book_snapshot_v1",
            "exact_contract": item.exact_contract,
            "exchange_timestamp": exchange_timestamp.isoformat().replace("+00:00", "Z"),
            "received_at_utc": item.received_at_utc.isoformat().replace("+00:00", "Z"),
            "ingest_seq": item.ingest_seq,
            "ingest_id": item.ingest_id,
            "cumulative_volume": cumulative_volume,
            "bid_prices": bid_prices,
            "ask_prices": ask_prices,
            "bid_sizes": bid_sizes,
            "ask_sizes": ask_sizes,
        }
        return CFastL1L5BookSnapshotDTO.model_validate(
            {**core, "book_snapshot_hash": sha256_json(core)}
        )

    def _book_side(
        self,
        raw: Mapping[str, Any],
        side: str,
    ) -> tuple[list[str | None], list[int | None]]:
        prices: list[str | None] = []
        sizes: list[int | None] = []
        for level in range(1, 6):
            price = self._decimal_text(
                raw.get(f"{side}_price_{level}"),
                allow_none=True,
            )
            if price is not None and Decimal(price) == 0:
                price = None
            size = self._integer_size(
                raw.get(f"{side}_volume_{level}"),
                allow_none=True,
            )
            if price is None:
                size = None
            prices.append(price)
            sizes.append(size)
        return prices, sizes

    @staticmethod
    def _decimal_text(value: Any, *, allow_none: bool) -> str | None:
        if value is None and allow_none:
            return None
        if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
            raise CFastExecutionQualityTickFanoutError("TICK_DECIMAL_FIELD_INVALID")
        if isinstance(value, float) and not math.isfinite(value):
            raise CFastExecutionQualityTickFanoutError("TICK_DECIMAL_FIELD_INVALID")
        raw = str(value)
        if len(raw) > 64:
            raise CFastExecutionQualityTickFanoutError("TICK_DECIMAL_FIELD_INVALID")
        try:
            parsed = Decimal(raw)
        except InvalidOperation as exc:
            raise CFastExecutionQualityTickFanoutError(
                "TICK_DECIMAL_FIELD_INVALID"
            ) from exc
        if not parsed.is_finite():
            raise CFastExecutionQualityTickFanoutError("TICK_DECIMAL_FIELD_INVALID")
        return format(parsed, "f")

    @staticmethod
    def _integer_size(value: Any, *, allow_none: bool) -> int | None:
        if value is None and allow_none:
            return None
        if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
            raise CFastExecutionQualityTickFanoutError("TICK_DEPTH_SIZE_INVALID")
        raw = str(value)
        if len(raw) > 32:
            raise CFastExecutionQualityTickFanoutError("TICK_DEPTH_SIZE_INVALID")
        try:
            parsed = Decimal(raw)
        except InvalidOperation as exc:
            raise CFastExecutionQualityTickFanoutError(
                "TICK_DEPTH_SIZE_INVALID"
            ) from exc
        if not parsed.is_finite() or parsed < 0 or parsed != parsed.to_integral():
            raise CFastExecutionQualityTickFanoutError("TICK_DEPTH_SIZE_INVALID")
        return int(parsed)

    @staticmethod
    def _parse_utc_datetime(value: Any, code: str) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            if len(value) > 64:
                raise CFastExecutionQualityTickFanoutError(code)
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise CFastExecutionQualityTickFanoutError(code) from exc
        else:
            raise CFastExecutionQualityTickFanoutError(code)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise CFastExecutionQualityTickFanoutError(code)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _route_exact_contract(payload: Mapping[str, Any]) -> str | None:
        symbol = payload.get("symbol")
        exchange = payload.get("exchange")
        vt_symbol = payload.get("vt_symbol")
        if (not isinstance(symbol, str) or not symbol) and isinstance(vt_symbol, str):
            symbol = vt_symbol.partition(".")[0]
        if (not isinstance(exchange, str) or not exchange) and isinstance(
            vt_symbol, str
        ):
            exchange = vt_symbol.partition(".")[2]
        if not isinstance(symbol, str) or not isinstance(exchange, str):
            return None
        if (
            _SYMBOL_RE.fullmatch(symbol) is None
            or _EXCHANGE_RE.fullmatch(exchange) is None
        ):
            return None
        expected_vt_symbol = f"{symbol}.{exchange}"
        if isinstance(vt_symbol, str) and vt_symbol != expected_vt_symbol:
            raise CFastExecutionQualityTickFanoutError(
                "TICK_EXACT_CONTRACT_IDENTITY_SPLICE"
            )
        exact_contract = f"{exchange}.{symbol}"
        if _EXACT_CONTRACT_RE.fullmatch(exact_contract) is None:
            return None
        return exact_contract

    def _utc_now(self) -> datetime:
        value = self.clock()
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise CFastExecutionQualityTickFanoutError("TICK_FANOUT_CLOCK_MUST_USE_UTC")
        return value

    def _validate_subscription_candidate(
        self,
        worker: PreverifiedTickHorizonWorker,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
        *,
        require_frozen: bool,
    ) -> CFastExecutionQualityRuntimeRevalidationDTO:
        if type(worker) is not PreverifiedTickHorizonWorker:
            raise CFastExecutionQualityTickFanoutError(
                "PREVERIFIED_HORIZON_WORKER_TYPE_INVALID"
            )
        try:
            receipt = CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
                revalidation_receipt
            )
        except ValidationError as exc:
            raise CFastExecutionQualityTickFanoutError(
                "REVALIDATION_RECEIPT_INVALID"
            ) from exc
        now = self._utc_now()
        if not receipt.revalidated_at_utc <= now < receipt.valid_until_utc:
            raise CFastExecutionQualityTickFanoutError("REVALIDATION_RECEIPT_INACTIVE")
        worker_status = worker.status()
        if worker_status["blocked_fail_closed"] is not False:
            raise CFastExecutionQualityTickFanoutError(
                "PREVERIFIED_HORIZON_WORKER_BLOCKED"
            )
        accepted = tuple(worker_status["accepted_exact_contracts"])
        if accepted != receipt.exact_contracts:
            raise CFastExecutionQualityTickFanoutError(
                "EXACT_CONTRACT_SUBSCRIPTION_MISMATCH"
            )
        if require_frozen and (
            worker_status["exact_contract_subscription_frozen"] is not True
            or tuple(worker_status["frozen_exact_contracts"])
            != receipt.exact_contracts
        ):
            raise CFastExecutionQualityTickFanoutError(
                "PREVERIFIED_EXACT_CONTRACT_FREEZE_MISMATCH"
            )
        return receipt

    def _receipt_active_locked(self, now: datetime) -> bool:
        receipt = self._receipt
        return bool(
            receipt is not None
            and receipt.revalidated_at_utc <= now < receipt.valid_until_utc
        )

    def _block_locked(self, code: str) -> None:
        self._accepting = False
        self._blocked = True
        self._state = "BLOCKED_FAIL_CLOSED"
        self._last_error = code

    def _offer_result(self, state: str) -> dict[str, object]:
        with self._lock:
            return self._offer_result_locked(state)

    def _offer_result_locked(self, state: str) -> dict[str, object]:
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_tick_fanout_offer_v1"
            ),
            "offer_state": state,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }

    def _status_locked(self) -> dict[str, object]:
        thread_running = bool(self._thread and self._thread.is_alive())
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_tick_fanout_status_v1"
            ),
            "fanout_state": self._state,
            "configured_enabled": (
                self.settings.commodity_c_fast_execution_quality_runtime_enabled
            ),
            "blocked_fail_closed": self._blocked,
            "last_error": self._last_error,
            "worker_thread_running": thread_running,
            "tick_input_accepting": self._accepting,
            "preverified_worker_bound": self._worker is not None,
            "subscription_generation": self._subscription_generation,
            "revalidation_receipt_sha256": (
                self._receipt.receipt_sha256 if self._receipt is not None else None
            ),
            "revalidation_valid_until_utc": (
                self._receipt.valid_until_utc.isoformat().replace("+00:00", "Z")
                if self._receipt is not None
                else None
            ),
            "subscribed_exact_contracts": sorted(self._exact_contracts),
            "local_exact_contract_subscription_built": bool(self._exact_contracts),
            "external_market_subscription_requested": False,
            "queue_size": self._queue.qsize(),
            "queue_capacity": self._queue.maxsize,
            "offered_ticks": self._offered,
            "enqueued_ticks": self._enqueued,
            "delivered_ticks": self._delivered,
            "ignored_outside_exact_contracts": (self._ignored_outside_contracts),
            "ignored_unroutable_ticks": self._ignored_unroutable,
            "rejected_after_block": self._rejected_after_block,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "readonly_tick_input_only": True,
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }


commodity_c_fast_execution_quality_tick_fanout = (
    CommodityCFastExecutionQualityTickFanout()
)
