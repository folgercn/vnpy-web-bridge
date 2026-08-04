"""Event-thread-linearized Windows RPC deployment snapshot fence.

The module intentionally imports no vn.py package at import time.  Production
assembly may use the lazy default ``Event`` factory, while tests and packaging
checks can inject a compatible factory.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any

SCHEMA_VERSION = "windows_rpc_deployment_safety_snapshot_v1"
RPC_CALLABLE_NAME = "get_deployment_safety_snapshot_v1"
RECHECK_RPC_CALLABLE_NAME = "recheck_deployment_safety_snapshot_v1"
RECHECK_SCHEMA_VERSION = "windows_rpc_deployment_safety_recheck_v1"
SNAPSHOT_EVENT_TYPE = "eDeploymentSafetySnapshotV1"
RECHECK_EVENT_TYPE = "eDeploymentSafetyRecheckV1"
DEFAULT_ORDER_EVENT_TYPE = "eOrder."
DEFAULT_TRADE_EVENT_TYPE = "eTrade."
DEFAULT_POSITION_EVENT_TYPE = "ePosition."
DEFAULT_ACCOUNT_EVENT_TYPE = "eAccount."

_FORBIDDEN_CREDENTIAL_FIELDS = {
    "access_key",
    "access_token",
    "api_key",
    "api_secret",
    "auth_code",
    "auth_token",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "private_key",
    "pwd",
    "secret",
    "secret_key",
    "session_token",
}
_FORBIDDEN_STRATEGY_METHODS = {
    "add_strategy",
    "edit_strategy",
    "get_all_strategy_names",
    "get_all_strategy_status",
    "get_all_strategies",
    "get_strategy_status",
    "init_strategy",
    "init_cta_strategy",
    "start_strategy",
    "start_cta_strategy",
    "start_all_strategies",
}
_ALLOWED_COMPONENT_IDENTITIES = {
    "email",
    "emailapp",
    "emailengine",
    "log",
    "logapp",
    "logengine",
    "oms",
    "omsapp",
    "omsengine",
    "rpcengine",
    "rpcservice",
    "rpcserviceapp",
    "rpcserviceengine",
    "wechat",
    "wechatapp",
    "wechatengine",
}


class WindowsRpcDeploymentSnapshotError(RuntimeError):
    """The read-only deployment snapshot could not be captured safely."""


@dataclass
class _SnapshotRequest:
    completed: threading.Event
    request_id: str
    challenge: str
    result: dict[str, Any] | None = None
    error: BaseException | None = None


@dataclass
class _RecheckRequest:
    completed: threading.Event
    parameters: tuple[str, str, str, str, int]
    result_json: str | None = None
    error: BaseException | None = None


def _default_event_factory(event_type: str, data: Any) -> Any:
    # Lazy by design: importing this module must work on non-vn.py hosts.
    from vnpy.event import Event

    return Event(event_type, data)


def _event_data(event: Any) -> Any:
    if isinstance(event, Mapping):
        return event.get("data")
    return getattr(event, "data", None)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _field_is_credential(name: str) -> bool:
    normalized = name.strip().lower().replace("-", "_")
    return normalized in _FORBIDDEN_CREDENTIAL_FIELDS or normalized.endswith(
        (
            "_auth_code",
            "_passphrase",
            "_password",
            "_private_key",
            "_secret",
            "_token",
        )
    )


def _plain_json(value: Any, *, path: str, seen: set[int]) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise WindowsRpcDeploymentSnapshotError(f"non-finite number at {path}")
        return value
    if isinstance(value, Enum):
        return _plain_json(value.value, path=path, seen=seen)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise WindowsRpcDeploymentSnapshotError(f"naive datetime at {path}")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()

    identity = id(value)
    if identity in seen:
        raise WindowsRpcDeploymentSnapshotError(f"cyclic value at {path}")
    seen.add(identity)
    try:
        if is_dataclass(value) and not isinstance(value, type):
            source = {field.name: getattr(value, field.name) for field in fields(value)}
            return _plain_json(source, path=path, seen=seen)
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            if any(not isinstance(key, str) for key in value):
                raise WindowsRpcDeploymentSnapshotError(
                    f"non-string mapping key at {path}"
                )
            for key in sorted(value):
                if _field_is_credential(key):
                    raise WindowsRpcDeploymentSnapshotError(
                        f"credential field is forbidden at {path}.{key}"
                    )
                result[key] = _plain_json(value[key], path=f"{path}.{key}", seen=seen)
            return result
        if isinstance(value, (list, tuple)):
            return [
                _plain_json(item, path=f"{path}[{index}]", seen=seen)
                for index, item in enumerate(value)
            ]
    finally:
        seen.remove(identity)
    raise WindowsRpcDeploymentSnapshotError(
        f"value at {path} is not plain-JSON serializable"
    )


def _stable_rows(value: Any, *, field: str) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise WindowsRpcDeploymentSnapshotError(
            f"{field} snapshot must be a list or tuple"
        )
    rows = [
        _plain_json(row, path=f"{field}[{index}]", seen=set())
        for index, row in enumerate(value)
    ]
    rows.sort(key=_canonical_json)
    return rows


def _normalized_execution_facts(
    execution_facts: Mapping[str, Any],
    *,
    pending_send_outcomes: int,
) -> dict[str, Any]:
    account_hashes: set[str] = set()
    for account in execution_facts["accounts"]:
        if not isinstance(account, Mapping):
            raise WindowsRpcDeploymentSnapshotError("account fact must be a mapping")
        account_id = str(
            account.get("accountid")
            or account.get("account_id")
            or account.get("vt_accountid")
            or ""
        )
        if not account_id:
            raise WindowsRpcDeploymentSnapshotError("account identity is missing")
        account_hashes.add(hashlib.sha256(account_id.encode("utf-8")).hexdigest())
    return {
        "execution_admission_frozen": True,
        "pending_send_outcomes": pending_send_outcomes,
        "strategy_execution_enabled": False,
        "account_hashes": sorted(account_hashes),
        "orders": execution_facts["orders"],
        "active_orders": execution_facts["active_orders"],
        "trades": execution_facts["trades"],
        "positions": execution_facts["positions"],
    }


class WindowsRpcDeploymentSnapshotV1:
    """Install one non-trading snapshot RPC over an EventEngine barrier."""

    def __init__(
        self,
        *,
        rpc_engine: Any,
        event_engine: Any,
        fact_source: Any,
        event_factory: Callable[[str, Any], Any] | None = None,
        timeout_seconds: float = 5.0,
        order_event_type: str = DEFAULT_ORDER_EVENT_TYPE,
        trade_event_type: str = DEFAULT_TRADE_EVENT_TYPE,
        position_event_type: str = DEFAULT_POSITION_EVENT_TYPE,
        account_event_type: str = DEFAULT_ACCOUNT_EVENT_TYPE,
        clock: Callable[[], datetime] | None = None,
        recheck_cache_size: int = 128,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        if (
            isinstance(recheck_cache_size, bool)
            or not isinstance(recheck_cache_size, int)
            or recheck_cache_size < 1
        ):
            raise ValueError("recheck_cache_size must be a positive integer")
        self.rpc_engine = rpc_engine
        self.event_engine = event_engine
        self.fact_source = fact_source
        self.event_factory = event_factory or _default_event_factory
        self.timeout_seconds = float(timeout_seconds)
        self.order_event_type = order_event_type
        self.trade_event_type = trade_event_type
        self.position_event_type = position_event_type
        self.account_event_type = account_event_type
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.recheck_cache_size = recheck_cache_size
        self.server_instance_id = f"windows-rpc-{uuid.uuid4().hex}"
        self._fact_generation = 0
        self._admission = threading.Condition(threading.RLock())
        self._inflight_mutations = 0
        self._frozen_request_id: str | None = None
        self._frozen_challenge: str | None = None
        self._snapshot_baselines: OrderedDict[int, tuple[str, str]] = OrderedDict()
        self._pending_send_outcomes: dict[str, str | None] = {}
        self._seen_order_ids: dict[str, int] = {}
        self._rechecks: OrderedDict[str, _RecheckRequest] = OrderedDict()
        self._fresh_challenges: OrderedDict[str, str] = OrderedDict()
        self._original_send_order: Callable[..., Any] | None = None
        self._original_cancel_order: Callable[..., Any] | None = None
        self._registered = False

        def rpc_callable(request_id: str, challenge: str) -> dict[str, Any]:
            return self.get_deployment_safety_snapshot_v1(request_id, challenge)

        rpc_callable.__name__ = RPC_CALLABLE_NAME
        rpc_callable.__qualname__ = RPC_CALLABLE_NAME
        self.rpc_callable = rpc_callable

        def recheck_rpc_callable(
            request_id: str,
            owner_challenge: str,
            recheck_id: str,
            fresh_challenge: str,
            expected_generation: int,
        ) -> dict[str, Any]:
            return self.recheck_deployment_safety_snapshot_v1(
                request_id,
                owner_challenge,
                recheck_id,
                fresh_challenge,
                expected_generation,
            )

        recheck_rpc_callable.__name__ = RECHECK_RPC_CALLABLE_NAME
        recheck_rpc_callable.__qualname__ = RECHECK_RPC_CALLABLE_NAME
        self.recheck_rpc_callable = recheck_rpc_callable

    def register(self) -> Callable[[], dict[str, Any]]:
        if self._registered:
            return self.rpc_callable
        server = getattr(self.rpc_engine, "server", None)
        register_rpc = getattr(server, "register", None)
        register_event = getattr(self.event_engine, "register", None)
        if not callable(register_rpc) or not callable(register_event):
            raise TypeError("rpc server and event engine must support register")
        functions = getattr(server, "_functions", None)
        if not isinstance(functions, dict):
            raise WindowsRpcDeploymentSnapshotError(
                "rpc server function registry is unavailable"
            )
        self._validate_runtime_boundary()
        original_send = functions.get("send_order")
        original_cancel = functions.get("cancel_order")
        if not callable(original_send) or not callable(original_cancel):
            raise WindowsRpcDeploymentSnapshotError(
                "send_order and cancel_order must already be registered"
            )
        self._original_send_order = original_send
        self._original_cancel_order = original_cancel
        register_event(self.order_event_type, self._on_order_or_trade)
        register_event(self.trade_event_type, self._on_order_or_trade)
        register_event(self.position_event_type, self._on_position_or_account)
        register_event(self.account_event_type, self._on_position_or_account)
        register_event(SNAPSHOT_EVENT_TYPE, self._on_snapshot_request)
        register_event(RECHECK_EVENT_TYPE, self._on_recheck_request)
        register_rpc(self._named_wrapper("send_order", self._guarded_send_order))
        register_rpc(self._named_wrapper("cancel_order", self._guarded_cancel_order))
        register_rpc(self.rpc_callable)
        register_rpc(self.recheck_rpc_callable)
        self._registered = True
        return self.rpc_callable

    @staticmethod
    def _named_wrapper(name: str, target: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return target(*args, **kwargs)

        wrapper.__name__ = name
        wrapper.__qualname__ = name
        return wrapper

    def get_deployment_safety_snapshot_v1(
        self, request_id: str, challenge: str
    ) -> dict[str, Any]:
        self._validate_identifier(request_id, "request_id")
        self._validate_identifier(challenge, "challenge", minimum=16)
        self._validate_runtime_boundary()
        deadline = time.monotonic() + self.timeout_seconds
        with self._admission:
            if self._frozen_request_id is None:
                # Install the fence before waiting, otherwise a new send can
                # race into the gap after the in-flight count reaches zero.
                self._frozen_request_id = request_id
                self._frozen_challenge = challenge
            elif (
                self._frozen_request_id != request_id
                or self._frozen_challenge != challenge
            ):
                raise WindowsRpcDeploymentSnapshotError(
                    "Windows execution admission is owned by another request"
                )
            while self._inflight_mutations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "deployment snapshot timed out waiting for in-flight RPC"
                    )
                self._admission.wait(remaining)

        request = _SnapshotRequest(
            completed=threading.Event(),
            request_id=request_id,
            challenge=challenge,
        )
        event = self.event_factory(SNAPSHOT_EVENT_TYPE, request)
        put = getattr(self.event_engine, "put", None)
        if not callable(put):
            raise TypeError("event engine must support put")
        put(event)
        remaining = max(0.0, deadline - time.monotonic())
        if not request.completed.wait(remaining):
            raise TimeoutError(
                "get_deployment_safety_snapshot_v1 timed out waiting for EventEngine"
            )
        if request.error is not None:
            if isinstance(request.error, WindowsRpcDeploymentSnapshotError):
                raise request.error
            raise WindowsRpcDeploymentSnapshotError(
                "deployment snapshot capture failed"
            ) from request.error
        if request.result is None:
            raise WindowsRpcDeploymentSnapshotError(
                "deployment snapshot completed without a result"
            )
        with self._admission:
            self._require_frozen_owner(request_id, challenge)
            if (
                self._fact_generation != request.result["fact_generation"]
                or self._pending_send_outcomes
            ):
                raise WindowsRpcDeploymentSnapshotError(
                    "deployment snapshot changed before it was served"
                )
            return self._with_served_proof(
                request.result,
                cache_replayed=False,
                served_fact_generation=self._fact_generation,
            )

    def recheck_deployment_safety_snapshot_v1(
        self,
        request_id: str,
        owner_challenge: str,
        recheck_id: str,
        fresh_challenge: str,
        expected_generation: int,
    ) -> dict[str, Any]:
        """Capture one fresh, owner-bound snapshot with replay-safe idempotency."""

        self._validate_identifier(request_id, "request_id")
        self._validate_identifier(owner_challenge, "owner_challenge", minimum=16)
        self._validate_identifier(recheck_id, "recheck_id")
        self._validate_identifier(fresh_challenge, "fresh_challenge", minimum=16)
        if fresh_challenge == owner_challenge:
            raise WindowsRpcDeploymentSnapshotError(
                "fresh_challenge must differ from owner_challenge"
            )
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 0
        ):
            raise WindowsRpcDeploymentSnapshotError(
                "expected_generation must be a non-negative integer"
            )
        self._validate_runtime_boundary()
        parameters = (
            request_id,
            owner_challenge,
            recheck_id,
            fresh_challenge,
            expected_generation,
        )
        deadline = time.monotonic() + self.timeout_seconds
        created = False
        with self._admission:
            self._require_frozen_owner(request_id, owner_challenge)
            if expected_generation > self._fact_generation:
                raise WindowsRpcDeploymentSnapshotError(
                    "fact generation rollback detected"
                )
            if expected_generation not in self._snapshot_baselines:
                raise WindowsRpcDeploymentSnapshotError(
                    "expected generation has no original snapshot baseline"
                )
            existing = self._rechecks.get(recheck_id)
            if existing is not None:
                if existing.parameters != parameters:
                    raise WindowsRpcDeploymentSnapshotError(
                        "recheck_id was already used with different parameters"
                    )
                request = existing
                self._rechecks.move_to_end(recheck_id)
            else:
                challenge_owner = self._fresh_challenges.get(fresh_challenge)
                if challenge_owner is not None and challenge_owner != recheck_id:
                    raise WindowsRpcDeploymentSnapshotError(
                        "fresh_challenge was already used by another recheck"
                    )
                if len(self._rechecks) >= self.recheck_cache_size:
                    raise WindowsRpcDeploymentSnapshotError(
                        "recheck cache capacity is exhausted"
                    )
                request = _RecheckRequest(
                    completed=threading.Event(),
                    parameters=parameters,
                )
                self._rechecks[recheck_id] = request
                self._fresh_challenges[fresh_challenge] = recheck_id
                created = True

        if created:
            put = getattr(self.event_engine, "put", None)
            if not callable(put):
                self._complete_recheck_error(
                    request, TypeError("event engine must support put")
                )
            else:
                try:
                    put(self.event_factory(RECHECK_EVENT_TYPE, request))
                except BaseException as exc:  # noqa: BLE001
                    self._complete_recheck_error(request, exc)

        remaining = max(0.0, deadline - time.monotonic())
        if not request.completed.wait(remaining):
            raise TimeoutError(
                "recheck_deployment_safety_snapshot_v1 timed out waiting for EventEngine"
            )
        if request.error is not None:
            if isinstance(request.error, WindowsRpcDeploymentSnapshotError):
                raise request.error
            raise WindowsRpcDeploymentSnapshotError(
                "deployment snapshot recheck failed"
            ) from request.error
        if request.result_json is None:
            raise WindowsRpcDeploymentSnapshotError(
                "deployment snapshot recheck completed without a result"
            )
        with self._admission:
            self._require_frozen_owner(request_id, owner_challenge)
            result = json.loads(request.result_json)
            if (
                self._fact_generation != result["current_generation"]
                or self._pending_send_outcomes
            ):
                raise WindowsRpcDeploymentSnapshotError(
                    "cached recheck is stale or Windows pending state is unsafe"
                )
            return self._with_served_proof(
                result,
                cache_replayed=not created,
                served_fact_generation=self._fact_generation,
            )

    def _with_served_proof(
        self,
        payload: Mapping[str, Any],
        *,
        cache_replayed: bool,
        served_fact_generation: int,
    ) -> dict[str, Any]:
        served_at = self.clock()
        if served_at.tzinfo is None or served_at.utcoffset() is None:
            raise WindowsRpcDeploymentSnapshotError(
                "snapshot clock must return a timezone-aware datetime"
            )
        result = dict(payload)
        result.update(
            {
                "cache_replayed": cache_replayed,
                "served_at_utc": served_at.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "served_fact_generation": served_fact_generation,
            }
        )
        _canonical_json(result)
        return result

    def _guarded_send_order(self, *args: Any, **kwargs: Any) -> Any:
        original = self._original_send_order
        if original is None:
            raise WindowsRpcDeploymentSnapshotError("send_order is unavailable")
        send_start_generation = self._enter_mutation("send_order")
        token = f"send-{uuid.uuid4().hex}"
        try:
            result = original(*args, **kwargs)
        except BaseException:
            with self._admission:
                self._pending_send_outcomes[token] = None
            raise
        else:
            order_id = self._result_order_id(result)
            with self._admission:
                if not order_id or not any(
                    self._seen_order_ids.get(identity, -1) > send_start_generation
                    for identity in self._order_id_aliases(order_id)
                ):
                    self._pending_send_outcomes[token] = order_id
            return result
        finally:
            self._leave_mutation()

    def _guarded_cancel_order(self, *args: Any, **kwargs: Any) -> Any:
        original = self._original_cancel_order
        if original is None:
            raise WindowsRpcDeploymentSnapshotError("cancel_order is unavailable")
        self._enter_mutation("cancel_order")
        try:
            return original(*args, **kwargs)
        finally:
            self._leave_mutation()

    def _enter_mutation(self, operation: str) -> int:
        with self._admission:
            if self._frozen_request_id is not None:
                raise WindowsRpcDeploymentSnapshotError(
                    f"{operation} rejected while deployment admission is frozen"
                )
            self._inflight_mutations += 1
            return self._fact_generation

    def _leave_mutation(self) -> None:
        with self._admission:
            self._inflight_mutations -= 1
            self._admission.notify_all()

    def _on_order_or_trade(self, _event: Any) -> None:
        order_ids = self._event_order_ids(_event)
        with self._admission:
            self._fact_generation += 1
            for order_id in order_ids:
                self._seen_order_ids[order_id] = self._fact_generation
            for token, pending_order_id in tuple(self._pending_send_outcomes.items()):
                if pending_order_id and (
                    self._order_id_aliases(pending_order_id) & order_ids
                ):
                    del self._pending_send_outcomes[token]
            if len(self._seen_order_ids) > 10_000:
                cutoff = self._fact_generation - 10_000
                self._seen_order_ids = {
                    key: generation
                    for key, generation in self._seen_order_ids.items()
                    if generation >= cutoff
                }

    def _on_position_or_account(self, _event: Any) -> None:
        with self._admission:
            self._fact_generation += 1

    def _on_snapshot_request(self, event: Any) -> None:
        request = _event_data(event)
        if not isinstance(request, _SnapshotRequest):
            return
        try:
            self._validate_runtime_boundary()
            with self._admission:
                if (
                    self._frozen_request_id != request.request_id
                    or self._frozen_challenge != request.challenge
                ):
                    raise WindowsRpcDeploymentSnapshotError(
                        "snapshot event no longer owns Windows admission"
                    )
                generation = self._fact_generation
                pending_send_outcomes = len(self._pending_send_outcomes)
            captured_at = self.clock()
            if captured_at.tzinfo is None or captured_at.utcoffset() is None:
                raise WindowsRpcDeploymentSnapshotError(
                    "snapshot clock must return a timezone-aware datetime"
                )
            # This handler runs on the EventEngine thread.  All five getters
            # are copied before that thread can process the next order/trade
            # event, so generation and facts share one event-order boundary.
            snapshot = {
                "schema_version": SCHEMA_VERSION,
                "server_instance_id": self.server_instance_id,
                "fact_generation": generation,
                "request_id": request.request_id,
                "challenge": request.challenge,
                "captured_at_utc": captured_at.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "strategy_execution_enabled": False,
                "execution_admission_frozen": True,
                "pending_send_outcomes": pending_send_outcomes,
                **self._capture_execution_facts(),
            }
            # A final serialization pass proves the returned graph contains
            # only finite, plain JSON values.
            _canonical_json(snapshot)
            execution_facts = {
                field: snapshot[field]
                for field in (
                    "accounts",
                    "orders",
                    "active_orders",
                    "trades",
                    "positions",
                )
            }
            with self._admission:
                baseline = (
                    self.server_instance_id,
                    _canonical_sha256(
                        _normalized_execution_facts(
                            execution_facts,
                            pending_send_outcomes=pending_send_outcomes,
                        )
                    ),
                )
                existing_baseline = self._snapshot_baselines.get(generation)
                if existing_baseline is not None and existing_baseline != baseline:
                    raise WindowsRpcDeploymentSnapshotError(
                        "execution facts drifted without a generation change"
                    )
                if existing_baseline is None:
                    if len(self._snapshot_baselines) >= self.recheck_cache_size:
                        raise WindowsRpcDeploymentSnapshotError(
                            "original snapshot baseline capacity is exhausted"
                        )
                    self._snapshot_baselines[generation] = baseline
            request.result = snapshot
        except BaseException as exc:  # noqa: BLE001 - returned to RPC thread
            request.error = exc
        finally:
            request.completed.set()

    def _on_recheck_request(self, event: Any) -> None:
        request = _event_data(event)
        if not isinstance(request, _RecheckRequest):
            return
        (
            request_id,
            owner_challenge,
            recheck_id,
            fresh_challenge,
            expected_generation,
        ) = request.parameters
        try:
            self._validate_runtime_boundary()
            with self._admission:
                self._require_frozen_owner(request_id, owner_challenge)
                current_generation = self._fact_generation
                if expected_generation > current_generation:
                    raise WindowsRpcDeploymentSnapshotError(
                        "fact generation rollback detected"
                    )
                pending_send_outcomes = len(self._pending_send_outcomes)
                original_baseline = self._snapshot_baselines.get(expected_generation)
                if original_baseline is None:
                    raise WindowsRpcDeploymentSnapshotError(
                        "original deployment snapshot is unavailable"
                    )
                (
                    original_server_instance_id,
                    original_execution_facts_sha256,
                ) = original_baseline
            captured_at = self.clock()
            if captured_at.tzinfo is None or captured_at.utcoffset() is None:
                raise WindowsRpcDeploymentSnapshotError(
                    "snapshot clock must return a timezone-aware datetime"
                )
            execution_facts = self._capture_execution_facts()
            response = {
                "schema_version": RECHECK_SCHEMA_VERSION,
                "owner_request_id": request_id,
                "owner_challenge": owner_challenge,
                "recheck_id": recheck_id,
                "fresh_challenge": fresh_challenge,
                "expected_generation": expected_generation,
                "current_generation": current_generation,
                "server_instance_id": self.server_instance_id,
                "original_server_instance_id": original_server_instance_id,
                "original_fact_generation": expected_generation,
                "original_execution_facts_canonical_sha256": (
                    original_execution_facts_sha256
                ),
                "execution_facts_canonical_sha256": _canonical_sha256(
                    _normalized_execution_facts(
                        execution_facts,
                        pending_send_outcomes=pending_send_outcomes,
                    )
                ),
                "captured_at_utc": captured_at.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "admission": {
                    "execution_frozen": True,
                    "send_order_frozen": True,
                    "cancel_order_frozen": True,
                },
                "pending": {
                    "send_outcomes": pending_send_outcomes,
                },
                "facts": execution_facts,
            }
            request.result_json = _canonical_json(response)
        except BaseException as exc:  # noqa: BLE001
            request.error = exc
        finally:
            request.completed.set()

    def _complete_recheck_error(
        self, request: _RecheckRequest, error: BaseException
    ) -> None:
        request.error = error
        request.completed.set()

    def _require_frozen_owner(self, request_id: str, owner_challenge: str) -> None:
        if (
            self._frozen_request_id != request_id
            or self._frozen_challenge != owner_challenge
        ):
            raise WindowsRpcDeploymentSnapshotError(
                "recheck does not own Windows execution admission"
            )

    def _copy(self, getter_name: str, field: str) -> list[Any]:
        getter = getattr(self.fact_source, getter_name, None)
        if not callable(getter):
            raise WindowsRpcDeploymentSnapshotError(
                f"fact source does not provide {getter_name}"
            )
        return _stable_rows(getter(), field=field)

    def _capture_execution_facts(self) -> dict[str, list[Any]]:
        return {
            "accounts": self._copy("get_all_accounts", "accounts"),
            "orders": self._copy("get_all_orders", "orders"),
            "active_orders": self._copy("get_all_active_orders", "active_orders"),
            "trades": self._copy("get_all_trades", "trades"),
            "positions": self._copy("get_all_positions", "positions"),
        }

    def _validate_runtime_boundary(self) -> None:
        for attribute in ("engines", "apps"):
            components = getattr(self.fact_source, attribute, None)
            if not isinstance(components, Mapping):
                raise WindowsRpcDeploymentSnapshotError(
                    f"fact_source.{attribute} registry is required"
                )
            for name, component in components.items():
                identities = [str(name)]
                if component is not None:
                    identities.append(
                        component.__name__
                        if isinstance(component, type)
                        else component.__class__.__name__
                    )
                for identity in identities:
                    normalized = "".join(
                        character
                        for character in identity.lower()
                        if character.isalnum()
                    )
                    if normalized not in _ALLOWED_COMPONENT_IDENTITIES:
                        raise WindowsRpcDeploymentSnapshotError(
                            f"unknown {attribute} component: {identity}"
                        )

        server = getattr(self.rpc_engine, "server", None)
        functions = getattr(server, "_functions", {})
        candidates = set(_FORBIDDEN_STRATEGY_METHODS)
        candidates.update(name for name in functions if "strategy" in name.lower())
        candidates.update(
            name
            for name in dir(self.fact_source)
            if "strategy" in name.lower()
            and callable(getattr(self.fact_source, name, None))
        )
        exposed = sorted(
            name
            for name in candidates
            if callable(getattr(self.fact_source, name, None))
            or callable(functions.get(name))
        )
        if exposed:
            raise WindowsRpcDeploymentSnapshotError(
                "strategy-capable Windows gateway cannot publish deployment "
                f"safety snapshots: {','.join(exposed)}"
            )

    @staticmethod
    def _validate_identifier(value: str, field: str, *, minimum: int = 8) -> None:
        if (
            not isinstance(value, str)
            or not minimum <= len(value) <= 128
            or not value[0].isalnum()
            or any(
                character
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                for character in value
            )
        ):
            raise WindowsRpcDeploymentSnapshotError(f"invalid {field}")

    @staticmethod
    def _result_order_id(result: Any) -> str | None:
        if isinstance(result, str):
            return result or None
        if isinstance(result, Mapping):
            value = result.get("vt_orderid") or result.get("orderid")
            return str(value) if value else None
        value = getattr(result, "vt_orderid", None) or getattr(result, "orderid", None)
        return str(value) if value else None

    @staticmethod
    def _event_order_ids(event: Any) -> set[str]:
        data = _event_data(event)
        values: list[Any]
        if isinstance(data, Mapping):
            values = [data.get("vt_orderid"), data.get("orderid")]
        else:
            values = [
                getattr(data, "vt_orderid", None),
                getattr(data, "orderid", None),
            ]
        identifiers = {
            alias
            for value in values
            if value
            for alias in WindowsRpcDeploymentSnapshotV1._order_id_aliases(str(value))
        }
        return identifiers

    @staticmethod
    def _order_id_aliases(value: str) -> set[str]:
        aliases = {value}
        if "." in value:
            aliases.add(value.rsplit(".", 1)[-1])
        return aliases


def register_windows_rpc_deployment_snapshot_v1(
    rpc_engine: Any,
    event_engine: Any,
    fact_source: Any,
    *,
    event_factory: Callable[[str, Any], Any] | None = None,
    timeout_seconds: float = 5.0,
    order_event_type: str = DEFAULT_ORDER_EVENT_TYPE,
    trade_event_type: str = DEFAULT_TRADE_EVENT_TYPE,
    position_event_type: str = DEFAULT_POSITION_EVENT_TYPE,
    account_event_type: str = DEFAULT_ACCOUNT_EVENT_TYPE,
    clock: Callable[[], datetime] | None = None,
    recheck_cache_size: int = 128,
) -> WindowsRpcDeploymentSnapshotV1:
    """Construct and register the extension on ``rpc_engine.server``."""

    extension = WindowsRpcDeploymentSnapshotV1(
        rpc_engine=rpc_engine,
        event_engine=event_engine,
        fact_source=fact_source,
        event_factory=event_factory,
        timeout_seconds=timeout_seconds,
        order_event_type=order_event_type,
        trade_event_type=trade_event_type,
        position_event_type=position_event_type,
        account_event_type=account_event_type,
        clock=clock,
        recheck_cache_size=recheck_cache_size,
    )
    extension.register()
    return extension
