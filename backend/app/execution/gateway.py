"""Typed Windows gateway boundary used by Execution Orchestrator.

Only this package is allowed to invoke order mutations.  The concrete RPC
client is supplied by deployment integration; no import of the legacy
``VnpyRpcService`` is made here.  The in-memory implementation is intentionally
small and useful for offline safety tests.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Protocol, runtime_checkable

from .errors import GatewayConfigurationError, GatewayTimeout, GatewayUnavailable
from .gateway_contracts import GatewaySnapshot
from .models import (
    SendIntent,
    canonical_json,
    format_utc,
    parse_utc,
    sha256_json,
    utc_now,
    validate_idempotency_key,
    validate_identifier,
    validate_sha256,
)


@dataclass(frozen=True, slots=True)
class MutationContext:
    account_scope: str
    leader_epoch: int
    fencing_token: int
    plan_id: str
    plan_hash: str
    intent_id: str
    idempotency_key: str
    action: str
    environment: str = ""
    receipt_id: str = ""
    receipt_hash: str = ""
    request_hash: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "account_scope": self.account_scope,
            "leader_epoch": self.leader_epoch,
            "fencing_token": self.fencing_token,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "intent_id": self.intent_id,
            "idempotency_key": self.idempotency_key,
            "action": self.action,
            "environment": self.environment,
            "receipt_id": self.receipt_id,
            "receipt_hash": self.receipt_hash,
            "request_hash": self.request_hash,
        }


@runtime_checkable
class ExecutionGateway(Protocol):
    """The only mutation-capable interface accepted by the orchestrator."""

    def send_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]: ...

    def cancel_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]: ...

    def query_intent(
        self, intent: SendIntent, context: MutationContext | None = None
    ) -> Mapping[str, Any]: ...

    def snapshot(self) -> GatewaySnapshot: ...

    def readiness_snapshot(self) -> GatewaySnapshot: ...

    def readiness_snapshot_uses_durable_generation(self) -> bool: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...


class NullGateway:
    """Fail-closed default; it cannot accidentally send a live order."""

    def send_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        raise GatewayUnavailable("no Windows gateway is configured")

    def cancel_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        raise GatewayUnavailable("no Windows gateway is configured")

    def query_intent(
        self, intent: SendIntent, context: MutationContext | None = None
    ) -> Mapping[str, Any]:
        raise GatewayUnavailable("no Windows gateway is configured")

    def snapshot(self) -> GatewaySnapshot:
        raise GatewayUnavailable("no Windows gateway is configured")

    def readiness_snapshot(self) -> GatewaySnapshot:
        return self.snapshot()

    def readiness_snapshot_uses_durable_generation(self) -> bool:
        return True

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


class RpcTransport(Protocol):
    """Minimal typed transport seam; production uses ZeroMQ REQ/REP."""

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def call(
        self,
        method: str,
        payload: Mapping[str, Any],
        context: MutationContext | None = None,
    ) -> Mapping[str, Any]: ...


class ZmqRpcTransport:
    """Typed transport over the native vn.py ``RpcClient`` wire protocol.

    The transport is deliberately narrow: it exposes no arbitrary ``eval`` or
    dynamic method surface and every call carries the account/fence context.
    """

    def __init__(self, req_address: str, *, timeout_ms: int = 10_000) -> None:
        if not req_address or not req_address.startswith(("tcp://", "ipc://")):
            raise GatewayConfigurationError(
                "EXECUTION_RPC_REQ_ADDRESS must be a typed ZeroMQ endpoint"
            )
        if timeout_ms < 1:
            raise GatewayConfigurationError("gateway timeout must be positive")
        self.req_address = req_address
        self.timeout_ms = int(timeout_ms)
        self._context: Any = None
        self._zmq: Any = None
        self._socket: Any = None
        self._started = False
        self._lock = RLock()
        self._transport_exceptions: tuple[type[BaseException], ...] = (
            TimeoutError,
            OSError,
        )

    def _open_socket_locked(self) -> None:
        zmq = self._zmq
        if zmq is None:
            import zmq as imported_zmq

            zmq = imported_zmq
            self._zmq = zmq

        socket = self._context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        socket.setsockopt(zmq.RCVTIMEO, self.timeout_ms)
        socket.setsockopt(zmq.SNDTIMEO, self.timeout_ms)
        socket.connect(self.req_address)
        self._socket = socket

    def _discard_socket_locked(self) -> None:
        socket, self._socket = self._socket, None
        if socket is not None:
            socket.close(linger=0)

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            try:
                import zmq
            except (
                ImportError
            ) as exc:  # pragma: no cover - deployment image supplies pyzmq
                raise GatewayConfigurationError(
                    "pyzmq is required for the Windows gateway"
                ) from exc
            self._zmq = zmq
            transport_exceptions = [TimeoutError, OSError]
            for name in ("ZMQError", "Again"):
                candidate = getattr(zmq, name, None)
                if isinstance(candidate, type) and issubclass(candidate, BaseException):
                    transport_exceptions.append(candidate)
            self._transport_exceptions = tuple(dict.fromkeys(transport_exceptions))
            self._context = zmq.Context.instance()
            self._open_socket_locked()
            self._started = True

    def stop(self) -> None:
        with self._lock:
            self._discard_socket_locked()
            self._started = False

    def call(
        self,
        method: str,
        payload: Mapping[str, Any],
        context: MutationContext | None = None,
    ) -> Mapping[str, Any]:
        if method not in {
            "install_fence_v1",
            "register_receipt_v1",
            "send_order_fenced_v1",
            "cancel_order_fenced_v1",
            "query_intent_v1",
            "query_intent",
            "get_execution_snapshot_v1",
            "peek_current_facts_v1",
        }:
            raise GatewayConfigurationError(
                "Windows RPC method is outside the typed execution surface"
            )
        arguments: tuple[Any, ...] = (dict(payload),)
        if context is not None:
            arguments += (context.as_dict(),)
        request = [method, arguments, {}]
        with self._lock:
            if not self._started or self._socket is None:
                raise GatewayUnavailable("Windows typed RPC transport is not started")
            try:
                self._socket.send_pyobj(request)
                response = self._socket.recv_pyobj()
            except self._transport_exceptions as exc:
                # A REQ socket that missed its reply is permanently in the
                # wrong EFSM state.  Destroy it before any same-intent query.
                self._discard_socket_locked()
                try:
                    self._open_socket_locked()
                except self._transport_exceptions:
                    self._started = False
                raise GatewayTimeout(
                    f"Windows typed RPC {method} timed out; REQ socket rebuilt"
                ) from exc
        if (
            not isinstance(response, (list, tuple))
            or len(response) != 2
            or not isinstance(response[0], bool)
        ):
            raise GatewayUnavailable("Windows gateway returned an invalid RPC reply")
        succeeded, result = response
        if not succeeded:
            raise GatewayUnavailable(str(result or "Windows gateway rejected request"))
        if not isinstance(result, Mapping):
            raise GatewayUnavailable("Windows gateway result is not an object")
        return dict(result)


class VnpyWindowsGateway:
    """Real typed Execution→Windows CTP gateway adapter."""

    _DURABLE_SNAPSHOT_SOURCE = "durable-snapshot-v1"
    _FINAL_VALIDATION_PEEK_SOURCE = "final-validation-peek-current-facts-v1"
    _FINAL_VALIDATION_GATEWAY_NAME = "CTP"
    _FINAL_VALIDATION_SERVICE_ENVIRONMENT = "SIMNOW"
    _FINAL_VALIDATION_WINDOWS_ENVIRONMENT = "simnow"

    def __init__(
        self,
        *,
        req_address: str,
        pub_address: str,
        account_scope: str,
        environment: str,
        timeout_ms: int = 10_000,
        transport: RpcTransport | None = None,
        readonly_transport: RpcTransport | None = None,
        readiness_snapshot_source: str = _DURABLE_SNAPSHOT_SOURCE,
    ) -> None:
        if not req_address or not req_address.startswith(("tcp://", "ipc://")):
            raise GatewayConfigurationError(
                "a typed Windows RPC request endpoint is required"
            )
        if not pub_address or not pub_address.startswith(("tcp://", "ipc://")):
            raise GatewayConfigurationError("both Windows RPC endpoints are required")
        if not account_scope or account_scope == "account:default":
            raise GatewayConfigurationError(
                "explicit non-default account scope is required"
            )
        if not environment or environment == "default":
            raise GatewayConfigurationError(
                "explicit execution environment is required"
            )
        try:
            timeout_ms = int(timeout_ms)
        except (TypeError, ValueError) as exc:
            raise GatewayConfigurationError(
                "gateway timeout must be an integer"
            ) from exc
        if timeout_ms < 1:
            raise GatewayConfigurationError("gateway timeout must be positive")
        if readiness_snapshot_source not in {
            self._DURABLE_SNAPSHOT_SOURCE,
            self._FINAL_VALIDATION_PEEK_SOURCE,
        }:
            raise GatewayConfigurationError(
                "EXECUTION_READINESS_SNAPSHOT_SOURCE is not supported"
            )
        if (
            readiness_snapshot_source == self._FINAL_VALIDATION_PEEK_SOURCE
            and environment != self._FINAL_VALIDATION_SERVICE_ENVIRONMENT
        ):
            raise GatewayConfigurationError(
                "final-validation peek requires EXECUTION_ENVIRONMENT=SIMNOW"
            )
        self.req_address = req_address
        self.pub_address = pub_address
        self.account_scope = account_scope
        self.environment = environment
        self.timeout_ms = timeout_ms
        self.readiness_snapshot_source = readiness_snapshot_source
        self.transport = transport or ZmqRpcTransport(
            req_address, timeout_ms=timeout_ms
        )
        self.readonly_transport = readonly_transport or (
            transport
            if transport is not None
            else ZmqRpcTransport(req_address, timeout_ms=timeout_ms)
        )
        self.started = False

    @classmethod
    def from_env(cls) -> VnpyWindowsGateway:
        req = os.getenv("EXECUTION_RPC_REQ_ADDRESS", "").strip()
        pub = os.getenv("EXECUTION_RPC_PUB_ADDRESS", "").strip()
        scope = (
            os.getenv("EXECUTION_ACCOUNT_SCOPE", "").strip()
            or os.getenv("EXECUTION_SCOPE", "").strip()
        )
        environment = os.getenv("EXECUTION_ENVIRONMENT", "").strip()
        raw_timeout = os.getenv("EXECUTION_RPC_TIMEOUT_MS", "10000")
        readiness_snapshot_source = os.getenv(
            "EXECUTION_READINESS_SNAPSHOT_SOURCE",
            cls._DURABLE_SNAPSHOT_SOURCE,
        ).strip()
        try:
            timeout = int(raw_timeout)
        except ValueError as exc:
            raise GatewayConfigurationError(
                "EXECUTION_RPC_TIMEOUT_MS must be an integer"
            ) from exc
        return cls(
            req_address=req,
            pub_address=pub,
            account_scope=scope,
            environment=environment,
            timeout_ms=timeout,
            readiness_snapshot_source=readiness_snapshot_source,
        )

    def start(self) -> None:
        if self.started:
            return
        self.transport.start()
        if self.readonly_transport is not self.transport:
            self.readonly_transport.start()
        self.started = True

    def stop(self) -> None:
        try:
            if self.readonly_transport is not self.transport:
                self.readonly_transport.stop()
            self.transport.stop()
        finally:
            self.started = False

    def _require_started(self) -> None:
        if not self.started:
            raise GatewayUnavailable("Windows typed gateway is not started")

    def _validate_context(self, context: MutationContext) -> None:
        if context.account_scope != self.account_scope:
            raise GatewayConfigurationError("gateway account scope mismatch")
        if context.environment != self.environment:
            raise GatewayConfigurationError("gateway environment mismatch")
        if context.action not in {"send", "cancel"}:
            raise GatewayConfigurationError("gateway mutation action is invalid")
        if (
            isinstance(context.leader_epoch, bool)
            or isinstance(context.fencing_token, bool)
            or not isinstance(context.leader_epoch, int)
            or not isinstance(context.fencing_token, int)
            or context.leader_epoch < 1
            or context.fencing_token < 1
        ):
            raise GatewayConfigurationError(
                "gateway mutation requires a positive fence"
            )
        for value, label in (
            (context.plan_id, "plan_id"),
            (context.intent_id, "intent_id"),
        ):
            try:
                validate_identifier(value, label)
            except Exception as exc:
                raise GatewayConfigurationError(f"gateway {label} is invalid") from exc
        try:
            validate_identifier(context.receipt_id, "receipt_id")
            validate_idempotency_key(context.idempotency_key)
            validate_sha256(context.plan_hash, "plan_hash")
            validate_sha256(context.receipt_hash, "receipt_hash")
            validate_sha256(context.request_hash, "request_hash")
        except Exception as exc:
            raise GatewayConfigurationError(
                "gateway receipt binding is invalid"
            ) from exc

    def _windows_wire_context(self, context: MutationContext) -> MutationContext:
        """Map the fixed service SimNow label to the Windows fence label."""

        if self.environment != self._FINAL_VALIDATION_SERVICE_ENVIRONMENT:
            return context
        wire_environment = self._FINAL_VALIDATION_WINDOWS_ENVIRONMENT
        return replace(
            context,
            environment=wire_environment,
            receipt_hash=sha256_json(
                {
                    "account_scope": context.account_scope,
                    "environment": wire_environment,
                    "intent_id": context.intent_id,
                    "idempotency_key": context.idempotency_key,
                    "plan_id": context.plan_id,
                    "plan_hash": context.plan_hash,
                    "request_hash": context.request_hash,
                    "action": context.action,
                }
            ),
        )

    def _windows_wire_environment(self) -> str:
        if self.environment == self._FINAL_VALIDATION_SERVICE_ENVIRONMENT:
            return self._FINAL_VALIDATION_WINDOWS_ENVIRONMENT
        return self.environment

    def _call_mutation(
        self, method: str, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        self._require_started()
        self._validate_context(context)
        wire_context = self._windows_wire_context(context)
        # The Windows admission is advanced and receipt-bound immediately
        # before every mutation.  A missing/foreign/stale remote lifecycle
        # response fails closed before the order method is reached.
        fence_result = self.transport.call(
            "install_fence_v1",
            {
                "account_scope": wire_context.account_scope,
                "environment": wire_context.environment,
                "leader_epoch": wire_context.leader_epoch,
                "fencing_token": wire_context.fencing_token,
            },
            None,
        )
        self._validate_fence_result(fence_result, wire_context)
        receipt_result = self.transport.call(
            "register_receipt_v1",
            {
                "intent_id": wire_context.intent_id,
                "receipt": {
                    "intent_id": wire_context.intent_id,
                    "receipt_id": wire_context.receipt_id,
                    "receipt_hash": wire_context.receipt_hash,
                    "request_hash": wire_context.request_hash,
                    "account_scope": wire_context.account_scope,
                    "environment": wire_context.environment,
                    "leader_epoch": wire_context.leader_epoch,
                    "fencing_token": wire_context.fencing_token,
                    "idempotency_key": wire_context.idempotency_key,
                    "plan_id": wire_context.plan_id,
                    "plan_hash": wire_context.plan_hash,
                    "action": wire_context.action,
                },
            },
            None,
        )
        self._validate_receipt_result(receipt_result, wire_context)
        result = self.transport.call(
            method,
            dict(request),
            wire_context,
        )
        return self._validate_fenced_response(result, wire_context)

    def _validate_fence_result(
        self, result: Mapping[str, Any], context: MutationContext
    ) -> None:
        if not isinstance(result, Mapping):
            raise GatewayUnavailable("Windows fence install returned a non-object")
        expected = {
            "schema_version": "windows_execution_fenced_mutation_v1",
            "account_scope": context.account_scope,
            "environment": context.environment,
            "current_epoch": context.leader_epoch,
            "current_fencing_token": context.fencing_token,
        }
        for response_field, value in expected.items():
            if result.get(response_field) != value:
                raise GatewayUnavailable(
                    f"Windows fence install {response_field} binding mismatch"
                )

    def _validate_receipt_result(
        self, result: Mapping[str, Any], context: MutationContext
    ) -> None:
        if not isinstance(result, Mapping):
            raise GatewayUnavailable(
                "Windows receipt registration returned a non-object"
            )
        expected = {
            "schema_version": "windows_execution_fenced_mutation_v1",
            "admission": "REGISTERED",
            "account_scope": context.account_scope,
            "environment": context.environment,
            "intent_id": context.intent_id,
            "receipt_id": context.receipt_id,
            "leader_epoch": context.leader_epoch,
            "fencing_token": context.fencing_token,
        }
        for response_field, value in expected.items():
            if result.get(response_field) != value:
                raise GatewayUnavailable(
                    f"Windows receipt registration {response_field} binding mismatch"
                )

    @staticmethod
    def _validate_fenced_response(
        result: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        if not isinstance(result, Mapping):
            raise GatewayUnavailable("Windows fenced gateway returned a non-object")
        expected = {
            "admission": "ACCEPTED",
            "account_scope": context.account_scope,
            "environment": context.environment,
            "leader_epoch": context.leader_epoch,
            "fencing_token": context.fencing_token,
            "intent_id": context.intent_id,
            "receipt_id": context.receipt_id,
            "receipt_hash": context.receipt_hash,
            "request_hash": context.request_hash,
            "plan_id": context.plan_id,
            "plan_hash": context.plan_hash,
            "idempotency_key": context.idempotency_key,
            "operation": context.action,
        }
        for response_field, value in expected.items():
            if result.get(response_field) != value:
                raise GatewayUnavailable(
                    f"Windows fenced response {response_field} binding mismatch"
                )
        state = result.get("state")
        if not isinstance(state, str) or state.upper() in {
            "",
            "UNKNOWN",
            "UNKNOWN_OUTCOME",
            "PENDING",
        }:
            raise GatewayTimeout("Windows fenced gateway returned an unknown outcome")
        if state.upper() not in {
            "SUBMITTED",
            "ACKNOWLEDGED",
            "CANCELLED",
            "TERMINAL",
            "RECONCILED",
            "REJECTED",
        }:
            raise GatewayUnavailable(
                "Windows fenced gateway returned an unsupported state"
            )
        accepted = result.get("accepted")
        if accepted is not None and not isinstance(accepted, bool):
            raise GatewayUnavailable("Windows fenced gateway accepted flag is invalid")
        if state.upper() == "REJECTED" and accepted is True:
            raise GatewayTimeout(
                "Windows fenced gateway returned contradictory rejected acceptance"
            )
        if accepted is False and state.upper() in {
            "SUBMITTED",
            "ACKNOWLEDGED",
            "CANCELLED",
            "RECONCILED",
        }:
            raise GatewayTimeout(
                "Windows fenced gateway returned contradictory declined state"
            )
        return dict(result)

    def send_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        return self._call_mutation("send_order_fenced_v1", request, context)

    def cancel_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        return self._call_mutation("cancel_order_fenced_v1", request, context)

    def query_intent(
        self, intent: SendIntent, context: MutationContext | None = None
    ) -> Mapping[str, Any]:
        self._require_started()
        wire_context = (
            self._windows_wire_context(context) if context is not None else None
        )
        windows_environment = self._windows_wire_environment()
        result = self.transport.call(
            "query_intent_v1",
            {
                "account_scope": self.account_scope,
                "environment": windows_environment,
                "intent_id": intent.intent_id,
                "broker_order_id": intent.broker_order_id,
            },
            wire_context,
        )
        expected = {
            "intent_id": intent.intent_id,
            "account_scope": self.account_scope,
            "environment": windows_environment,
        }
        if any(result.get(field) != value for field, value in expected.items()):
            raise GatewayUnavailable("Windows intent query binding mismatch")
        state = result.get("state")
        if not isinstance(state, str) or state.upper() not in {
            "UNKNOWN",
            "UNKNOWN_OUTCOME",
            "SUBMITTED",
            "ACKNOWLEDGED",
            "CANCELLED",
            "TERMINAL",
            "RECONCILED",
            "REJECTED",
        }:
            raise GatewayUnavailable("Windows intent query state is invalid")
        broker_order_id = result.get("broker_order_id")
        if broker_order_id is not None and not isinstance(broker_order_id, str):
            raise GatewayUnavailable("Windows intent query order binding is invalid")
        if (
            intent.broker_order_id
            and broker_order_id
            and intent.broker_order_id != broker_order_id
        ):
            raise GatewayUnavailable("Windows intent query order binding mismatch")
        accepted = result.get("accepted")
        if accepted is not None and not isinstance(accepted, bool):
            raise GatewayUnavailable("Windows intent query acceptance is invalid")
        return dict(result)

    def snapshot(self) -> GatewaySnapshot:
        self._require_started()
        windows_environment = (
            self._FINAL_VALIDATION_WINDOWS_ENVIRONMENT
            if self.readiness_snapshot_source == self._FINAL_VALIDATION_PEEK_SOURCE
            else self.environment
        )
        result = self.readonly_transport.call(
            "get_execution_snapshot_v1",
            {"environment": windows_environment, "account_scope": self.account_scope},
            None,
        )
        try:
            required = {
                "snapshot_id",
                "generation",
                "connected",
                "active_order_count",
                "position_snapshot_hash",
                "observed_at",
                "orders",
                "positions",
                "account_scope",
                "environment",
                "fresh",
            }
            if set(result) != required:
                raise TypeError("snapshot fields are not exact")
            if any(
                not isinstance(result[field], expected)
                for field, expected in {
                    "snapshot_id": str,
                    "position_snapshot_hash": str,
                    "observed_at": str,
                    "account_scope": str,
                    "environment": str,
                    "orders": Mapping,
                    "positions": Mapping,
                }.items()
            ):
                raise TypeError("snapshot field type is invalid")
            generation = result["generation"]
            connected = result["connected"]
            active_order_count = result["active_order_count"]
            fresh = result["fresh"]
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or isinstance(active_order_count, bool)
                or not isinstance(active_order_count, int)
                or not isinstance(connected, bool)
                or not isinstance(fresh, bool)
            ):
                raise TypeError("snapshot field type is invalid")
            validate_identifier(result["snapshot_id"], "snapshot_id")
            validate_sha256(result["position_snapshot_hash"], "position_snapshot_hash")
            parse_utc(result["observed_at"], field_name="snapshot.observed_at")
            canonical_json(dict(result["orders"]))
            canonical_json(dict(result["positions"]))
            return GatewaySnapshot(
                snapshot_id=result["snapshot_id"],
                generation=generation,
                connected=connected,
                active_order_count=active_order_count,
                position_snapshot_hash=result["position_snapshot_hash"],
                observed_at=result["observed_at"],
                orders=result["orders"],
                positions=result["positions"],
                account_scope=result["account_scope"],
                environment=(
                    self.environment
                    if self.readiness_snapshot_source
                    == self._FINAL_VALIDATION_PEEK_SOURCE
                    else result["environment"]
                ),
                fresh=fresh,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayUnavailable(
                "Windows gateway returned an invalid snapshot"
            ) from exc

    def readiness_snapshot(self) -> GatewaySnapshot:
        self._require_started()
        if self.readiness_snapshot_source == self._FINAL_VALIDATION_PEEK_SOURCE:
            return self._snapshot_from_final_validation_peek()
        return self.snapshot()

    def readiness_snapshot_uses_durable_generation(self) -> bool:
        return self.readiness_snapshot_source != self._FINAL_VALIDATION_PEEK_SOURCE

    @staticmethod
    def _canonical_fact_rows(value: Any, *, field: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping) or any(
            not isinstance(key, str) or not isinstance(row, Mapping)
            for key, row in value.items()
        ):
            raise TypeError(f"{field} facts are invalid")
        canonical_json(dict(value))
        return value

    def _snapshot_from_final_validation_peek(self) -> GatewaySnapshot:
        """Derive a local snapshot from the fixed validation-only peek RPC.

        This path deliberately consumes no broker-provided snapshot identity or
        time.  The resulting identity is bound to the entire canonical facts
        object, while freshness means when this process served that read.
        """

        result = self.readonly_transport.call(
            "peek_current_facts_v1",
            {
                "account_scope": self.account_scope,
                "environment": self._FINAL_VALIDATION_WINDOWS_ENVIRONMENT,
            },
            None,
        )
        try:
            required = {
                "schema_version",
                "position_query_complete",
                "account",
                "positions",
                "active_orders",
                "gateway",
                "execution",
                "admission",
            }
            if not isinstance(result, Mapping) or set(result) != required:
                raise TypeError("current facts fields are not exact")
            if result["schema_version"] != "windows_execution_current_facts_v1":
                raise TypeError("current facts schema is invalid")
            if result["position_query_complete"] is not True:
                raise TypeError("current facts position query is not ready")
            self._canonical_fact_rows(result["account"], field="account")
            positions = self._canonical_fact_rows(result["positions"], field="position")
            active_orders = self._canonical_fact_rows(
                result["active_orders"], field="active order"
            )
            gateway = result["gateway"]
            if (
                not isinstance(gateway, Mapping)
                or dict(gateway)
                != {
                    "gateway_name": self._FINAL_VALIDATION_GATEWAY_NAME,
                    "account_scope": self.account_scope,
                    "environment": self._FINAL_VALIDATION_WINDOWS_ENVIRONMENT,
                    "connected": gateway.get("connected"),
                }
                or not isinstance(gateway["connected"], bool)
            ):
                raise TypeError("current facts gateway binding is invalid")
            execution = result["execution"]
            if not isinstance(execution, Mapping) or set(execution) != {"orders"}:
                raise TypeError("current facts execution fields are not exact")
            self._canonical_fact_rows(execution["orders"], field="order")
            admission = result["admission"]
            admission_fields = {
                "account_scope",
                "environment",
                "durable_state_version",
                "durable_state_hash",
                "snapshot_generation",
                "fence",
                "receipt_intents",
            }
            if not isinstance(admission, Mapping) or set(admission) != admission_fields:
                raise TypeError("current facts admission fields are not exact")
            if (
                admission["account_scope"] != self.account_scope
                or admission["environment"]
                != self._FINAL_VALIDATION_WINDOWS_ENVIRONMENT
            ):
                raise TypeError("current facts admission scope is invalid")
            for field in ("durable_state_version", "snapshot_generation"):
                if (
                    isinstance(admission[field], bool)
                    or not isinstance(admission[field], int)
                    or admission[field] < 0
                ):
                    raise TypeError("current facts admission generation is invalid")
            validate_sha256(admission["durable_state_hash"], "durable_state_hash")
            fence = admission["fence"]
            if not isinstance(fence, Mapping) or set(fence) != {
                "active",
                "current_epoch",
                "current_fencing_token",
                "high_water_epoch",
                "high_water_fencing_token",
            }:
                raise TypeError("current facts fence fields are not exact")
            if not isinstance(fence["active"], bool) or any(
                isinstance(fence[field], bool)
                or not isinstance(fence[field], int)
                or fence[field] < 0
                for field in (
                    "current_epoch",
                    "current_fencing_token",
                    "high_water_epoch",
                    "high_water_fencing_token",
                )
            ):
                raise TypeError("current facts fence is invalid")
            receipt_intents = admission["receipt_intents"]
            if (
                not isinstance(receipt_intents, list)
                or any(not isinstance(value, str) for value in receipt_intents)
                or receipt_intents != sorted(set(receipt_intents))
            ):
                raise TypeError("current facts receipts are invalid")
            raw_facts_hash = sha256_json(dict(result))
            return GatewaySnapshot(
                snapshot_id=f"snapshot-peek-{raw_facts_hash}",
                generation=admission["snapshot_generation"],
                connected=gateway["connected"],
                active_order_count=len(active_orders),
                position_snapshot_hash=sha256_json(dict(positions)),
                observed_at=format_utc(utc_now()),
                orders=active_orders,
                positions=positions,
                account_scope=self.account_scope,
                environment=self.environment,
                fresh=True,
                fence_high_water_epoch=fence["high_water_epoch"],
                fence_high_water_fencing_token=fence["high_water_fencing_token"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayUnavailable(
                "Windows gateway returned invalid final-validation current facts"
            ) from exc


class InMemoryGateway:
    """Deterministic gateway fake that records all mutation attempts."""

    def __init__(
        self, *, account_scope: str = "account:default", environment: str = "test"
    ) -> None:
        self.send_calls: list[tuple[dict[str, Any], MutationContext]] = []
        self.cancel_calls: list[tuple[dict[str, Any], MutationContext]] = []
        self.query_calls: list[str] = []
        self.snapshots: list[GatewaySnapshot] = []
        self.fail_send: Exception | None = None
        self.fail_cancel: Exception | None = None
        self.fail_query: Exception | None = None
        self.next_order_id = 1
        self.intent_outcomes: dict[str, dict[str, Any]] = {}
        self.account_scope = account_scope
        self.environment = environment
        self._snapshot_generation = 0

    def send_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        self.send_calls.append((dict(request), context))
        if self.fail_send is not None:
            error = self.fail_send
            if isinstance(error, Exception):
                raise error
            raise GatewayTimeout(str(error))
        order_id = str(request.get("broker_order_id") or f"order-{self.next_order_id}")
        self.next_order_id += 1
        result = {
            "accepted": True,
            "state": "ACKNOWLEDGED",
            "broker_order_id": order_id,
            "intent_id": context.intent_id,
        }
        self.intent_outcomes[context.intent_id] = {"state": "ACKNOWLEDGED", **result}
        return result

    def cancel_order(
        self, request: Mapping[str, Any], context: MutationContext
    ) -> Mapping[str, Any]:
        self.cancel_calls.append((dict(request), context))
        if self.fail_cancel is not None:
            error = self.fail_cancel
            if isinstance(error, Exception):
                raise error
            raise GatewayTimeout(str(error))
        result = {
            "accepted": True,
            "cancelled": True,
            "state": "CANCELLED",
            "intent_id": context.intent_id,
        }
        self.intent_outcomes[context.intent_id] = {"state": "ACKNOWLEDGED", **result}
        return result

    def query_intent(
        self, intent: SendIntent, context: MutationContext | None = None
    ) -> Mapping[str, Any]:
        self.query_calls.append(intent.intent_id)
        if self.fail_query is not None:
            error = self.fail_query
            if isinstance(error, Exception):
                raise error
            raise GatewayTimeout(str(error))
        return dict(self.intent_outcomes.get(intent.intent_id, {"state": "UNKNOWN"}))

    def snapshot(self) -> GatewaySnapshot:
        if self.snapshots:
            return self.snapshots[-1]
        self._snapshot_generation += 1
        return GatewaySnapshot(
            snapshot_id="snapshot-default",
            generation=self._snapshot_generation - 1,
            connected=True,
            position_snapshot_hash=sha256_json({}),
            account_scope=self.account_scope,
            environment=self.environment,
        )

    def readiness_snapshot(self) -> GatewaySnapshot:
        return self.snapshot()

    def readiness_snapshot_uses_durable_generation(self) -> bool:
        return True

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None
