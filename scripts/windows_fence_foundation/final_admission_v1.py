"""Typed final Windows send/cancel admission for the Phase A boundary.

The existing WF-1 assembly remains the immutable ``FROZEN/NONE`` foundation
and deliberately denies its legacy ``send_order``/``cancel_order`` names.  A
later runtime may attach this small, separately named boundary.  It owns no
strategy logic: it atomically checks the account/environment, current
monotonic fence, intent and receipt binding before invoking one supplied vn.py
handler.  Invalid or unknown results are never upgraded to an acknowledgement.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from threading import RLock
from typing import Any

from .admission import WindowsRpcDurableFenceDenied, WindowsRpcDurableFenceError
from .final_store_v1 import DurableFinalAdmissionStoreV1

SCHEMA_VERSION = "windows_execution_fenced_mutation_v1"
INSTALL_FENCE_METHOD = "install_fence_v1"
REGISTER_RECEIPT_METHOD = "register_receipt_v1"
SEND_METHOD = "send_order_fenced_v1"
CANCEL_METHOD = "cancel_order_fenced_v1"
QUERY_METHOD = "query_intent_v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
_MUTATION_STATES = frozenset(
    {"SUBMITTED", "ACKNOWLEDGED", "CANCELLED", "TERMINAL", "RECONCILED", "REJECTED"}
)
_UNKNOWN_STATES = frozenset({"", "UNKNOWN", "UNKNOWN_OUTCOME", "PENDING"})


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise WindowsRpcDurableFenceDenied(
            f"{field} is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
        )
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise WindowsRpcDurableFenceDenied(
            f"{field} is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
        )
    return value


def _receipt_digest(context: Mapping[str, Any]) -> str:
    payload = {
        "account_scope": context["account_scope"],
        "environment": context["environment"],
        "intent_id": context["intent_id"],
        "idempotency_key": context["idempotency_key"],
        "plan_id": context["plan_id"],
        "plan_hash": context["plan_hash"],
        "request_hash": context.get("request_hash", ""),
        "action": context["action"],
    }
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _request_digest(request: Mapping[str, Any]) -> str:
    try:
        raw = json.dumps(
            dict(request),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsRpcDurableFenceDenied(
            "order request is not canonical JSON", code="WINDOWS_FENCE_REQUEST_INVALID"
        ) from exc
    return hashlib.sha256(raw).hexdigest()


class WindowsRpcFencedAdmissionV1:
    """Atomic typed final admission around one Windows vn.py handler pair."""

    def __init__(
        self,
        *,
        account_scope: str,
        environment: str,
        current_epoch: int = 0,
        current_fencing_token: int = 0,
        send_handler: Callable[
            [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
        ],
        cancel_handler: Callable[
            [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
        ],
        query_handler: Callable[
            [Mapping[str, Any], Mapping[str, Any] | None], Mapping[str, Any]
        ]
        | None = None,
        durable_store: DurableFinalAdmissionStoreV1 | None = None,
    ) -> None:
        if (
            not isinstance(account_scope, str)
            or not account_scope
            or account_scope == "account:default"
        ):
            raise WindowsRpcDurableFenceError(
                "an explicit account scope is required",
                code="WINDOWS_FENCE_SCOPE_INVALID",
            )
        if (
            not isinstance(environment, str)
            or not environment
            or environment == "default"
        ):
            raise WindowsRpcDurableFenceError(
                "an explicit execution environment is required",
                code="WINDOWS_FENCE_SCOPE_INVALID",
            )
        for value, field in (
            (current_epoch, "current_epoch"),
            (current_fencing_token, "current_fencing_token"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise WindowsRpcDurableFenceError(
                    f"{field} is invalid", code="WINDOWS_FENCE_STATE_INVALID"
                )
        if not callable(send_handler) or not callable(cancel_handler):
            raise WindowsRpcDurableFenceError(
                "typed send/cancel handlers are required",
                code="WINDOWS_FENCE_HANDLER_INVALID",
            )
        self.account_scope = account_scope
        self.environment = environment
        self._epoch = current_epoch
        self._fencing_token = current_fencing_token
        self._active = current_epoch > 0
        self._high_water_epoch = current_epoch
        self._high_water_fencing_token = current_fencing_token
        self._send_handler = send_handler
        self._cancel_handler = cancel_handler
        self._query_handler = query_handler
        self._durable_store = durable_store
        self._receipts: dict[str, dict[str, Any]] = {}
        self._idempotency: dict[str, str] = {}
        self._lock = RLock()
        if durable_store is not None:
            if (
                durable_store.account_scope != account_scope
                or durable_store.environment != environment
            ):
                raise WindowsRpcDurableFenceError(
                    "durable final store scope mismatch",
                    code="WINDOWS_FINAL_STORE_INVALID",
                )
            durable = durable_store.snapshot()
            if current_epoch != 0 or current_fencing_token != 0:
                raise WindowsRpcDurableFenceError(
                    "durable admission must start without an active fence",
                    code="WINDOWS_FINAL_STORE_INVALID",
                )
            self._epoch = 0
            self._fencing_token = 0
            self._active = False
            self._high_water_epoch = int(durable["current_epoch"])
            self._high_water_fencing_token = int(durable["current_fencing_token"])
            self._receipts = copy.deepcopy(durable["receipts"])
            self._idempotency = copy.deepcopy(durable["idempotency"])

    @classmethod
    def bootstrap(
        cls,
        *,
        store_path: str,
        account_scope: str,
        environment: str,
        send_handler: Callable[
            [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
        ],
        cancel_handler: Callable[
            [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
        ],
        query_handler: Callable[
            [Mapping[str, Any], Mapping[str, Any] | None], Mapping[str, Any]
        ]
        | None = None,
    ) -> WindowsRpcFencedAdmissionV1:
        """Explicitly bootstrap/open the durable final admission store."""

        store = DurableFinalAdmissionStoreV1.bootstrap(
            store_path,
            account_scope=account_scope,
            environment=environment,
        )
        return cls(
            account_scope=account_scope,
            environment=environment,
            current_epoch=0,
            current_fencing_token=0,
            send_handler=send_handler,
            cancel_handler=cancel_handler,
            query_handler=query_handler,
            durable_store=store,
        )

    def _refresh_durable(self) -> None:
        if self._durable_store is None:
            return
        durable = self._durable_store.snapshot()
        high_water_epoch = int(durable["current_epoch"])
        high_water_token = int(durable["current_fencing_token"])
        if self._active and (
            high_water_epoch != self._epoch or high_water_token != self._fencing_token
        ):
            self._active = False
            self._epoch = 0
            self._fencing_token = 0
        self._high_water_epoch = high_water_epoch
        self._high_water_fencing_token = high_water_token
        self._receipts = copy.deepcopy(durable["receipts"])
        self._idempotency = copy.deepcopy(durable["idempotency"])

    @property
    def current_epoch(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def current_fencing_token(self) -> int:
        with self._lock:
            return self._fencing_token

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._refresh_durable()
            return {
                "schema_version": SCHEMA_VERSION,
                "account_scope": self.account_scope,
                "environment": self.environment,
                "current_epoch": self._epoch,
                "current_fencing_token": self._fencing_token,
                "active": self._active,
                "high_water_epoch": self._high_water_epoch,
                "high_water_fencing_token": self._high_water_fencing_token,
                "receipt_intents": sorted(self._receipts),
            }

    def peek_current_facts(self) -> dict[str, Any]:
        """Return the current durable fence facts without allocating a generation.

        This is intentionally distinct from ``allocate_snapshot_generation``:
        a ceremony may inspect the current state, but cannot turn that read into
        a durable transition or observation reservation.
        """

        with self._lock:
            self._refresh_durable()
            if self._durable_store is None:
                raise WindowsRpcDurableFenceError(
                    "current facts require the durable final store",
                    code="WINDOWS_FINAL_STORE_MISSING",
                )
            durable = self._durable_store.snapshot()
            return {
                "account_scope": self.account_scope,
                "environment": self.environment,
                "durable_state_version": int(durable["state_version"]),
                "durable_state_hash": str(durable["state_hash"]),
                "snapshot_generation": int(durable["snapshot_generation"]),
                "fence": {
                    "active": self._active,
                    "current_epoch": self._epoch,
                    "current_fencing_token": self._fencing_token,
                    "high_water_epoch": self._high_water_epoch,
                    "high_water_fencing_token": self._high_water_fencing_token,
                },
                "receipt_intents": sorted(self._receipts),
            }

    def allocate_snapshot_generation(self) -> tuple[int, str]:
        """Allocate a durable observation generation without changing trade facts."""

        with self._lock:
            if self._durable_store is None:
                raise WindowsRpcDurableFenceError(
                    "snapshot generation requires the durable final store",
                    code="WINDOWS_FINAL_STORE_MISSING",
                )
            durable = self._durable_store.allocate_snapshot_generation()
            return int(durable["snapshot_generation"]), str(durable["state_hash"])

    def install_fence(self, *, epoch: int, fencing_token: int) -> dict[str, Any]:
        """Install a monotonic durable fence; equal values are idempotent."""
        with self._lock:
            self._refresh_durable()
            if (
                isinstance(epoch, bool)
                or isinstance(fencing_token, bool)
                or not isinstance(epoch, int)
                or not isinstance(fencing_token, int)
                or (epoch == 0) != (fencing_token == 0)
            ):
                raise WindowsRpcDurableFenceDenied(
                    "fence epoch/token is stale or partially advanced",
                    code="WINDOWS_FENCE_STALE_TOKEN",
                )
            if (
                self._active
                and epoch == self._epoch
                and fencing_token == self._fencing_token
            ):
                return self.snapshot()
            if (
                epoch <= self._high_water_epoch
                or fencing_token <= self._high_water_fencing_token
                or (epoch == self._high_water_epoch)
                or (fencing_token == self._high_water_fencing_token)
            ):
                raise WindowsRpcDurableFenceDenied(
                    "fence epoch/token is not strictly newer than high-water",
                    code="WINDOWS_FENCE_STALE_TOKEN",
                )
            if self._durable_store is not None:
                durable = self._durable_store.mutate(
                    lambda state: state.update(
                        {
                            "current_epoch": epoch,
                            "current_fencing_token": fencing_token,
                        }
                    )
                )
                self._epoch = int(durable["current_epoch"])
                self._fencing_token = int(durable["current_fencing_token"])
                self._high_water_epoch = self._epoch
                self._high_water_fencing_token = self._fencing_token
                self._active = True
                return self.snapshot()
            self._epoch = epoch
            self._fencing_token = fencing_token
            self._high_water_epoch = epoch
            self._high_water_fencing_token = fencing_token
            self._active = True
            return self.snapshot()

    def register_receipt(self, *, intent_id: str, receipt: Mapping[str, Any]) -> None:
        """Bind an externally issued receipt before accepting a mutation."""

        intent_id = _identifier(intent_id, "intent_id")
        if not isinstance(receipt, Mapping):
            raise WindowsRpcDurableFenceDenied(
                "receipt must be an object", code="WINDOWS_FENCE_RECEIPT_INVALID"
            )
        required = {
            "intent_id",
            "receipt_id",
            "receipt_hash",
            "request_hash",
            "account_scope",
            "environment",
            "leader_epoch",
            "fencing_token",
            "idempotency_key",
            "plan_id",
            "plan_hash",
            "action",
        }
        if set(receipt) != required:
            raise WindowsRpcDurableFenceDenied(
                "receipt fields are not exact", code="WINDOWS_FENCE_RECEIPT_INVALID"
            )
        item = copy.deepcopy(dict(receipt))
        if item["intent_id"] != intent_id:
            raise WindowsRpcDurableFenceDenied(
                "receipt intent binding mismatch", code="WINDOWS_FENCE_RECEIPT_INVALID"
            )
        _identifier(item["intent_id"], "intent_id")
        _identifier(item["receipt_id"], "receipt_id")
        _sha256(item["receipt_hash"], "receipt_hash")
        _sha256(item["request_hash"], "request_hash")
        if (
            not isinstance(item["idempotency_key"], str)
            or _IDEMPOTENCY_RE.fullmatch(item["idempotency_key"]) is None
        ):
            raise WindowsRpcDurableFenceDenied(
                "receipt idempotency key is invalid",
                code="WINDOWS_FENCE_RECEIPT_INVALID",
            )
        _identifier(item["plan_id"], "plan_id")
        _sha256(item["plan_hash"], "plan_hash")
        if item["action"] not in {"send", "cancel"}:
            raise WindowsRpcDurableFenceDenied(
                "receipt action is invalid", code="WINDOWS_FENCE_RECEIPT_INVALID"
            )
        if item["receipt_id"] != f"receipt-{intent_id}":
            raise WindowsRpcDurableFenceDenied(
                "receipt id is not bound to intent",
                code="WINDOWS_FENCE_RECEIPT_INVALID",
            )
        receipt_context = {
            "account_scope": item["account_scope"],
            "environment": item["environment"],
            "intent_id": item["intent_id"],
            "idempotency_key": item["idempotency_key"],
            "plan_id": item["plan_id"],
            "plan_hash": item["plan_hash"],
            "request_hash": item["request_hash"],
            "action": item["action"],
        }
        if item["receipt_hash"] != _receipt_digest(receipt_context):
            raise WindowsRpcDurableFenceDenied(
                "receipt hash binding mismatch",
                code="WINDOWS_FENCE_RECEIPT_INVALID",
            )
        with self._lock:
            self._refresh_durable()
            if not self._active:
                raise WindowsRpcDurableFenceDenied(
                    "an active fence is required before receipt registration",
                    code="WINDOWS_FENCE_STALE_TOKEN",
                )
            if (
                not isinstance(item["account_scope"], str)
                or not isinstance(item["environment"], str)
                or isinstance(item["leader_epoch"], bool)
                or not isinstance(item["leader_epoch"], int)
                or isinstance(item["fencing_token"], bool)
                or not isinstance(item["fencing_token"], int)
                or item["account_scope"] != self.account_scope
                or item["environment"] != self.environment
            ):
                raise WindowsRpcDurableFenceDenied(
                    "receipt scope is foreign", code="WINDOWS_FENCE_SCOPE_INVALID"
                )
            if (
                item["leader_epoch"] != self._epoch
                or item["fencing_token"] != self._fencing_token
            ):
                raise WindowsRpcDurableFenceDenied(
                    "receipt fence is stale", code="WINDOWS_FENCE_STALE_TOKEN"
                )
            existing = self._receipts.get(intent_id)
            if existing is not None:
                raise WindowsRpcDurableFenceDenied(
                    "receipt is create-only and already registered",
                    code="WINDOWS_FENCE_RECEIPT_CONFLICT",
                )
            existing_intent = self._idempotency.get(item["idempotency_key"])
            if existing_intent is not None and existing_intent != intent_id:
                raise WindowsRpcDurableFenceDenied(
                    "idempotency key is bound to another intent",
                    code="WINDOWS_FENCE_RECEIPT_CONFLICT",
                )
            if self._durable_store is not None:

                def persist(state: dict[str, Any]) -> None:
                    if intent_id in state["receipts"]:
                        raise WindowsRpcDurableFenceDenied(
                            "receipt is create-only and already registered",
                            code="WINDOWS_FENCE_RECEIPT_CONFLICT",
                        )
                    if item["idempotency_key"] in state["idempotency"]:
                        raise WindowsRpcDurableFenceDenied(
                            "idempotency key is already registered",
                            code="WINDOWS_FENCE_RECEIPT_CONFLICT",
                        )
                    state["receipts"][intent_id] = copy.deepcopy(item)
                    state["idempotency"][item["idempotency_key"]] = intent_id

                durable = self._durable_store.mutate(persist)
                self._receipts = copy.deepcopy(durable["receipts"])
                self._idempotency = copy.deepcopy(durable["idempotency"])
                return
            self._receipts[intent_id] = item
            self._idempotency[item["idempotency_key"]] = intent_id

    def install_fence_v1(
        self,
        request: Mapping[str, Any] | None = None,
        _context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Typed RPC wrapper for the monotonic fence installation lifecycle."""

        if not isinstance(request, Mapping) or set(request) != {
            "account_scope",
            "environment",
            "leader_epoch",
            "fencing_token",
        }:
            raise WindowsRpcDurableFenceDenied(
                "install fence request fields are not exact",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        if (
            request["account_scope"] != self.account_scope
            or request["environment"] != self.environment
        ):
            raise WindowsRpcDurableFenceDenied(
                "install fence scope is foreign", code="WINDOWS_FENCE_SCOPE_INVALID"
            )
        return self.install_fence(
            epoch=request["leader_epoch"], fencing_token=request["fencing_token"]
        )

    def register_receipt_v1(
        self,
        request: Mapping[str, Any] | None = None,
        _context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Typed RPC wrapper for create-only receipt registration."""

        if not isinstance(request, Mapping) or set(request) != {"intent_id", "receipt"}:
            raise WindowsRpcDurableFenceDenied(
                "register receipt request fields are not exact",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        intent_id = _identifier(request["intent_id"], "intent_id")
        self.register_receipt(intent_id=intent_id, receipt=request["receipt"])
        receipt = request["receipt"]
        return {
            "schema_version": SCHEMA_VERSION,
            "admission": "REGISTERED",
            "account_scope": self.account_scope,
            "environment": self.environment,
            "intent_id": intent_id,
            "receipt_id": receipt["receipt_id"],
            "leader_epoch": self.current_epoch,
            "fencing_token": self.current_fencing_token,
        }

    def send_order_fenced_v1(
        self, request: Mapping[str, Any], context: Mapping[str, Any] | Any
    ) -> Mapping[str, Any]:
        return self._admit("send", request, context)

    def cancel_order_fenced_v1(
        self, request: Mapping[str, Any], context: Mapping[str, Any] | Any
    ) -> Mapping[str, Any]:
        return self._admit("cancel", request, context)

    def _admit(
        self,
        operation: str,
        request: Mapping[str, Any],
        context: Mapping[str, Any] | Any,
    ) -> Mapping[str, Any]:
        with self._lock:
            self._refresh_durable()
            checked = self._validate(operation, request, context)
            handler = (
                self._send_handler if operation == "send" else self._cancel_handler
            )
            # The lock covers final validation and handler invocation.  A
            # concurrent fence rotation cannot make an old response look like
            # an acknowledgement.
            result = handler(dict(request), dict(checked))
            if not isinstance(result, Mapping):
                raise WindowsRpcDurableFenceError(
                    "typed handler returned a non-object",
                    code="WINDOWS_FENCE_RESPONSE_INVALID",
                )
            current = (self._epoch, self._fencing_token)
            if current != (checked["leader_epoch"], checked["fencing_token"]):
                raise WindowsRpcDurableFenceDenied(
                    "fence changed while handler was running",
                    code="WINDOWS_FENCE_STALE_RESPONSE",
                )
            return self._bind_response(operation, result, checked)

    def _validate(
        self,
        operation: str,
        request: Mapping[str, Any],
        context: Mapping[str, Any] | Any,
    ) -> dict[str, Any]:
        if operation not in {"send", "cancel"}:
            raise WindowsRpcDurableFenceError(
                "unsupported mutation operation", code="WINDOWS_FENCE_METHOD_INVALID"
            )
        if not isinstance(request, Mapping):
            raise WindowsRpcDurableFenceDenied(
                "order request must be an object", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        if hasattr(context, "as_dict"):
            context = context.as_dict()
        if not isinstance(context, Mapping):
            raise WindowsRpcDurableFenceDenied(
                "fence context must be an object", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        required = {
            "account_scope",
            "environment",
            "leader_epoch",
            "fencing_token",
            "plan_id",
            "plan_hash",
            "intent_id",
            "idempotency_key",
            "action",
            "receipt_id",
            "receipt_hash",
            "request_hash",
        }
        if set(context) != required:
            raise WindowsRpcDurableFenceDenied(
                "fence context fields are not exact",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        checked = dict(context)
        if (
            checked["account_scope"] != self.account_scope
            or checked["environment"] != self.environment
        ):
            raise WindowsRpcDurableFenceDenied(
                "fence context scope is foreign", code="WINDOWS_FENCE_SCOPE_INVALID"
            )
        if checked["action"] != operation:
            raise WindowsRpcDurableFenceDenied(
                "fence context action mismatch", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        if (
            isinstance(checked["leader_epoch"], bool)
            or isinstance(checked["fencing_token"], bool)
            or not isinstance(checked["leader_epoch"], int)
            or not isinstance(checked["fencing_token"], int)
            or checked["leader_epoch"] != self._epoch
            or checked["fencing_token"] != self._fencing_token
        ):
            raise WindowsRpcDurableFenceDenied(
                "fence token is missing, stale, or foreign",
                code="WINDOWS_FENCE_STALE_TOKEN",
            )
        _identifier(checked["plan_id"], "plan_id")
        _sha256(checked["plan_hash"], "plan_hash")
        _identifier(checked["intent_id"], "intent_id")
        if (
            not isinstance(checked["idempotency_key"], str)
            or _IDEMPOTENCY_RE.fullmatch(checked["idempotency_key"]) is None
        ):
            raise WindowsRpcDurableFenceDenied(
                "idempotency_key is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        _identifier(checked["receipt_id"], "receipt_id")
        _sha256(checked["receipt_hash"], "receipt_hash")
        _sha256(checked["request_hash"], "request_hash")
        if checked["request_hash"] != _request_digest(request):
            raise WindowsRpcDurableFenceDenied(
                "order request hash binding mismatch",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        receipt = self._receipts.get(checked["intent_id"])
        if receipt is None:
            raise WindowsRpcDurableFenceDenied(
                "receipt was not registered",
                code="WINDOWS_FENCE_RECEIPT_INVALID",
            )
        if any(checked[field] != receipt[field] for field in receipt):
            raise WindowsRpcDurableFenceDenied(
                "receipt binding mismatch", code="WINDOWS_FENCE_RECEIPT_INVALID"
            )
        return checked

    def query_intent_v1(
        self,
        request: Mapping[str, Any],
        context: Mapping[str, Any] | Any | None = None,
    ) -> Mapping[str, Any]:
        """Typed read-only query for a previously registered intent."""

        if not isinstance(request, Mapping) or set(request) != {
            "account_scope",
            "environment",
            "intent_id",
            "broker_order_id",
        }:
            raise WindowsRpcDurableFenceDenied(
                "query request fields are not exact",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        if (
            request["account_scope"] != self.account_scope
            or request["environment"] != self.environment
        ):
            raise WindowsRpcDurableFenceDenied(
                "query scope is foreign", code="WINDOWS_FENCE_SCOPE_INVALID"
            )
        intent_id = _identifier(request["intent_id"], "intent_id")
        with self._lock:
            self._refresh_durable()
            receipt = self._receipts.get(intent_id)
            if receipt is None:
                raise WindowsRpcDurableFenceDenied(
                    "query intent was not registered",
                    code="WINDOWS_FENCE_RECEIPT_INVALID",
                )
            checked_context: dict[str, Any] | None = None
            if context is not None:
                if hasattr(context, "as_dict"):
                    context = context.as_dict()
                if not isinstance(context, Mapping):
                    raise WindowsRpcDurableFenceDenied(
                        "query context must be an object",
                        code="WINDOWS_FENCE_REQUEST_INVALID",
                    )
                checked_context = dict(context)
                if checked_context.get("intent_id") != intent_id:
                    raise WindowsRpcDurableFenceDenied(
                        "query intent binding mismatch",
                        code="WINDOWS_FENCE_RECEIPT_INVALID",
                    )
                if any(
                    checked_context.get(field) != receipt[field] for field in receipt
                ):
                    raise WindowsRpcDurableFenceDenied(
                        "query receipt binding mismatch",
                        code="WINDOWS_FENCE_RECEIPT_INVALID",
                    )
            if self._query_handler is None:
                return {"intent_id": intent_id, "state": "UNKNOWN_OUTCOME"}
            result = self._query_handler(dict(request), checked_context)
            if not isinstance(result, Mapping):
                raise WindowsRpcDurableFenceError(
                    "typed query handler returned a non-object",
                    code="WINDOWS_FENCE_RESPONSE_INVALID",
                )
            return {"intent_id": intent_id, **dict(result)}

    @staticmethod
    def _bind_response(
        operation: str, result: Mapping[str, Any], context: Mapping[str, Any]
    ) -> dict[str, Any]:
        state = result.get("state")
        if not isinstance(state, str) or state.upper() in _UNKNOWN_STATES:
            raise WindowsRpcDurableFenceError(
                "typed handler returned an unknown outcome",
                code="WINDOWS_FENCE_UNKNOWN_OUTCOME",
            )
        if state.upper() not in _MUTATION_STATES:
            raise WindowsRpcDurableFenceError(
                "typed handler returned an unsupported state",
                code="WINDOWS_FENCE_RESPONSE_INVALID",
            )
        accepted = result.get("accepted")
        if accepted is not None and not isinstance(accepted, bool):
            raise WindowsRpcDurableFenceError(
                "typed handler returned an invalid accepted flag",
                code="WINDOWS_FENCE_RESPONSE_INVALID",
            )
        if state.upper() == "REJECTED" and accepted is True:
            raise WindowsRpcDurableFenceError(
                "rejected handler result cannot be accepted",
                code="WINDOWS_FENCE_RESPONSE_INVALID",
            )
        if accepted is False and state.upper() in {
            "SUBMITTED",
            "ACKNOWLEDGED",
            "CANCELLED",
            "RECONCILED",
        }:
            raise WindowsRpcDurableFenceError(
                "non-rejected handler result cannot be declined",
                code="WINDOWS_FENCE_RESPONSE_INVALID",
            )
        expected = {
            "account_scope": context["account_scope"],
            "environment": context["environment"],
            "leader_epoch": context["leader_epoch"],
            "fencing_token": context["fencing_token"],
            "intent_id": context["intent_id"],
            "receipt_id": context["receipt_id"],
            "receipt_hash": context["receipt_hash"],
            "request_hash": context["request_hash"],
            "plan_id": context["plan_id"],
            "plan_hash": context["plan_hash"],
            "idempotency_key": context["idempotency_key"],
            "operation": operation,
        }
        for field, value in expected.items():
            if field in result and result[field] != value:
                raise WindowsRpcDurableFenceError(
                    f"typed response {field} binding mismatch",
                    code="WINDOWS_FENCE_RESPONSE_INVALID",
                )
        return {**dict(result), **expected, "admission": "ACCEPTED"}


# Names used by integration code and acceptance tests while the frozen WF-1
# class remains unchanged.
WindowsRpcFinalAdmissionV2 = WindowsRpcFencedAdmissionV1
FinalFencedAdmissionV1 = WindowsRpcFencedAdmissionV1

__all__ = [
    "CANCEL_METHOD",
    "INSTALL_FENCE_METHOD",
    "QUERY_METHOD",
    "REGISTER_RECEIPT_METHOD",
    "SCHEMA_VERSION",
    "SEND_METHOD",
    "FinalFencedAdmissionV1",
    "WindowsRpcFencedAdmissionV1",
    "WindowsRpcFinalAdmissionV2",
]
