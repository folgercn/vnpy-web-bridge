"""Fail-closed Windows RPC admission for the WF-1 foundation stage.

WF-1 intentionally has no activation transition.  A recovered store may only
describe ``FROZEN/NONE`` and both mutation handlers always reject before an
underlying gateway callable can be reached.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from scripts.windows_fence_foundation.contracts import AUTHORITY_FIELDS

STATE_SCHEMA_VERSION = "windows_rpc_durable_fence_state_v1"
SEND_HANDLER_IDENTITY = "vnpy.issue267.windows-fence.final-admission.send-order.v1"
CANCEL_HANDLER_IDENTITY = "vnpy.issue267.windows-fence.final-admission.cancel-order.v1"
_EMPTY_INVENTORIES = (
    "staged_token_inventory",
    "active_token_inventory",
    "grant_inventory",
)


class WindowsRpcDurableFenceError(RuntimeError):
    """The durable Windows fence cannot safely serve this operation."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class WindowsRpcDurableFenceDenied(WindowsRpcDurableFenceError):
    """A mutation was rejected by the final WF-1 admission handler."""


@runtime_checkable
class FrozenNoneStoreRecovery(Protocol):
    """Narrow result contract supplied by the durable-store implementation."""

    ready: bool
    state: Any
    raw_sha256: str | None
    inventory_sha256: str | None
    reason: str | None


@dataclass(frozen=True)
class FrozenNoneProjection:
    """Immutable, privacy-safe projection retained by runtime admission."""

    state_id: str
    store_id: str
    install_attempt_id: str
    fence_epoch: int
    state_raw_sha256: str
    inventory_sha256: str
    admission_state: str = "FROZEN"
    token_state: str = "NONE"


def _require_sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise WindowsRpcDurableFenceError(
            f"{field} is not one lowercase SHA-256",
            code="FROZEN_NONE_RECOVERY_INVALID",
        )
    return value


def _validate_frozen_none_recovery(
    recovery: FrozenNoneStoreRecovery,
) -> tuple[dict[str, Any], FrozenNoneProjection]:
    recovered_state = recovery.state
    if not isinstance(recovered_state, Mapping):
        recovered_state = getattr(recovered_state, "value", None)
    if recovery.ready is not True or not isinstance(recovered_state, Mapping):
        reason = recovery.reason if isinstance(recovery.reason, str) else "unavailable"
        raise WindowsRpcDurableFenceError(
            f"durable FROZEN_NONE store is not ready: {reason}",
            code="FROZEN_NONE_STORE_NOT_READY",
        )
    state = copy.deepcopy(dict(recovered_state))
    if (
        state.get("schema_version") != STATE_SCHEMA_VERSION
        or state.get("admission_state") != "FROZEN"
        or state.get("token_state") != "NONE"
        or state.get("staged_token") is not None
        or state.get("active_token") is not None
        or state.get("authority_grant") is not None
        or state.get("pending_send_outcomes") != 0
        or state.get("active_orders") != []
        or any(state.get(field) != [] for field in _EMPTY_INVENTORIES)
    ):
        raise WindowsRpcDurableFenceError(
            "durable store is not exact foundation FROZEN_NONE",
            code="FROZEN_NONE_STATE_INVALID",
        )
    authority = state.get("authority")
    if (
        not isinstance(authority, Mapping)
        or set(authority) != AUTHORITY_FIELDS
        or any(authority[field] is not False for field in AUTHORITY_FIELDS)
    ):
        raise WindowsRpcDurableFenceError(
            "durable store contains runtime authority",
            code="FROZEN_NONE_AUTHORITY_PRESENT",
        )
    fence_epoch = state.get("fence_epoch")
    if (
        isinstance(fence_epoch, bool)
        or not isinstance(fence_epoch, int)
        or fence_epoch != 1
    ):
        raise WindowsRpcDurableFenceError(
            "durable store fence epoch is invalid",
            code="FROZEN_NONE_STATE_INVALID",
        )
    state_raw_sha256 = _require_sha256(recovery.raw_sha256, "state raw digest")
    inventory_sha256 = _require_sha256(
        recovery.inventory_sha256, "store inventory digest"
    )
    identity_fields = ("state_id", "store_id", "install_attempt_id")
    if any(
        not isinstance(state.get(field), str) or not state[field]
        for field in identity_fields
    ):
        raise WindowsRpcDurableFenceError(
            "durable store identity is incomplete",
            code="FROZEN_NONE_STATE_INVALID",
        )
    return state, FrozenNoneProjection(
        state_id=state["state_id"],
        store_id=state["store_id"],
        install_attempt_id=state["install_attempt_id"],
        fence_epoch=fence_epoch,
        state_raw_sha256=state_raw_sha256,
        inventory_sha256=inventory_sha256,
    )


class WindowsRpcFinalAdmissionV1:
    """The single runtime admission authority for WF-1.

    The class deliberately retains no underlying send/cancel callable.  Future
    STAGED/ACTIVE behavior must arrive in a later, separately reviewed stage.
    """

    def __init__(self, recovery: FrozenNoneStoreRecovery) -> None:
        state, projection = _validate_frozen_none_recovery(recovery)
        self._condition = threading.Condition(threading.RLock())
        self._state = state
        self._projection = projection
        self._denied = {"send_order": 0, "cancel_order": 0}

    @property
    def condition(self) -> threading.Condition:
        """Shared condition used by A2 integration and future state transitions."""

        return self._condition

    @property
    def projection(self) -> FrozenNoneProjection:
        return self._projection

    def frozen_snapshot(self) -> dict[str, Any]:
        with self._condition:
            return {
                "schema_version": self._state["schema_version"],
                "state_id": self._projection.state_id,
                "store_id": self._projection.store_id,
                "install_attempt_id": self._projection.install_attempt_id,
                "fence_epoch": self._projection.fence_epoch,
                "admission_state": "FROZEN",
                "token_state": "NONE",
                "staged_token_inventory": [],
                "active_token_inventory": [],
                "grant_inventory": [],
                "state_raw_sha256": self._projection.state_raw_sha256,
                "inventory_sha256": self._projection.inventory_sha256,
                "handler_identities": {
                    "send_order": SEND_HANDLER_IDENTITY,
                    "cancel_order": CANCEL_HANDLER_IDENTITY,
                },
                "denied_calls": dict(self._denied),
            }

    def _deny(self, operation: str) -> None:
        with self._condition:
            self._denied[operation] += 1
        raise WindowsRpcDurableFenceDenied(
            f"{operation} rejected by durable FROZEN_NONE admission",
            code="WINDOWS_FENCE_ACTIVE_TOKEN_REQUIRED",
        )

    def send_order(self, *_args: Any, **_kwargs: Any) -> None:
        self._deny("send_order")

    def cancel_order(self, *_args: Any, **_kwargs: Any) -> None:
        self._deny("cancel_order")


__all__ = [
    "CANCEL_HANDLER_IDENTITY",
    "SEND_HANDLER_IDENTITY",
    "STATE_SCHEMA_VERSION",
    "FrozenNoneProjection",
    "FrozenNoneStoreRecovery",
    "WindowsRpcDurableFenceDenied",
    "WindowsRpcDurableFenceError",
    "WindowsRpcFinalAdmissionV1",
]
