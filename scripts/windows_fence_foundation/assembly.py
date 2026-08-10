"""Atomic in-process assembly for the WF-1 frozen Windows RPC runtime."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from scripts.windows_fence_foundation.admission import (
    FrozenNoneStoreRecovery,
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
    WindowsRpcFinalAdmissionV1,
)
from scripts.windows_fence_foundation.final_admission_v1 import (
    CANCEL_METHOD,
    INSTALL_FENCE_METHOD,
    QUERY_METHOD,
    REGISTER_RECEIPT_METHOD,
    SEND_METHOD,
)

_PROTECTED_MUTATIONS = frozenset({"send_order", "cancel_order"})
_FORBIDDEN_FOUNDATION_RPC = frozenset(
    {
        "activate_fence_token",
        "activate_token",
        "release_deployment_snapshot_v1",
        "stage_fence_token",
        "stage_token",
        "unfreeze",
    }
)
_A2_RPC_NAMES = frozenset(
    {
        "get_deployment_safety_snapshot_v1",
        "recheck_deployment_safety_snapshot_v1",
    }
)
_TYPED_RPC_NAMES = frozenset(
    {
        INSTALL_FENCE_METHOD,
        REGISTER_RECEIPT_METHOD,
        SEND_METHOD,
        CANCEL_METHOD,
        QUERY_METHOD,
        "get_execution_snapshot_v1",
        "peek_current_facts_v1",
    }
)


def attach_windows_rpc_fenced_methods_v1(server: Any, admission: Any) -> None:
    """Attach the separately named final typed execution lifecycle methods.

    The WF-1 ``assemble_windows_rpc_frozen_v1`` path intentionally remains
    denial-only.  Active runtimes must call this explicit hook with a
    ``WindowsRpcFencedAdmissionV1`` instance; legacy method names are never
    replaced here.
    """

    from scripts.windows_fence_foundation.final_admission_v1 import (
        CANCEL_METHOD,
        INSTALL_FENCE_METHOD,
        QUERY_METHOD,
        REGISTER_RECEIPT_METHOD,
        SEND_METHOD,
        WindowsRpcFencedAdmissionV1,
    )

    if not isinstance(admission, WindowsRpcFencedAdmissionV1):
        raise WindowsRpcDurableFenceError(
            "typed final admission object is required",
            code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
        )
    if not callable(getattr(server, "register", None)):
        raise WindowsRpcDurableFenceError(
            "RPC server registry is unavailable", code="RPC_REGISTRY_UNAVAILABLE"
        )
    active = getattr(server, "is_active", None)
    if callable(active) and active():
        raise WindowsRpcDurableFenceError(
            "typed final handlers must attach before listen",
            code="RPC_LISTENER_STARTED_EARLY",
        )
    handlers = {
        INSTALL_FENCE_METHOD: admission.install_fence_v1,
        REGISTER_RECEIPT_METHOD: admission.register_receipt_v1,
        SEND_METHOD: admission.send_order_fenced_v1,
        CANCEL_METHOD: admission.cancel_order_fenced_v1,
        QUERY_METHOD: admission.query_intent_v1,
    }
    for handler in handlers.values():
        server.register(handler)
    functions = getattr(server, "_functions", {})
    if any(functions.get(name) is not handler for name, handler in handlers.items()):
        raise WindowsRpcDurableFenceError(
            "typed final handler identity mismatch",
            code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
        )


class RuntimeBuilder(Protocol):
    def __call__(self) -> Any: ...


class SnapshotAttacher(Protocol):
    def __call__(self, runtime: Any, admission: WindowsRpcFinalAdmissionV1) -> Any: ...


class TypedAdmissionAttacher(Protocol):
    def __call__(self, runtime: Any) -> Any: ...


class _SealedRpcRegistry(Mapping[str, Any]):
    """Immutable RPC lookup table without a writable ``dict`` escape hatch."""

    def __init__(self, source: Mapping[str, Any], protected: Mapping[str, Any]) -> None:
        self._functions = MappingProxyType(dict(source))
        self._protected = dict(protected)

    def __getitem__(self, key: str) -> Any:
        return self._functions[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._functions)

    def __len__(self) -> int:
        return len(self._functions)

    def __setitem__(self, key: str, _value: Any) -> None:
        raise WindowsRpcDurableFenceError(
            f"RPC registry is sealed: {key}",
            code="FINAL_RPC_REGISTRY_SEALED",
        )

    def __delitem__(self, key: str) -> None:
        raise WindowsRpcDurableFenceError(
            f"RPC registry is sealed: {key}",
            code="FINAL_RPC_REGISTRY_SEALED",
        )

    def verify(self) -> None:
        if any(
            self._functions.get(name) is not handler
            for name, handler in self._protected.items()
        ):
            raise WindowsRpcDurableFenceError(
                "final RPC handler identity changed after seal",
                code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
            )


@dataclass(frozen=True)
class WindowsRpcFrozenAssemblyV1:
    runtime: Any
    admission: WindowsRpcFinalAdmissionV1
    snapshot_extension: Any
    server: Any
    registry: _SealedRpcRegistry
    typed_admission: Any | None = None

    def assert_not_listening(self) -> None:
        active = getattr(self.server, "is_active", None)
        if callable(active) and active():
            raise WindowsRpcDurableFenceError(
                "RPC listener started before the protected listen transition",
                code="RPC_LISTENER_STARTED_EARLY",
            )

    def assert_ready_to_listen(self) -> None:
        if getattr(self.server, "_functions", None) is not self.registry:
            raise WindowsRpcDurableFenceError(
                "RPC registry object changed after seal",
                code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
            )
        self.registry.verify()


def attach_windows_rpc_deployment_snapshot_v1(
    runtime: Any, admission: WindowsRpcFinalAdmissionV1
) -> Any:
    """Attach the reviewed A2 extension over the already-denying handlers."""

    from scripts.windows_rpc_deployment_snapshot_v1 import (
        RECHECK_RPC_CALLABLE_NAME,
        RPC_CALLABLE_NAME,
        register_windows_rpc_deployment_snapshot_v1,
    )

    rpc_engine = getattr(runtime, "rpc_engine", None)
    event_engine = getattr(runtime, "event_engine", None)
    fact_source = getattr(runtime, "fact_source", None)
    server = getattr(rpc_engine, "server", None)
    functions = getattr(server, "_functions", None)
    if (
        not isinstance(functions, dict)
        or getattr(functions.get("send_order"), "__self__", None) is not admission
        or getattr(functions.get("cancel_order"), "__self__", None) is not admission
    ):
        raise WindowsRpcDurableFenceError(
            "A2 must attach over the exact durable admission handlers",
            code="A2_ADMISSION_BINDING_MISMATCH",
        )
    kwargs = getattr(runtime, "snapshot_kwargs", None)
    if kwargs is None:
        kwargs = {}
    if not isinstance(kwargs, Mapping):
        raise WindowsRpcDurableFenceError(
            "A2 snapshot kwargs are invalid",
            code="A2_SNAPSHOT_NOT_ATTACHED",
        )
    if "durable_admission" in kwargs:
        raise WindowsRpcDurableFenceError(
            "A2 durable admission cannot be overridden by runtime kwargs",
            code="A2_ADMISSION_BINDING_MISMATCH",
        )
    extension = register_windows_rpc_deployment_snapshot_v1(
        rpc_engine,
        event_engine,
        fact_source,
        durable_admission=admission,
        **dict(kwargs),
    )
    functions = server._functions
    if (
        functions.get(RPC_CALLABLE_NAME) is not extension.rpc_callable
        or functions.get(RECHECK_RPC_CALLABLE_NAME)
        is not extension.recheck_rpc_callable
    ):
        raise WindowsRpcDurableFenceError(
            "A2 exact snapshot RPC identities are missing",
            code="A2_SNAPSHOT_NOT_ATTACHED",
        )
    return extension


def _server_for(runtime: Any) -> Any:
    rpc_engine = getattr(runtime, "rpc_engine", runtime)
    server = getattr(rpc_engine, "server", None)
    functions = getattr(server, "_functions", None)
    if not isinstance(functions, dict) or not callable(
        getattr(server, "register", None)
    ):
        raise WindowsRpcDurableFenceError(
            "RPC server registry is unavailable",
            code="RPC_REGISTRY_UNAVAILABLE",
        )
    active = getattr(server, "is_active", None)
    if callable(active) and active():
        raise WindowsRpcDurableFenceError(
            "RPC server was already listening before durable assembly",
            code="RPC_LISTENER_STARTED_EARLY",
        )
    return server


def _register_final_denials(server: Any, admission: WindowsRpcFinalAdmissionV1) -> None:
    functions = server._functions
    if not all(callable(functions.get(name)) for name in _PROTECTED_MUTATIONS):
        raise WindowsRpcDurableFenceError(
            "original mutation RPC handlers are unavailable",
            code="RPC_MUTATION_HANDLERS_MISSING",
        )
    server.register(admission.send_order)
    server.register(admission.cancel_order)


def _probe_final_denials(functions: Mapping[str, Any]) -> None:
    for name in sorted(_PROTECTED_MUTATIONS):
        handler = functions.get(name)
        if not callable(handler):
            raise WindowsRpcDurableFenceError(
                f"final {name} handler is unavailable",
                code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
            )
        try:
            handler(object(), "WF1-NONFORWARDING-PROBE")
        except WindowsRpcDurableFenceDenied:
            continue
        except BaseException as exc:
            raise WindowsRpcDurableFenceError(
                f"final {name} handler did not reach durable admission",
                code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
            ) from exc
        raise WindowsRpcDurableFenceError(
            f"final {name} handler unexpectedly returned",
            code="FINAL_RPC_HANDLER_FORWARDED",
        )


def assemble_windows_rpc_frozen_v1(
    *,
    recovery: FrozenNoneStoreRecovery,
    build_runtime: RuntimeBuilder,
    attach_snapshot: SnapshotAttacher,
    attach_typed: TypedAdmissionAttacher | None = None,
) -> WindowsRpcFrozenAssemblyV1:
    """Build and seal one frozen runtime without connecting or listening."""

    admission = WindowsRpcFinalAdmissionV1(recovery)
    runtime = build_runtime()
    server = _server_for(runtime)
    typed_admission = attach_typed(runtime) if attach_typed is not None else None
    _register_final_denials(server, admission)
    snapshot_extension = attach_snapshot(runtime, admission)
    if snapshot_extension is None:
        raise WindowsRpcDurableFenceError(
            "A2 snapshot extension was not attached",
            code="A2_SNAPSHOT_NOT_ATTACHED",
        )
    functions = server._functions
    expected_a2 = {
        "get_deployment_safety_snapshot_v1": getattr(
            snapshot_extension, "rpc_callable", None
        ),
        "recheck_deployment_safety_snapshot_v1": getattr(
            snapshot_extension, "recheck_rpc_callable", None
        ),
    }
    if any(
        not callable(handler) or functions.get(name) is not handler
        for name, handler in expected_a2.items()
    ):
        raise WindowsRpcDurableFenceError(
            "A2 exact snapshot/recheck RPC identities are missing",
            code="A2_SNAPSHOT_NOT_ATTACHED",
        )
    # A2 retains mutation wrappers for its standalone legacy contract.  They
    # must never remain the final WF-1 registry boundary because their mutable
    # downstream references would create a post-assembly bypass.  Capture is
    # already attached, so replace both final mutations with the admission
    # object that deliberately retains no underlying gateway callable.
    _register_final_denials(server, admission)
    functions = server._functions
    forbidden = sorted(_FORBIDDEN_FOUNDATION_RPC & set(functions))
    if forbidden:
        raise WindowsRpcDurableFenceError(
            f"foundation runtime exposes forbidden RPC: {','.join(forbidden)}",
            code="FOUNDATION_AUTHORITY_RPC_EXPOSED",
        )
    _probe_final_denials(functions)
    protected_names = _PROTECTED_MUTATIONS | (_TYPED_RPC_NAMES & set(functions))
    protected = {name: functions[name] for name in protected_names}
    registry = _SealedRpcRegistry(functions, protected)
    # RpcServer implementations and tests sometimes retain a public alias such
    # as ``registered``.  Replace every exact old-registry alias before the old
    # mapping can remain as a callable bypass.
    for attribute, value in tuple(vars(server).items()):
        if value is functions:
            setattr(server, attribute, registry)
    server._functions = registry
    assembly = WindowsRpcFrozenAssemblyV1(
        runtime=runtime,
        admission=admission,
        snapshot_extension=snapshot_extension,
        server=server,
        registry=registry,
        typed_admission=typed_admission,
    )
    assembly.assert_ready_to_listen()
    return assembly


__all__ = [
    "SnapshotAttacher",
    "TypedAdmissionAttacher",
    "WindowsRpcFrozenAssemblyV1",
    "assemble_windows_rpc_frozen_v1",
    "attach_windows_rpc_deployment_snapshot_v1",
    "attach_windows_rpc_fenced_methods_v1",
]
