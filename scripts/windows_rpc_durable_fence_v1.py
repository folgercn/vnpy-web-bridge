"""Public WF-1 durable-fence API; importing it performs no runtime action."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any

from scripts.windows_fence_foundation.admission import (
    FrozenNoneProjection,
    FrozenNoneStoreRecovery,
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
    WindowsRpcFinalAdmissionV1,
)
from scripts.windows_fence_foundation.assembly import (
    WindowsRpcFrozenAssemblyV1,
    assemble_windows_rpc_frozen_v1,
    attach_windows_rpc_deployment_snapshot_v1,
)
from scripts.windows_fence_foundation.bootstrap_v1 import (
    bootstrap_windows_rpc_frozen_v1,
)
from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.store import (
    StoreExpectation,
    StoreRecovery,
    recover_frozen_none_store,
)
from scripts.windows_fence_foundation.win32_fs import WindowsFilesystemFactsAdapter

_RPC_ADDRESS_RE = re.compile(r"^tcp://(?:\*|127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$")
_ASSEMBLY_COMPONENTS = (
    "__init__.py",
    "admission.py",
    "assembly.py",
    "bootstrap_v1.py",
    "contracts.py",
    "store.py",
    "win32_fs.py",
)


@dataclass(frozen=True)
class WindowsRpcRuntimeConfigV1:
    """Credential-bearing config consumed only by the fixed Windows builder."""

    gateway_setting: Mapping[str, Any]
    gateway_name: str = "CTP"
    rep_address: str = "tcp://*:2014"
    pub_address: str = "tcp://*:4102"

    def __post_init__(self) -> None:
        setting = dict(self.gateway_setting)
        if not setting or any(not isinstance(key, str) for key in setting):
            raise ValueError("gateway_setting must be a non-empty string-key mapping")
        if any(
            value is not None and type(value) not in {str, bool, int}
            for value in setting.values()
        ):
            raise ValueError("gateway_setting values must be immutable JSON scalars")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", self.gateway_name):
            raise ValueError("gateway_name is invalid")
        for address in (self.rep_address, self.pub_address):
            if not _RPC_ADDRESS_RE.fullmatch(address):
                raise ValueError("RPC listener address is not an approved local bind")
            port = int(address.rsplit(":", 1)[1])
            if port > 65535:
                raise ValueError("RPC listener port is outside the valid range")
        if self.rep_address == self.pub_address:
            raise ValueError("RPC request and publish addresses must differ")
        canonical_json_bytes(setting)
        object.__setattr__(self, "gateway_setting", MappingProxyType(setting))

    def canonical_sha256(self) -> str:
        payload = {
            "schema_version": "windows_rpc_durable_fence_runtime_config_v1",
            "purpose": "build_fixed_frozen_windows_rpc_runtime",
            "gateway_name": self.gateway_name,
            "gateway_setting": dict(self.gateway_setting),
            "rep_address": self.rep_address,
            "pub_address": self.pub_address,
        }
        return sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class _WindowsRpcRuntimeV1:
    event_engine: Any
    main_engine: Any
    rpc_engine: Any
    fact_source: Any
    config: WindowsRpcRuntimeConfigV1


def _production_windows_filesystem() -> WindowsFilesystemFactsAdapter:
    if os.name != "nt":
        raise OSError("launch_windows_rpc_durable_fence_v1 requires native Windows")
    return WindowsFilesystemFactsAdapter()


def _recover_runtime_bound_store(
    root: Path,
    *,
    expected: StoreExpectation,
    fs: WindowsFilesystemFactsAdapter,
    runtime_config: WindowsRpcRuntimeConfigV1,
) -> StoreRecovery:
    recovery = recover_frozen_none_store(root, expected=expected, fs=fs)
    state = recovery.state
    if not recovery.ready or state is None:
        return recovery
    state_value = state if isinstance(state, Mapping) else state.value
    closure = _runtime_closure_hashes()
    if (
        state_value["config_sha256"] != runtime_config.canonical_sha256()
        or state_value["gateway_name"] != runtime_config.gateway_name
    ):
        return StoreRecovery(
            ready=False, reason="RUNTIME_CONFIG_STATE_BINDING_MISMATCH"
        )
    if any(state_value[field] != digest for field, digest in closure.items()):
        return StoreRecovery(
            ready=False, reason="RUNTIME_CLOSURE_STATE_BINDING_MISMATCH"
        )
    return recovery


def _runtime_closure_hashes() -> dict[str, str]:
    scripts_root = Path(__file__).resolve().parent
    foundation_root = scripts_root / "windows_fence_foundation"
    inventory = []
    for name in _ASSEMBLY_COMPONENTS:
        raw = (foundation_root / name).read_bytes()
        inventory.append(
            {
                "path": f"windows_fence_foundation/{name}",
                "sha256": sha256(raw).hexdigest(),
            }
        )
    return {
        "extension_sha256": sha256(
            (scripts_root / "windows_rpc_deployment_snapshot_v1.py").read_bytes()
        ).hexdigest(),
        "launcher_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "assembly_sha256": sha256(canonical_json_bytes(inventory)).hexdigest(),
    }


def _build_fixed_vnpy_runtime(
    config: WindowsRpcRuntimeConfigV1,
) -> _WindowsRpcRuntimeV1:
    # Lazy imports keep offline verification available on non-Windows hosts.
    from vnpy.event import EventEngine
    from vnpy.trader.engine import MainEngine
    from vnpy_ctp import CtpGateway
    from vnpy_rpcservice import RpcServiceApp

    event_engine = EventEngine()
    main_engine = MainEngine(event_engine)
    main_engine.add_gateway(CtpGateway)
    rpc_engine = main_engine.add_app(RpcServiceApp)
    return _WindowsRpcRuntimeV1(
        event_engine=event_engine,
        main_engine=main_engine,
        rpc_engine=rpc_engine,
        fact_source=main_engine,
        config=config,
    )


def _connect_fixed_vnpy_runtime(runtime: _WindowsRpcRuntimeV1) -> None:
    runtime.main_engine.connect(
        dict(runtime.config.gateway_setting), runtime.config.gateway_name
    )


def _listen_fixed_vnpy_runtime(runtime: _WindowsRpcRuntimeV1) -> bool:
    runtime.rpc_engine.start(
        runtime.config.rep_address,
        runtime.config.pub_address,
    )
    active = getattr(runtime.rpc_engine.server, "is_active", None)
    return bool(callable(active) and active())


def launch_windows_rpc_durable_fence_v1(
    *,
    store_root: str | Path,
    store_expectation: StoreExpectation,
    runtime_config: WindowsRpcRuntimeConfigV1,
) -> WindowsRpcFrozenAssemblyV1:
    """Launch through fixed recovery, vn.py construction, A2 and lifecycle code."""

    filesystem = _production_windows_filesystem()

    def recover_bound(
        root: Path, *, expected: StoreExpectation, fs: WindowsFilesystemFactsAdapter
    ) -> StoreRecovery:
        return _recover_runtime_bound_store(
            root,
            expected=expected,
            fs=fs,
            runtime_config=runtime_config,
        )

    return bootstrap_windows_rpc_frozen_v1(
        store_root=Path(store_root),
        store_expectation=store_expectation,
        recover_store=recover_bound,
        build_runtime=lambda: _build_fixed_vnpy_runtime(runtime_config),
        attach_snapshot=attach_windows_rpc_deployment_snapshot_v1,
        connect_runtime=_connect_fixed_vnpy_runtime,
        listen_runtime=_listen_fixed_vnpy_runtime,
        filesystem=filesystem,
    )


__all__ = [
    "FrozenNoneProjection",
    "FrozenNoneStoreRecovery",
    "StoreExpectation",
    "StoreRecovery",
    "WindowsRpcDurableFenceDenied",
    "WindowsRpcDurableFenceError",
    "WindowsRpcFinalAdmissionV1",
    "WindowsRpcFrozenAssemblyV1",
    "WindowsRpcRuntimeConfigV1",
    "assemble_windows_rpc_frozen_v1",
    "attach_windows_rpc_deployment_snapshot_v1",
    "bootstrap_windows_rpc_frozen_v1",
    "launch_windows_rpc_durable_fence_v1",
    "recover_frozen_none_store",
]
