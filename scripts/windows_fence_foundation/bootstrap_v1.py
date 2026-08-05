"""Protected sequencing boundary for the WF-1 Windows RPC runtime.

This module performs no installation, service control, restart, token staging,
activation, or authority restoration.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from scripts.windows_fence_foundation.admission import FrozenNoneStoreRecovery
from scripts.windows_fence_foundation.assembly import (
    SnapshotAttacher,
    TypedAdmissionAttacher,
    WindowsRpcFrozenAssemblyV1,
    assemble_windows_rpc_frozen_v1,
    attach_windows_rpc_deployment_snapshot_v1,
)


class StoreRecoverer(Protocol):
    def __call__(
        self, root: Any, expected: Any, fs: Any | None = None
    ) -> FrozenNoneStoreRecovery: ...


def bootstrap_windows_rpc_frozen_v1(
    *,
    store_root: Any,
    store_expectation: Any,
    recover_store: StoreRecoverer,
    build_runtime: Callable[[], Any],
    attach_snapshot: SnapshotAttacher = attach_windows_rpc_deployment_snapshot_v1,
    attach_typed: TypedAdmissionAttacher | None = None,
    connect_runtime: Callable[[Any], Any],
    listen_runtime: Callable[[Any], Any],
    filesystem: Any | None = None,
) -> WindowsRpcFrozenAssemblyV1:
    """Recover, assemble, connect and listen in the only safe WF-1 order."""

    recovery = recover_store(
        store_root,
        expected=store_expectation,
        fs=filesystem,
    )
    # Construction validates ready/state/digests before build_runtime can create
    # MainEngine, a gateway, an EventEngine thread, or an RPC server.
    assembly = assemble_windows_rpc_frozen_v1(
        recovery=recovery,
        build_runtime=build_runtime,
        attach_snapshot=attach_snapshot,
        attach_typed=attach_typed,
    )
    assembly.assert_ready_to_listen()
    assembly.assert_not_listening()
    connect_runtime(assembly.runtime)
    assembly.assert_ready_to_listen()
    assembly.assert_not_listening()
    started = listen_runtime(assembly.runtime)
    if started is False:
        raise RuntimeError("frozen RPC listener failed to start")
    assembly.assert_ready_to_listen()
    return assembly


def main() -> None:
    raise SystemExit(
        "WF-1 bootstrap requires the pinned runtime assembler and protected "
        "credential-config loader; it never installs or restarts a service"
    )


if __name__ == "__main__":
    main()


__all__ = ["StoreRecoverer", "bootstrap_windows_rpc_frozen_v1"]
