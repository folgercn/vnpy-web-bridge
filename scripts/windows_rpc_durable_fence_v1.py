"""WF-1 durable-fence API and hash-pinned installed service entry."""

from __future__ import annotations

import importlib.abc
import importlib.util
import io
import json
import os
import re
import sys
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any

_FOUNDATION_ARCHIVE_NAME = "windows_fence_foundation_v1.pyz"
_FOUNDATION_ARCHIVE_PATH = Path(__file__).resolve().with_name(_FOUNDATION_ARCHIVE_NAME)
_VERIFIED_FOUNDATION_ARCHIVE_RAW: bytes | None = None


def _required_unique_argument(arguments: list[str], name: str) -> str:
    positions = [index for index, item in enumerate(arguments) if item == name]
    if len(positions) != 1 or positions[0] + 1 >= len(arguments):
        raise RuntimeError(f"{name.removeprefix('--').upper()}_ARGUMENT_INVALID")
    value = arguments[positions[0] + 1]
    if not value or value.startswith("--"):
        raise RuntimeError(f"{name.removeprefix('--').upper()}_ARGUMENT_INVALID")
    return value


class _VerifiedAssemblyImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Load modules only from already hash-verified in-memory archive bytes."""

    def __init__(self, raw: bytes) -> None:
        sources: dict[str, tuple[bytes, bool, str]] = {}
        with zipfile.ZipFile(io.BytesIO(raw), mode="r") as archive:
            for info in archive.infolist():
                if not info.filename.endswith(".py"):
                    continue
                parts = info.filename[:-3].split("/")
                is_package = parts[-1] == "__init__"
                if is_package:
                    parts.pop()
                module_name = ".".join(parts)
                if not module_name or module_name in sources:
                    raise RuntimeError("FOUNDATION_ASSEMBLY_MODULE_INVENTORY_INVALID")
                sources[module_name] = (
                    archive.read(info),
                    is_package,
                    f"<verified-foundation-assembly>/{info.filename}",
                )
        if "scripts.windows_fence_foundation" not in sources:
            raise RuntimeError("FOUNDATION_ASSEMBLY_MODULE_INVENTORY_INVALID")
        self._sources = sources

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        source = self._sources.get(fullname)
        if source is None:
            return None
        return importlib.util.spec_from_loader(fullname, self, is_package=source[1])

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> None:
        return None

    def exec_module(self, module: Any) -> None:
        source, is_package, filename = self._sources[module.__name__]
        module.__file__ = filename
        if is_package:
            module.__path__ = [filename.rsplit("/", 1)[0]]
        # The source bytes are the hash-pinned archive held in memory above.
        exec(compile(source, filename, "exec"), module.__dict__)  # noqa: S102


if _FOUNDATION_ARCHIVE_PATH.is_file():
    _archive_argument = Path(
        _required_unique_argument(sys.argv[1:], "--assembly")
    ).resolve()
    _archive_sha256 = _required_unique_argument(sys.argv[1:], "--assembly-sha256")
    _archive_raw = _FOUNDATION_ARCHIVE_PATH.read_bytes()
    if (
        _archive_argument != _FOUNDATION_ARCHIVE_PATH
        or re.fullmatch(r"[0-9a-f]{64}", _archive_sha256) is None
        or sha256(_archive_raw).hexdigest() != _archive_sha256
    ):
        raise RuntimeError("FOUNDATION_ASSEMBLY_PREIMPORT_BINDING_MISMATCH")
    _VERIFIED_FOUNDATION_ARCHIVE_RAW = _archive_raw
    sys.meta_path.insert(0, _VerifiedAssemblyImporter(_archive_raw))

# These imports must remain after the installed-layout archive verification above.
from scripts.windows_fence_foundation.admission import (  # noqa: E402
    FrozenNoneProjection,
    FrozenNoneStoreRecovery,
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
    WindowsRpcFinalAdmissionV1,
)
from scripts.windows_fence_foundation.assembly import (  # noqa: E402
    WindowsRpcFrozenAssemblyV1,
    assemble_windows_rpc_frozen_v1,
    attach_windows_rpc_deployment_snapshot_v1,
)
from scripts.windows_fence_foundation.bootstrap_v1 import (  # noqa: E402
    bootstrap_windows_rpc_frozen_v1,
)
from scripts.windows_fence_foundation.contracts import (  # noqa: E402
    StoreContractError,
    canonical_json_bytes,
    canonical_local_windows_path,
)
from scripts.windows_fence_foundation.store import (  # noqa: E402
    StoreExpectation,
    StoreRecovery,
    recover_frozen_none_store,
)
from scripts.windows_fence_foundation.win32_fs import (  # noqa: E402
    WindowsFilesystemFactsAdapter,
)

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
class _InstalledWindowsRpcServiceConfigV1:
    store_root: str
    store_expectation: StoreExpectation
    runtime_config: WindowsRpcRuntimeConfigV1
    raw_sha256: str


def _parse_installed_service_config_v1(
    raw: bytes,
) -> _InstalledWindowsRpcServiceConfigV1:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("SERVICE_CONFIG_JSON_DUPLICATE_KEY")
            value[key] = item
        return value

    def reject_number(_: str) -> None:
        raise ValueError("SERVICE_CONFIG_NUMBER_INVALID")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
        if canonical_json_bytes(value) != raw:
            raise ValueError("SERVICE_CONFIG_RAW_NOT_CANONICAL")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("SERVICE_CONFIG_JSON_INVALID") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "purpose",
        "store_root",
        "store_expectation",
        "runtime_config",
    }:
        raise ValueError("SERVICE_CONFIG_FIELDS_INVALID")
    if (
        value["schema_version"] != "windows_rpc_durable_fence_service_config_v1"
        or value["purpose"] != "launch_fixed_frozen_windows_rpc_service"
    ):
        raise ValueError("SERVICE_CONFIG_CONSTANT_INVALID")
    store_root = value["store_root"]
    try:
        canonical_store_root = canonical_local_windows_path(store_root)
    except StoreContractError as exc:
        raise ValueError("SERVICE_CONFIG_STORE_ROOT_INVALID") from exc
    if canonical_store_root != store_root:
        raise ValueError("SERVICE_CONFIG_STORE_ROOT_INVALID")
    expectation = value["store_expectation"]
    expectation_fields = {
        "service_name",
        "store_id",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "owner_sid_sha256",
        "directory_acl_sddl_sha256",
        "state_acl_sddl_sha256",
    }
    if not isinstance(expectation, dict) or set(expectation) != expectation_fields:
        raise ValueError("SERVICE_CONFIG_STORE_EXPECTATION_INVALID")
    hashes = (
        "store_path_sha256",
        "store_volume_identity_sha256",
        "owner_sid_sha256",
        "directory_acl_sddl_sha256",
        "state_acl_sddl_sha256",
    )
    if (
        any(
            not isinstance(expectation[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", expectation[field]) is None
            for field in hashes
        )
        or not isinstance(expectation["service_name"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", expectation["service_name"])
        is None
        or not isinstance(expectation["store_id"], str)
        or re.fullmatch(r"windows-fence-store-[0-9a-f]{64}", expectation["store_id"])
        is None
        or not isinstance(expectation["store_volume_serial"], str)
        or re.fullmatch(r"[A-F0-9]{8,32}", expectation["store_volume_serial"]) is None
        or expectation["store_path_sha256"]
        != sha256(store_root.encode("utf-8")).hexdigest()
    ):
        raise ValueError("SERVICE_CONFIG_STORE_EXPECTATION_INVALID")
    runtime = value["runtime_config"]
    if not isinstance(runtime, dict) or set(runtime) != {
        "gateway_name",
        "gateway_setting",
        "rep_address",
        "pub_address",
    }:
        raise ValueError("SERVICE_CONFIG_RUNTIME_FIELDS_INVALID")
    return _InstalledWindowsRpcServiceConfigV1(
        store_root=store_root,
        store_expectation=StoreExpectation(**expectation),
        runtime_config=WindowsRpcRuntimeConfigV1(**runtime),
        raw_sha256=sha256(raw).hexdigest(),
    )


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
    config_binding_sha256: str,
) -> StoreRecovery:
    recovery = recover_frozen_none_store(root, expected=expected, fs=fs)
    state = recovery.state
    if not recovery.ready or state is None:
        return recovery
    state_value = state if isinstance(state, Mapping) else state.value
    closure = _runtime_closure_hashes()
    if (
        state_value["config_sha256"] != config_binding_sha256
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
    foundation_archive = scripts_root / _FOUNDATION_ARCHIVE_NAME
    if _VERIFIED_FOUNDATION_ARCHIVE_RAW is not None:
        assembly_sha256 = sha256(_VERIFIED_FOUNDATION_ARCHIVE_RAW).hexdigest()
    elif foundation_archive.is_file():
        raise RuntimeError("FOUNDATION_ASSEMBLY_NOT_PREIMPORT_VERIFIED")
    else:
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
        assembly_sha256 = sha256(canonical_json_bytes(inventory)).hexdigest()
    return {
        "extension_sha256": sha256(
            (scripts_root / "windows_rpc_deployment_snapshot_v1.py").read_bytes()
        ).hexdigest(),
        "launcher_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "assembly_sha256": assembly_sha256,
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


def _launch_windows_rpc_durable_fence_bound_v1(
    *,
    store_root: str | Path,
    store_expectation: StoreExpectation,
    runtime_config: WindowsRpcRuntimeConfigV1,
    config_binding_sha256: str,
) -> WindowsRpcFrozenAssemblyV1:
    filesystem = _production_windows_filesystem()

    def recover_bound(
        root: Path, *, expected: StoreExpectation, fs: WindowsFilesystemFactsAdapter
    ) -> StoreRecovery:
        return _recover_runtime_bound_store(
            root,
            expected=expected,
            fs=fs,
            runtime_config=runtime_config,
            config_binding_sha256=config_binding_sha256,
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


def launch_windows_rpc_durable_fence_v1(
    *,
    store_root: str | Path,
    store_expectation: StoreExpectation,
    runtime_config: WindowsRpcRuntimeConfigV1,
) -> WindowsRpcFrozenAssemblyV1:
    """Launch through fixed recovery, vn.py construction, A2 and lifecycle code."""

    return _launch_windows_rpc_durable_fence_bound_v1(
        store_root=store_root,
        store_expectation=store_expectation,
        runtime_config=runtime_config,
        config_binding_sha256=runtime_config.canonical_sha256(),
    )


def _validated_adjacent_component(
    arguments: list[str],
    *,
    path_flag: str,
    sha_flag: str,
    expected_name: str,
) -> tuple[Path, str, bytes]:
    path = Path(_required_unique_argument(arguments, path_flag)).resolve()
    expected_path = Path(__file__).resolve().with_name(expected_name)
    expected_sha256 = _required_unique_argument(arguments, sha_flag)
    raw = path.read_bytes() if path.is_file() else b""
    if (
        path != expected_path
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or not raw
        or sha256(raw).hexdigest() != expected_sha256
    ):
        raise RuntimeError(f"{path_flag.removeprefix('--').upper()}_BINDING_MISMATCH")
    return path, expected_sha256, raw


def _main(arguments: list[str]) -> None:
    expected_flags = [
        "--extension",
        "--extension-sha256",
        "--assembly",
        "--assembly-sha256",
        "--config",
        "--config-sha256",
    ]
    if len(arguments) != len(expected_flags) * 2 or arguments[::2] != expected_flags:
        raise RuntimeError("INSTALLED_LAUNCHER_ARGUMENTS_INVALID")
    _validated_adjacent_component(
        arguments,
        path_flag="--extension",
        sha_flag="--extension-sha256",
        expected_name="windows_rpc_deployment_snapshot_v1.py",
    )
    _validated_adjacent_component(
        arguments,
        path_flag="--assembly",
        sha_flag="--assembly-sha256",
        expected_name=_FOUNDATION_ARCHIVE_NAME,
    )
    _, config_sha256, config_raw = _validated_adjacent_component(
        arguments,
        path_flag="--config",
        sha_flag="--config-sha256",
        expected_name="windows_rpc_service_config_v1.json",
    )
    service_config = _parse_installed_service_config_v1(config_raw)
    if service_config.raw_sha256 != config_sha256:
        raise RuntimeError("CONFIG_BINDING_MISMATCH")
    _launch_windows_rpc_durable_fence_bound_v1(
        store_root=service_config.store_root,
        store_expectation=service_config.store_expectation,
        runtime_config=service_config.runtime_config,
        config_binding_sha256=service_config.raw_sha256,
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


if __name__ == "__main__":
    _main(sys.argv[1:])
