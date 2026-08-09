"""WF-1 durable-fence API and hash-pinned installed service entry."""

from __future__ import annotations

import importlib.abc
import importlib.util
import io
import json
import math
import os
import re
import sys
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any, ClassVar

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


# Resolve foundation modules only after the installed-layout archive has been
# verified and its importer installed.  Keeping these as local dynamic imports
# preserves that ordering without suppressing E402 on seven module-level imports.
def _load_verified_foundation_exports() -> tuple[Any, ...]:
    admission = importlib.import_module("scripts.windows_fence_foundation.admission")
    assembly = importlib.import_module("scripts.windows_fence_foundation.assembly")
    bootstrap = importlib.import_module("scripts.windows_fence_foundation.bootstrap_v1")
    contracts = importlib.import_module("scripts.windows_fence_foundation.contracts")
    final_admission = importlib.import_module(
        "scripts.windows_fence_foundation.final_admission_v1"
    )
    credential = importlib.import_module(
        "scripts.windows_fence_foundation.credential_config_v1"
    )
    store = importlib.import_module("scripts.windows_fence_foundation.store")
    win32_fs = importlib.import_module("scripts.windows_fence_foundation.win32_fs")
    return (
        admission.FrozenNoneProjection,
        admission.FrozenNoneStoreRecovery,
        admission.WindowsRpcDurableFenceDenied,
        admission.WindowsRpcDurableFenceError,
        admission.WindowsRpcFinalAdmissionV1,
        assembly.WindowsRpcFrozenAssemblyV1,
        assembly.assemble_windows_rpc_frozen_v1,
        assembly.attach_windows_rpc_deployment_snapshot_v1,
        assembly.attach_windows_rpc_fenced_methods_v1,
        bootstrap.bootstrap_windows_rpc_frozen_v1,
        contracts.StoreContractError,
        contracts.canonical_json_bytes,
        contracts.canonical_local_windows_path,
        final_admission.WindowsRpcFencedAdmissionV1,
        final_admission.WindowsRpcFinalAdmissionV2,
        credential.CredentialConfigError,
        credential.CredentialDescriptorBindingV1,
        credential.WindowsDpapiCredentialReaderV1,
        credential.load_gateway_setting_from_local_blob_v1,
        credential.load_local_credential_descriptor_v1,
        store.StoreExpectation,
        store.StoreRecovery,
        store.recover_frozen_none_store,
        win32_fs.WindowsFilesystemFactsAdapter,
    )


(
    FrozenNoneProjection,
    FrozenNoneStoreRecovery,
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
    WindowsRpcFinalAdmissionV1,
    WindowsRpcFrozenAssemblyV1,
    assemble_windows_rpc_frozen_v1,
    attach_windows_rpc_deployment_snapshot_v1,
    attach_windows_rpc_fenced_methods_v1,
    bootstrap_windows_rpc_frozen_v1,
    StoreContractError,
    canonical_json_bytes,
    canonical_local_windows_path,
    WindowsRpcFencedAdmissionV1,
    WindowsRpcFinalAdmissionV2,
    CredentialConfigError,
    CredentialDescriptorBindingV1,
    WindowsDpapiCredentialReaderV1,
    load_gateway_setting_from_local_blob_v1,
    load_local_credential_descriptor_v1,
    StoreExpectation,
    StoreRecovery,
    recover_frozen_none_store,
    WindowsFilesystemFactsAdapter,
) = _load_verified_foundation_exports()

_RPC_ADDRESS_RE = re.compile(r"^tcp://(?:\*|127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$")
_ASSEMBLY_COMPONENTS = (
    "__init__.py",
    "admission.py",
    "assembly.py",
    "bootstrap_v1.py",
    "contracts.py",
    "credential_config_v1.py",
    "final_admission_v1.py",
    "final_store_v1.py",
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
    account_scope: str = "account:windows"
    environment: str = "simnow"

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
        if (
            not isinstance(self.account_scope, str)
            or not self.account_scope
            or self.account_scope == "account:default"
        ):
            raise ValueError("account_scope must be explicit")
        if (
            not isinstance(self.environment, str)
            or not self.environment
            or self.environment == "default"
        ):
            raise ValueError("environment must be explicit")
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
            "account_scope": self.account_scope,
            "environment": self.environment,
        }
        return sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class _InstalledWindowsRpcServiceConfigV1:
    store_root: str
    store_expectation: StoreExpectation
    gateway_name: str
    rep_address: str
    pub_address: str
    account_scope: str
    environment: str
    credential_descriptor: CredentialDescriptorBindingV1
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
        "installer_store_bootstrap",
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
    bootstrap = value["installer_store_bootstrap"]
    if not isinstance(bootstrap, dict) or set(bootstrap) != {
        "root_path",
        "root_path_sha256",
        "owner_sid",
        "directory_acl_sddl",
    }:
        raise ValueError("SERVICE_CONFIG_STORE_BOOTSTRAP_INVALID")
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
        "rep_address",
        "pub_address",
        "account_scope",
        "environment",
        "credential_descriptor",
    }:
        raise ValueError("SERVICE_CONFIG_RUNTIME_FIELDS_INVALID")
    try:
        credential = CredentialDescriptorBindingV1(**runtime["credential_descriptor"])
    except (TypeError, CredentialConfigError) as exc:
        raise ValueError("SERVICE_CONFIG_CREDENTIAL_DESCRIPTOR_INVALID") from exc
    public = {
        "gateway_name": runtime["gateway_name"],
        "rep_address": runtime["rep_address"],
        "pub_address": runtime["pub_address"],
        "account_scope": runtime["account_scope"],
        "environment": runtime["environment"],
    }
    # Reuse the strict public-field validators without retaining a secret.
    try:
        WindowsRpcRuntimeConfigV1(gateway_setting={"_probe": None}, **public)
    except ValueError as exc:
        raise ValueError("SERVICE_CONFIG_RUNTIME_VALUE_INVALID") from exc
    return _InstalledWindowsRpcServiceConfigV1(
        store_root=store_root,
        store_expectation=StoreExpectation(**expectation),
        credential_descriptor=credential,
        **public,
        raw_sha256=sha256(raw).hexdigest(),
    )


@dataclass(frozen=True)
class _WindowsRpcRuntimeV1:
    event_engine: Any
    main_engine: Any
    rpc_engine: Any
    fact_source: Any
    config: WindowsRpcRuntimeConfigV1


def _execution_fact_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise WindowsRpcDurableFenceError(
                "execution fact datetime is naive",
                code="WINDOWS_EXECUTION_FACT_INVALID",
            )
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _execution_fact_row(value: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    source = value if isinstance(value, Mapping) else vars(value)
    return {
        field: _execution_fact_value(source[field])
        for field in fields
        if field in source and source[field] is not None
    }


class _WindowsExecutionFactsV1:
    """Strict read-only projection over vn.py OMS facts and mutation outcomes."""

    _ORDER_FIELDS = (
        "vt_orderid",
        "orderid",
        "symbol",
        "exchange",
        "direction",
        "offset",
        "price",
        "volume",
        "traded",
        "status",
        "datetime",
        "reference",
        "gateway_name",
    )
    _POSITION_FIELDS = (
        "vt_positionid",
        "symbol",
        "exchange",
        "direction",
        "volume",
        "frozen",
        "price",
        "pnl",
        "gateway_name",
    )

    def __init__(
        self,
        runtime: _WindowsRpcRuntimeV1,
        config: WindowsRpcRuntimeConfigV1 | None = None,
    ) -> None:
        self.runtime = runtime
        self.config = config or runtime.config
        self._lock = RLock()
        self._admission: WindowsRpcFencedAdmissionV1 | None = None
        self._intent_orders: dict[str, str] = {}

    def bind_admission(self, admission: WindowsRpcFencedAdmissionV1) -> None:
        if self._admission is not None:
            raise WindowsRpcDurableFenceError(
                "execution facts admission is already bound",
                code="FINAL_RPC_HANDLER_IDENTITY_MISMATCH",
            )
        self._admission = admission

    def record_outcome(
        self, context: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        intent_id = context.get("intent_id")
        order_id = result.get("broker_order_id") or result.get("vt_orderid")
        if isinstance(intent_id, str) and isinstance(order_id, str) and order_id:
            with self._lock:
                self._intent_orders[intent_id] = order_id

    def _facts(self, method: str) -> list[Any]:
        reader = getattr(self.runtime.fact_source, method, None)
        if not callable(reader):
            raise WindowsRpcDurableFenceError(
                f"Windows OMS fact reader is unavailable: {method}",
                code="WINDOWS_EXECUTION_FACT_UNAVAILABLE",
            )
        result = reader()
        if not isinstance(result, (list, tuple)):
            raise WindowsRpcDurableFenceError(
                f"Windows OMS fact reader is invalid: {method}",
                code="WINDOWS_EXECUTION_FACT_INVALID",
            )
        return list(result)

    @staticmethod
    def _key(row: Mapping[str, Any], *names: str) -> str:
        for name in names:
            value = row.get(name)
            if isinstance(value, str) and value:
                return value
        raise WindowsRpcDurableFenceError(
            "Windows OMS fact identity is missing",
            code="WINDOWS_EXECUTION_FACT_INVALID",
        )

    def _orders(self) -> dict[str, Any]:
        rows = [
            _execution_fact_row(item, self._ORDER_FIELDS)
            for item in self._facts("get_all_orders")
        ]
        return {self._key(row, "vt_orderid", "orderid"): row for row in rows}

    def _positions(self) -> dict[str, Any]:
        rows = [
            _execution_fact_row(item, self._POSITION_FIELDS)
            for item in self._facts("get_all_positions")
        ]
        return {self._key(row, "vt_positionid", "symbol"): row for row in rows}

    def get_execution_snapshot_v1(self, request: Mapping[str, Any]) -> dict[str, Any]:
        expected = {
            "account_scope": self.config.account_scope,
            "environment": self.config.environment,
        }
        if not isinstance(request, Mapping) or dict(request) != {
            "environment": expected["environment"],
            "account_scope": expected["account_scope"],
        }:
            raise WindowsRpcDurableFenceDenied(
                "execution snapshot scope is foreign",
                code="WINDOWS_FENCE_SCOPE_INVALID",
            )
        orders = self._orders()
        positions = self._positions()
        active_orders = self._facts("get_all_active_orders")
        accounts = self._facts("get_all_accounts")
        observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        admission = self._admission
        if admission is None:
            raise WindowsRpcDurableFenceError(
                "execution snapshot durable allocator is unavailable",
                code="WINDOWS_FINAL_STORE_MISSING",
            )
        generation, store_hash = admission.allocate_snapshot_generation()
        return {
            "snapshot_id": f"snapshot-{generation:016d}-{store_hash}",
            "generation": generation,
            "connected": bool(accounts),
            "active_order_count": len(active_orders),
            "position_snapshot_hash": sha256(
                canonical_json_bytes(positions)
            ).hexdigest(),
            "observed_at": observed_at,
            "orders": orders,
            "positions": positions,
            "account_scope": expected["account_scope"],
            "environment": expected["environment"],
            "fresh": True,
        }

    def query_intent_v1(
        self, request: Mapping[str, Any], context: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        intent_id = str(request["intent_id"])
        requested_order_id = request.get("broker_order_id")
        with self._lock:
            recorded_order_id = self._intent_orders.get(intent_id)
        order_id = requested_order_id or recorded_order_id
        orders = self._orders()
        matched: Mapping[str, Any] | None = None
        if isinstance(order_id, str) and order_id:
            matched = orders.get(order_id)
            if matched is None:
                matched = next(
                    (
                        row
                        for row in orders.values()
                        if order_id in {row.get("orderid"), row.get("vt_orderid")}
                    ),
                    None,
                )
        if matched is None:
            matched = next(
                (row for row in orders.values() if row.get("reference") == intent_id),
                None,
            )
        if matched is None:
            return {
                "intent_id": intent_id,
                "state": "UNKNOWN_OUTCOME",
                "account_scope": self.config.account_scope,
                "environment": self.config.environment,
            }
        status = str(matched.get("status", "")).lower().replace(" ", "_")
        state = {
            "all_traded": "TERMINAL",
            "alltraded": "TERMINAL",
            "cancelled": "CANCELLED",
            "canceled": "CANCELLED",
            "rejected": "REJECTED",
            "submitting": "SUBMITTED",
        }.get(status, "ACKNOWLEDGED")
        bound_order_id = self._key(matched, "vt_orderid", "orderid")
        return {
            "intent_id": intent_id,
            "state": state,
            "accepted": state != "REJECTED",
            "broker_order_id": bound_order_id,
            "account_scope": self.config.account_scope,
            "environment": self.config.environment,
        }

    def resolve_cancel(self, request: Mapping[str, Any]) -> dict[str, str]:
        if not isinstance(request, Mapping) or not {
            "target_intent_id",
            "broker_order_id",
        }.issuperset(request):
            raise WindowsRpcDurableFenceDenied(
                "cancel request fields are not exact",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        target_intent = request.get("target_intent_id")
        broker_order_id = request.get("broker_order_id")
        if not isinstance(target_intent, str) or not target_intent:
            raise WindowsRpcDurableFenceDenied(
                "cancel target intent is invalid",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        with self._lock:
            recorded = self._intent_orders.get(target_intent)
        wanted = broker_order_id or recorded
        orders = self._orders()
        match = next(
            (
                row
                for row in orders.values()
                if (
                    isinstance(wanted, str)
                    and wanted in {row.get("orderid"), row.get("vt_orderid")}
                )
                or row.get("reference") == target_intent
            ),
            None,
        )
        if match is None:
            raise WindowsRpcDurableFenceDenied(
                "cancel order is absent from current OMS facts",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        fact_gateway = match.get("gateway_name")
        vt_orderid = self._key(match, "vt_orderid", "orderid")
        if fact_gateway not in {None, "", self.config.gateway_name} or (
            "." in vt_orderid
            and vt_orderid.split(".", 1)[0] != self.config.gateway_name
        ):
            raise WindowsRpcDurableFenceDenied(
                "cancel order belongs to a foreign gateway",
                code="WINDOWS_FENCE_SCOPE_INVALID",
            )
        orderid = match.get("orderid")
        if not isinstance(orderid, str) or not orderid:
            orderid = vt_orderid.split(".", 1)[-1]
        symbol = match.get("symbol")
        exchange = match.get("exchange")
        if not isinstance(symbol, str) or not symbol or not isinstance(exchange, str):
            raise WindowsRpcDurableFenceError(
                "cancel order facts are incomplete",
                code="WINDOWS_EXECUTION_FACT_INVALID",
            )
        return {
            "orderid": orderid,
            "vt_orderid": vt_orderid,
            "symbol": symbol,
            "exchange": exchange,
        }

    def cancel_state(self, vt_orderid: str) -> str:
        order = self._orders().get(vt_orderid)
        if order is None:
            return "UNKNOWN_OUTCOME"
        status = str(order.get("status", "")).lower().replace(" ", "_")
        if status in {"cancelled", "canceled", "all_traded", "alltraded"}:
            return "CANCELLED"
        if status == "rejected":
            return "REJECTED"
        return "UNKNOWN_OUTCOME"


class _VnpyExecutionRequestFactoryV1:
    """Exact-schema conversion from JSON facts to native vn.py requests."""

    schema_version = "windows_execution_vnpy_request_factory_v1"
    _SEND_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "symbol",
            "exchange",
            "direction",
            "type",
            "volume",
            "price",
            "offset",
            "reference",
            "gateway_name",
        }
    )
    _SEND_REQUIRED: ClassVar[frozenset[str]] = frozenset(
        {"symbol", "exchange", "direction", "type", "volume"}
    )

    def __init__(self, gateway_name: str) -> None:
        self.gateway_name = gateway_name
        self.Direction: Any = None
        self.Exchange: Any = None
        self.Offset: Any = None
        self.OrderType: Any = None
        self.OrderRequest: Any = None
        self.CancelRequest: Any = None

    def _load_vnpy_types(self) -> None:
        if self.OrderRequest is not None and self.CancelRequest is not None:
            return
        try:
            from vnpy.trader.constant import Direction, Exchange, Offset, OrderType
            from vnpy.trader.object import CancelRequest, OrderRequest
        except ImportError as exc:
            raise WindowsRpcDurableFenceError(
                "vn.py request types are unavailable",
                code="WINDOWS_FENCE_HANDLER_INVALID",
            ) from exc
        self.Direction = Direction
        self.Exchange = Exchange
        self.Offset = Offset
        self.OrderType = OrderType
        self.OrderRequest = OrderRequest
        self.CancelRequest = CancelRequest

    @staticmethod
    def _enum(enum_type: Any, value: Any, field: str) -> Any:
        if not isinstance(value, str):
            raise WindowsRpcDurableFenceDenied(
                f"{field} is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        try:
            return enum_type[value.strip().upper()]
        except KeyError as exc:
            raise WindowsRpcDurableFenceDenied(
                f"{field} is outside the allowlist",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            ) from exc

    @staticmethod
    def _number(value: Any, field: str, *, positive: bool) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise WindowsRpcDurableFenceDenied(
                f"{field} is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        number = float(value)
        if not math.isfinite(number) or (number <= 0 if positive else number < 0):
            raise WindowsRpcDurableFenceDenied(
                f"{field} is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        return number

    def order_request(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Any:
        if (
            not isinstance(request, Mapping)
            or not self._SEND_REQUIRED.issubset(request)
            or not set(request).issubset(self._SEND_FIELDS)
        ):
            raise WindowsRpcDurableFenceDenied(
                "send request fields are not exact",
                code="WINDOWS_FENCE_REQUEST_INVALID",
            )
        gateway = request.get("gateway_name")
        if gateway is not None and gateway != self.gateway_name:
            raise WindowsRpcDurableFenceDenied(
                "send request names a foreign gateway",
                code="WINDOWS_FENCE_SCOPE_INVALID",
            )
        symbol = request.get("symbol")
        if not isinstance(symbol, str) or not symbol or len(symbol) > 64:
            raise WindowsRpcDurableFenceDenied(
                "send symbol is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        reference = request.get("reference", context.get("intent_id"))
        if not isinstance(reference, str) or not reference or len(reference) > 64:
            raise WindowsRpcDurableFenceDenied(
                "send reference is invalid", code="WINDOWS_FENCE_REQUEST_INVALID"
            )
        self._load_vnpy_types()
        return self.OrderRequest(
            symbol=symbol,
            exchange=self._enum(self.Exchange, request["exchange"], "exchange"),
            direction=self._enum(self.Direction, request["direction"], "direction"),
            type=self._enum(self.OrderType, request["type"], "type"),
            volume=self._number(request["volume"], "volume", positive=True),
            price=self._number(request.get("price", 0), "price", positive=False),
            offset=self._enum(self.Offset, request.get("offset", "NONE"), "offset"),
            reference=reference,
        )

    def cancel_request(self, facts: Mapping[str, str]) -> Any:
        self._load_vnpy_types()
        return self.CancelRequest(
            orderid=facts["orderid"],
            symbol=facts["symbol"],
            exchange=self._enum(self.Exchange, facts["exchange"], "exchange"),
        )


def _attach_fixed_typed_fenced_methods(
    runtime: _WindowsRpcRuntimeV1,
    runtime_config: WindowsRpcRuntimeConfigV1,
    store_root: str | Path,
) -> WindowsRpcFencedAdmissionV1:
    """Create and attach the dormant typed execution lifecycle at startup.

    The foundation remains frozen: this admission starts with no registered
    receipts, so its typed send/cancel methods cannot reach the vn.py handlers
    until the Linux Execution lifecycle installs a current fence and receipt.
    """

    server = runtime.rpc_engine.server
    functions = getattr(server, "_functions", None)
    if not isinstance(functions, dict):
        raise WindowsRpcDurableFenceError(
            "RPC server registry is unavailable",
            code="RPC_REGISTRY_UNAVAILABLE",
        )
    send_handler = functions.get("send_order")
    cancel_handler = functions.get("cancel_order")
    if not callable(send_handler) or not callable(cancel_handler):
        raise WindowsRpcDurableFenceError(
            "underlying send/cancel handlers are unavailable",
            code="RPC_MUTATION_HANDLERS_MISSING",
        )
    facts = _WindowsExecutionFactsV1(runtime, runtime_config)
    request_factory = getattr(runtime, "execution_request_factory", None)
    if request_factory is None:
        request_factory = _VnpyExecutionRequestFactoryV1(runtime_config.gateway_name)
    if (
        getattr(request_factory, "schema_version", None)
        != _VnpyExecutionRequestFactoryV1.schema_version
        or not callable(getattr(request_factory, "order_request", None))
        or not callable(getattr(request_factory, "cancel_request", None))
    ):
        raise WindowsRpcDurableFenceError(
            "strict vn.py request factory is unavailable",
            code="WINDOWS_FENCE_HANDLER_INVALID",
        )

    def send_bound(request: Mapping[str, Any], context: Mapping[str, Any]) -> Any:
        native_request = request_factory.order_request(request, context)
        vt_orderid = send_handler(native_request, runtime_config.gateway_name)
        if not isinstance(vt_orderid, str) or not vt_orderid:
            return {"state": "UNKNOWN_OUTCOME"}
        if (
            "." not in vt_orderid
            or vt_orderid.split(".", 1)[0] != runtime_config.gateway_name
        ):
            raise WindowsRpcDurableFenceError(
                "native send returned a foreign order identity",
                code="WINDOWS_FENCE_RESPONSE_INVALID",
            )
        result = {
            "accepted": True,
            "state": "SUBMITTED",
            "broker_order_id": vt_orderid,
        }
        facts.record_outcome(context, result)
        return result

    def cancel_bound(request: Mapping[str, Any], context: Mapping[str, Any]) -> Any:
        cancel_facts = facts.resolve_cancel(request)
        native_request = request_factory.cancel_request(cancel_facts)
        facts.record_outcome(context, {"broker_order_id": cancel_facts["vt_orderid"]})
        native_result = cancel_handler(native_request, runtime_config.gateway_name)
        if native_result is not None:
            raise WindowsRpcDurableFenceError(
                "native cancel handler returned an invalid acknowledgement",
                code="WINDOWS_FENCE_RESPONSE_INVALID",
            )
        state = facts.cancel_state(cancel_facts["vt_orderid"])
        if state == "UNKNOWN_OUTCOME":
            return {"state": state}
        result = {
            "accepted": state != "REJECTED",
            "state": state,
            "broker_order_id": cancel_facts["vt_orderid"],
        }
        facts.record_outcome(context, result)
        return result

    # The execution ledger lives under the already verified service-owned WF-1
    # root at one fixed filename; callers cannot redirect it to an arbitrary
    # path or migration chain.
    final_store_path = Path(store_root).absolute() / "execution-final-admission-v1.json"
    admission = WindowsRpcFencedAdmissionV1.bootstrap(
        store_path=str(final_store_path),
        account_scope=runtime_config.account_scope,
        environment=runtime_config.environment,
        send_handler=send_bound,
        cancel_handler=cancel_bound,
        query_handler=facts.query_intent_v1,
    )
    facts.bind_admission(admission)
    attach_windows_rpc_fenced_methods_v1(server, admission)
    server.register(facts.get_execution_snapshot_v1)
    return admission


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
        attach_typed=lambda runtime: _attach_fixed_typed_fenced_methods(
            runtime, runtime_config, store_root
        ),
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


def run_installed_windows_rpc_entry_v1(
    arguments: list[str],
) -> WindowsRpcFrozenAssemblyV1:
    """Hash-pinned service entry; secrets enter only after descriptor readback."""
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
    filesystem = _production_windows_filesystem()
    descriptor = load_local_credential_descriptor_v1(
        service_config.credential_descriptor, filesystem=filesystem
    )
    if descriptor.gateway_name != service_config.gateway_name:
        raise RuntimeError("CREDENTIAL_GATEWAY_BINDING_MISMATCH")
    try:
        gateway_setting = load_gateway_setting_from_local_blob_v1(
            descriptor,
            filesystem=filesystem,
            reader=WindowsDpapiCredentialReaderV1(),
        )
        runtime_config = WindowsRpcRuntimeConfigV1(
            gateway_setting=gateway_setting,
            gateway_name=service_config.gateway_name,
            rep_address=service_config.rep_address,
            pub_address=service_config.pub_address,
            account_scope=service_config.account_scope,
            environment=service_config.environment,
        )
    except CredentialConfigError as exc:
        raise RuntimeError(exc.code) from exc
    return _launch_windows_rpc_durable_fence_bound_v1(
        store_root=service_config.store_root,
        store_expectation=service_config.store_expectation,
        runtime_config=runtime_config,
        config_binding_sha256=service_config.raw_sha256,
    )


def _main(arguments: list[str]) -> None:
    run_installed_windows_rpc_entry_v1(arguments)


__all__ = [
    "FrozenNoneProjection",
    "FrozenNoneStoreRecovery",
    "StoreExpectation",
    "StoreRecovery",
    "WindowsRpcDurableFenceDenied",
    "WindowsRpcDurableFenceError",
    "WindowsRpcFencedAdmissionV1",
    "WindowsRpcFinalAdmissionV1",
    "WindowsRpcFinalAdmissionV2",
    "WindowsRpcFrozenAssemblyV1",
    "WindowsRpcRuntimeConfigV1",
    "assemble_windows_rpc_frozen_v1",
    "attach_windows_rpc_deployment_snapshot_v1",
    "attach_windows_rpc_fenced_methods_v1",
    "bootstrap_windows_rpc_frozen_v1",
    "launch_windows_rpc_durable_fence_v1",
    "recover_frozen_none_store",
    "run_installed_windows_rpc_entry_v1",
]


if __name__ == "__main__":
    _main(sys.argv[1:])
