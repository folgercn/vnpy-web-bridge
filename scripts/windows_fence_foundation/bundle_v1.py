"""Deterministic, offline WF-2 bundle construction and verification.

This module only reads source bytes and constructs/verifies in-memory archives.
It has no signing, installation, ACL, SCM, network, or service-control behavior.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import unicodedata
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import (
    StoreContractError,
    canonical_json_bytes,
    canonical_local_windows_path,
)

BUNDLE_INDEX_SCHEMA_VERSION = "windows_rpc_durable_fence_bundle_index_v1"
BUNDLE_INDEX_PURPOSE = "identify_reproducible_windows_fence_offline_bundle"
BUNDLE_FORMAT = "deterministic_zip_stored_v1"

FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_FILE_MODE = 0o100644
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ASSEMBLY_BYTES = 4 * 1024 * 1024
MAX_COMPONENT_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024

FOUNDATION_SOURCE_NAMES = (
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
SYNTHETIC_SCRIPTS_INIT = "scripts/__init__.py"
ASSEMBLY_EXTENSION_PATH = "scripts/windows_rpc_deployment_snapshot_v1.py"

COMPONENT_PATHS = {
    "wrapper": "components/windows_rpc_service_wrapper_v1.py",
    "extension": "components/windows_rpc_deployment_snapshot_v1.py",
    "launcher": "components/windows_rpc_durable_fence_v1.py",
    "assembly": "components/windows_fence_foundation_v1.pyz",
    "config": "components/windows_rpc_service_config_v1.json",
}
COMPONENT_ORDER = ("wrapper", "extension", "launcher", "assembly", "config")

_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "bundle_format",
        "bundle_sha256",
        "components",
        "assembly_archive_raw_sha256",
        "assembly_source_inventory_sha256",
        "assembly_sources",
    }
)
_INVENTORY_FIELDS = frozenset({"role", "path", "size_bytes", "raw_sha256"})
_SOURCE_FIELDS = frozenset({"path", "size_bytes", "raw_sha256"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_GATEWAY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RPC_ADDRESS_RE = re.compile(r"^tcp://(?:\*|127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$")
_SERVICE_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "store_root",
        "store_expectation",
        "installer_store_bootstrap",
        "runtime_config",
    }
)
STORE_BINDING_FIELDS = frozenset(
    {
        "service_name",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "owner_sid_sha256",
        "directory_acl_sddl_sha256",
        "state_acl_sddl_sha256",
    }
)
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)


class WindowsFenceBundleError(ValueError):
    """Stable fail-closed rejection for an offline WF-2 bundle."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class BuiltWindowsFenceBundleV1:
    bundle_raw: bytes = field(repr=False)
    bundle_sha256: str
    index_raw: bytes = field(repr=False)
    index_raw_sha256: str
    assembly_archive_raw_sha256: str
    assembly_source_inventory_sha256: str


@dataclass(frozen=True)
class VerifiedWindowsFenceBundleV1:
    bundle_sha256: str
    index_raw_sha256: str
    assembly_archive_raw_sha256: str
    assembly_source_inventory_sha256: str
    component_sha256s: Mapping[str, str]
    component_sizes: Mapping[str, int]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_archive_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path
        or unicodedata.normalize("NFC", path) != path
        or "\\" in path
        or path.startswith(("/", "//"))
        or _DRIVE_RE.match(path)
        or ":" in path
        or any(ord(character) < 32 for character in path)
    ):
        raise WindowsFenceBundleError("BUNDLE_PATH_UNSAFE")
    parts = path.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise WindowsFenceBundleError("BUNDLE_PATH_UNSAFE")
    for part in parts:
        if part.endswith((".", " ")):
            raise WindowsFenceBundleError("BUNDLE_PATH_UNSAFE")
        basename = part.split(".", 1)[0].upper()
        if basename in _WINDOWS_RESERVED:
            raise WindowsFenceBundleError("BUNDLE_PATH_UNSAFE")
    if PurePosixPath(path).as_posix() != path:
        raise WindowsFenceBundleError("BUNDLE_PATH_UNSAFE")
    return path


def _zip_info(path: str) -> zipfile.ZipInfo:
    _validate_archive_path(path)
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = FIXED_FILE_MODE << 16
    info.internal_attr = 0
    info.extra = b""
    info.comment = b""
    return info


def _build_zip(entries: Mapping[str, bytes]) -> bytes:
    normalized: dict[str, bytes] = {}
    casefolded: set[str] = set()
    for path, raw in entries.items():
        path = _validate_archive_path(path)
        folded = path.casefold()
        if folded in casefolded:
            raise WindowsFenceBundleError("BUNDLE_PATH_CASEFOLD_COLLISION")
        casefolded.add(folded)
        if not isinstance(raw, bytes):
            raise WindowsFenceBundleError("BUNDLE_COMPONENT_NOT_BYTES")
        normalized[path] = raw
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=False,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for path in sorted(normalized):
                archive.writestr(_zip_info(path), normalized[path])
    except (OSError, ValueError, zipfile.LargeZipFile) as exc:
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_BUILD_FAILED") from exc
    return output.getvalue()


def _read_canonical_json_object(raw: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise WindowsFenceBundleError("BUNDLE_CANONICAL_JSON_SIZE_INVALID")

    def reject_float(_: str) -> None:
        raise WindowsFenceBundleError("BUNDLE_JSON_FLOAT_FORBIDDEN")

    def reject_constant(_: str) -> None:
        raise WindowsFenceBundleError("BUNDLE_JSON_NONFINITE_FORBIDDEN")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise WindowsFenceBundleError("BUNDLE_JSON_DUPLICATE_KEY")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except WindowsFenceBundleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WindowsFenceBundleError("BUNDLE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise WindowsFenceBundleError("BUNDLE_JSON_NOT_OBJECT")
    try:
        canonical = canonical_json_bytes(value)
    except StoreContractError as exc:
        raise WindowsFenceBundleError(exc.code) from exc
    if canonical != raw:
        raise WindowsFenceBundleError("BUNDLE_JSON_NOT_CANONICAL")
    return value


def _foundation_source_entries(source_root: Path) -> dict[str, bytes]:
    foundation_root = source_root / "scripts" / "windows_fence_foundation"
    entries: dict[str, bytes] = {SYNTHETIC_SCRIPTS_INIT: b""}
    try:
        entries[ASSEMBLY_EXTENSION_PATH] = (
            source_root / "scripts" / "windows_rpc_deployment_snapshot_v1.py"
        ).read_bytes()
        for name in FOUNDATION_SOURCE_NAMES:
            entries[f"scripts/windows_fence_foundation/{name}"] = (
                foundation_root / name
            ).read_bytes()
    except (OSError, PermissionError) as exc:
        raise WindowsFenceBundleError("BUNDLE_SOURCE_UNREADABLE") from exc
    return entries


def _validate_runtime_config(
    raw: bytes, *, expected_store_binding: Mapping[str, object]
) -> dict[str, Any]:
    value = _read_canonical_json_object(raw, maximum_bytes=MAX_CONFIG_BYTES)
    if set(value) != _SERVICE_CONFIG_FIELDS:
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_FIELDS_INVALID")
    if (
        value["schema_version"] != "windows_rpc_durable_fence_service_config_v1"
        or value["purpose"] != "launch_fixed_frozen_windows_rpc_service"
        or not isinstance(value["store_root"], str)
        or not isinstance(value["store_expectation"], dict)
        or not isinstance(value["installer_store_bootstrap"], dict)
        or not isinstance(value["runtime_config"], dict)
    ):
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID")
    expectation = value["store_expectation"]
    if set(expectation) != {
        "service_name",
        "store_id",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "owner_sid_sha256",
        "directory_acl_sddl_sha256",
        "state_acl_sddl_sha256",
    }:
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID")
    store_root = value["store_root"]
    try:
        canonical_store_root = canonical_local_windows_path(store_root)
    except StoreContractError as exc:
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID") from exc
    hash_fields = (
        "store_path_sha256",
        "store_volume_identity_sha256",
        "owner_sid_sha256",
        "directory_acl_sddl_sha256",
        "state_acl_sddl_sha256",
    )
    if (
        canonical_store_root != store_root
        or any(
            not isinstance(expectation[field], str)
            or _SHA256_RE.fullmatch(expectation[field]) is None
            for field in hash_fields
        )
        or expectation["store_path_sha256"] != _sha256(store_root.encode("utf-8"))
        or not isinstance(expectation["service_name"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", expectation["service_name"])
        is None
        or not isinstance(expectation["store_id"], str)
        or re.fullmatch(r"windows-fence-store-[0-9a-f]{64}", expectation["store_id"])
        is None
        or not isinstance(expectation["store_volume_serial"], str)
        or re.fullmatch(r"[A-F0-9]{8,32}", expectation["store_volume_serial"]) is None
    ):
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID")
    if (
        not isinstance(expected_store_binding, Mapping)
        or set(expected_store_binding) != STORE_BINDING_FIELDS
        or any(
            type(expectation[field]) is not type(expected_store_binding[field])
            or expectation[field] != expected_store_binding[field]
            for field in STORE_BINDING_FIELDS
        )
    ):
        raise WindowsFenceBundleError("BUNDLE_STORE_TARGET_BINDING_MISMATCH")
    bootstrap = value["installer_store_bootstrap"]
    if set(bootstrap) != {"root_path", "root_path_sha256", "owner_sid", "directory_acl_sddl"}:
        raise WindowsFenceBundleError("BUNDLE_STORE_BOOTSTRAP_INVALID")
    try:
        bootstrap_root = canonical_local_windows_path(bootstrap["root_path"])
    except StoreContractError as exc:
        raise WindowsFenceBundleError("BUNDLE_STORE_BOOTSTRAP_INVALID") from exc
    if (
        bootstrap_root != store_root
        or bootstrap_root != bootstrap["root_path"]
        or bootstrap["root_path_sha256"] != _sha256(bootstrap_root.encode("utf-8"))
        or bootstrap["root_path_sha256"] != expectation["store_path_sha256"]
        or not isinstance(bootstrap["owner_sid"], str)
        or not isinstance(bootstrap["directory_acl_sddl"], str)
        or _sha256(bootstrap["owner_sid"].encode("utf-8")) != expectation["owner_sid_sha256"]
        or _sha256(bootstrap["directory_acl_sddl"].encode("utf-8")) != expectation["directory_acl_sddl_sha256"]
    ):
        raise WindowsFenceBundleError("BUNDLE_STORE_BOOTSTRAP_INVALID")
    runtime = value["runtime_config"]
    if set(runtime) != {
        "gateway_name",
        "rep_address",
        "pub_address",
        "account_scope",
        "environment",
        "credential_descriptor",
    }:
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID")
    descriptor = runtime["credential_descriptor"]
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "path",
        "path_sha256",
        "raw_sha256",
        "owner_sid_sha256",
        "acl_sddl_sha256",
    }:
        raise WindowsFenceBundleError("BUNDLE_CREDENTIAL_DESCRIPTOR_INVALID")
    try:
        descriptor_path = canonical_local_windows_path(descriptor["path"])
    except StoreContractError as exc:
        raise WindowsFenceBundleError("BUNDLE_CREDENTIAL_DESCRIPTOR_INVALID") from exc
    if (
        descriptor_path != descriptor["path"]
        or descriptor["path_sha256"] != _sha256(descriptor_path.encode("utf-8"))
        or any(
            not isinstance(descriptor[field], str)
            or _SHA256_RE.fullmatch(descriptor[field]) is None
            for field in (
                "path_sha256",
                "raw_sha256",
                "owner_sid_sha256",
                "acl_sddl_sha256",
            )
        )
    ):
        raise WindowsFenceBundleError("BUNDLE_CREDENTIAL_DESCRIPTOR_INVALID")
    if (
        not isinstance(runtime["gateway_name"], str)
        or _GATEWAY_NAME_RE.fullmatch(runtime["gateway_name"]) is None
    ):
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID")
    addresses = (runtime["rep_address"], runtime["pub_address"])
    if (
        any(
            not isinstance(address, str)
            or _RPC_ADDRESS_RE.fullmatch(address) is None
            or int(address.rsplit(":", 1)[1]) > 65535
            for address in addresses
        )
        or addresses[0] == addresses[1]
    ):
        raise WindowsFenceBundleError("BUNDLE_RUNTIME_CONFIG_VALUE_INVALID")
    return value


def _source_inventory(entries: Mapping[str, bytes]) -> list[dict[str, Any]]:
    expected = {
        f"scripts/windows_fence_foundation/{name}" for name in FOUNDATION_SOURCE_NAMES
    }
    actual = set(entries) - {SYNTHETIC_SCRIPTS_INIT, ASSEMBLY_EXTENSION_PATH}
    if actual != expected or entries.get(SYNTHETIC_SCRIPTS_INIT) != b"":
        raise WindowsFenceBundleError("ASSEMBLY_SOURCE_INVENTORY_INVALID")
    return [
        {
            "path": path.removeprefix("scripts/"),
            "size_bytes": len(entries[path]),
            "raw_sha256": _sha256(entries[path]),
        }
        for path in sorted(actual)
    ]


def _source_inventory_identity(inventory: list[dict[str, Any]]) -> str:
    # This deliberately matches WF-1 `_runtime_closure_hashes`: size is useful
    # detached evidence, while the runtime assembly identity binds path+digest.
    identity = [
        {"path": item["path"], "sha256": item["raw_sha256"]} for item in inventory
    ]
    return _sha256(canonical_json_bytes(identity))


def _component_inventory(entries: Mapping[str, bytes]) -> list[dict[str, Any]]:
    return [
        {
            "role": role,
            "path": COMPONENT_PATHS[role],
            "size_bytes": len(entries[COMPONENT_PATHS[role]]),
            "raw_sha256": _sha256(entries[COMPONENT_PATHS[role]]),
        }
        for role in COMPONENT_ORDER
    ]


def build_windows_fence_bundle_v1(
    source_root: Path,
    *,
    config_raw: bytes,
    expected_store_binding: Mapping[str, object],
) -> BuiltWindowsFenceBundleV1:
    """Build deterministic bundle and detached index without writing files."""

    source_root = Path(source_root).absolute()
    _validate_runtime_config(config_raw, expected_store_binding=expected_store_binding)
    try:
        wrapper_raw = (
            source_root / "scripts" / "windows_rpc_service_wrapper_v1.py"
        ).read_bytes()
        extension_raw = (
            source_root / "scripts" / "windows_rpc_deployment_snapshot_v1.py"
        ).read_bytes()
        launcher_raw = (
            source_root / "scripts" / "windows_rpc_durable_fence_v1.py"
        ).read_bytes()
    except (OSError, PermissionError) as exc:
        raise WindowsFenceBundleError("BUNDLE_SOURCE_UNREADABLE") from exc

    assembly_entries = _foundation_source_entries(source_root)
    assembly_inventory = _source_inventory(assembly_entries)
    assembly_source_sha256 = _source_inventory_identity(assembly_inventory)
    assembly_raw = _build_zip(assembly_entries)
    if len(assembly_raw) > MAX_ASSEMBLY_BYTES:
        raise WindowsFenceBundleError("ASSEMBLY_ARCHIVE_TOO_LARGE")

    component_entries = {
        COMPONENT_PATHS["wrapper"]: wrapper_raw,
        COMPONENT_PATHS["extension"]: extension_raw,
        COMPONENT_PATHS["launcher"]: launcher_raw,
        COMPONENT_PATHS["assembly"]: assembly_raw,
        COMPONENT_PATHS["config"]: config_raw,
    }
    if any(len(raw) > MAX_COMPONENT_BYTES for raw in component_entries.values()):
        raise WindowsFenceBundleError("BUNDLE_COMPONENT_TOO_LARGE")
    bundle_raw = _build_zip(component_entries)
    if len(bundle_raw) > MAX_BUNDLE_BYTES:
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_TOO_LARGE")
    bundle_sha256 = _sha256(bundle_raw)
    assembly_archive_sha256 = _sha256(assembly_raw)
    index = {
        "schema_version": BUNDLE_INDEX_SCHEMA_VERSION,
        "purpose": BUNDLE_INDEX_PURPOSE,
        "bundle_format": BUNDLE_FORMAT,
        "bundle_sha256": bundle_sha256,
        "components": _component_inventory(component_entries),
        "assembly_archive_raw_sha256": assembly_archive_sha256,
        "assembly_source_inventory_sha256": assembly_source_sha256,
        "assembly_sources": assembly_inventory,
    }
    index_raw = canonical_json_bytes(index)
    return BuiltWindowsFenceBundleV1(
        bundle_raw=bundle_raw,
        bundle_sha256=bundle_sha256,
        index_raw=index_raw,
        index_raw_sha256=_sha256(index_raw),
        assembly_archive_raw_sha256=assembly_archive_sha256,
        assembly_source_inventory_sha256=assembly_source_sha256,
    )


def _read_strict_zip(
    raw: bytes,
    *,
    maximum_bytes: int,
    expected_paths: set[str],
) -> dict[str, bytes]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_SIZE_INVALID")
    try:
        with zipfile.ZipFile(io.BytesIO(raw), mode="r") as archive:
            if archive.comment:
                raise WindowsFenceBundleError("BUNDLE_ZIP_COMMENT_FORBIDDEN")
            infos = archive.infolist()
            if len(infos) != len(expected_paths):
                raise WindowsFenceBundleError("BUNDLE_ARCHIVE_INVENTORY_INVALID")
            names: set[str] = set()
            folded: set[str] = set()
            entries: dict[str, bytes] = {}
            total = 0
            for info in infos:
                name = _validate_archive_path(info.filename)
                if name in names:
                    raise WindowsFenceBundleError("BUNDLE_PATH_DUPLICATE")
                if name.casefold() in folded:
                    raise WindowsFenceBundleError("BUNDLE_PATH_CASEFOLD_COLLISION")
                names.add(name)
                folded.add(name.casefold())
                if (
                    info.is_dir()
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.file_size != info.compress_size
                    or info.file_size > MAX_COMPONENT_BYTES
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.external_attr != FIXED_FILE_MODE << 16
                    or info.internal_attr != 0
                    or info.extra
                    or info.comment
                    or info.flag_bits & 0x1
                ):
                    raise WindowsFenceBundleError("BUNDLE_ZIP_METADATA_INVALID")
                total += info.file_size
                if total > maximum_bytes:
                    raise WindowsFenceBundleError("BUNDLE_ARCHIVE_SIZE_INVALID")
                entries[name] = archive.read(info)
    except WindowsFenceBundleError:
        raise
    except (OSError, EOFError, ValueError, zipfile.BadZipFile) as exc:
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_INVALID") from exc
    if names != expected_paths:
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_INVENTORY_INVALID")
    # Byte-for-byte reconstruction rejects trailing bytes, alternate central
    # directories, zip64, data descriptors, ordering drift and hidden metadata.
    if _build_zip(entries) != raw:
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_NOT_DETERMINISTIC")
    return entries


def _require_inventory_item(
    item: Any,
    *,
    expected_fields: frozenset[str],
    role: str | None = None,
) -> tuple[str, int, str]:
    if not isinstance(item, dict) or set(item) != expected_fields:
        raise WindowsFenceBundleError("BUNDLE_INDEX_FIELDS_INVALID")
    if role is not None and item.get("role") != role:
        raise WindowsFenceBundleError("BUNDLE_COMPONENT_ORDER_INVALID")
    path = _validate_archive_path(item.get("path"))
    size = item.get("size_bytes")
    digest = item.get("raw_sha256")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > MAX_COMPONENT_BYTES
        or not isinstance(digest, str)
        or not _SHA256_RE.fullmatch(digest)
    ):
        raise WindowsFenceBundleError("BUNDLE_INDEX_VALUE_INVALID")
    return path, size, digest


def verify_windows_fence_bundle_v1(
    bundle_raw: bytes,
    index_raw: bytes,
    *,
    expected_store_binding: Mapping[str, object],
) -> VerifiedWindowsFenceBundleV1:
    """Verify exact archive bytes and detached canonical inventory."""

    if (
        not isinstance(bundle_raw, bytes)
        or not bundle_raw
        or len(bundle_raw) > MAX_BUNDLE_BYTES
    ):
        raise WindowsFenceBundleError("BUNDLE_ARCHIVE_SIZE_INVALID")
    index = _read_canonical_json_object(index_raw, maximum_bytes=MAX_COMPONENT_BYTES)
    if set(index) != _INDEX_FIELDS:
        raise WindowsFenceBundleError("BUNDLE_INDEX_FIELDS_INVALID")
    if (
        index.get("schema_version") != BUNDLE_INDEX_SCHEMA_VERSION
        or index.get("purpose") != BUNDLE_INDEX_PURPOSE
        or index.get("bundle_format") != BUNDLE_FORMAT
    ):
        raise WindowsFenceBundleError("BUNDLE_INDEX_VERSION_INVALID")
    bundle_sha256 = _sha256(bundle_raw)
    if index.get("bundle_sha256") != bundle_sha256:
        raise WindowsFenceBundleError("BUNDLE_RAW_SHA256_MISMATCH")

    outer = _read_strict_zip(
        bundle_raw,
        maximum_bytes=MAX_BUNDLE_BYTES,
        expected_paths=set(COMPONENT_PATHS.values()),
    )
    component_index = index.get("components")
    if not isinstance(component_index, list) or len(component_index) != len(
        COMPONENT_ORDER
    ):
        raise WindowsFenceBundleError("BUNDLE_COMPONENT_INVENTORY_INVALID")
    component_sha256s: dict[str, str] = {}
    component_sizes: dict[str, int] = {}
    for role, item in zip(COMPONENT_ORDER, component_index, strict=True):
        path, size, digest = _require_inventory_item(
            item, expected_fields=_INVENTORY_FIELDS, role=role
        )
        if path != COMPONENT_PATHS[role]:
            raise WindowsFenceBundleError("BUNDLE_COMPONENT_PATH_MISMATCH")
        raw = outer[path]
        if len(raw) != size or _sha256(raw) != digest:
            raise WindowsFenceBundleError("BUNDLE_COMPONENT_DIGEST_MISMATCH")
        component_sha256s[role] = digest
        component_sizes[role] = size

    config_raw = outer[COMPONENT_PATHS["config"]]
    _validate_runtime_config(config_raw, expected_store_binding=expected_store_binding)
    assembly_raw = outer[COMPONENT_PATHS["assembly"]]
    assembly_archive_sha256 = _sha256(assembly_raw)
    if index.get("assembly_archive_raw_sha256") != assembly_archive_sha256:
        raise WindowsFenceBundleError("ASSEMBLY_ARCHIVE_SHA256_MISMATCH")
    assembly_paths = {SYNTHETIC_SCRIPTS_INIT} | {
        f"scripts/windows_fence_foundation/{name}" for name in FOUNDATION_SOURCE_NAMES
    }
    assembly_paths.add(ASSEMBLY_EXTENSION_PATH)
    assembly_entries = _read_strict_zip(
        assembly_raw,
        maximum_bytes=MAX_ASSEMBLY_BYTES,
        expected_paths=assembly_paths,
    )
    if assembly_entries[ASSEMBLY_EXTENSION_PATH] != outer[COMPONENT_PATHS["extension"]]:
        raise WindowsFenceBundleError("ASSEMBLY_EXTENSION_COPY_MISMATCH")
    assembly_inventory = _source_inventory(assembly_entries)
    supplied_sources = index.get("assembly_sources")
    if not isinstance(supplied_sources, list) or len(supplied_sources) != len(
        FOUNDATION_SOURCE_NAMES
    ):
        raise WindowsFenceBundleError("ASSEMBLY_SOURCE_INVENTORY_INVALID")
    for actual, supplied in zip(assembly_inventory, supplied_sources, strict=True):
        path, size, digest = _require_inventory_item(
            supplied, expected_fields=_SOURCE_FIELDS
        )
        if (
            path != actual["path"]
            or size != actual["size_bytes"]
            or digest != actual["raw_sha256"]
        ):
            raise WindowsFenceBundleError("ASSEMBLY_SOURCE_DIGEST_MISMATCH")
    assembly_source_sha256 = _source_inventory_identity(assembly_inventory)
    if index.get("assembly_source_inventory_sha256") != assembly_source_sha256:
        raise WindowsFenceBundleError("ASSEMBLY_SOURCE_INVENTORY_SHA256_MISMATCH")
    return VerifiedWindowsFenceBundleV1(
        bundle_sha256=bundle_sha256,
        index_raw_sha256=_sha256(index_raw),
        assembly_archive_raw_sha256=assembly_archive_sha256,
        assembly_source_inventory_sha256=assembly_source_sha256,
        component_sha256s=component_sha256s,
        component_sizes=component_sizes,
    )


__all__ = [
    "ASSEMBLY_EXTENSION_PATH",
    "BUNDLE_FORMAT",
    "BUNDLE_INDEX_PURPOSE",
    "BUNDLE_INDEX_SCHEMA_VERSION",
    "COMPONENT_ORDER",
    "COMPONENT_PATHS",
    "FOUNDATION_SOURCE_NAMES",
    "STORE_BINDING_FIELDS",
    "BuiltWindowsFenceBundleV1",
    "VerifiedWindowsFenceBundleV1",
    "WindowsFenceBundleError",
    "build_windows_fence_bundle_v1",
    "verify_windows_fence_bundle_v1",
]
