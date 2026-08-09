from __future__ import annotations

import ast
import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.windows_fence_foundation import (
    PathSecurityFacts,
    SecureDirectoryInventory,
    SecureFileRead,
    StoreContractError,
    StoreExpectation,
    WindowsFilesystemFactsAdapter,
    canonical_json_bytes,
    parse_frozen_none_state,
    recover_frozen_none_store,
)
from scripts.windows_fence_foundation.admission import WindowsRpcFinalAdmissionV1
from scripts.windows_fence_foundation.win32_fs import _access_mask_can_mutate

SHA = "a" * 64
OTHER_SHA = "b" * 64
OWNER = "f" * 64
DIR_ACL = "d" * 64
FILE_ACL = "e" * 64
WRITER = "f" * 64
WIN32_FS_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "scripts/windows_fence_foundation/win32_fs.py"
).read_text(encoding="utf-8")


def _state() -> dict[str, object]:
    authority = {
        "windows_fence_released": False,
        "authority_restore_allowed": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "send_order_authorized": False,
        "cancel_order_authorized": False,
        "countable_forward": False,
    }
    value: dict[str, object] = {
        "schema_version": "windows_rpc_durable_fence_state_v1",
        "purpose": "persist_windows_rpc_fail_closed_fence_genesis",
        "state_id": "",
        "state_core_sha256": "",
        "store_id": f"windows-fence-store-{SHA}",
        "store_format_version": 1,
        "state_sequence": 1,
        "previous_state_raw_sha256": None,
        "install_attempt_id": f"windows-fence-install-{SHA}",
        "attempt_nonce_sha256": SHA,
        "bundle_sha256": SHA,
        "install_manifest_id": f"windows-fence-install-manifest-{SHA}",
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_id": f"windows-fence-preflight-{SHA}",
        "preflight_receipt_raw_sha256": SHA,
        "service_name": "VnpyRpcService",
        "store_path_sha256": SHA,
        "store_volume_serial": "A1B2C3D4",
        "store_volume_identity_sha256": SHA,
        "extension_sha256": SHA,
        "launcher_sha256": SHA,
        "assembly_sha256": SHA,
        "config_sha256": SHA,
        "fence_epoch": 1,
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token": None,
        "active_token": None,
        "authority_grant": None,
        "staged_token_inventory": [],
        "active_token_inventory": [],
        "grant_inventory": [],
        "expected_account_sha256": SHA,
        "raw_account_row_sha256": SHA,
        "gateway_name": "CTP",
        "gateway_scope_sha256": SHA,
        "preflight_server_instance_id": "windows-rpc-server-0001",
        "preflight_fact_generation": 7,
        "preflight_execution_facts_sha256": SHA,
        "pending_send_outcomes": 0,
        "active_orders": [],
        "created_at_utc": "2026-08-05T00:00:12Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "authority": authority,
    }
    core = hashlib.sha256(
        canonical_json_bytes(
            {
                key: item
                for key, item in value.items()
                if key not in {"state_id", "state_core_sha256"}
            }
        )
    ).hexdigest()
    value["state_core_sha256"] = core
    value["state_id"] = f"windows-fence-state-{core}"
    return value


def _expectation() -> StoreExpectation:
    return StoreExpectation(
        service_name="VnpyRpcService",
        store_id=f"windows-fence-store-{SHA}",
        store_path_sha256=SHA,
        store_volume_serial="A1B2C3D4",
        store_volume_identity_sha256=SHA,
        owner_sid_sha256=OWNER,
        directory_acl_sddl_sha256=DIR_ACL,
        state_acl_sddl_sha256=FILE_ACL,
    )


class Facts:
    def __init__(self, root: Path, expectation: StoreExpectation) -> None:
        self.root = root
        self.expectation = expectation
        self.overrides: dict[str, dict[str, object]] = {}

    def inspect(self, path: Path) -> PathSecurityFacts:
        relative = path.relative_to(self.root).as_posix() if path != self.root else "."
        is_file = relative.startswith("states/") or relative == "HEAD"
        values: dict[str, object] = {
            "path_sha256": SHA if relative == "." else OTHER_SHA,
            "volume_serial": self.expectation.store_volume_serial,
            "volume_identity_sha256": self.expectation.store_volume_identity_sha256,
            "file_identity": relative,
            "owner_sid_sha256": OWNER,
            "acl_sddl_sha256": FILE_ACL if is_file else DIR_ACL,
            "unsafe_write_principals": (),
            "write_principal_sid_sha256s": (WRITER,),
            "regular_file": is_file,
            "directory": not is_file,
            "reparse_point": False,
            "parent_chain_reparse_free": True,
            "hardlink_count": 1,
            "alternate_data_streams": False,
            "dacl_protected": True,
            "inherited_ace_count": 0,
        }
        values.update(self.overrides.get(relative, {}))
        return PathSecurityFacts(**values)  # type: ignore[arg-type]

    def read_file(
        self, path: Path, *, maximum_bytes: int = 1024 * 1024
    ) -> SecureFileRead:
        raw = path.read_bytes()
        if len(raw) > maximum_bytes:
            raise OSError("too large")
        return SecureFileRead(raw=raw, facts=self.inspect(path))

    def list_directory(self, path: Path) -> SecureDirectoryInventory:
        return SecureDirectoryInventory(
            names=tuple(sorted(item.name for item in path.iterdir())),
            facts=self.inspect(path),
        )

    def resolve_service_sid_sha256(self, service_name: str) -> str:
        assert service_name == "VnpyRpcService"
        return WRITER


def _store(tmp_path: Path) -> tuple[Path, StoreExpectation, Facts, bytes]:
    root = tmp_path / "fence"
    states = root / "states"
    states.mkdir(parents=True)
    raw = canonical_json_bytes(_state())
    digest = hashlib.sha256(raw).hexdigest()
    filename = f"00000000000000000001.{digest}.json"
    (states / filename).write_bytes(raw)
    expected = _expectation()
    return root, expected, Facts(root, expected), raw


def test_strict_state_accepts_only_exact_canonical_frozen_none() -> None:
    raw = canonical_json_bytes(_state())
    parsed = parse_frozen_none_state(raw)
    assert parsed.value["admission_state"] == "FROZEN"
    assert parsed.value["token_state"] == "NONE"

    with pytest.raises(StoreContractError, match="STATE_RAW_NOT_CANONICAL"):
        parse_frozen_none_state(raw + b"\n")


def test_windows_delete_child_is_a_mutating_acl_permission() -> None:
    assert _access_mask_can_mutate(0x40) is True
    assert _access_mask_can_mutate(0x00120089) is False


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        (
            "schema_version",
            "windows_rpc_durable_fence_state_v2",
            "STATE_SCHEMA_VERSION_UNSUPPORTED",
        ),
        ("store_format_version", 2, "STORE_FORMAT_VERSION_UNSUPPORTED"),
        ("state_sequence", 2, "STATE_SEQUENCE_UNSUPPORTED"),
        ("admission_state", "ACTIVE", "AUTHORITY_OR_TOKEN"),
        ("token_state", "STAGED", "AUTHORITY_OR_TOKEN"),
        ("active_token", {}, "AUTHORITY_OR_TOKEN"),
    ],
)
def test_unknown_or_non_foundation_state_is_rejected(
    field: str, value: object, code: str
) -> None:
    candidate = _state()
    candidate[field] = value
    with pytest.raises(StoreContractError, match=code):
        parse_frozen_none_state(canonical_json_bytes(candidate))


@pytest.mark.parametrize("field", ["store_format_version", "state_sequence"])
def test_boolean_is_not_accepted_as_integer_constant(field: str) -> None:
    candidate = _state()
    candidate[field] = True
    with pytest.raises(StoreContractError, match="UNSUPPORTED"):
        parse_frozen_none_state(canonical_json_bytes(candidate))


@pytest.mark.parametrize(
    "created_at",
    [
        "2026-08-05Z",
        "2026-08-05 00:00:12Z",
        "2026-08-05T00:00:12,1Z",
        "2026-13-05T00:00:12Z",
    ],
)
def test_created_at_is_strict_utc_rfc3339(created_at: str) -> None:
    candidate = _state()
    candidate["created_at_utc"] = created_at
    with pytest.raises(StoreContractError, match="STATE_SCHEMA_INVALID"):
        parse_frozen_none_state(canonical_json_bytes(candidate))


def test_recovery_uses_inventory_and_treats_missing_head_as_cache(
    tmp_path: Path,
) -> None:
    root, expected, facts, raw = _store(tmp_path)
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.ready is True
    assert result.reason == "FOUNDATION_FROZEN_NONE_RECOVERED"
    assert result.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.head_status == "MISSING_RECONSTRUCTIBLE"


def test_recovery_is_directly_consumable_by_final_admission(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    recovery = recover_frozen_none_store(root, expected=expected, fs=facts)

    admission = WindowsRpcFinalAdmissionV1(recovery)

    assert recovery.state is not None
    assert admission.projection.state_id == recovery.state["state_id"]


def test_stale_head_does_not_override_inventory(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    (root / "HEAD").write_bytes(b"stale")
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.ready is True
    assert result.head_status == "STALE_RECONSTRUCTIBLE"


@pytest.mark.parametrize(
    ("relative", "override", "code"),
    [
        (".", {"owner_sid_sha256": OTHER_SHA}, "STORE_OWNER_MISMATCH"),
        ("states", {"dacl_protected": False}, "STORE_PATH_OR_ACL_UNSAFE"),
        ("states", {"inherited_ace_count": 1}, "STORE_PATH_OR_ACL_UNSAFE"),
        ("states", {"reparse_point": True}, "STORE_PATH_OR_ACL_UNSAFE"),
        ("STATE", {"hardlink_count": 2}, "STORE_STATE_FILE_TYPE_INVALID"),
        ("STATE", {"alternate_data_streams": True}, "STORE_STATE_FILE_TYPE_INVALID"),
        (
            "STATE",
            {"write_principal_sid_sha256s": (OTHER_SHA,)},
            "STORE_ACL_WRITER_POLICY_MISMATCH",
        ),
    ],
)
def test_acl_and_path_fact_mismatches_fail_closed(
    tmp_path: Path, relative: str, override: dict[str, object], code: str
) -> None:
    root, expected, facts, _ = _store(tmp_path)
    if relative == "STATE":
        relative = f"states/{next((root / 'states').iterdir()).name}"
    facts.overrides[relative] = override
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.ready is False
    assert result.reason == code


def test_expected_owner_pin_must_be_the_resolved_service_sid(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    result = recover_frozen_none_store(
        root,
        expected=replace(expected, owner_sid_sha256=OTHER_SHA),
        fs=facts,
    )
    assert result.ready is False
    assert result.reason == "STORE_EXPECTED_OWNER_NOT_SERVICE_SID"


def test_extra_inventory_entry_and_bad_filename_fail_closed(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    (root / "states" / "orphan.tmp").write_bytes(b"")
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.reason == "STORE_INVENTORY_NOT_SINGLE_GENESIS"


def test_raw_filename_binding_and_store_identity_fail_closed(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    original = next((root / "states").iterdir())
    original.rename(original.with_name(f"00000000000000000001.{OTHER_SHA}.json"))
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.reason == "STORE_STATE_FILENAME_RAW_SHA256_MISMATCH"

    original = next((root / "states").iterdir())
    original.rename(
        original.with_name(
            original.name.replace(
                OTHER_SHA, hashlib.sha256(original.read_bytes()).hexdigest()
            )
        )
    )
    result = recover_frozen_none_store(
        root,
        expected=replace(expected, store_id=f"windows-fence-store-{OTHER_SHA}"),
        fs=facts,
    )
    assert result.reason == "SERVICE_OR_STORE_IDENTITY_MISMATCH"


def test_duplicate_key_and_truncation_fail_closed(tmp_path: Path) -> None:
    root, expected, facts, raw = _store(tmp_path)
    state_file = next((root / "states").iterdir())
    state_file.write_bytes(raw[:-1])
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.ready is False
    assert result.reason == "STATE_JSON_INVALID"

    duplicate = b'{"schema_version":"x","schema_version":"y"}'
    with pytest.raises(StoreContractError, match="FOUNDATION_JSON_DUPLICATE_KEY"):
        parse_frozen_none_state(duplicate)


def test_missing_store_is_not_created(tmp_path: Path) -> None:
    root = tmp_path / "missing"
    facts = Facts(root, _expectation())
    result = recover_frozen_none_store(root, expected=_expectation(), fs=facts)
    assert result.ready is False
    assert result.reason == "STORE_MISSING"
    assert not root.exists()


def test_adapter_reported_handle_read_failure_fails_closed(tmp_path: Path) -> None:
    root, expected, base, _ = _store(tmp_path)

    class ChangingFacts:
        def resolve_service_sid_sha256(self, service_name: str) -> str:
            return base.resolve_service_sid_sha256(service_name)

        def inspect(self, path: Path) -> PathSecurityFacts:
            return base.inspect(path)

        def list_directory(self, path: Path) -> SecureDirectoryInventory:
            return base.list_directory(path)

        def read_file(
            self, path: Path, *, maximum_bytes: int = 1024 * 1024
        ) -> SecureFileRead:
            raise OSError("identity changed during handle read")

    result = recover_frozen_none_store(root, expected=expected, fs=ChangingFacts())
    assert result.ready is False
    assert result.reason == "STORE_IO_ERROR"


def test_unknown_root_entry_fails_closed(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    (root / "publish.tmp").write_bytes(b"")
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.reason == "STORE_ROOT_INVENTORY_INVALID"


def test_inventory_change_during_recovery_fails_closed(tmp_path: Path) -> None:
    root, expected, base, _ = _store(tmp_path)

    class ChangingInventory(Facts):
        state_inventory_reads = 0

        def list_directory(self, path: Path) -> SecureDirectoryInventory:
            inventory = base.list_directory(path)
            if path == root / "states":
                self.state_inventory_reads += 1
                if self.state_inventory_reads == 2:
                    return replace(inventory, names=(*inventory.names, "publish.tmp"))
            return inventory

    result = recover_frozen_none_store(
        root,
        expected=expected,
        fs=ChangingInventory(root, expected),
    )
    assert result.ready is False
    assert result.reason == "STORE_INVENTORY_CHANGED_DURING_RECOVERY"


def test_oversized_state_fails_closed(tmp_path: Path) -> None:
    root, expected, _, _ = _store(tmp_path)

    class OversizedFacts(Facts):
        def read_file(
            self, path: Path, *, maximum_bytes: int = 1024 * 1024
        ) -> SecureFileRead:
            raise OSError("foundation state exceeds size bound")

    result = recover_frozen_none_store(
        root, expected=expected, fs=OversizedFacts(root, expected)
    )
    assert result.reason == "STORE_IO_ERROR"


def test_unsafe_head_is_ignored_without_being_read(tmp_path: Path) -> None:
    root, expected, facts, _ = _store(tmp_path)
    (root / "HEAD").write_bytes(b"do-not-read")
    facts.overrides["HEAD"] = {"reparse_point": True}
    result = recover_frozen_none_store(root, expected=expected, fs=facts)
    assert result.ready is True
    assert result.head_status == "UNSAFE_RECONSTRUCTIBLE"


def test_windows_relative_unicode_strings_use_explicit_lpwstr_casts() -> None:
    assert WIN32_FS_SOURCE.count("ctypes.cast(buffer, wintypes.LPWSTR)") == 2
    assert WIN32_FS_SOURCE.count("len(encoded_name) + 2") == 2


def test_windows_ntcreatefile_static_signature_and_calls_are_eleven_arguments() -> None:
    tree = ast.parse(WIN32_FS_SOURCE)
    signature = next(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Attribute)
        and isinstance(node.targets[0].value, ast.Attribute)
        and isinstance(node.targets[0].value.value, ast.Name)
        and node.targets[0].value.value.id == "_ntdll"
        and node.targets[0].value.attr == "NtCreateFile"
        and node.targets[0].attr == "argtypes"
    )
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "_ntdll"
        and node.func.attr == "NtCreateFile"
    ]

    assert isinstance(signature, ast.List)
    assert len(signature.elts) == 11
    assert len(calls) == 2
    assert all(len(call.args) == 11 and not call.keywords for call in calls)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows ctypes structures")
def test_windows_relative_unicode_string_accepts_explicit_lpwstr_buffer() -> None:
    import ctypes
    from ctypes import wintypes

    from scripts.windows_fence_foundation import win32_fs

    name = "nonce.json"
    encoded_name = name.encode("utf-16-le")
    buffer = ctypes.create_unicode_buffer(name)
    unicode_name = win32_fs._UNICODE_STRING(
        len(encoded_name),
        len(encoded_name) + 2,
        ctypes.cast(buffer, wintypes.LPWSTR),
    )
    assert unicode_name.buffer == name
    assert unicode_name.length == len(encoded_name)
    assert unicode_name.maximum_length == len(encoded_name) + 2


@pytest.mark.skipif(os.name != "nt", reason="requires Windows ntdll binding")
def test_windows_ntcreatefile_runtime_signature_has_eleven_arguments() -> None:
    import ctypes

    from scripts.windows_fence_foundation import win32_fs

    assert len(win32_fs._ntdll.NtCreateFile.argtypes) == 11
    assert win32_fs._ntdll.NtCreateFile.restype is ctypes.c_long


@pytest.mark.skipif(os.name != "nt", reason="requires Win32 handle and ACL APIs")
def test_windows_adapter_handle_smoke(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    state.write_bytes(b"{}")
    adapter = WindowsFilesystemFactsAdapter()

    inventory = adapter.list_directory(tmp_path)
    secure_read = adapter.read_file(state)

    assert inventory.names == ("state.json",)
    assert inventory.facts.directory is True
    assert secure_read.raw == b"{}"
    assert secure_read.facts.regular_file is True
    assert secure_read.facts.hardlink_count == 1
    assert secure_read.facts.file_identity
    assert secure_read.facts.owner_sid_sha256
    assert secure_read.facts.acl_sddl_sha256
    assert len(adapter.resolve_service_sid_sha256("EventLog")) == 64
