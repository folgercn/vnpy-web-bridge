"""Read-only, inventory-authoritative recovery for a WF-1 foundation store."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    FrozenNoneState,
    StoreContractError,
    canonical_json_bytes,
    parse_frozen_none_state,
)
from .win32_fs import FilesystemFactsAdapter, PathSecurityFacts

STATE_DIRECTORY = "states"
HEAD_FILE = "HEAD"
STATE_FILENAME_RE = re.compile(
    r"^(?P<sequence>[0-9]{20})\.(?P<raw>[0-9a-f]{64})\.json$"
)


@dataclass(frozen=True)
class StoreExpectation:
    service_name: str
    store_id: str
    store_path_sha256: str
    store_volume_serial: str
    store_volume_identity_sha256: str
    owner_sid_sha256: str
    directory_acl_sddl_sha256: str
    state_acl_sddl_sha256: str


@dataclass(frozen=True)
class StoreRecovery:
    ready: bool
    reason: str
    state: FrozenNoneState | None = None
    raw_sha256: str | None = None
    inventory_sha256: str | None = None
    head_status: str = "UNREAD"


def _blocked(code: str, *, head_status: str = "UNREAD") -> StoreRecovery:
    return StoreRecovery(ready=False, reason=code, head_status=head_status)


def _security_error(
    facts: PathSecurityFacts,
    *,
    expectation: StoreExpectation,
    kind: str,
    service_writer_sid_sha256: str,
) -> str | None:
    if facts.path_sha256 != expectation.store_path_sha256 and kind == "root":
        return "STORE_PATH_IDENTITY_MISMATCH"
    if (
        facts.volume_serial != expectation.store_volume_serial
        or facts.volume_identity_sha256 != expectation.store_volume_identity_sha256
    ):
        return "STORE_VOLUME_IDENTITY_MISMATCH"
    if expectation.owner_sid_sha256 != service_writer_sid_sha256:
        return "STORE_EXPECTED_OWNER_NOT_SERVICE_SID"
    if facts.owner_sid_sha256 != service_writer_sid_sha256:
        return "STORE_OWNER_MISMATCH"
    if facts.write_principal_sid_sha256s != (service_writer_sid_sha256,):
        return "STORE_ACL_WRITER_POLICY_MISMATCH"
    expected_acl = (
        expectation.directory_acl_sddl_sha256
        if kind in {"root", "directory"}
        else expectation.state_acl_sddl_sha256
    )
    if facts.acl_sddl_sha256 != expected_acl:
        return "STORE_ACL_MISMATCH"
    if (
        facts.reparse_point
        or not facts.parent_chain_reparse_free
        or facts.unsafe_write_principals
        or not facts.dacl_protected
        or facts.inherited_ace_count != 0
    ):
        return "STORE_PATH_OR_ACL_UNSAFE"
    if kind in {"root", "directory"} and not facts.directory:
        return "STORE_DIRECTORY_TYPE_INVALID"
    if kind == "state" and (
        not facts.regular_file
        or facts.hardlink_count != 1
        or facts.alternate_data_streams
    ):
        return "STORE_STATE_FILE_TYPE_INVALID"
    return None


def recover_frozen_none_store(
    root: Path,
    *,
    expected: StoreExpectation,
    fs: FilesystemFactsAdapter,
) -> StoreRecovery:
    """Recover exactly one immutable genesis state without writing anything."""
    root = root.absolute()
    states = root / STATE_DIRECTORY
    try:
        service_writer_sid_sha256 = fs.resolve_service_sid_sha256(expected.service_name)
        root_inventory = fs.list_directory(root)
        root_facts = root_inventory.facts
        error = _security_error(
            root_facts,
            expectation=expected,
            kind="root",
            service_writer_sid_sha256=service_writer_sid_sha256,
        )
        if error:
            return _blocked(error)
        root_names = set(root_inventory.names)
        if STATE_DIRECTORY not in root_names or not root_names <= {
            STATE_DIRECTORY,
            HEAD_FILE,
        }:
            return _blocked("STORE_ROOT_INVENTORY_INVALID")
        inventory = fs.list_directory(states)
        states_facts = inventory.facts
        error = _security_error(
            states_facts,
            expectation=expected,
            kind="directory",
            service_writer_sid_sha256=service_writer_sid_sha256,
        )
        if error:
            return _blocked(error)

        if len(inventory.names) != 1:
            return _blocked("STORE_INVENTORY_NOT_SINGLE_GENESIS")
        state_name = inventory.names[0]
        state_path = states / state_name
        match = STATE_FILENAME_RE.fullmatch(state_name)
        if match is None or match.group("sequence") != "00000000000000000001":
            return _blocked("STORE_INVENTORY_FILENAME_INVALID")
        secure_read = fs.read_file(state_path)
        raw, state_facts = secure_read.raw, secure_read.facts
        error = _security_error(
            state_facts,
            expectation=expected,
            kind="state",
            service_writer_sid_sha256=service_writer_sid_sha256,
        )
        if error:
            return _blocked(error)
        state = parse_frozen_none_state(raw)
        if match.group("raw") != state.raw_sha256:
            return _blocked("STORE_STATE_FILENAME_RAW_SHA256_MISMATCH")
        value = state.value
        if (
            value["store_id"] != expected.store_id
            or value["store_path_sha256"] != expected.store_path_sha256
            or value["service_name"] != expected.service_name
        ):
            return _blocked("SERVICE_OR_STORE_IDENTITY_MISMATCH")
        if (
            value["store_volume_serial"] != expected.store_volume_serial
            or value["store_volume_identity_sha256"]
            != expected.store_volume_identity_sha256
        ):
            return _blocked("STORE_VOLUME_IDENTITY_MISMATCH")

        inventory_value = [
            {"filename": state_path.name, "raw_sha256": state.raw_sha256}
        ]
        inventory_sha256 = hashlib.sha256(
            canonical_json_bytes(inventory_value)
        ).hexdigest()
        head_status = _head_status(
            root / HEAD_FILE,
            state_path.name,
            state.raw_sha256,
            expected=expected,
            fs=fs,
            service_writer_sid_sha256=service_writer_sid_sha256,
        )
        final_root_inventory = fs.list_directory(root)
        final_state_inventory = fs.list_directory(states)
        if final_root_inventory != root_inventory or final_state_inventory != inventory:
            return _blocked("STORE_INVENTORY_CHANGED_DURING_RECOVERY")
        return StoreRecovery(
            ready=True,
            reason="FOUNDATION_FROZEN_NONE_RECOVERED",
            state=state,
            raw_sha256=state.raw_sha256,
            inventory_sha256=inventory_sha256,
            head_status=head_status,
        )
    except FileNotFoundError:
        return _blocked("STORE_MISSING")
    except PermissionError:
        return _blocked("STORE_UNREADABLE")
    except OSError:
        return _blocked("STORE_IO_ERROR")
    except StoreContractError as exc:
        return _blocked(exc.code)
    except Exception:  # noqa: BLE001 - recovery boundary must return fail-closed
        return _blocked("STORE_RECOVERY_INTERNAL_ERROR")


def _head_status(
    head: Path,
    filename: str,
    raw_sha256: str,
    *,
    expected: StoreExpectation,
    fs: FilesystemFactsAdapter,
    service_writer_sid_sha256: str,
) -> str:
    """HEAD is an untrusted cache; absence/staleness cannot override inventory."""
    try:
        secure_read = fs.read_file(head)
        error = _security_error(
            secure_read.facts,
            expectation=expected,
            kind="state",
            service_writer_sid_sha256=service_writer_sid_sha256,
        )
        if error:
            raise StoreContractError(error)
        raw = secure_read.raw
    except FileNotFoundError:
        return "MISSING_RECONSTRUCTIBLE"
    except PermissionError:
        return "UNREADABLE_RECONSTRUCTIBLE"
    except OSError:
        return "IO_ERROR_RECONSTRUCTIBLE"
    except StoreContractError:
        return "UNSAFE_RECONSTRUCTIBLE"
    expected = canonical_json_bytes(
        {
            "filename": filename,
            "raw_sha256": raw_sha256,
            "state_sequence": 1,
            "store_format_version": 1,
        }
    )
    if raw == expected:
        return "MATCHED"
    # Any present pointer that is not the exact cache is reported as stale. It
    # cannot select another state, because inventory remains authoritative.
    return "STALE_RECONSTRUCTIBLE"
