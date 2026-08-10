from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.windows_fence_foundation.installer_windows_v1 import (
    WindowsFinalInstallerError,
)
from scripts.windows_fence_foundation.restart_dispatch_audit_v1 import (
    build_restart_dispatch_audit_v1,
)


class _JournalFilesystem:
    def __init__(self) -> None:
        self.writes: list[tuple[Path, bytes, str]] = []

    def inspect(self, _path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            directory=True,
            reparse_point=False,
            parent_chain_reparse_free=True,
            hardlink_count=1,
            alternate_data_streams=False,
            dacl_protected=True,
            inherited_ace_count=0,
            unsafe_write_principals=(),
            owner_sid_sha256=hashlib.sha256(b"S-1-5-18").hexdigest(),
            acl_sddl_sha256=hashlib.sha256(b"O:SYD:PAI").hexdigest(),
        )

    def write_file_create_only(
        self, path: Path, *, raw: bytes, protected_sddl: str
    ) -> SimpleNamespace:
        self.writes.append((path, raw, protected_sddl))
        return SimpleNamespace(raw=raw)


def test_restart_dispatch_audit_uses_provided_caller_and_records_no_scm_call() -> None:
    raw = build_restart_dispatch_audit_v1(
        install_attempt_id="windows-fence-install-0001",
        service_control_operation_id="windows-service-restart-0001",
        restart_dispatch_nonce="dispatch-nonce-0001",
        caller={"sid": "S-1-5-18", "pid": 4321, "session_id": 0},
        captured_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    value = json.loads(raw)

    assert value["caller"] == {"sid": "S-1-5-18", "pid": 4321, "session_id": 0}
    assert value["restart_dispatch_nonce_sha256"] == hashlib.sha256(
        b"dispatch-nonce-0001"
    ).hexdigest()
    assert value["restart_dispatched"] is False
    assert value["scm_calls"] == {
        operation: {
            "attempted": False,
            "started_at_utc": None,
            "completed_at_utc": None,
            "result": "NOT_EXECUTED_POLICY_DISABLED",
        }
        for operation in ("stop", "start")
    }


@pytest.mark.parametrize("caller", [{}, {"sid": "S-1-5-18", "pid": 1}])
def test_restart_dispatch_audit_missing_caller_facts_fails_closed(caller: dict) -> None:
    with pytest.raises(WindowsFinalInstallerError, match="CALLER_FACTS_MISSING"):
        build_restart_dispatch_audit_v1(
            install_attempt_id="windows-fence-install-0001",
            service_control_operation_id="windows-service-restart-0001",
            restart_dispatch_nonce="dispatch-nonce-0001",
            caller=caller,
            captured_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )


def test_native_audit_writes_protected_journal_from_readonly_caller_facts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import scripts.windows_fence_foundation.native_windows_installer_host_v1 as native

    filesystem = _JournalFilesystem()
    monkeypatch.setattr(native, "WindowsFilesystemFactsAdapter", lambda: filesystem)
    host = native.NativeWindowsFenceInstallerHostV1(
        caller_facts_reader=lambda: {"sid": "S-1-5-18", "pid": 4321, "session_id": 0},
        clock=lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    host._journal_root = tmp_path
    host._journal_owner_sha256 = hashlib.sha256(b"S-1-5-18").hexdigest()
    host._journal_acl_sddl = "O:SYD:PAI"
    monkeypatch.setattr(host, "_require_windows", lambda: None)

    result = host.record_restart_dispatch_audit_create_only(
        install_attempt_id="windows-fence-install-0001",
        service_control_operation_id="windows-service-restart-0001",
        restart_dispatch_nonce="dispatch-nonce-0001",
    )

    assert len(result) == 64
    assert len(filesystem.writes) == 1
    path, raw, protected_sddl = filesystem.writes[0]
    assert path.parent == tmp_path / "windows-fence-install-0001"
    assert path.name.startswith("restart-dispatch-audit-")
    assert protected_sddl == "O:SYD:PAI"
    assert json.loads(raw)["caller"] == {
        "sid": "S-1-5-18",
        "pid": 4321,
        "session_id": 0,
    }
