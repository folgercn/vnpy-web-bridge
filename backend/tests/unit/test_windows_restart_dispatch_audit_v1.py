from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import pytest

from scripts.windows_fence_foundation.installer_windows_v1 import (
    WindowsFinalInstallerError,
)
from scripts.windows_fence_foundation.native_windows_installer_host_v1 import (
    NativeWindowsFenceInstallerHostV1,
)
from scripts.windows_fence_foundation.restart_dispatch_audit_v1 import (
    RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE,
    RESTART_DISPATCH_AUDIT_STATE,
    RestartDispatchAuditError,
    build_restart_dispatch_audit_v1,
    persist_restart_dispatch_audit_v1,
    readback_restart_dispatch_audit_v1,
)

CAPTURED_AT = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)


def _observed_facts() -> dict:
    return {
        "operation_id": "windows-service-restart-0001",
        "restart_dispatch_nonce": "dispatch-nonce-0001",
        "caller": {"sid": "S-1-5-18", "pid": 4321, "session_id": 0},
        "scm_calls": {
            "stop": {
                "attempted": True,
                "started_at": CAPTURED_AT,
                "completed_at": CAPTURED_AT + timedelta(seconds=2),
                "result": "SUCCESS",
            },
            "start": {
                "attempted": True,
                "started_at": CAPTURED_AT + timedelta(seconds=3),
                "completed_at": CAPTURED_AT + timedelta(seconds=5),
                "result": "SUCCESS",
            },
        },
    }


def test_restart_dispatch_audit_canonicalizes_observed_scm_facts() -> None:
    raw = build_restart_dispatch_audit_v1(
        install_attempt_id="windows-fence-install-0001",
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )
    value = json.loads(raw)

    assert raw == json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    assert value["policy"] == "OBSERVED_SCM_FACTS"
    assert value["restart_dispatched"] is True
    assert value["observed_scm_facts"] == {
        "operation_id": "windows-service-restart-0001",
        "restart_dispatch_nonce_sha256": hashlib.sha256(
            b"dispatch-nonce-0001"
        ).hexdigest(),
        "caller": {"sid": "S-1-5-18", "pid": 4321, "session_id": 0},
        "scm_calls": {
            "stop": {
                "attempted": True,
                "started_at_utc": "2030-01-01T12:00:00Z",
                "completed_at_utc": "2030-01-01T12:00:02Z",
                "result": "SUCCESS",
            },
            "start": {
                "attempted": True,
                "started_at_utc": "2030-01-01T12:00:03Z",
                "completed_at_utc": "2030-01-01T12:00:05Z",
                "result": "SUCCESS",
            },
        },
    }


@pytest.mark.parametrize(
    ("policy", "facts", "error"),
    [
        ("OBSERVED_SCM_FACTS", None, "OBSERVED_FACTS_MISSING"),
        (
            "OBSERVED_SCM_FACTS",
            {"operation_id": "windows-service-restart-0001"},
            "OBSERVED_FACTS_MISSING",
        ),
        (
            "OBSERVED_SCM_FACTS",
            {
                **_observed_facts(),
                "scm_calls": {"stop": _observed_facts()["scm_calls"]["stop"]},
            },
            "SCM_CALL_FACTS_MISSING",
        ),
        ("DRY_RUN_NON_EXECUTING", _observed_facts(), "DRY_RUN_FACTS_FORBIDDEN"),
    ],
)
def test_restart_dispatch_audit_missing_or_invalid_facts_fail_closed(
    policy: str, facts: dict | None, error: str
) -> None:
    with pytest.raises(RestartDispatchAuditError, match=error):
        build_restart_dispatch_audit_v1(
            install_attempt_id="windows-fence-install-0001",
            policy=policy,  # type: ignore[arg-type]
            observed_scm_facts=facts,
            captured_at=CAPTURED_AT,
        )


def test_restart_dispatch_audit_dry_run_is_explicit_and_does_not_fake_scm_result() -> (
    None
):
    value = json.loads(
        build_restart_dispatch_audit_v1(
            install_attempt_id="windows-fence-install-0001",
            policy="DRY_RUN_NON_EXECUTING",
            observed_scm_facts=None,
            captured_at=CAPTURED_AT,
        )
    )

    assert value["restart_dispatched"] is False
    assert value["observed_scm_facts"] is None
    assert "scm_calls" not in value


def test_restart_dispatch_audit_persists_raw_before_event5_and_recovers_exact_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = NativeWindowsFenceInstallerHostV1()
    install_attempt_id = "windows-fence-install-0001"
    calls: list[tuple[str, object]] = []
    expected_raw = build_restart_dispatch_audit_v1(
        install_attempt_id=install_attempt_id,
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )

    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "is_real_windows_host",
        property(lambda _host: True),
    )

    def append_install_event_create_only(
        _host: NativeWindowsFenceInstallerHostV1,
        *,
        install_attempt_id: str,
        event_sequence: int,
        state: str,
        details_sha256: str,
    ) -> str:
        calls.append(
            (
                "event5",
                {
                    "install_attempt_id": install_attempt_id,
                    "event_sequence": event_sequence,
                    "state": state,
                    "details_sha256": details_sha256,
                },
            )
        )
        return "event-created"

    def persist_restart_dispatch_audit_raw_create_only(
        _host: NativeWindowsFenceInstallerHostV1,
        *,
        install_attempt_id: str,
        raw: bytes,
    ) -> str:
        calls.append(("raw", (install_attempt_id, raw)))
        return hashlib.sha256(raw).hexdigest()

    def read_restart_dispatch_audit_raw_verified(
        _host: NativeWindowsFenceInstallerHostV1, *, install_attempt_id: str
    ) -> bytes:
        calls.append(("readback", install_attempt_id))
        return expected_raw

    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "append_install_event_create_only",
        append_install_event_create_only,
    )
    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "persist_restart_dispatch_audit_raw_create_only",
        persist_restart_dispatch_audit_raw_create_only,
    )
    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "read_restart_dispatch_audit_raw_verified",
        read_restart_dispatch_audit_raw_verified,
    )

    raw = persist_restart_dispatch_audit_v1(
        native_host=host,
        install_attempt_id=install_attempt_id,
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )

    assert calls == [
        ("raw", (install_attempt_id, raw)),
        (
            "event5",
            {
                "install_attempt_id": install_attempt_id,
                "event_sequence": RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE,
                "state": RESTART_DISPATCH_AUDIT_STATE,
                "details_sha256": hashlib.sha256(raw).hexdigest(),
            },
        ),
        ("readback", install_attempt_id),
    ]


def test_restart_dispatch_audit_raw_native_journal_is_fixed_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = NativeWindowsFenceInstallerHostV1()
    host._journal_acl_sddl = "D:PA"
    install_attempt_id = "windows-fence-install-0001"
    raw = build_restart_dispatch_audit_v1(
        install_attempt_id=install_attempt_id,
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )
    journal_root = tmp_path / "installer-journal-v1"
    host._journal_root = journal_root
    opened_parents: list[Path] = []
    writes: list[tuple[Path, str]] = []
    reads: list[tuple[Path, str]] = []
    contents: dict[Path, bytes] = {}

    class FakeOpenedParent:
        def __init__(self, path: Path) -> None:
            self.path = path

        def __enter__(self) -> Self:
            opened_parents.append(self.path)
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def assert_named_path_is_opened_parent(self) -> None:
            return None

    class FakeFilesystem:
        def open_directory_anchor(self, path: Path) -> FakeOpenedParent:
            return FakeOpenedParent(path)

        def write_file_create_only_relative_to_opened_parent(
            self,
            *,
            parent: FakeOpenedParent,
            name: str,
            raw: bytes,
            protected_sddl: str,
        ) -> SimpleNamespace:
            assert protected_sddl == "D:PA"
            assert name == "restart-dispatch-audit.raw"
            path = parent.path / name
            writes.append((parent.path, name))
            if path in contents:
                raise FileExistsError(path)
            contents[path] = raw
            return SimpleNamespace(raw=raw)

        def read_file_relative_to_opened_parent(
            self, *, parent: FakeOpenedParent, name: str
        ) -> SimpleNamespace:
            assert name in {"05.json", "restart-dispatch-audit.raw"}
            path = parent.path / name
            reads.append((parent.path, name))
            return SimpleNamespace(raw=contents[path])

    monkeypatch.setattr(host, "_require_windows", lambda: None)
    monkeypatch.setattr(
        host,
        "_secure_install_event_root",
        lambda *, install_attempt_id, create: journal_root / install_attempt_id,
    )
    monkeypatch.setattr(
        "scripts.windows_fence_foundation.native_windows_installer_host_v1.WindowsFilesystemFactsAdapter",
        FakeFilesystem,
    )

    assert (
        host.persist_restart_dispatch_audit_raw_create_only(
            install_attempt_id=install_attempt_id, raw=raw
        )
        == hashlib.sha256(raw).hexdigest()
    )
    raw_path = journal_root / install_attempt_id / "restart-dispatch-audit.raw"
    assert writes == [(raw_path.parent, raw_path.name)]

    with pytest.raises(WindowsFinalInstallerError, match="CREATE_ONLY_CONFLICT"):
        host.persist_restart_dispatch_audit_raw_create_only(
            install_attempt_id=install_attempt_id, raw=raw
        )
    with pytest.raises(WindowsFinalInstallerError, match="INSTALL_ATTEMPT_ID_INVALID"):
        host.persist_restart_dispatch_audit_raw_create_only(
            install_attempt_id="../foreign-attempt", raw=raw
        )
    with pytest.raises(
        WindowsFinalInstallerError, match="RAW_INSTALL_ATTEMPT_MISMATCH"
    ):
        host.persist_restart_dispatch_audit_raw_create_only(
            install_attempt_id="windows-fence-install-0002", raw=raw
        )
    assert writes == [(raw_path.parent, raw_path.name)] * 2
    assert opened_parents == [raw_path.parent, raw_path.parent]

    event_path = journal_root / install_attempt_id / "05.json"
    contents[event_path] = json.dumps(
        {
            "schema_version": "windows_fence_installer_event_v1",
            "install_attempt_id": install_attempt_id,
            "event_sequence": 5,
            "state": "RESTART_DISPATCHED_FROZEN",
            "details_sha256": hashlib.sha256(raw).hexdigest(),
        }
    ).encode()
    assert (
        host.read_restart_dispatch_audit_raw_verified(
            install_attempt_id=install_attempt_id
        )
        == raw
    )
    assert reads == [
        (raw_path.parent, "05.json"),
        (raw_path.parent, raw_path.name),
    ]

    contents[event_path] = contents[event_path].replace(b"a", b"b", 1)
    with pytest.raises(WindowsFinalInstallerError, match="EVENT5_HASH_MISMATCH"):
        host.read_restart_dispatch_audit_raw_verified(
            install_attempt_id=install_attempt_id
        )


def test_restart_dispatch_audit_reparse_attempt_root_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = NativeWindowsFenceInstallerHostV1()
    host._journal_acl_sddl = "D:PA"
    install_attempt_id = "windows-fence-install-0001"
    host._journal_root = tmp_path / "installer-journal-v1"
    raw = build_restart_dispatch_audit_v1(
        install_attempt_id=install_attempt_id,
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )
    monkeypatch.setattr(host, "_require_windows", lambda: None)
    monkeypatch.setattr(
        host,
        "_secure_install_event_root",
        lambda *, install_attempt_id, create: tmp_path / install_attempt_id,
    )

    class ReparseFilesystem:
        def open_directory_anchor(self, _path: Path) -> None:
            raise OSError("unsafe opened parent directory")

    monkeypatch.setattr(
        "scripts.windows_fence_foundation.native_windows_installer_host_v1.WindowsFilesystemFactsAdapter",
        ReparseFilesystem,
    )

    with pytest.raises(WindowsFinalInstallerError, match="RAW_WRITE_FAILED"):
        host.persist_restart_dispatch_audit_raw_create_only(
            install_attempt_id=install_attempt_id, raw=raw
        )


def test_restart_dispatch_audit_duplicate_raw_conflict_stops_before_event5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = NativeWindowsFenceInstallerHostV1()
    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "is_real_windows_host",
        property(lambda _host: True),
    )
    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "persist_restart_dispatch_audit_raw_create_only",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            WindowsFinalInstallerError(
                "RESTART_DISPATCH_AUDIT_RAW_CREATE_ONLY_CONFLICT"
            )
        ),
    )
    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "append_install_event_create_only",
        lambda *_args, **_kwargs: pytest.fail("Event5 must not follow raw conflict"),
    )

    with pytest.raises(RestartDispatchAuditError, match="RAW_CREATE_ONLY_CONFLICT"):
        persist_restart_dispatch_audit_v1(
            native_host=host,
            install_attempt_id="windows-fence-install-0001",
            policy="OBSERVED_SCM_FACTS",
            observed_scm_facts=_observed_facts(),
            captured_at=CAPTURED_AT,
        )


def test_restart_dispatch_audit_readback_requires_native_windows_host() -> None:
    with pytest.raises(RestartDispatchAuditError, match="NATIVE_WINDOWS_REQUIRED"):
        readback_restart_dispatch_audit_v1(
            native_host=NativeWindowsFenceInstallerHostV1(),
            install_attempt_id="windows-fence-install-0001",
        )


def test_restart_dispatch_audit_rejects_fake_native_host() -> None:
    with pytest.raises(RestartDispatchAuditError, match="NATIVE_HOST_REQUIRED"):
        persist_restart_dispatch_audit_v1(
            native_host=object(),  # type: ignore[arg-type]
            install_attempt_id="windows-fence-install-0001",
            policy="OBSERVED_SCM_FACTS",
            observed_scm_facts=_observed_facts(),
            captured_at=CAPTURED_AT,
        )


def test_restart_dispatch_audit_requires_a_real_windows_host() -> None:
    with pytest.raises(RestartDispatchAuditError, match="NATIVE_WINDOWS_REQUIRED"):
        persist_restart_dispatch_audit_v1(
            native_host=NativeWindowsFenceInstallerHostV1(),
            install_attempt_id="windows-fence-install-0001",
            policy="OBSERVED_SCM_FACTS",
            observed_scm_facts=_observed_facts(),
            captured_at=CAPTURED_AT,
        )


def test_restart_dispatch_audit_uninitialized_native_host_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        NativeWindowsFenceInstallerHostV1,
        "is_real_windows_host",
        property(lambda _host: True),
    )

    with pytest.raises(
        RestartDispatchAuditError,
        match="NATIVE_PERSISTENCE_FAILED:INSTALL_JOURNAL_NOT_INITIALIZED",
    ):
        persist_restart_dispatch_audit_v1(
            native_host=NativeWindowsFenceInstallerHostV1(),
            install_attempt_id="windows-fence-install-0001",
            policy="OBSERVED_SCM_FACTS",
            observed_scm_facts=_observed_facts(),
            captured_at=CAPTURED_AT,
        )
