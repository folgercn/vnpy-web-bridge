from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

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
    _append_restart_dispatch_audit_to_native_seam_v1,
    build_restart_dispatch_audit_v1,
    persist_restart_dispatch_audit_v1,
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


class _FakeNativeInstallEventSeam:
    def __init__(self) -> None:
        self.events: dict[tuple[str, int], dict[str, object]] = {}

    def append_install_event_create_only(
        self,
        *,
        install_attempt_id: str,
        event_sequence: int,
        state: str,
        details_sha256: str,
        reject_existing: bool = False,
    ) -> str:
        key = (install_attempt_id, event_sequence)
        if key in self.events and reject_existing:
            raise WindowsFinalInstallerError("INSTALL_EVENT_CREATE_ONLY_CONFLICT")
        if key in self.events:
            return "event-existing"
        self.events[key] = {
            "install_attempt_id": install_attempt_id,
            "event_sequence": event_sequence,
            "state": state,
            "details_sha256": details_sha256,
            "reject_existing": reject_existing,
        }
        return "event-created"


def _raw() -> bytes:
    return build_restart_dispatch_audit_v1(
        install_attempt_id="windows-fence-install-0001",
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )


def test_restart_dispatch_audit_native_seam_binds_canonical_raw_once() -> None:
    native_seam = _FakeNativeInstallEventSeam()
    install_attempt_id = "windows-fence-install-0001"
    raw = _raw()

    _append_restart_dispatch_audit_to_native_seam_v1(
        native_seam=native_seam,
        install_attempt_id=install_attempt_id,
        raw=raw,
    )

    assert native_seam.events == {
        (install_attempt_id, RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE): {
            "install_attempt_id": install_attempt_id,
            "event_sequence": RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE,
            "state": RESTART_DISPATCH_AUDIT_STATE,
            "details_sha256": hashlib.sha256(raw).hexdigest(),
            "reject_existing": True,
        }
    }


def test_restart_dispatch_audit_native_seam_duplicate_nonce_conflicts() -> None:
    native_seam = _FakeNativeInstallEventSeam()
    install_attempt_id = "windows-fence-install-0001"
    raw = _raw()

    _append_restart_dispatch_audit_to_native_seam_v1(
        native_seam=native_seam,
        install_attempt_id=install_attempt_id,
        raw=raw,
    )

    with pytest.raises(WindowsFinalInstallerError, match="CREATE_ONLY_CONFLICT"):
        _append_restart_dispatch_audit_to_native_seam_v1(
            native_seam=native_seam,
            install_attempt_id=install_attempt_id,
            raw=raw,
        )

    assert len(native_seam.events) == 1


def test_restart_dispatch_audit_rejects_fake_native_host() -> None:
    with pytest.raises(RestartDispatchAuditError, match="NATIVE_HOST_REQUIRED"):
        persist_restart_dispatch_audit_v1(
            native_host=_FakeNativeInstallEventSeam(),  # type: ignore[arg-type]
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
