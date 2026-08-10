from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from scripts.windows_fence_foundation.restart_dispatch_audit_v1 import (
    RestartDispatchAuditError,
    build_restart_dispatch_audit_v1,
    emit_restart_dispatch_audit_v1,
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


def test_restart_dispatch_audit_emits_once_to_caller_owned_journal_seam() -> None:
    received: list[bytes] = []

    raw = emit_restart_dispatch_audit_v1(
        journal_append=received.append,
        install_attempt_id="windows-fence-install-0001",
        policy="OBSERVED_SCM_FACTS",
        observed_scm_facts=_observed_facts(),
        captured_at=CAPTURED_AT,
    )

    assert received == [raw]

    with pytest.raises(RestartDispatchAuditError, match="OBSERVED_FACTS_MISSING"):
        emit_restart_dispatch_audit_v1(
            journal_append=received.append,
            install_attempt_id="windows-fence-install-0001",
            policy="OBSERVED_SCM_FACTS",
            observed_scm_facts=None,
            captured_at=CAPTURED_AT,
        )
    assert received == [raw]
