from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from scripts.windows_fence_foundation.restart_dispatch_audit_v1 import (
    RestartDispatchAuditError,
    build_restart_dispatch_audit_v1,
)


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
    assert (
        value["restart_dispatch_nonce_sha256"]
        == hashlib.sha256(b"dispatch-nonce-0001").hexdigest()
    )
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
    with pytest.raises(RestartDispatchAuditError, match="CALLER_FACTS_MISSING"):
        build_restart_dispatch_audit_v1(
            install_attempt_id="windows-fence-install-0001",
            service_control_operation_id="windows-service-restart-0001",
            restart_dispatch_nonce="dispatch-nonce-0001",
            caller=caller,
            captured_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
