"""Create-only audit facts for a deliberately non-executing restart dispatch.

This module has no SCM dependency and cannot stop or start a service. Native
callers must supply facts observed from the actual caller token/process;
missing facts fail closed instead of receiving defaults.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .contracts import canonical_json_bytes
from .installer_windows_v1 import WindowsFinalInstallerError

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise WindowsFinalInstallerError(f"RESTART_AUDIT_{field.upper()}_INVALID")
    return value


def _caller(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != {"sid", "pid", "session_id"}:
        raise WindowsFinalInstallerError("RESTART_AUDIT_CALLER_FACTS_MISSING")
    sid = value["sid"]
    pid = value["pid"]
    session_id = value["session_id"]
    if (
        not isinstance(sid, str)
        or not sid
        or isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid < 1
        or isinstance(session_id, bool)
        or not isinstance(session_id, int)
        or session_id < 0
    ):
        raise WindowsFinalInstallerError("RESTART_AUDIT_CALLER_FACTS_MISSING")
    return {"sid": sid, "pid": pid, "session_id": session_id}


def build_restart_dispatch_audit_v1(
    *,
    install_attempt_id: str,
    service_control_operation_id: str,
    restart_dispatch_nonce: str,
    caller: Mapping[str, Any],
    captured_at: datetime,
) -> bytes:
    """Build canonical evidence for an intentionally unexecuted dispatch.

    SCM timestamps/results are null because neither SCM call is made. The
    policy result documents non-execution; it is not a simulated SCM response.
    """

    if captured_at.tzinfo is None or captured_at.utcoffset() is None:
        raise WindowsFinalInstallerError("RESTART_AUDIT_CLOCK_INVALID")
    nonce = _identifier(restart_dispatch_nonce, "restart_dispatch_nonce")
    payload = {
        "schema_version": "windows_fence_restart_dispatch_audit_v1",
        "purpose": "record_non_executing_restart_dispatch_attempt",
        "install_attempt_id": _identifier(install_attempt_id, "install_attempt_id"),
        "service_control_operation_id": _identifier(
            service_control_operation_id, "service_control_operation_id"
        ),
        "restart_dispatch_nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
        "captured_at_utc": captured_at.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "caller": _caller(caller),
        "restart_dispatched": False,
        "scm_calls": {
            operation: {
                "attempted": False,
                "started_at_utc": None,
                "completed_at_utc": None,
                "result": "NOT_EXECUTED_POLICY_DISABLED",
            }
            for operation in ("stop", "start")
        },
    }
    return canonical_json_bytes(payload)


__all__ = ["build_restart_dispatch_audit_v1"]
