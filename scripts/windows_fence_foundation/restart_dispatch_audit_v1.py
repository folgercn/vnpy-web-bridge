"""Canonical restart-dispatch facts with a native create-only journal adapter.

This module never opens a journal, starts a service, or stops a service. Its
only persistence path is the already-protected native installer-host event
seam.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from .contracts import canonical_json_bytes
from .installer_windows_v1 import WindowsFinalInstallerError
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_RESULT_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_SID_RE = re.compile(r"^S-\d+(?:-\d+)+$")

RestartDispatchAuditPolicy = Literal["OBSERVED_SCM_FACTS", "DRY_RUN_NON_EXECUTING"]
RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE = 5
RESTART_DISPATCH_AUDIT_STATE = "RESTART_DISPATCHED_FROZEN"


class NativeInstallEventCreateOnlySeam(Protocol):
    """The exact protected native installer-event persistence seam."""

    def append_install_event_create_only(
        self,
        *,
        install_attempt_id: str,
        event_sequence: int,
        state: str,
        details_sha256: str,
        reject_existing: bool = False,
    ) -> str: ...


class RestartDispatchAuditError(ValueError):
    """The restart-dispatch facts or journal seam were invalid."""


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise RestartDispatchAuditError(f"RESTART_AUDIT_{field.upper()}_INVALID")
    return value


def _timestamp(value: Any, field: str) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise RestartDispatchAuditError(f"RESTART_AUDIT_{field.upper()}_INVALID")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _caller(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"sid", "pid", "session_id"}:
        raise RestartDispatchAuditError("RESTART_AUDIT_CALLER_FACTS_MISSING")
    sid = value["sid"]
    pid = value["pid"]
    session_id = value["session_id"]
    if (
        not isinstance(sid, str)
        or _SID_RE.fullmatch(sid) is None
        or isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid < 1
        or isinstance(session_id, bool)
        or not isinstance(session_id, int)
        or session_id < 0
    ):
        raise RestartDispatchAuditError("RESTART_AUDIT_CALLER_FACTS_MISSING")
    return {"sid": sid, "pid": pid, "session_id": session_id}


def _scm_call(value: Any, operation: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "attempted",
        "started_at",
        "completed_at",
        "result",
    }:
        raise RestartDispatchAuditError(
            f"RESTART_AUDIT_{operation.upper()}_FACTS_MISSING"
        )
    attempted = value["attempted"]
    if not isinstance(attempted, bool):
        raise RestartDispatchAuditError(
            f"RESTART_AUDIT_{operation.upper()}_ATTEMPT_INVALID"
        )
    if not attempted:
        if any(
            value[name] is not None for name in ("started_at", "completed_at", "result")
        ):
            raise RestartDispatchAuditError(
                f"RESTART_AUDIT_{operation.upper()}_UNATTEMPTED_INVALID"
            )
        return {
            "attempted": False,
            "started_at_utc": None,
            "completed_at_utc": None,
            "result": None,
        }
    started_at = value["started_at"]
    completed_at = value["completed_at"]
    result = value["result"]
    if not isinstance(result, str) or _RESULT_RE.fullmatch(result) is None:
        raise RestartDispatchAuditError(
            f"RESTART_AUDIT_{operation.upper()}_RESULT_INVALID"
        )
    started_at_utc = _timestamp(started_at, f"{operation}_started_at")
    completed_at_utc = _timestamp(completed_at, f"{operation}_completed_at")
    if completed_at.astimezone(timezone.utc) < started_at.astimezone(timezone.utc):
        raise RestartDispatchAuditError(
            f"RESTART_AUDIT_{operation.upper()}_TIMESTAMPS_INVALID"
        )
    return {
        "attempted": True,
        "started_at_utc": started_at_utc,
        "completed_at_utc": completed_at_utc,
        "result": result,
    }


def _observed_scm_facts(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "operation_id",
        "restart_dispatch_nonce",
        "caller",
        "scm_calls",
    }:
        raise RestartDispatchAuditError("RESTART_AUDIT_OBSERVED_FACTS_MISSING")
    scm_calls = value["scm_calls"]
    if not isinstance(scm_calls, Mapping) or set(scm_calls) != {"stop", "start"}:
        raise RestartDispatchAuditError("RESTART_AUDIT_SCM_CALL_FACTS_MISSING")
    return {
        "operation_id": _identifier(value["operation_id"], "operation_id"),
        "restart_dispatch_nonce_sha256": hashlib.sha256(
            _identifier(
                value["restart_dispatch_nonce"], "restart_dispatch_nonce"
            ).encode()
        ).hexdigest(),
        "caller": _caller(value["caller"]),
        "scm_calls": {
            operation: _scm_call(scm_calls[operation], operation)
            for operation in ("stop", "start")
        },
    }


def build_restart_dispatch_audit_v1(
    *,
    install_attempt_id: str,
    policy: RestartDispatchAuditPolicy,
    observed_scm_facts: Mapping[str, Any] | None,
    captured_at: datetime,
) -> bytes:
    """Build canonical facts from a caller-owned observation or explicit dry policy.

    ``OBSERVED_SCM_FACTS`` requires actual captured facts.  The dry seam requires
    no SCM facts and records only its non-executing policy; it never fabricates a
    result, timestamp, or attempted call.
    """

    if policy not in {"OBSERVED_SCM_FACTS", "DRY_RUN_NON_EXECUTING"}:
        raise RestartDispatchAuditError("RESTART_AUDIT_POLICY_INVALID")
    payload: dict[str, Any] = {
        "schema_version": "windows_fence_restart_dispatch_audit_v1",
        "install_attempt_id": _identifier(install_attempt_id, "install_attempt_id"),
        "captured_at_utc": _timestamp(captured_at, "captured_at"),
        "policy": policy,
    }
    if policy == "DRY_RUN_NON_EXECUTING":
        if observed_scm_facts is not None:
            raise RestartDispatchAuditError("RESTART_AUDIT_DRY_RUN_FACTS_FORBIDDEN")
        payload.update(
            {
                "purpose": "record_explicit_non_executing_restart_dispatch_policy",
                "restart_dispatched": False,
                "observed_scm_facts": None,
            }
        )
    else:
        facts = _observed_scm_facts(observed_scm_facts)
        payload.update(
            {
                "purpose": "record_observed_restart_dispatch_facts",
                "restart_dispatched": any(
                    call["attempted"] for call in facts["scm_calls"].values()
                ),
                "observed_scm_facts": facts,
            }
        )
    return canonical_json_bytes(payload)


def _append_restart_dispatch_audit_to_native_seam_v1(
    *,
    native_seam: NativeInstallEventCreateOnlySeam,
    install_attempt_id: str,
    raw: bytes,
) -> None:
    """Append a canonical audit only through the installer create-only event seam."""

    native_seam.append_install_event_create_only(
        install_attempt_id=install_attempt_id,
        event_sequence=RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE,
        state=RESTART_DISPATCH_AUDIT_STATE,
        details_sha256=hashlib.sha256(raw).hexdigest(),
        reject_existing=True,
    )


def persist_restart_dispatch_audit_v1(
    *,
    native_host: NativeWindowsFenceInstallerHostV1,
    install_attempt_id: str,
    policy: RestartDispatchAuditPolicy,
    observed_scm_facts: Mapping[str, Any] | None,
    captured_at: datetime,
) -> bytes:
    """Persist once through the initialized native host's protected event journal.

    The fixed restart-dispatched event sequence binds one audit to one install
    attempt. Any replay is rejected through the host's create-only conflict
    detection; host initialization and Windows security checks remain
    authoritative.
    """

    if type(native_host) is not NativeWindowsFenceInstallerHostV1:
        raise RestartDispatchAuditError("RESTART_AUDIT_NATIVE_HOST_REQUIRED")
    if not native_host.is_real_windows_host:
        raise RestartDispatchAuditError("RESTART_AUDIT_NATIVE_WINDOWS_REQUIRED")
    raw = build_restart_dispatch_audit_v1(
        install_attempt_id=install_attempt_id,
        policy=policy,
        observed_scm_facts=observed_scm_facts,
        captured_at=captured_at,
    )
    try:
        _append_restart_dispatch_audit_to_native_seam_v1(
            native_seam=native_host,
            install_attempt_id=install_attempt_id,
            raw=raw,
        )
    except WindowsFinalInstallerError as exc:
        raise RestartDispatchAuditError(
            f"RESTART_AUDIT_NATIVE_PERSISTENCE_FAILED:{exc}"
        ) from exc
    return raw


__all__ = [
    "RESTART_DISPATCH_AUDIT_EVENT_SEQUENCE",
    "RESTART_DISPATCH_AUDIT_STATE",
    "NativeInstallEventCreateOnlySeam",
    "RestartDispatchAuditError",
    "RestartDispatchAuditPolicy",
    "build_restart_dispatch_audit_v1",
    "persist_restart_dispatch_audit_v1",
]
