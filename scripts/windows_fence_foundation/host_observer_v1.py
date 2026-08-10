"""Read-only Windows host-observer drafts for the durable-fence ceremony.

The observer deliberately has no signing, SCM mutation, restart, RPC mutation,
or order API.  It collects facts through a narrow native/fake seam and emits
canonical *unsigned* drafts for the existing offline observer signer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator, ValidationError

from .contracts import canonical_json_bytes
from .installer_windows_v1 import WindowsScmReadbackV1
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1


class WindowsHostObservationError(ValueError):
    """Stable fail-closed observer error."""


_ROOT = Path(__file__).resolve().parents[2]
_SCHEMAS = _ROOT / "docs" / "schemas"
_DRAFT_SPECS = {
    "zero_preflight": (
        "windows-rpc-durable-fence-zero-order-preflight-v1.schema.json",
        "receipt_id",
        "receipt_core_sha256",
        "windows-fence-preflight-",
    ),
    "publish_receipt": (
        "windows-rpc-durable-fence-publish-receipt-v1.schema.json",
        "receipt_id",
        "receipt_core_sha256",
        "windows-fence-publish-receipt-",
    ),
    "scm_dispatch_evidence": (
        "windows-rpc-durable-fence-scm-dispatch-evidence-v1.schema.json",
        "evidence_id",
        "evidence_core_sha256",
        "windows-fence-scm-dispatch-evidence-",
    ),
    "startup_receipt": (
        "windows-rpc-durable-fence-startup-receipt-v1.schema.json",
        "receipt_id",
        "receipt_core_sha256",
        "windows-fence-startup-receipt-",
    ),
    "attestation": (
        "windows-rpc-durable-fence-foundation-attestation-v1.schema.json",
        "attestation_id",
        "attestation_core_sha256",
        "windows-fence-foundation-attestation-",
    ),
}
_PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _utc(value: object) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise WindowsHostObservationError("OBSERVER_TIME_INVALID") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise WindowsHostObservationError("OBSERVER_TIME_INVALID")
    return result.astimezone(timezone.utc)


def _canonical_b64_sha(value: object, expected_sha: object) -> None:
    if not isinstance(value, str) or not isinstance(expected_sha, str):
        raise WindowsHostObservationError("OBSERVER_CANONICAL_FACT_INVALID")
    try:
        raw = base64.b64decode(value, validate=True)
        parsed = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise WindowsHostObservationError("OBSERVER_CANONICAL_FACT_INVALID") from exc
    if (
        canonical_json_bytes(parsed) != raw
        or hashlib.sha256(raw).hexdigest() != expected_sha
    ):
        raise WindowsHostObservationError("OBSERVER_CANONICAL_FACT_INVALID")


def _canonical_observer_draft_v1(kind: str, facts: Mapping[str, Any]) -> bytes:
    """Validate and canonicalize one unsigned observer artifact draft.

    The identity/core are derived here; the detached signature is intentionally
    absent from the returned bytes and must be added by the offline signer.
    """
    try:
        schema_name, id_field, core_field, prefix = _DRAFT_SPECS[kind]
    except KeyError as exc:
        raise WindowsHostObservationError("OBSERVER_ARTIFACT_KIND_INVALID") from exc
    value = dict(facts)
    if any(field in value for field in (id_field, core_field, "signature")):
        raise WindowsHostObservationError("OBSERVER_DRAFT_IDENTITY_SUPPLIED")
    if kind == "zero_preflight":
        _validate_fresh_zero_order_facts(value)
    elif kind == "attestation":
        proof = value.get("final_registry_admission_proof")
        if not isinstance(proof, Mapping) or proof.get(
            "live_mutation_rpc_probe_performed"
        ):
            raise WindowsHostObservationError("OBSERVER_MUTATION_PROBE_FORBIDDEN")
    core = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    candidate = {
        **value,
        core_field: core,
        id_field: prefix + core,
        "signature": _PLACEHOLDER_SIGNATURE,
    }
    try:
        schema = json.loads((_SCHEMAS / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(candidate)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise WindowsHostObservationError("OBSERVER_DRAFT_SCHEMA_INVALID") from exc
    candidate.pop("signature")
    return canonical_json_bytes(candidate)


def _validate_fresh_zero_order_facts(value: Mapping[str, Any]) -> None:
    now = _utc(value.get("observed_at_utc"))
    issued = _utc(value.get("challenge_issued_at_utc"))
    served = _utc(value.get("snapshot_served_at_utc"))
    expires = _utc(value.get("challenge_expires_at_utc"))
    if not (issued <= served <= now < expires) or (now - served).total_seconds() > 30:
        raise WindowsHostObservationError("OBSERVER_PREFLIGHT_NOT_FRESH")
    required = {
        "old_runtime_frozen": True,
        "web_trade_enabled": False,
        "execution_authority_revoked": True,
        "pending_send_outcomes": 0,
        "zero_order_preflight_verified": True,
        "challenge_single_use": True,
        "maximum_preflight_age_seconds": 30,
    }
    if any(value.get(key) != expected for key, expected in required.items()):
        raise WindowsHostObservationError("OBSERVER_ZERO_ORDER_REQUIRED")
    if value.get("active_orders") != []:
        raise WindowsHostObservationError("OBSERVER_ZERO_ORDER_REQUIRED")
    _canonical_b64_sha(
        value.get("raw_account_row_canonical_json_base64"),
        value.get("raw_account_row_sha256"),
    )
    _canonical_b64_sha(
        value.get("gateway_scope_canonical_json_base64"),
        value.get("gateway_scope_sha256"),
    )


class WindowsReadOnlyHostSeamV1(Protocol):
    """All production methods are observations; fakes implement the same seam."""

    @property
    def is_real_windows_host(self) -> bool: ...

    def query_scm_readback(self, service_name: str) -> WindowsScmReadbackV1: ...

    def query_service_status(self, service_name: str) -> Mapping[str, Any]: ...

    def capture_observer_facts(self, kind: str) -> Mapping[str, Any]: ...


class WindowsReadOnlyFactsSourceV1(Protocol):
    """Reviewed adapter for the native Windows/M2 query-only fact source."""

    def capture_observer_facts(self, kind: str) -> Mapping[str, Any]: ...


class NativeWindowsHostObserverV1:
    """Windows native seam containing only SCM/status readbacks."""

    def __init__(
        self,
        *,
        installer_host: NativeWindowsFenceInstallerHostV1 | None = None,
        facts_source: WindowsReadOnlyFactsSourceV1 | None = None,
    ) -> None:
        self._installer_host = installer_host or NativeWindowsFenceInstallerHostV1()
        self._facts_source = facts_source

    @property
    def is_real_windows_host(self) -> bool:
        return os.name == "nt" and self._installer_host.is_real_windows_host

    def query_scm_readback(self, service_name: str) -> WindowsScmReadbackV1:
        if not self.is_real_windows_host:
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        return self._installer_host.query_scm_readback(service_name)

    def query_service_status(self, service_name: str) -> Mapping[str, Any]:
        if not self.is_real_windows_host:
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        try:
            completed = subprocess.run(
                ["sc.exe", "queryex", service_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowsHostObservationError(
                "OBSERVER_SCM_STATUS_QUERY_FAILED"
            ) from exc
        # Preserve exact readback only as a hash; it avoids treating localized
        # sc.exe output as a stable structured API while retaining evidence.
        return {
            "service_name": service_name,
            "status_raw_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            "query_only": True,
        }

    def capture_observer_facts(self, kind: str) -> Mapping[str, Any]:
        if not self.is_real_windows_host:
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        if self._facts_source is None:
            raise WindowsHostObservationError("OBSERVER_FACT_SOURCE_UNAVAILABLE")
        try:
            facts = self._facts_source.capture_observer_facts(kind)
        except Exception as exc:
            raise WindowsHostObservationError("OBSERVER_FACT_CAPTURE_FAILED") from exc
        if not isinstance(facts, Mapping):
            raise WindowsHostObservationError("OBSERVER_FACT_SOURCE_INVALID")
        return facts

    def capture_draft(self, kind: str, *, seam: WindowsReadOnlyHostSeamV1) -> bytes:
        """Build one signed-artifact draft from a read-only host seam.

        The seam is deliberately the only source of facts.  There is no
        ``facts=`` escape hatch: callers cannot hand-author an unsigned
        preflight or substitute a fixture for the production observer.
        Production adapters must reject non-Windows hosts; tests may use an
        explicit fake implementing the same query-only protocol.
        """
        if not isinstance(kind, str) or kind not in _DRAFT_SPECS:
            raise WindowsHostObservationError("OBSERVER_ARTIFACT_KIND_INVALID")
        if not getattr(seam, "is_real_windows_host", False):
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        try:
            facts = seam.capture_observer_facts(kind)
        except AttributeError as exc:
            raise WindowsHostObservationError(
                "OBSERVER_FACT_SOURCE_UNAVAILABLE"
            ) from exc
        if not isinstance(facts, Mapping):
            raise WindowsHostObservationError("OBSERVER_FACT_SOURCE_INVALID")
        return _canonical_observer_draft_v1(kind, facts)


__all__ = [
    "NativeWindowsHostObserverV1",
    "WindowsHostObservationError",
    "WindowsReadOnlyHostSeamV1",
    "WindowsReadOnlyFactsSourceV1",
    "_canonical_observer_draft_v1",
]
