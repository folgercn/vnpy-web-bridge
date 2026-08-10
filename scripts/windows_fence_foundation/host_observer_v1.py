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
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator, ValidationError

from .contracts import canonical_json_bytes
from .installer_windows_v1 import WindowsScmReadbackV1
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1
from .win32_fs import WindowsFilesystemFactsAdapter


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


class WindowsReadOnlyFactsSourceV1(Protocol):
    """Explicit query-only captures; no caller-selected artifact kind."""

    def capture_publish_receipt_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]: ...

    def capture_scm_dispatch_evidence_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]: ...

    def capture_startup_receipt_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]: ...

    def capture_attestation_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]: ...


class NativeWindowsReadOnlyFactsAdapterV1:
    """Concrete native observer source; no command or caller-fact seam exists.

    SCM, process and journal facts are collected here through the already
    sealed native host and the handle-anchored filesystem adapter.  The v1
    schemas additionally require a protected SCM audit trace and in-process
    M2 facts, for which this repository has no concrete reader.  Those paths
    therefore fail closed after the native readbacks, rather than accepting a
    command, a fixture, or caller-provided facts as production evidence.
    """

    def __init__(
        self,
        *,
        service_name: str,
        store_path: str,
        installer_host: NativeWindowsFenceInstallerHostV1,
    ) -> None:
        self.service_name = service_name
        self.store_path = store_path
        self._installer_host = installer_host

    def _native_readbacks(self, *, event_sequence: int) -> None:
        if (
            os.name != "nt"
            or type(self._installer_host) is not NativeWindowsFenceInstallerHostV1
            or not self._installer_host.is_real_windows_host
        ):
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        try:
            fs = WindowsFilesystemFactsAdapter()
            store = Path(self.store_path)
            fs.list_directory(store)
            journal = fs.list_directory(store / "installer-journal-v1")
            attempts = [
                name
                for name in journal.names
                if name.startswith("windows-fence-install-")
            ]
            if len(attempts) != 1:
                raise WindowsHostObservationError("OBSERVER_JOURNAL_ATTEMPT_AMBIGUOUS")
            self._installer_host.read_install_event_read_only(
                install_attempt_id=attempts[0], event_sequence=event_sequence
            )
            self._installer_host.query_scm_readback(self.service_name)
            self._installer_host.query_service_runtime_readback(
                service_name=self.service_name
            )
        except WindowsHostObservationError:
            raise
        except Exception as exc:
            raise WindowsHostObservationError(
                "OBSERVER_NATIVE_READBACK_FAILED"
            ) from exc

    def _unavailable(
        self, *, event_sequence: int, code: str
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]:
        self._native_readbacks(event_sequence=event_sequence)
        raise WindowsHostObservationError(code)

    def capture_publish_receipt_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]:
        return self._unavailable(
            event_sequence=2, code="OBSERVER_PUBLISH_FACTS_UNAVAILABLE"
        )

    def capture_scm_dispatch_evidence_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]:
        return self._unavailable(
            event_sequence=5, code="OBSERVER_SCM_AUDIT_TRACE_UNAVAILABLE"
        )

    def capture_startup_receipt_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]:
        return self._unavailable(
            event_sequence=5, code="OBSERVER_STARTUP_FACTS_UNAVAILABLE"
        )

    def capture_attestation_facts(
        self,
    ) -> tuple[Mapping[str, Any], Mapping[str, bytes]]:
        return self._unavailable(
            event_sequence=5, code="OBSERVER_M2_ATTESTATION_FACTS_UNAVAILABLE"
        )


class NativeWindowsHostObserverV1:
    """Windows native seam containing only SCM/status readbacks."""

    def __init__(
        self,
        *,
        service_name: str | None = None,
        store_path: str | None = None,
        installer_host: NativeWindowsFenceInstallerHostV1 | None = None,
        facts_source: WindowsReadOnlyFactsSourceV1 | None = None,
    ) -> None:
        self._installer_host = installer_host or NativeWindowsFenceInstallerHostV1()
        if facts_source is None and service_name is not None and store_path is not None:
            self._facts_source: WindowsReadOnlyFactsSourceV1 | None = (
                NativeWindowsReadOnlyFactsAdapterV1(
                    service_name=service_name,
                    store_path=store_path,
                    installer_host=self._installer_host,
                )
            )
        else:
            self._facts_source = facts_source

    @property
    def is_real_windows_host(self) -> bool:
        return (
            os.name == "nt"
            and type(self._installer_host) is NativeWindowsFenceInstallerHostV1
            and self._installer_host.is_real_windows_host
        )

    def query_scm_readback(self, service_name: str) -> WindowsScmReadbackV1:
        if not self.is_real_windows_host:
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        return self._installer_host.query_scm_readback(service_name)

    def query_service_status(self, service_name: str) -> Mapping[str, Any]:
        if not self.is_real_windows_host:
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        try:
            return self._installer_host.query_service_runtime_readback(
                service_name=service_name
            )
        except Exception as exc:
            raise WindowsHostObservationError(
                "OBSERVER_SCM_STATUS_QUERY_FAILED"
            ) from exc

    def capture_publish_receipt(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None = None
    ) -> bytes:
        return self._capture_publish_receipt(offline_contract=offline_contract)

    def capture_scm_dispatch_evidence(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None = None
    ) -> bytes:
        return self._capture_scm_dispatch_evidence(offline_contract=offline_contract)

    def capture_startup_receipt(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None = None
    ) -> bytes:
        return self._capture_startup_receipt(offline_contract=offline_contract)

    def capture_attestation(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None = None
    ) -> bytes:
        return self._capture_attestation(offline_contract=offline_contract)

    def _source(
        self, offline_contract: WindowsReadOnlyFactsSourceV1 | None
    ) -> WindowsReadOnlyFactsSourceV1:
        if offline_contract is not None:
            # This explicit parameter is an offline contract seam only.  It is
            # never selected implicitly by production code.
            return offline_contract
        if not self.is_real_windows_host:
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        if type(self._facts_source) is not NativeWindowsReadOnlyFactsAdapterV1:
            raise WindowsHostObservationError("OBSERVER_NATIVE_SOURCE_REQUIRED")
        return self._facts_source

    @staticmethod
    def _draft_from_read_only_facts(kind: str, captured: object) -> bytes:
        try:
            facts, raw_bindings = captured  # type: ignore[misc]
        except (TypeError, ValueError) as exc:
            raise WindowsHostObservationError("OBSERVER_FACT_SOURCE_INVALID") from exc
        if not isinstance(facts, Mapping) or not isinstance(raw_bindings, Mapping):
            raise WindowsHostObservationError("OBSERVER_FACT_SOURCE_INVALID")
        for field, raw in raw_bindings.items():
            if (
                not isinstance(field, str)
                or not field.endswith("_raw_sha256")
                or type(raw) is not bytes
                or facts.get(field) != hashlib.sha256(raw).hexdigest()
            ):
                raise WindowsHostObservationError("OBSERVER_RAW_BINDING_MISMATCH")
        if not raw_bindings:
            raise WindowsHostObservationError("OBSERVER_RAW_BINDING_REQUIRED")
        return _canonical_observer_draft_v1(kind, facts)

    def _capture_publish_receipt(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None
    ) -> bytes:
        return self._draft_from_read_only_facts(
            "publish_receipt",
            self._source(offline_contract).capture_publish_receipt_facts(),
        )

    def _capture_scm_dispatch_evidence(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None
    ) -> bytes:
        return self._draft_from_read_only_facts(
            "scm_dispatch_evidence",
            self._source(offline_contract).capture_scm_dispatch_evidence_facts(),
        )

    def _capture_startup_receipt(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None
    ) -> bytes:
        return self._draft_from_read_only_facts(
            "startup_receipt",
            self._source(offline_contract).capture_startup_receipt_facts(),
        )

    def _capture_attestation(
        self, *, offline_contract: WindowsReadOnlyFactsSourceV1 | None
    ) -> bytes:
        return self._draft_from_read_only_facts(
            "attestation", self._source(offline_contract).capture_attestation_facts()
        )


__all__ = [
    "NativeWindowsHostObserverV1",
    "NativeWindowsReadOnlyFactsAdapterV1",
    "WindowsHostObservationError",
    "WindowsReadOnlyFactsSourceV1",
    "_canonical_observer_draft_v1",
]
