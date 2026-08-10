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
from ctypes import byref, create_unicode_buffer, wintypes
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


class NativeWindowsReadOnlyFactsAdapterV1:
    """Concrete, query-only Windows fact adapter.

    The two commands are deliberately injected as *readers* so the production
    deployment can pin its RPC snapshot helper.  Their stdout is the source
    artifact; it must be one canonical JSON object, with no whitespace or
    wrapper added by this adapter.
    """

    def __init__(
        self,
        *,
        service_name: str,
        store_path: str,
        execution_facts_command: tuple[str, ...] | None = None,
        snapshot_command: tuple[str, ...] | None = None,
        execution_facts_command_sha256: str | None = None,
        snapshot_command_sha256: str | None = None,
    ) -> None:
        self.service_name = service_name
        self.store_path = store_path
        self.execution_facts_command = execution_facts_command
        self.snapshot_command = snapshot_command
        self.execution_facts_command_sha256 = execution_facts_command_sha256
        self.snapshot_command_sha256 = snapshot_command_sha256

    @staticmethod
    def _require_native() -> tuple[Any, Any, Any]:
        if os.name != "nt":
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        try:
            import win32service  # type: ignore[import-not-found]
            import win32process  # type: ignore[import-not-found]
            from ctypes import windll
        except Exception as exc:
            raise WindowsHostObservationError(
                "OBSERVER_NATIVE_SOURCE_UNAVAILABLE"
            ) from exc
        return win32service, win32process, windll

    @staticmethod
    def _read_canonical_command(
        command: tuple[str, ...] | None,
        expected_command_sha256: str | None,
        code: str,
    ) -> tuple[dict[str, Any], bytes]:
        if not command or any(
            not isinstance(item, str) or not item for item in command
        ):
            raise WindowsHostObservationError("OBSERVER_FACT_SOURCE_UNAVAILABLE")
        executable = Path(command[0])
        if (
            not executable.is_absolute()
            or not isinstance(expected_command_sha256, str)
            or len(expected_command_sha256) != 64
        ):
            raise WindowsHostObservationError("OBSERVER_READER_PIN_REQUIRED")
        try:
            if (
                hashlib.sha256(executable.read_bytes()).hexdigest()
                != expected_command_sha256
            ):
                raise WindowsHostObservationError("OBSERVER_READER_PIN_MISMATCH")
        except OSError as exc:
            raise WindowsHostObservationError("OBSERVER_READER_READ_FAILED") from exc
        try:
            completed = subprocess.run(
                list(command), check=True, capture_output=True, timeout=10, shell=False
            )
            raw = completed.stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowsHostObservationError(code) from exc
        try:
            if (
                hashlib.sha256(executable.read_bytes()).hexdigest()
                != expected_command_sha256
            ):
                raise WindowsHostObservationError(
                    "OBSERVER_READER_CHANGED_DURING_QUERY"
                )
        except OSError as exc:
            raise WindowsHostObservationError("OBSERVER_READER_READ_FAILED") from exc
        if not isinstance(raw, bytes):
            raise WindowsHostObservationError("OBSERVER_CANONICAL_SOURCE_INVALID")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=NativeWindowsReadOnlyFactsAdapterV1._unique_pairs,
                parse_float=lambda _value: (_ for _ in ()).throw(
                    ValueError("float is forbidden")
                ),
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise WindowsHostObservationError(
                "OBSERVER_CANONICAL_SOURCE_INVALID"
            ) from exc
        try:
            canonical = canonical_json_bytes(value)
        except Exception as exc:
            raise WindowsHostObservationError(
                "OBSERVER_CANONICAL_SOURCE_INVALID"
            ) from exc
        if not isinstance(value, dict) or canonical != raw:
            raise WindowsHostObservationError("OBSERVER_CANONICAL_SOURCE_INVALID")
        return value, raw

    @staticmethod
    def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    @staticmethod
    def _process_time_utc(value: Any) -> str:
        try:
            timestamp = (
                value.timestamp()
                if hasattr(value, "timestamp")
                else (int(value) / 10_000_000 - 11_644_473_600)
            )
            return (
                datetime.fromtimestamp(timestamp, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except (OverflowError, TypeError, ValueError) as exc:
            raise WindowsHostObservationError("OBSERVER_PROCESS_TIME_INVALID") from exc

    def capture_observer_facts_with_raw(
        self, kind: str
    ) -> tuple[Mapping[str, Any], bytes | None, bytes | None]:
        del kind
        ws, wp, windll = self._require_native()
        try:
            manager = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)
            service = ws.OpenService(
                manager, self.service_name, ws.SERVICE_QUERY_STATUS
            )
            status = ws.QueryServiceStatusEx(service)
            ws.CloseServiceHandle(service)
            ws.CloseServiceHandle(manager)
            pid = int(status.get("ProcessId", 0))
            if pid <= 0:
                raise OSError("service has no live process")
            process = wp.OpenProcess(wp.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            creation, _, _, _ = wp.GetProcessTimes(process)
            wp.CloseHandle(process)
            tick = int(windll.kernel32.GetTickCount64())
            volume_serial = wintypes.DWORD()
            if not windll.kernel32.GetVolumeInformationW(
                self.store_path, None, 0, byref(volume_serial), None, None, None, 0
            ):
                raise OSError("GetVolumeInformationW failed")
            volume_root = self.store_path[:3]
            volume_name = create_unicode_buffer(1024)
            if not windll.kernel32.GetVolumeNameForVolumeMountPointW(
                volume_root, volume_name, len(volume_name)
            ):
                raise OSError("GetVolumeNameForVolumeMountPointW failed")
            volume_guid = volume_name.value.rstrip("\\").upper()
            if not volume_guid.startswith("\\\\?\\VOLUME{"):
                raise OSError("invalid volume GUID")
        except Exception as exc:
            raise WindowsHostObservationError(
                "OBSERVER_NATIVE_FACT_CAPTURE_FAILED"
            ) from exc
        execution, execution_raw = self._read_canonical_command(
            self.execution_facts_command,
            self.execution_facts_command_sha256,
            "OBSERVER_EXECUTION_FACTS_SOURCE_FAILED",
        )
        snapshot, snapshot_raw = self._read_canonical_command(
            self.snapshot_command,
            self.snapshot_command_sha256,
            "OBSERVER_SNAPSHOT_SOURCE_FAILED",
        )
        if any(
            source.get("pending_send_outcomes") != 0
            or source.get("active_orders") != []
            or source.get("positions") != []
            for source in (execution, snapshot)
        ):
            raise WindowsHostObservationError("OBSERVER_ZERO_ORDER_REQUIRED")
        facts = dict(snapshot)
        facts.update(
            {
                "service_name": self.service_name,
                "service_process_id": pid,
                "service_process_started_at_utc": self._process_time_utc(creation),
                "host_boot_id": f"windows-boot-tick-{tick:016x}",
                "store_volume_serial": f"{int(volume_serial.value):08X}",
                "store_volume_identity_sha256": hashlib.sha256(
                    volume_guid.encode("ascii")
                ).hexdigest(),
                "execution_facts_canonical_sha256": hashlib.sha256(
                    execution_raw
                ).hexdigest(),
                "snapshot_raw_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
            }
        )
        return facts, execution_raw, snapshot_raw

    def capture_observer_facts(self, kind: str) -> Mapping[str, Any]:
        facts, _, _ = self.capture_observer_facts_with_raw(kind)
        return facts


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
        if (
            type(seam) is not NativeWindowsHostObserverV1
            or not seam.is_real_windows_host
        ):
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        draft, _, _ = self.capture_draft_with_sources(kind, seam=seam)
        return draft

    def capture_draft_with_sources(
        self, kind: str, *, seam: WindowsReadOnlyHostSeamV1
    ) -> tuple[bytes, bytes, bytes]:
        if not isinstance(kind, str) or kind != "zero_preflight":
            raise WindowsHostObservationError("OBSERVER_CANONICAL_SOURCE_REQUIRED")
        if (
            type(seam) is not NativeWindowsHostObserverV1
            or not seam.is_real_windows_host
        ):
            raise WindowsHostObservationError("OBSERVER_REAL_WINDOWS_HOST_REQUIRED")
        source = seam._facts_source
        if type(source) is not NativeWindowsReadOnlyFactsAdapterV1:
            raise WindowsHostObservationError("OBSERVER_NATIVE_SOURCE_REQUIRED")
        facts, execution_raw, snapshot_raw = source.capture_observer_facts_with_raw(
            kind
        )
        if execution_raw is None or snapshot_raw is None:
            raise WindowsHostObservationError("OBSERVER_CANONICAL_SOURCE_REQUIRED")
        if (
            facts.get("execution_facts_canonical_sha256")
            != hashlib.sha256(execution_raw).hexdigest()
            or facts.get("snapshot_raw_sha256")
            != hashlib.sha256(snapshot_raw).hexdigest()
        ):
            raise WindowsHostObservationError("OBSERVER_CANONICAL_SOURCE_HASH_MISMATCH")
        return _canonical_observer_draft_v1(kind, facts), execution_raw, snapshot_raw


__all__ = [
    "NativeWindowsHostObserverV1",
    "NativeWindowsReadOnlyFactsAdapterV1",
    "WindowsHostObservationError",
    "WindowsReadOnlyHostSeamV1",
    "WindowsReadOnlyFactsSourceV1",
    "_canonical_observer_draft_v1",
]
