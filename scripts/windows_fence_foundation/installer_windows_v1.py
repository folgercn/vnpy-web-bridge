"""Final Windows-only installer state machine for the durable fence.

This is deliberately an adapter-driven installer: the production adapter must
use opened Windows handles and SCM/pywin32 registry APIs; portable adapters are
test doubles only and are rejected before an install can become ready.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .bundle_v1 import VerifiedWindowsFenceBundleV1
from .contracts import canonical_json_bytes
from .credential_config_v1 import (
    CredentialConfigError,
    parse_installer_store_bootstrap_v1,
)
from .manifest_v1 import EXPECTED_BINDING_FIELDS, VerifiedInstallManifestV1


class WindowsFinalInstallerError(RuntimeError):
    """Stable fail-closed terminal installer error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class InstallCheckpointV1(str, Enum):
    PREPARED = "PREPARED_FROZEN"
    FILES_PUBLISHED = "FILES_READY_FROZEN"
    EVENT3_RESERVED = "RESTART_DISPATCH_RESERVED_FROZEN"
    TARGET_READY = "SERVICE_CONFIG_READY_FROZEN"
    FAILED_FROZEN = "FAILED_FROZEN"


@dataclass(frozen=True)
class WindowsPathReadbackV1:
    path: str
    raw_sha256: str
    owner_sid_sha256: str
    acl_sddl_sha256: str
    regular_file: bool
    reparse_point: bool
    parent_chain_reparse_free: bool
    hardlink_count: int
    alternate_data_streams: bool
    dacl_protected: bool
    inherited_ace_count: int
    unsafe_write_principals: tuple[str, ...]


@dataclass(frozen=True)
class WindowsScmReadbackV1:
    service_name: str
    image_path: Mapping[str, Any]
    start_type: str
    failure_actions: tuple[Mapping[str, Any], ...]
    recovery_actions: tuple[Mapping[str, Any], ...]
    service_account_sid_sha256: str
    dependencies: tuple[str, ...]
    python_class: str
    python_path: str
    registry_owner_sid_sha256: str
    registry_acl_sddl_sha256: str
    registry_owner_sid: str
    registry_acl_sddl: str

    def canonical_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "service_name": self.service_name,
                    "image_path": dict(self.image_path),
                    "start_type": self.start_type,
                    "failure_actions": list(self.failure_actions),
                    "recovery_actions": list(self.recovery_actions),
                    "service_account_sid_sha256": self.service_account_sid_sha256,
                    "dependencies": list(self.dependencies),
                    "python_class": self.python_class,
                    "python_path": self.python_path,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class InstallResultV1:
    checkpoint: InstallCheckpointV1
    backup_id: str
    publish_receipt_raw_sha256: str | None
    transition_receipt_raw_sha256: str | None


class WindowsFenceInstallerHostV1(Protocol):
    """Privileged Windows adapter.  All methods must fail on unpinned handles."""

    @property
    def is_real_windows_host(self) -> bool: ...

    def query_scm_readback(self, service_name: str) -> WindowsScmReadbackV1: ...

    def initialize_secure_durable_journal_create_only(
        self,
        *,
        store_root: str,
        store_expectation: Mapping[str, Any],
        owner_sid: str,
        directory_acl_sddl: str,
    ) -> None: ...

    def backup_scm_and_pywin32_registry_create_only(
        self, *, service_name: str, readback: WindowsScmReadbackV1
    ) -> str: ...

    def publish_same_volume_content_addressed_create_only(
        self,
        *,
        bundle_raw: bytes,
        bundle_sha256: str,
        destination_root: str,
        final_owner_sid: str,
        final_directory_acl_sddl: str,
        component_acl_sddl: str,
    ) -> tuple[str, Mapping[str, WindowsPathReadbackV1]]: ...

    def append_install_event_create_only(
        self,
        *,
        install_attempt_id: str,
        event_sequence: int,
        state: str,
        details_sha256: str,
    ) -> str: ...

    def apply_exact_scm_and_pywin32_registry_once(
        self,
        *,
        expected_before: WindowsScmReadbackV1,
        target: Mapping[str, Any],
        registry_security: Mapping[str, str],
    ) -> None: ...

    def restore_pre_event3_backup(self, *, backup_id: str) -> None: ...

    def remove_pre_event3_published_orphan(
        self,
        *,
        destination_root: str,
        install_attempt_id: str,
        bundle_sha256: str,
        component_sha256s: Mapping[str, str],
        owner_sid_sha256: str,
        component_acl_sddl_sha256: str,
        final_owner_sid_sha256: str,
        final_directory_acl_sddl_sha256: str,
    ) -> None: ...

    def query_same_restart_attempt_only(self, *, install_attempt_id: str) -> str: ...


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _secure_component(
    item: WindowsPathReadbackV1,
    *,
    expected_path_sha256: str,
    expected_raw_sha256: str,
    owner: str,
    acl: str,
) -> None:
    path_sha = hashlib.sha256(item.path.encode("utf-8")).hexdigest()
    if (
        path_sha != expected_path_sha256
        or item.raw_sha256 != expected_raw_sha256
        or item.owner_sid_sha256 != owner
        or item.acl_sddl_sha256 != acl
        or not item.regular_file
        or item.reparse_point
        or not item.parent_chain_reparse_free
        or item.hardlink_count != 1
        or item.alternate_data_streams
        or not item.dacl_protected
        or item.inherited_ace_count
        or item.unsafe_write_principals
    ):
        raise WindowsFinalInstallerError("INSTALL_COMPONENT_READBACK_MISMATCH")


def _exact_scm(expected: Mapping[str, Any], actual: WindowsScmReadbackV1) -> None:
    wanted = {
        "service_name": expected["service_name"],
        "image_path": expected["image_path"],
        "start_type": expected["start_type"],
        "failure_actions": expected["failure_actions"],
        "recovery_actions": expected["recovery_actions"],
        "service_account_sid_sha256": expected["service_account_sid_sha256"],
        "dependencies": expected["dependencies"],
        "python_class": expected["python_class"],
        "python_path": expected["python_path"],
    }
    actual_value = {
        "service_name": actual.service_name,
        "image_path": dict(actual.image_path),
        "start_type": actual.start_type,
        "failure_actions": list(actual.failure_actions),
        "recovery_actions": list(actual.recovery_actions),
        "service_account_sid_sha256": actual.service_account_sid_sha256,
        "dependencies": list(actual.dependencies),
        "python_class": actual.python_class,
        "python_path": actual.python_path,
    }
    if wanted != actual_value:
        raise WindowsFinalInstallerError("SCM_OR_PYWIN32_READBACK_MISMATCH")


def _exact_registry_security(
    actual: WindowsScmReadbackV1, *, owner_sha256: str, acl_sha256: str
) -> None:
    if (
        actual.registry_owner_sid_sha256 != owner_sha256
        or actual.registry_acl_sddl_sha256 != acl_sha256
    ):
        raise WindowsFinalInstallerError("PYWIN32_REGISTRY_SECURITY_READBACK_MISMATCH")


def _publish_sddl_is_safe(value: str) -> bool:
    """Reject broad writers and DELETE_CHILD before any publish can begin."""
    normalized = value.upper()
    if "D:P" not in normalized:
        return False
    ace_pattern = re.compile(r"\([AD];[^;]*;([^;]*);[^;]*;[^;]*;([^)]+)\)")
    for rights, trustee in ace_pattern.findall(normalized):
        if rights in {"DC", "0X00000040"} or "DC" in rights:
            return False
        if trustee in {
            "WD",
            "BU",
            "AU",
            "AN",
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-545",
        } and rights not in {"", "GR", "GX", "RC"}:
            return False
    return True


class FinalWindowsFenceInstallerV1:
    """No fallback installer: it can only progress one exact frozen attempt."""

    def __init__(
        self,
        *,
        host: WindowsFenceInstallerHostV1,
        manifest: VerifiedInstallManifestV1,
        bundle: VerifiedWindowsFenceBundleV1,
        target_projection: Any,
        public_config_raw: bytes,
    ) -> None:
        if not host.is_real_windows_host:
            raise WindowsFinalInstallerError("WINDOWS_INSTALLER_REAL_HOST_REQUIRED")
        self._host = host
        self._manifest = manifest
        self._bundle = bundle
        self._target = target_projection
        bindings = target_projection.manifest_bindings
        if (
            not isinstance(bindings, Mapping)
            or set(bindings) < set(EXPECTED_BINDING_FIELDS)
            or any(
                bindings[field] != manifest[field] for field in EXPECTED_BINDING_FIELDS
            )
        ):
            raise WindowsFinalInstallerError(
                "INSTALLER_TARGET_MANIFEST_BINDING_MISMATCH"
            )
        for field, projection_name in (
            ("preinstall_service_config_canonical_sha256", "preinstall_service_config"),
            ("safety_service_config_canonical_sha256", "safety_service_config"),
            ("service_config_canonical_sha256", "target_service_config"),
        ):
            projection = getattr(target_projection, projection_name, None)
            if (
                not isinstance(projection, Mapping)
                or _sha(projection) != manifest[field]
            ):
                raise WindowsFinalInstallerError("INSTALLER_TARGET_CONFIG_MISMATCH")
        registry_security = getattr(target_projection, "registry_security", None)
        if (
            not isinstance(registry_security, Mapping)
            or set(registry_security) != {"owner_sid", "acl_sddl"}
            or not isinstance(registry_security["owner_sid"], str)
            or not isinstance(registry_security["acl_sddl"], str)
            or hashlib.sha256(registry_security["owner_sid"].encode()).hexdigest()
            != manifest["expected_service_config_owner_sid_sha256"]
            or hashlib.sha256(registry_security["acl_sddl"].encode()).hexdigest()
            != manifest["expected_service_config_acl_sddl_sha256"]
        ):
            raise WindowsFinalInstallerError("INSTALLER_REGISTRY_SECURITY_MISMATCH")
        publish_security = getattr(target_projection, "publish_security", None)
        if (
            not isinstance(publish_security, Mapping)
            or set(publish_security)
            != {"final_owner_sid", "final_directory_acl_sddl", "component_acl_sddl"}
            or any(
                not isinstance(value, str) or not value
                for value in publish_security.values()
            )
            or hashlib.sha256(publish_security["final_owner_sid"].encode()).hexdigest()
            != manifest["expected_final_owner_sid_sha256"]
            or hashlib.sha256(
                publish_security["final_directory_acl_sddl"].encode()
            ).hexdigest()
            != manifest["expected_final_directory_acl_sddl_sha256"]
            or hashlib.sha256(
                publish_security["component_acl_sddl"].encode()
            ).hexdigest()
            != manifest["expected_component_acl_sddl_sha256"]
            or not _publish_sddl_is_safe(publish_security["final_directory_acl_sddl"])
            or not _publish_sddl_is_safe(publish_security["component_acl_sddl"])
        ):
            raise WindowsFinalInstallerError("INSTALLER_PUBLISH_SECURITY_MISMATCH")
        try:
            bootstrap = parse_installer_store_bootstrap_v1(
                public_config_raw, expected_raw_sha256=manifest["config_sha256"]
            )
        except (CredentialConfigError, KeyError) as exc:
            raise WindowsFinalInstallerError(
                "INSTALLER_PUBLIC_CONFIG_REJECTED"
            ) from exc
        required_store = {
            "store_path_sha256": hashlib.sha256(
                bootstrap.store_root.encode()
            ).hexdigest(),
            "store_id": bootstrap.store_expectation.get("store_id"),
            "store_volume_serial": bootstrap.store_expectation.get(
                "store_volume_serial"
            ),
            "store_volume_identity_sha256": bootstrap.store_expectation.get(
                "store_volume_identity_sha256"
            ),
            "store_owner_sid_sha256": bootstrap.store_expectation.get(
                "owner_sid_sha256"
            ),
            "store_directory_acl_sddl_sha256": bootstrap.store_expectation.get(
                "directory_acl_sddl_sha256"
            ),
            "store_state_acl_sddl_sha256": bootstrap.store_expectation.get(
                "state_acl_sddl_sha256"
            ),
        }
        if any(manifest.get(key) != value for key, value in required_store.items()):
            raise WindowsFinalInstallerError("INSTALLER_STORE_MANIFEST_MISMATCH")
        host.initialize_secure_durable_journal_create_only(
            store_root=bootstrap.store_root,
            store_expectation=bootstrap.store_expectation,
            owner_sid=bootstrap.owner_sid,
            directory_acl_sddl=bootstrap.directory_acl_sddl,
        )
        self._checkpoint = InstallCheckpointV1.PREPARED
        self._backup_id: str | None = None
        self._publish_receipt: str | None = None
        self._transition_receipt: str | None = None

    def stage_and_publish(self, *, bundle_raw: bytes) -> InstallResultV1:
        """Event 1/2.  Failure here may restore only the exact captured backup."""
        if self._checkpoint is not InstallCheckpointV1.PREPARED:
            raise WindowsFinalInstallerError("INSTALL_STAGE_STATE_INVALID")
        manifest = self._manifest
        bindings = self._target.manifest_bindings
        if manifest["bundle_sha256"] != self._bundle.bundle_sha256:
            raise WindowsFinalInstallerError("INSTALL_BUNDLE_MANIFEST_MISMATCH")
        if bindings["bundle_sha256"] != self._bundle.bundle_sha256:
            raise WindowsFinalInstallerError("INSTALL_TARGET_MANIFEST_MISMATCH")
        preinstall = self._host.query_scm_readback(manifest["service_name"])
        expected_preinstall = self._target.preinstall_service_config
        _exact_scm(expected_preinstall, preinstall)
        _exact_registry_security(
            preinstall,
            owner_sha256=manifest["expected_service_config_owner_sid_sha256"],
            acl_sha256=manifest["expected_service_config_acl_sddl_sha256"],
        )
        self._backup_id = self._host.backup_scm_and_pywin32_registry_create_only(
            service_name=manifest["service_name"], readback=preinstall
        )
        self._host.append_install_event_create_only(
            install_attempt_id=manifest["install_attempt_id"],
            event_sequence=1,
            state=InstallCheckpointV1.PREPARED.value,
            details_sha256=_sha(
                {
                    "backup_id": self._backup_id,
                    "preinstall": preinstall.canonical_sha256(),
                }
            ),
        )
        try:
            receipt, files = (
                self._host.publish_same_volume_content_addressed_create_only(
                    bundle_raw=bundle_raw,
                    bundle_sha256=self._bundle.bundle_sha256,
                    destination_root=str(
                        self._target.component_paths["wrapper"].rsplit("\\", 1)[0]
                    ),
                    **dict(self._target.publish_security),
                )
            )
            for role in ("wrapper", "extension", "launcher", "assembly", "config"):
                _secure_component(
                    files[role],
                    expected_path_sha256=bindings[f"{role}_destination_path_sha256"],
                    expected_raw_sha256=self._bundle.component_sha256s[role],
                    owner=bindings["expected_final_owner_sid_sha256"],
                    acl=bindings["expected_component_acl_sddl_sha256"],
                )
            self._publish_receipt = receipt
            self._host.append_install_event_create_only(
                install_attempt_id=manifest["install_attempt_id"],
                event_sequence=2,
                state=InstallCheckpointV1.FILES_PUBLISHED.value,
                details_sha256=_sha(
                    {"receipt": receipt, "bundle": self._bundle.bundle_sha256}
                ),
            )
            self._checkpoint = InstallCheckpointV1.FILES_PUBLISHED
        except Exception as exc:
            self._host.remove_pre_event3_published_orphan(
                destination_root=str(
                    self._target.component_paths["wrapper"].rsplit("\\", 1)[0]
                ),
                install_attempt_id=manifest["install_attempt_id"],
                bundle_sha256=self._bundle.bundle_sha256,
                component_sha256s=self._bundle.component_sha256s,
                owner_sid_sha256=manifest["expected_final_owner_sid_sha256"],
                component_acl_sddl_sha256=manifest[
                    "expected_component_acl_sddl_sha256"
                ],
                final_owner_sid_sha256=manifest["expected_final_owner_sid_sha256"],
                final_directory_acl_sddl_sha256=manifest[
                    "expected_final_directory_acl_sddl_sha256"
                ],
            )
            self._host.restore_pre_event3_backup(backup_id=self._backup_id)
            raise WindowsFinalInstallerError("INSTALL_PRE_EVENT3_ROLLED_BACK") from exc
        return self.result()

    def reserve_event3_and_apply_target(self) -> InstallResultV1:
        """Event 3 is irreversible: later uncertainty may only query/fail frozen."""
        if self._checkpoint is not InstallCheckpointV1.FILES_PUBLISHED:
            raise WindowsFinalInstallerError("INSTALL_EVENT3_STATE_INVALID")
        manifest = self._manifest
        event_2_raw = self.read_event_readback(event_sequence=2)
        event_3_details = (
            {"event_2_raw_sha256": hashlib.sha256(event_2_raw).hexdigest()}
            if self._backup_id == "journal-resume"
            else {
                "publish_receipt": self._publish_receipt,
                "backup_id": self._backup_id,
            }
        )
        self._host.append_install_event_create_only(
            install_attempt_id=manifest["install_attempt_id"],
            event_sequence=3,
            state=InstallCheckpointV1.EVENT3_RESERVED.value,
            details_sha256=_sha(event_3_details),
        )
        self._checkpoint = InstallCheckpointV1.EVENT3_RESERVED
        try:
            before = self._host.query_scm_readback(manifest["service_name"])
            _exact_scm(self._target.preinstall_service_config, before)
            self._host.apply_exact_scm_and_pywin32_registry_once(
                expected_before=before,
                target=self._target.safety_service_config,
                registry_security=self._target.registry_security,
            )
            safety = self._host.query_scm_readback(manifest["service_name"])
            _exact_scm(self._target.safety_service_config, safety)
            _exact_registry_security(
                safety,
                owner_sha256=manifest["expected_service_config_owner_sid_sha256"],
                acl_sha256=manifest["expected_service_config_acl_sddl_sha256"],
            )
            self._host.apply_exact_scm_and_pywin32_registry_once(
                expected_before=safety,
                target=self._target.target_service_config,
                registry_security=self._target.registry_security,
            )
            after = self._host.query_scm_readback(manifest["service_name"])
            _exact_scm(self._target.target_service_config, after)
            _exact_registry_security(
                after,
                owner_sha256=manifest["expected_service_config_owner_sid_sha256"],
                acl_sha256=manifest["expected_service_config_acl_sddl_sha256"],
            )
            bindings = self._target.manifest_bindings
            if (
                hashlib.sha256(after.python_class.encode()).hexdigest()
                != bindings["python_class_sha256"]
                or hashlib.sha256(after.python_path.encode()).hexdigest()
                != bindings["python_path_sha256"]
            ):
                raise WindowsFinalInstallerError("PYWIN32_REGISTRY_BINDING_MISMATCH")
            self._transition_receipt = _sha(
                {
                    "before": before.canonical_sha256(),
                    "safety": safety.canonical_sha256(),
                    "after": after.canonical_sha256(),
                }
            )
            self._host.append_install_event_create_only(
                install_attempt_id=manifest["install_attempt_id"],
                event_sequence=4,
                state=InstallCheckpointV1.TARGET_READY.value,
                details_sha256=self._transition_receipt,
            )
            self._checkpoint = InstallCheckpointV1.TARGET_READY
            return self.result()
        except Exception as exc:
            # Do not resurrect a pre-fence store/config after event 3.  The
            # authorized successor is an explicit frozen failure record only.
            self._checkpoint = InstallCheckpointV1.FAILED_FROZEN
            raise WindowsFinalInstallerError(
                "INSTALL_POST_EVENT3_FAILED_FROZEN"
            ) from exc

    def query_unknown_restart_only(self) -> str:
        if self._checkpoint not in {
            InstallCheckpointV1.EVENT3_RESERVED,
            InstallCheckpointV1.TARGET_READY,
            InstallCheckpointV1.FAILED_FROZEN,
        }:
            raise WindowsFinalInstallerError("INSTALL_RESTART_QUERY_STATE_INVALID")
        return self._host.query_same_restart_attempt_only(
            install_attempt_id=self._manifest["install_attempt_id"]
        )

    def read_event_readback(self, *, event_sequence: int) -> bytes:
        """Read the existing native journal; no event may be caller supplied."""
        reader = getattr(self._host, "read_install_event_read_only", None)
        if not callable(reader):
            raise WindowsFinalInstallerError("INSTALL_EVENT_READBACK_UNAVAILABLE")
        try:
            return reader(
                install_attempt_id=self._manifest["install_attempt_id"],
                event_sequence=event_sequence,
            )
        except WindowsFinalInstallerError:
            raise
        except Exception as exc:
            raise WindowsFinalInstallerError("INSTALL_EVENT_READBACK_FAILED") from exc

    def resume_from_secure_journal(self, *, frontier_sequence: int) -> None:
        """Rehydrate only a completed journal prefix for the same attempt.

        This does not recreate a backup, publish files, or apply SCM state.  It
        merely re-establishes the in-memory checkpoint required by the existing
        v1 operations after their create-only journal records have been read.
        """
        expected = {
            1: InstallCheckpointV1.PREPARED.value,
            2: InstallCheckpointV1.FILES_PUBLISHED.value,
            3: InstallCheckpointV1.EVENT3_RESERVED.value,
            4: InstallCheckpointV1.TARGET_READY.value,
            5: "RESTART_DISPATCHED_FROZEN",
            6: "START_OBSERVED_FROZEN",
            7: "FOUNDATION_VERIFIED_FROZEN",
        }
        if frontier_sequence not in range(2, 8):
            raise WindowsFinalInstallerError("INSTALL_RESUME_FRONTIER_INVALID")
        for sequence in range(1, frontier_sequence + 1):
            try:
                value = json.loads(self.read_event_readback(event_sequence=sequence))
            except (TypeError, ValueError) as exc:
                raise WindowsFinalInstallerError(
                    "INSTALL_RESUME_JOURNAL_INVALID"
                ) from exc
            if (
                not isinstance(value, dict)
                or value.get("install_attempt_id")
                != self._manifest["install_attempt_id"]
                or value.get("event_sequence") != sequence
                or value.get("state") != expected[sequence]
            ):
                raise WindowsFinalInstallerError("INSTALL_RESUME_JOURNAL_INVALID")
        self._backup_id = "journal-resume"
        if frontier_sequence == 2:
            self._checkpoint = InstallCheckpointV1.FILES_PUBLISHED
        elif frontier_sequence == 3:
            self._checkpoint = InstallCheckpointV1.EVENT3_RESERVED
        else:
            self._checkpoint = InstallCheckpointV1.TARGET_READY

    def dispatch_reserved_restart_once(
        self, *, restart_authorization_raw: bytes
    ) -> None:
        """Dispatch once after Event3/4; Event5 follows signed SCM readback."""
        if self._checkpoint is not InstallCheckpointV1.TARGET_READY:
            raise WindowsFinalInstallerError("INSTALL_RESTART_DISPATCH_STATE_INVALID")
        if (
            type(restart_authorization_raw) is not bytes
            or not restart_authorization_raw
        ):
            raise WindowsFinalInstallerError("INSTALL_RESTART_AUTHORIZATION_INVALID")
        dispatch = getattr(self._host, "dispatch_reserved_restart_once", None)
        if not callable(dispatch):
            raise WindowsFinalInstallerError("INSTALL_RESTART_DISPATCH_UNAVAILABLE")
        try:
            dispatch(
                install_attempt_id=self._manifest["install_attempt_id"],
                service_name=self._manifest["service_name"],
                restart_authorization_raw_sha256=hashlib.sha256(
                    restart_authorization_raw
                ).hexdigest(),
            )
        except WindowsFinalInstallerError:
            raise
        except Exception as exc:
            raise WindowsFinalInstallerError(
                "INSTALL_RESTART_DISPATCH_UNKNOWN"
            ) from exc

    def query_service_runtime_readback(self) -> Mapping[str, Any]:
        """Event6/7 read-only SCM/process source; no portable fallback exists."""
        reader = getattr(self._host, "query_service_runtime_readback", None)
        if not callable(reader):
            raise WindowsFinalInstallerError("INSTALL_RUNTIME_READBACK_UNAVAILABLE")
        try:
            value = reader(service_name=self._manifest["service_name"])
        except WindowsFinalInstallerError:
            raise
        except Exception as exc:
            raise WindowsFinalInstallerError("INSTALL_RUNTIME_READBACK_FAILED") from exc
        if (
            not isinstance(value, Mapping)
            or value.get("service_name") != self._manifest["service_name"]
        ):
            raise WindowsFinalInstallerError("INSTALL_RUNTIME_READBACK_INVALID")
        return value

    def append_signed_evidence_event(
        self, *, event_sequence: int, evidence_raw: bytes
    ) -> bytes:
        """Append an existing v1 signed evidence raw-hash join only."""
        expected = {
            5: ("RESTART_DISPATCHED_FROZEN", 4),
            6: ("START_OBSERVED_FROZEN", 5),
            7: ("FOUNDATION_VERIFIED_FROZEN", 6),
        }.get(event_sequence)
        if self._checkpoint is not InstallCheckpointV1.TARGET_READY or expected is None:
            raise WindowsFinalInstallerError("INSTALL_OBSERVATION_EVENT_STATE_INVALID")
        if type(evidence_raw) is not bytes or not evidence_raw:
            raise WindowsFinalInstallerError("INSTALL_SIGNED_EVIDENCE_EVENT_INVALID")
        self.read_event_readback(event_sequence=expected[1])
        self._host.append_install_event_create_only(
            install_attempt_id=self._manifest["install_attempt_id"],
            event_sequence=event_sequence,
            state=expected[0],
            details_sha256=hashlib.sha256(evidence_raw).hexdigest(),
        )
        return self.read_event_readback(event_sequence=event_sequence)

    def result(self) -> InstallResultV1:
        if self._backup_id is None:
            raise WindowsFinalInstallerError("INSTALL_RESULT_UNAVAILABLE")
        return InstallResultV1(
            checkpoint=self._checkpoint,
            backup_id=self._backup_id,
            publish_receipt_raw_sha256=self._publish_receipt,
            transition_receipt_raw_sha256=self._transition_receipt,
        )


__all__ = [
    "FinalWindowsFenceInstallerV1",
    "InstallCheckpointV1",
    "InstallResultV1",
    "WindowsFenceInstallerHostV1",
    "WindowsFinalInstallerError",
    "WindowsPathReadbackV1",
    "WindowsScmReadbackV1",
]
