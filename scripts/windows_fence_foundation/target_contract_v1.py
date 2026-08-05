"""Pure WF-2 Windows path, ACL, and SCM transition contract derivation."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PureWindowsPath
from types import MappingProxyType
from typing import Any

from .contracts import (
    StoreContractError,
    canonical_json_bytes,
    canonical_local_windows_path,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VOLUME_SERIAL_RE = re.compile(r"^[A-F0-9]{8,32}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_COMPONENT_FILENAMES = MappingProxyType(
    {
        "extension": "windows_rpc_deployment_snapshot_v1.py",
        "launcher": "windows_rpc_durable_fence_v1.py",
        "assembly": "windows_fence_foundation_v1.pyz",
        "config": "windows_rpc_service_config_v1.json",
    }
)
_IMAGE_PLACEHOLDERS = frozenset(
    {
        "{extension}",
        "{extension_sha256}",
        "{launcher}",
        "{assembly}",
        "{assembly_sha256}",
        "{config}",
        "{config_sha256}",
        "{final_directory}",
    }
)
_REQUIRED_IMAGE_PLACEHOLDERS = frozenset(
    {
        "{extension}",
        "{extension_sha256}",
        "{launcher}",
        "{assembly}",
        "{assembly_sha256}",
        "{config}",
        "{config_sha256}",
    }
)
_EXPECTED_IMAGE_ARGUMENT_TEMPLATE = (
    "{launcher}",
    "--extension",
    "{extension}",
    "--extension-sha256",
    "{extension_sha256}",
    "--assembly",
    "{assembly}",
    "--assembly-sha256",
    "{assembly_sha256}",
    "--config",
    "{config}",
    "--config-sha256",
    "{config_sha256}",
)


class WindowsFoundationTargetContractError(ValueError):
    """Stable fail-closed error raised by the pure target contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require_sha(value: str, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise WindowsFoundationTargetContractError(f"{field.upper()}_INVALID")
    return value


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def canonical_windows_absolute_path(value: str) -> str:
    """Return the one accepted spelling of a local absolute Windows path."""
    try:
        return canonical_local_windows_path(value)
    except StoreContractError as exc:
        raise WindowsFoundationTargetContractError(exc.code) from exc


def _join(root: str, name: str) -> str:
    return canonical_windows_absolute_path(str(PureWindowsPath(root) / name))


def _validate_image_arguments(arguments: tuple[str, ...]) -> None:
    if type(arguments) is not tuple or not arguments:
        raise WindowsFoundationTargetContractError("IMAGE_ARGUMENT_TEMPLATE_EMPTY")
    if arguments != _EXPECTED_IMAGE_ARGUMENT_TEMPLATE:
        raise WindowsFoundationTargetContractError("IMAGE_ARGUMENT_TEMPLATE_INVALID")
    seen: set[str] = set()
    for argument in arguments:
        if not isinstance(argument, str) or not argument or "\x00" in argument:
            raise WindowsFoundationTargetContractError(
                "IMAGE_ARGUMENT_TEMPLATE_INVALID"
            )
        placeholders = {item for item in _IMAGE_PLACEHOLDERS if item in argument}
        residue = argument
        for item in placeholders:
            residue = residue.replace(item, "")
        if "{" in residue or "}" in residue:
            raise WindowsFoundationTargetContractError(
                "IMAGE_ARGUMENT_PLACEHOLDER_UNKNOWN"
            )
        seen.update(placeholders)
    if seen != _REQUIRED_IMAGE_PLACEHOLDERS:
        raise WindowsFoundationTargetContractError("IMAGE_ARGUMENT_BINDING_INCOMPLETE")


@dataclass(frozen=True)
class WindowsFoundationTargetPolicyV1:
    """Externally pinned policy used to derive manifest hash expectations."""

    service_name: str
    final_versions_root: str
    service_executable_path: str
    image_argument_template: tuple[str, ...]
    service_account_sid_sha256: str
    service_dependencies: tuple[str, ...]
    store_root_path: str
    store_volume_serial: str
    store_volume_identity_sha256: str
    store_owner_sid_sha256: str
    store_directory_acl_sddl_sha256: str
    store_state_acl_sddl_sha256: str
    final_owner_sid_sha256: str
    final_directory_acl_sddl_sha256: str
    component_acl_sddl_sha256: str
    service_config_owner_sid_sha256: str
    service_config_acl_sddl_sha256: str
    installer_principal_sid_sha256: str
    installer_process_image_sha256: str

    def __post_init__(self) -> None:
        if not SERVICE_RE.fullmatch(self.service_name):
            raise WindowsFoundationTargetContractError("SERVICE_NAME_INVALID")
        object.__setattr__(
            self,
            "final_versions_root",
            canonical_windows_absolute_path(self.final_versions_root),
        )
        object.__setattr__(
            self,
            "service_executable_path",
            canonical_windows_absolute_path(self.service_executable_path),
        )
        object.__setattr__(
            self,
            "store_root_path",
            canonical_windows_absolute_path(self.store_root_path),
        )
        final_root = self.final_versions_root.casefold()
        store_root = self.store_root_path.casefold()
        if (
            final_root == store_root
            or final_root.startswith(store_root + "\\")
            or store_root.startswith(final_root + "\\")
        ):
            raise WindowsFoundationTargetContractError("TARGET_AND_STORE_PATHS_OVERLAP")
        _validate_image_arguments(self.image_argument_template)
        if not isinstance(
            self.store_volume_serial, str
        ) or not VOLUME_SERIAL_RE.fullmatch(self.store_volume_serial):
            raise WindowsFoundationTargetContractError("STORE_VOLUME_SERIAL_INVALID")
        for field in (
            "service_account_sid_sha256",
            "store_volume_identity_sha256",
            "store_owner_sid_sha256",
            "store_directory_acl_sddl_sha256",
            "store_state_acl_sddl_sha256",
            "final_owner_sid_sha256",
            "final_directory_acl_sddl_sha256",
            "component_acl_sddl_sha256",
            "service_config_owner_sid_sha256",
            "service_config_acl_sddl_sha256",
            "installer_principal_sid_sha256",
            "installer_process_image_sha256",
        ):
            _require_sha(getattr(self, field), field)
        if (
            type(self.service_dependencies) is not tuple
            or not self.service_dependencies
            or any(not SERVICE_RE.fullmatch(item) for item in self.service_dependencies)
            or len({item.casefold() for item in self.service_dependencies})
            != len(self.service_dependencies)
        ):
            raise WindowsFoundationTargetContractError("SERVICE_DEPENDENCIES_INVALID")


@dataclass(frozen=True)
class WindowsFoundationTargetProjectionV1:
    manifest_bindings: Mapping[str, Any]
    component_paths: Mapping[str, str]
    store_policy: Mapping[str, Any]
    preinstall_service_config: Mapping[str, Any]
    safety_service_config: Mapping[str, Any]
    target_service_config: Mapping[str, Any]
    transition_plan: Mapping[str, Any]


def _render_image_path(
    policy: WindowsFoundationTargetPolicyV1,
    component_paths: Mapping[str, str],
    component_sha256s: Mapping[str, str],
) -> dict[str, Any]:
    values = {
        **component_paths,
        **{f"{role}_sha256": digest for role, digest in component_sha256s.items()},
        "final_directory": str(PureWindowsPath(component_paths["launcher"]).parent),
    }
    arguments = []
    for template in policy.image_argument_template:
        argument = template
        for key, value in values.items():
            argument = argument.replace(f"{{{key}}}", value)
        arguments.append(argument)
    return {
        "application_path": policy.service_executable_path,
        "arguments": arguments,
    }


def derive_windows_foundation_target_v1(
    *,
    policy: WindowsFoundationTargetPolicyV1,
    bundle_sha256: str,
    extension_sha256: str,
    launcher_sha256: str,
    assembly_sha256: str,
    config_sha256: str,
    preinstall_image_path: Mapping[str, Any],
    preinstall_start_type: str,
    preinstall_failure_actions: list[Mapping[str, Any]],
    preinstall_recovery_actions: list[Mapping[str, Any]],
) -> WindowsFoundationTargetProjectionV1:
    """Derive exact path and service-config hashes without mutating the host."""
    for field, value in (
        ("bundle_sha256", bundle_sha256),
        ("extension_sha256", extension_sha256),
        ("launcher_sha256", launcher_sha256),
        ("assembly_sha256", assembly_sha256),
        ("config_sha256", config_sha256),
    ):
        _require_sha(value, field)
    if preinstall_start_type not in {"AUTO_START", "DEMAND_START", "DISABLED"}:
        raise WindowsFoundationTargetContractError("PREINSTALL_START_TYPE_INVALID")
    preinstall_image = dict(preinstall_image_path)
    if set(preinstall_image) != {"application_path", "arguments"}:
        raise WindowsFoundationTargetContractError("PREINSTALL_IMAGE_PATH_INVALID")
    preinstall_image["application_path"] = canonical_windows_absolute_path(
        preinstall_image["application_path"]
    )
    if not isinstance(preinstall_image["arguments"], list) or any(
        not isinstance(item, str) or "\x00" in item
        for item in preinstall_image["arguments"]
    ):
        raise WindowsFoundationTargetContractError("PREINSTALL_IMAGE_PATH_INVALID")

    final_directory = _join(policy.final_versions_root, bundle_sha256)
    component_paths = {
        name: _join(final_directory, filename)
        for name, filename in _COMPONENT_FILENAMES.items()
    }
    component_sha256s = {
        "extension": extension_sha256,
        "launcher": launcher_sha256,
        "assembly": assembly_sha256,
        "config": config_sha256,
    }
    target_image = _render_image_path(policy, component_paths, component_sha256s)
    common = {
        "service_name": policy.service_name,
        "service_account_sid_sha256": policy.service_account_sid_sha256,
        "dependencies": list(policy.service_dependencies),
    }
    preinstall = {
        **common,
        "image_path": preinstall_image,
        "start_type": preinstall_start_type,
        "failure_actions": list(preinstall_failure_actions),
        "recovery_actions": list(preinstall_recovery_actions),
    }
    safety = {
        **common,
        "image_path": preinstall_image,
        "start_type": "DEMAND_START",
        "failure_actions": [],
        "recovery_actions": [],
    }
    target = {
        **common,
        "image_path": target_image,
        "start_type": "DEMAND_START",
        "failure_actions": [],
        "recovery_actions": [],
    }
    transition = {
        "schema_version": "windows_rpc_durable_fence_service_transition_plan_v1",
        "purpose": "freeze_safe_preinstall_to_exact_target_without_restart",
        "service_name": policy.service_name,
        "authorized_changed_fields": [
            "FailureActions",
            "ImagePath",
            "RecoveryActions",
            "StartType",
        ],
        "preinstall_service_config_sha256": _canonical_hash(preinstall),
        "safety_service_config_sha256": _canonical_hash(safety),
        "target_service_config_sha256": _canonical_hash(target),
        "service_account_unchanged": True,
        "dependencies_unchanged": True,
        "restart_authorized": False,
        "automatic_policy_restore_authorized": False,
    }
    bindings = {
        "service_name": policy.service_name,
        "store_path_sha256": hashlib.sha256(
            policy.store_root_path.encode("utf-8")
        ).hexdigest(),
        "store_volume_serial": policy.store_volume_serial,
        "store_volume_identity_sha256": policy.store_volume_identity_sha256,
        "bundle_sha256": bundle_sha256,
        "publish_mode": "atomic_content_addressed_final_directory",
        "final_version_directory_path_sha256": hashlib.sha256(
            final_directory.encode("utf-8")
        ).hexdigest(),
        "expected_final_owner_sid_sha256": policy.final_owner_sid_sha256,
        "expected_final_directory_acl_sddl_sha256": (
            policy.final_directory_acl_sddl_sha256
        ),
        "expected_component_acl_sddl_sha256": policy.component_acl_sddl_sha256,
        "extension_version": "windows-rpc-durable-fence-foundation-v1",
        "extension_sha256": extension_sha256,
        "extension_destination_path_sha256": hashlib.sha256(
            component_paths["extension"].encode("utf-8")
        ).hexdigest(),
        "launcher_sha256": launcher_sha256,
        "launcher_destination_path_sha256": hashlib.sha256(
            component_paths["launcher"].encode("utf-8")
        ).hexdigest(),
        "assembly_sha256": assembly_sha256,
        "assembly_destination_path_sha256": hashlib.sha256(
            component_paths["assembly"].encode("utf-8")
        ).hexdigest(),
        "config_sha256": config_sha256,
        "config_destination_path_sha256": hashlib.sha256(
            component_paths["config"].encode("utf-8")
        ).hexdigest(),
        "service_image_path_canonical_sha256": _canonical_hash(target_image),
        "service_config_canonical_sha256": _canonical_hash(target),
        "expected_service_config_owner_sid_sha256": (
            policy.service_config_owner_sid_sha256
        ),
        "expected_service_config_acl_sddl_sha256": (
            policy.service_config_acl_sddl_sha256
        ),
        "installer_write_access_after_publish": False,
        "preinstall_service_image_path_canonical_sha256": _canonical_hash(
            preinstall_image
        ),
        "preinstall_service_config_canonical_sha256": _canonical_hash(preinstall),
        "safety_service_config_canonical_sha256": _canonical_hash(safety),
        "service_config_transition_plan_sha256": _canonical_hash(transition),
        "service_config_mutation_before_dispatch_reservation_authorized": False,
        "service_config_transition_after_dispatch_reservation_authorized": True,
        "unbound_service_config_mutation_after_observer_seal_authorized": False,
        "target_service_start_type": "DEMAND_START",
        "target_recovery_actions_disabled": True,
        "target_failure_actions_disabled": True,
        "automatic_policy_restore_authorized": False,
        "expected_installer_principal_sid_sha256": (
            policy.installer_principal_sid_sha256
        ),
        "expected_installer_process_image_sha256": (
            policy.installer_process_image_sha256
        ),
        "target_state_schema_version": "windows_rpc_durable_fence_state_v1",
    }
    store_policy = {
        "root_path": policy.store_root_path,
        "owner_sid_sha256": policy.store_owner_sid_sha256,
        "directory_acl_sddl_sha256": policy.store_directory_acl_sddl_sha256,
        "state_acl_sddl_sha256": policy.store_state_acl_sddl_sha256,
        "sole_writer_must_equal_service_sid": True,
    }

    def freeze(item: Any) -> Any:
        if isinstance(item, dict):
            return MappingProxyType({key: freeze(value) for key, value in item.items()})
        if isinstance(item, list):
            return tuple(freeze(value) for value in item)
        return item

    return WindowsFoundationTargetProjectionV1(
        manifest_bindings=freeze(bindings),
        component_paths=freeze(component_paths),
        store_policy=freeze(store_policy),
        preinstall_service_config=freeze(preinstall),
        safety_service_config=freeze(safety),
        target_service_config=freeze(target),
        transition_plan=freeze(transition),
    )


__all__ = [
    "WindowsFoundationTargetContractError",
    "WindowsFoundationTargetPolicyV1",
    "WindowsFoundationTargetProjectionV1",
    "canonical_windows_absolute_path",
    "derive_windows_foundation_target_v1",
]
