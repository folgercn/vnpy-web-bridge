from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from scripts.windows_fence_foundation.target_contract_v1 import (
    WindowsFoundationTargetContractError,
    WindowsFoundationTargetPolicyV1,
    canonical_windows_absolute_path,
    derive_windows_foundation_target_v1,
    parse_windows_foundation_target_policy_v1,
)

SHA = "a" * 64
OTHER_SHA = "b" * 64
FINAL_OWNER = "S-1-5-18"
FINAL_ACL = "O:SYD:PAI"
COMPONENT_ACL = "O:SYD:PAI(A;;FA;;;SY)"


def _policy() -> WindowsFoundationTargetPolicyV1:
    return WindowsFoundationTargetPolicyV1(
        service_name="VnpyRpcService",
        final_versions_root=r"C:\ProgramData\vnpy-web-bridge\windows-fence\versions",
        service_executable_path=r"C:\veighna_studio\pythonservice.exe",
        service_python_class="windows_rpc_service_wrapper_v1.VnpyRpcServiceWrapperV1",
        image_argument_template=(
            "{wrapper}",
            "--wrapper-sha256",
            "{wrapper_sha256}",
            "{launcher}",
            "--launcher-sha256",
            "{launcher_sha256}",
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
        ),
        service_account_sid_sha256=SHA,
        service_dependencies=("Tcpip",),
        store_root_path=r"C:\ProgramData\vnpy-web-bridge\windows-fence\store",
        store_volume_serial="A1B2C3D4",
        store_volume_identity_sha256=SHA,
        store_owner_sid_sha256=SHA,
        store_directory_acl_sddl_sha256=SHA,
        store_state_acl_sddl_sha256=SHA,
        final_owner_sid_sha256=hashlib.sha256(FINAL_OWNER.encode()).hexdigest(),
        final_directory_acl_sddl_sha256=hashlib.sha256(FINAL_ACL.encode()).hexdigest(),
        component_acl_sddl_sha256=hashlib.sha256(COMPONENT_ACL.encode()).hexdigest(),
        final_owner_sid=FINAL_OWNER,
        final_directory_acl_sddl=FINAL_ACL,
        component_acl_sddl=COMPONENT_ACL,
        service_config_owner_sid_sha256=hashlib.sha256(
            FINAL_OWNER.encode()
        ).hexdigest(),
        service_config_acl_sddl_sha256=hashlib.sha256(FINAL_ACL.encode()).hexdigest(),
        service_config_owner_sid=FINAL_OWNER,
        service_config_acl_sddl=FINAL_ACL,
        installer_principal_sid_sha256=SHA,
        installer_process_image_sha256=SHA,
    )


def _projection():
    return derive_windows_foundation_target_v1(
        policy=_policy(),
        bundle_sha256=SHA,
        wrapper_sha256=SHA,
        extension_sha256=SHA,
        launcher_sha256=SHA,
        assembly_sha256=SHA,
        config_sha256=SHA,
        preinstall_image_path={
            "application_path": r"C:\veighna_studio\pythonservice.exe",
            "arguments": [],
        },
        preinstall_python_class="legacy.module.Service",
        preinstall_python_path=r"C:\quant",
        preinstall_start_type="AUTO_START",
        preinstall_failure_actions=[{"action": "restart"}],
        preinstall_recovery_actions=[{"action": "restart"}],
    )


@pytest.mark.parametrize(
    "path",
    [
        r"relative\file.py",
        r"\\server\share\file.py",
        r"C:/mixed/separator.py",
        r"C:\safe\..\escape.py",
        r"C:\safe\payload.py:stream",
        r"C:\safe\CON.txt",
        r"C:\safe\trailing.\file.py",
        r"C:\safe\%TEMP%\file.py",
        r"C:\safe\wild?card.py",
        "C:\\safe\\e\u0301.py",
    ],
)
def test_windows_path_contract_rejects_alias_and_traversal(path: str) -> None:
    with pytest.raises(WindowsFoundationTargetContractError):
        canonical_windows_absolute_path(path)


def test_target_projection_binds_content_addressed_paths_and_safe_scm_transition() -> (
    None
):
    projection = _projection()
    bindings = projection.manifest_bindings

    final_directory = (
        "C:\\ProgramData\\vnpy-web-bridge\\windows-fence\\versions\\" + SHA
    )
    assert (
        bindings["final_version_directory_path_sha256"]
        == hashlib.sha256(final_directory.encode()).hexdigest()
    )
    assert projection.component_paths["assembly"].endswith(
        r"\windows_fence_foundation_v1.pyz"
    )
    assert projection.component_paths["config"].endswith(
        r"\windows_rpc_service_config_v1.json"
    )
    assert projection.store_policy["sole_writer_must_equal_service_sid"] is True
    assert (
        projection.safety_service_config["image_path"]
        == (projection.preinstall_service_config["image_path"])
    )
    assert projection.safety_service_config["start_type"] == "DEMAND_START"
    assert projection.safety_service_config["failure_actions"] == ()
    assert projection.safety_service_config["recovery_actions"] == ()
    assert (
        projection.target_service_config["image_path"]
        != (projection.preinstall_service_config["image_path"])
    )
    assert projection.transition_plan["restart_authorized"] is False
    assert projection.transition_plan["automatic_policy_restore_authorized"] is False
    assert bindings["installer_write_access_after_publish"] is False
    with pytest.raises(TypeError):
        projection.target_service_config["image_path"]["application_path"] = (  # type: ignore[index]
            r"C:\unsafe.exe"
        )


def test_signed_target_policy_is_complete_and_reconstructible() -> None:
    policy = _policy()
    raw = dict(policy.manifest_value())
    assert parse_windows_foundation_target_policy_v1(raw) == policy
    assert raw["final_versions_root"].endswith(r"\versions")
    assert raw["service_python_class"] == policy.service_python_class
    assert raw["image_argument_template"][-1] == "{config_sha256}"
    del raw["component_acl_sddl"]
    with pytest.raises(WindowsFoundationTargetContractError):
        parse_windows_foundation_target_policy_v1(raw)


def test_any_bundle_or_component_change_changes_derived_manifest_binding() -> None:
    baseline = _projection().manifest_bindings
    changed = derive_windows_foundation_target_v1(
        policy=_policy(),
        bundle_sha256=OTHER_SHA,
        wrapper_sha256=OTHER_SHA,
        extension_sha256=OTHER_SHA,
        launcher_sha256=SHA,
        assembly_sha256=SHA,
        config_sha256=SHA,
        preinstall_image_path={
            "application_path": r"C:\veighna_studio\pythonservice.exe",
            "arguments": [],
        },
        preinstall_python_class="legacy.module.Service",
        preinstall_python_path=r"C:\quant",
        preinstall_start_type="AUTO_START",
        preinstall_failure_actions=[],
        preinstall_recovery_actions=[],
    ).manifest_bindings
    assert changed["bundle_sha256"] != baseline["bundle_sha256"]
    assert changed["extension_sha256"] != baseline["extension_sha256"]
    assert (
        changed["final_version_directory_path_sha256"]
        != (baseline["final_version_directory_path_sha256"])
    )
    assert (
        changed["service_image_path_canonical_sha256"]
        != (baseline["service_image_path_canonical_sha256"])
    )


def test_policy_rejects_incomplete_launcher_binding_and_unsafe_service_identity() -> (
    None
):
    with pytest.raises(
        WindowsFoundationTargetContractError, match="IMAGE_ARGUMENT_TEMPLATE_INVALID"
    ):
        replace(_policy(), image_argument_template=("{launcher}", "{config}"))
    with pytest.raises(WindowsFoundationTargetContractError):
        replace(_policy(), service_executable_path=r"\\host\share\service.exe")
    with pytest.raises(WindowsFoundationTargetContractError):
        replace(_policy(), service_dependencies=("Tcpip", "tcpip"))
    with pytest.raises(WindowsFoundationTargetContractError):
        replace(_policy(), service_dependencies=["Tcpip"])  # type: ignore[arg-type]
    with pytest.raises(WindowsFoundationTargetContractError):
        replace(
            _policy(),
            final_versions_root=(
                r"C:\ProgramData\vnpy-web-bridge\windows-fence\store\versions"
            ),
        )


def test_projection_rejects_untrusted_preinstall_shapes_and_unknown_start_type() -> (
    None
):
    kwargs = {
        "policy": _policy(),
        "bundle_sha256": SHA,
        "wrapper_sha256": SHA,
        "extension_sha256": SHA,
        "launcher_sha256": SHA,
        "assembly_sha256": SHA,
        "config_sha256": SHA,
        "preinstall_image_path": {
            "application_path": r"C:\old\service.exe",
            "arguments": [],
        },
        "preinstall_python_class": "legacy.module.Service",
        "preinstall_python_path": r"C:\quant",
        "preinstall_start_type": "AUTO_START",
        "preinstall_failure_actions": [],
        "preinstall_recovery_actions": [],
    }
    with pytest.raises(WindowsFoundationTargetContractError):
        derive_windows_foundation_target_v1(
            **{**kwargs, "preinstall_start_type": "BOOT_START"}
        )
    with pytest.raises(WindowsFoundationTargetContractError):
        derive_windows_foundation_target_v1(
            **{
                **kwargs,
                "preinstall_image_path": {
                    "application_path": r"C:\old\service.exe",
                    "arguments": [],
                    "untrusted": True,
                },
            }
        )
