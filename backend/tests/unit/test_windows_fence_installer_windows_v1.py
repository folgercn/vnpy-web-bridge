from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace

import pytest

from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.installer_windows_v1 import (
    FinalWindowsFenceInstallerV1,
    InstallCheckpointV1,
    WindowsFinalInstallerError,
    WindowsPathReadbackV1,
    WindowsScmReadbackV1,
)
from scripts.windows_fence_foundation.manifest_v1 import (
    EXPECTED_BINDING_FIELDS,
    VerifiedInstallManifestV1,
)
from scripts.windows_fence_foundation.native_windows_installer_host_v1 import (
    NativeWindowsFenceInstallerHostV1,
)

SHA = "a" * 64
REGISTRY_OWNER_SHA = hashlib.sha256(b"SYSTEM").hexdigest()
REGISTRY_ACL_SHA = hashlib.sha256(b"O:SYD:PAI").hexdigest()


def _config(*, target: bool, safety: bool = False) -> dict[str, object]:
    return {
        "service_name": "VnpyRpcService",
        "image_path": {
            "application_path": r"C:\veighna_studio\pythonservice.exe",
            "arguments": ["new"] if target else ["old"],
        },
        "start_type": "DEMAND_START" if target or safety else "AUTO_START",
        "failure_actions": [],
        "recovery_actions": [],
        "service_account_sid_sha256": SHA,
        "dependencies": ["Tcpip"],
        "python_class": "windows_rpc_service_wrapper_v1.VnpyRpcServiceWrapperV1"
        if target
        else "legacy.Class",
        "python_path": r"C:\ProgramData\vnpy\versions\bundle"
        if target
        else r"C:\quant",
    }


def _readback(value: dict[str, object]) -> WindowsScmReadbackV1:
    return WindowsScmReadbackV1(
        service_name=value["service_name"],
        image_path=value["image_path"],
        start_type=value["start_type"],
        failure_actions=tuple(value["failure_actions"]),
        recovery_actions=tuple(value["recovery_actions"]),
        service_account_sid_sha256=value["service_account_sid_sha256"],
        dependencies=tuple(value["dependencies"]),
        python_class=value["python_class"],
        python_path=value["python_path"],
        registry_owner_sid_sha256=REGISTRY_OWNER_SHA,
        registry_acl_sddl_sha256=REGISTRY_ACL_SHA,
        registry_owner_sid="SYSTEM",
        registry_acl_sddl="O:SYD:PAI",
    )  # type: ignore[arg-type]


class _Host:
    is_real_windows_host = True

    def __init__(self, *, fail_on_apply: int | None = None) -> None:
        self.current = _readback(_config(target=False))
        self.fail_on_apply = fail_on_apply
        self.restored = False
        self.events: list[int] = []
        self.applied: list[dict[str, object]] = []

    def query_scm_readback(self, _service: str) -> WindowsScmReadbackV1:
        return self.current

    def initialize_secure_durable_journal_create_only(self, **_kwargs: object) -> None:
        return None

    def backup_scm_and_pywin32_registry_create_only(self, **_kwargs: object) -> str:
        return "backup-1"

    def publish_same_volume_content_addressed_create_only(self, **_kwargs: object):
        files = {}
        for role in ("wrapper", "extension", "launcher", "assembly", "config"):
            path = rf"C:\ProgramData\vnpy\versions\bundle\{role}.bin"
            files[role] = WindowsPathReadbackV1(
                path=path,
                raw_sha256=SHA,
                owner_sid_sha256=SHA,
                acl_sddl_sha256=SHA,
                regular_file=True,
                reparse_point=False,
                parent_chain_reparse_free=True,
                hardlink_count=1,
                alternate_data_streams=False,
                dacl_protected=True,
                inherited_ace_count=0,
                unsafe_write_principals=(),
            )
        return "publish-1", files

    def append_install_event_create_only(self, **kwargs: object) -> str:
        self.events.append(kwargs["event_sequence"])  # type: ignore[arg-type]
        return f"event-{kwargs['event_sequence']}"

    def apply_exact_scm_and_pywin32_registry_once(self, **kwargs: object) -> None:
        self.applied.append(kwargs["target"])  # type: ignore[arg-type]
        if self.fail_on_apply == len(self.applied):
            raise RuntimeError("simulated post-event3 fault")
        self.current = _readback(kwargs["target"])  # type: ignore[arg-type]

    def restore_pre_event3_backup(self, **_kwargs: object) -> None:
        self.restored = True

    def remove_pre_event3_published_orphan(self, **_kwargs: object) -> None:
        return None

    def query_same_restart_attempt_only(self, **_kwargs: object) -> str:
        return "QUERY_ONLY"


def _installer(
    host: _Host, *, mutate_target: object | None = None
) -> FinalWindowsFenceInstallerV1:
    components = {
        role: SHA for role in ("wrapper", "extension", "launcher", "assembly", "config")
    }
    paths = {
        role: rf"C:\ProgramData\vnpy\versions\bundle\{role}.bin" for role in components
    }
    bindings: dict[str, str] = {
        "bundle_sha256": SHA,
        "expected_final_owner_sid_sha256": SHA,
        "expected_component_acl_sddl_sha256": SHA,
    }
    for role, path in paths.items():
        bindings[f"{role}_destination_path_sha256"] = hashlib.sha256(
            path.encode()
        ).hexdigest()
    bindings.update(
        {
            "python_class_sha256": hashlib.sha256(
                str(_config(target=True)["python_class"]).encode()
            ).hexdigest(),
            "python_path_sha256": hashlib.sha256(
                str(_config(target=True)["python_path"]).encode()
            ).hexdigest(),
        }
    )
    config = {
        "schema_version": "windows_rpc_durable_fence_service_config_v1",
        "purpose": "launch_fixed_frozen_windows_rpc_service",
        "store_root": r"C:\ProgramData\vnpy\store",
        "store_expectation": {
            "store_id": "windows-fence-store-" + SHA,
            "store_path_sha256": hashlib.sha256(
                rb"C:\ProgramData\vnpy\store"
            ).hexdigest(),
            "store_volume_serial": "A1B2C3D4",
            "store_volume_identity_sha256": SHA,
            "owner_sid_sha256": hashlib.sha256(b"SYSTEM").hexdigest(),
            "directory_acl_sddl_sha256": hashlib.sha256(b"O:SYD:PAI").hexdigest(),
            "state_acl_sddl_sha256": SHA,
            "service_name": "VnpyRpcService",
        },
        "installer_store_bootstrap": {
            "root_path": r"C:\ProgramData\vnpy\store",
            "root_path_sha256": hashlib.sha256(
                rb"C:\ProgramData\vnpy\store"
            ).hexdigest(),
            "owner_sid": "SYSTEM",
            "directory_acl_sddl": "O:SYD:PAI",
        },
        "runtime_config": {},
    }
    config_raw = canonical_json_bytes(config)
    manifest_value: dict[str, object] = {
        field: SHA for field in EXPECTED_BINDING_FIELDS
    }
    manifest_value.update(
        {
            "bundle_sha256": SHA,
            "config_sha256": hashlib.sha256(config_raw).hexdigest(),
            "install_attempt_id": "windows-fence-install-" + SHA,
            "service_name": "VnpyRpcService",
            "store_path_sha256": config["store_expectation"]["store_path_sha256"],
            "store_id": config["store_expectation"]["store_id"],
            "store_volume_serial": "A1B2C3D4",
            "store_volume_identity_sha256": SHA,
            "store_owner_sid_sha256": config["store_expectation"]["owner_sid_sha256"],
            "store_directory_acl_sddl_sha256": config["store_expectation"][
                "directory_acl_sddl_sha256"
            ],
            "store_state_acl_sddl_sha256": SHA,
            "expected_service_config_owner_sid_sha256": REGISTRY_OWNER_SHA,
            "expected_service_config_acl_sddl_sha256": REGISTRY_ACL_SHA,
            "preinstall_service_config_canonical_sha256": hashlib.sha256(
                canonical_json_bytes(_config(target=False))
            ).hexdigest(),
            "service_config_canonical_sha256": hashlib.sha256(
                canonical_json_bytes(_config(target=True))
            ).hexdigest(),
            "safety_service_config_canonical_sha256": hashlib.sha256(
                canonical_json_bytes(_config(target=False, safety=True))
            ).hexdigest(),
        }
    )
    manifest_value.update(bindings)
    bindings.update(manifest_value)
    manifest = VerifiedInstallManifestV1(
        value=manifest_value,
        raw_sha256=SHA,
        install_attempt_immutable_inputs_sha256=SHA,
        verified_at_utc=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ),
    )
    bundle = SimpleNamespace(bundle_sha256=SHA, component_sha256s=components)
    target = SimpleNamespace(
        manifest_bindings=bindings,
        component_paths=paths,
        preinstall_service_config=_config(target=False),
        safety_service_config=_config(target=False, safety=True),
        target_service_config=_config(target=True),
        publish_security={
            "final_owner_sid": "SYSTEM",
            "final_directory_acl_sddl": "O:SYD:PAI",
            "component_acl_sddl": "O:SYD:PAI",
        },
        registry_security={"owner_sid": "SYSTEM", "acl_sddl": "O:SYD:PAI"},
    )
    if mutate_target is not None:
        mutate_target(target)  # type: ignore[operator]
    return FinalWindowsFenceInstallerV1(
        host=host,
        manifest=manifest,
        bundle=bundle,
        target_projection=target,
        public_config_raw=config_raw,
    )


def test_event3_makes_failure_fail_frozen_without_restore() -> None:
    host = _Host(fail_on_apply=2)
    installer = _installer(host)
    installer.stage_and_publish(bundle_raw=b"fixed")
    with pytest.raises(WindowsFinalInstallerError, match="POST_EVENT3"):
        installer.reserve_event3_and_apply_target()
    assert host.events == [1, 2, 3]
    assert [item["image_path"] for item in host.applied] == [
        _config(target=False, safety=True)["image_path"],
        _config(target=True)["image_path"],
    ]
    assert host.restored is False
    assert installer.query_unknown_restart_only() == "QUERY_ONLY"


def test_forged_target_projection_is_rejected_before_filesystem_actions() -> None:
    def _forge(target: SimpleNamespace) -> None:
        target.manifest_bindings["service_name"] = "forged-service"

    with pytest.raises(WindowsFinalInstallerError, match="TARGET_MANIFEST"):
        _installer(_Host(), mutate_target=_forge)


def test_event3_applies_and_reads_safety_before_target_and_event4() -> None:
    host = _Host()
    installer = _installer(host)
    installer.stage_and_publish(bundle_raw=b"fixed")
    installer.reserve_event3_and_apply_target()
    assert [item["start_type"] for item in host.applied] == [
        "DEMAND_START",
        "DEMAND_START",
    ]
    assert host.applied[0]["image_path"] != host.applied[1]["image_path"]
    assert host.events == [1, 2, 3, 4]


def test_target_transition_requires_pythonclass_and_pythonpath_readback() -> None:
    host = _Host()
    result = _installer(host).stage_and_publish(bundle_raw=b"fixed")
    assert result.checkpoint is InstallCheckpointV1.FILES_PUBLISHED
    installer = _installer(_Host())
    installer.stage_and_publish(bundle_raw=b"fixed")
    result = installer.reserve_event3_and_apply_target()
    assert result.checkpoint is InstallCheckpointV1.TARGET_READY


@pytest.mark.skipif(os.name == "nt", reason="non-Windows fail-closed contract")
def test_native_host_never_falls_back_to_portable_filesystem_publish() -> None:
    host = NativeWindowsFenceInstallerHostV1()
    assert host.is_real_windows_host is False
    with pytest.raises(WindowsFinalInstallerError, match="REAL_HOST_REQUIRED"):
        host.publish_same_volume_content_addressed_create_only(
            bundle_raw=b"not-a-windows-bundle",
            bundle_sha256=hashlib.sha256(b"not-a-windows-bundle").hexdigest(),
            destination_root=r"C:\ProgramData\vnpy\versions\bundle",
            final_owner_sid="SYSTEM",
            final_directory_acl_sddl="O:SYD:PAI",
            component_acl_sddl="O:SYD:PAI",
        )


def test_native_failure_actions_requires_pywin32_legal_empty_dictionary() -> None:
    empty = {
        "ResetPeriod": 0,
        "RebootMsg": None,
        "Command": None,
        "Actions": [],
    }
    assert NativeWindowsFenceInstallerHostV1._empty_failure_actions(empty)
    assert not NativeWindowsFenceInstallerHostV1._empty_failure_actions({})
    assert not NativeWindowsFenceInstallerHostV1._empty_failure_actions(
        {**empty, "Actions": [(1, 1000)]}
    )
