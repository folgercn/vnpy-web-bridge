"""Native Windows implementation of the final fence installer host protocol.

This module has no network, credential, order, or restart operation.  It only
performs the manifest-bound file publish and SCM/pywin32 registry transition.
Every unsupported Windows/pywin32 capability fails closed rather than falling
back to a portable implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes
from .installer_windows_v1 import (
    WindowsFenceInstallerHostV1,
    WindowsFinalInstallerError,
    WindowsPathReadbackV1,
    WindowsScmReadbackV1,
)
from .win32_fs import WindowsFilesystemFactsAdapter

try:  # Windows-only registry API; import must remain safe for CI contract tests.
    import winreg  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - non-Windows guard only
    winreg = None  # type: ignore[assignment]


class NativeWindowsFenceInstallerHostV1(WindowsFenceInstallerHostV1):
    """Windows-only host; a non-Windows process is never installation-ready."""

    @property
    def is_real_windows_host(self) -> bool:
        return os.name == "nt"

    def __init__(self) -> None:
        self._journal_root: Path | None = None

    @staticmethod
    def _require_windows() -> None:
        if os.name != "nt" or winreg is None:
            raise WindowsFinalInstallerError("WINDOWS_INSTALLER_REAL_HOST_REQUIRED")

    @staticmethod
    def _service_key(name: str) -> str:
        return rf"SYSTEM\CurrentControlSet\Services\{name}"

    @staticmethod
    def _win32() -> Any:
        try:
            import win32service  # type: ignore[import-not-found]

            return win32service
        except Exception as exc:
            raise WindowsFinalInstallerError(
                "WINDOWS_PYWIN32_SERVICE_API_REQUIRED"
            ) from exc

    @staticmethod
    def _registry_string(key: Any, name: str) -> str:
        try:
            value, value_type = winreg.QueryValueEx(key, name)
        except OSError as exc:
            raise WindowsFinalInstallerError("PYWIN32_REGISTRY_VALUE_MISSING") from exc
        if (
            value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ}
            or not isinstance(value, str)
            or not value
        ):
            raise WindowsFinalInstallerError("PYWIN32_REGISTRY_VALUE_INVALID")
        return value

    @staticmethod
    def _parse_command_line(value: str) -> list[str]:
        """Use Windows' own parser, not POSIX tokenisation, for SCM ImagePath."""
        try:
            from ctypes import byref, c_int, windll

            count = c_int()
            argv = windll.shell32.CommandLineToArgvW(value, byref(count))
            if not argv or count.value < 1:
                raise OSError("CommandLineToArgvW failed")
            try:
                result = [argv[index] for index in range(count.value)]
            finally:
                windll.kernel32.LocalFree(argv)
            if any(not item or "\x00" in item for item in result):
                raise OSError("invalid SCM command line")
            return result
        except Exception as exc:
            raise WindowsFinalInstallerError("SCM_IMAGEPATH_PARSE_FAILED") from exc

    @staticmethod
    def _image_from_command_line(value: str) -> dict[str, object]:
        argv = NativeWindowsFenceInstallerHostV1._parse_command_line(value)
        return {"application_path": argv[0], "arguments": argv[1:]}

    @staticmethod
    def _service_config(handle: Any, win32service: Any) -> tuple[Any, ...]:
        try:
            return tuple(win32service.QueryServiceConfig(handle))
        except Exception as exc:
            raise WindowsFinalInstallerError("SCM_QUERY_FAILED") from exc

    def query_scm_readback(self, service_name: str) -> WindowsScmReadbackV1:
        self._require_windows()
        ws = self._win32()
        manager = service = None
        try:
            manager = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)
            service = ws.OpenService(manager, service_name, ws.SERVICE_QUERY_CONFIG)
            config = self._service_config(service, ws)
            start_map = {
                ws.SERVICE_AUTO_START: "AUTO_START",
                ws.SERVICE_DEMAND_START: "DEMAND_START",
                ws.SERVICE_DISABLED: "DISABLED",
            }
            start = start_map.get(config[1])
            if start is None:
                raise WindowsFinalInstallerError("SCM_START_TYPE_UNSUPPORTED")
            dependencies = config[6]
            if isinstance(dependencies, str):
                dependencies = [item for item in dependencies.split("\x00") if item]
            if not isinstance(dependencies, (tuple, list)) or any(
                not isinstance(item, str) for item in dependencies
            ):
                raise WindowsFinalInstallerError("SCM_DEPENDENCIES_INVALID")
            # Only an already-disabled empty failure/recovery policy is accepted
            # by this final installer.  A non-empty policy must be explicitly
            # observed and represented by a later contract, never guessed here.
            try:
                failure = ws.QueryServiceConfig2(
                    service, ws.SERVICE_CONFIG_FAILURE_ACTIONS
                )
            except Exception as exc:
                raise WindowsFinalInstallerError(
                    "SCM_FAILURE_ACTIONS_QUERY_FAILED"
                ) from exc
            if failure not in {None, (), {}, []}:
                raise WindowsFinalInstallerError(
                    "SCM_FAILURE_ACTIONS_NOT_CANONICAL_EMPTY"
                )
        finally:
            if service is not None:
                ws.CloseServiceHandle(service)
            if manager is not None:
                ws.CloseServiceHandle(manager)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self._service_key(service_name),
                0,
                winreg.KEY_READ,
            )
            try:
                python_class = self._registry_string(key, "PythonClass")
                python_path = self._registry_string(key, "PythonPath")
            finally:
                winreg.CloseKey(key)
        except WindowsFinalInstallerError:
            raise
        except OSError as exc:
            raise WindowsFinalInstallerError("PYWIN32_REGISTRY_QUERY_FAILED") from exc
        # Registry ACL facts are obtained through the same opened-handle Windows
        # facts adapter after resolving the registry-export path is impossible;
        # pywin32 registry ACL support is a hard requirement for write use.
        try:
            import win32security  # type: ignore[import-not-found]

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self._service_key(service_name),
                0,
                winreg.KEY_READ,
            )
            try:
                security = win32security.GetSecurityInfo(
                    key,
                    win32security.SE_REGISTRY_KEY,
                    win32security.OWNER_SECURITY_INFORMATION
                    | win32security.DACL_SECURITY_INFORMATION,
                )
                owner = win32security.ConvertSidToStringSid(
                    security.GetSecurityDescriptorOwner()
                )
                sddl = (
                    win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        security,
                        1,
                        win32security.OWNER_SECURITY_INFORMATION
                        | win32security.DACL_SECURITY_INFORMATION,
                    )[0]
                )
            finally:
                winreg.CloseKey(key)
        except Exception as exc:
            raise WindowsFinalInstallerError(
                "PYWIN32_REGISTRY_SECURITY_QUERY_FAILED"
            ) from exc
        return WindowsScmReadbackV1(
            service_name=service_name,
            image_path=self._image_from_command_line(config[3]),
            start_type=start,
            failure_actions=(),
            recovery_actions=(),
            service_account_sid_sha256=hashlib.sha256(
                str(config[7]).encode()
            ).hexdigest(),
            dependencies=tuple(dependencies),
            python_class=python_class,
            python_path=python_path,
            registry_owner_sid_sha256=hashlib.sha256(owner.encode()).hexdigest(),
            registry_acl_sddl_sha256=hashlib.sha256(sddl.encode()).hexdigest(),
        )

    @staticmethod
    def _apply_directory_security(path: Path, *, sddl: str) -> None:
        try:
            import win32security  # type: ignore[import-not-found]

            descriptor = (
                win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, 1
                )
            )
            win32security.SetFileSecurity(
                str(path),
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
                descriptor,
            )
        except Exception as exc:
            raise WindowsFinalInstallerError(
                "INSTALL_JOURNAL_ACL_APPLY_FAILED"
            ) from exc

    def initialize_secure_durable_journal_create_only(
        self,
        *,
        store_root: str,
        store_expectation: Mapping[str, Any],
        owner_sid: str,
        directory_acl_sddl: str,
    ) -> None:
        self._require_windows()
        root = Path(store_root)
        try:
            if not root.exists():
                root.mkdir(parents=True, mode=0o700)
                self._apply_directory_security(root, sddl=directory_acl_sddl)
            fs = WindowsFilesystemFactsAdapter()
            facts = fs.inspect(root)
        except OSError as exc:
            raise WindowsFinalInstallerError(
                "INSTALL_JOURNAL_ROOT_READ_FAILED"
            ) from exc
        expected_owner = hashlib.sha256(owner_sid.encode()).hexdigest()
        expected_acl = hashlib.sha256(directory_acl_sddl.encode()).hexdigest()
        if (
            not facts.directory
            or facts.reparse_point
            or not facts.parent_chain_reparse_free
            or facts.hardlink_count != 1
            or facts.alternate_data_streams
            or not facts.dacl_protected
            or facts.inherited_ace_count
            or facts.unsafe_write_principals
            or facts.owner_sid_sha256 != expected_owner
            or facts.acl_sddl_sha256 != expected_acl
            or facts.path_sha256 != store_expectation.get("store_path_sha256")
            or facts.volume_serial != store_expectation.get("store_volume_serial")
            or facts.volume_identity_sha256
            != store_expectation.get("store_volume_identity_sha256")
        ):
            raise WindowsFinalInstallerError("INSTALL_JOURNAL_ROOT_SECURITY_MISMATCH")
        journal = root / "installer-journal-v1"
        try:
            if not journal.exists():
                journal.mkdir(mode=0o700)
                self._apply_directory_security(journal, sddl=directory_acl_sddl)
            journal_facts = fs.inspect(journal)
        except OSError as exc:
            raise WindowsFinalInstallerError("INSTALL_JOURNAL_CREATE_FAILED") from exc
        if (
            not journal_facts.directory
            or journal_facts.reparse_point
            or not journal_facts.parent_chain_reparse_free
            or journal_facts.hardlink_count != 1
            or journal_facts.alternate_data_streams
            or not journal_facts.dacl_protected
            or journal_facts.inherited_ace_count
            or journal_facts.unsafe_write_principals
            or journal_facts.owner_sid_sha256 != expected_owner
            or journal_facts.acl_sddl_sha256 != expected_acl
        ):
            raise WindowsFinalInstallerError("INSTALL_JOURNAL_SECURITY_MISMATCH")
        self._journal_root = journal

    def _journal_path(self, name: str) -> Path:
        if self._journal_root is None:
            raise WindowsFinalInstallerError("INSTALL_JOURNAL_NOT_INITIALIZED")
        return self._journal_root / name

    def backup_scm_and_pywin32_registry_create_only(
        self, *, service_name: str, readback: WindowsScmReadbackV1
    ) -> str:
        self._require_windows()
        root = self._journal_path("backups")
        root.mkdir(exist_ok=True)
        identifier = hashlib.sha256(
            canonical_json_bytes(
                {"service": service_name, "readback": readback.canonical_sha256()}
            )
        ).hexdigest()
        path = root / f"{identifier}.json"
        raw = canonical_json_bytes(
            {
                "schema_version": "windows_fence_installer_backup_v1",
                "service_name": service_name,
                "readback": {
                    "service_name": readback.service_name,
                    "image_path": dict(readback.image_path),
                    "start_type": readback.start_type,
                    "failure_actions": list(readback.failure_actions),
                    "recovery_actions": list(readback.recovery_actions),
                    "service_account_sid_sha256": readback.service_account_sid_sha256,
                    "dependencies": list(readback.dependencies),
                    "python_class": readback.python_class,
                    "python_path": readback.python_path,
                },
            }
        )
        try:
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_BINARY, 0o600
            )
            try:
                os.write(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise WindowsFinalInstallerError("SCM_BACKUP_CREATE_ONLY_CONFLICT")
        except OSError as exc:
            raise WindowsFinalInstallerError("SCM_BACKUP_WRITE_FAILED") from exc
        return identifier

    def publish_same_volume_content_addressed_create_only(
        self, *, bundle_raw: bytes, bundle_sha256: str, destination_root: str
    ) -> tuple[str, Mapping[str, WindowsPathReadbackV1]]:
        self._require_windows()
        if hashlib.sha256(bundle_raw).hexdigest() != bundle_sha256:
            raise WindowsFinalInstallerError("INSTALL_BUNDLE_BYTES_MISMATCH")
        final = Path(destination_root)
        parent = final.parent
        fs = WindowsFilesystemFactsAdapter()
        try:
            parent_facts = fs.inspect(parent)
        except OSError as exc:
            raise WindowsFinalInstallerError("INSTALL_PARENT_READ_FAILED") from exc
        if (
            not parent_facts.directory
            or parent_facts.reparse_point
            or not parent_facts.parent_chain_reparse_free
            or parent_facts.unsafe_write_principals
        ):
            raise WindowsFinalInstallerError("INSTALL_PARENT_SECURITY_INVALID")
        if final.exists():
            raise WindowsFinalInstallerError("INSTALL_FINAL_ALREADY_EXISTS")
        staging = parent / f".staging-{bundle_sha256}-{uuid.uuid4().hex}"
        try:
            staging.mkdir(mode=0o700)
            with zipfile.ZipFile(__import__("io").BytesIO(bundle_raw)) as archive:
                for item in archive.infolist():
                    if (
                        item.is_dir()
                        or not item.filename.startswith("components/")
                        or "/" in item.filename[len("components/") :]
                    ):
                        raise WindowsFinalInstallerError(
                            "INSTALL_BUNDLE_ARCHIVE_INVALID"
                        )
                    target = staging / item.filename.rsplit("/", 1)[1]
                    with target.open("xb") as output:
                        output.write(archive.read(item))
                        output.flush()
                        os.fsync(output.fileno())
            os.replace(staging, final)
        except Exception as exc:
            shutil.rmtree(staging, ignore_errors=True)
            if isinstance(exc, WindowsFinalInstallerError):
                raise
            raise WindowsFinalInstallerError("INSTALL_ATOMIC_PUBLISH_FAILED") from exc
        receipt = hashlib.sha256(
            canonical_json_bytes({"bundle": bundle_sha256, "destination": str(final)})
        ).hexdigest()
        roles = {
            "wrapper": "windows_rpc_service_wrapper_v1.py",
            "extension": "windows_rpc_deployment_snapshot_v1.py",
            "launcher": "windows_rpc_durable_fence_v1.py",
            "assembly": "windows_fence_foundation_v1.pyz",
            "config": "windows_rpc_service_config_v1.json",
        }
        result: dict[str, WindowsPathReadbackV1] = {}
        for role, name in roles.items():
            path = final / name
            try:
                read = fs.read_file(path, maximum_bytes=8 * 1024 * 1024)
            except OSError as exc:
                raise WindowsFinalInstallerError(
                    "INSTALL_COMPONENT_READBACK_FAILED"
                ) from exc
            facts = read.facts
            result[role] = WindowsPathReadbackV1(
                path=str(path),
                raw_sha256=hashlib.sha256(read.raw).hexdigest(),
                owner_sid_sha256=facts.owner_sid_sha256,
                acl_sddl_sha256=facts.acl_sddl_sha256,
                regular_file=facts.regular_file,
                reparse_point=facts.reparse_point,
                parent_chain_reparse_free=facts.parent_chain_reparse_free,
                hardlink_count=facts.hardlink_count,
                alternate_data_streams=facts.alternate_data_streams,
                dacl_protected=facts.dacl_protected,
                inherited_ace_count=facts.inherited_ace_count,
                unsafe_write_principals=facts.unsafe_write_principals,
            )
        return receipt, result

    def append_install_event_create_only(
        self,
        *,
        install_attempt_id: str,
        event_sequence: int,
        state: str,
        details_sha256: str,
    ) -> str:
        root = self._journal_path(install_attempt_id)
        try:
            root.mkdir()
        except FileExistsError:
            pass
        raw = canonical_json_bytes(
            {
                "schema_version": "windows_fence_installer_event_v1",
                "install_attempt_id": install_attempt_id,
                "event_sequence": event_sequence,
                "state": state,
                "details_sha256": details_sha256,
            }
        )
        path = root / f"{event_sequence:02d}.json"
        try:
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_BINARY, 0o600
            )
            try:
                os.write(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise WindowsFinalInstallerError("INSTALL_EVENT_CREATE_ONLY_CONFLICT")
        except OSError as exc:
            raise WindowsFinalInstallerError("INSTALL_EVENT_WRITE_FAILED") from exc
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _command_line(image: Mapping[str, Any]) -> str:
        if (
            set(image) != {"application_path", "arguments"}
            or not isinstance(image["application_path"], str)
            or not isinstance(image["arguments"], list)
            or any(not isinstance(item, str) for item in image["arguments"])
        ):
            raise WindowsFinalInstallerError("SCM_TARGET_IMAGE_INVALID")
        return subprocess.list2cmdline([image["application_path"], *image["arguments"]])

    def _apply_unchecked(self, target: Mapping[str, Any]) -> None:
        self._require_windows()
        ws = self._win32()
        service_name = target.get("service_name")
        if not isinstance(service_name, str):
            raise WindowsFinalInstallerError("SCM_TARGET_INVALID")
        start_map = {
            "AUTO_START": ws.SERVICE_AUTO_START,
            "DEMAND_START": ws.SERVICE_DEMAND_START,
            "DISABLED": ws.SERVICE_DISABLED,
        }
        if (
            target.get("start_type") not in start_map
            or tuple(target.get("failure_actions", ()))
            or tuple(target.get("recovery_actions", ()))
        ):
            raise WindowsFinalInstallerError("SCM_TARGET_POLICY_INVALID")
        manager = service = None
        try:
            manager = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)
            service = ws.OpenService(
                manager,
                service_name,
                ws.SERVICE_CHANGE_CONFIG | ws.SERVICE_QUERY_CONFIG,
            )
            ws.ChangeServiceConfig(
                service,
                ws.SERVICE_NO_CHANGE,
                start_map[target["start_type"]],
                ws.SERVICE_NO_CHANGE,
                self._command_line(target["image_path"]),
                None,
                0,
                list(target["dependencies"]),
                None,
                None,
                None,
            )
            ws.ChangeServiceConfig2(service, ws.SERVICE_CONFIG_FAILURE_ACTIONS, None)
        except Exception as exc:
            raise WindowsFinalInstallerError("SCM_TARGET_APPLY_FAILED") from exc
        finally:
            if service is not None:
                ws.CloseServiceHandle(service)
            if manager is not None:
                ws.CloseServiceHandle(manager)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self._service_key(service_name),
                0,
                winreg.KEY_SET_VALUE,
            )
            try:
                winreg.SetValueEx(
                    key, "PythonClass", 0, winreg.REG_SZ, target["python_class"]
                )
                winreg.SetValueEx(
                    key, "PythonPath", 0, winreg.REG_SZ, target["python_path"]
                )
            finally:
                winreg.CloseKey(key)
        except Exception as exc:
            raise WindowsFinalInstallerError("PYWIN32_REGISTRY_APPLY_FAILED") from exc

    def apply_exact_scm_and_pywin32_registry_once(
        self, *, expected_before: WindowsScmReadbackV1, target: Mapping[str, Any]
    ) -> None:
        current = self.query_scm_readback(expected_before.service_name)
        if (
            current.canonical_sha256() != expected_before.canonical_sha256()
            or current.registry_owner_sid_sha256
            != expected_before.registry_owner_sid_sha256
            or current.registry_acl_sddl_sha256
            != expected_before.registry_acl_sddl_sha256
        ):
            raise WindowsFinalInstallerError("SCM_PRECONDITION_READBACK_MISMATCH")
        self._apply_unchecked(target)

    def restore_pre_event3_backup(self, *, backup_id: str) -> None:
        path = self._journal_path("backups") / f"{backup_id}.json"
        try:
            value = json.loads(path.read_bytes())
            target = value["readback"]
        except Exception as exc:
            raise WindowsFinalInstallerError("SCM_BACKUP_READ_FAILED") from exc
        self._apply_unchecked(target)

    def query_same_restart_attempt_only(self, **_kwargs: object) -> str:
        raise WindowsFinalInstallerError("SCM_RESTART_QUERY_ADAPTER_NOT_CONFIGURED")


__all__ = ["NativeWindowsFenceInstallerHostV1"]
