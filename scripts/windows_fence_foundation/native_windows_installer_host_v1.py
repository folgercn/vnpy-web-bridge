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
        self._journal_owner_sha256: str | None = None
        self._journal_acl_sddl: str | None = None

    @staticmethod
    def _require_windows() -> None:
        if os.name != "nt" or winreg is None:
            raise WindowsFinalInstallerError("WINDOWS_INSTALLER_REAL_HOST_REQUIRED")

    @staticmethod
    def _service_key(name: str) -> str:
        return rf"SYSTEM\CurrentControlSet\Services\{name}"

    @staticmethod
    def _empty_failure_actions(value: Any) -> bool:
        """Match pywin32's documented SERVICE_FAILURE_ACTIONS dictionary."""
        return (
            isinstance(value, Mapping)
            and set(value) == {"ResetPeriod", "RebootMsg", "Command", "Actions"}
            and value["ResetPeriod"] == 0
            and value["RebootMsg"] is None
            and value["Command"] is None
            and value["Actions"] in ((), [])
        )

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
    def _pywin32_sddl_text(value: Any) -> str:
        """pywin32 builds return either SDDL text or ``(text, revision)``."""
        if isinstance(value, tuple):
            value = value[0] if value else None
        if not isinstance(value, str) or not value:
            raise WindowsFinalInstallerError("PYWIN32_REGISTRY_SDDL_INVALID")
        return value

    @staticmethod
    def _parse_command_line(value: str) -> list[str]:
        """Use Windows' own parser, not POSIX tokenisation, for SCM ImagePath."""
        try:
            from ctypes import POINTER, byref, c_int, c_void_p, windll, wintypes

            count = c_int()
            command_line_to_argv = windll.shell32.CommandLineToArgvW
            command_line_to_argv.argtypes = [wintypes.LPCWSTR, POINTER(c_int)]
            command_line_to_argv.restype = POINTER(wintypes.LPWSTR)
            local_free = windll.kernel32.LocalFree
            local_free.argtypes = [c_void_p]
            local_free.restype = c_void_p
            argv = command_line_to_argv(value, byref(count))
            if not argv or count.value < 1:
                raise OSError("CommandLineToArgvW failed")
            try:
                result = [argv[index] for index in range(count.value)]
            finally:
                local_free(argv)
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
            if not self._empty_failure_actions(failure):
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
                sddl = self._pywin32_sddl_text(
                    win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        security,
                        1,
                        win32security.OWNER_SECURITY_INFORMATION
                        | win32security.DACL_SECURITY_INFORMATION,
                    )
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
            registry_owner_sid=owner,
            registry_acl_sddl=sddl,
        )

    @staticmethod
    def _apply_path_security(path: Path, *, sddl: str, directory: bool) -> None:
        try:
            WindowsFilesystemFactsAdapter.apply_protected_security_by_handle(
                path, sddl=sddl, directory=directory
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
                self._apply_path_security(root, sddl=directory_acl_sddl, directory=True)
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
                self._apply_path_security(
                    journal, sddl=directory_acl_sddl, directory=True
                )
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
        self._journal_owner_sha256 = expected_owner
        self._journal_acl_sddl = directory_acl_sddl

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
                    "registry_owner_sid": readback.registry_owner_sid,
                    "registry_acl_sddl": readback.registry_acl_sddl,
                },
            }
        )
        try:
            written = WindowsFilesystemFactsAdapter().write_file_create_only(
                path, raw=raw, protected_sddl=self._journal_acl_sddl or ""
            )
            if written.raw != raw:
                raise WindowsFinalInstallerError("SCM_BACKUP_HANDLE_READBACK_MISMATCH")
        except FileExistsError:
            if WindowsFilesystemFactsAdapter().read_file(path).raw != raw:
                raise WindowsFinalInstallerError("SCM_BACKUP_CREATE_ONLY_CONFLICT")
        except OSError as exc:
            raise WindowsFinalInstallerError("SCM_BACKUP_WRITE_FAILED") from exc
        return identifier

    def publish_same_volume_content_addressed_create_only(
        self,
        *,
        bundle_raw: bytes,
        bundle_sha256: str,
        destination_root: str,
        final_owner_sid: str,
        final_directory_acl_sddl: str,
        component_acl_sddl: str,
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
            # Keep the parent opened for the entire publish and compare every
            # pathname operation to that immutable handle identity.  This
            # turns a parent replacement/reparse race into a hard failure
            # before the following state boundary can be accepted.
            with fs.open_directory_anchor(parent) as anchor:
                anchor.assert_named_path_is_opened_parent()
                staging.mkdir(mode=0o700)
                anchor.assert_named_path_is_opened_parent()
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
                        expected_raw = archive.read(item)
                        written = fs.write_file_create_only(
                            target,
                            raw=expected_raw,
                            protected_sddl=component_acl_sddl,
                        )
                        if written.raw != expected_raw:
                            raise WindowsFinalInstallerError(
                                "INSTALL_COMPONENT_HANDLE_READBACK_MISMATCH"
                            )
                        anchor.assert_named_path_is_opened_parent()
                if final.exists():
                    raise WindowsFinalInstallerError("INSTALL_FINAL_ALREADY_EXISTS")
                anchor.assert_named_path_is_opened_parent()
                fs.rename_create_only_to_opened_parent(
                    staging, target_name=final.name, parent=anchor
                )
                anchor.assert_named_path_is_opened_parent()
                self._apply_path_security(
                    final, sddl=final_directory_acl_sddl, directory=True
                )
                for path in final.iterdir():
                    self._apply_path_security(
                        path, sddl=component_acl_sddl, directory=False
                    )
                    anchor.assert_named_path_is_opened_parent()
                final_facts = fs.inspect(final)
            if (
                not final_facts.directory
                or final_facts.reparse_point
                or not final_facts.parent_chain_reparse_free
                or final_facts.hardlink_count != 1
                or final_facts.alternate_data_streams
                or not final_facts.dacl_protected
                or final_facts.inherited_ace_count
                or final_facts.unsafe_write_principals
                or final_facts.owner_sid_sha256
                != hashlib.sha256(final_owner_sid.encode()).hexdigest()
                or final_facts.acl_sddl_sha256
                != hashlib.sha256(final_directory_acl_sddl.encode()).hexdigest()
            ):
                raise WindowsFinalInstallerError("INSTALL_FINAL_ACL_READBACK_MISMATCH")
        except Exception as exc:
            # Do not pathname-delete an unverified staging tree after a fault.
            # It remains an inert, non-installed forensic orphan.
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
            if self._journal_acl_sddl is None or self._journal_owner_sha256 is None:
                raise WindowsFinalInstallerError("INSTALL_JOURNAL_NOT_INITIALIZED")
            self._apply_path_security(root, sddl=self._journal_acl_sddl, directory=True)
        except FileExistsError:
            pass
        try:
            facts = WindowsFilesystemFactsAdapter().inspect(root)
        except OSError as exc:
            raise WindowsFinalInstallerError("INSTALL_EVENT_ROOT_READ_FAILED") from exc
        if (
            not facts.directory
            or facts.reparse_point
            or not facts.parent_chain_reparse_free
            or facts.hardlink_count != 1
            or facts.alternate_data_streams
            or not facts.dacl_protected
            or facts.inherited_ace_count
            or facts.unsafe_write_principals
            or facts.owner_sid_sha256 != self._journal_owner_sha256
            or facts.acl_sddl_sha256
            != hashlib.sha256(self._journal_acl_sddl.encode()).hexdigest()
        ):
            raise WindowsFinalInstallerError("INSTALL_EVENT_ROOT_SECURITY_MISMATCH")
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
            written = WindowsFilesystemFactsAdapter().write_file_create_only(
                path, raw=raw, protected_sddl=self._journal_acl_sddl or ""
            )
            if written.raw != raw:
                raise WindowsFinalInstallerError(
                    "INSTALL_EVENT_HANDLE_READBACK_MISMATCH"
                )
        except FileExistsError:
            if WindowsFilesystemFactsAdapter().read_file(path).raw != raw:
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

    def _apply_registry_security(
        self, *, service_name: str, owner_sid: str, acl_sddl: str
    ) -> None:
        try:
            import win32security  # type: ignore[import-not-found]

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self._service_key(service_name),
                0,
                winreg.KEY_READ | winreg.KEY_WRITE | 0x00040000 | 0x00080000,
            )
            try:
                descriptor = (
                    win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                        acl_sddl, 1
                    )
                )
                owner = win32security.ConvertStringSidToSid(owner_sid)
                win32security.SetSecurityInfo(
                    key,
                    win32security.SE_REGISTRY_KEY,
                    win32security.OWNER_SECURITY_INFORMATION
                    | win32security.DACL_SECURITY_INFORMATION
                    | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                    owner,
                    None,
                    descriptor.GetSecurityDescriptorDacl(),
                    None,
                )
            finally:
                winreg.CloseKey(key)
        except Exception as exc:
            raise WindowsFinalInstallerError(
                "PYWIN32_REGISTRY_SECURITY_APPLY_FAILED"
            ) from exc

    def _apply_unchecked(
        self,
        target: Mapping[str, Any],
        *,
        registry_security: Mapping[str, str] | None = None,
    ) -> None:
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
            ws.ChangeServiceConfig2(
                service,
                ws.SERVICE_CONFIG_FAILURE_ACTIONS,
                {
                    "ResetPeriod": 0,
                    "RebootMsg": None,
                    "Command": None,
                    "Actions": (),
                },
            )
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
        security = registry_security
        if security is None:
            security = {
                "owner_sid": target.get("registry_owner_sid"),
                "acl_sddl": target.get("registry_acl_sddl"),
            }
        if not isinstance(security.get("owner_sid"), str) or not isinstance(
            security.get("acl_sddl"), str
        ):
            raise WindowsFinalInstallerError("PYWIN32_REGISTRY_SECURITY_TARGET_INVALID")
        self._apply_registry_security(
            service_name=service_name,
            owner_sid=security["owner_sid"],
            acl_sddl=security["acl_sddl"],
        )

    def apply_exact_scm_and_pywin32_registry_once(
        self,
        *,
        expected_before: WindowsScmReadbackV1,
        target: Mapping[str, Any],
        registry_security: Mapping[str, str],
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
        self._apply_unchecked(target, registry_security=registry_security)

    def restore_pre_event3_backup(self, *, backup_id: str) -> None:
        path = self._journal_path("backups") / f"{backup_id}.json"
        try:
            read = WindowsFilesystemFactsAdapter().read_file(path)
            value = json.loads(read.raw)
            target = value["readback"]
        except Exception as exc:
            raise WindowsFinalInstallerError("SCM_BACKUP_READ_FAILED") from exc
        self._apply_unchecked(target)

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
    ) -> None:
        self._require_windows()
        path = Path(destination_root)
        if (
            not install_attempt_id.startswith("windows-fence-install-")
            or len(bundle_sha256) != 64
            or path.name != bundle_sha256
            or set(component_sha256s)
            != {"wrapper", "extension", "launcher", "assembly", "config"}
        ):
            raise WindowsFinalInstallerError("INSTALL_ORPHAN_IDENTITY_INVALID")
        try:
            filesystem = WindowsFilesystemFactsAdapter()
            inventory = filesystem.list_directory(path)
            facts = inventory.facts
        except OSError as exc:
            if getattr(exc, "winerror", None) in {2, 3}:
                return
            raise WindowsFinalInstallerError("INSTALL_ORPHAN_READ_FAILED") from None
        if (
            not facts.directory
            or facts.reparse_point
            or not facts.parent_chain_reparse_free
            or facts.hardlink_count != 1
            or facts.alternate_data_streams
            or not facts.dacl_protected
            or facts.inherited_ace_count
            or facts.unsafe_write_principals
            or facts.owner_sid_sha256 != final_owner_sid_sha256
            or facts.acl_sddl_sha256 != final_directory_acl_sddl_sha256
            or set(inventory.names)
            != {
                "windows_rpc_service_wrapper_v1.py",
                "windows_rpc_deployment_snapshot_v1.py",
                "windows_rpc_durable_fence_v1.py",
                "windows_fence_foundation_v1.pyz",
                "windows_rpc_service_config_v1.json",
            }
        ):
            raise WindowsFinalInstallerError("INSTALL_ORPHAN_CLEANUP_UNSAFE")
        role_names = {
            "wrapper": "windows_rpc_service_wrapper_v1.py",
            "extension": "windows_rpc_deployment_snapshot_v1.py",
            "launcher": "windows_rpc_durable_fence_v1.py",
            "assembly": "windows_fence_foundation_v1.pyz",
            "config": "windows_rpc_service_config_v1.json",
        }
        try:
            with (
                filesystem.open_directory_anchor(path.parent) as parent_anchor,
                filesystem.open_directory_anchor(path) as bundle_anchor,
            ):
                parent_before = parent_anchor.assert_named_path_is_opened_parent()
                bundle_before = bundle_anchor.assert_named_path_is_opened_parent()
                if (
                    bundle_before != facts
                    or bundle_before.owner_sid_sha256 != final_owner_sid_sha256
                    or bundle_before.acl_sddl_sha256 != final_directory_acl_sddl_sha256
                    or not bundle_before.dacl_protected
                    or bundle_before.inherited_ace_count
                    or bundle_before.unsafe_write_principals
                ):
                    raise WindowsFinalInstallerError("INSTALL_ORPHAN_CLEANUP_UNSAFE")
                for role, name in role_names.items():
                    parent_anchor.assert_named_path_is_opened_parent()
                    if (
                        bundle_anchor.assert_named_path_is_opened_parent()
                        != bundle_before
                    ):
                        raise WindowsFinalInstallerError(
                            "INSTALL_ORPHAN_CLEANUP_UNSAFE"
                        )
                    parent_anchor.assert_named_path_is_opened_parent()
                    if (
                        bundle_anchor.assert_named_path_is_opened_parent()
                        != bundle_before
                    ):
                        raise WindowsFinalInstallerError(
                            "INSTALL_ORPHAN_CLEANUP_UNSAFE"
                        )
                    filesystem.read_verify_delete_relative_to_opened_parent(
                        parent=bundle_anchor,
                        name=name,
                        expected_raw_sha256=component_sha256s[role],
                        expected_owner_sid_sha256=owner_sid_sha256,
                        expected_acl_sddl_sha256=component_acl_sddl_sha256,
                    )
                    parent_anchor.assert_named_path_is_opened_parent()
                    if (
                        bundle_anchor.assert_named_path_is_opened_parent()
                        != bundle_before
                    ):
                        raise WindowsFinalInstallerError(
                            "INSTALL_ORPHAN_CLEANUP_UNSAFE"
                        )
                parent_after = parent_anchor.assert_named_path_is_opened_parent()
                if parent_after != parent_before:
                    raise WindowsFinalInstallerError("INSTALL_ORPHAN_CLEANUP_UNSAFE")
                if bundle_anchor.assert_named_path_is_opened_parent() != bundle_before:
                    raise WindowsFinalInstallerError("INSTALL_ORPHAN_CLEANUP_UNSAFE")
                filesystem.read_verify_delete_relative_to_opened_parent(
                    parent=parent_anchor,
                    name=path.name,
                    expected_raw_sha256="",
                    expected_owner_sid_sha256=final_owner_sid_sha256,
                    expected_acl_sddl_sha256=final_directory_acl_sddl_sha256,
                    directory=True,
                )
        except OSError:
            raise WindowsFinalInstallerError("INSTALL_ORPHAN_CLEANUP_FAILED") from None

    def query_same_restart_attempt_only(self, **_kwargs: object) -> str:
        install_attempt_id = _kwargs.get("install_attempt_id")
        if not isinstance(install_attempt_id, str):
            raise WindowsFinalInstallerError("SCM_RESTART_QUERY_INPUT_INVALID")
        path = self._journal_path(install_attempt_id) / "03.json"
        try:
            read = WindowsFilesystemFactsAdapter().read_file(path)
            value = json.loads(read.raw)
        except Exception as exc:
            raise WindowsFinalInstallerError(
                "SCM_RESTART_QUERY_EVIDENCE_MISSING"
            ) from exc
        if (
            value.get("install_attempt_id") != install_attempt_id
            or value.get("event_sequence") != 3
            or value.get("state") != "RESTART_DISPATCH_RESERVED_FROZEN"
        ):
            raise WindowsFinalInstallerError("SCM_RESTART_QUERY_EVIDENCE_MISMATCH")
        return "NO_RESTART_DISPATCHED_FROZEN"


__all__ = ["NativeWindowsFenceInstallerHostV1"]
