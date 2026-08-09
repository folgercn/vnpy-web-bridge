"""Windows-only installed entry for the sealed final-fence installer.

This module deliberately accepts only already-verified custody objects.  It
does not expose a JSON/argv reconstruction path, because doing so would turn
untrusted CLI bytes into a substitute for manifest verification.  The installed
bootstrap must perform bundle/manifest/trust validation first and then call
this entry with those immutable objects.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from dataclasses import dataclass

from .bundle_v1 import VerifiedWindowsFenceBundleV1
from .installer_windows_v1 import FinalWindowsFenceInstallerV1, InstallResultV1
from .manifest_v1 import VerifiedInstallManifestV1
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1
from .target_contract_v1 import WindowsFoundationTargetProjectionV1
from .win32_fs import WindowsFilesystemFactsAdapter


class WindowsInstalledInstallerEntryError(RuntimeError):
    """Stable no-fallback installed-entry rejection."""


@dataclass(frozen=True)
class VerifiedFinalInstallerInputsV1:
    """Validated data boundary passed by the signed installed bootstrap."""

    bundle_raw: bytes
    bundle: VerifiedWindowsFenceBundleV1
    manifest: VerifiedInstallManifestV1
    target_projection: WindowsFoundationTargetProjectionV1
    public_config_raw: bytes

    def __post_init__(self) -> None:
        if (
            type(self.bundle_raw) is not bytes
            or type(self.public_config_raw) is not bytes
            or not isinstance(self.bundle, VerifiedWindowsFenceBundleV1)
            or not isinstance(self.manifest, VerifiedInstallManifestV1)
            or not isinstance(
                self.target_projection, WindowsFoundationTargetProjectionV1
            )
            or hashlib.sha256(self.bundle_raw).hexdigest() != self.bundle.bundle_sha256
        ):
            raise WindowsInstalledInstallerEntryError("INSTALLER_ENTRY_INPUT_INVALID")


def _run_installed_final_windows_installer_entry_v1(
    inputs: VerifiedFinalInstallerInputsV1, *, dry_run: bool = False
) -> InstallResultV1 | str:
    """Construct only the native host; portable/fake hosts are impossible here."""
    if os.name != "nt" or not isinstance(inputs, VerifiedFinalInstallerInputsV1):
        raise WindowsInstalledInstallerEntryError("WINDOWS_INSTALLER_ENTRY_REQUIRED")
    host = NativeWindowsFenceInstallerHostV1()
    if not host.is_real_windows_host:
        raise WindowsInstalledInstallerEntryError("WINDOWS_INSTALLER_ENTRY_REQUIRED")
    if dry_run:
        # Host smoke is query-only: no journal, SCM, registry, or file mutation.
        host.query_scm_readback(inputs.manifest["service_name"])
        return "WINDOWS_INSTALLER_NATIVE_PREFLIGHT_OK"
    installer = FinalWindowsFenceInstallerV1(
        host=host,
        manifest=inputs.manifest,
        bundle=inputs.bundle,
        target_projection=inputs.target_projection,
        public_config_raw=inputs.public_config_raw,
    )
    installer.stage_and_publish(bundle_raw=inputs.bundle_raw)
    return installer.reserve_event3_and_apply_target()


def run_installed_final_windows_installer_entry_for_test_v1(
    inputs: VerifiedFinalInstallerInputsV1, *, dry_run: bool = False
) -> InstallResultV1 | str:
    """Portable contract helper; native installation stays sealed to bootstrap."""
    if os.name == "nt":
        raise WindowsInstalledInstallerEntryError("INSTALLER_ENTRY_TEST_ONLY")
    return _run_installed_final_windows_installer_entry_v1(inputs, dry_run=dry_run)


def native_windows_installer_host_preflight_v1() -> str:
    """CLI-safe host smoke: load required native APIs without naming a service."""
    if os.name != "nt":
        raise WindowsInstalledInstallerEntryError("WINDOWS_INSTALLER_ENTRY_REQUIRED")
    host = NativeWindowsFenceInstallerHostV1()
    if not host.is_real_windows_host:
        raise WindowsInstalledInstallerEntryError("WINDOWS_INSTALLER_ENTRY_REQUIRED")
    host._win32()
    WindowsFilesystemFactsAdapter()
    return "WINDOWS_INSTALLER_NATIVE_HOST_PREFLIGHT_OK"


def main(argv: list[str] | None = None) -> int:
    """Expose only non-mutating native-host preflight on the command line."""
    parser = argparse.ArgumentParser(prog="windows-final-installer-v1")
    parser.add_argument("--native-host-preflight", action="store_true")
    options = parser.parse_args(argv)
    if not options.native_host_preflight:
        raise WindowsInstalledInstallerEntryError(
            "INSTALLER_ENTRY_SEALED_INPUT_REQUIRED"
        )
    print(native_windows_installer_host_preflight_v1())
    return 0


__all__ = [
    "VerifiedFinalInstallerInputsV1",
    "WindowsInstalledInstallerEntryError",
    "main",
    "native_windows_installer_host_preflight_v1",
    "run_installed_final_windows_installer_entry_for_test_v1",
]


if __name__ == "__main__":  # pragma: no cover - Windows CI invokes this entry.
    raise SystemExit(main())
