"""Windows-only native-host preflight entry for the sealed installer."""

from __future__ import annotations

import argparse
import os

from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1
from .win32_fs import WindowsFilesystemFactsAdapter


class WindowsInstalledInstallerEntryError(RuntimeError):
    """Stable no-fallback installed-entry rejection."""


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
    "WindowsInstalledInstallerEntryError",
    "main",
    "native_windows_installer_host_preflight_v1",
]


if __name__ == "__main__":  # pragma: no cover - Windows CI invokes this entry.
    raise SystemExit(main())
