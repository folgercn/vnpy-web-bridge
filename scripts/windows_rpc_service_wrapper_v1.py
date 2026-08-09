"""The sole pywin32 SCM wrapper for the final fenced Windows RPC service.

`pythonservice.exe` owns the SCM process.  This wrapper owns exactly one
hash-pinned installed launcher lifetime and performs a bounded, observable
stop.  It is not a legacy launcher fallback and it never reads credentials.
"""

from __future__ import annotations

import hashlib
import re
import sys
import threading
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:  # pywin32 is intentionally required only on the Windows service host.
    import win32service  # type: ignore[import-not-found]
    import win32serviceutil  # type: ignore[import-not-found]

    _ServiceFramework = win32serviceutil.ServiceFramework
except ImportError:  # pragma: no cover - exercised through the portable seam
    win32service = None  # type: ignore[assignment]

    class _ServiceFramework:  # type: ignore[no-redef]
        def __init__(self, _args: list[str]) -> None:
            pass

        def ReportServiceStatus(self, _status: int) -> None:
            pass


_SHA = re.compile(r"^[0-9a-f]{64}$")
_WRAPPER_NAME = "windows_rpc_service_wrapper_v1.py"
_LAUNCHER_NAME = "windows_rpc_durable_fence_v1.py"
STOP_WAIT_SECONDS = 30


class WindowsRpcServiceWrapperError(RuntimeError):
    """Stable wrapper rejection before the vn.py runtime may be constructed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _read_pinned(path: Path, digest: str, *, expected_name: str) -> bytes:
    expected = Path(__file__).resolve().with_name(expected_name)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WindowsRpcServiceWrapperError("WRAPPER_COMPONENT_READ_FAILED") from exc
    if (
        path.resolve() != expected
        or _SHA.fullmatch(digest) is None
        or hashlib.sha256(raw).hexdigest() != digest
    ):
        raise WindowsRpcServiceWrapperError("WRAPPER_COMPONENT_BINDING_MISMATCH")
    return raw


def split_verified_wrapper_arguments_v1(
    arguments: list[str],
) -> tuple[bytes, list[str]]:
    """Verify wrapper and launcher identity before interpreting launcher flags."""
    if (
        len(arguments) < 7
        or arguments[1] != "--wrapper-sha256"
        or arguments[4] != "--launcher-sha256"
    ):
        raise WindowsRpcServiceWrapperError("WRAPPER_ARGUMENTS_INVALID")
    wrapper = Path(arguments[0])
    digest = arguments[2]
    launcher = Path(arguments[3])
    launcher_digest = arguments[5]
    if not wrapper.is_absolute() or not launcher.is_absolute():
        raise WindowsRpcServiceWrapperError("WRAPPER_ARGUMENTS_INVALID")
    _read_pinned(wrapper, digest, expected_name=_WRAPPER_NAME)
    launcher_raw = _read_pinned(launcher, launcher_digest, expected_name=_LAUNCHER_NAME)
    # The launcher owns its own extension/assembly/config hashes.  The wrapper
    # only accepts that exact canonical flag sequence and never forwards extras.
    launcher_args = arguments[6:]
    flags = [
        "--extension",
        "--extension-sha256",
        "--assembly",
        "--assembly-sha256",
        "--config",
        "--config-sha256",
    ]
    if len(launcher_args) != 12 or launcher_args[::2] != flags:
        raise WindowsRpcServiceWrapperError("WRAPPER_ARGUMENTS_INVALID")
    return launcher_raw, launcher_args


def _load_verified_launcher_entry(arguments: list[str]) -> Any:
    launcher_raw, launcher_args = split_verified_wrapper_arguments_v1(arguments)
    launcher_path = Path(arguments[3]).resolve()
    namespace: dict[str, Any] = {
        "__name__": "_vnpy_verified_windows_launcher_v1",
        "__file__": str(launcher_path),
        "__package__": None,
    }
    original_argv = sys.argv
    try:
        # The launcher verifies the adjacent assembly before importing any
        # foundation module; use the same exact flags it receives from SCM.
        sys.argv = [str(launcher_path), *launcher_args]
        exec(compile(launcher_raw, str(launcher_path), "exec"), namespace)  # noqa: S102
    finally:
        sys.argv = original_argv
    entry = namespace.get("run_installed_windows_rpc_entry_v1")
    if not callable(entry):
        raise WindowsRpcServiceWrapperError("WRAPPER_LAUNCHER_ENTRY_MISSING")
    return entry, launcher_args


def run_hash_pinned_service_lifetime_v1(
    arguments: list[str], *, stop_event: threading.Event
) -> None:
    """Run exactly one installed entry then bound shutdown after SCM stop."""
    entry, launcher_args = _load_verified_launcher_entry(arguments)
    assembly = entry(launcher_args)
    if not stop_event.wait():
        return
    deadline = time.monotonic() + STOP_WAIT_SECONDS
    runtime = getattr(assembly, "runtime", None)
    main_engine = getattr(runtime, "main_engine", None)
    close = getattr(main_engine, "close", None)
    if not callable(close):
        raise WindowsRpcServiceWrapperError("WRAPPER_RUNTIME_STOP_UNAVAILABLE")
    close()
    if time.monotonic() > deadline:
        raise WindowsRpcServiceWrapperError("WRAPPER_STOP_TIMEOUT")


class VnpyRpcServiceWrapperV1(_ServiceFramework):
    """Canonical pywin32 ServiceFramework class pinned by PythonClass registry."""

    _svc_name_ = "VnpyRpcService"
    _svc_display_name_ = "vn.py CTP RPC Service"
    _svc_description_ = "Hash-pinned durable-fence Windows RPC service"

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self._stop_event = threading.Event()

    def SvcStop(self) -> None:
        if win32service is not None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_event.set()

    def SvcDoRun(self) -> None:
        run_hash_pinned_service_lifetime_v1(sys.argv[1:], stop_event=self._stop_event)


SERVICE_WRAPPER_REGISTRY_V1 = MappingProxyType(
    {
        "python_class": "windows_rpc_service_wrapper_v1.VnpyRpcServiceWrapperV1",
        "python_path_module": "windows_rpc_service_wrapper_v1",
        "service_name": VnpyRpcServiceWrapperV1._svc_name_,
    }
)


if __name__ == "__main__":  # pragma: no cover - Windows SCM entry only
    if win32serviceutil is None:  # type: ignore[name-defined]
        raise SystemExit("WINDOWS_PYWIN32_REQUIRED")
    win32serviceutil.HandleCommandLine(VnpyRpcServiceWrapperV1)


__all__ = [
    "SERVICE_WRAPPER_REGISTRY_V1",
    "VnpyRpcServiceWrapperV1",
    "WindowsRpcServiceWrapperError",
    "run_hash_pinned_service_lifetime_v1",
    "split_verified_wrapper_arguments_v1",
]
