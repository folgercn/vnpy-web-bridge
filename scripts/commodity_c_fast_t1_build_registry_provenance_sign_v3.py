"""Sign a reviewed query-v4 build/registry provenance-v3 record."""

from __future__ import annotations

import sys


RUNNING_AS_SCRIPT = __name__ == "__main__"


def _require_isolated_no_site_startup() -> None:
    flags = sys.flags
    if not (
        flags.isolated == 1
        and flags.no_site == 1
        and flags.no_user_site == 1
        and flags.ignore_environment == 1
        and flags.dont_write_bytecode == 1
    ):
        raise SystemExit(
            "query-v4 provenance signer requires a fixed interpreter "
            "with -I -S -s -E -B"
        )


if RUNNING_AS_SCRIPT:
    _require_isolated_no_site_startup()


import hashlib
import hmac
import importlib.machinery
import os
from pathlib import Path
import stat
from types import ModuleType
from typing import Any

SIGNER_SOURCE_PATH = Path(__file__).resolve()
PROVENANCE_WRAPPER_PATH = SIGNER_SOURCE_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_v3.py"
)
DELEGATE_SIGNER_PATH = SIGNER_SOURCE_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_sign_v2.py"
)
EXPECTED_PROVENANCE_WRAPPER_SHA256 = (
    "be022471bec66d6c5c1cfe55dca55fa87442fe68d32b3b185b7ba5828d4619e0"
)
MAX_BOOTSTRAP_SOURCE_BYTES = 8 * 1024 * 1024
V2_VERIFIER_PUBLIC_MODULE = (
    "commodity_c_fast_t1_build_registry_provenance_v2"
)
BOOTSTRAP_SITE_PACKAGES_ARGUMENT = "--bootstrap-site-packages"
BOOTSTRAP_SITE_PACKAGES_PIN_ARGUMENT = (
    "--expected-bootstrap-site-packages-identity-sha256"
)
FORBIDDEN_BOOTSTRAP_SITE_ENTRIES = frozenset(
    {
        "sitecustomize.py",
        "sitecustomize.pyc",
        "usercustomize.py",
        "usercustomize.pyc",
    }
)


class SignerBootstrapError(RuntimeError):
    """Signer dependency failed before any untrusted code was executed."""


def _take_bootstrap_argument(name: str) -> str:
    positions = [
        index
        for index, value in enumerate(sys.argv)
        if value == name
    ]
    if len(positions) != 1:
        raise SignerBootstrapError(
            f"{name} must appear exactly once"
        )
    index = positions[0]
    if index + 1 >= len(sys.argv):
        raise SignerBootstrapError(f"{name} requires one value")
    value = sys.argv[index + 1]
    del sys.argv[index : index + 2]
    return value


def bootstrap_site_packages_identity(path: Path) -> str:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError as exc:
        raise SignerBootstrapError(
            "bootstrap site-packages is unavailable"
        ) from exc
    if (
        not path.is_absolute()
        or path != resolved
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or _file_identity(before) != _file_identity(after)
        or before.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise SignerBootstrapError(
            "bootstrap site-packages identity is unsafe"
        )
    identity = (
        "c-fast-provenance-bootstrap-site-packages-v1"
        f"\0{resolved}"
        f"\0{before.st_dev}"
        f"\0{before.st_ino}"
        f"\0{before.st_uid}"
        f"\0{stat.S_IMODE(before.st_mode):o}"
    ).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()


def _install_bootstrap_site_packages_from_argv() -> None:
    raw_path = _take_bootstrap_argument(
        BOOTSTRAP_SITE_PACKAGES_ARGUMENT
    )
    expected = _take_bootstrap_argument(
        BOOTSTRAP_SITE_PACKAGES_PIN_ARGUMENT
    )
    if (
        len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise SignerBootstrapError(
            "bootstrap site-packages identity pin is invalid"
        )
    path = Path(raw_path)
    actual = bootstrap_site_packages_identity(path)
    if not hmac.compare_digest(actual, expected):
        raise SignerBootstrapError(
            "bootstrap site-packages identity pin mismatch"
        )
    for entry in path.iterdir():
        name = entry.name
        if (
            name in FORBIDDEN_BOOTSTRAP_SITE_ENTRIES
            or name.endswith((".pth", ".egg-link"))
        ):
            raise SignerBootstrapError(
                "bootstrap site-packages contains a startup hook"
            )
    sys.path.append(str(path))


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_fd_bytes(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_BOOTSTRAP_SOURCE_BYTES:
            raise SignerBootstrapError(f"{label} is too large")
        chunks.append(chunk)


def _read_verified_source(
    path: Path,
    expected_sha256: str,
    label: str,
) -> tuple[bytes, str]:
    """Retain stable exact bytes and check their pin before execution."""

    descriptor = -1
    try:
        before_path = path.lstat()
        if (
            not stat.S_ISREG(before_path.st_mode)
            or stat.S_ISLNK(before_path.st_mode)
            or before_path.st_nlink != 1
        ):
            raise SignerBootstrapError(
                f"{label} must be a single-link regular file"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(before_path) != _file_identity(opened):
            raise SignerBootstrapError(
                f"{label} changed before stable read"
            )
        first = _read_fd_bytes(descriptor, label)
        after_first = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_bytes(descriptor, label)
        after_second = os.fstat(descriptor)
        after_path = path.lstat()
        identity = _file_identity(opened)
        if (
            _file_identity(after_first) != identity
            or _file_identity(after_second) != identity
            or _file_identity(after_path) != identity
            or first != second
        ):
            raise SignerBootstrapError(
                f"{label} changed during stable read"
            )
    except SignerBootstrapError:
        raise
    except OSError as exc:
        raise SignerBootstrapError(
            f"{label} cannot be read safely"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    digest = hashlib.sha256(first).hexdigest()
    if not hmac.compare_digest(digest, expected_sha256):
        raise SignerBootstrapError(
            f"{label} failed the pre-execution SHA256 pin"
        )
    return first, digest


def _module_from_verified_source(
    name: str,
    path: Path,
    source: bytes,
) -> ModuleType:
    """Execute only the same in-memory bytes that passed the pin."""

    module = ModuleType(name)
    module.__file__ = str(path)
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = importlib.machinery.ModuleSpec(
        name,
        loader=None,
        origin=str(path),
    )
    code = compile(source, str(path), "exec", dont_inherit=True)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


if RUNNING_AS_SCRIPT:
    _install_bootstrap_site_packages_from_argv()


(
    PROVENANCE_WRAPPER_SOURCE,
    RETAINED_PROVENANCE_WRAPPER_SHA256,
) = _read_verified_source(
    PROVENANCE_WRAPPER_PATH,
    EXPECTED_PROVENANCE_WRAPPER_SHA256,
    "query-v4 provenance verifier wrapper",
)
provenance_v3 = _module_from_verified_source(
    "_c_fast_t1_verified_build_registry_provenance_v3",
    PROVENANCE_WRAPPER_PATH,
    PROVENANCE_WRAPPER_SOURCE,
)
if Path(provenance_v3.VERIFIER_PATH) != PROVENANCE_WRAPPER_PATH:
    raise SignerBootstrapError(
        "query-v4 provenance verifier wrapper path diverged"
    )
provenance_v3.RETAINED_VERIFIER_SHA256 = (
    RETAINED_PROVENANCE_WRAPPER_SHA256
)


def _load_delegate() -> ModuleType:
    name = "_c_fast_t1_query_v4_build_registry_provenance_signer_delegate"
    source, digest = provenance_v3._read_verified_source(
        DELEGATE_SIGNER_PATH,
        provenance_v3.EXPECTED_DELEGATE_SIGNER_SHA256,
        "query-v4 provenance signer delegate",
    )
    if digest != provenance_v3.RETAINED_DELEGATE_SIGNER_SHA256:
        raise provenance_v3.DelegateBootstrapError(
            "query-v4 provenance signer delegate identity diverged"
        )
    previous_verifier = sys.modules.get(V2_VERIFIER_PUBLIC_MODULE)
    previous_support = sys.modules.get(
        provenance_v3.SUPPORT_PUBLIC_MODULE
    )
    sys.modules[V2_VERIFIER_PUBLIC_MODULE] = provenance_v3._delegate
    sys.modules[provenance_v3.SUPPORT_PUBLIC_MODULE] = (
        provenance_v3._support
    )
    try:
        module = provenance_v3._module_from_verified_source(
            name,
            DELEGATE_SIGNER_PATH,
            source,
        )
    finally:
        if previous_verifier is None:
            sys.modules.pop(V2_VERIFIER_PUBLIC_MODULE, None)
        else:
            sys.modules[V2_VERIFIER_PUBLIC_MODULE] = previous_verifier
        if previous_support is None:
            sys.modules.pop(provenance_v3.SUPPORT_PUBLIC_MODULE, None)
        else:
            sys.modules[provenance_v3.SUPPORT_PUBLIC_MODULE] = (
                previous_support
            )
    module.provenance_v2 = provenance_v3
    module.SIGNER_SOURCE_PATH = SIGNER_SOURCE_PATH
    return module


_delegate = _load_delegate()

load_private_key = _delegate.load_private_key
prepare_provenance = _delegate.prepare_provenance
complete_signature = _delegate.complete_signature
sign_provenance = _delegate.sign_provenance
sign_provenance_from_private_key_path = (
    _delegate.sign_provenance_from_private_key_path
)
parse_args = _delegate.parse_args
main = _delegate.main


def __getattr__(name: str) -> Any:
    return getattr(_delegate, name)


if __name__ == "__main__":
    raise SystemExit(main())
