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


import hashlib  # noqa: E402
import hmac  # noqa: E402
import importlib.machinery  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import stat  # noqa: E402
from types import ModuleType  # noqa: E402
from typing import Any  # noqa: E402

SIGNER_SOURCE_PATH = Path(__file__).resolve()
PROVENANCE_WRAPPER_PATH = SIGNER_SOURCE_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_v3.py"
)
DELEGATE_SIGNER_PATH = SIGNER_SOURCE_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_sign_v2.py"
)
EXPECTED_PROVENANCE_WRAPPER_SHA256 = (
    "7152b68c2bf26759a28c2d15c76ee5de854ec35b6b25ca2e4da00b4e24bd8dbd"
)
MAX_BOOTSTRAP_SOURCE_BYTES = 8 * 1024 * 1024
V2_VERIFIER_PUBLIC_MODULE = (
    "commodity_c_fast_t1_build_registry_provenance_v2"
)
BOOTSTRAP_SITE_PACKAGES_ARGUMENT = "--bootstrap-site-packages"
BOOTSTRAP_SITE_PACKAGES_PIN_ARGUMENT = (
    "--expected-bootstrap-site-packages-identity-sha256"
)
BOOTSTRAP_DEPENDENCY_MANIFEST_PIN_ARGUMENT = (
    "--expected-bootstrap-dependency-manifest-sha256"
)
SIGNER_RUNTIME_IMAGE_DIGEST_ARGUMENT = (
    "--signer-runtime-image-digest"
)
FORBIDDEN_BOOTSTRAP_SITE_ENTRIES = frozenset(
    {
        "sitecustomize.py",
        "sitecustomize.pyc",
        "usercustomize.py",
        "usercustomize.pyc",
    }
)
MAX_BOOTSTRAP_DEPENDENCY_ENTRIES = 100_000
MAX_BOOTSTRAP_DEPENDENCY_FILE_BYTES = 512 * 1024 * 1024
BOOTSTRAP_DEPENDENCY_MANIFEST_VERSION = (
    "c-fast-provenance-bootstrap-dependency-closure-v1"
)
BOOTSTRAP_SITE_PACKAGES_IDENTITY_VERSION = (
    "c-fast-provenance-bootstrap-site-packages-v2"
)
RETAINED_BOOTSTRAP_SITE_PACKAGES_IDENTITY_SHA256: str | None = None
RETAINED_BOOTSTRAP_DEPENDENCY_MANIFEST_SHA256: str | None = None
RETAINED_SIGNER_RUNTIME_IMAGE_DIGEST: str | None = None
BOOTSTRAP_SITE_PACKAGES_PATH: Path | None = None


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


def _effective_access(path: Path, mode: int) -> bool:
    if os.access in os.supports_effective_ids:
        return os.access(path, mode, effective_ids=True)
    return os.access(path, mode)


def _site_packages_path_chain_records(
    path: Path,
    *,
    require_immutable: bool,
) -> list[bytes]:
    if os.geteuid() == 0 and require_immutable:
        raise SignerBootstrapError(
            "provenance signer must run as a non-root user"
        )
    chain = [path, *path.parents]
    records: list[bytes] = []
    for component in reversed(chain):
        label = f"bootstrap dependency parent {component}"
        try:
            info = component.lstat()
        except OSError as exc:
            raise SignerBootstrapError(f"{label} is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SignerBootstrapError(
                f"{label} must be a regular directory"
            )
        if require_immutable:
            if info.st_uid != 0:
                raise SignerBootstrapError(
                    f"{label} must be root-owned"
                )
            if stat.S_IMODE(info.st_mode) & 0o022:
                raise SignerBootstrapError(
                    f"{label} is group/world writable"
                )
            if _effective_access(component, os.W_OK):
                raise SignerBootstrapError(
                    f"{label} is writable by the signer runtime"
                )
        records.append(
            (
                f"{component}\0{info.st_dev}\0{info.st_ino}\0"
                f"{info.st_uid}\0{info.st_gid}\0"
                f"{stat.S_IMODE(info.st_mode):o}"
            ).encode("utf-8")
        )
    return records


def bootstrap_site_packages_identity(
    path: Path,
    *,
    require_immutable: bool = False,
) -> str:
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
    first = _site_packages_path_chain_records(
        path,
        require_immutable=require_immutable,
    )
    second = _site_packages_path_chain_records(
        path,
        require_immutable=require_immutable,
    )
    if first != second:
        raise SignerBootstrapError(
            "bootstrap dependency parent chain changed during identity scan"
        )
    digest = hashlib.sha256()
    digest.update(
        BOOTSTRAP_SITE_PACKAGES_IDENTITY_VERSION.encode("ascii")
    )
    digest.update(b"\0")
    for record in first:
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return digest.hexdigest()


def _validate_sha256(value: str, label: str) -> None:
    if (
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SignerBootstrapError(f"{label} is invalid")


def _validate_image_digest(value: str, label: str) -> None:
    prefix = "sha256:"
    if not value.startswith(prefix):
        raise SignerBootstrapError(f"{label} is invalid")
    _validate_sha256(value[len(prefix) :], label)


def _dependency_entry_is_safe(
    info: os.stat_result,
    *,
    path: Path,
    regular: bool,
    label: str,
    require_immutable: bool,
) -> None:
    if info.st_uid not in {0, os.geteuid()}:
        raise SignerBootstrapError(f"{label} owner is unsafe")
    if require_immutable and info.st_uid != 0:
        raise SignerBootstrapError(f"{label} must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise SignerBootstrapError(f"{label} is group/world writable")
    if require_immutable and _effective_access(path, os.W_OK):
        raise SignerBootstrapError(
            f"{label} is writable by the signer runtime"
        )
    if regular and info.st_nlink != 1:
        raise SignerBootstrapError(
            f"{label} must be a single-link regular file"
        )


def _read_dependency_file(
    path: Path,
    label: str,
    *,
    require_immutable: bool,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        before_path = path.lstat()
        if (
            stat.S_ISLNK(before_path.st_mode)
            or not stat.S_ISREG(before_path.st_mode)
        ):
            raise SignerBootstrapError(
                f"{label} must be a regular non-symlink file"
            )
        _dependency_entry_is_safe(
            before_path,
            path=path,
            regular=True,
            label=label,
            require_immutable=require_immutable,
        )
        if before_path.st_size > MAX_BOOTSTRAP_DEPENDENCY_FILE_BYTES:
            raise SignerBootstrapError(f"{label} is too large")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(before_path) != _file_identity(opened):
            raise SignerBootstrapError(
                f"{label} changed before stable read"
            )
        first = _read_fd_bytes(
            descriptor,
            label,
            limit=MAX_BOOTSTRAP_DEPENDENCY_FILE_BYTES,
        )
        after_first = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_bytes(
            descriptor,
            label,
            limit=MAX_BOOTSTRAP_DEPENDENCY_FILE_BYTES,
        )
        after_second = os.fstat(descriptor)
        after_path = path.lstat()
        identity = _file_identity(opened)
        if (
            _file_identity(after_first) != identity
            or _file_identity(after_second) != identity
            or _file_identity(after_path) != identity
            or first != second
        ):
            raise SignerBootstrapError(f"{label} changed during stable read")
        return first, opened
    except SignerBootstrapError:
        raise
    except OSError as exc:
        raise SignerBootstrapError(f"{label} cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _dependency_manifest_records(
    path: Path,
    *,
    require_immutable: bool,
) -> list[bytes]:
    records: list[bytes] = []
    entries = 0

    def visit(directory: Path, relative: Path) -> None:
        nonlocal entries
        try:
            before = directory.lstat()
        except OSError as exc:
            raise SignerBootstrapError(
                "bootstrap dependency directory is unavailable"
            ) from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise SignerBootstrapError(
                "bootstrap dependency directory must not be a symlink"
            )
        _dependency_entry_is_safe(
            before,
            path=directory,
            regular=False,
            label=f"bootstrap dependency directory {relative.as_posix()}",
            require_immutable=require_immutable,
        )
        try:
            with os.scandir(directory) as iterator:
                children = sorted(
                    iterator,
                    key=lambda entry: os.fsencode(entry.name),
                )
        except OSError as exc:
            raise SignerBootstrapError(
                "bootstrap dependency directory cannot be enumerated"
            ) from exc
        for child in children:
            entries += 1
            if entries > MAX_BOOTSTRAP_DEPENDENCY_ENTRIES:
                raise SignerBootstrapError(
                    "bootstrap dependency closure has too many entries"
                )
            child_relative = relative / child.name
            child_label = (
                f"bootstrap dependency {child_relative.as_posix()}"
            )
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise SignerBootstrapError(
                    f"{child_label} cannot be inspected"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                raise SignerBootstrapError(
                    f"{child_label} symlink escape is forbidden"
                )
            encoded_path = child_relative.as_posix().encode("utf-8")
            if stat.S_ISDIR(info.st_mode):
                _dependency_entry_is_safe(
                    info,
                    path=Path(child.path),
                    regular=False,
                    label=child_label,
                    require_immutable=require_immutable,
                )
                if (
                    relative == Path(".")
                    and not child.name.endswith(
                        (".dist-info", ".data", ".libs")
                    )
                ):
                    package_init = Path(child.path) / "__init__.py"
                    try:
                        init_info = package_init.lstat()
                    except OSError as exc:
                        raise SignerBootstrapError(
                            f"{child_label} namespace escape is forbidden"
                        ) from exc
                    if (
                        stat.S_ISLNK(init_info.st_mode)
                        or not stat.S_ISREG(init_info.st_mode)
                    ):
                        raise SignerBootstrapError(
                            f"{child_label} namespace escape is forbidden"
                        )
                records.append(
                    b"D\0"
                    + encoded_path
                    + b"\0"
                    + f"{info.st_uid}:{stat.S_IMODE(info.st_mode):o}".encode(
                        "ascii"
                    )
                )
                visit(Path(child.path), child_relative)
            elif stat.S_ISREG(info.st_mode):
                if (
                    child.name in FORBIDDEN_BOOTSTRAP_SITE_ENTRIES
                    or child.name.endswith((".pth", ".egg-link"))
                ):
                    raise SignerBootstrapError(
                        f"{child_label} startup hook is forbidden"
                    )
                raw, opened = _read_dependency_file(
                    Path(child.path),
                    child_label,
                    require_immutable=require_immutable,
                )
                records.append(
                    b"F\0"
                    + encoded_path
                    + b"\0"
                    + (
                        f"{opened.st_uid}:"
                        f"{stat.S_IMODE(opened.st_mode):o}:"
                        f"{opened.st_size}:"
                    ).encode("ascii")
                    + hashlib.sha256(raw).hexdigest().encode("ascii")
                )
            else:
                raise SignerBootstrapError(
                    f"{child_label} has a forbidden file type"
                )
        try:
            after = directory.lstat()
        except OSError as exc:
            raise SignerBootstrapError(
                "bootstrap dependency directory changed during scan"
            ) from exc
        if _file_identity(before) != _file_identity(after):
            raise SignerBootstrapError(
                "bootstrap dependency directory changed during scan"
            )

    visit(path, Path("."))
    return records


def bootstrap_dependency_manifest_sha256(
    path: Path,
    *,
    require_immutable: bool = False,
) -> str:
    """Hash the exact safe dependency tree twice without importing it."""

    first = _dependency_manifest_records(
        path,
        require_immutable=require_immutable,
    )
    second = _dependency_manifest_records(
        path,
        require_immutable=require_immutable,
    )
    if first != second:
        raise SignerBootstrapError(
            "bootstrap dependency closure changed during stable scan"
        )
    digest = hashlib.sha256()
    digest.update(BOOTSTRAP_DEPENDENCY_MANIFEST_VERSION.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(path).encode("utf-8"))
    digest.update(b"\0")
    for record in first:
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return digest.hexdigest()


def _install_bootstrap_site_packages_from_argv() -> None:
    global BOOTSTRAP_SITE_PACKAGES_PATH
    global RETAINED_BOOTSTRAP_DEPENDENCY_MANIFEST_SHA256
    global RETAINED_BOOTSTRAP_SITE_PACKAGES_IDENTITY_SHA256
    global RETAINED_SIGNER_RUNTIME_IMAGE_DIGEST

    raw_path = _take_bootstrap_argument(
        BOOTSTRAP_SITE_PACKAGES_ARGUMENT
    )
    expected_identity = _take_bootstrap_argument(
        BOOTSTRAP_SITE_PACKAGES_PIN_ARGUMENT
    )
    expected_manifest = _take_bootstrap_argument(
        BOOTSTRAP_DEPENDENCY_MANIFEST_PIN_ARGUMENT
    )
    runtime_image_digest = _take_bootstrap_argument(
        SIGNER_RUNTIME_IMAGE_DIGEST_ARGUMENT
    )
    _validate_sha256(
        expected_identity,
        "bootstrap site-packages identity pin",
    )
    _validate_sha256(
        expected_manifest,
        "bootstrap dependency manifest pin",
    )
    _validate_image_digest(
        runtime_image_digest,
        "signer runtime image digest",
    )
    path = Path(raw_path)
    actual_identity = bootstrap_site_packages_identity(
        path,
        require_immutable=True,
    )
    if not hmac.compare_digest(actual_identity, expected_identity):
        raise SignerBootstrapError(
            "bootstrap site-packages identity pin mismatch"
        )
    actual_manifest = bootstrap_dependency_manifest_sha256(
        path,
        require_immutable=True,
    )
    if not hmac.compare_digest(actual_manifest, expected_manifest):
        raise SignerBootstrapError(
            "bootstrap dependency manifest pin mismatch"
        )
    BOOTSTRAP_SITE_PACKAGES_PATH = path.resolve(strict=True)
    RETAINED_BOOTSTRAP_SITE_PACKAGES_IDENTITY_SHA256 = actual_identity
    RETAINED_BOOTSTRAP_DEPENDENCY_MANIFEST_SHA256 = actual_manifest
    RETAINED_SIGNER_RUNTIME_IMAGE_DIGEST = runtime_image_digest
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


def _read_fd_bytes(
    descriptor: int,
    label: str,
    *,
    limit: int = MAX_BOOTSTRAP_SOURCE_BYTES,
) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
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

_delegate_signing_tool_source_identity = (
    _delegate._signing_tool_source_identity
)
_delegate_load_private_key = _delegate.load_private_key


def _require_retained_signer_runtime_identity() -> tuple[str, str]:
    manifest = RETAINED_BOOTSTRAP_DEPENDENCY_MANIFEST_SHA256
    image_digest = RETAINED_SIGNER_RUNTIME_IMAGE_DIGEST
    if manifest is None or image_digest is None:
        raise SignerBootstrapError(
            "signer runtime identity was not established by the "
            "isolated production entry"
        )
    return manifest, image_digest


def _signing_tool_source_identity(
    *,
    expected_source_sha256: str,
    expected_source_commit_sha: str,
) -> dict[str, str]:
    manifest, image_digest = _require_retained_signer_runtime_identity()
    identity = _delegate_signing_tool_source_identity(
        expected_source_sha256=expected_source_sha256,
        expected_source_commit_sha=expected_source_commit_sha,
    )
    identity.update(
        {
            "bootstrap_dependency_manifest_sha256": manifest,
            "signer_runtime_image_digest": image_digest,
            "runtime_verification_scope": (
                "INDEPENDENTLY_PINNED_DEPENDENCY_CLOSURE_IN_"
                "TRUSTED_READONLY_SIGNER_IMAGE"
            ),
        }
    )
    provenance_v3.EXPECTED_SIGNER_DEPENDENCY_MANIFEST_SHA256 = (
        manifest
    )
    provenance_v3.EXPECTED_SIGNER_RUNTIME_IMAGE_DIGEST = image_digest
    return identity


def _revalidate_bootstrap_dependency_closure() -> None:
    if BOOTSTRAP_SITE_PACKAGES_PATH is None:
        if RUNNING_AS_SCRIPT:
            raise SignerBootstrapError(
                "bootstrap dependency closure path is unavailable"
            )
        return
    expected_manifest, _image_digest = (
        _require_retained_signer_runtime_identity()
    )
    if RETAINED_BOOTSTRAP_SITE_PACKAGES_IDENTITY_SHA256 is None:
        raise SignerBootstrapError(
            "bootstrap site-packages identity was not retained"
        )
    actual_root = bootstrap_site_packages_identity(
        BOOTSTRAP_SITE_PACKAGES_PATH,
        require_immutable=True,
    )
    if not hmac.compare_digest(
        actual_root,
        RETAINED_BOOTSTRAP_SITE_PACKAGES_IDENTITY_SHA256,
    ):
        raise SignerBootstrapError(
            "bootstrap site-packages identity drifted before private-key read"
        )
    actual_manifest = bootstrap_dependency_manifest_sha256(
        BOOTSTRAP_SITE_PACKAGES_PATH,
        require_immutable=True,
    )
    if not hmac.compare_digest(actual_manifest, expected_manifest):
        raise SignerBootstrapError(
            "bootstrap dependency closure drifted before private-key read"
        )


def load_private_key(path: Path) -> Any:
    _revalidate_bootstrap_dependency_closure()
    return _delegate_load_private_key(path)


_delegate._signing_tool_source_identity = _signing_tool_source_identity
_delegate.load_private_key = load_private_key

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
