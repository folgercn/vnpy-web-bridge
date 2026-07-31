"""Isolated, independently pinned launcher for readiness-v4."""

from __future__ import annotations

import sys


RUNNING_AS_SCRIPT = __name__ == "__main__"


def _require_isolated_startup() -> None:
    flags = sys.flags
    if not (
        flags.isolated == 1
        and flags.no_site == 1
        and flags.no_user_site == 1
        and flags.ignore_environment == 1
        and flags.dont_write_bytecode == 1
    ):
        raise SystemExit(
            "readiness-v4 launcher requires a fixed interpreter with "
            "-I -S -s -E -B"
        )


if RUNNING_AS_SCRIPT:
    _require_isolated_startup()


import hashlib  # noqa: E402
import hmac  # noqa: E402
import importlib.abc  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import stat  # noqa: E402
from types import ModuleType  # noqa: E402
from typing import Any  # noqa: E402


PIN_ROOT = Path("/run/c-fast-t1-readiness-v4-pins")
PIN_MANIFEST_PATH = PIN_ROOT / "pin-set.manifest.json"
PIN_MANIFEST_VERSION = "commodity_c_fast_t1_readiness_v4_pin_set_v2"
READINESS_MODULE = "commodity_c_fast_t1_readiness_v4"
LAUNCHER_PATH = Path(__file__).resolve()
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 100_000
SOURCE_MANIFEST_VERSION = "c-fast-readiness-v4-source-closure-v1"
DEPENDENCY_MANIFEST_VERSION = "c-fast-readiness-v4-dependency-closure-v1"
DIRECTORY_IDENTITY_VERSION = "c-fast-readiness-v4-directory-identity-v1"
FORBIDDEN_DEPENDENCY_ENTRIES = frozenset(
    {
        "sitecustomize.py",
        "sitecustomize.pyc",
        "usercustomize.py",
        "usercustomize.pyc",
    }
)
PIN_FILES = {
    "readiness_runtime_image_digest": "readiness-runtime-image.digest",
    "readiness_runtime_launcher_sha256": (
        "readiness-runtime-launcher.sha256"
    ),
    "readiness_runtime_verifier_sha256": (
        "readiness-runtime-verifier.sha256"
    ),
    "readiness_runtime_python_executable_path": (
        "readiness-runtime-python-executable.path"
    ),
    "readiness_runtime_python_executable_sha256": (
        "readiness-runtime-python-executable.sha256"
    ),
    "readiness_runtime_source_root_path": (
        "readiness-runtime-source-root.path"
    ),
    "readiness_runtime_source_root_identity_sha256": (
        "readiness-runtime-source-root-identity.sha256"
    ),
    "readiness_runtime_source_closure_manifest_sha256": (
        "readiness-runtime-source-closure-manifest.sha256"
    ),
    "readiness_runtime_site_packages_path": (
        "readiness-runtime-site-packages.path"
    ),
    "readiness_runtime_site_packages_identity_sha256": (
        "readiness-runtime-site-packages-identity.sha256"
    ),
    "readiness_runtime_dependency_manifest_sha256": (
        "readiness-runtime-dependency-manifest.sha256"
    ),
    "provenance_keyring_sha256": "provenance-keyring.sha256",
    "provenance_signing_tool_source_sha256": (
        "provenance-signing-tool-source.sha256"
    ),
    "provenance_signing_tool_source_commit_sha": (
        "provenance-signing-tool-source.commit"
    ),
    "provenance_signer_dependency_manifest_sha256": (
        "provenance-signer-dependency-manifest.sha256"
    ),
    "provenance_signer_runtime_image_digest": (
        "provenance-signer-runtime-image.digest"
    ),
    "query_v5_authority_keyring_sha256": (
        "query-v5-authority-keyring.sha256"
    ),
    "t1_authority_keyring_sha256": "t1-authority-keyring.sha256",
    "l3_authority_keyring_sha256": "l3-authority-keyring.sha256",
    "outcome_keyring_sha256": "outcome-keyring.sha256",
    "packet_custody_path": "packet-custody.path",
}
MANIFEST_EXTRA_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "packet_custody_id",
        "packet_custody_identity_sha256",
        "packet_custody_directory_identity_sha256",
        "evidence_join_identity_sha256",
    }
)


class ReadinessLauncherError(RuntimeError):
    """The trusted readiness execution closure failed closed."""


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ReadinessLauncherError(f"{label} is not a lowercase SHA256")


def _validate_image_digest(value: str, label: str) -> None:
    if not value.startswith("sha256:"):
        raise ReadinessLauncherError(f"{label} is not an OCI RepoDigest")
    _validate_sha256(value[7:], label)


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


def _read_fd(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_FILE_BYTES:
            raise ReadinessLauncherError(f"{label} is too large")
        chunks.append(chunk)


def _effective_writable(path: Path) -> bool:
    if os.access in os.supports_effective_ids:
        return os.access(path, os.W_OK, effective_ids=True)
    return os.access(path, os.W_OK)


def _require_safe_entry(
    path: Path,
    info: os.stat_result,
    label: str,
    *,
    regular: bool,
    require_immutable: bool,
) -> None:
    if info.st_uid not in {0, os.geteuid()}:
        raise ReadinessLauncherError(f"{label} owner is unsafe")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise ReadinessLauncherError(f"{label} is group/world writable")
    if regular and info.st_nlink != 1:
        raise ReadinessLauncherError(f"{label} must have one hard link")
    if require_immutable:
        if os.geteuid() == 0:
            raise ReadinessLauncherError(
                "readiness-v4 runtime must execute as non-root"
            )
        if info.st_uid != 0:
            raise ReadinessLauncherError(f"{label} must be root-owned")
        if _effective_writable(path):
            raise ReadinessLauncherError(
                f"{label} is writable by the readiness runtime"
            )


def _stable_read(
    path: Path,
    label: str,
    *,
    require_immutable: bool,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ReadinessLauncherError(
                f"{label} must be a regular non-symlink file"
            )
        _require_safe_entry(
            path,
            before,
            label,
            regular=True,
            require_immutable=require_immutable,
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise ReadinessLauncherError(f"{label} changed before read")
        first = _read_fd(descriptor, label)
        after_first = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd(descriptor, label)
        after_second = os.fstat(descriptor)
        after_path = path.lstat()
        identity = _file_identity(opened)
        if (
            first != second
            or _file_identity(after_first) != identity
            or _file_identity(after_second) != identity
            or _file_identity(after_path) != identity
        ):
            raise ReadinessLauncherError(f"{label} changed during read")
        return first, opened
    except ReadinessLauncherError:
        raise
    except OSError as exc:
        raise ReadinessLauncherError(f"{label} cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _directory_chain_records(
    path: Path,
    *,
    require_immutable: bool,
) -> list[dict[str, Any]]:
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ReadinessLauncherError("runtime directory path is not canonical")
    records: list[dict[str, Any]] = []
    for component in reversed((path, *path.parents)):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReadinessLauncherError(
                f"runtime ancestor {component} is not a safe directory"
            )
        _require_safe_entry(
            component,
            info,
            f"runtime ancestor {component}",
            regular=False,
            require_immutable=require_immutable,
        )
        records.append(
            {
                "path": str(component),
                "device": info.st_dev,
                "inode": info.st_ino,
                "owner_uid": info.st_uid,
                "owner_gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
                "file_type": stat.S_IFMT(info.st_mode),
            }
        )
    return records


def directory_identity_sha256(
    path: Path,
    *,
    require_immutable: bool = False,
) -> str:
    first = _directory_chain_records(path, require_immutable=require_immutable)
    second = _directory_chain_records(path, require_immutable=require_immutable)
    if first != second:
        raise ReadinessLauncherError("runtime directory identity changed")
    return _sha256(
        _canonical(
            {
                "schema_version": DIRECTORY_IDENTITY_VERSION,
                "resolved_path": str(path.resolve(strict=True)),
                "chain": first,
            }
        )
    )


def _scan_tree(
    root: Path,
    *,
    manifest_version: str,
    require_immutable: bool,
    retain_python_under: Path | None = None,
    reject_startup_hooks: bool = False,
) -> tuple[str, dict[str, tuple[bytes, Path, bool]]]:
    records: list[dict[str, Any]] = []
    retained: dict[str, tuple[bytes, Path, bool]] = {}
    count = 0

    def visit(directory: Path, relative: Path) -> None:
        nonlocal count
        before = directory.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise ReadinessLauncherError("runtime tree directory is unsafe")
        _require_safe_entry(
            directory,
            before,
            f"runtime directory {relative.as_posix()}",
            regular=False,
            require_immutable=require_immutable,
        )
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for child in children:
            count += 1
            if count > MAX_ENTRIES:
                raise ReadinessLauncherError("runtime closure has too many entries")
            child_path = Path(child.path)
            child_relative = relative / child.name
            info = child.stat(follow_symlinks=False)
            label = f"runtime entry {child_relative.as_posix()}"
            if stat.S_ISLNK(info.st_mode):
                raise ReadinessLauncherError(f"{label} symlink is forbidden")
            if stat.S_ISDIR(info.st_mode):
                _require_safe_entry(
                    child_path,
                    info,
                    label,
                    regular=False,
                    require_immutable=require_immutable,
                )
                records.append(
                    {
                        "type": "directory",
                        "path": child_relative.as_posix(),
                        "uid": info.st_uid,
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                visit(child_path, child_relative)
            elif stat.S_ISREG(info.st_mode):
                if reject_startup_hooks and (
                    child.name in FORBIDDEN_DEPENDENCY_ENTRIES
                    or child.name.endswith((".pth", ".egg-link"))
                ):
                    raise ReadinessLauncherError(
                        f"{label} startup hook is forbidden"
                    )
                raw, opened = _stable_read(
                    child_path,
                    label,
                    require_immutable=require_immutable,
                )
                records.append(
                    {
                        "type": "file",
                        "path": child_relative.as_posix(),
                        "uid": opened.st_uid,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "size": len(raw),
                        "sha256": _sha256(raw),
                    }
                )
                if (
                    retain_python_under is not None
                    and child_path.suffix == ".py"
                    and child_path.is_relative_to(retain_python_under)
                ):
                    module_relative = child_path.relative_to(retain_python_under)
                    package = module_relative.name == "__init__.py"
                    parts = list(module_relative.parts)
                    if package:
                        parts.pop()
                    else:
                        parts[-1] = module_relative.stem
                    module_name = ".".join(parts)
                    if module_name:
                        retained[module_name] = (raw, child_path, package)
            else:
                raise ReadinessLauncherError(f"{label} file type is forbidden")
        after = directory.lstat()
        if _file_identity(before) != _file_identity(after):
            raise ReadinessLauncherError("runtime tree changed during scan")

    visit(root, Path("."))
    digest = _sha256(
        _canonical(
            {
                "schema_version": manifest_version,
                "root": str(root),
                "records": records,
            }
        )
    )
    return digest, retained


def scan_source_closure(
    root: Path,
    *,
    require_immutable: bool = False,
) -> tuple[str, dict[str, tuple[bytes, Path, bool]]]:
    scripts = root / "scripts"
    first, retained = _scan_tree(
        root,
        manifest_version=SOURCE_MANIFEST_VERSION,
        require_immutable=require_immutable,
        retain_python_under=scripts,
    )
    second, second_retained = _scan_tree(
        root,
        manifest_version=SOURCE_MANIFEST_VERSION,
        require_immutable=require_immutable,
        retain_python_under=scripts,
    )
    if first != second or retained != second_retained:
        raise ReadinessLauncherError("source closure changed during stable scan")
    if READINESS_MODULE not in retained:
        raise ReadinessLauncherError("readiness-v4 verifier is absent from closure")
    return first, retained


def scan_dependency_closure(
    root: Path,
    *,
    require_immutable: bool = False,
) -> str:
    first, _ = _scan_tree(
        root,
        manifest_version=DEPENDENCY_MANIFEST_VERSION,
        require_immutable=require_immutable,
        reject_startup_hooks=True,
    )
    second, _ = _scan_tree(
        root,
        manifest_version=DEPENDENCY_MANIFEST_VERSION,
        require_immutable=require_immutable,
        reject_startup_hooks=True,
    )
    if first != second:
        raise ReadinessLauncherError(
            "dependency closure changed during stable scan"
        )
    return first


def _read_root_pin(path: Path, label: str) -> str:
    raw, _ = _stable_read(path, label, require_immutable=True)
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReadinessLauncherError(f"{label} must be ASCII") from exc
    if not value or b"\n" in raw.strip() or b"\r" in raw.strip():
        raise ReadinessLauncherError(f"{label} must contain one line")
    return value


def _read_pin_snapshot() -> tuple[dict[str, str], str]:
    directory_identity_sha256(PIN_ROOT, require_immutable=True)
    manifest_raw_before, _ = _stable_read(
        PIN_MANIFEST_PATH,
        "readiness-v4 pin manifest",
        require_immutable=True,
    )
    try:
        manifest = json.loads(manifest_raw_before)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadinessLauncherError("pin manifest is not valid JSON") from exc
    expected_fields = set(PIN_FILES) | set(MANIFEST_EXTRA_FIELDS)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_fields
        or manifest.get("schema_version") != PIN_MANIFEST_VERSION
    ):
        raise ReadinessLauncherError("pin manifest fields are invalid")
    values = {
        field: _read_root_pin(PIN_ROOT / filename, field)
        for field, filename in PIN_FILES.items()
    }
    if any(str(manifest[field]) != value for field, value in values.items()):
        raise ReadinessLauncherError("pin files do not match one generation")
    manifest_raw_after, _ = _stable_read(
        PIN_MANIFEST_PATH,
        "readiness-v4 pin manifest",
        require_immutable=True,
    )
    if manifest_raw_before != manifest_raw_after:
        raise ReadinessLauncherError("pin generation changed during read")
    return values, _sha256(_canonical(manifest))


class _RetainedSourceLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(
        self,
        sources: dict[str, tuple[bytes, Path, bool]],
        scripts_root: Path,
    ) -> None:
        self.sources = sources
        self.synthetic_packages: dict[str, Path] = {}
        for module_name in sources:
            parts = module_name.split(".")
            for length in range(1, len(parts)):
                package_name = ".".join(parts[:length])
                if package_name not in sources:
                    self.synthetic_packages[package_name] = (
                        scripts_root.joinpath(*parts[:length])
                    )

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: ModuleType | None = None,
    ) -> Any:
        entry = self.sources.get(fullname)
        if entry is None:
            if fullname not in self.synthetic_packages:
                return None
            return importlib.util.spec_from_loader(
                fullname,
                self,
                origin=str(self.synthetic_packages[fullname]),
                is_package=True,
            )
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=str(entry[1]),
            is_package=entry[2],
        )

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        entry = self.sources.get(module.__name__)
        if entry is None:
            module.__path__ = [  # type: ignore[attr-defined]
                str(self.synthetic_packages[module.__name__])
            ]
            return
        raw, path, package = entry
        module.__file__ = str(path)
        if package:
            module.__path__ = [str(path.parent)]  # type: ignore[attr-defined]
        code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)


def _build_runtime() -> tuple[dict[str, Any], Any, dict[str, tuple[bytes, Path, bool]]]:
    pins, manifest_sha256 = _read_pin_snapshot()
    _validate_image_digest(
        pins["readiness_runtime_image_digest"],
        "readiness runtime image digest",
    )
    for field in (
        "readiness_runtime_launcher_sha256",
        "readiness_runtime_verifier_sha256",
        "readiness_runtime_python_executable_sha256",
        "readiness_runtime_source_root_identity_sha256",
        "readiness_runtime_source_closure_manifest_sha256",
        "readiness_runtime_site_packages_identity_sha256",
        "readiness_runtime_dependency_manifest_sha256",
    ):
        _validate_sha256(pins[field], field)
    python_path = Path(pins["readiness_runtime_python_executable_path"])
    source_root = Path(pins["readiness_runtime_source_root_path"])
    site_packages = Path(pins["readiness_runtime_site_packages_path"])
    if Path(sys.executable) != python_path:
        raise ReadinessLauncherError("running interpreter path is not pinned")
    expected_launcher = (
        source_root
        / "scripts/commodity_c_fast_t1_readiness_v4_launcher.py"
    ).resolve(strict=True)
    if LAUNCHER_PATH != expected_launcher:
        raise ReadinessLauncherError(
            "running launcher is outside the pinned source closure"
        )
    launcher_raw, _ = _stable_read(
        LAUNCHER_PATH,
        "readiness-v4 launcher",
        require_immutable=True,
    )
    python_raw, _ = _stable_read(
        python_path,
        "readiness-v4 Python executable",
        require_immutable=True,
    )
    source_identity = directory_identity_sha256(
        source_root,
        require_immutable=True,
    )
    site_identity = directory_identity_sha256(
        site_packages,
        require_immutable=True,
    )
    source_manifest, retained = scan_source_closure(
        source_root,
        require_immutable=True,
    )
    dependency_manifest = scan_dependency_closure(
        site_packages,
        require_immutable=True,
    )
    verifier_raw = retained[READINESS_MODULE][0]
    actual = {
        "readiness_runtime_launcher_sha256": _sha256(launcher_raw),
        "readiness_runtime_verifier_sha256": _sha256(verifier_raw),
        "readiness_runtime_python_executable_sha256": _sha256(python_raw),
        "readiness_runtime_source_root_identity_sha256": source_identity,
        "readiness_runtime_source_closure_manifest_sha256": source_manifest,
        "readiness_runtime_site_packages_identity_sha256": site_identity,
        "readiness_runtime_dependency_manifest_sha256": dependency_manifest,
    }
    if any(not hmac.compare_digest(actual[field], pins[field]) for field in actual):
        raise ReadinessLauncherError("readiness runtime closure pin mismatch")
    identity = {
        "runtime_image_digest": pins["readiness_runtime_image_digest"],
        "launcher_sha256": actual["readiness_runtime_launcher_sha256"],
        "verifier_sha256": actual["readiness_runtime_verifier_sha256"],
        "python_executable_path_sha256": _sha256(str(python_path).encode()),
        "python_executable_sha256": actual[
            "readiness_runtime_python_executable_sha256"
        ],
        "source_root_path_sha256": _sha256(str(source_root).encode()),
        "source_root_identity_sha256": source_identity,
        "source_closure_manifest_sha256": source_manifest,
        "site_packages_path_sha256": _sha256(str(site_packages).encode()),
        "site_packages_identity_sha256": site_identity,
        "dependency_manifest_sha256": dependency_manifest,
        "isolated_flags_verified": True,
        "source_closure_retained": True,
        "immutable_runtime_verified": True,
    }
    snapshot = (pins, manifest_sha256, identity)

    def revalidate() -> None:
        current_pins, current_manifest_sha256 = _read_pin_snapshot()
        if current_pins != snapshot[0] or current_manifest_sha256 != snapshot[1]:
            raise ReadinessLauncherError("readiness pin generation changed")
        current_source, _ = scan_source_closure(
            source_root,
            require_immutable=True,
        )
        current_dependency = scan_dependency_closure(
            site_packages,
            require_immutable=True,
        )
        current_launcher, _ = _stable_read(
            LAUNCHER_PATH,
            "readiness-v4 launcher",
            require_immutable=True,
        )
        current_python, _ = _stable_read(
            python_path,
            "readiness-v4 Python executable",
            require_immutable=True,
        )
        if (
            current_source != source_manifest
            or current_dependency != dependency_manifest
            or _sha256(current_launcher) != identity["launcher_sha256"]
            or _sha256(current_python) != identity["python_executable_sha256"]
            or directory_identity_sha256(source_root, require_immutable=True)
            != source_identity
            or directory_identity_sha256(site_packages, require_immutable=True)
            != site_identity
        ):
            raise ReadinessLauncherError("readiness runtime identity drifted")

    return identity, revalidate, retained


def main() -> int:
    try:
        identity, revalidate, retained = _build_runtime()
        site_packages = Path(
            _read_pin_snapshot()[0]["readiness_runtime_site_packages_path"]
        )
        sys.path = [
            entry
            for entry in sys.path
            if entry and Path(entry).resolve() != LAUNCHER_PATH.parent
        ]
        sys.path.append(str(site_packages))
        retained_loader = _RetainedSourceLoader(
            retained,
            Path(_read_pin_snapshot()[0]["readiness_runtime_source_root_path"])
            / "scripts",
        )
        sys.meta_path.insert(0, retained_loader)
        spec = importlib.util.find_spec(READINESS_MODULE)
        if spec is None or spec.loader is not retained_loader:
            raise ReadinessLauncherError(
                "readiness verifier did not resolve from retained bytes"
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[READINESS_MODULE] = module
        spec.loader.exec_module(module)
        module.install_verified_runtime_identity(
            module.ReadinessRuntimeIdentity(**identity),
            revalidate,
        )
        revalidate()
        return int(module.main())
    except (ReadinessLauncherError, OSError, ValueError) as exc:
        print(f"readiness-v4 trusted launcher failed: {exc}", file=sys.stderr)
        return 2


if RUNNING_AS_SCRIPT:
    raise SystemExit(main())
