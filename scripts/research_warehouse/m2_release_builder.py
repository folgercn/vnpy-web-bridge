"""Build one deterministic, non-authoritative M2 Research release package."""

from __future__ import annotations

import email.parser
import os
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .authority import assert_research_source_boundary
from .canonical import canonical_json_line, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_release_bundle_contracts import (
    BUNDLE_MANIFEST_SCHEMA,
    LOGICAL_RELEASE_ROOT,
    RUNTIME_METADATA_PATH,
    RUNTIME_METADATA_SCHEMA,
    DependencyBinding,
    DependencyLock,
    false_authority,
    python_identity,
    require_release_id,
    require_source_commit,
    scan_content_tree,
    tree_content_sha256,
    validate_dependency_lock_binding,
)

ENTRY_MODULE_PATH = "libexec/m2_release_entry.py"
SITE_PACKAGES_PATH = "lib/python3.12/site-packages"
FORBIDDEN_WHEEL_BASENAMES = {
    "sitecustomize.py",
    "sitecustomize.pyc",
    "usercustomize.py",
    "usercustomize.pyc",
}
FORBIDDEN_WHEEL_ROOTS = {
    "backend",
    "psycopg",
    "questdb",
    "research_warehouse",
    "vnpy",
    "zmq",
}


def require_clean_source_commit(source_root: Path) -> str:
    try:
        resolved = source_root.resolve(strict=True)
        facts = source_root.lstat()
        top_level = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=source_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=source_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RegistryError("cannot determine M2 release source state") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or Path(top_level).resolve(strict=True) != resolved
    ):
        raise RegistryError("M2 release source root custody mismatch")
    if status:
        raise RegistryError("M2 release source checkout must be clean")
    return require_source_commit(commit)


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir()
    os.chown(path, os.geteuid(), os.getegid())
    path.chmod(mode)


def _write_file(path: Path, raw: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchown(descriptor, os.geteuid(), os.getegid())
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(mode)


def _remove_private_tree(path: Path) -> None:
    try:
        path.chmod(0o700)
    except OSError:
        pass
    for directory, names, _files in os.walk(path, topdown=True):
        current = Path(directory)
        try:
            current.chmod(0o700)
        except OSError:
            pass
        for name in names:
            child = current / name
            try:
                facts = child.lstat()
                if stat.S_ISDIR(facts.st_mode) and not stat.S_ISLNK(
                    facts.st_mode
                ):
                    child.chmod(0o700)
            except OSError:
                pass
    shutil.rmtree(path)


def _ensure_directory(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists():
            facts = current.lstat()
            if stat.S_ISLNK(facts.st_mode) or not stat.S_ISDIR(facts.st_mode):
                raise RegistryError("wheel extraction directory collision")
        else:
            _mkdir(current, 0o700)
    return current


def _freeze_directories(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in sorted(
        directories,
        key=lambda value: len(value.relative_to(root).parts),
        reverse=True,
    ):
        path.chmod(0o555)
    root.chmod(0o755)


def _safe_wheel_member(name: str) -> PurePosixPath:
    logical = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or logical.is_absolute()
        or ".." in logical.parts
        or "." in logical.parts
        or logical.as_posix() != name.rstrip("/")
    ):
        raise RegistryError(f"wheel contains unsafe path: {name}")
    if logical.parts[0].endswith(".data"):
        raise RegistryError("wheel .data relocation is not supported")
    basename = logical.name.lower()
    if basename.endswith(".pth") or basename in FORBIDDEN_WHEEL_BASENAMES:
        raise RegistryError(f"wheel startup injection is forbidden: {name}")
    if logical.parts[0].lower() in FORBIDDEN_WHEEL_ROOTS:
        raise RegistryError(f"wheel forbidden import root: {logical.parts[0]}")
    return logical


def _wheel_metadata(
    archive: zipfile.ZipFile,
    dependency: DependencyBinding,
) -> None:
    expected_suffix = f"{dependency.name.replace('-', '_')}-{dependency.version}.dist-info/METADATA"
    candidates = [
        name
        for name in archive.namelist()
        if name.lower() == expected_suffix.lower()
    ]
    if len(candidates) != 1:
        raise RegistryError(
            f"wheel metadata missing for dependency {dependency.name}"
        )
    try:
        metadata = email.parser.BytesParser().parsebytes(
            archive.read(candidates[0])
        )
    except (KeyError, OSError) as exc:
        raise RegistryError("wheel metadata is unreadable") from exc
    if (
        metadata.get("Name", "").lower().replace("-", "_")
        != dependency.name.lower().replace("-", "_")
        or metadata.get("Version") != dependency.version
    ):
        raise RegistryError("wheel metadata name/version mismatch")


def _extract_wheel(
    wheel_path: Path,
    *,
    dependency: DependencyBinding,
    site_packages: Path,
    claimed_paths: set[str],
) -> None:
    raw = read_regular_strict(
        wheel_path,
        f"M2 release wheel {dependency.name}",
        private=False,
    )
    if len(raw) != dependency.size_bytes or sha256(raw) != dependency.wheel_sha256:
        raise RegistryError(f"M2 release wheel hash/size mismatch: {dependency.name}")
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            _wheel_metadata(archive, dependency)
            names = archive.infolist()
            if len({item.filename for item in names}) != len(names):
                raise RegistryError("wheel contains duplicate members")
            for item in sorted(names, key=lambda value: value.filename):
                logical = _safe_wheel_member(item.filename)
                unix_mode = (item.external_attr >> 16) & 0o177777
                if stat.S_ISLNK(unix_mode):
                    raise RegistryError(
                        f"wheel symlink is forbidden: {item.filename}"
                    )
                relative = logical.as_posix()
                if item.is_dir():
                    _ensure_directory(site_packages, logical)
                    continue
                if relative in claimed_paths:
                    raise RegistryError(f"wheel path collision: {relative}")
                claimed_paths.add(relative)
                parent = _ensure_directory(site_packages, logical.parent)
                try:
                    member_raw = archive.read(item)
                except (KeyError, OSError) as exc:
                    raise RegistryError(
                        f"wheel member is unreadable: {relative}"
                    ) from exc
                _write_file(parent / logical.name, member_raw, 0o444)
    except (zipfile.BadZipFile, OSError) as exc:
        raise RegistryError(
            f"M2 release wheel is invalid: {dependency.name}"
        ) from exc


def _entry_module() -> bytes:
    return (
        "#!/usr/local/bin/python3.12\n"
        "from pathlib import Path\n"
        "import sys\n"
        "\n"
        "release_root = Path(__file__).resolve(strict=True).parents[1]\n"
        "sys.path.insert(0, str(release_root / 'lib/python3.12/site-packages'))\n"
        "sys.path.insert(0, str(release_root / 'lib'))\n"
        "from research_warehouse.m2_release_entry import main\n"
        "\n"
        "raise SystemExit(main(sys.argv[1:], release_root=release_root))\n"
    ).encode("utf-8")


def _role_entrypoint(role: str) -> bytes:
    if role not in {"warehouse", "monitor"}:
        raise RegistryError("M2 release role is invalid")
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        "umask 077\n"
        "unset PYTHONPATH PYTHONHOME PYTHONUSERBASE\n"
        f"exec {python_identity()['executable']} -I -s -E "
        f"{LOGICAL_RELEASE_ROOT}/{ENTRY_MODULE_PATH} {role} self-check\n"
    ).encode("utf-8")


def _copy_research_sources(
    source_root: Path,
    release_root: Path,
) -> list[dict[str, str]]:
    package_root = source_root / "scripts/research_warehouse"
    sources = sorted(package_root.glob("*.py"))
    if not sources or not (package_root / "__init__.py").is_file():
        raise RegistryError("Research source package is incomplete")
    assert_research_source_boundary(sources)
    destination = release_root / "lib/research_warehouse"
    bindings: list[dict[str, str]] = []
    for source in sources:
        raw = read_regular_strict(
            source,
            f"M2 release source {source.name}",
            private=False,
        )
        release_path = f"lib/research_warehouse/{source.name}"
        _write_file(destination / source.name, raw, 0o444)
        bindings.append(
            {
                "repo_path": source.relative_to(source_root).as_posix(),
                "release_path": release_path,
                "raw_sha256": sha256(raw),
            }
        )
    return bindings


def build_release_package(
    *,
    source_root: Path,
    package_root: Path,
    wheelhouse: Path,
    dependency_lock: DependencyLock,
    release_id: str,
    source_commit_sha: str,
) -> dict[str, Any]:
    """Build a create-only package; no installation or authority is granted."""
    release_id = require_release_id(release_id)
    source_commit_sha = require_source_commit(source_commit_sha)
    validate_dependency_lock_binding(dependency_lock)
    observed_source_commit_sha = require_clean_source_commit(source_root)
    if observed_source_commit_sha != source_commit_sha:
        raise RegistryError("M2 release source commit does not match checkout")
    if package_root.exists():
        raise RegistryError("M2 release package root already exists")
    try:
        package_root.mkdir(mode=0o700)
        os.chown(package_root, os.geteuid(), os.getegid())
        package_root.chmod(0o700)
        release_root = package_root / "release"
        _mkdir(release_root, 0o700)
        for relative in (
            "bin",
            "lib",
            "lib/research_warehouse",
            "lib/python3.12",
            SITE_PACKAGES_PATH,
            "libexec",
            "meta",
        ):
            _ensure_directory(release_root, PurePosixPath(relative))

        claimed_paths: set[str] = set()
        site_packages = release_root / SITE_PACKAGES_PATH
        for dependency in dependency_lock.dependencies:
            wheel = wheelhouse / dependency.wheel_filename
            _extract_wheel(
                wheel,
                dependency=dependency,
                site_packages=site_packages,
                claimed_paths=claimed_paths,
            )

        source_bindings = _copy_research_sources(source_root, release_root)
        _write_file(
            release_root / ENTRY_MODULE_PATH,
            _entry_module(),
            0o555,
        )
        _write_file(
            release_root / "bin/research-warehouse-job",
            _role_entrypoint("warehouse"),
            0o555,
        )
        _write_file(
            release_root / "bin/research-warehouse-monitor",
            _role_entrypoint("monitor"),
            0o555,
        )

        _freeze_directories(release_root)
        runtime_entries = scan_content_tree(
            release_root,
            exclude=frozenset({RUNTIME_METADATA_PATH}),
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
        )
        runtime_metadata = {
            "schema_version": RUNTIME_METADATA_SCHEMA,
            "release_id": release_id,
            "source_commit_sha": source_commit_sha,
            "logical_release_root": LOGICAL_RELEASE_ROOT,
            "dependency_lock_raw_sha256": dependency_lock.raw_sha256,
            "python": python_identity(),
            "dependencies": dependency_lock.dependency_dicts(),
            "source_bindings": source_bindings,
            "runtime_entries": runtime_entries,
            "runtime_tree_content_sha256": tree_content_sha256(runtime_entries),
            "authority": false_authority(),
        }
        metadata_parent = (release_root / RUNTIME_METADATA_PATH).parent
        metadata_parent.chmod(0o700)
        _write_file(
            release_root / RUNTIME_METADATA_PATH,
            canonical_json_line(runtime_metadata),
            0o444,
        )
        metadata_parent.chmod(0o555)
        entries = scan_content_tree(
            release_root,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
        )
        manifest = {
            "schema_version": BUNDLE_MANIFEST_SCHEMA,
            "release_id": release_id,
            "source_commit_sha": source_commit_sha,
            "logical_release_root": LOGICAL_RELEASE_ROOT,
            "dependency_lock_raw_sha256": dependency_lock.raw_sha256,
            "python": python_identity(),
            "dependencies": dependency_lock.dependency_dicts(),
            "source_bindings": source_bindings,
            "entries": entries,
            "tree_content_sha256": tree_content_sha256(entries),
            "authority": false_authority(),
        }
        _write_file(
            package_root / "bundle-manifest.json",
            canonical_json_line(manifest),
            0o444,
        )
        return manifest
    except Exception:
        if package_root.exists():
            _remove_private_tree(package_root)
        raise
