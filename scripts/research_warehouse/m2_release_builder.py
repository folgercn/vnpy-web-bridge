"""Build one offline M2 Research release from exact committed source blobs."""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import sha256
from .errors import RegistryError
from .m2_release_contracts import (
    BUNDLE_SCHEMA,
    COMMIT_PATTERN,
    LOGICAL_RELEASE_ROOT,
    REQUIRED_ENTRYPOINTS,
    REQUIREMENTS_RAW_SHA256,
    python_facts,
    regular_bytes,
    snapshot_bundle_content,
    tree_content_sha256,
)
from .m2_wheelhouse import load_wheelhouse_manifest, verify_wheelhouse


def _copy_source_tree(
    source_root: Path,
    destination: Path,
    source_commit_sha: str,
) -> None:
    listed = subprocess.run(
        [
            "git",
            "-C",
            str(source_root),
            "ls-tree",
            "-rz",
            "--full-tree",
            source_commit_sha,
            "--",
            "scripts/research_warehouse",
        ],
        check=False,
        capture_output=True,
    )
    if listed.returncode != 0 or not listed.stdout:
        raise RegistryError("cannot enumerate Research source commit")
    paths = []
    for record in listed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise RegistryError("Research source Git tree is malformed") from exc
        prefix = "scripts/research_warehouse/"
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or COMMIT_PATTERN.fullmatch(object_id) is None
            or not path.startswith(prefix)
        ):
            raise RegistryError("Research source Git entry type is forbidden")
        relative = PurePosixPath(path.removeprefix("scripts/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise RegistryError("Research source Git path is unsafe")
        paths.append((relative, object_id, mode))
    if not paths or [item[0].as_posix() for item in paths] != sorted(
        item[0].as_posix() for item in paths
    ):
        raise RegistryError("Research source Git tree is empty or unsorted")
    for relative, object_id, mode in paths:
        blob = subprocess.run(
            ["git", "-C", str(source_root), "cat-file", "blob", object_id],
            check=False,
            capture_output=True,
        )
        if blob.returncode != 0:
            raise RegistryError("cannot read Research source Git blob")
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob.stdout)
        target.chmod(0o755 if mode == "100755" else 0o644)


def _bootstrap(role: str) -> bytes:
    module = (
        "research_warehouse.cli"
        if role == "warehouse"
        else "research_warehouse.m2_monitor_cli"
    )
    return (
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import sys\n"
        "root = Path(__file__).resolve().parent.parent\n"
        "sys.path.insert(0, str(root / 'vendor'))\n"
        "sys.path.insert(0, str(root / 'app'))\n"
        f"from {module} import main\n"
        "raise SystemExit(main())\n"
    ).encode()


def _launcher(python_executable: str, role: str) -> bytes:
    bootstrap = (
        "research_warehouse_job.py"
        if role == "warehouse"
        else "research_warehouse_monitor.py"
    )
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"exec {python_executable} -I "
        f"{LOGICAL_RELEASE_ROOT}/app/{bootstrap} \"$@\"\n"
    ).encode()


def _normalize_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise RegistryError("M2 release bundle contains a symlink")
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            executable = bool(stat.S_IMODE(value.st_mode) & 0o111)
            path.chmod(0o555 if executable else 0o444)
        else:
            raise RegistryError("M2 release bundle entry type is forbidden")
    root.chmod(0o755)


def _verify_source_checkout(source_root: Path, source_commit_sha: str) -> Path:
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise RegistryError("M2 release source checkout is unavailable") from exc
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
    )
    if (
        head.returncode != 0
        or head.stdout.strip() != source_commit_sha
        or status.returncode != 0
        or status.stdout
    ):
        raise RegistryError("M2 release source checkout is not exact clean HEAD")
    return root


def build_release_bundle(
    *,
    source_root: Path,
    source_commit_sha: str,
    requirements_path: Path,
    wheelhouse: Path,
    wheelhouse_manifest_path: Path,
    expected_wheelhouse_manifest_raw_sha256: str,
    python_executable: Path,
    output_root: Path,
) -> dict[str, Any]:
    if COMMIT_PATTERN.fullmatch(source_commit_sha) is None:
        raise RegistryError("M2 release source commit SHA is invalid")
    exact_source_root = _verify_source_checkout(source_root, source_commit_sha)
    requirements_raw = regular_bytes(requirements_path, "M2 runtime requirements")
    if sha256(requirements_raw) != REQUIREMENTS_RAW_SHA256:
        raise RegistryError("M2 runtime requirements raw SHA256 mismatch")
    manifest, manifest_sha = load_wheelhouse_manifest(
        wheelhouse_manifest_path,
        expected_raw_sha256=expected_wheelhouse_manifest_raw_sha256,
    )
    verify_wheelhouse(wheelhouse, manifest)
    python_path, python_sha = python_facts(python_executable)
    if output_root.exists():
        raise RegistryError("M2 release output already exists")
    output_root.mkdir(parents=False, mode=0o700)
    try:
        vendor = output_root / "vendor"
        app = output_root / "app"
        bin_dir = output_root / "bin"
        vendor.mkdir()
        app.mkdir()
        bin_dir.mkdir()
        completed = subprocess.run(
            [
                python_path,
                "-I",
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-deps",
                "--no-compile",
                "--find-links",
                str(wheelhouse.resolve(strict=True)),
                "--requirement",
                str(requirements_path.resolve(strict=True)),
                "--target",
                str(vendor),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RegistryError("offline M2 dependency installation failed")
        _copy_source_tree(exact_source_root, app, source_commit_sha)
        (app / "research_warehouse_job.py").write_bytes(_bootstrap("warehouse"))
        (app / "research_warehouse_monitor.py").write_bytes(_bootstrap("monitor"))
        (bin_dir / "research-warehouse-job").write_bytes(
            _launcher(python_path, "warehouse")
        )
        (bin_dir / "research-warehouse-monitor").write_bytes(
            _launcher(python_path, "monitor")
        )
        for entrypoint in REQUIRED_ENTRYPOINTS:
            (output_root / entrypoint).chmod(0o755)
        _normalize_tree(output_root)
        for bootstrap in (
            app / "research_warehouse_job.py",
            app / "research_warehouse_monitor.py",
        ):
            check = subprocess.run(
                [python_path, "-I", str(bootstrap), "--help"],
                check=False,
                capture_output=True,
                text=True,
            )
            if check.returncode != 0:
                raise RegistryError("M2 release entrypoint import self-check failed")
        entries = snapshot_bundle_content(output_root)
        return {
            "schema_version": BUNDLE_SCHEMA,
            "source_commit_sha": source_commit_sha,
            "requirements_raw_sha256": REQUIREMENTS_RAW_SHA256,
            "wheelhouse_manifest_raw_sha256": manifest_sha,
            "python_executable": python_path,
            "python_executable_raw_sha256": python_sha,
            "entries": entries,
            "tree_content_sha256": tree_content_sha256(entries),
        }
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
