"""Build one offline M2 Research release from exact committed source blobs."""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import sha256
from .errors import RegistryError
from .m2_python_runtime import (
    load_python_runtime_manifest,
    verify_python_runtime,
    verify_runtime_execution,
)
from .m2_release_contracts import (
    BUNDLE_SCHEMA,
    COMMIT_PATTERN,
    REQUIRED_ENTRYPOINTS,
    REQUIREMENTS_RAW_SHA256,
    regular_bytes,
    release_launcher,
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
    modules = {
        "backup-signer": "research_warehouse.m2_backup_signer_cli",
        "evidence-capture": "research_warehouse.m2_evidence_capture_cli",
        "genesis-publisher": "research_warehouse.m2_genesis_predecessor_cli",
        "manifest-signer": "research_warehouse.m2_manifest_signer_cli",
        "monitor": "research_warehouse.m2_monitor_cli",
        "operator-state": "research_warehouse.m2_operator_state_cli",
        "rebuild": "research_warehouse.m2_rebuild_cli",
        "warehouse": "research_warehouse.m2_scheduler_cli",
    }
    try:
        module = modules[role]
    except KeyError as exc:
        raise RegistryError("M2 release bootstrap role is invalid") from exc
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
    python_runtime: Path,
    python_runtime_manifest_path: Path,
    expected_python_runtime_manifest_raw_sha256: str,
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
    runtime_manifest, runtime_manifest_sha = load_python_runtime_manifest(
        python_runtime_manifest_path,
        expected_raw_sha256=expected_python_runtime_manifest_raw_sha256,
    )
    verify_python_runtime(python_runtime, runtime_manifest)
    if output_root.exists():
        raise RegistryError("M2 release output already exists")
    output_root.mkdir(parents=False, mode=0o700)
    try:
        vendor = output_root / "vendor"
        app = output_root / "app"
        bin_dir = output_root / "bin"
        metadata = output_root / "metadata"
        runtime = output_root / "runtime"
        vendor.mkdir()
        app.mkdir()
        bin_dir.mkdir()
        metadata.mkdir()
        (metadata / "source-commit-sha").write_text(
            f"{source_commit_sha}\n",
            encoding="ascii",
        )
        (metadata / "runtime-requirements-v1.txt").write_bytes(
            requirements_raw
        )
        shutil.copytree(
            python_runtime,
            runtime,
            symlinks=True,
            copy_function=shutil.copy,
        )
        shutil.copyfile(
            python_runtime_manifest_path,
            output_root / "python-runtime-manifest.json",
        )
        _normalize_tree(runtime)
        verify_python_runtime(runtime, runtime_manifest)
        python_path = verify_runtime_execution(runtime)
        completed = subprocess.run(
            [
                str(python_path),
                "-B",
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
        roles = {
            "backup-signer": "research-warehouse-backup-signer",
            "evidence-capture": "research-warehouse-evidence-capture",
            "genesis-publisher": "research-warehouse-genesis-publisher",
            "manifest-signer": "research-warehouse-manifest-signer",
            "monitor": "research-warehouse-monitor",
            "operator-state": "research-warehouse-operator-state",
            "rebuild": "research-warehouse-rebuild",
            "warehouse": "research-warehouse-job",
        }
        bootstraps = []
        for role, executable in roles.items():
            bootstrap = app / f"{executable.replace('-', '_')}.py"
            bootstrap.write_bytes(_bootstrap(role))
            (bin_dir / executable).write_bytes(release_launcher(role))
            bootstraps.append(bootstrap)
        for entrypoint in REQUIRED_ENTRYPOINTS:
            (output_root / entrypoint).chmod(0o755)
        _normalize_tree(output_root)
        for bootstrap in bootstraps:
            check = subprocess.run(
                [str(python_path), "-B", "-I", str(bootstrap), "--help"],
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
            "python_runtime_manifest_raw_sha256": runtime_manifest_sha,
            "python_runtime_tree_content_sha256": runtime_manifest[
                "tree_content_sha256"
            ],
            "entries": entries,
            "tree_content_sha256": tree_content_sha256(entries),
        }
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
