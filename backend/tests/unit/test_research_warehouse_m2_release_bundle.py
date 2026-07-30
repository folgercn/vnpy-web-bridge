from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from research_warehouse import (
    m2_monitor_cli,
    m2_python_runtime,
    m2_release_install,
)
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_python_runtime import (
    create_python_runtime_manifest,
)
from research_warehouse.m2_python_runtime_archive import prepare_python_runtime
from research_warehouse.m2_release_builder import build_release_bundle
from research_warehouse.m2_release_contracts import (
    REQUIREMENTS_RAW_SHA256,
    verify_release_bundle,
)
from research_warehouse.m2_release_install import install_release_bundle
from research_warehouse.m2_wheelhouse import (
    create_wheelhouse_manifest,
    load_wheelhouse_manifest,
    verify_wheelhouse,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
REQUIREMENTS = (
    REPO_ROOT
    / "deployments/research-warehouse/m2/runtime-requirements-v1.txt"
)
POLICY = (
    REPO_ROOT / "deployments/research-warehouse/m2/isolation-policy-v1.json"
)


def write_manifest(path: Path, value: dict) -> str:
    raw = canonical_json_line(value)
    path.write_bytes(raw)
    path.chmod(0o600)
    return sha256(raw)


def fake_wheelhouse(tmp_path: Path) -> tuple[Path, Path, str]:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "example-1.0-py3-none-any.whl").write_bytes(b"wheel")
    manifest = create_wheelhouse_manifest(wheelhouse)
    manifest_path = tmp_path / "wheelhouse-manifest.json"
    digest = write_manifest(manifest_path, manifest)
    return wheelhouse, manifest_path, digest


def fake_python_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, str]:
    runtime = tmp_path / "python-runtime"
    bin_dir = runtime / "bin"
    stdlib = runtime / "lib/python3.12"
    bin_dir.mkdir(parents=True)
    stdlib.mkdir(parents=True)
    runtime.chmod(0o755)
    bin_dir.chmod(0o755)
    stdlib.parent.chmod(0o755)
    stdlib.chmod(0o755)
    executable = bin_dir / "python3.12"
    executable.write_bytes(b"fake private Python 3.12\n")
    executable.chmod(0o555)
    entries = m2_python_runtime.snapshot_python_runtime(runtime)
    tree_digest = m2_python_runtime.runtime_content_sha256(entries)
    manifest = {
        "schema_version": m2_python_runtime.RUNTIME_SCHEMA,
        "python_version": m2_python_runtime.PYTHON_RUNTIME_VERSION,
        "source_archive_raw_sha256": (
            m2_python_runtime.PYTHON_RUNTIME_SOURCE_ARCHIVE_SHA256
        ),
        "entries": entries,
        "tree_content_sha256": tree_digest,
    }
    approved_manifest_digest = sha256(canonical_json_line(manifest))
    monkeypatch.setattr(
        m2_python_runtime,
        "PYTHON_RUNTIME_TREE_CONTENT_SHA256",
        tree_digest,
    )
    monkeypatch.setattr(
        m2_python_runtime,
        "PYTHON_RUNTIME_MANIFEST_RAW_SHA256",
        approved_manifest_digest,
    )
    manifest_path = tmp_path / "python-runtime-manifest.json"
    digest = write_manifest(manifest_path, manifest)
    return runtime, manifest_path, digest


def fake_subprocess(monkeypatch: pytest.MonkeyPatch, *, pip_status: int = 0) -> None:
    def run(args, **_kwargs):
        if args[0] == "git" and args[-2:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(args, 0, "1" * 40 + "\n", "")
        if args[0] == "git" and "status" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "git" and "ls-tree" in args:
            return subprocess.CompletedProcess(
                args,
                0,
                (
                    b"100644 blob "
                    + b"2" * 40
                    + b"\tscripts/research_warehouse/__init__.py\0"
                    + b"100644 blob "
                    + b"3" * 40
                    + b"\tscripts/research_warehouse/errors.py\0"
                ),
                b"",
            )
        if args[0] == "git" and "cat-file" in args:
            return subprocess.CompletedProcess(args, 0, b"source = True\n", b"")
        if "-c" in args:
            runtime_root = Path(args[0]).parent.parent.resolve()
            facts = {
                "prefix": str(runtime_root),
                "stdlib": str(runtime_root / "lib/python3.12"),
                "user_site": False,
                "version": "3.12.13",
            }
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps(facts) + "\n",
                "",
            )
        if "-m" in args and "pip" in args:
            if pip_status == 0:
                target = Path(args[args.index("--target") + 1])
                (target / "example_vendor.py").write_bytes(b"VALUE = 1\n")
            return subprocess.CompletedProcess(args, pip_status, "", "pip failed")
        if "--help" in args:
            return subprocess.CompletedProcess(args, 0, "help\n", "")
        raise AssertionError(args)

    monkeypatch.setattr(
        "research_warehouse.m2_release_builder.subprocess.run",
        run,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_python_runtime.subprocess.run",
        run,
    )


def test_wheelhouse_manifest_is_exact_and_tamper_evident(tmp_path: Path) -> None:
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    manifest, loaded_digest = load_wheelhouse_manifest(
        manifest_path,
        expected_raw_sha256=digest,
    )
    assert loaded_digest == digest
    verify_wheelhouse(wheelhouse, manifest)

    wheel = wheelhouse / "example-1.0-py3-none-any.whl"
    wheel.write_bytes(b"tampered")
    with pytest.raises(RegistryError, match="wheel raw SHA256"):
        verify_wheelhouse(wheelhouse, manifest)

    wheel.write_bytes(b"wheel")
    (wheelhouse / "unexpected-1.0-py3-none-any.whl").write_bytes(b"extra")
    with pytest.raises(RegistryError, match="membership"):
        verify_wheelhouse(wheelhouse, manifest)


def test_wheelhouse_rejects_symlink(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    target = tmp_path / "target.whl"
    target.write_bytes(b"wheel")
    (wheelhouse / "example-1.0-py3-none-any.whl").symlink_to(target)
    with pytest.raises(RegistryError, match="regular non-symlink"):
        create_wheelhouse_manifest(wheelhouse)


def test_python_runtime_rejects_links_and_unpinned_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _manifest_path, _digest = fake_python_runtime(tmp_path, monkeypatch)
    linked = runtime / "linked-python"
    linked.symlink_to(runtime / "bin/python3.12")
    with pytest.raises(RegistryError, match="contains a symlink"):
        create_python_runtime_manifest(runtime)
    linked.unlink()

    hardlink = runtime / "hardlinked-python"
    os.link(runtime / "bin/python3.12", hardlink)
    with pytest.raises(RegistryError, match="exactly one hard link"):
        create_python_runtime_manifest(runtime)
    hardlink.unlink()

    executable = runtime / "bin/python3.12"
    executable.chmod(0o755)
    executable.write_bytes(b"another self-reporting private Python 3.12\n")
    executable.chmod(0o555)
    with pytest.raises(RegistryError, match="approved archive extraction"):
        create_python_runtime_manifest(runtime)

    archive = tmp_path / "runtime.tar.gz"
    archive.write_bytes(b"not the pinned runtime")
    archive.chmod(0o600)
    with pytest.raises(RegistryError, match="source archive SHA256"):
        prepare_python_runtime(archive, tmp_path / "prepared")


def test_build_and_verify_bundle_is_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_subprocess(monkeypatch)
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)
    output = tmp_path / "release"
    manifest = build_release_bundle(
        source_root=REPO_ROOT,
        source_commit_sha="1" * 40,
        requirements_path=REQUIREMENTS,
        wheelhouse=wheelhouse,
        wheelhouse_manifest_path=manifest_path,
        expected_wheelhouse_manifest_raw_sha256=digest,
        python_runtime=runtime,
        python_runtime_manifest_path=runtime_manifest,
        expected_python_runtime_manifest_raw_sha256=runtime_digest,
        output_root=output,
    )
    assert manifest["requirements_raw_sha256"] == REQUIREMENTS_RAW_SHA256
    assert (output / "bin/research-warehouse-job").stat().st_mode & 0o777 == 0o555
    assert (
        output / "bin/research-warehouse-monitor"
    ).stat().st_mode & 0o777 == 0o555
    assert b"research_warehouse.cli" in (
        output / "app/research_warehouse_job.py"
    ).read_bytes()
    assert b"research_warehouse.m2_monitor_cli" in (
        output / "app/research_warehouse_monitor.py"
    ).read_bytes()
    verify_release_bundle(output, manifest)

    target = output / "app/research_warehouse/errors.py"
    target.chmod(0o644)
    target.write_bytes(target.read_bytes() + b"\n")
    target.chmod(0o444)
    with pytest.raises(RegistryError, match="content mismatch"):
        verify_release_bundle(output, manifest)


def test_failed_dependency_install_publishes_no_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_subprocess(monkeypatch, pip_status=1)
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)
    output = tmp_path / "release"
    with pytest.raises(RegistryError, match="dependency installation"):
        build_release_bundle(
            source_root=REPO_ROOT,
            source_commit_sha="1" * 40,
            requirements_path=REQUIREMENTS,
            wheelhouse=wheelhouse,
            wheelhouse_manifest_path=manifest_path,
            expected_wheelhouse_manifest_raw_sha256=digest,
            python_runtime=runtime,
            python_runtime_manifest_path=runtime_manifest,
            expected_python_runtime_manifest_raw_sha256=runtime_digest,
            output_root=output,
        )
    assert not output.exists()


def test_install_switches_under_lock_and_retains_previous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_subprocess(monkeypatch)
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)
    staged = tmp_path / "staged"
    manifest = build_release_bundle(
        source_root=REPO_ROOT,
        source_commit_sha="1" * 40,
        requirements_path=REQUIREMENTS,
        wheelhouse=wheelhouse,
        wheelhouse_manifest_path=manifest_path,
        expected_wheelhouse_manifest_raw_sha256=digest,
        python_runtime=runtime,
        python_runtime_manifest_path=runtime_manifest,
        expected_python_runtime_manifest_raw_sha256=runtime_digest,
        output_root=staged,
    )
    parent = tmp_path / "libexec"
    parent.mkdir(mode=0o755)
    lock = parent / "release.lock"
    lock.write_bytes(b"")
    lock.chmod(0o444)
    release = parent / "release"
    installed_manifest = tmp_path / "installed-tree-manifest.json"
    first = install_release_bundle(
        staged_root=staged,
        manifest=manifest,
        release_root=release,
        lock_path=lock,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_logical_paths=False,
        installed_manifest_output=installed_manifest,
    )
    assert first["previous_retained"] is False
    assert first["installed_tree_manifest_raw_sha256"] == sha256(
        installed_manifest.read_bytes()
    )
    installed_entries = {
        entry["relative_path"]
        for entry in json.loads(installed_manifest.read_text())["entries"]
    }
    assert "runtime/bin/python3.12" in installed_entries
    assert (
        b"/usr/local/libexec/vnpyresearch/release/runtime/bin/python3.12"
        in (release / "bin/research-warehouse-job").read_bytes()
    )
    verify_release_bundle(release, manifest)

    staged_again = tmp_path / "staged-again"
    manifest_again = build_release_bundle(
        source_root=REPO_ROOT,
        source_commit_sha="1" * 40,
        requirements_path=REQUIREMENTS,
        wheelhouse=wheelhouse,
        wheelhouse_manifest_path=manifest_path,
        expected_wheelhouse_manifest_raw_sha256=digest,
        python_runtime=runtime,
        python_runtime_manifest_path=runtime_manifest,
        expected_python_runtime_manifest_raw_sha256=runtime_digest,
        output_root=staged_again,
    )
    second = install_release_bundle(
        staged_root=staged_again,
        manifest=manifest_again,
        release_root=release,
        lock_path=lock,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_logical_paths=False,
        installed_manifest_output=tmp_path / "installed-tree-manifest-2.json",
    )
    assert second["previous_retained"] is True
    verify_release_bundle(release, manifest_again)
    verify_release_bundle(parent / "release.previous", manifest)


def test_install_rolls_back_failed_post_switch_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_subprocess(monkeypatch)
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)
    staged = tmp_path / "staged"
    manifest = build_release_bundle(
        source_root=REPO_ROOT,
        source_commit_sha="1" * 40,
        requirements_path=REQUIREMENTS,
        wheelhouse=wheelhouse,
        wheelhouse_manifest_path=manifest_path,
        expected_wheelhouse_manifest_raw_sha256=digest,
        python_runtime=runtime,
        python_runtime_manifest_path=runtime_manifest,
        expected_python_runtime_manifest_raw_sha256=runtime_digest,
        output_root=staged,
    )
    parent = tmp_path / "libexec"
    parent.mkdir(mode=0o755)
    lock = parent / "release.lock"
    lock.write_bytes(b"")
    lock.chmod(0o444)
    release = parent / "release"
    install_release_bundle(
        staged_root=staged,
        manifest=manifest,
        release_root=release,
        lock_path=lock,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_logical_paths=False,
    )
    old_inode = release.stat().st_ino
    staged_again = tmp_path / "staged-again"
    manifest_again = build_release_bundle(
        source_root=REPO_ROOT,
        source_commit_sha="1" * 40,
        requirements_path=REQUIREMENTS,
        wheelhouse=wheelhouse,
        wheelhouse_manifest_path=manifest_path,
        expected_wheelhouse_manifest_raw_sha256=digest,
        python_runtime=runtime,
        python_runtime_manifest_path=runtime_manifest,
        expected_python_runtime_manifest_raw_sha256=runtime_digest,
        output_root=staged_again,
    )
    original_verify = verify_release_bundle
    calls = 0

    def fail_after_switch(root: Path, value: dict) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RegistryError("forced post-switch failure")
        original_verify(root, value)

    monkeypatch.setattr(
        "research_warehouse.m2_release_install.verify_release_bundle",
        fail_after_switch,
    )
    with pytest.raises(RegistryError, match="forced post-switch"):
        install_release_bundle(
            staged_root=staged_again,
            manifest=manifest_again,
            release_root=release,
            lock_path=lock,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
            enforce_logical_paths=False,
        )
    assert release.stat().st_ino == old_inode
    assert not (parent / "release.previous").exists()
    assert not (parent / "release.candidate").exists()
    original_verify(release, manifest)


def test_installer_rejects_changed_runtime_without_executing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_subprocess(monkeypatch)
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)
    staged = tmp_path / "staged"
    manifest = build_release_bundle(
        source_root=REPO_ROOT,
        source_commit_sha="1" * 40,
        requirements_path=REQUIREMENTS,
        wheelhouse=wheelhouse,
        wheelhouse_manifest_path=manifest_path,
        expected_wheelhouse_manifest_raw_sha256=digest,
        python_runtime=runtime,
        python_runtime_manifest_path=runtime_manifest,
        expected_python_runtime_manifest_raw_sha256=runtime_digest,
        output_root=staged,
    )
    substituted = staged / "runtime/bin/python3.12"
    substituted.chmod(0o755)
    substituted.write_bytes(b"#!/bin/sh\nexit 99\n")
    substituted.chmod(0o555)

    def unexpected_execution(*_args, **_kwargs):
        raise AssertionError("root installer executed the staged runtime")

    monkeypatch.setattr(
        "research_warehouse.m2_python_runtime.subprocess.run",
        unexpected_execution,
    )
    parent = tmp_path / "libexec"
    parent.mkdir(mode=0o755)
    lock = parent / "release.lock"
    lock.write_bytes(b"")
    lock.chmod(0o444)
    with pytest.raises(RegistryError, match="content mismatch"):
        install_release_bundle(
            staged_root=staged,
            manifest=manifest,
            release_root=parent / "release",
            lock_path=lock,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
            enforce_logical_paths=False,
        )


@pytest.mark.parametrize("interrupt", [False, True])
def test_atomic_switch_failure_restores_current_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt: bool,
) -> None:
    fake_subprocess(monkeypatch)
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)

    def build(path: Path) -> dict:
        return build_release_bundle(
            source_root=REPO_ROOT,
            source_commit_sha="1" * 40,
            requirements_path=REQUIREMENTS,
            wheelhouse=wheelhouse,
            wheelhouse_manifest_path=manifest_path,
            expected_wheelhouse_manifest_raw_sha256=digest,
            python_runtime=runtime,
            python_runtime_manifest_path=runtime_manifest,
            expected_python_runtime_manifest_raw_sha256=runtime_digest,
            output_root=path,
        )

    staged = tmp_path / "staged"
    manifest = build(staged)
    parent = tmp_path / "libexec"
    parent.mkdir(mode=0o755)
    lock = parent / "release.lock"
    lock.write_bytes(b"")
    lock.chmod(0o444)
    release = parent / "release"
    install_release_bundle(
        staged_root=staged,
        manifest=manifest,
        release_root=release,
        lock_path=lock,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_logical_paths=False,
    )
    old_inode = release.stat().st_ino
    staged_again = tmp_path / "staged-again"
    manifest_again = build(staged_again)
    original_fsync = m2_release_install._fsync_directory
    injected = False

    def fail_after_old_release_moves(path: Path) -> None:
        nonlocal injected
        if (
            not injected
            and path == parent
            and (parent / "release.candidate").exists()
            and release.exists()
        ):
            injected = True
            if interrupt:
                raise KeyboardInterrupt
            raise RegistryError("forced first parent fsync failure")
        original_fsync(path)

    monkeypatch.setattr(
        "research_warehouse.m2_release_install._fsync_directory",
        fail_after_old_release_moves,
    )
    expected = KeyboardInterrupt if interrupt else RegistryError
    match = None if interrupt else "first parent fsync"
    with pytest.raises(expected, match=match):
        install_release_bundle(
            staged_root=staged_again,
            manifest=manifest_again,
            release_root=release,
            lock_path=lock,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
            enforce_logical_paths=False,
        )
    assert injected is True
    assert release.stat().st_ino == old_inode
    assert not (parent / "release.previous").exists()
    assert not (parent / "release.candidate").exists()
    verify_release_bundle(release, manifest)


def test_interrupted_legacy_transition_recovers_unique_current(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "libexec"
    parent.mkdir(mode=0o755)
    previous = parent / "release.previous"
    previous.mkdir(mode=0o755)
    marker = previous / "old-release"
    marker.write_bytes(b"old")
    marker.chmod(0o444)
    candidate = parent / "release.candidate"
    candidate.mkdir(mode=0o755)
    (candidate / "partial").write_bytes(b"partial")
    release = parent / "release"

    m2_release_install._recover_interrupted_install(
        parent=parent,
        release_root=release,
        candidate=candidate,
        previous=previous,
    )

    assert (release / "old-release").read_bytes() == b"old"
    assert not previous.exists()
    assert not candidate.exists()


def test_runtime_requirements_are_raw_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_subprocess(monkeypatch)
    changed = tmp_path / "requirements.txt"
    changed.write_bytes(REQUIREMENTS.read_bytes() + b"extra==1\n")
    wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    runtime, runtime_manifest, runtime_digest = fake_python_runtime(tmp_path, monkeypatch)
    with pytest.raises(RegistryError, match="requirements raw SHA256"):
        build_release_bundle(
            source_root=REPO_ROOT,
            source_commit_sha="1" * 40,
            requirements_path=changed,
            wheelhouse=wheelhouse,
            wheelhouse_manifest_path=manifest_path,
            expected_wheelhouse_manifest_raw_sha256=digest,
            python_runtime=runtime,
            python_runtime_manifest_path=runtime_manifest,
            expected_python_runtime_manifest_raw_sha256=runtime_digest,
            output_root=tmp_path / "release",
        )


def test_manifest_json_has_no_duplicate_keys(tmp_path: Path) -> None:
    _wheelhouse, manifest_path, digest = fake_wheelhouse(tmp_path)
    value = json.loads(manifest_path.read_text())
    value["wheels"].append(value["wheels"][0])
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_digest = write_manifest(duplicate_path, value)
    with pytest.raises(RegistryError, match="unique and sorted"):
        load_wheelhouse_manifest(
            duplicate_path,
            expected_raw_sha256=duplicate_digest,
        )
    assert digest != duplicate_digest


def test_monitor_cli_returns_operational_status(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monitor_input = {
        "last_success_at": "2026-07-30T01:00:00.000000Z",
        "expected_official_day": "2026-07-29",
        "latest_official_day": "2026-07-29",
        "missing_official_days": [],
        "unreviewed_revision_count": 0,
        "hash_mismatch_count": 0,
        "disk_free_bytes": 100_000_000_000,
        "last_backup_at": "2026-07-30T01:00:00.000000Z",
        "backup_verified": True,
    }
    input_path = tmp_path / "monitor-input.json"
    input_path.write_bytes(canonical_json_line(monitor_input))
    input_path.chmod(0o600)
    args = [
        "--policy",
        str(POLICY),
        "--input",
        str(input_path),
        "--now",
        "2026-07-30T02:00:00.000000Z",
    ]
    assert m2_monitor_cli.main(args) == 0
    healthy = json.loads(capfd.readouterr().out)
    assert healthy["status"] == "HEALTHY"

    monitor_input["disk_free_bytes"] = 1
    input_path.write_bytes(canonical_json_line(monitor_input))
    assert m2_monitor_cli.main(args) == 1
    degraded = json.loads(capfd.readouterr().out)
    assert degraded["status"] == "DEGRADED"
    assert degraded["incidents"] == ["DISK_FREE_LOW"]


def test_release_tree_scan_stays_below_launchd_fd_limit(tmp_path: Path) -> None:
    release = tmp_path / "release"
    bin_dir = release / "bin"
    vendor = release / "vendor"
    bin_dir.mkdir(parents=True)
    vendor.mkdir()
    release.chmod(0o755)
    bin_dir.chmod(0o755)
    vendor.chmod(0o755)
    for name in ("research-warehouse-job", "research-warehouse-monitor"):
        entrypoint = bin_dir / name
        entrypoint.write_bytes(b"#!/bin/sh\nexit 2\n")
        entrypoint.chmod(0o555)
    for index in range(300):
        package = vendor / f"package-{index:03d}"
        package.mkdir()
        package.chmod(0o755)
        dependency = package / "dependency.py"
        dependency.write_bytes(f"VALUE = {index}\n".encode())
        dependency.chmod(0o444)
    script = """
import os
from pathlib import Path
import resource
import sys
sys.path.insert(0, sys.argv[2])
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, hard), hard))
from research_warehouse.m2_release_tree_custody import snapshot_release_tree
snapshot_release_tree(
    Path(sys.argv[1]),
    expected_owner_uid=os.geteuid(),
    expected_owner_gid=os.getegid(),
)
print("FD_BOUNDED")
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(release),
            str(REPO_ROOT / "scripts"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "FD_BOUNDED"
