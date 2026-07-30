from __future__ import annotations

# ruff: noqa: E402

import ast
import json
import os
import stat
import subprocess
import sys
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import (
    m2_release_builder as builder_module,
    m2_release_bundle_contracts as contracts,
    m2_release_installer as installer_module,
)
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_release_builder import (
    CommitSource,
    _extract_wheel,
    build_release_package,
    load_commit_source_snapshot,
)
from research_warehouse.m2_release_bundle_contracts import (
    DependencyBinding,
    DependencyLock,
    load_dependency_lock,
    scan_content_tree,
    tree_content_sha256,
)
from research_warehouse.m2_release_entry import (
    _import_from_release,
    self_check_release,
)
from research_warehouse.m2_release_installer import (
    install_release_package,
    rollback_release,
    verify_release_package,
)

LOCK_PATH = (
    ROOT / "deployments/research-warehouse/m2/release-dependency-lock-v1.json"
)
SOURCE_COMMIT = "1" * 40
DEPENDENCY_VERSIONS = {
    "cffi": "2.0.0",
    "cryptography": "48.0.0",
    "duckdb": "1.5.5",
    "pycparser": "2.23",
}


def _thaw_tree(root: Path) -> None:
    if not root.exists():
        return
    try:
        root.chmod(0o700)
    except OSError:
        pass
    for directory, names, _files in os.walk(root, topdown=True):
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


@pytest.fixture(autouse=True)
def thaw_tmp_tree(tmp_path: Path) -> Iterator[None]:
    yield
    _thaw_tree(tmp_path)


def _wheel(
    path: Path,
    *,
    name: str,
    version: str,
    extra_members: dict[str, bytes] | None = None,
    symlink_member: str | None = None,
) -> DependencyBinding:
    normalized = name.replace("-", "_")
    metadata_dir = f"{normalized}-{version}.dist-info"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            f"{metadata_dir}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        archive.writestr(f"{normalized}/__init__.py", b"")
        for member, raw in sorted((extra_members or {}).items()):
            archive.writestr(member, raw)
        if symlink_member is not None:
            info = zipfile.ZipInfo(symlink_member)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
    raw = path.read_bytes()
    return DependencyBinding(
        name=name,
        version=version,
        wheel_filename=path.name,
        wheel_sha256=sha256(raw),
        size_bytes=len(raw),
    )


@pytest.fixture
def synthetic_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, DependencyLock]:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    dependencies = tuple(
        _wheel(
            wheelhouse / f"{name}-{version}-py3-none-any.whl",
            name=name,
            version=version,
        )
        for name, version in sorted(DEPENDENCY_VERSIONS.items())
    )
    lock = DependencyLock(
        raw_sha256="a" * 64,
        dependencies=dependencies,
    )
    monkeypatch.setattr(
        contracts,
        "FROZEN_DEPENDENCIES",
        tuple(item.as_dict() for item in dependencies),
    )
    monkeypatch.setattr(
        contracts,
        "FROZEN_DEPENDENCY_LOCK_SHA256",
        lock.raw_sha256,
    )
    monkeypatch.setattr(
        builder_module,
        "require_clean_source_commit",
        lambda _source_root: SOURCE_COMMIT,
    )
    monkeypatch.setattr(
        builder_module,
        "load_commit_source_snapshot",
        lambda source_root, _commit: tuple(
            CommitSource(
                repo_path=path.relative_to(source_root).as_posix(),
                raw=path.read_bytes(),
                workspace_path=path,
            )
            for path in sorted(
                (source_root / "scripts/research_warehouse").glob("*.py")
            )
        ),
    )
    return wheelhouse, lock


@pytest.fixture
def bundle_factory(
    tmp_path: Path,
    synthetic_lock: tuple[Path, DependencyLock],
) -> Callable[[str], Path]:
    wheelhouse, lock = synthetic_lock

    def build(release_id: str) -> Path:
        package_root = tmp_path / f"package-{release_id}"
        build_release_package(
            source_root=ROOT,
            package_root=package_root,
            wheelhouse=wheelhouse,
            dependency_lock=lock,
            release_id=release_id,
            source_commit_sha=SOURCE_COMMIT,
        )
        return package_root

    return build


def _install_paths(tmp_path: Path) -> dict[str, Path | int]:
    root = tmp_path / "install"
    root.mkdir()
    os.chown(root, os.geteuid(), os.getegid())
    root.chmod(0o755)
    lock_path = tmp_path / "release.lock"
    lock_path.write_bytes(b"")
    os.chown(lock_path, os.geteuid(), os.getegid())
    lock_path.chmod(0o444)
    return {
        "active_root": root / "release",
        "rollback_root": tmp_path / "rollbacks",
        "release_lock_path": lock_path,
        "expected_owner_uid": os.geteuid(),
        "expected_owner_gid": os.getegid(),
    }


def _install(
    *,
    package_root: Path,
    paths: dict[str, Path | int],
    installed_manifest_path: Path,
    hook: Callable[[str], None] | None = None,
    preflight_runner: Callable[[Path], None] | None = None,
) -> dict:
    if preflight_runner is None:
        preflight_runner = lambda _stage_root: None
    return install_release_package(
        package_root=package_root,
        active_root=paths["active_root"],
        rollback_root=paths["rollback_root"],
        release_lock_path=paths["release_lock_path"],
        installed_manifest_path=installed_manifest_path,
        expected_owner_uid=paths["expected_owner_uid"],
        expected_owner_gid=paths["expected_owner_gid"],
        hook=hook,
        preflight_runner=preflight_runner,
    )


def test_committed_dependency_lock_is_exact_and_frozen() -> None:
    value = load_dependency_lock(
        LOCK_PATH,
        expected_raw_sha256=contracts.FROZEN_DEPENDENCY_LOCK_SHA256,
    )
    assert value.dependency_dicts() == list(contracts.FROZEN_DEPENDENCIES)
    assert value.raw_sha256 == contracts.FROZEN_DEPENDENCY_LOCK_SHA256


def test_source_commit_binding_requires_exact_clean_checkout(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        ["git", "config", "user.name", "M2 Test"],
        cwd=source,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "m2-test@example.invalid"],
        cwd=source,
        check=True,
    )
    tracked = source / "tracked.txt"
    tracked.write_text("frozen\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "frozen"], cwd=source, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert builder_module.require_clean_source_commit(source) == commit
    (source / "untracked.txt").write_text("drift\n")
    with pytest.raises(RegistryError, match="must be clean"):
        builder_module.require_clean_source_commit(source)


def _git_source_repo(tmp_path: Path) -> tuple[Path, str, Path]:
    source = tmp_path / "git-source"
    package = source / "scripts/research_warehouse"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    module = package / "registry.py"
    module.write_text("FROZEN = True\n")
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        ["git", "config", "user.name", "M2 Test"],
        cwd=source,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "m2-test@example.invalid"],
        cwd=source,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "frozen"], cwd=source, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return source, commit, module


def test_source_snapshot_rejects_ignored_python_extra(
    tmp_path: Path,
) -> None:
    source, commit, _module = _git_source_repo(tmp_path)
    exclude = source / ".git/info/exclude"
    exclude.write_text(
        exclude.read_text() + "\nscripts/research_warehouse/ignored.py\n"
    )
    (source / "scripts/research_warehouse/ignored.py").write_text(
        "ESCAPE = True\n"
    )
    assert builder_module.require_clean_source_commit(source) == commit
    with pytest.raises(RegistryError, match="source set differs"):
        load_commit_source_snapshot(source, commit)


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_source_snapshot_rejects_index_hidden_drift(
    tmp_path: Path,
    index_flag: str,
) -> None:
    source, commit, module = _git_source_repo(tmp_path)
    relative = module.relative_to(source).as_posix()
    subprocess.run(
        ["git", "update-index", index_flag, relative],
        cwd=source,
        check=True,
    )
    module.write_text("FROZEN = False\n")
    assert builder_module.require_clean_source_commit(source) == commit
    with pytest.raises(RegistryError, match="differs from commit"):
        load_commit_source_snapshot(source, commit)


def test_source_bindings_are_reconstructible_from_declared_commit(
    tmp_path: Path,
) -> None:
    source, commit, _module = _git_source_repo(tmp_path)
    snapshot = load_commit_source_snapshot(source, commit)
    assert snapshot
    for item in snapshot:
        committed_raw = subprocess.run(
            ["git", "cat-file", "blob", f"{commit}:{item.repo_path}"],
            cwd=source,
            check=True,
            capture_output=True,
        ).stdout
        assert item.raw == committed_raw
        assert sha256(item.raw) == sha256(committed_raw)


def test_build_is_deterministic_and_entrypoints_are_real(
    bundle_factory: Callable[[str], Path],
) -> None:
    first = bundle_factory("release-a001")
    first_manifest = verify_release_package(first)
    first.rename(first.with_name("saved-release-a001"))
    second = bundle_factory("release-a001")
    second_manifest = verify_release_package(second)
    assert first_manifest == second_manifest
    assert first_manifest["source_commit_sha"] == SOURCE_COMMIT
    assert first_manifest["authority"] == contracts.false_authority()
    for name in ("research-warehouse-job", "research-warehouse-monitor"):
        raw = (second / "release/bin" / name).read_text()
        assert "-I -S -s -E" in raw
        assert "self-check" in raw
        assert "exit 0" not in raw
    entry_source = (
        second
        / "release/lib/research_warehouse/m2_release_entry.py"
    ).read_text()
    assert "ROLE_IMPORTS" in entry_source
    libexec_entry = second / "release/libexec/m2_release_entry.py"
    assert stat.S_IMODE(libexec_entry.stat().st_mode) == 0o444
    assert not libexec_entry.read_bytes().startswith(b"#!")


def test_no_site_startup_and_non_executable_libexec_block_early_code(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
) -> None:
    user_base = tmp_path / "userbase"
    startup = user_base / (
        f"lib/python{sys.version_info.major}.{sys.version_info.minor}"
        "/site-packages"
    )
    startup.mkdir(parents=True)
    sentinel = tmp_path / "startup-ran"
    (startup / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')\n"
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-s",
            "-E",
            "-B",
            "-c",
            "import sys; assert sys.flags.no_site == 1",
        ],
        env={**os.environ, "PYTHONUSERBASE": str(user_base)},
        check=False,
    )
    assert completed.returncode == 0
    assert not sentinel.exists()

    entry = (
        bundle_factory("release-no-direct")
        / "release/libexec/m2_release_entry.py"
    )
    with pytest.raises(PermissionError):
        subprocess.run(
            [str(entry)],
            env={**os.environ, "PYTHONUSERBASE": str(user_base)},
            check=False,
        )
    assert not sentinel.exists()


def test_build_rejects_source_commit_mismatch_without_partial_output(
    tmp_path: Path,
    synthetic_lock: tuple[Path, DependencyLock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheelhouse, lock = synthetic_lock
    output = tmp_path / "partial"
    monkeypatch.setattr(
        builder_module,
        "require_clean_source_commit",
        lambda _source_root: "2" * 40,
    )
    with pytest.raises(RegistryError, match="does not match checkout"):
        build_release_package(
            source_root=ROOT,
            package_root=output,
            wheelhouse=wheelhouse,
            dependency_lock=lock,
            release_id="release-a002",
            source_commit_sha=SOURCE_COMMIT,
        )
    assert not output.exists()


def test_build_rejects_programmatic_dependency_lock_substitution(
    tmp_path: Path,
    synthetic_lock: tuple[Path, DependencyLock],
) -> None:
    wheelhouse, lock = synthetic_lock
    output = tmp_path / "substituted-lock"
    with pytest.raises(RegistryError, match="lock binding mismatch"):
        build_release_package(
            source_root=ROOT,
            package_root=output,
            wheelhouse=wheelhouse,
            dependency_lock=DependencyLock(
                raw_sha256="b" * 64,
                dependencies=lock.dependencies,
            ),
            release_id="release-a011",
            source_commit_sha=SOURCE_COMMIT,
        )
    assert not output.exists()


@pytest.mark.parametrize("failure", ["missing", "tampered"])
def test_build_rejects_missing_or_tampered_wheel_and_cleans_partial_output(
    tmp_path: Path,
    synthetic_lock: tuple[Path, DependencyLock],
    failure: str,
) -> None:
    wheelhouse, lock = synthetic_lock
    wheel = wheelhouse / lock.dependencies[0].wheel_filename
    if failure == "missing":
        wheel.unlink()
    else:
        wheel.chmod(0o600)
        wheel.write_bytes(wheel.read_bytes() + b"tampered")
    output = tmp_path / f"partial-{failure}"
    with pytest.raises((RegistryError, OSError)):
        build_release_package(
            source_root=ROOT,
            package_root=output,
            wheelhouse=wheelhouse,
            dependency_lock=lock,
            release_id=f"release-{failure}",
            source_commit_sha=SOURCE_COMMIT,
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("extra_members", "symlink_member", "message"),
    [
        ({"../../escape.py": b""}, None, "unsafe path"),
        ({"startup.pth": b"import os\n"}, None, "startup injection"),
        ({}, "package/link.py", "symlink"),
        ({"vnpy/__init__.py": b""}, None, "forbidden import root"),
        (
            {"research_warehouse/__init__.py": b""},
            None,
            "forbidden import root",
        ),
    ],
)
def test_wheel_extraction_rejects_injection_and_symlinks(
    tmp_path: Path,
    extra_members: dict[str, bytes],
    symlink_member: str | None,
    message: str,
) -> None:
    wheel_path = tmp_path / "unsafe-1.0-py3-none-any.whl"
    dependency = _wheel(
        wheel_path,
        name="unsafe",
        version="1.0",
        extra_members=extra_members,
        symlink_member=symlink_member,
    )
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    with pytest.raises(RegistryError, match=message):
        _extract_wheel(
            wheel_path,
            dependency=dependency,
            site_packages=site_packages,
            claimed_paths=set(),
        )


def test_package_verification_rejects_tamper_symlink_and_mode(
    bundle_factory: Callable[[str], Path],
) -> None:
    package_root = bundle_factory("release-a003")
    target = package_root / "release/bin/research-warehouse-job"
    target.chmod(0o755)
    with pytest.raises(RegistryError, match="does not match manifest"):
        verify_release_package(package_root)

    target.chmod(0o555)
    target.parent.chmod(0o755)
    target.unlink()
    target.symlink_to("research-warehouse-monitor")
    target.parent.chmod(0o555)
    with pytest.raises(RegistryError, match="symlink is forbidden"):
        verify_release_package(package_root)


def test_package_verification_cross_checks_runtime_and_bundle_identity(
    bundle_factory: Callable[[str], Path],
) -> None:
    package_root = bundle_factory("release-a012")
    release_root = package_root / "release"
    runtime_path = release_root / "meta/release-runtime.json"
    runtime = json.loads(runtime_path.read_text())
    runtime["release_id"] = "release-a013"
    runtime_path.parent.chmod(0o755)
    runtime_path.chmod(0o600)
    runtime_raw = canonical_json_line(runtime)
    runtime_path.write_bytes(runtime_raw)
    runtime_path.chmod(0o444)
    runtime_path.parent.chmod(0o555)

    manifest_path = package_root / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["entries"]:
        if entry["relative_path"] == "meta/release-runtime.json":
            entry["size_bytes"] = len(runtime_raw)
            entry["raw_sha256"] = sha256(runtime_raw)
    manifest["tree_content_sha256"] = tree_content_sha256(
        manifest["entries"]
    )
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(canonical_json_line(manifest))
    manifest_path.chmod(0o444)

    with pytest.raises(RegistryError, match="runtime/bundle identity mismatch"):
        verify_release_package(package_root)


def test_owner_and_mode_custody_are_fail_closed(
    bundle_factory: Callable[[str], Path],
) -> None:
    package_root = bundle_factory("release-a004")
    release_root = package_root / "release"
    with pytest.raises(RegistryError, match="owner UID mismatch"):
        scan_content_tree(
            release_root,
            expected_owner_uid=os.geteuid() + 1,
            expected_owner_gid=os.getegid(),
        )
    release_root.chmod(0o757)
    with pytest.raises(RegistryError, match="root custody mismatch"):
        verify_release_package(package_root)


def test_import_origin_must_remain_inside_release(
    bundle_factory: Callable[[str], Path],
) -> None:
    release_root = bundle_factory("release-a014") / "release"
    with pytest.raises(RegistryError, match="escaped frozen tree"):
        _import_from_release("json", release_root / "lib")


def test_runtime_self_check_rejects_tree_drift_and_forbidden_environment(
    bundle_factory: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = bundle_factory("release-a005")
    release_root = package_root / "release"
    result = self_check_release(
        release_root=release_root,
        role="warehouse",
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_interpreter=False,
        import_modules=False,
    )
    assert result["status"] == (
        "RELEASE_SELF_CHECK_PASSED_NO_SCHEDULE_AUTHORITY"
    )
    monkeypatch.setenv("WEB_TRADE_ENABLED", "1")
    with pytest.raises(RegistryError, match="forbidden environment"):
        self_check_release(
            release_root=release_root,
            role="warehouse",
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
            enforce_interpreter=False,
            import_modules=False,
        )


def test_installer_preflight_uses_fixed_isolated_interpreter_for_both_roles(
    bundle_factory: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_root = bundle_factory("release-preflight") / "release"
    calls: list[tuple[list[str], dict]] = []

    def completed(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        role = command[-2]
        calls.append((command, dict(kwargs)))
        output = canonical_json_line(
            {
                "status": "RELEASE_SELF_CHECK_PASSED_NO_SCHEDULE_AUTHORITY",
                "role": role,
                "release_id": "release-preflight",
                "authority": contracts.false_authority(),
            }
        )
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

    monkeypatch.setattr(installer_module.subprocess, "run", completed)
    installer_module._run_stage_preflight(release_root)
    assert [command[-2] for command, _kwargs in calls] == [
        "warehouse",
        "monitor",
    ]
    for command, kwargs in calls:
        assert command[:5] == [
            contracts.PYTHON_EXECUTABLE,
            "-I",
            "-S",
            "-s",
            "-E",
        ]
        assert command[5] == "-B"
        assert kwargs["cwd"] == "/"
        assert not {
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONUSERBASE",
        } & set(kwargs["env"])


@pytest.mark.parametrize(
    "preflight_failure",
    ["wrong interpreter", "native import", "role import escape"],
)
def test_preflight_failure_keeps_previous_current_unchanged(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
    preflight_failure: str,
) -> None:
    first = bundle_factory(f"release-old-{preflight_failure.split()[0]}")
    second = bundle_factory(f"release-new-{preflight_failure.split()[0]}")
    paths = _install_paths(tmp_path)
    _install(
        package_root=first,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-old.json",
    )

    def fail_preflight(_stage_root: Path) -> None:
        raise RegistryError(preflight_failure)

    failed_manifest = tmp_path / "installed-new.json"
    with pytest.raises(RegistryError, match=preflight_failure):
        _install(
            package_root=second,
            paths=paths,
            installed_manifest_path=failed_manifest,
            preflight_runner=fail_preflight,
        )
    assert _active_release_id_for_test(paths) == first.name.removeprefix(
        "package-"
    )
    assert not failed_manifest.exists()
    assert not list((tmp_path / "install").glob(".release.stage.*"))


def _active_release_id_for_test(paths: dict[str, Path | int]) -> str:
    return self_check_release(
        release_root=paths["active_root"],
        role="warehouse",
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_interpreter=False,
        import_modules=False,
    )["release_id"]


def test_initial_install_failure_leaves_no_current_or_partial_state(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
) -> None:
    package_root = bundle_factory("release-a006")
    paths = _install_paths(tmp_path)
    installed_manifest = tmp_path / "installed-a006.json"

    def fail_after_verification(event: str) -> None:
        if event == "after_stage_verified":
            raise RuntimeError("injected")

    with pytest.raises(RuntimeError, match="injected"):
        _install(
            package_root=package_root,
            paths=paths,
            installed_manifest_path=installed_manifest,
            hook=fail_after_verification,
        )
    assert not paths["active_root"].exists()
    assert not installed_manifest.exists()
    assert not list((tmp_path / "install").glob(".release.stage.*"))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
@pytest.mark.parametrize(
    "crash_event",
    [
        "after_transaction_prepared",
        "after_pending_manifest",
        "after_switch",
        "after_old_release_move",
        "before_parent_fsync",
        "after_parent_fsync",
    ],
)
def test_interrupted_upgrade_is_recovered_by_next_install(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
    crash_event: str,
) -> None:
    first = bundle_factory(f"release-crash-old-{crash_event}")
    second = bundle_factory(f"release-crash-new-{crash_event}")
    paths = _install_paths(tmp_path)
    _install(
        package_root=first,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-crash-old.json",
    )
    installed_manifest = tmp_path / "installed-crash-new.json"

    child = os.fork()
    if child == 0:
        def crash(event: str) -> None:
            if event == crash_event:
                os._exit(73)

        try:
            _install(
                package_root=second,
                paths=paths,
                installed_manifest_path=installed_manifest,
                hook=crash,
            )
        except BaseException:
            os._exit(74)
        os._exit(0)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 73
    assert not installed_manifest.exists()

    result = _install(
        package_root=second,
        paths=paths,
        installed_manifest_path=installed_manifest,
    )
    expected_id = second.name.removeprefix("package-")
    assert result["release_id"] == expected_id
    assert _active_release_id_for_test(paths) == expected_id
    assert installed_manifest.exists()
    assert not (tmp_path / "install/.release-install-transaction.json").exists()
    assert not list((tmp_path / "install").glob(".release.stage.*"))
    assert not list(tmp_path.glob(".*.pending.*"))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
@pytest.mark.parametrize(
    "crash_event",
    [
        "after_transaction_switched",
        "after_manifest_publish_before_fsync",
    ],
)
def test_switched_transaction_is_committed_before_next_install(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
    crash_event: str,
) -> None:
    first = bundle_factory("release-journal-old")
    second = bundle_factory("release-journal-middle")
    third = bundle_factory("release-journal-new")
    paths = _install_paths(tmp_path)
    _install(
        package_root=first,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-journal-old.json",
    )
    middle_manifest = tmp_path / "installed-journal-middle.json"

    child = os.fork()
    if child == 0:
        def crash(event: str) -> None:
            if event == crash_event:
                os._exit(75)

        try:
            _install(
                package_root=second,
                paths=paths,
                installed_manifest_path=middle_manifest,
                hook=crash,
            )
        except BaseException:
            os._exit(76)
        os._exit(0)
    _waited, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 75

    newest_manifest = tmp_path / "installed-journal-new.json"
    result = _install(
        package_root=third,
        paths=paths,
        installed_manifest_path=newest_manifest,
    )
    assert middle_manifest.exists()
    assert newest_manifest.exists()
    assert result["release_id"] == "release-journal-new"
    assert _active_release_id_for_test(paths) == "release-journal-new"


def test_install_manifest_destination_cannot_overlap_release_custody(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
) -> None:
    package_root = bundle_factory("release-a015")
    paths = _install_paths(tmp_path)
    with pytest.raises(RegistryError, match="overlaps release custody"):
        _install(
            package_root=package_root,
            paths=paths,
            installed_manifest_path=package_root / "installed.json",
        )
    assert not paths["active_root"].exists()


def test_upgrade_failure_after_switch_restores_previous_release(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
) -> None:
    first = bundle_factory("release-a007")
    second = bundle_factory("release-a008")
    paths = _install_paths(tmp_path)
    _install(
        package_root=first,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-a007.json",
    )

    def fail_after_switch(event: str) -> None:
        if event == "after_switch":
            raise RuntimeError("injected switch failure")

    failed_manifest = tmp_path / "installed-a008.json"
    with pytest.raises(RuntimeError, match="injected switch failure"):
        _install(
            package_root=second,
            paths=paths,
            installed_manifest_path=failed_manifest,
            hook=fail_after_switch,
        )
    result = self_check_release(
        release_root=paths["active_root"],
        role="warehouse",
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_interpreter=False,
        import_modules=False,
    )
    assert result["release_id"] == "release-a007"
    assert not failed_manifest.exists()
    assert not list((tmp_path / "install").glob(".release.stage.*"))


def test_explicit_rollback_failure_restores_preoperation_release(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
) -> None:
    first = bundle_factory("release-a016")
    second = bundle_factory("release-a017")
    paths = _install_paths(tmp_path)
    _install(
        package_root=first,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-a016.json",
    )
    upgraded = _install(
        package_root=second,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-a017.json",
    )
    candidate = Path(upgraded["rollback_release"])

    def fail_after_switch(event: str) -> None:
        if event == "after_switch":
            raise RuntimeError("injected rollback failure")

    with pytest.raises(RuntimeError, match="injected rollback failure"):
        rollback_release(
            active_root=paths["active_root"],
            rollback_root=paths["rollback_root"],
            rollback_candidate=candidate,
            release_lock_path=paths["release_lock_path"],
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
            hook=fail_after_switch,
        )
    assert self_check_release(
        release_root=paths["active_root"],
        role="warehouse",
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_interpreter=False,
        import_modules=False,
    )["release_id"] == "release-a017"
    assert self_check_release(
        release_root=candidate,
        role="warehouse",
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_interpreter=False,
        import_modules=False,
    )["release_id"] == "release-a016"


def test_upgrade_and_explicit_rollback_are_atomic(
    tmp_path: Path,
    bundle_factory: Callable[[str], Path],
) -> None:
    first = bundle_factory("release-a009")
    second = bundle_factory("release-a010")
    paths = _install_paths(tmp_path)
    _install(
        package_root=first,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-a009.json",
    )
    upgraded = _install(
        package_root=second,
        paths=paths,
        installed_manifest_path=tmp_path / "installed-a010.json",
    )
    candidate = Path(upgraded["rollback_release"])
    assert candidate.name == "release-a009"
    result = rollback_release(
        active_root=paths["active_root"],
        rollback_root=paths["rollback_root"],
        rollback_candidate=candidate,
        release_lock_path=paths["release_lock_path"],
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
    )
    assert result["active_release_id"] == "release-a009"
    assert result["rollback_release_id"] == "release-a010"
    assert self_check_release(
        release_root=paths["active_root"],
        role="monitor",
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        enforce_interpreter=False,
        import_modules=False,
    )["release_id"] == "release-a009"


def test_release_modules_remain_outside_execution_plane() -> None:
    forbidden = {"backend", "psycopg", "questdb", "vnpy", "zmq"}
    for name in (
        "m2_release_builder.py",
        "m2_release_bundle_contracts.py",
        "m2_release_cli.py",
        "m2_release_entry.py",
        "m2_release_installer.py",
    ):
        tree = ast.parse(
            (ROOT / "scripts/research_warehouse" / name).read_text()
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden)
    payload = json.loads(LOCK_PATH.read_text())
    assert not any(payload["authority"].values())
