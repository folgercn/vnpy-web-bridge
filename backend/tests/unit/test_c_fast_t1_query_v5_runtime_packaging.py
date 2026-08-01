from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest
from jsonschema import Draft202012Validator

from c_fast_t1.create_query_v5_source_bundle import build_source_bundle
from c_fast_t1.validate_query_v5_runtime import (
    QueryV5PackagingError,
    validate_package,
)
import commodity_c_fast_t1_query_v5_launcher as launcher


ROOT = Path(__file__).resolve().parents[3]
CONTAINERFILE = ROOT / "scripts/c_fast_t1/Containerfile.query-v5"
TEMPLATE = ROOT / "docs/operations/c-fast-t1-query-v5-runtime.template.yml"
COMMIT = "a" * 40


def test_query_v5_packaging_is_valid_but_blocked() -> None:
    report = validate_package(CONTAINERFILE, TEMPLATE)
    assert (
        report["status"] == "QUERY_V5_CODE_ONLY_OVERLAY_PACKAGING_VALID_RUNTIME_BLOCKED"
    )
    assert report["runtime_execution_ready"] is False
    assert report["query_release_v5_implemented"] is False
    assert report["dsn_accessed"] is False
    assert report["query_executed"] is False
    assert report["authority_granted"] is False


def test_query_v5_packaging_rejects_extra_copy(tmp_path: Path) -> None:
    drifted = tmp_path / "Containerfile.query-v5"
    drifted.write_text(
        CONTAINERFILE.read_text(encoding="utf-8")
        + "\nCOPY scripts/commodity_c_fast_t1_query_v4.py ./release/scripts/commodity_c_fast_t1_query_v4.py\n",
        encoding="utf-8",
    )
    with pytest.raises(QueryV5PackagingError):
        validate_package(drifted, TEMPLATE)


def test_query_v5_schemas_are_valid() -> None:
    names = (
        "commodity-c-fast-t1-query-v5-source-manifest-v1.schema.json",
        "commodity-c-fast-t1-query-v5-runtime-pin-set-v1.schema.json",
    )
    for name in names:
        schema = json.loads((ROOT / "docs/schemas" / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_source_bundle_is_deterministic_and_code_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blobs = {
        "scripts/c_fast_t1/Containerfile.query-v5": (CONTAINERFILE.read_bytes(), 0o644),
        "scripts/commodity_c_fast_t1_query_v5_launcher.py": (
            (ROOT / "scripts/commodity_c_fast_t1_query_v5_launcher.py").read_bytes(),
            0o644,
        ),
    }
    module = sys.modules[build_source_bundle.__module__]
    monkeypatch.setattr(module._delegate, "_resolve_commit", lambda _root, sha: sha)
    monkeypatch.setattr(
        module._delegate,
        "_git_blob",
        lambda _root, _sha, path: blobs[path],
    )
    first = build_source_bundle(ROOT, COMMIT)
    second = build_source_bundle(ROOT, COMMIT)
    assert first == second
    manifest = first[2]
    assert [entry["path"] for entry in manifest["entries"]] == sorted(blobs)
    assert manifest["code_only_blocked"] is True
    assert manifest["authority_granted"] is False


def _runtime_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    source_root = tmp_path / "release"
    scripts = source_root / "scripts"
    scripts.mkdir(parents=True)
    copied_launcher = scripts / "commodity_c_fast_t1_query_v5_launcher.py"
    copied_launcher.write_bytes(Path(launcher.__file__).read_bytes())
    copied_launcher.chmod(0o444)
    interpreter = tmp_path / "private-python"
    interpreter.write_bytes(Path(sys.executable).resolve().read_bytes())
    interpreter.chmod(0o555)
    root_identity, closure_sha256, _closure = launcher.source_closure(
        source_root,
        require_root_owned=False,
    )
    pins = {
        "schema_version": launcher.SCHEMA_VERSION,
        "generation_id": "query-v5-test-generation",
        "runtime_image_digest": "sha256:" + "b" * 64,
        "launcher_sha256": launcher._sha256(copied_launcher.read_bytes()),
        "python_executable_path": str(interpreter),
        "python_executable_sha256": launcher._sha256(interpreter.read_bytes()),
        "source_root_path": str(source_root),
        "source_root_identity_sha256": root_identity,
        "source_closure_manifest_sha256": closure_sha256,
        "code_only_blocked": True,
        "authority_granted": False,
    }
    pin_path = tmp_path / "pin-set.manifest.json"
    pin_path.write_bytes(launcher.canonical_json(pins))
    pin_path.chmod(0o444)
    return source_root, copied_launcher, pin_path, interpreter


def test_launcher_binds_pinned_interpreter_and_stable_closure(tmp_path: Path) -> None:
    source_root, copied_launcher, pin_path, interpreter = _runtime_fixture(tmp_path)
    digest = "sha256:" + "b" * 64
    result = launcher._inspect_runtime_identity(
        digest,
        pin_manifest_path=pin_path,
        launcher_path=copied_launcher,
        interpreter_path=interpreter,
        source_root=source_root,
        reported_executable_path=interpreter,
        loaded_executable_path=interpreter,
        require_root_owned=False,
    )
    assert result["status"] == launcher.INSPECTION_STATUS
    assert result["isolated_flags_verified"] is False
    assert result["code_only_blocked"] is True
    before = launcher.source_closure(source_root, require_root_owned=False)[:2]
    os.utime(source_root, ns=(1_000_000_000, 2_000_000_000))
    after = launcher.source_closure(source_root, require_root_owned=False)[:2]
    assert before == after


def test_launcher_rejects_alternate_reported_interpreter(tmp_path: Path) -> None:
    source_root, copied_launcher, pin_path, interpreter = _runtime_fixture(tmp_path)
    alternate = tmp_path / "alternate-python"
    alternate.write_bytes(interpreter.read_bytes())
    alternate.chmod(0o555)
    with pytest.raises(launcher.QueryV5LauncherError, match="pinned interpreter"):
        launcher._inspect_runtime_identity(
            "sha256:" + "b" * 64,
            pin_manifest_path=pin_path,
            launcher_path=copied_launcher,
            interpreter_path=interpreter,
            source_root=source_root,
            reported_executable_path=alternate,
            loaded_executable_path=interpreter,
            require_root_owned=False,
        )


def test_launcher_rejects_loaded_executable_path_replacement(tmp_path: Path) -> None:
    source_root, copied_launcher, pin_path, loaded = _runtime_fixture(tmp_path)
    pinned = tmp_path / "replacement-python"
    pinned.write_bytes(loaded.read_bytes())
    pinned.chmod(0o555)
    pins = json.loads(pin_path.read_text(encoding="utf-8"))
    pins["python_executable_path"] = str(pinned)
    pins["python_executable_sha256"] = launcher._sha256(pinned.read_bytes())
    pin_path.chmod(0o644)
    pin_path.write_bytes(launcher.canonical_json(pins))
    pin_path.chmod(0o444)
    with pytest.raises(
        launcher.QueryV5LauncherError,
        match="loaded executable is not the pinned interpreter",
    ):
        launcher._inspect_runtime_identity(
            "sha256:" + "b" * 64,
            pin_manifest_path=pin_path,
            launcher_path=copied_launcher,
            interpreter_path=pinned,
            source_root=source_root,
            reported_executable_path=pinned,
            loaded_executable_path=loaded,
            require_root_owned=False,
        )


def test_launcher_rejects_loaded_executable_bytes_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, copied_launcher, pin_path, interpreter = _runtime_fixture(tmp_path)
    interpreter_info = interpreter.lstat()
    monkeypatch.setattr(
        launcher,
        "_stable_loaded_executable",
        lambda *_args, **_kwargs: (b"loaded-executable-drift", interpreter_info),
    )
    with pytest.raises(
        launcher.QueryV5LauncherError,
        match="loaded executable bytes or identity changed",
    ):
        launcher._inspect_runtime_identity(
            "sha256:" + "b" * 64,
            pin_manifest_path=pin_path,
            launcher_path=copied_launcher,
            interpreter_path=interpreter,
            source_root=source_root,
            reported_executable_path=interpreter,
            loaded_executable_path=interpreter,
            require_root_owned=False,
        )


def test_source_closure_fails_closed_on_walk_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, _copied_launcher, _pin_path, _interpreter = _runtime_fixture(tmp_path)

    def failed_walk(
        *_args: object, onerror: object = None, **_kwargs: object
    ) -> object:
        assert callable(onerror)
        onerror(PermissionError("simulated scandir denial"))
        return iter(())

    monkeypatch.setattr(launcher.os, "walk", failed_walk)
    with pytest.raises(
        launcher.QueryV5LauncherError,
        match="cannot enumerate query-v5 source directory",
    ):
        launcher.source_closure(source_root, require_root_owned=False)


def test_source_closure_rejects_non_enumerable_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, _copied_launcher, _pin_path, _interpreter = _runtime_fixture(tmp_path)
    hidden = source_root / "hidden"
    hidden.mkdir()
    (hidden / "hidden.py").write_text("raise RuntimeError\n", encoding="utf-8")
    original = launcher._effective_access

    def denied(path: Path, mode: int) -> bool:
        if path == hidden and mode == (os.R_OK | os.X_OK):
            return False
        return original(path, mode)

    monkeypatch.setattr(launcher, "_effective_access", denied)
    with pytest.raises(
        launcher.QueryV5LauncherError,
        match="source directory hidden is not enumerable by the runtime",
    ):
        launcher.source_closure(source_root, require_root_owned=False)


def test_imported_verify_rejects_nonisolated_process() -> None:
    with pytest.raises(SystemExit, match="-I -S -s -E -B"):
        launcher.verify_runtime_identity("sha256:" + "b" * 64)


def test_public_verifier_has_no_injectable_trust_root() -> None:
    signature = inspect.signature(launcher.verify_runtime_identity)
    assert tuple(signature.parameters) == ("runtime_image_digest",)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        launcher.verify_runtime_identity(
            "sha256:" + "b" * 64,
            loaded_executable_path=Path(sys.executable),  # type: ignore[call-arg]
        )


def test_public_verifier_uses_fixed_production_trust_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "b" * 64
    captured: dict[str, object] = {}

    def inspect(runtime_image_digest: str, **kwargs: object) -> dict[str, object]:
        captured["runtime_image_digest"] = runtime_image_digest
        captured.update(kwargs)
        return {"status": launcher.INSPECTION_STATUS}

    monkeypatch.setattr(launcher, "_require_isolated_startup", lambda: None)
    monkeypatch.setattr(launcher, "_inspect_runtime_identity", inspect)

    result = launcher.verify_runtime_identity(digest)

    assert result["status"] == launcher.STATUS
    assert result["isolated_flags_verified"] is True
    assert captured == {
        "runtime_image_digest": digest,
        "pin_manifest_path": launcher.PIN_MANIFEST_PATH,
        "launcher_path": launcher.LAUNCHER_PATH,
        "interpreter_path": launcher.INTERPRETER_PATH,
        "source_root": launcher.SOURCE_ROOT,
        "reported_executable_path": None,
        "loaded_executable_path": None,
        "require_root_owned": True,
    }


def test_private_inspection_allows_root_owned_sticky_shared_ancestor() -> None:
    shared_parent = Path("/tmp").resolve(strict=True)
    source_parent = Path(tempfile.mkdtemp(dir=shared_parent))
    try:
        source_root = source_parent / "release"
        scripts = source_root / "scripts"
        scripts.mkdir(parents=True)
        copied_launcher = scripts / "commodity_c_fast_t1_query_v5_launcher.py"
        copied_launcher.write_bytes(Path(launcher.__file__).read_bytes())
        copied_launcher.chmod(0o444)
        identity, closure, manifest = launcher.source_closure(
            source_root,
            require_root_owned=False,
        )
        assert len(identity) == 64
        assert len(closure) == 64
        assert manifest["entries"]
    finally:
        shutil.rmtree(source_parent)


def test_production_mode_rejects_root_owned_sticky_shared_ancestor() -> None:
    shared_parent = Path("/tmp").resolve(strict=True)
    source_parent = Path(tempfile.mkdtemp(dir=shared_parent))
    try:
        with pytest.raises(
            launcher.QueryV5LauncherError,
            match="ancestor is group/world writable",
        ):
            launcher._require_safe_ancestor_chain(
                source_parent,
                "production source root",
                require_root_owned=True,
            )
    finally:
        shutil.rmtree(source_parent)


def test_launcher_rejects_nonisolated_direct_execution() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/commodity_c_fast_t1_query_v5_launcher.py"),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "-I -S -s -E -B" in completed.stderr
