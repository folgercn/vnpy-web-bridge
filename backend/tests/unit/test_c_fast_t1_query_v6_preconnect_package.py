from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from c_fast_t1 import query_v6_preconnect_package as subject  # noqa: E402


def _dependencies() -> tuple[list[dict[str, str]], str]:
    return (
        [{"name": name, "version": "1.0"} for name in subject.DEPENDENCY_NAMES],
        "d" * 64,
    )


def test_build_is_deterministic_exact_closure_and_has_no_secret_or_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(subject, "_resolve_commit", lambda *_args: "a" * 40)
    monkeypatch.setattr(
        subject,
        "_git_blob",
        lambda _root, _commit, path: (f"frozen:{path}\n".encode(), 0o444),
    )
    monkeypatch.setattr(
        subject, "_interpreter_identity", lambda _path: ("/python", "b" * 64)
    )
    monkeypatch.setattr(
        subject, "dependency_closure", lambda *_args, **_kwargs: _dependencies()
    )
    first = subject.build_package(tmp_path, "HEAD")
    second = subject.build_package(tmp_path, "HEAD")
    assert first == second
    archive, manifest_raw, manifest = first
    assert manifest["legacy_authority_reused"] is False
    assert manifest["dsn_secret_included"] is False
    assert manifest["network_accessed"] is False
    assert manifest["authority_granted"] is False
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as package:
        assert sorted(package.getnames()) == sorted(
            [subject.MANIFEST_ARCHIVE_PATH, *subject.SOURCE_PATHS]
        )
        assert package.extractfile(subject.MANIFEST_ARCHIVE_PATH).read() == manifest_raw


def test_real_head_build_round_trip_is_byte_deterministic() -> None:
    first = subject.build_package(ROOT, "HEAD")
    second = subject.build_package(ROOT, "HEAD")
    assert first == second
    archive, manifest_raw, payload = first
    members = subject._archive_members(archive, payload)
    assert members[subject.MANIFEST_ARCHIVE_PATH] == manifest_raw
    assert [entry["path"] for entry in payload["entries"]] == sorted(
        subject.SOURCE_PATHS
    )


def test_preflight_detects_interpreter_dependency_and_root_identity_tamper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    package_root = tmp_path / "installed"
    package_root.mkdir()
    entries = []
    for source_path in sorted(subject.SOURCE_PATHS):
        entry = package_root / source_path
        entry.parent.mkdir(parents=True, exist_ok=True)
        raw = b"adapter" if source_path == subject.ENTRYPOINT else source_path.encode()
        entry.write_bytes(raw)
        entry.chmod(0o444)
        entries.append(
            {
                "path": source_path,
                "sha256": subject._sha256(raw),
                "size": len(raw),
                "mode": 0o444,
            }
        )
    dependencies, closure = _dependencies()
    payload = {
        "schema_version": subject.SCHEMA_VERSION,
        "package_id": "",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "source_commit_sha": "a" * 40,
        "entrypoint": subject.ENTRYPOINT,
        "entries": entries,
        "python_executable_path": "/python",
        "python_executable_sha256": "b" * 64,
        "python_dependencies": dependencies,
        "python_dependency_closure_sha256": closure,
        "deterministic_archive": True,
        "v6_only_preconnect_adapter": True,
        "legacy_authority_reused": False,
        "dsn_secret_included": False,
        "network_accessed": False,
        "authority_granted": False,
        "production_authorized": False,
    }
    identity = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = "query-v6-preconnect-" + subject._sha256(
        subject.canonical_json(identity)
    )
    manifest_path = package_root / subject.MANIFEST_ARCHIVE_PATH
    manifest_path.write_bytes(subject.canonical_json(payload))
    manifest_path.chmod(0o444)
    monkeypatch.setattr(
        subject, "_interpreter_identity", lambda _path: ("/python", "b" * 64)
    )
    monkeypatch.setattr(
        subject, "dependency_closure", lambda *_args, **_kwargs: _dependencies()
    )
    manifest_sha = subject._sha256(subject.canonical_json(payload))
    with pytest.raises(subject.QueryV6PackageError, match="root identity"):
        subject.preflight_installed_runtime(
            manifest_path,
            expected_manifest_sha256=manifest_sha,
            expected_package_root_identity_sha256="f" * 64,
            expected_python_executable_sha256="b" * 64,
            expected_dependency_closure_sha256=closure,
            require_root_owned=False,
        )
    with pytest.raises(subject.QueryV6PackageError, match="interpreter binding"):
        subject.preflight_installed_runtime(
            manifest_path,
            expected_manifest_sha256=manifest_sha,
            expected_python_executable_sha256="c" * 64,
            expected_dependency_closure_sha256=closure,
            require_root_owned=False,
        )
    with pytest.raises(subject.QueryV6PackageError, match="dependency closure"):
        subject.preflight_installed_runtime(
            manifest_path,
            expected_manifest_sha256=manifest_sha,
            expected_python_executable_sha256="b" * 64,
            expected_dependency_closure_sha256="e" * 64,
            require_root_owned=False,
        )


def test_root_install_is_default_and_base_cannot_inject_computed_pins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    with pytest.raises(subject.QueryV6PackageError, match="requires root"):
        subject.install_package(
            tmp_path / "archive.tar",
            tmp_path / "manifest.json",
            tmp_path / "install",
            tmp_path / "active",
            "query-v6-test-pins",
            tmp_path / "keyring.json",
            tmp_path / "questdb-build.txt",
        )
    with pytest.raises(subject.QueryV6PackageError, match="non-local fields"):
        subject.build_active_pin_payload(
            {
                "generation_id": "query-v6-test-pins",
                "executable_keyring_sha256": "a" * 64,
                "questdb_build_sha256": "b" * 64,
                "execution_adapter_sha256": "c" * 64,
            },
            {},
            {},
        )


def test_installer_computes_all_deployment_pins_and_publishes_last(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(subject, "_resolve_commit", lambda *_args: "a" * 40)
    monkeypatch.setattr(
        subject,
        "_git_blob",
        lambda _root, _commit, path: (f"frozen:{path}\n".encode(), 0o444),
    )
    monkeypatch.setattr(
        subject, "_interpreter_identity", lambda _path: ("/python", "b" * 64)
    )
    monkeypatch.setattr(
        subject, "dependency_closure", lambda *_args, **_kwargs: _dependencies()
    )
    archive, manifest_raw, manifest = subject.build_package(tmp_path, "HEAD")
    archive_path = tmp_path / "package.tar"
    manifest_path = tmp_path / "package.json"
    keyring_path = tmp_path / "keyring.json"
    build_path = tmp_path / "questdb-build.txt"
    archive_path.write_bytes(archive)
    manifest_path.write_bytes(manifest_raw)
    keyring_path.write_text('{"keys":[]}', encoding="utf-8")
    build_path.write_text("questdb-test-build\n", encoding="utf-8")
    keyring_path.chmod(0o600)
    build_path.chmod(0o444)
    install_root = tmp_path / "installed"
    active_root = tmp_path / "active-pins"
    pins = subject.install_package(
        archive_path,
        manifest_path,
        install_root,
        active_root,
        "query-v6-root-generation-test-0001",
        keyring_path,
        build_path,
        require_root=False,
    )
    entry_hashes = {entry["path"]: entry["sha256"] for entry in manifest["entries"]}
    assert pins["execution_adapter_sha256"] == entry_hashes[subject.ENTRYPOINT]
    assert (
        pins["executable_verifier_sha256"]
        == entry_hashes[subject.PIN_SOURCE_PATHS["executable_verifier_sha256"]]
    )
    assert pins["executable_keyring_sha256"] == subject._sha256(
        subject.canonical_json({"keys": []})
    )
    assert pins["questdb_build_sha256"] == subject._sha256(b"questdb-test-build")
    assert (active_root / "pin-set.manifest.json").read_bytes() == (
        subject.canonical_json(pins)
    )
    with pytest.raises(
        subject.QueryV6PackageError, match="destinations must be absent"
    ):
        subject.install_package(
            archive_path,
            manifest_path,
            install_root,
            active_root,
            "query-v6-root-generation-test-0002",
            keyring_path,
            build_path,
            require_root=False,
        )
