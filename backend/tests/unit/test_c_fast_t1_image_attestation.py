from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "scripts/c_fast_t1/verify_image_attestation.py"
ATTESTATION_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-image-attestation-v1.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-external-image-evidence-v1.schema.json"
)

spec = importlib.util.spec_from_file_location(
    "c_fast_t1_verify_image_attestation",
    SCRIPT_PATH,
)
assert spec is not None and spec.loader is not None
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)
_RUNTIME_FILE_CACHE: dict[tuple[str, str], dict[str, bytes]] = {}


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture(scope="module")
def source_repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repository = tmp_path_factory.mktemp("image-source")
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    source_paths = {
        subject.CONTAINERFILE_PATH,
        subject.VERIFIER_SOURCE_PATH,
        subject.EVIDENCE_SCHEMA_SOURCE_PATH,
        subject.ATTESTATION_SCHEMA_SOURCE_PATH,
        *subject.EXPECTED_COPY_SOURCES,
    }
    for relative in source_paths:
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "synthetic exact source")
    return repository


@pytest.fixture(scope="module")
def source_sha(source_repository: Path) -> str:
    return _git(source_repository, "rev-parse", "HEAD")


@pytest.fixture(scope="module")
def source_facts(
    source_repository: Path,
    source_sha: str,
) -> dict[str, Any]:
    return subject.derive_source_facts(source_repository, source_sha)


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _tar_bytes(
    regular_files: dict[str, bytes],
    *,
    symlinks: dict[str, str] | None = None,
    hardlinks: dict[str, str] | None = None,
    duplicate: tuple[str, bytes] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for name, raw in regular_files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(raw))
        for name, target in (symlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)
        for name, target in (hardlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.LNKTYPE
            member.linkname = target
            archive.addfile(member)
        if duplicate is not None:
            name, raw = duplicate
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def _layer_blob(
    regular_files: dict[str, bytes],
    *,
    whiteouts: tuple[str, ...] = (),
    symlinks: dict[str, str] | None = None,
    compressed: bool,
) -> tuple[bytes, str, str]:
    entries = dict(regular_files)
    for path in whiteouts:
        entries[path] = b""
    plain = _tar_bytes(entries, symlinks=symlinks)
    if compressed:
        return (
            gzip.compress(plain, mtime=0),
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "sha256:" + hashlib.sha256(plain).hexdigest(),
        )
    return (
        plain,
        "application/vnd.oci.image.layer.v1.tar",
        "sha256:" + hashlib.sha256(plain).hexdigest(),
    )


def _installed_metadata_files(
    *,
    overrides: dict[str, str] | None = None,
) -> dict[str, bytes]:
    versions = dict(subject.EXPECTED_INSTALLED_DEPENDENCIES)
    versions.update(overrides or {})
    files: dict[str, bytes] = {}
    for name, version in versions.items():
        directory = name.replace("-", "_") + f"-{version}.dist-info"
        path = f"usr/local/lib/python3.12/site-packages/{directory}/METADATA"
        files[path] = (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"
        ).encode()
    return files


def _runtime_files(
    source_repository: Path,
    source_sha: str,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    container_raw = subject._git_blob(
        source_repository,
        source_sha,
        subject.CONTAINERFILE_PATH,
    )
    _, copy_map = subject._parse_containerfile(container_raw)
    for source, target in copy_map.items():
        result[subject._image_path(target).removeprefix("/")] = subject._git_blob(
            source_repository, source_sha, source
        )
    return result


def _build_oci_layout(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    *,
    runtime_overrides: dict[str, bytes] | None = None,
    extra_runtime_files: dict[str, bytes] | None = None,
    whiteout_stale_runtime: bool = False,
    opaque_whiteout_stale_runtime: bool = False,
    config_overrides: dict[str, Any] | None = None,
    installed_version_overrides: dict[str, str] | None = None,
    runtime_symlinks: dict[str, str] | None = None,
) -> tuple[Path, dict[str, Any]]:
    base_files = _installed_metadata_files(overrides=installed_version_overrides)
    if whiteout_stale_runtime:
        base_files.update(
            {
                "opt/c-fast-t1/stale.pyc": b"compiled",
                "opt/c-fast-t1/release-signing.key": (b"-----BEGIN PRIVATE KEY-----"),
            }
        )
    if opaque_whiteout_stale_runtime:
        base_files["opt/c-fast-t1/old/stale.txt"] = b"stale"
    cache_key = (str(source_repository), source_sha)
    if cache_key not in _RUNTIME_FILE_CACHE:
        _RUNTIME_FILE_CACHE[cache_key] = _runtime_files(
            source_repository,
            source_sha,
        )
    expected_runtime_files = _RUNTIME_FILE_CACHE[cache_key]
    runtime_files = dict(expected_runtime_files)
    runtime_files.update(runtime_overrides or {})
    runtime_files.update(extra_runtime_files or {})
    for path in runtime_symlinks or {}:
        runtime_files.pop(path, None)
    whiteouts = (
        (
            "opt/c-fast-t1/.wh.stale.pyc",
            "opt/c-fast-t1/.wh.release-signing.key",
        )
        if whiteout_stale_runtime
        else ()
    )
    if opaque_whiteout_stale_runtime:
        whiteouts = (
            *whiteouts,
            "opt/c-fast-t1/old/.wh..wh..opq",
        )
    base_layer, base_media, base_diff_id = _layer_blob(
        base_files,
        compressed=True,
    )
    runtime_layer, runtime_media, runtime_diff_id = _layer_blob(
        runtime_files,
        whiteouts=whiteouts,
        symlinks=runtime_symlinks,
        compressed=False,
    )
    layer_values = [
        (base_layer, base_media),
        (runtime_layer, runtime_media),
    ]
    layer_descriptors = [
        {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
        for raw, media_type in layer_values
    ]
    config = {
        "User": "65532:65532",
        "WorkingDir": "/opt/c-fast-t1",
        "Entrypoint": copy.deepcopy(subject.ENTRYPOINT),
        "Env": [
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONUNBUFFERED=1",
        ],
        "Labels": {
            **subject.EXPECTED_LABELS,
            "org.opencontainers.image.revision": source_sha,
        },
    }
    config.update(config_overrides or {})
    config_document = {
        "architecture": "amd64",
        "os": "linux",
        "config": config,
        "rootfs": {
            "type": "layers",
            "diff_ids": [base_diff_id, runtime_diff_id],
        },
    }
    config_raw = _json_bytes(config_document)
    config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": subject.OCI_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": subject.OCI_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": len(config_raw),
        },
        "layers": layer_descriptors,
    }
    manifest_raw = _json_bytes(manifest)
    manifest_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    index = {
        "schemaVersion": 2,
        "mediaType": subject.OCI_INDEX_MEDIA_TYPE,
        "manifests": [
            {
                "mediaType": subject.OCI_MANIFEST_MEDIA_TYPE,
                "digest": manifest_digest,
                "size": len(manifest_raw),
                "platform": {
                    "architecture": "amd64",
                    "os": "linux",
                },
            }
        ],
    }
    blobs = {
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"): (manifest_raw),
        "blobs/sha256/" + config_digest.removeprefix("sha256:"): config_raw,
    }
    for descriptor, (raw, _) in zip(
        layer_descriptors,
        layer_values,
        strict=True,
    ):
        blobs["blobs/sha256/" + descriptor["digest"].removeprefix("sha256:")] = raw
    archive_raw = _tar_bytes(
        {
            "oci-layout": _json_bytes({"imageLayoutVersion": "1.0.0"}),
            "index.json": _json_bytes(index),
            **blobs,
        }
    )
    archive_path = tmp_path / "image.oci.tar"
    archive_path.write_bytes(archive_raw)
    actual_runtime_hashes = {
        "/" + path: hashlib.sha256(runtime_files.get(path, expected_raw)).hexdigest()
        for path, expected_raw in expected_runtime_files.items()
    }
    image = {
        "reference": f"registry.example/c-fast-t1@{manifest_digest}",
        "digest": manifest_digest,
        "id": config_digest,
        "export_sha256": hashlib.sha256(archive_raw).hexdigest(),
        "rootfs_layer_digests": [
            descriptor["digest"] for descriptor in layer_descriptors
        ],
        "config": {
            "user": config["User"],
            "working_dir": config["WorkingDir"],
            "entrypoint": config["Entrypoint"],
            "relevant_environment": {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
            },
            "labels": config["Labels"],
        },
        "bundle_files": actual_runtime_hashes,
        "forbidden_path_matches": [],
        "unexpected_bundle_paths": [],
        "signer_or_private_key_paths": [],
    }
    return archive_path, image


def _valid_evidence(
    source_sha: str,
    source_facts: dict[str, Any],
    image: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": ("commodity_c_fast_t1_external_image_evidence_v1"),
        "capture_kind": "unsigned_external_oci_layout_capture_v1",
        "captured_at": "2026-07-25T00:00:00Z",
        "producer": {
            "tool": "test-oci-inspector",
            "tool_version": "1.0.0",
        },
        "build_provenance_verified": False,
        "registry_provenance_verified": False,
        "source_commit_sha": source_sha,
        "source_archive_sha256": source_facts["source_archive_sha256"],
        "build": {
            "platform": "linux/amd64",
            "context_root": ".",
            "containerfile_sha256": source_facts["containerfile_sha256"],
            "base_image_digest": source_facts["base_image_digest"],
            "direct_dependencies": copy.deepcopy(subject.EXPECTED_DEPENDENCIES),
        },
        "image": image,
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def _verify(
    tmp_path: Path,
    payload: dict[str, Any],
    archive_path: Path,
    source_repository: Path,
    source_sha: str,
) -> dict[str, Any]:
    evidence_path = tmp_path / "evidence.json"
    _write_json(evidence_path, payload)
    return subject.verify_image_evidence(
        evidence_path,
        archive_path,
        source_repository,
        source_sha,
    )


def test_valid_oci_content_passes_both_schemas_without_provenance(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    report = _verify(
        tmp_path,
        evidence,
        archive,
        source_repository,
        source_sha,
    )

    evidence_schema = json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    attestation_schema = json.loads(ATTESTATION_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(evidence_schema)
    Draft202012Validator.check_schema(attestation_schema)
    assert (
        list(
            Draft202012Validator(
                evidence_schema,
                format_checker=FormatChecker(),
            ).iter_errors(evidence)
        )
        == []
    )
    assert (
        list(
            Draft202012Validator(
                attestation_schema,
                format_checker=FormatChecker(),
            ).iter_errors(report)
        )
        == []
    )
    assert report["status"] == (
        "EXTERNAL_OCI_ARTIFACT_CONTENT_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE"
    )
    assert report["checks"]["build_provenance_verified"] is False
    assert report["checks"]["registry_provenance_verified"] is False
    assert report["checks"]["installed_dependency_versions_recomputed"] is True
    assert report["installed_dependencies"] == (subject.EXPECTED_INSTALLED_DEPENDENCIES)
    false_fields = (
        "authority_granted",
        "network_authorized",
        "network_query_authorized",
        "readonly_production_query_authorized",
        "write_probe_authorized",
        "database_mutation_authorized",
        "deployment_mutation_authorized",
        "collection_authorized",
        "runtime_activation_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "replacement_authorized",
        "production_authorized",
        "automatic_promotion_authorized",
        "authority_recovery_allowed",
        "receipt_replay_allowed",
        "t1_executed",
        "production_queried",
    )
    assert all(report[field] is False for field in false_fields)


def test_unsigned_json_cannot_forge_oci_facts(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
    )
    evidence = _valid_evidence(source_sha, source_facts, image)
    evidence["image"]["id"] = "sha256:" + "6" * 64

    with pytest.raises(
        subject.ImageAttestationError,
        match="config digest/image ID",
    ):
        _verify(
            tmp_path,
            evidence,
            archive,
            source_repository,
            source_sha,
        )


def test_runtime_files_are_recomputed_from_layers(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    first_path = next(iter(source_facts["bundle_files"])).removeprefix("/")
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        runtime_overrides={first_path: b"tampered runtime"},
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    with pytest.raises(
        subject.ImageAttestationError,
        match="runtime bundle/source hashes",
    ):
        _verify(
            tmp_path,
            evidence,
            archive,
            source_repository,
            source_sha,
        )


@pytest.mark.parametrize(
    "extra_path",
    [
        "opt/c-fast-t1/scripts/__pycache__/runner.pyc",
        "opt/c-fast-t1/release-signer.py",
    ],
)
def test_extra_bytecode_or_signer_in_final_image_is_rejected(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
    extra_path: str,
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        extra_runtime_files={extra_path: b"unexpected"},
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    with pytest.raises(
        subject.ImageAttestationError,
        match=(
            "forbidden_path_matches|unexpected_bundle_paths|signer_or_private_key_paths"
        ),
    ):
        _verify(
            tmp_path,
            evidence,
            archive,
            source_repository,
            source_sha,
        )


def test_gzip_plain_layers_and_whiteouts_are_applied_in_order(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        whiteout_stale_runtime=True,
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    report = _verify(
        tmp_path,
        evidence,
        archive,
        source_repository,
        source_sha,
    )

    assert report["checks"]["runtime_files_recomputed_from_layers"] is True


def test_opaque_whiteout_removes_lower_directory_contents(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        opaque_whiteout_stale_runtime=True,
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    report = _verify(
        tmp_path,
        evidence,
        archive,
        source_repository,
        source_sha,
    )

    assert report["checks"]["runtime_files_recomputed_from_layers"] is True


@pytest.mark.parametrize(
    ("config_overrides", "message"),
    [
        ({"User": "0:0"}, "non-root"),
        ({"Entrypoint": ["/bin/sh"]}, "entrypoint"),
        (
            {
                "Env": [
                    "PYTHONDONTWRITEBYTECODE=1",
                    "PYTHONUNBUFFERED=1",
                    "QUESTDB_PASSWORD=secret",
                ]
            },
            "sensitive environment",
        ),
    ],
)
def test_actual_oci_config_is_verified(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
    config_overrides: dict[str, Any],
    message: str,
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        config_overrides=config_overrides,
    )
    image["config"] = {
        "user": "65532:65532",
        "working_dir": "/opt/c-fast-t1",
        "entrypoint": copy.deepcopy(subject.ENTRYPOINT),
        "relevant_environment": {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        },
        "labels": {
            **subject.EXPECTED_LABELS,
            "org.opencontainers.image.revision": source_sha,
        },
    }
    evidence = _valid_evidence(source_sha, source_facts, image)

    with pytest.raises(subject.ImageAttestationError, match=message):
        _verify(
            tmp_path,
            evidence,
            archive,
            source_repository,
            source_sha,
        )


def test_actual_installed_dependency_versions_are_verified(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        installed_version_overrides={"psycopg-binary": "9.9.9"},
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    with pytest.raises(
        subject.ImageAttestationError,
        match="installed dependency versions",
    ):
        _verify(
            tmp_path,
            evidence,
            archive,
            source_repository,
            source_sha,
        )


def test_runtime_symlink_is_not_accepted_as_bundle_file(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    expected = next(iter(source_facts["bundle_files"])).removeprefix("/")
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
        runtime_symlinks={expected: "/tmp/attacker"},
    )
    evidence = _valid_evidence(source_sha, source_facts, image)

    with pytest.raises(
        subject.ImageAttestationError,
        match="missing or non-regular",
    ):
        _verify(
            tmp_path,
            evidence,
            archive,
            source_repository,
            source_sha,
        )


@pytest.mark.parametrize("unsafe_name", ["../index.json", "/index.json"])
def test_oci_archive_rejects_path_traversal(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    archive = tmp_path / "unsafe.tar"
    archive.write_bytes(_tar_bytes({unsafe_name: b"{}"}))

    with pytest.raises(
        subject.ImageAttestationError,
        match="path traversal",
    ):
        subject.derive_oci_facts(archive, "a" * 40, set())


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_oci_archive_rejects_duplicate_and_link_entries(
    tmp_path: Path,
    link_kind: str,
) -> None:
    duplicate = tmp_path / "duplicate.tar"
    duplicate.write_bytes(
        _tar_bytes(
            {"index.json": b"{}"},
            duplicate=("index.json", b"{}"),
        )
    )
    with pytest.raises(subject.ImageAttestationError, match="duplicate path"):
        subject.derive_oci_facts(duplicate, "a" * 40, set())

    linked = tmp_path / "linked.tar"
    link_arguments = (
        {"symlinks": {"index.json": "/tmp/attacker"}}
        if link_kind == "symlink"
        else {"hardlinks": {"index.json": "other"}}
    )
    linked.write_bytes(_tar_bytes({}, **link_arguments))
    with pytest.raises(subject.ImageAttestationError, match="must not contain links"):
        subject.derive_oci_facts(linked, "a" * 40, set())


def test_layer_rejects_path_traversal_and_duplicates() -> None:
    traversal = _tar_bytes({"../escape": b"x"})
    with pytest.raises(subject.ImageAttestationError, match="path traversal"):
        subject._apply_layer({}, traversal, "layer")

    duplicate = _tar_bytes(
        {"same": b"one"},
        duplicate=("same", b"two"),
    )
    with pytest.raises(subject.ImageAttestationError, match="duplicate path"):
        subject._apply_layer({}, duplicate, "layer")


def test_oci_archive_rejects_non_regular_key_entry(
    tmp_path: Path,
) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        member = tarfile.TarInfo("index.json")
        member.type = tarfile.CHRTYPE
        archive.addfile(member)
    archive_path = tmp_path / "special.tar"
    archive_path.write_bytes(output.getvalue())

    with pytest.raises(subject.ImageAttestationError, match="non-regular"):
        subject.derive_oci_facts(archive_path, "a" * 40, set())


def test_oci_archive_size_limit_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "large.tar"
    archive.write_bytes(b"x" * 101)
    monkeypatch.setattr(subject, "MAX_ARCHIVE_BYTES", 100)

    with pytest.raises(subject.ImageAttestationError, match="byte limit"):
        subject.derive_oci_facts(archive, "a" * 40, set())


def test_git_replace_objects_are_ignored(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "value.txt").write_text("original\n", encoding="utf-8")
    _git(repository, "add", "value.txt")
    _git(repository, "commit", "-q", "-m", "original")
    original_sha = _git(repository, "rev-parse", "HEAD")
    (repository / "value.txt").write_text("replacement\n", encoding="utf-8")
    _git(repository, "commit", "-qam", "replacement")
    replacement_sha = _git(repository, "rev-parse", "HEAD")
    _git(repository, "replace", original_sha, replacement_sha)

    raw = subject._git_blob(repository, original_sha, "value.txt")

    assert raw == b"original\n"


def test_duplicate_nonfinite_symlink_and_read_change_are_rejected(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"a","schema_version":"b"}\n',
        encoding="utf-8",
    )
    with pytest.raises(subject.ImageAttestationError, match="duplicate JSON key"):
        subject.verify_image_evidence(
            duplicate,
            tmp_path / "missing.tar",
            source_repository,
            source_sha,
        )
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}\n', encoding="utf-8")
    with pytest.raises(subject.ImageAttestationError, match="non-finite"):
        subject.verify_image_evidence(
            nonfinite,
            tmp_path / "missing.tar",
            source_repository,
            source_sha,
        )
    symlink = tmp_path / "evidence-link.json"
    symlink.symlink_to(duplicate)
    with pytest.raises(subject.ImageAttestationError, match="must not be a symlink"):
        subject.verify_image_evidence(
            symlink,
            tmp_path / "missing.tar",
            source_repository,
            source_sha,
        )

    real_read = subject._read_fd_bounded
    calls = 0

    def changing_read(descriptor: int, label: str, limit: int) -> bytes:
        nonlocal calls
        calls += 1
        raw = real_read(descriptor, label, limit)
        return raw + b" " if calls == 2 else raw

    monkeypatch.setattr(subject, "_read_fd_bounded", changing_read)
    with pytest.raises(subject.ImageAttestationError, match="changed while being read"):
        subject._read_regular_file(duplicate, "evidence")


def test_create_only_retries_short_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "attestation.json"
    real_write = os.write

    def short_write(descriptor: int, raw: bytes) -> int:
        return real_write(descriptor, raw[: max(1, len(raw) // 2)])

    monkeypatch.setattr(subject.os, "write", short_write)
    subject._write_create_only(output, {"status": "complete"})

    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "complete"}


def test_cli_requires_archive_and_output_is_create_only(
    tmp_path: Path,
    source_repository: Path,
    source_sha: str,
    source_facts: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive, image = _build_oci_layout(
        tmp_path,
        source_repository,
        source_sha,
    )
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "attestation.json"
    _write_json(
        evidence_path,
        _valid_evidence(source_sha, source_facts, image),
    )
    args = [
        "--evidence",
        str(evidence_path),
        "--oci-layout-archive",
        str(archive),
        "--source-root",
        str(source_repository),
        "--expected-source-commit-sha",
        source_sha,
        "--json-output",
        str(output_path),
    ]

    assert subject.main(args) == 0
    assert subject.main(args) == 2
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert "cannot create image attestation output" in capsys.readouterr().err
