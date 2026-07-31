from __future__ import annotations

import copy
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
import pytest


ROOT = Path(__file__).resolve().parents[3]
PRODUCER_PATH = ROOT / "scripts/c_fast_t1/create_query_v3_source_bundle.py"
VERIFIER_PATH = ROOT / "scripts/c_fast_t1/verify_query_v3_image_attestation.py"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


producer = _load("c_fast_t1_query_v3_source_bundle", PRODUCER_PATH)
subject = _load("c_fast_t1_query_v3_image_attestation", VERIFIER_PATH)


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture(scope="module")
def source_commit() -> str:
    return _git("rev-parse", "HEAD")


@pytest.fixture(scope="module")
def source_bundle(source_commit: str) -> tuple[bytes, bytes, dict[str, Any]]:
    return producer.build_source_bundle(ROOT, source_commit)


def _tar(
    entries: list[tuple[str, bytes, int, str]],
    *,
    canonical: bool = False,
    tar_format: int = tarfile.USTAR_FORMAT,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tar_format,
    ) as archive:
        for name, raw, mode, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            if kind == "regular":
                member.size = len(raw)
                member.type = tarfile.REGTYPE
                archive.addfile(member, io.BytesIO(raw))
            elif kind == "directory":
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = raw.decode()
                archive.addfile(member)
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = raw.decode()
                archive.addfile(member)
            elif kind == "character":
                member.type = tarfile.CHRTYPE
                archive.addfile(member)
            else:
                raise AssertionError(kind)
    result = output.getvalue()
    assert result if canonical else True
    return result


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


def _source_entries(bundle_raw: bytes) -> list[tuple[str, bytes, int, str]]:
    result: list[tuple[str, bytes, int, str]] = []
    with tarfile.open(fileobj=io.BytesIO(bundle_raw), mode="r:") as archive:
        for member in archive:
            stream = archive.extractfile(member)
            assert stream is not None
            result.append((member.name, stream.read(), member.mode, "regular"))
    return result


def _rehash_manifest(
    entries: list[tuple[str, bytes, int, str]],
) -> list[tuple[str, bytes, int, str]]:
    manifest = json.loads(entries[0][1])
    source_entries = entries[1:]
    manifest["entries"] = [
        {
            "path": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "mode": mode,
        }
        for name, raw, mode, kind in source_entries
        if kind == "regular"
    ]
    manifest["entries"].sort(key=lambda item: item["path"])
    identity = {key: value for key, value in manifest.items() if key != "manifest_id"}
    manifest["manifest_id"] = (
        "query-v3-source-manifest-v1-"
        + hashlib.sha256(producer.canonical_json(identity)).hexdigest()
    )
    ordered = {
        name: (name, raw, mode, kind)
        for name, raw, mode, kind in source_entries
    }
    return [
        (
            producer.MANIFEST_ARCHIVE_PATH,
            producer.canonical_json(manifest),
            0o444,
            "regular",
        ),
        *[ordered[item["path"]] for item in manifest["entries"]],
    ]


def _metadata(name: str, version: str) -> bytes:
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()


def _layer(
    files: dict[str, bytes],
    *,
    modes: dict[str, int] | None = None,
    directories: dict[str, int] | None = None,
    compressed: bool = False,
) -> tuple[bytes, str, str]:
    raw = _tar(
        [
            *[
                (path, b"", mode, "directory")
                for path, mode in sorted((directories or {}).items())
            ],
            *[
                (path, content, (modes or {}).get(path, 0o644), "regular")
                for path, content in sorted(files.items())
            ],
        ]
    )
    if compressed:
        stored = gzip.compress(raw, mtime=0)
        media_type = "application/vnd.oci.image.layer.v1.tar+gzip"
    else:
        stored = raw
        media_type = "application/vnd.oci.image.layer.v1.tar"
    return stored, "sha256:" + hashlib.sha256(stored).hexdigest(), media_type


def _build_oci(
    source_facts: dict[str, Any],
    source_commit: str,
    *,
    config_override: dict[str, Any] | None = None,
    runtime_extra: dict[str, bytes] | None = None,
    runtime_modes: dict[str, int] | None = None,
    extra_raw_layers: list[bytes] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    metadata_files = {
        (
            "usr/local/lib/python3.12/site-packages/"
            "attrs-26.1.0.dist-info/METADATA"
        ): _metadata("attrs", "26.1.0"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "cffi-2.1.0.dist-info/METADATA"
        ): _metadata("cffi", "2.1.0"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "cryptography-48.0.0.dist-info/METADATA"
        ): _metadata("cryptography", "48.0.0"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "jsonschema-4.26.0.dist-info/METADATA"
        ): _metadata("jsonschema", "4.26.0"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "jsonschema_specifications-2025.9.1.dist-info/METADATA"
        ): _metadata("jsonschema-specifications", "2025.9.1"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "psycopg-3.2.3.dist-info/METADATA"
        ): _metadata("psycopg", "3.2.3"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "psycopg_binary-3.2.3.dist-info/METADATA"
        ): _metadata("psycopg-binary", "3.2.3"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "pycparser-3.0.dist-info/METADATA"
        ): _metadata("pycparser", "3.0"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "referencing-0.37.0.dist-info/METADATA"
        ): _metadata("referencing", "0.37.0"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "rpds_py-2026.6.3.dist-info/METADATA"
        ): _metadata("rpds-py", "2026.6.3"),
        (
            "usr/local/lib/python3.12/site-packages/"
            "typing_extensions-4.16.0.dist-info/METADATA"
        ): _metadata("typing-extensions", "4.16.0"),
        subject.INTERPRETER_PATH: b"synthetic-python-interpreter",
        subject.RUNTIME_PTH_PATH: subject.RUNTIME_PTH_CONTENT,
    }
    runtime_files = {
        path.removeprefix("/"): bytes.fromhex("00")
        for path in source_facts["runtime_bundle"]
    }
    bundle_raw = source_facts["bundle_raw"]
    bundle_entries = {
        name: raw
        for name, raw, _mode, _kind in _source_entries(bundle_raw)[1:]
    }
    for image_path in source_facts["runtime_bundle"]:
        source_path = image_path.removeprefix("/opt/c-fast-t1/")
        runtime_files[image_path.removeprefix("/")] = bundle_entries[source_path]
    runtime_files.update(runtime_extra or {})
    base_blob, base_digest, base_media = _layer(
        metadata_files,
        modes={
            subject.INTERPRETER_PATH: 0o555,
            subject.RUNTIME_PTH_PATH: 0o444,
        },
        compressed=True,
    )
    runtime_blob, runtime_digest, runtime_media = _layer(
        runtime_files,
        modes={
            path: (runtime_modes or {}).get(path, 0o444)
            for path in runtime_files
        },
        directories={
            directory: 0o555
            for path in runtime_files
            if path.startswith("opt/c-fast-t1/")
            for directory in {
                "/".join(path.split("/")[:depth])
                for depth in range(2, len(path.split("/")))
            }
            if (
                directory == "opt/c-fast-t1"
                or directory.startswith("opt/c-fast-t1/")
            )
        },
    )
    base_diff = "sha256:" + hashlib.sha256(gzip.decompress(base_blob)).hexdigest()
    runtime_diff = "sha256:" + hashlib.sha256(runtime_blob).hexdigest()
    subject.BASE_ROOTFS_LAYER_DIGESTS = (base_digest,)
    subject.BASE_ROOTFS_DIFF_IDS = (base_diff,)
    config = {
        "User": "65532:65532",
        "WorkingDir": "/opt/c-fast-t1",
        "Entrypoint": subject.ENTRYPOINT,
        "Cmd": None,
        "Env": [f"{key}={value}" for key, value in subject.EXPECTED_ENVIRONMENT.items()],
        "Labels": {
            **subject.EXPECTED_LABELS,
            "org.opencontainers.image.revision": source_commit,
        },
    }
    config.update(config_override or {})
    extra_layers = [
        (
            raw,
            "sha256:" + hashlib.sha256(raw).hexdigest(),
            "application/vnd.oci.image.layer.v1.tar",
            "sha256:" + hashlib.sha256(raw).hexdigest(),
        )
        for raw in (extra_raw_layers or [])
    ]
    config_document = {
        "architecture": "amd64",
        "os": "linux",
        "config": config,
        "rootfs": {
            "type": "layers",
            "diff_ids": [
                base_diff,
                runtime_diff,
                *[item[3] for item in extra_layers],
            ],
        },
    }
    config_raw = _json_bytes(config_document)
    config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    layers = [
        {
            "mediaType": base_media,
            "digest": base_digest,
            "size": len(base_blob),
        },
        {
            "mediaType": runtime_media,
            "digest": runtime_digest,
            "size": len(runtime_blob),
        },
        *[
            {
                "mediaType": media_type,
                "digest": digest,
                "size": len(raw),
            }
            for raw, digest, media_type, _diff_id in extra_layers
        ],
    ]
    manifest = {
        "schemaVersion": 2,
        "mediaType": subject.OCI_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": subject.OCI_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": len(config_raw),
        },
        "layers": layers,
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
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    blobs = {
        "blobs/sha256/" + config_digest.removeprefix("sha256:"): config_raw,
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"): manifest_raw,
        "blobs/sha256/" + base_digest.removeprefix("sha256:"): base_blob,
        "blobs/sha256/" + runtime_digest.removeprefix("sha256:"): runtime_blob,
        **{
            "blobs/sha256/" + digest.removeprefix("sha256:"): raw
            for raw, digest, _media_type, _diff_id in extra_layers
        },
    }
    archive_raw = _tar(
        [
            ("oci-layout", _json_bytes({"imageLayoutVersion": "1.0.0"}), 0o644, "regular"),
            ("index.json", _json_bytes(index), 0o644, "regular"),
            *[
                (path, raw, 0o644, "regular")
                for path, raw in sorted(blobs.items())
            ],
        ]
    )
    image = {
        "reference": f"registry.invalid/c-fast/query-v3@{manifest_digest}",
        "digest": manifest_digest,
        "id": config_digest,
        "export_sha256": hashlib.sha256(archive_raw).hexdigest(),
        "rootfs_layer_digests": [
            base_digest,
            runtime_digest,
            *[item[1] for item in extra_layers],
        ],
        "config": {
            "user": config["User"],
            "working_dir": config["WorkingDir"],
            "entrypoint": config["Entrypoint"],
            "relevant_environment": subject.EXPECTED_ENVIRONMENT,
            "labels": config["Labels"],
        },
        "bundle_files": source_facts["runtime_bundle"],
        "forbidden_path_matches": [],
        "unexpected_bundle_paths": [],
        "signer_or_private_key_paths": [],
    }
    return archive_raw, image


def _evidence(
    source_facts: dict[str, Any],
    source_commit: str,
    archive_raw: bytes,
    image: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": subject.EVIDENCE_SCHEMA_VERSION,
        "capture_kind": "unsigned_external_query_v3_oci_layout_capture_v1",
        "captured_at": datetime(2026, 7, 29, tzinfo=timezone.utc).isoformat(),
        "producer": {"tool": "pytest", "tool_version": "1"},
        "build_provenance_verified": False,
        "registry_provenance_verified": False,
        "source_commit_sha": source_commit,
        "source_bundle_archive_sha256": hashlib.sha256(
            source_facts["bundle_raw"]
        ).hexdigest(),
        "source_manifest_raw_sha256": hashlib.sha256(
            source_facts["manifest_raw"]
        ).hexdigest(),
        "source_manifest_canonical_sha256": hashlib.sha256(
            subject.canonical_json(source_facts["manifest"])
        ).hexdigest(),
        "build": {
            "platform": "linux/amd64",
            "context_kind": "exact_query_v3_source_bundle_v1",
            "containerfile_sha256": source_facts["containerfile_sha256"],
            "base_image_digest": subject.BASE_IMAGE_DIGEST,
            "direct_dependencies": subject.EXPECTED_DEPENDENCIES,
        },
        "image": image,
        "sensitive_material_present": False,
        "authority_granted": False,
    }


def _valid_artifacts(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> tuple[Path, Path, Path, dict[str, Any]]:
    bundle_raw = source_bundle[0]
    bundle_path = _write(tmp_path / "source-bundle.tar", bundle_raw)
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    archive_raw, image = _build_oci(source_facts, source_commit)
    oci_path = _write(tmp_path / "runtime.oci.tar", archive_raw)
    evidence = _evidence(source_facts, source_commit, archive_raw, image)
    evidence_path = _write(tmp_path / "evidence.json", _json_bytes(evidence))
    return evidence_path, bundle_path, oci_path, evidence


def test_producer_is_deterministic_and_manifest_schema_valid(
    source_commit: str,
) -> None:
    first = producer.build_source_bundle(ROOT, source_commit)
    second = producer.build_source_bundle(ROOT, source_commit)

    assert first[0] == second[0]
    assert first[1] == second[1]
    assert first[2] == second[2]
    schema = json.loads(producer.SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert not list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(first[2])
    )
    assert first[2]["runtime_git_resolution_required"] is False
    assert (
        first[2]["source_commit_lineage_independently_verified_by_runtime"]
        is False
    )


def test_valid_exact_bundle_and_oci_pass_without_git_dependency(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path, bundle_path, oci_path, _evidence_payload = _valid_artifacts(
        tmp_path,
        source_bundle,
        source_commit,
    )
    monkeypatch.setenv("PATH", "/definitely/no/git")

    report = subject.verify_query_v3_image_evidence(
        evidence_path,
        bundle_path,
        oci_path,
        source_commit,
    )

    assert report["status"] == subject.STATUS
    assert report["checks"]["git_binary_required"] is False
    assert report["checks"]["git_commit_independently_resolved"] is False
    assert report["checks"]["runtime_bundle_matches_source_bundle"] is True
    assert report["checks"]["python_execution_closure_frozen"] is True
    assert len(report["python_execution_closure_sha256"]) == 64
    assert report["python_execution_closure_entries"] > 0
    assert report["authority_granted"] is False
    assert report["production_query_authorized"] is False


@pytest.mark.parametrize(
    ("attack", "error"),
    [
        ("missing", "paths do not match"),
        ("extra", "paths do not match"),
        ("duplicate", "duplicate"),
        ("traversal", "path traversal"),
        ("symlink", "metadata is not canonical"),
        ("hardlink", "metadata is not canonical"),
        ("device", "metadata is not canonical"),
        ("unsafe_mode", "metadata is not canonical"),
    ],
)
def test_source_bundle_structural_attacks_fail_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    attack: str,
    error: str,
) -> None:
    entries = _source_entries(source_bundle[0])
    if attack == "missing":
        entries.pop()
    elif attack == "extra":
        entries.append(("scripts/extra.py", b"x", 0o644, "regular"))
    elif attack == "duplicate":
        entries.append(entries[-1])
    elif attack == "traversal":
        entries.append(("../escape", b"x", 0o644, "regular"))
    elif attack == "symlink":
        entries.append(("scripts/link.py", b"target", 0o644, "symlink"))
    elif attack == "hardlink":
        entries.append(
            (
                "scripts/hardlink.py",
                producer.CONTAINERFILE_PATH.encode(),
                0o644,
                "hardlink",
            )
        )
    elif attack == "device":
        entries.append(("scripts/device", b"", 0o644, "character"))
    elif attack == "unsafe_mode":
        name, raw, _mode, kind = entries[-1]
        entries[-1] = (name, raw, 0o666, kind)
    path = _write(tmp_path / f"{attack}.tar", _tar(entries))

    with pytest.raises(subject.QueryV3ImageAttestationError, match=error):
        subject.derive_source_facts(path, source_commit)


@pytest.mark.parametrize(
    "instruction",
    [
        "RUN true",
        "ENV EXTRA=value",
        'LABEL extra="value"',
        "USER 65532:65532",
        "WORKDIR /opt/c-fast-t1",
        "COPY docs/schemas/extra-safe.schema.json ./docs/schemas/extra-safe.schema.json",
    ],
)
def test_complete_containerfile_instruction_sequence_rejects_injection(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    instruction: str,
) -> None:
    entries = _source_entries(source_bundle[0])
    container_index = next(
        index
        for index, item in enumerate(entries)
        if item[0] == producer.CONTAINERFILE_PATH
    )
    name, raw, mode, kind = entries[container_index]
    entries[container_index] = (
        name,
        raw + f"\n{instruction}\n".encode(),
        mode,
        kind,
    )
    if "extra-safe.schema.json" in instruction:
        entries.append(
            (
                "docs/schemas/extra-safe.schema.json",
                b"{}\n",
                0o644,
                "regular",
            )
        )
    entries = _rehash_manifest(entries)
    path = _write(tmp_path / "injected.tar", _tar(entries))

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="normalized instruction sequence drifted|invariant drifted",
    ):
        subject.derive_source_facts(path, source_commit)


def test_manifest_and_bundle_splicing_fail_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> None:
    entries = _source_entries(source_bundle[0])
    manifest = json.loads(entries[0][1])
    manifest["source_commit_sha"] = "f" * 40
    entries[0] = (
        entries[0][0],
        producer.canonical_json(manifest),
        entries[0][2],
        entries[0][3],
    )
    path = _write(tmp_path / "splice.tar", _tar(entries))

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="namespace",
    ):
        subject.derive_source_facts(path, source_commit)


def test_noncanonical_source_tar_and_size_limit_fail_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    noncanonical_path = _write(
        tmp_path / "noncanonical.tar",
        source_bundle[0] + bytes(512),
    )
    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="canonical USTAR",
    ):
        subject.derive_source_facts(noncanonical_path, source_commit)

    exact_path = _write(tmp_path / "oversize.tar", source_bundle[0])
    monkeypatch.setattr(subject, "MAX_SOURCE_BUNDLE_BYTES", 1)
    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="exceeds 1 byte",
    ):
        subject.derive_source_facts(exact_path, source_commit)


def test_source_bundle_changed_during_read_fails_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path = _write(tmp_path / "changing.tar", source_bundle[0])
    real_read = subject._read_fd
    calls = 0

    def changing_read(descriptor: int, limit: int, label: str) -> bytes:
        nonlocal calls
        raw = real_read(descriptor, limit, label)
        calls += 1
        if calls == 1:
            changed = bytes([raw[0] ^ 1]) + raw[1:]
            bundle_path.write_bytes(changed)
        return raw

    monkeypatch.setattr(subject, "_read_fd", changing_read)
    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="changed while being read",
    ):
        subject.derive_source_facts(bundle_path, source_commit)


@pytest.mark.parametrize(
    ("override", "error"),
    [
        ({"Entrypoint": ["/bin/sh"]}, "runtime config drifted"),
        ({"Env": ["PATH=/tmp"]}, "environment"),
        ({"Labels": {}}, "labels"),
        ({"User": "0:0"}, "runtime config drifted"),
    ],
)
def test_oci_config_drift_fails_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    override: dict[str, Any],
    error: str,
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    oci_raw, _image = _build_oci(
        source_facts,
        source_commit,
        config_override=override,
    )
    oci_path = _write(tmp_path / "drift.oci.tar", oci_raw)

    with pytest.raises(subject.QueryV3ImageAttestationError, match=error):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"opt/c-fast-t1/scripts/extra.py": b"extra"},
        {"opt/c-fast-t1/release-signer.py": b"signer"},
        {
            "tmp/key": (
                b"-----BEGIN PRIVATE KEY-----\n"
                b"not-a-real-key\n"
            )
        },
    ],
)
def test_oci_extra_runtime_or_sensitive_material_fails_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    extra: dict[str, bytes],
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    oci_raw, _image = _build_oci(
        source_facts,
        source_commit,
        runtime_extra=extra,
    )
    oci_path = _write(tmp_path / "extra.oci.tar", oci_raw)

    with pytest.raises(subject.QueryV3ImageAttestationError):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


@pytest.mark.parametrize(
    "path",
    [
        "usr/local/lib/python3.12/site-packages/00-evil.pth",
        "usr/local/lib/python3.12/site-packages/sitecustomize.py",
        "usr/local/lib/python3.12/site-packages/usercustomize.pyc",
    ],
)
def test_python_startup_hook_injection_fails_with_runtime_unchanged(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    path: str,
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    oci_raw, _image = _build_oci(
        source_facts,
        source_commit,
        runtime_extra={path: b"import os\nos.system('false')\n"},
    )
    oci_path = _write(tmp_path / "startup-hook.oci.tar", oci_raw)

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="startup closure",
    ):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


def test_unallowlisted_importable_site_package_fails_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    oci_raw, _image = _build_oci(
        source_facts,
        source_commit,
        runtime_extra={
            "usr/local/lib/python3.12/site-packages/evil_import.py": (
                b"raise RuntimeError('executed')\n"
            )
        },
    )
    oci_path = _write(tmp_path / "evil-import.oci.tar", oci_raw)

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="outside the frozen build delta",
    ):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


def test_hardlink_private_key_survives_source_whiteout_and_is_detected(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    root = "usr/local/lib/python3.12/site-packages/psycopg"
    private_path = f"{root}/temporary-material"
    alias_path = f"{root}/apparently-benign-data"
    private_raw = b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n"
    hardlink_layer = _tar(
        [
            (private_path, private_raw, 0o400, "regular"),
            (alias_path, private_path.encode(), 0o400, "hardlink"),
        ]
    )
    whiteout_layer = _tar(
        [(f"{root}/.wh.temporary-material", b"", 0o000, "regular")]
    )
    oci_raw, _image = _build_oci(
        source_facts,
        source_commit,
        extra_raw_layers=[hardlink_layer, whiteout_layer],
    )
    oci_path = _write(tmp_path / "hardlink-whiteout.oci.tar", oci_raw)

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="private-key material",
    ):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


def test_unpinned_base_rootfs_prefix_fails_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    oci_raw, _image = _build_oci(source_facts, source_commit)
    subject.BASE_ROOTFS_LAYER_DIGESTS = ("sha256:" + "f" * 64,)
    oci_path = _write(tmp_path / "wrong-base.oci.tar", oci_raw)

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="pinned linux/amd64 base image prefix",
    ):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


def test_runtime_file_unreadable_by_frozen_uid_fails_closed(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> None:
    bundle_path = _write(tmp_path / "bundle.tar", source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    target = next(iter(source_facts["runtime_bundle"])).removeprefix("/")
    oci_raw, _image = _build_oci(
        source_facts,
        source_commit,
        runtime_modes={target: 0o400},
    )
    oci_path = _write(tmp_path / "unreadable.oci.tar", oci_raw)

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="does not match source bundle",
    ):
        subject.derive_oci_facts(
            oci_path,
            source_commit,
            source_facts["runtime_bundle"],
        )


def test_unsigned_evidence_cannot_splice_bundle_or_oci_digest(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
) -> None:
    evidence_path, bundle_path, oci_path, evidence = _valid_artifacts(
        tmp_path,
        source_bundle,
        source_commit,
    )
    forged = copy.deepcopy(evidence)
    forged["source_bundle_archive_sha256"] = "0" * 64
    evidence_path.write_bytes(_json_bytes(forged))

    with pytest.raises(
        subject.QueryV3ImageAttestationError,
        match="source_bundle_archive_sha256",
    ):
        subject.verify_query_v3_image_evidence(
            evidence_path,
            bundle_path,
            oci_path,
            source_commit,
        )


def test_cli_has_no_source_root_and_output_is_private_create_only(
    tmp_path: Path,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
    source_commit: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path, bundle_path, oci_path, _evidence = _valid_artifacts(
        tmp_path,
        source_bundle,
        source_commit,
    )
    output = tmp_path / "attestation.json"
    args = [
        "--external-image-evidence",
        str(evidence_path),
        "--source-bundle-archive",
        str(bundle_path),
        "--oci-layout-archive",
        str(oci_path),
        "--expected-source-commit-sha",
        source_commit,
        "--output",
        str(output),
    ]
    monkeypatch.setattr(sys, "argv", ["verify_query_v3_image_attestation.py", *args])

    assert "--source-root" not in VERIFIER_PATH.read_text(encoding="utf-8")
    assert "subprocess" not in VERIFIER_PATH.read_text(encoding="utf-8")
    assert subject.main() == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert subject.main() == 2


def test_all_new_schemas_are_valid() -> None:
    for path in (
        subject.MANIFEST_SCHEMA_PATH,
        subject.EVIDENCE_SCHEMA_PATH,
        subject.ATTESTATION_SCHEMA_PATH,
    ):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
