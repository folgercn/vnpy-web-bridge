from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator, FormatChecker
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
V3_TEST_HELPER = (
    ROOT / "backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py"
)
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from c_fast_t1 import create_query_v4_source_bundle as v4_producer  # noqa: E402
from c_fast_t1 import create_query_v5_source_bundle as producer  # noqa: E402
from c_fast_t1 import verify_query_v4_image_attestation as query_v4  # noqa: E402
from c_fast_t1 import verify_query_v5_image_attestation as subject  # noqa: E402
import commodity_c_fast_t1_query_v5_image_attestation_launcher as runtime_launcher  # noqa: E402


PIN_SCHEMA = (
    ROOT / "docs/schemas/"
    "commodity-c-fast-t1-query-v5-image-attestation-pin-set-v1.schema.json"
)
PIN_TEMPLATE = (
    ROOT / "docs/operations/c-fast-t1-query-v5-image-attestation-pin-set.template.json"
)
BOOTSTRAP_TEMPLATE = (
    ROOT / "docs/operations/c-fast-t1-query-v5-image-attestation-bootstrap-pin.template"
)


@pytest.fixture(autouse=True)
def _verified_test_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = subject.QueryV5AttestationRuntimeIdentity(
        runtime_image_digest="sha256:" + "a" * 64,
        pin_manifest_sha256="b" * 64,
        launcher_sha256="c" * 64,
        verifier_sha256="d" * 64,
        query_v4_verifier_sha256="e" * 64,
        query_v4_delegate_sha256="f" * 64,
        query_v5_validator_sha256="1" * 64,
        query_v4_validator_sha256="2" * 64,
        bootstrap_pin_sha256="a" * 64,
        python_executable_path_sha256="3" * 64,
        python_executable_sha256="4" * 64,
        loaded_executable_sha256="4" * 64,
        python_runtime_root_path_sha256="b" * 64,
        python_runtime_closure_sha256="c" * 64,
        native_runtime_root_path_sha256="d" * 64,
        native_runtime_closure_sha256="e" * 64,
        source_root_path_sha256="5" * 64,
        source_root_identity_sha256="6" * 64,
        source_closure_manifest_sha256="7" * 64,
        bootstrap_source_closure_sha256="f" * 64,
        dependency_root_path_sha256="8" * 64,
        dependency_root_identity_sha256="9" * 64,
        dependency_closure_manifest_sha256="0" * 64,
        bootstrap_dependency_closure_sha256="1" * 64,
        isolated_flags_verified=True,
        pre_import_runtime_verified=True,
        source_closure_retained=True,
        immutable_runtime_verified=True,
    )
    monkeypatch.setattr(subject, "_ACTIVE_RUNTIME_IDENTITY", identity)
    monkeypatch.setattr(subject, "_ACTIVE_RUNTIME_REVALIDATOR", lambda: None)


@pytest.fixture(scope="module")
def isolated_runtime_fixture(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("query-v5-attestation-runtime")
    source_root = root / "release"
    for relative in {
        runtime_launcher.LAUNCHER_RELATIVE_PATH,
        *runtime_launcher.LOCAL_MODULE_PATHS.values(),
    }:
        source = ROOT / relative
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o644)
    launcher_path = source_root / runtime_launcher.LAUNCHER_RELATIVE_PATH
    python_path = root / "private-python"
    python_path.write_bytes(Path(sys.executable).resolve().read_bytes())
    python_path.chmod(0o555)
    installed_site_packages = Path(jsonschema.__file__).resolve().parents[1]
    dependency_root = root / "site-packages"
    dependency_root.mkdir()
    for package in (
        "attr",
        "attrs",
        "idna",
        "jsonschema",
        "jsonschema_specifications",
        "referencing",
        "rpds",
        "yaml",
    ):
        shutil.copytree(
            installed_site_packages / package,
            dependency_root / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
    shutil.copy2(
        installed_site_packages / "typing_extensions.py",
        dependency_root / "typing_extensions.py",
    )
    for copied in dependency_root.rglob("*"):
        copied.chmod(0o755 if copied.is_dir() else 0o644)
    dependency_root.chmod(0o755)
    source_identity = runtime_launcher.directory_identity_sha256(source_root)
    source_manifest, _retained = runtime_launcher.scan_source_closure(source_root)
    dependency_identity = runtime_launcher.directory_identity_sha256(dependency_root)
    dependency_manifest = runtime_launcher.scan_dependency_closure(dependency_root)
    local_hashes = {
        field: hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
        for field, relative in runtime_launcher.LOCAL_MODULE_PATHS.items()
    }
    pin_root = root / "pins"
    pin_root.mkdir()
    pin_path = pin_root / "pin-set.manifest.json"
    pins = {
        "schema_version": runtime_launcher.PIN_MANIFEST_VERSION,
        "generation_id": "query-v5-attestation-test-generation",
        "runtime_image_digest": "sha256:" + "a" * 64,
        "launcher_sha256": hashlib.sha256(launcher_path.read_bytes()).hexdigest(),
        **local_hashes,
        "python_executable_path": str(python_path),
        "python_executable_sha256": hashlib.sha256(
            python_path.read_bytes()
        ).hexdigest(),
        "bootstrap_pin_sha256": "a" * 64,
        "python_runtime_root_path": str(root),
        "python_runtime_closure_sha256": "b" * 64,
        "native_runtime_root_path": str(root),
        "native_runtime_closure_sha256": "c" * 64,
        "source_root_path": str(source_root),
        "source_root_identity_sha256": source_identity,
        "source_closure_manifest_sha256": source_manifest,
        "bootstrap_source_closure_sha256": "d" * 64,
        "dependency_root_path": str(dependency_root),
        "dependency_root_identity_sha256": dependency_identity,
        "dependency_closure_manifest_sha256": dependency_manifest,
        "bootstrap_dependency_closure_sha256": "e" * 64,
    }
    pin_path.write_bytes(runtime_launcher._canonical(pins))
    pin_path.chmod(0o444)
    return {
        "root": root,
        "source_root": source_root,
        "launcher": launcher_path,
        "python": python_path,
        "dependency_root": dependency_root,
        "pins": pin_path,
        "target": source_root / runtime_launcher.TARGET_RELATIVE_PATH,
    }


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _helper() -> Any:
    name = "_query_v5_composition_oci_test_helper"
    if name in sys.modules:
        helper = sys.modules[name]
    else:
        spec = importlib.util.spec_from_file_location(name, V3_TEST_HELPER)
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        sys.modules[name] = helper
        spec.loader.exec_module(helper)
    helper.subject = query_v4._delegate
    return helper


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _source_entries(bundle_raw: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(bundle_raw), mode="r:") as archive:
        for member in archive:
            if not member.isreg():
                continue
            stream = archive.extractfile(member)
            assert stream is not None
            result[member.name] = stream.read()
    return result


def _v4_evidence(
    source_facts: dict[str, Any],
    source_commit: str,
    image: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": query_v4.EVIDENCE_SCHEMA_VERSION,
        "capture_kind": "unsigned_external_query_v4_oci_layout_capture_v1",
        "captured_at": "2026-08-01T00:00:00Z",
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
            query_v4.canonical_json(source_facts["manifest"])
        ).hexdigest(),
        "build": {
            "platform": "linux/amd64",
            "context_kind": "exact_query_v4_source_bundle_v1",
            "containerfile_sha256": source_facts["containerfile_sha256"],
            "base_image_digest": query_v4._delegate.BASE_IMAGE_DIGEST,
            "direct_dependencies": query_v4._delegate.EXPECTED_DEPENDENCIES,
        },
        "image": image,
        "sensitive_material_present": False,
        "authority_granted": False,
    }


def _overlay_entries(
    source_facts: dict[str, Any],
) -> list[tuple[str, bytes, int, str]]:
    source_files = _source_entries(source_facts["bundle_raw"])
    launcher_source = "scripts/commodity_c_fast_t1_query_v5_launcher.py"
    return [
        ("opt/c-fast-query-v5", b"", 0o555, "directory"),
        ("opt/c-fast-query-v5/release", b"", 0o555, "directory"),
        ("opt/c-fast-query-v5/release/scripts", b"", 0o555, "directory"),
        (
            "opt/c-fast-query-v5/release/scripts/"
            "commodity_c_fast_t1_query_v5_launcher.py",
            source_files[launcher_source],
            0o444,
            "regular",
        ),
        ("run/c-fast-t1-query-v5-pins", b"", 0o555, "directory"),
    ]


def _tar_with_metadata(
    entries: list[tuple[str, bytes, int, str]],
    *,
    tar_format: int = tarfile.USTAR_FORMAT,
    global_pax: dict[str, str] | None = None,
    local_pax: dict[str, str] | None = None,
    uname: str = "",
    mtime: int = 0,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tar_format,
        pax_headers=global_pax,
    ) as archive:
        for name, raw, mode, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = uname
            member.gname = ""
            member.mtime = mtime
            member.pax_headers = dict(local_pax or {})
            if kind == "regular":
                member.size = len(raw)
                member.type = tarfile.REGTYPE
                archive.addfile(member, io.BytesIO(raw))
            elif kind == "directory":
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                raise AssertionError(kind)
    return output.getvalue()


def _scan_overlay(raw: bytes, source_facts: dict[str, Any]) -> set[str]:
    touched, _header_contract = subject._scan_overlay_layer(
        raw,
        "test overlay",
        set(),
        source_facts["runtime_bundle"],
        source_facts["runtime_modes"],
    )
    return touched


def test_overlay_allows_only_exact_existing_base_ancestor_directory_marker(
    tmp_path: Path,
    source_commit: str,
) -> None:
    bundle_raw = producer.build_source_bundle(ROOT, source_commit)[0]
    source_facts = subject._source_facts(
        _write(tmp_path / "query-v5-source.tar", bundle_raw),
        source_commit,
    )
    base_directory = subject._delegate.FileEntry(
        kind="directory",
        mode=0o755,
        uid=0,
        gid=0,
    )
    exact = _tar_with_metadata([("opt", b"", 0o755, "directory")])

    touched, _contract = subject._scan_overlay_layer(
        exact,
        "test overlay",
        {"opt"},
        source_facts["runtime_bundle"],
        source_facts["runtime_modes"],
        {"opt": base_directory},
    )
    assert touched == {"opt"}

    drifted = _tar_with_metadata([("opt", b"", 0o777, "directory")])
    with pytest.raises(
        subject.QueryV5ImageAttestationError,
        match="overwrites query-v4 base path",
    ):
        subject._scan_overlay_layer(
            drifted,
            "test overlay",
            {"opt"},
            source_facts["runtime_bundle"],
            source_facts["runtime_modes"],
            {"opt": base_directory},
        )


def _compose_oci(
    v4_oci_raw: bytes,
    v4_image_reference: str,
    source_facts: dict[str, Any],
    source_commit: str,
    *,
    overlay_entries: list[tuple[str, bytes, int, str]] | None = None,
    overlay_layers: list[list[tuple[str, bytes, int, str]]] | None = None,
    config_override: dict[str, Any] | None = None,
    config_document_override: dict[str, Any] | None = None,
    reverse_base_prefix: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    helper = _helper()
    files = subject._delegate._parse_oci_archive(v4_oci_raw)
    index = json.loads(files["index.json"])
    v4_manifest_descriptor = index["manifests"][0]
    v4_manifest_raw = subject._delegate._blob(
        files,
        v4_manifest_descriptor["digest"],
        v4_manifest_descriptor["size"],
        "synthetic query-v4 manifest",
    )
    v4_manifest = json.loads(v4_manifest_raw)
    v4_config_descriptor = v4_manifest["config"]
    v4_config_raw = subject._delegate._blob(
        files,
        v4_config_descriptor["digest"],
        v4_config_descriptor["size"],
        "synthetic query-v4 config",
    )
    v4_config_document = json.loads(v4_config_raw)
    assert not (overlay_entries is not None and overlay_layers is not None)
    entry_layers = overlay_layers or [overlay_entries or _overlay_entries(source_facts)]
    overlays: list[tuple[bytes, str, dict[str, Any]]] = []
    for entries in entry_layers:
        raw = helper._tar(entries)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        overlays.append(
            (
                raw,
                digest,
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": digest,
                    "size": len(raw),
                },
            )
        )
    base_layers = list(v4_manifest["layers"])
    base_diff_ids = list(v4_config_document["rootfs"]["diff_ids"])
    if reverse_base_prefix:
        base_layers.reverse()
        base_diff_ids.reverse()
    config = copy.deepcopy(v4_config_document["config"])
    config.update(
        {
            "User": "65532:65532",
            "WorkingDir": "/opt/c-fast-query-v5",
            "Entrypoint": subject.ENTRYPOINT,
            "Cmd": None,
            "Labels": {
                "io.vnpy-web-bridge.c-fast-t1.authority-granted": "false",
                "io.vnpy-web-bridge.c-fast-t1.query-v4-runtime": "true",
                "io.vnpy-web-bridge.c-fast-t1.query-v5-base-image": (
                    v4_image_reference
                ),
                "io.vnpy-web-bridge.c-fast-t1.query-v5-runtime": "true",
                "org.opencontainers.image.revision": source_commit,
                "org.opencontainers.image.title": subject.EXPECTED_LABEL_TITLE,
            },
        }
    )
    config.update(config_override or {})
    config_document = {
        "architecture": "amd64",
        "os": "linux",
        "config": config,
        "rootfs": {
            "type": "layers",
            "diff_ids": [*base_diff_ids, *[item[1] for item in overlays]],
        },
    }
    config_document.update(config_document_override or {})
    config_raw = _json_bytes(config_document)
    config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": subject._delegate.OCI_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": subject._delegate.OCI_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": len(config_raw),
        },
        "layers": [*base_layers, *[item[2] for item in overlays]],
    }
    manifest_raw = _json_bytes(manifest)
    manifest_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    final_index = {
        "schemaVersion": 2,
        "mediaType": subject._delegate.OCI_INDEX_MEDIA_TYPE,
        "manifests": [
            {
                "mediaType": subject._delegate.OCI_MANIFEST_MEDIA_TYPE,
                "digest": manifest_digest,
                "size": len(manifest_raw),
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    referenced_base_blobs = {
        "blobs/sha256/" + item["digest"].removeprefix("sha256:"): (
            subject._delegate._blob(
                files,
                item["digest"],
                item["size"],
                "synthetic query-v4 layer",
            )
        )
        for item in base_layers
    }
    blobs = {
        **referenced_base_blobs,
        **{
            "blobs/sha256/" + digest.removeprefix("sha256:"): raw
            for raw, digest, _descriptor in overlays
        },
        "blobs/sha256/" + config_digest.removeprefix("sha256:"): config_raw,
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"): manifest_raw,
    }
    archive_raw = helper._tar(
        [
            (
                "oci-layout",
                _json_bytes({"imageLayoutVersion": "1.0.0"}),
                0o644,
                "regular",
            ),
            ("index.json", _json_bytes(final_index), 0o644, "regular"),
            *[(path, raw, 0o644, "regular") for path, raw in sorted(blobs.items())],
        ]
    )
    relevant_environment = {
        item.split("=", 1)[0]: item.split("=", 1)[1] for item in config["Env"]
    }
    touched = sorted({"/" + entry[0] for entries in entry_layers for entry in entries})
    image = {
        "reference": f"registry.invalid/c-fast/query-v5@{manifest_digest}",
        "digest": manifest_digest,
        "id": config_digest,
        "export_sha256": hashlib.sha256(archive_raw).hexdigest(),
        "rootfs_layer_digests": [
            *[item["digest"] for item in base_layers],
            *[item[1] for item in overlays],
        ],
        "rootfs_diff_ids": [*base_diff_ids, *[item[1] for item in overlays]],
        "config": {
            "user": config["User"],
            "working_dir": config["WorkingDir"],
            "entrypoint": config["Entrypoint"],
            "relevant_environment": relevant_environment,
            "labels": config["Labels"],
        },
        "bundle_files": source_facts["runtime_bundle"],
        "overlay_touched_paths": touched,
        "forbidden_path_matches": [],
        "unexpected_bundle_paths": [],
        "signer_or_private_key_paths": [],
    }
    return archive_raw, image


def _v5_evidence(
    source_facts: dict[str, Any],
    source_commit: str,
    v4_report_raw: bytes,
    v4_report: dict[str, Any],
    v4_oci_raw: bytes,
    image: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": subject.EVIDENCE_SCHEMA_VERSION,
        "capture_kind": ("unsigned_external_query_v5_final_oci_composition_capture_v1"),
        "captured_at": "2026-08-01T00:01:00Z",
        "producer": {"tool": "pytest", "tool_version": "1"},
        "query_v4": {
            "content_attestation_raw_sha256": hashlib.sha256(v4_report_raw).hexdigest(),
            "content_attestation_canonical_sha256": hashlib.sha256(
                subject.canonical_json(v4_report)
            ).hexdigest(),
            "oci_layout_archive_sha256": hashlib.sha256(v4_oci_raw).hexdigest(),
            "image_reference": v4_report["image_reference"],
            "image_digest": v4_report["image_digest"],
            "image_id": v4_report["image_id"],
        },
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
            "context_kind": "exact_query_v5_source_bundle_v1",
            "containerfile_sha256": source_facts["containerfile_sha256"],
            "query_v4_base_image_reference": v4_report["image_reference"],
            "query_v4_base_image_digest": v4_report["image_digest"],
        },
        "image": image,
        "build_provenance_verified": False,
        "registry_provenance_verified": False,
        "image_built_here": False,
        "sensitive_material_present": False,
        "authority_granted": False,
    }


def _artifacts(
    tmp_path: Path,
    source_commit: str,
    *,
    overlay_entries: list[tuple[str, bytes, int, str]] | None = None,
    overlay_layers: list[list[tuple[str, bytes, int, str]]] | None = None,
    config_override: dict[str, Any] | None = None,
    config_document_override: dict[str, Any] | None = None,
    reverse_base_prefix: bool = False,
) -> dict[str, Any]:
    helper = _helper()
    v4_bundle_raw, _manifest_raw, _manifest = v4_producer.build_source_bundle(
        ROOT,
        source_commit,
    )
    v4_bundle_path = _write(tmp_path / "query-v4-source.tar", v4_bundle_raw)
    v4_source = query_v4.derive_source_facts(v4_bundle_path, source_commit)
    v4_oci_raw, v4_image = helper._build_oci(v4_source, source_commit)
    v4_image["reference"] = v4_image["reference"].replace(
        "query-v3@",
        "query-v4@",
    )
    v4_evidence = _v4_evidence(v4_source, source_commit, v4_image)
    v4_evidence_path = _write(
        tmp_path / "query-v4-evidence.json",
        _json_bytes(v4_evidence),
    )
    v4_oci_path = _write(tmp_path / "query-v4.oci.tar", v4_oci_raw)
    v4_report = query_v4.verify_query_v4_image_evidence(
        v4_evidence_path,
        v4_bundle_path,
        v4_oci_path,
        source_commit,
    )
    v4_report_raw = (json.dumps(v4_report, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    v4_report_path = _write(
        tmp_path / "query-v4-attestation.json",
        v4_report_raw,
    )
    bundle_raw, _v5_manifest_raw, _v5_manifest = producer.build_source_bundle(
        ROOT,
        source_commit,
    )
    bundle_path = _write(tmp_path / "query-v5-source.tar", bundle_raw)
    source_facts = subject._source_facts(bundle_path, source_commit)
    final_oci_raw, image = _compose_oci(
        v4_oci_raw,
        v4_report["image_reference"],
        source_facts,
        source_commit,
        overlay_entries=overlay_entries,
        overlay_layers=overlay_layers,
        config_override=config_override,
        config_document_override=config_document_override,
        reverse_base_prefix=reverse_base_prefix,
    )
    final_oci_path = _write(tmp_path / "query-v5.oci.tar", final_oci_raw)
    evidence = _v5_evidence(
        source_facts,
        source_commit,
        v4_report_raw,
        v4_report,
        v4_oci_raw,
        image,
    )
    evidence_path = _write(
        tmp_path / "query-v5-evidence.json",
        _json_bytes(evidence),
    )
    return {
        "v4_evidence": v4_evidence_path,
        "v4_bundle": v4_bundle_path,
        "v4_oci": v4_oci_path,
        "v4_report": v4_report_path,
        "bundle": bundle_path,
        "oci": final_oci_path,
        "evidence": evidence_path,
        "source_facts": source_facts,
    }


def _verify(artifacts: dict[str, Any], source_commit: str) -> dict[str, Any]:
    return subject.verify_query_v5_image_evidence(
        artifacts["v4_evidence"],
        artifacts["v4_bundle"],
        artifacts["v4_oci"],
        artifacts["v4_report"],
        source_commit,
        artifacts["evidence"],
        artifacts["bundle"],
        artifacts["oci"],
        source_commit,
    )


@pytest.fixture(scope="module")
def source_commit() -> str:
    return _git("rev-parse", "HEAD")


def test_exact_query_v4_prefix_and_query_v5_overlay_pass(
    tmp_path: Path,
    source_commit: str,
) -> None:
    artifacts = _artifacts(tmp_path, source_commit)
    report = _verify(artifacts, source_commit)

    assert report["status"] == subject.STATUS
    assert report["checks"]["query_v4_content_attestation_replayed"] is True
    assert report["checks"]["query_v4_layer_descriptor_prefix_verified"] is True
    assert report["checks"]["query_v4_diff_id_prefix_verified"] is True
    assert report["checks"]["all_overlay_layer_contents_sensitive_free"] is True
    assert report["checks"]["overlay_layers_strict_ustar_verified"] is True
    assert len(report["overlay_layer_header_contract_sha256"]) == 1
    assert report["checks"]["merged_python_execution_closure_frozen"] is True
    assert report["verifier_sha256"] == "d" * 64
    assert report["attestation_runtime"]["runtime_image_digest"] == (
        "sha256:" + "a" * 64
    )
    assert report["attestation_runtime"]["isolated_flags_verified"] is True
    assert report["attestation_runtime"]["pre_import_runtime_verified"] is True
    assert report["attestation_runtime"]["source_closure_retained"] is True
    assert report["image_built_here"] is False
    assert report["authority_granted"] is False
    assert report["network_authorized"] is False
    assert report["production_query_authorized"] is False

    output = tmp_path / "receipt.json"
    subject.write_create_only(output, report)
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(subject.QueryV5ImageAttestationError, match="cannot create"):
        subject.write_create_only(output, report)


def test_reordered_query_v4_prefix_is_rejected(
    tmp_path: Path,
    source_commit: str,
) -> None:
    artifacts = _artifacts(
        tmp_path,
        source_commit,
        reverse_base_prefix=True,
    )
    with pytest.raises(
        subject.QueryV5ImageAttestationError,
        match="layer descriptor prefix",
    ):
        _verify(artifacts, source_commit)


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        (
            (
                "opt/c-fast-query-v5/release/scripts/.wh.injected",
                b"",
                0o444,
                "regular",
            ),
            "whiteout",
        ),
        (
            ("usr/local/bin/python3.12", b"replacement", 0o555, "regular"),
            "overwrites query-v4 base path",
        ),
        (("tmp/injected", b"x", 0o444, "regular"), "outside overlay allowlist"),
        (
            (
                "opt/c-fast-query-v5/release/scripts/link.py",
                b"commodity_c_fast_t1_query_v5_launcher.py",
                0o444,
                "symlink",
            ),
            "special file",
        ),
        (
            (
                "opt/c-fast-query-v5/release/scripts/hardlink.py",
                b"opt/c-fast-query-v5/release/scripts/"
                b"commodity_c_fast_t1_query_v5_launcher.py",
                0o444,
                "hardlink",
            ),
            "special file",
        ),
        (
            (
                "opt/c-fast-query-v5/release/scripts/device",
                b"",
                0o444,
                "character",
            ),
            "special file",
        ),
    ],
)
def test_overlay_structural_attacks_fail_closed(
    tmp_path: Path,
    source_commit: str,
    entry: tuple[str, bytes, int, str],
    error: str,
) -> None:
    bundle_raw = producer.build_source_bundle(ROOT, source_commit)[0]
    bundle_path = _write(tmp_path / "seed-source.tar", bundle_raw)
    source_facts = subject._source_facts(bundle_path, source_commit)
    entries = [*_overlay_entries(source_facts), entry]
    artifacts = _artifacts(
        tmp_path,
        source_commit,
        overlay_entries=entries,
    )
    with pytest.raises(subject.QueryV5ImageAttestationError, match=error):
        _verify(artifacts, source_commit)


@pytest.mark.parametrize(
    ("attack_entry", "error"),
    [
        (
            (
                "opt/c-fast-query-v5/release/scripts/"
                "commodity_c_fast_t1_query_v5_launcher.py",
                b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n",
                0o444,
                "regular",
            ),
            "raw tar contains private-key material",
        ),
        (
            (
                "opt/c-fast-query-v5/release/scripts/"
                "commodity_c_fast_t1_query_v5_launcher.py",
                b"wrong launcher bytes\n",
                0o444,
                "regular",
            ),
            "does not match exact source",
        ),
        (
            ("opt/c-fast-query-v5/release", b"", 0o555, "regular"),
            "allowlisted directory entry is not exact",
        ),
    ],
)
def test_superseded_overlay_payload_or_type_fails_closed(
    tmp_path: Path,
    source_commit: str,
    attack_entry: tuple[str, bytes, int, str],
    error: str,
) -> None:
    bundle_raw = producer.build_source_bundle(ROOT, source_commit)[0]
    bundle_path = _write(tmp_path / "seed-source.tar", bundle_raw)
    source_facts = subject._source_facts(bundle_path, source_commit)
    artifacts = _artifacts(
        tmp_path,
        source_commit,
        overlay_layers=[[attack_entry], _overlay_entries(source_facts)],
    )

    final_state = subject._load_oci_state(artifacts["oci"], "test-final")
    launcher_path = next(
        path.removeprefix("/") for path in source_facts["runtime_bundle"]
    )
    assert (
        final_state["filesystem"][launcher_path].sha256
        == source_facts["runtime_bundle"]["/" + launcher_path]
    )

    with pytest.raises(subject.QueryV5ImageAttestationError, match=error):
        _verify(artifacts, source_commit)


def test_overlay_tar_hidden_metadata_and_trailing_bytes_fail_closed(
    tmp_path: Path,
    source_commit: str,
) -> None:
    bundle_raw = producer.build_source_bundle(ROOT, source_commit)[0]
    bundle_path = _write(tmp_path / "canonical-source.tar", bundle_raw)
    source_facts = subject._source_facts(bundle_path, source_commit)
    entries = _overlay_entries(source_facts)
    canonical = _tar_with_metadata(entries)
    with tarfile.open(fileobj=io.BytesIO(canonical), mode="r:") as archive:
        runtime = next(member for member in archive if member.isreg())
        padding_offset = runtime.offset_data + runtime.size
        runtime_header_offset = runtime.offset
    assert padding_offset % 512 != 0
    padding_payload = bytearray(canonical)
    padding_payload[padding_offset] = 1
    sparse_payload = bytearray(canonical)
    sparse_payload[runtime_header_offset + 156] = ord("S")
    sparse_payload[runtime_header_offset + 148 : runtime_header_offset + 156] = b" " * 8
    checksum = sum(sparse_payload[runtime_header_offset : runtime_header_offset + 512])
    sparse_payload[runtime_header_offset + 148 : runtime_header_offset + 156] = (
        f"{checksum:06o}\0 ".encode("ascii")
    )
    long_name = "opt/c-fast-query-v5/" + "x" * 180

    attacks = {
        "local PAX": _tar_with_metadata(
            entries,
            tar_format=tarfile.PAX_FORMAT,
            local_pax={"comment": "hidden-payload"},
        ),
        "global PAX": _tar_with_metadata(
            entries,
            tar_format=tarfile.PAX_FORMAT,
            global_pax={"comment": "hidden-payload"},
        ),
        "GNU longname": _tar_with_metadata(
            [(long_name, b"hidden", 0o444, "regular")],
            tar_format=tarfile.GNU_FORMAT,
        ),
        "GNU sparse metadata": bytes(sparse_payload),
        "unfrozen header": _tar_with_metadata(entries, uname="root"),
        "nonzero padding": bytes(padding_payload),
        "trailing payload": canonical + b"hidden-after-tar-eof",
    }
    for name, raw in attacks.items():
        with pytest.raises(subject.QueryV5ImageAttestationError) as captured:
            _scan_overlay(raw, source_facts)
        assert str(captured.value), name


def test_strict_ustar_accepts_bound_builder_mtime_and_zero_record_padding(
    tmp_path: Path,
    source_commit: str,
) -> None:
    bundle_raw = producer.build_source_bundle(ROOT, source_commit)[0]
    bundle_path = _write(tmp_path / "builder-source.tar", bundle_raw)
    source_facts = subject._source_facts(bundle_path, source_commit)
    raw = (
        _tar_with_metadata(
            _overlay_entries(source_facts),
            mtime=1_777_777_777,
        )
        + b"\0" * 1024
    )
    touched, header_contract = subject._scan_overlay_layer(
        raw,
        "builder-style overlay",
        set(),
        source_facts["runtime_bundle"],
        source_facts["runtime_modes"],
    )
    assert touched
    assert len(header_contract) == 64


@pytest.mark.parametrize(
    ("hidden_value", "error"),
    [
        (
            "-----BEGIN PRIVATE KEY-----\nnot-a-real-config-key\n",
            "OCI config contains private-key material",
        ),
        (
            "private_key=not-a-real-config-key",
            "OCI config contains sensitive material",
        ),
    ],
)
def test_sensitive_outer_config_history_fails_closed(
    tmp_path: Path,
    source_commit: str,
    hidden_value: str,
    error: str,
) -> None:
    artifacts = _artifacts(
        tmp_path,
        source_commit,
        config_document_override={"history": [{"author": hidden_value}]},
    )
    with pytest.raises(
        subject.QueryV5ImageAttestationError,
        match=error,
    ):
        _verify(artifacts, source_commit)


def test_base_label_and_entrypoint_drift_fail_closed(
    tmp_path: Path,
    source_commit: str,
) -> None:
    attacks = (
        ({"Entrypoint": ["/bin/sh"]}, "runtime config drifted"),
        ({"StopSignal": "SIGKILL"}, "inherited OCI config fields"),
        (
            {"Labels": {"io.vnpy-web-bridge.c-fast-t1.authority-granted": "false"}},
            "labels",
        ),
    )
    for number, (override, error) in enumerate(attacks):
        attack_root = tmp_path / str(number)
        attack_root.mkdir()
        artifacts = _artifacts(
            attack_root,
            source_commit,
            config_override=override,
        )
        with pytest.raises(subject.QueryV5ImageAttestationError, match=error):
            _verify(artifacts, source_commit)


def test_query_v4_attestation_and_external_claim_tamper_fail_closed(
    tmp_path: Path,
    source_commit: str,
) -> None:
    artifacts = _artifacts(tmp_path, source_commit)
    v4_report = json.loads(artifacts["v4_report"].read_text(encoding="utf-8"))
    v4_report["orders_sent"] = 1
    artifacts["v4_report"].write_text(
        json.dumps(v4_report, sort_keys=True),
        encoding="utf-8",
    )
    with pytest.raises(subject.QueryV5ImageAttestationError):
        _verify(artifacts, source_commit)

    clean_root = tmp_path / "claim"
    clean_root.mkdir()
    artifacts = _artifacts(clean_root, source_commit)
    evidence = json.loads(artifacts["evidence"].read_text(encoding="utf-8"))
    evidence["image"]["export_sha256"] = "0" * 64
    artifacts["evidence"].write_text(
        json.dumps(evidence, sort_keys=True),
        encoding="utf-8",
    )
    with pytest.raises(
        subject.QueryV5ImageAttestationError,
        match="export_sha256",
    ):
        _verify(artifacts, source_commit)


def test_query_v4_source_bundle_cannot_downgrade_query_v5_namespace(
    tmp_path: Path,
    source_commit: str,
) -> None:
    bundle_raw = v4_producer.build_source_bundle(ROOT, source_commit)[0]
    path = _write(tmp_path / "query-v4-as-v5.tar", bundle_raw)
    with pytest.raises(
        subject.QueryV5ImageAttestationError,
        match="first archive entry",
    ):
        subject._source_facts(path, source_commit)


@pytest.mark.parametrize(
    "schema_path",
    [
        subject.MANIFEST_SCHEMA_PATH,
        subject.EVIDENCE_SCHEMA_PATH,
        subject.ATTESTATION_SCHEMA_PATH,
    ],
)
def test_query_v5_schemas_are_strict_and_namespace_clean(
    schema_path: Path,
) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors({})
    )
    rendered = json.dumps(schema, sort_keys=True)
    assert "query-v3" not in rendered
    assert "query_v3" not in rendered


def test_external_evidence_template_is_schema_valid_and_non_authoritative() -> None:
    template_path = (
        ROOT / "docs/operations/"
        "c-fast-t1-query-v5-external-image-evidence.template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    schema = json.loads(subject.EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(template)
    )
    assert errors == []
    assert template["build_provenance_verified"] is False
    assert template["registry_provenance_verified"] is False
    assert template["image_built_here"] is False
    assert template["authority_granted"] is False


def test_runtime_pin_template_is_strict_and_non_authoritative() -> None:
    schema = json.loads(PIN_SCHEMA.read_text(encoding="utf-8"))
    template = json.loads(PIN_TEMPLATE.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert (
        list(
            Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            ).iter_errors(template)
        )
        == []
    )
    assert template["runtime_image_digest"].startswith("sha256:")
    assert "authority_granted" not in template


def test_preimport_bootstrap_hash_and_pin_template_are_self_contained() -> None:
    for raw in (b"", b"abc", bytes(range(256)), b"x" * 1000):
        assert (
            runtime_launcher._bootstrap_sha256(raw) == hashlib.sha256(raw).hexdigest()
        )
    raw = BOOTSTRAP_TEMPLATE.read_bytes()
    pins = runtime_launcher._bootstrap_parse_pin(raw)
    assert tuple(pins) == runtime_launcher.BOOTSTRAP_FIELDS
    assert pins["schema_version"] == runtime_launcher.BOOTSTRAP_SCHEMA_VERSION


def test_preimport_bootstrap_detects_stdlib_and_native_replacements_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    sentinel = tmp_path / "malicious-module-executed"
    payloads = {
        "json.py": f"open({str(sentinel)!r}, 'w').write('json')\n".encode(),
        "pathlib.py": f"open({str(sentinel)!r}, 'w').write('pathlib')\n".encode(),
        "tarfile.py": f"open({str(sentinel)!r}, 'w').write('tarfile')\n".encode(),
        "lib-dynload/_attack.so": b"native-extension-payload",
    }
    for relative, raw in payloads.items():
        path = runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    monkeypatch.setattr(runtime_launcher, "_bootstrap_safe", lambda *_a, **_k: None)
    trusted = runtime_launcher._bootstrap_tree_digest(str(runtime))
    for relative in payloads:
        path = runtime / relative
        original = path.read_bytes()
        path.write_bytes(original + b"tampered")
        assert runtime_launcher._bootstrap_tree_digest(str(runtime)) != trusted
        assert not sentinel.exists()
        path.write_bytes(original)


def test_production_entrypoints_are_launcher_only() -> None:
    assert tuple(inspect.signature(runtime_launcher.main).parameters) == ()
    direct_verifier = subprocess.run(
        [sys.executable, str(subject.VERIFIER_PATH), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    direct_launcher = subprocess.run(
        [
            sys.executable,
            str(ROOT / runtime_launcher.LAUNCHER_RELATIVE_PATH),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert direct_verifier.returncode != 0
    assert "requires the independently pinned isolated launcher" in (
        direct_verifier.stderr
    )
    assert direct_launcher.returncode != 0
    assert "-I -S -s -E -B" in direct_launcher.stderr


def test_isolated_launcher_uses_retained_sources_and_rejects_path_drift(
    isolated_runtime_fixture: dict[str, Path],
    tmp_path: Path,
) -> None:
    shadow_root = tmp_path / "shadow"
    shadow_package = shadow_root / "c_fast_t1"
    shadow_package.mkdir(parents=True)
    sentinel = tmp_path / "startup-hook-ran"
    (shadow_root / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    (shadow_package / "verify_query_v5_image_attestation.py").write_text(
        "raise RuntimeError('module shadow executed')\n",
        encoding="utf-8",
    )
    script = """
import importlib.util
from pathlib import Path
import sys

launcher_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("query_v5_attestation_test_launcher", launcher_path)
assert spec is not None and spec.loader is not None
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
identity, revalidate, retained, source_root, dependency_root = launcher._inspect_runtime(
    pin_manifest_path=Path(sys.argv[2]),
    launcher_path=launcher_path,
    reported_executable_path=Path(sys.argv[3]),
    loaded_executable_path=Path(sys.argv[3]),
    require_immutable=False,
)
target = Path(sys.argv[4])
original = target.read_bytes()
target.chmod(0o644)
target.write_bytes(b"raise RuntimeError('pre-import disk drift executed')\\n")
try:
    module = launcher._load_retained_target(retained, source_root, dependency_root)
    assert module.STATUS.startswith("QUERY_V5_BASE_AND_OVERLAY")
    assert identity["source_closure_retained"] is True
    target.write_bytes(original)
    revalidate()
    print("SELF_RESTORE_EXECUTED_RETAINED_BYTES")
    target.write_bytes(b"raise RuntimeError('post-import path drift')\\n")
    try:
        revalidate()
    except launcher.QueryV5AttestationLauncherError:
        print("POST_IMPORT_PATH_DRIFT_REJECTED")
    else:
        raise AssertionError("post-import path drift was accepted")
finally:
    target.write_bytes(original)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(shadow_root)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-s",
            "-E",
            "-B",
            "-c",
            script,
            str(isolated_runtime_fixture["launcher"]),
            str(isolated_runtime_fixture["pins"]),
            str(isolated_runtime_fixture["python"]),
            str(isolated_runtime_fixture["target"]),
        ],
        cwd=shadow_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "SELF_RESTORE_EXECUTED_RETAINED_BYTES" in completed.stdout
    assert "POST_IMPORT_PATH_DRIFT_REJECTED" in completed.stdout
    assert not sentinel.exists()


def test_dependency_closure_rejects_startup_hooks(tmp_path: Path) -> None:
    dependency_root = tmp_path / "site-packages"
    dependency_root.mkdir()
    (dependency_root / "sitecustomize.py").write_text(
        "raise RuntimeError('startup hook')\n",
        encoding="utf-8",
    )
    with pytest.raises(
        runtime_launcher.QueryV5AttestationLauncherError,
        match="startup hook is forbidden",
    ):
        runtime_launcher.scan_dependency_closure(dependency_root)
