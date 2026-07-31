from __future__ import annotations

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
SCRIPTS = ROOT / "scripts"
V3_TEST_HELPER = (
    ROOT
    / "backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py"
)
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from c_fast_t1 import create_query_v3_source_bundle as v3_producer  # noqa: E402
from c_fast_t1 import create_query_v4_source_bundle as producer  # noqa: E402
from c_fast_t1 import verify_query_v3_image_attestation as v3_subject  # noqa: E402
from c_fast_t1 import verify_query_v4_image_attestation as subject  # noqa: E402
from c_fast_t1.validate_query_v4_runtime import (  # noqa: E402
    EXPECTED_COPY_SOURCES,
)


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _oci_helper() -> Any:
    name = "_query_v4_oci_test_helper"
    if name in sys.modules:
        helper = sys.modules[name]
    else:
        spec = importlib.util.spec_from_file_location(name, V3_TEST_HELPER)
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        sys.modules[name] = helper
        spec.loader.exec_module(helper)
    helper.subject = subject._delegate
    return helper


def _permission_override_layer(
    path: str,
    content: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    directory: bool = False,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        member = tarfile.TarInfo(path)
        member.mode = mode
        member.uid = uid
        member.gid = gid
        member.uname = ""
        member.gname = ""
        member.mtime = 0
        if directory:
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        else:
            member.type = tarfile.REGTYPE
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _link_override_layer(
    path: str,
    target: str,
    *,
    hardlink: bool = False,
    target_files: dict[str, tuple[bytes, int]] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for target_path, (content, mode) in sorted(
            (target_files or {}).items()
        ):
            member = tarfile.TarInfo(target_path)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            member.type = tarfile.REGTYPE
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        member = tarfile.TarInfo(path)
        member.mode = 0o444
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        member.mtime = 0
        member.type = tarfile.LNKTYPE if hardlink else tarfile.SYMTYPE
        member.linkname = target
        archive.addfile(member)
    return output.getvalue()


@pytest.fixture(scope="module")
def source_commit() -> str:
    return _git("rev-parse", "HEAD")


@pytest.fixture(scope="module")
def source_bundle(
    source_commit: str,
) -> tuple[bytes, bytes, dict[str, Any]]:
    return producer.build_source_bundle(ROOT, source_commit)


def test_query_v4_source_bundle_is_exact_deterministic_commit_content(
    source_commit: str,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
) -> None:
    bundle_raw, manifest_raw, manifest = source_bundle
    repeated = producer.build_source_bundle(ROOT, source_commit)

    assert repeated[0] == bundle_raw
    assert repeated[1] == manifest_raw
    assert repeated[2] == manifest
    assert manifest["schema_version"] == producer.SCHEMA_VERSION
    assert manifest["runtime_kind"] == producer.RUNTIME_KIND
    assert manifest["source_commit_sha"] == source_commit
    assert manifest["manifest_id"].startswith(
        producer.MANIFEST_ID_PREFIX
    )
    assert {entry["path"] for entry in manifest["entries"]} == {
        producer.CONTAINERFILE_PATH,
        *EXPECTED_COPY_SOURCES,
    }
    assert manifest["authority_granted"] is False


def test_query_v4_source_bundle_is_canonical_and_runtime_verifiable(
    tmp_path: Path,
    source_commit: str,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
) -> None:
    bundle_raw, manifest_raw, manifest = source_bundle
    bundle_path = tmp_path / "query-v4-source.tar"
    bundle_path.write_bytes(bundle_raw)

    facts = subject.derive_source_facts(bundle_path, source_commit)

    assert facts["manifest"] == manifest
    assert facts["manifest_raw"] == manifest_raw
    assert facts["containerfile_sha256"] == next(
        entry["sha256"]
        for entry in manifest["entries"]
        if entry["path"] == producer.CONTAINERFILE_PATH
    )
    assert facts["runtime_bundle"]
    assert hashlib.sha256(bundle_raw).hexdigest() == (
        hashlib.sha256(facts["bundle_raw"]).hexdigest()
    )
    with tarfile.open(bundle_path, mode="r:") as archive:
        assert archive.getnames()[0] == producer.MANIFEST_ARCHIVE_PATH


def test_v3_runtime_rejects_query_v4_bundle_without_namespace_downgrade(
    tmp_path: Path,
    source_commit: str,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
) -> None:
    bundle_path = tmp_path / "query-v4-source.tar"
    bundle_path.write_bytes(source_bundle[0])

    with pytest.raises(
        v3_subject.QueryV3ImageAttestationError,
        match="first archive entry",
    ):
        v3_subject.derive_source_facts(bundle_path, source_commit)


def test_query_v4_exact_bundle_and_synthetic_oci_pass_full_verifier(
    tmp_path: Path,
    source_commit: str,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
) -> None:
    helper = _oci_helper()

    bundle_path = tmp_path / "query-v4-source.tar"
    bundle_path.write_bytes(source_bundle[0])
    source_facts = subject.derive_source_facts(
        bundle_path,
        source_commit,
    )
    oci_raw, image = helper._build_oci(source_facts, source_commit)
    image["reference"] = image["reference"].replace(
        "query-v3@",
        "query-v4@",
    )
    evidence = {
        "schema_version": subject.EVIDENCE_SCHEMA_VERSION,
        "capture_kind": (
            "unsigned_external_query_v4_oci_layout_capture_v1"
        ),
        "captured_at": "2026-07-31T03:00:00Z",
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
            "context_kind": "exact_query_v4_source_bundle_v1",
            "containerfile_sha256": source_facts[
                "containerfile_sha256"
            ],
            "base_image_digest": subject._delegate.BASE_IMAGE_DIGEST,
            "direct_dependencies": subject._delegate.EXPECTED_DEPENDENCIES,
        },
        "image": image,
        "sensitive_material_present": False,
        "authority_granted": False,
    }
    evidence_path = tmp_path / "query-v4-evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, sort_keys=True),
        encoding="utf-8",
    )
    oci_path = tmp_path / "query-v4-runtime.oci.tar"
    oci_path.write_bytes(oci_raw)

    report = subject.verify_query_v4_image_evidence(
        evidence_path,
        bundle_path,
        oci_path,
        source_commit,
    )

    assert report["schema_version"] == subject.SCHEMA_VERSION
    assert report["status"] == subject.STATUS
    assert report["source_commit_sha"] == source_commit
    assert report["image_digest"] == evidence["image"]["digest"]
    assert len(report["delegate_verifier_sha256"]) == 64
    assert report["checks"]["runtime_bundle_matches_source_bundle"] is True
    assert report["authority_granted"] is False
    assert report["production_query_authorized"] is False


def test_query_v4_rejects_runtime_and_python_closure_writable_by_runtime(
    tmp_path: Path,
    source_commit: str,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
) -> None:
    helper = _oci_helper()
    bundle_path = tmp_path / "query-v4-source.tar"
    bundle_path.write_bytes(source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    bundle_entries = {
        name: raw
        for name, raw, _mode, _kind in helper._source_entries(
            source_facts["bundle_raw"]
        )[1:]
    }
    runtime_script = (
        "opt/c-fast-t1/scripts/commodity_c_fast_t1_query_v4.py"
    )
    runtime_schema = next(
        path
        for path in sorted(
            item.removeprefix("/")
            for item in source_facts["runtime_bundle"]
        )
        if path.endswith(".schema.json")
    )
    dependency_module = (
        "usr/local/lib/python3.12/site-packages/"
        "attrs/__init__.py"
    )
    attacks = (
        (
            runtime_script,
            bundle_entries[
                runtime_script.removeprefix("opt/c-fast-t1/")
            ],
            0o777,
            65532,
            65532,
            False,
            "runtime file",
        ),
        (
            runtime_schema,
            bundle_entries[
                runtime_schema.removeprefix("opt/c-fast-t1/")
            ],
            0o666,
            0,
            0,
            False,
            "runtime file",
        ),
        (
            "opt/c-fast-t1/scripts",
            b"",
            0o755,
            65532,
            65532,
            True,
            "runtime directory",
        ),
        (
            dependency_module,
            b"# synthetic dependency module\n",
            0o666,
            0,
            0,
            False,
            "Python execution closure",
        ),
        (
            "opt/c-fast-t1/writable-injection",
            b"",
            0o777,
            65532,
            65532,
            True,
            "runtime directory",
        ),
    )
    for index, (
        path,
        content,
        mode,
        uid,
        gid,
        directory,
        error,
    ) in enumerate(attacks):
        attack_layer = _permission_override_layer(
            path,
            content,
            mode=mode,
            uid=uid,
            gid=gid,
            directory=directory,
        )
        oci_raw, _image = helper._build_oci(
            source_facts,
            source_commit,
            extra_raw_layers=[attack_layer],
        )
        oci_path = tmp_path / f"writable-{index}.oci.tar"
        oci_path.write_bytes(oci_raw)

        with pytest.raises(
            subject.QueryV4ImageAttestationError,
            match=error,
        ):
            subject.derive_oci_facts(
                oci_path,
                source_commit,
                source_facts["runtime_bundle"],
            )


def test_query_v4_rejects_python_execution_closure_links(
    tmp_path: Path,
    source_commit: str,
    source_bundle: tuple[bytes, bytes, dict[str, Any]],
) -> None:
    helper = _oci_helper()
    bundle_path = tmp_path / "query-v4-source.tar"
    bundle_path.write_bytes(source_bundle[0])
    source_facts = subject.derive_source_facts(bundle_path, source_commit)
    site_packages = "usr/local/lib/python3.12/site-packages"
    dependency_file = f"{site_packages}/psycopg/__init__.py"
    runtime_script = next(
        path.removeprefix("/")
        for path in source_facts["runtime_bundle"]
        if path.endswith("commodity_c_fast_t1_query_v4.py")
    )
    writable_target = f"{site_packages}/psycopg/writable_target.py"
    attacks = (
        (
            "dependency-absolute-escape",
            dependency_file,
            "/tmp/psycopg.py",
            False,
            {},
        ),
        (
            "package-directory-escape",
            f"{site_packages}/psycopg",
            "../../../../../tmp/psycopg",
            False,
            {},
        ),
        (
            "dependency-missing-target",
            dependency_file,
            "missing.py",
            False,
            {},
        ),
        (
            "dependency-writable-target",
            dependency_file,
            "writable_target.py",
            False,
            {writable_target: (b"raise RuntimeError('mutable')\n", 0o666)},
        ),
        (
            "dependency-cross-closure-hardlink",
            dependency_file,
            runtime_script,
            True,
            {},
        ),
    )
    for label, path, target, hardlink, target_files in attacks:
        attack_layer = _link_override_layer(
            path,
            target,
            hardlink=hardlink,
            target_files=target_files,
        )
        oci_raw, _image = helper._build_oci(
            source_facts,
            source_commit,
            extra_raw_layers=[attack_layer],
        )
        oci_path = tmp_path / f"{label}.oci.tar"
        oci_path.write_bytes(oci_raw)

        with pytest.raises(
            subject.QueryV4ImageAttestationError,
            match="Python execution closure cannot contain",
        ):
            subject.derive_oci_facts(
                oci_path,
                source_commit,
                source_facts["runtime_bundle"],
            )


def test_v4_delegate_configuration_does_not_mutate_v3_contract() -> None:
    assert subject._delegate is not v3_subject
    assert (
        subject._delegate.MANIFEST_SCHEMA_VERSION
        == subject.MANIFEST_SCHEMA_VERSION
    )
    assert (
        v3_subject.MANIFEST_SCHEMA_VERSION
        == "commodity_c_fast_t1_query_v3_source_manifest_v1"
    )
    assert subject._delegate.ENTRYPOINT[-1].endswith("_query_v4.py")
    assert v3_subject.ENTRYPOINT[-1].endswith("_query_v3.py")
    assert subject._delegate.RUNTIME_PTH_PATH.endswith(
        "query-v4-runtime.pth"
    )
    assert v3_subject.RUNTIME_PTH_PATH.endswith("query-v3-runtime.pth")


@pytest.mark.parametrize(
    "schema_path",
    [
        producer.SCHEMA_PATH,
        subject.EVIDENCE_SCHEMA_PATH,
        subject.ATTESTATION_SCHEMA_PATH,
    ],
)
def test_query_v4_schemas_are_valid_and_namespace_clean(
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


def test_v4_source_bundle_rejects_v3_containerfile(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        producer.SourceBundleError,
        match="source commit",
    ):
        producer.build_source_bundle(tmp_path, "0" * 40)

    assert (
        v3_producer.CONTAINERFILE_PATH
        != producer.CONTAINERFILE_PATH
    )
