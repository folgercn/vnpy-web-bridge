from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = (
    ROOT / "scripts/c_fast_t1/verify_image_attestation.py"
)
ATTESTATION_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-image-attestation-v1.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-external-image-evidence-v1.schema.json"
)

spec = importlib.util.spec_from_file_location(
    "c_fast_t1_verify_image_attestation",
    SCRIPT_PATH,
)
assert spec is not None and spec.loader is not None
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


@pytest.fixture(scope="module")
def source_sha() -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture(scope="module")
def source_facts(source_sha: str) -> dict[str, Any]:
    return subject.derive_source_facts(ROOT, source_sha)


def _valid_evidence(
    source_sha: str,
    source_facts: dict[str, Any],
) -> dict[str, Any]:
    image_digest = "sha256:" + "4" * 64
    return {
        "schema_version": (
            "commodity_c_fast_t1_external_image_evidence_v1"
        ),
        "capture_kind": "registry_manifest_and_image_export_v1",
        "captured_at": "2026-07-25T00:00:00Z",
        "producer": {
            "tool": "test-oci-inspector",
            "tool_version": "1.0.0",
        },
        "source_commit_sha": source_sha,
        "source_archive_sha256": source_facts[
            "source_archive_sha256"
        ],
        "build": {
            "platform": "linux/amd64",
            "context_root": ".",
            "containerfile_sha256": source_facts[
                "containerfile_sha256"
            ],
            "base_image_digest": source_facts[
                "base_image_digest"
            ],
            "direct_dependencies": copy.deepcopy(
                subject.EXPECTED_DEPENDENCIES
            ),
        },
        "image": {
            "reference": (
                "registry.example/c-fast-t1@" + image_digest
            ),
            "digest": image_digest,
            "id": "sha256:" + "6" * 64,
            "export_sha256": "5" * 64,
            "rootfs_layer_digests": [
                "sha256:" + "7" * 64,
                "sha256:" + "8" * 64,
            ],
            "config": {
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
            },
            "bundle_files": copy.deepcopy(
                source_facts["bundle_files"]
            ),
            "forbidden_path_matches": [],
            "unexpected_bundle_paths": [],
            "signer_or_private_key_paths": [],
        },
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
    source_sha: str,
) -> dict[str, Any]:
    evidence_path = tmp_path / "evidence.json"
    _write_json(evidence_path, payload)
    return subject.verify_image_evidence(
        evidence_path,
        ROOT,
        source_sha,
    )


def test_valid_external_evidence_passes_both_schemas(
    tmp_path: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    evidence = _valid_evidence(source_sha, source_facts)
    report = _verify(tmp_path, evidence, source_sha)
    evidence_schema = json.loads(
        EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    attestation_schema = json.loads(
        ATTESTATION_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(evidence_schema)
    Draft202012Validator.check_schema(attestation_schema)

    assert list(
        Draft202012Validator(
            evidence_schema,
            format_checker=FormatChecker(),
        ).iter_errors(evidence)
    ) == []
    assert list(
        Draft202012Validator(
            attestation_schema,
            format_checker=FormatChecker(),
        ).iter_errors(report)
    ) == []
    assert (
        report["status"]
        == "EXTERNAL_BUILD_EVIDENCE_VERIFIED_NOT_IMAGE_BUILT_HERE"
    )
    assert report["source_commit_sha"] == source_sha
    assert report["image_built_here"] is False
    assert report["authority_granted"] is False
    assert report["production_query_authorized"] is False
    assert report["execution_quality_collection_authorized"] is False
    assert report["orders_sent"] == 0
    assert report["positions_modified"] == 0


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda value: value["image"].update(
                {
                    "reference": (
                        "registry.example/c-fast-t1:mutable"
                    )
                }
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["image"]["config"].update(
                {"user": "0:0"}
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["image"]["config"].update(
                {"entrypoint": ["/bin/sh"]}
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["image"]["config"]["labels"].update(
                {"org.opencontainers.image.revision": "a" * 40}
            ),
            "OCI labels does not match exact source",
        ),
        (
            lambda value: value["image"].update(
                {
                    "signer_or_private_key_paths": [
                        "/opt/c-fast-t1/release-signing.key"
                    ]
                }
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["image"].update(
                {
                    "rootfs_layer_digests": [
                        "sha256:" + "7" * 64,
                        "sha256:" + "7" * 64,
                    ]
                }
            ),
            "rootfs layer digests must be unique",
        ),
    ],
)
def test_rejects_unsafe_image_evidence(
    tmp_path: Path,
    source_sha: str,
    source_facts: dict[str, Any],
    mutate: Any,
    match: str,
) -> None:
    evidence = _valid_evidence(source_sha, source_facts)
    mutate(evidence)

    with pytest.raises(subject.ImageAttestationError, match=match):
        _verify(tmp_path, evidence, source_sha)


def test_rejects_runtime_bundle_hash_drift(
    tmp_path: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    evidence = _valid_evidence(source_sha, source_facts)
    first = next(iter(evidence["image"]["bundle_files"]))
    evidence["image"]["bundle_files"][first] = "9" * 64

    with pytest.raises(
        subject.ImageAttestationError,
        match="runtime bundle hashes does not match exact source",
    ):
        _verify(tmp_path, evidence, source_sha)


def test_rejects_image_reference_digest_mismatch(
    tmp_path: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    evidence = _valid_evidence(source_sha, source_facts)
    evidence["image"]["digest"] = "sha256:" + "9" * 64

    with pytest.raises(
        subject.ImageAttestationError,
        match="immutable image reference digest",
    ):
        _verify(tmp_path, evidence, source_sha)


def test_rejects_wrong_expected_source_commit(
    tmp_path: Path,
    source_sha: str,
    source_facts: dict[str, Any],
) -> None:
    evidence = _valid_evidence(source_sha, source_facts)
    evidence_path = tmp_path / "evidence.json"
    _write_json(evidence_path, evidence)

    with pytest.raises(
        subject.ImageAttestationError,
        match="expected source commit",
    ):
        subject.verify_image_evidence(
            evidence_path,
            ROOT,
            "f" * 40,
        )


def test_rejects_duplicate_json_key(
    tmp_path: Path,
    source_sha: str,
) -> None:
    evidence_path = tmp_path / "duplicate.json"
    evidence_path.write_text(
        '{"schema_version":"a","schema_version":"b"}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        subject.ImageAttestationError,
        match="duplicate JSON key",
    ):
        subject.verify_image_evidence(
            evidence_path,
            ROOT,
            source_sha,
        )


def test_rejects_non_finite_json(
    tmp_path: Path,
    source_sha: str,
) -> None:
    evidence_path = tmp_path / "nan.json"
    evidence_path.write_text('{"value":NaN}\n', encoding="utf-8")

    with pytest.raises(
        subject.ImageAttestationError,
        match="non-finite JSON value",
    ):
        subject.verify_image_evidence(
            evidence_path,
            ROOT,
            source_sha,
        )


def test_rejects_symlinked_evidence(
    tmp_path: Path,
    source_sha: str,
) -> None:
    target = tmp_path / "real.json"
    target.write_text("{}\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.symlink_to(target)

    with pytest.raises(
        subject.ImageAttestationError,
        match="must not be a symlink",
    ):
        subject.verify_image_evidence(evidence, ROOT, source_sha)


def test_rejects_symlink_blob_in_source_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "-q", str(repository)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "test@example.invalid",
        ],
        check=True,
    )
    (repository / "real.txt").write_text("real\n", encoding="utf-8")
    (repository / "linked.txt").symlink_to("real.txt")
    subprocess.run(
        ["git", "-C", str(repository), "add", "real.txt", "linked.txt"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
        check=True,
    )
    commit_sha = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    with pytest.raises(
        subject.ImageAttestationError,
        match="must be an exact regular blob",
    ):
        subject._git_blob(repository, commit_sha, "linked.txt")


def test_rejects_read_time_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"schema_version":"x"}\n')
    real_read = os.read
    calls = 0

    def changing_read(descriptor: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        raw = real_read(descriptor, size)
        if calls == 2:
            return raw + b" "
        return raw

    monkeypatch.setattr(subject.os, "read", changing_read)

    with pytest.raises(
        subject.ImageAttestationError,
        match="changed while being read",
    ):
        subject._read_regular_file(evidence, "external image evidence")


def test_cli_output_is_create_only_and_private(
    tmp_path: Path,
    source_sha: str,
    source_facts: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "attestation.json"
    _write_json(
        evidence_path,
        _valid_evidence(source_sha, source_facts),
    )
    args = [
        "--evidence",
        str(evidence_path),
        "--source-root",
        str(ROOT),
        "--expected-source-commit-sha",
        source_sha,
        "--json-output",
        str(output_path),
    ]

    assert subject.main(args) == 0
    assert subject.main(args) == 2
    assert stat_mode(output_path) == 0o600
    assert (
        "cannot create image attestation output"
        in capsys.readouterr().err
    )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
