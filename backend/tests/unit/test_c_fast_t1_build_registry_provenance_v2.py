from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_t1_build_registry_provenance_v2 as subject  # noqa: E402
import commodity_c_fast_t1_build_registry_provenance_sign_v2 as signer  # noqa: E402


NOW = datetime(2026, 7, 29, 1, 0, tzinfo=timezone.utc)
RUNTIME_COMMIT = "a" * 40
SIGNER_COMMIT = "b" * 40
IMAGE_DIGEST = "sha256:" + "c" * 64
IMAGE_ID = "sha256:" + "d" * 64
REPOSITORY = "registry.example.invalid/research/c-fast-query-v3"
IMAGE_REFERENCE = f"{REPOSITORY}@{IMAGE_DIGEST}"
TEMPLATE_PATH = (
    ROOT
    / "docs/operations/"
    "c-fast-t1-build-registry-provenance-v2.template.json"
)
V1_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-build-registry-provenance-v1.schema.json"
)


def canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def write_bytes(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    return write_bytes(path, canonical_bytes(payload))


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def public_key_sha256(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def keyring_for(
    private_key: Ed25519PrivateKey,
    *,
    schema_version: str = subject.KEYRING_VERSION,
    purpose: str = subject.KEY_PURPOSE,
    key_id: str = "c-fast-t1-provenance-v2-key-a01",
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "keys": [
            {
                "key_id": key_id,
                "purpose": purpose,
                "public_key_base64": public_key_base64(private_key),
            }
        ],
    }


def install_stacked_content_fixtures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    content_schema = write_json(
        tmp_path / "query-v3-attestation.schema.json",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
        },
    )
    manifest_schema = write_json(
        tmp_path / "query-v3-source-manifest.schema.json",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
        },
    )
    content_verifier = write_bytes(
        tmp_path / "verify_query_v3_image_attestation.py",
        b"# stacked Issue 155 verifier fixture\n",
    )
    monkeypatch.setattr(
        subject,
        "CONTENT_ATTESTATION_SCHEMA_PATH",
        content_schema,
    )
    monkeypatch.setattr(
        subject,
        "SOURCE_MANIFEST_SCHEMA_PATH",
        manifest_schema,
    )
    monkeypatch.setattr(
        subject,
        "CONTENT_VERIFIER_PATH",
        content_verifier,
    )


def valid_content() -> dict[str, Any]:
    runtime_bundle = {
        "scripts/commodity_c_fast_t1_query_v3.py": "1" * 64,
        "scripts/commodity_c_fast_t1_query_child_v3.py": "2" * 64,
    }
    return {
        "schema_version": subject.CONTENT_ATTESTATION_SCHEMA_VERSION,
        "evidence_captured_at": "2026-07-29T00:07:00Z",
        "source_commit_sha": RUNTIME_COMMIT,
        "source_bundle_archive_sha256": "3" * 64,
        "source_manifest_raw_sha256": "4" * 64,
        "source_manifest_canonical_sha256": "5" * 64,
        "source_manifest_schema_sha256": hashlib.sha256(
            subject.SOURCE_MANIFEST_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "containerfile_sha256": "6" * 64,
        "verifier_sha256": hashlib.sha256(
            subject.CONTENT_VERIFIER_PATH.read_bytes()
        ).hexdigest(),
        "attestation_schema_sha256": hashlib.sha256(
            subject.CONTENT_ATTESTATION_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "oci_layout_archive_sha256": "7" * 64,
        "image_reference": IMAGE_REFERENCE,
        "image_digest": IMAGE_DIGEST,
        "image_id": IMAGE_ID,
        "runtime_bundle_sha256": runtime_bundle,
        "runtime_bundle_index_sha256": hashlib.sha256(
            canonical_bytes(runtime_bundle)
        ).hexdigest(),
    }


def valid_draft(
    content_raw: bytes,
    content: dict[str, Any],
    keyring_sha256: str,
    excluded_hashes: list[str],
    excluded_keyring_hashes: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": subject.SCHEMA_VERSION,
        "provenance_id": "c-fast-t1-query-v3-provenance-a01",
        "candidate_id": subject.CANDIDATE_ID,
        "purpose": subject.PURPOSE,
        "issued_at": "2026-07-29T00:09:00Z",
        "signer_key_id": "c-fast-t1-provenance-v2-key-a01",
        "trusted_keyring_sha256": keyring_sha256,
        "excluded_authority_keyring_sha256s": (
            excluded_keyring_hashes
        ),
        "excluded_authority_public_key_sha256s": excluded_hashes,
        "runtime_source_commit_sha": RUNTIME_COMMIT,
        "content_attestation_raw_sha256": hashlib.sha256(
            content_raw
        ).hexdigest(),
        "content_attestation_canonical_sha256": hashlib.sha256(
            canonical_bytes(content)
        ).hexdigest(),
        "source_bundle_archive_sha256": content[
            "source_bundle_archive_sha256"
        ],
        "source_manifest_raw_sha256": content[
            "source_manifest_raw_sha256"
        ],
        "source_manifest_canonical_sha256": content[
            "source_manifest_canonical_sha256"
        ],
        "oci_layout_archive_sha256": content[
            "oci_layout_archive_sha256"
        ],
        "containerfile_sha256": content["containerfile_sha256"],
        "image_reference": content["image_reference"],
        "image_digest": content["image_digest"],
        "image_id": content["image_id"],
        "runtime_bundle_index_sha256": content[
            "runtime_bundle_index_sha256"
        ],
        "build": {
            "builder_identity_sha256": "8" * 64,
            "build_invocation_sha256": "9" * 64,
            "build_log_archive_sha256": "0" * 64,
            "platform": "linux/amd64",
            "started_at": "2026-07-29T00:00:00Z",
            "completed_at": "2026-07-29T00:05:00Z",
            "exact_source_archive_used": True,
            "exact_containerfile_used": True,
            "build_exit_code": 0,
            "output_oci_layout_archive_sha256": content[
                "oci_layout_archive_sha256"
            ],
            "output_image_digest": content["image_digest"],
            "output_image_id": content["image_id"],
            "reproducible_build_verified": False,
            "sensitive_material_present": False,
        },
        "registry": {
            "registry_identity_sha256": "a" * 64,
            "repository": REPOSITORY,
            "immutable_reference": content["image_reference"],
            "manifest_digest": content["image_digest"],
            "push_receipt_sha256": "b" * 64,
            "pushed_at": "2026-07-29T00:06:00Z",
            "observed_at": "2026-07-29T00:08:00Z",
            "digest_reference_resolved": True,
            "manifest_digest_matched": True,
            "mutable_tag_trusted": False,
            "sensitive_material_present": False,
        },
        "external_fact_scope": subject.EXTERNAL_FACT_SCOPE,
        **{field: False for field in subject.FALSE_AUTHORITY_FIELDS},
        **{field: 0 for field in subject.ZERO_FACT_FIELDS},
    }


def signed_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    provenance_key: Ed25519PrivateKey | None = None,
    excluded_hashes: list[str] | None = None,
) -> dict[str, Any]:
    install_stacked_content_fixtures(monkeypatch, tmp_path)
    private_key = provenance_key or Ed25519PrivateKey.generate()
    keyring = keyring_for(private_key)
    keyring_sha256 = hashlib.sha256(canonical_bytes(keyring)).hexdigest()
    content = valid_content()
    content_raw = canonical_bytes(content)
    t1_key = Ed25519PrivateKey.generate()
    l3_key = Ed25519PrivateKey.generate()
    authority_hashes = sorted(
        excluded_hashes
        or [public_key_sha256(t1_key), public_key_sha256(l3_key)]
    )
    excluded_keyrings = {
        "t1_release_keyring_sha256": "c" * 64,
        "l3_release_keyring_sha256": "d" * 64,
    }
    draft = valid_draft(
        content_raw,
        content,
        keyring_sha256,
        authority_hashes,
        excluded_keyrings,
    )
    signer_sha256 = hashlib.sha256(
        signer.SIGNER_SOURCE_PATH.read_bytes()
    ).hexdigest()
    signed = signer.sign_provenance(
        draft,
        private_key,
        keyring,
        content_raw,
        content,
        expected_trusted_keyring_sha256=keyring_sha256,
        expected_runtime_source_commit_sha=RUNTIME_COMMIT,
        expected_image_digest=IMAGE_DIGEST,
        expected_signing_tool_source_sha256=signer_sha256,
        expected_signing_tool_source_commit_sha=SIGNER_COMMIT,
        excluded_authority_key_hashes=authority_hashes,
        excluded_authority_keyring_sha256s=excluded_keyrings,
        now=NOW,
    )
    return {
        "signed": signed,
        "private_key": private_key,
        "keyring": keyring,
        "keyring_sha256": keyring_sha256,
        "content": content,
        "content_raw": content_raw,
        "excluded_hashes": authority_hashes,
        "excluded_keyrings": excluded_keyrings,
        "signer_sha256": signer_sha256,
    }


def verify_fixture(
    tmp_path: Path,
    fixture: dict[str, Any],
    *,
    signer_sha256: str | None = None,
    signer_commit: str = SIGNER_COMMIT,
) -> dict[str, Any]:
    provenance_path = write_json(
        tmp_path / "provenance.signed.json",
        fixture["signed"],
    )
    keyring_path = write_json(
        tmp_path / "provenance-keyring.json",
        fixture["keyring"],
    )
    content_path = write_bytes(
        tmp_path / "content.json",
        fixture["content_raw"],
    )
    return subject.verify_provenance(
        provenance_path,
        keyring_path,
        content_path,
        expected_trusted_keyring_sha256=fixture["keyring_sha256"],
        expected_runtime_source_commit_sha=RUNTIME_COMMIT,
        expected_image_digest=IMAGE_DIGEST,
        expected_signing_tool_source_sha256=(
            fixture["signer_sha256"]
            if signer_sha256 is None
            else signer_sha256
        ),
        expected_signing_tool_source_commit_sha=signer_commit,
        excluded_authority_key_hashes=fixture["excluded_hashes"],
        excluded_authority_keyring_sha256s=fixture["excluded_keyrings"],
        now=NOW,
    )


def test_v2_verifies_without_runtime_signer_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(
        signer,
        "SIGNER_SOURCE_PATH",
        tmp_path / "absent-from-runtime.py",
    )

    receipt = verify_fixture(tmp_path, fixture)

    assert receipt["signing_tool_source_pin_verified"] is True
    assert (
        receipt["signing_tool_source_bytes_revalidated_at_runtime"]
        is False
    )
    assert (
        receipt["signing_tool_execution_independently_verified"]
        is False
    )
    assert receipt["authority_granted"] is False
    verifier_source = subject.VERIFIER_PATH.read_text(encoding="utf-8")
    assert "SIGNER_SOURCE_PATH" not in verifier_source
    assert "import commodity_c_fast_t1_build_registry_provenance_sign_v2" not in (
        verifier_source
    )


@pytest.mark.parametrize(
    ("signer_sha256", "signer_commit", "error"),
    [
        ("f" * 64, SIGNER_COMMIT, "source SHA256 binding mismatch"),
        (
            None,
            "e" * 40,
            "source commit binding mismatch",
        ),
        ("INVALID", SIGNER_COMMIT, "must be a lowercase SHA256"),
    ],
)
def test_wrong_or_malformed_independent_signer_pin_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    signer_sha256: str | None,
    signer_commit: str,
    error: str,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match=error,
    ):
        verify_fixture(
            tmp_path,
            fixture,
            signer_sha256=signer_sha256,
            signer_commit=signer_commit,
        )


@pytest.mark.parametrize(
    ("missing_field", "error"),
    [
        ("sha256", "must be a lowercase SHA256"),
        ("commit", "must be a lowercase 40-character commit SHA"),
    ],
)
def test_missing_independent_signer_pin_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    missing_field: str,
    error: str,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    identity = fixture["signed"]["signing_tool_source_identity"]

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match=error,
    ):
        subject._validate_signing_tool_source_identity(
            {"signing_tool_source_identity": identity},
            expected_signing_tool_source_sha256=(
                None
                if missing_field == "sha256"
                else fixture["signer_sha256"]
            ),
            expected_signing_tool_source_commit_sha=(
                None if missing_field == "commit" else SIGNER_COMMIT
            ),
        )


def test_signer_refuses_when_current_source_misses_release_pin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    draft = {
        key: value
        for key, value in fixture["signed"].items()
        if key
        not in {
            "signature",
            "signing_tool_source_identity",
            "provenance_verifier_sha256",
            "provenance_schema_sha256",
            "receipt_schema_sha256",
            "content_attestation_schema_sha256",
            "content_verifier_sha256",
            "source_manifest_schema_sha256",
        }
    }

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match="source SHA256 binding mismatch",
    ):
        signer.sign_provenance(
            draft,
            fixture["private_key"],
            fixture["keyring"],
            fixture["content_raw"],
            fixture["content"],
            expected_trusted_keyring_sha256=fixture["keyring_sha256"],
            expected_runtime_source_commit_sha=RUNTIME_COMMIT,
            expected_image_digest=IMAGE_DIGEST,
            expected_signing_tool_source_sha256="f" * 64,
            expected_signing_tool_source_commit_sha=SIGNER_COMMIT,
            excluded_authority_key_hashes=fixture["excluded_hashes"],
            excluded_authority_keyring_sha256s=fixture[
                "excluded_keyrings"
            ],
            now=NOW,
        )


def test_tampered_signed_source_identity_fails_signature(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    tampered = copy.deepcopy(fixture["signed"])
    tampered["signing_tool_source_identity"]["sha256"] = "f" * 64
    fixture["signed"] = tampered

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match="signature is invalid",
    ):
        verify_fixture(
            tmp_path,
            fixture,
            signer_sha256="f" * 64,
        )


def test_trusted_resign_with_wrong_source_identity_still_misses_pin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    tampered = copy.deepcopy(fixture["signed"])
    tampered["signing_tool_source_identity"]["sha256"] = "f" * 64
    tampered["signature"] = base64.b64encode(
        fixture["private_key"].sign(
            canonical_bytes(subject.unsigned_provenance_payload(tampered))
        )
    ).decode("ascii")
    fixture["signed"] = tampered

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match="source SHA256 binding mismatch",
    ):
        verify_fixture(tmp_path, fixture)


@pytest.mark.parametrize(
    ("path_attribute", "error_field"),
    [
        ("VERIFIER_PATH", "provenance_verifier_sha256"),
        ("PROVENANCE_SCHEMA_PATH", "provenance_schema_sha256"),
        ("RECEIPT_SCHEMA_PATH", "receipt_schema_sha256"),
        ("CONTENT_VERIFIER_PATH", "content_verifier_sha256"),
        (
            "CONTENT_ATTESTATION_SCHEMA_PATH",
            "content_attestation_schema_sha256",
        ),
        ("SOURCE_MANIFEST_SCHEMA_PATH", "source_manifest_schema_sha256"),
    ],
)
def test_runtime_contract_byte_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path_attribute: str,
    error_field: str,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    original = getattr(subject, path_attribute)
    drifted = write_bytes(
        tmp_path / f"drifted-{path_attribute.lower()}",
        original.read_bytes() + b"\n",
    )
    monkeypatch.setattr(subject, path_attribute, drifted)

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match=rf"{error_field} binding mismatch",
    ):
        verify_fixture(tmp_path, fixture)


def test_stacked_query_v3_content_contract_is_exact_and_runtime_safe() -> None:
    content_schema = json.loads(
        subject.CONTENT_ATTESTATION_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    manifest_schema = json.loads(
        subject.SOURCE_MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    verifier_source = subject.CONTENT_VERIFIER_PATH.read_text(encoding="utf-8")

    assert (
        content_schema["properties"]["schema_version"]["const"]
        == subject.CONTENT_ATTESTATION_SCHEMA_VERSION
    )
    assert (
        manifest_schema["properties"]["schema_version"]["const"]
        == "commodity_c_fast_t1_query_v3_source_manifest_v1"
    )
    assert "def verify_query_v3_image_evidence(" in verifier_source
    assert "import subprocess" not in verifier_source
    assert "--source-root" not in verifier_source


def test_v1_v2_schema_downgrade_and_authority_escalation_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    schema = json.loads(
        subject.PROVENANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    downgraded = copy.deepcopy(fixture["signed"])
    downgraded["schema_version"] = (
        "commodity_c_fast_t1_build_registry_provenance_v1"
    )
    escalated = copy.deepcopy(fixture["signed"])
    escalated["production_query_authorized"] = True
    v1_schema = json.loads(V1_SCHEMA_PATH.read_text(encoding="utf-8"))

    assert list(Draft202012Validator(schema).iter_errors(downgraded))
    assert list(Draft202012Validator(schema).iter_errors(escalated))
    assert list(
        Draft202012Validator(v1_schema).iter_errors(fixture["signed"])
    )


def test_content_raw_rewrite_fails_even_when_canonical_json_is_equal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    fixture["content_raw"] += b"\n"

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match="content attestation raw SHA256 binding mismatch",
    ):
        verify_fixture(tmp_path, fixture)


def test_pending_template_is_invalid_and_has_no_generated_identity() -> None:
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    schema = json.loads(
        subject.PROVENANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )

    assert template["provenance_id"].startswith("PENDING_")
    assert "signature" not in template
    assert "signing_tool_source_identity" not in template
    for field in (
        "provenance_verifier_sha256",
        "provenance_schema_sha256",
        "receipt_schema_sha256",
        "content_attestation_schema_sha256",
        "content_verifier_sha256",
        "source_manifest_schema_sha256",
    ):
        assert field not in template
    assert all(
        template[field] is False
        for field in subject.FALSE_AUTHORITY_FIELDS
    )
    assert list(Draft202012Validator(schema).iter_errors(template))


def test_provenance_signer_cannot_reuse_authority_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reused = Ed25519PrivateKey.generate()

    with pytest.raises(
        subject.BuildRegistryProvenanceV2Error,
        match="reuses an excluded authority public key",
    ):
        signed_fixture(
            monkeypatch,
            tmp_path,
            provenance_key=reused,
            excluded_hashes=[
                public_key_sha256(reused),
                public_key_sha256(Ed25519PrivateKey.generate()),
            ],
        )


GENERATED_SIGNER_FIELDS = {
    "signature",
    "signing_tool_source_identity",
    "provenance_verifier_sha256",
    "provenance_schema_sha256",
    "receipt_schema_sha256",
    "content_attestation_schema_sha256",
    "content_verifier_sha256",
    "source_manifest_schema_sha256",
}


def unsigned_draft(fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in fixture["signed"].items()
        if key not in GENERATED_SIGNER_FIELDS
    }


def public_validation_args(
    fixture: dict[str, Any],
    *,
    trusted_keyring_sha256: str | None = None,
    excluded_hashes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "expected_trusted_keyring_sha256": (
            fixture["keyring_sha256"]
            if trusted_keyring_sha256 is None
            else trusted_keyring_sha256
        ),
        "expected_runtime_source_commit_sha": RUNTIME_COMMIT,
        "expected_image_digest": IMAGE_DIGEST,
        "expected_signing_tool_source_sha256": hashlib.sha256(
            signer.SIGNER_SOURCE_PATH.read_bytes()
        ).hexdigest(),
        "expected_signing_tool_source_commit_sha": SIGNER_COMMIT,
        "excluded_authority_key_hashes": (
            fixture["excluded_hashes"]
            if excluded_hashes is None
            else excluded_hashes
        ),
        "excluded_authority_keyring_sha256s": fixture[
            "excluded_keyrings"
        ],
        "now": NOW,
    }


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("signer_pin", "source SHA256 binding mismatch"),
        ("content", "content attestation raw SHA256 binding mismatch"),
        ("keyring_pin", "keyring pin binding mismatch"),
        ("purpose", "schema validation failed|identity or scope"),
        ("pending", "PENDING_|schema validation failed"),
        ("schema", "schema validation failed"),
        ("authority_reuse", "reuses an excluded authority public key"),
    ],
)
def test_invalid_public_inputs_never_read_private_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
    error: str,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    draft = unsigned_draft(fixture)
    content_raw = fixture["content_raw"]
    validation = public_validation_args(fixture)
    if case == "signer_pin":
        validation["expected_signing_tool_source_sha256"] = "f" * 64
    elif case == "content":
        content_raw += b"\n"
    elif case == "keyring_pin":
        validation["expected_trusted_keyring_sha256"] = "f" * 64
    elif case == "purpose":
        draft["purpose"] = "not-build-registry-provenance"
    elif case == "pending":
        draft["provenance_id"] = "PENDING_not-reviewed"
    elif case == "schema":
        draft["schema_version"] = "commodity_c_fast_t1_build_registry_provenance_v1"
    elif case == "authority_reuse":
        excluded = sorted(
            [
                public_key_sha256(fixture["private_key"]),
                fixture["excluded_hashes"][0],
            ]
        )
        draft["excluded_authority_public_key_sha256s"] = excluded
        validation["excluded_authority_key_hashes"] = excluded

    private_read = False

    def fail_private_read(_path: Path) -> Ed25519PrivateKey:
        nonlocal private_read
        private_read = True
        raise AssertionError("private key must not be read")

    monkeypatch.setattr(signer, "load_private_key", fail_private_read)
    with pytest.raises(subject.BuildRegistryProvenanceV2Error, match=error):
        signer.sign_provenance_from_private_key_path(
            draft,
            tmp_path / "must-not-be-read.key",
            fixture["keyring"],
            content_raw,
            fixture["content"],
            **validation,
        )
    assert private_read is False


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("invalid_base64", "public key is invalid"),
        ("invalid_length", "public key is invalid"),
        ("duplicate_material", "duplicates public-key material"),
        ("t1_reuse", "reuses an excluded authority public key"),
        ("l3_reuse", "reuses an excluded authority public key"),
    ],
)
def test_every_provenance_keyring_entry_is_validated_and_domain_isolated(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
    error: str,
) -> None:
    fixture = signed_fixture(monkeypatch, tmp_path)
    draft = unsigned_draft(fixture)
    keyring = copy.deepcopy(fixture["keyring"])
    unused = Ed25519PrivateKey.generate()
    encoded = public_key_base64(unused)
    if case == "invalid_base64":
        encoded = "not-base64!"
    elif case == "invalid_length":
        encoded = base64.b64encode(b"short").decode("ascii")
    elif case == "duplicate_material":
        encoded = keyring["keys"][0]["public_key_base64"]
    keyring["keys"].append(
        {
            "key_id": "c-fast-t1-provenance-v2-key-unused",
            "purpose": subject.KEY_PURPOSE,
            "public_key_base64": encoded,
        }
    )
    keyring_sha256 = hashlib.sha256(canonical_bytes(keyring)).hexdigest()
    draft["trusted_keyring_sha256"] = keyring_sha256
    excluded = list(fixture["excluded_hashes"])
    if case in {"t1_reuse", "l3_reuse"}:
        excluded = sorted([public_key_sha256(unused), excluded[0]])
        draft["excluded_authority_public_key_sha256s"] = excluded

    with pytest.raises(subject.BuildRegistryProvenanceV2Error, match=error):
        signer.sign_provenance(
            draft,
            fixture["private_key"],
            keyring,
            fixture["content_raw"],
            fixture["content"],
            **public_validation_args(
                fixture,
                trusted_keyring_sha256=keyring_sha256,
                excluded_hashes=excluded,
            ),
        )
