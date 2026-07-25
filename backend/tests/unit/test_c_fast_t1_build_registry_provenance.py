from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
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
from jsonschema import Draft202012Validator, FormatChecker
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_t1_build_registry_provenance as subject  # noqa: E402
import commodity_c_fast_t1_build_registry_provenance_sign as signer  # noqa: E402


NOW = datetime(2026, 7, 25, 1, 0, tzinfo=timezone.utc)
RUNTIME_SOURCE_COMMIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
REPOSITORY = "registry.example.invalid/research/c-fast-t1"
IMAGE_REFERENCE = f"{REPOSITORY}@{IMAGE_DIGEST}"
TEMPLATE_PATH = (
    ROOT
    / "docs/operations/"
    "c-fast-t1-build-registry-provenance-v1.template.json"
)


def canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def write_bytes(
    path: Path,
    raw: bytes,
    *,
    mode: int = 0o600,
) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(
    path: Path,
    payload: dict[str, Any],
    *,
    mode: int = 0o600,
) -> Path:
    return write_bytes(path, canonical_bytes(payload), mode=mode)


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


def valid_content_attestation() -> dict[str, Any]:
    schema = json.loads(
        subject.CONTENT_ATTESTATION_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )
    runtime_paths = schema["$defs"]["runtimeBundle"]["required"]
    checks = {
        field: True
        for field in schema["properties"]["checks"]["required"]
    }
    checks["build_provenance_verified"] = False
    checks["registry_provenance_verified"] = False
    payload: dict[str, Any] = {
        "schema_version": "commodity_c_fast_t1_image_attestation_v1",
        "status": (
            "EXTERNAL_OCI_ARTIFACT_CONTENT_VERIFIED_NO_BUILD_OR_"
            "REGISTRY_PROVENANCE"
        ),
        "source_commit_sha": RUNTIME_SOURCE_COMMIT_SHA,
        "source_archive_sha256": "d" * 64,
        "external_evidence_sha256": "e" * 64,
        "evidence_captured_at": "2026-07-25T00:07:00Z",
        "containerfile_sha256": "f" * 64,
        "verifier_sha256": hashlib.sha256(
            subject.CONTENT_VERIFIER_PATH.read_bytes()
        ).hexdigest(),
        "evidence_schema_sha256": "1" * 64,
        "attestation_schema_sha256": hashlib.sha256(
            subject.CONTENT_ATTESTATION_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "base_image_digest": "sha256:" + "2" * 64,
        "installed_dependency_metadata_versions": {
            "cryptography": "48.0.0",
            "jsonschema": "4.26.0",
            "psycopg": "3.2.3",
            "psycopg-binary": "3.2.3",
            "referencing": "0.37.0",
        },
        "oci_layout_archive_sha256": "3" * 64,
        "image_reference": IMAGE_REFERENCE,
        "image_digest": IMAGE_DIGEST,
        "image_id": IMAGE_ID,
        "rootfs_layer_digests": ["sha256:" + "4" * 64],
        "runtime_bundle_sha256": {
            path: "5" * 64 for path in runtime_paths
        },
        "checks": checks,
        "image_built_here": False,
        "cryptographic_approval_present": False,
        "sensitive_material_present": False,
        "authority_recovery_allowed": False,
        "receipt_replay_allowed": False,
        "t1_executed": False,
        "production_queried": False,
        "authority_granted": False,
        "network_authorized": False,
        "network_query_authorized": False,
        "readonly_production_query_authorized": False,
        "production_query_authorized": False,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "collection_authorized": False,
        "execution_quality_collection_authorized": False,
        "runtime_activation_authorized": False,
        "order_authorized": False,
        "order_submission_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "replacement_authorized": False,
        "production_authorized": False,
        "dynamic_selection_allowed": False,
        "automatic_promotion_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }
    subject._validate_schema(
        payload,
        subject.CONTENT_ATTESTATION_SCHEMA_PATH,
        "test content attestation",
    )
    return payload


def keyring_for(
    private_key: Ed25519PrivateKey,
    *,
    schema_version: str = subject.KEYRING_VERSION,
    purpose: str = subject.KEY_PURPOSE,
    key_id: str = "c-fast-t1-provenance-key-a01",
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


def valid_draft(
    content_raw: bytes,
    content: dict[str, Any],
    keyring_sha256: str,
    excluded_key_hashes: list[str],
    excluded_keyring_hashes: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": subject.SCHEMA_VERSION,
        "provenance_id": "c-fast-t1-provenance-a01",
        "candidate_id": subject.CANDIDATE_ID,
        "purpose": subject.PURPOSE,
        "issued_at": "2026-07-25T00:09:00Z",
        "signer_key_id": "c-fast-t1-provenance-key-a01",
        "trusted_keyring_sha256": keyring_sha256,
        "excluded_authority_keyring_sha256s": (
            excluded_keyring_hashes
        ),
        "excluded_authority_public_key_sha256s": excluded_key_hashes,
        "runtime_source_commit_sha": RUNTIME_SOURCE_COMMIT_SHA,
        "content_attestation_raw_sha256": hashlib.sha256(
            content_raw
        ).hexdigest(),
        "content_attestation_canonical_sha256": hashlib.sha256(
            canonical_bytes(content)
        ).hexdigest(),
        "content_attestation_schema_sha256": (
            content["attestation_schema_sha256"]
        ),
        "content_verifier_sha256": content["verifier_sha256"],
        "source_archive_sha256": content["source_archive_sha256"],
        "oci_layout_archive_sha256": (
            content["oci_layout_archive_sha256"]
        ),
        "containerfile_sha256": content["containerfile_sha256"],
        "image_reference": content["image_reference"],
        "image_digest": content["image_digest"],
        "image_id": content["image_id"],
        "runtime_bundle_index_sha256": hashlib.sha256(
            canonical_bytes(content["runtime_bundle_sha256"])
        ).hexdigest(),
        "build": {
            "builder_identity_sha256": "6" * 64,
            "build_invocation_sha256": "7" * 64,
            "build_log_archive_sha256": "8" * 64,
            "platform": "linux/amd64",
            "started_at": "2026-07-25T00:00:00Z",
            "completed_at": "2026-07-25T00:05:00Z",
            "exact_source_archive_used": True,
            "exact_containerfile_used": True,
            "build_exit_code": 0,
            "output_oci_layout_archive_sha256": (
                content["oci_layout_archive_sha256"]
            ),
            "output_image_digest": content["image_digest"],
            "output_image_id": content["image_id"],
            "reproducible_build_verified": False,
            "sensitive_material_present": False,
        },
        "registry": {
            "registry_identity_sha256": "9" * 64,
            "repository": REPOSITORY,
            "immutable_reference": content["image_reference"],
            "manifest_digest": content["image_digest"],
            "push_receipt_sha256": "0" * 64,
            "pushed_at": "2026-07-25T00:06:00Z",
            "observed_at": "2026-07-25T00:08:00Z",
            "digest_reference_resolved": True,
            "manifest_digest_matched": True,
            "mutable_tag_trusted": False,
            "sensitive_material_present": False,
        },
        "external_fact_scope": subject.EXTERNAL_FACT_SCOPE,
        **{field: False for field in subject.FALSE_AUTHORITY_FIELDS},
        **{field: 0 for field in subject.ZERO_FACT_FIELDS},
    }


@dataclass(frozen=True)
class ExcludedAuthorityFacts:
    t1_path: Path
    l3_path: Path
    t1_keyring_sha256: str
    l3_keyring_sha256: str
    public_key_hashes: list[str]
    keyring_hashes: dict[str, str]


def sign_fixture(
    tmp_path: Path,
    *,
    provenance_key: Ed25519PrivateKey | None = None,
    t1_key: Ed25519PrivateKey | None = None,
    l3_key: Ed25519PrivateKey | None = None,
    draft_mutator: Any = None,
) -> tuple[
    dict[str, Any],
    Path,
    Path,
    str,
    Path,
    ExcludedAuthorityFacts,
]:
    private_key = provenance_key or Ed25519PrivateKey.generate()
    t1_authority_key = t1_key or Ed25519PrivateKey.generate()
    l3_authority_key = l3_key or Ed25519PrivateKey.generate()
    keyring = keyring_for(private_key)
    keyring_path = write_json(tmp_path / "provenance-keyring.json", keyring)
    keyring_sha256 = hashlib.sha256(canonical_bytes(keyring)).hexdigest()
    excluded_keyring = keyring_for(
        t1_authority_key,
        schema_version="commodity_c_fast_t1_trusted_keys_v1",
        purpose="t1_audit_release_signer",
        key_id="c-fast-t1-release-key-a01",
    )
    excluded_keyring_path = write_json(
        tmp_path / "t1-keyring.json",
        excluded_keyring,
    )
    l3_keyring = keyring_for(
        l3_authority_key,
        schema_version=(
            "commodity_c_fast_readonly_deployment_trusted_keys_v1"
        ),
        purpose="readonly_deployment_release_signer",
        key_id="c-fast-l3-release-key-a01",
    )
    l3_keyring_path = write_json(
        tmp_path / "l3-keyring.json",
        l3_keyring,
    )
    t1_keyring_sha256 = hashlib.sha256(
        canonical_bytes(excluded_keyring)
    ).hexdigest()
    l3_keyring_sha256 = hashlib.sha256(
        canonical_bytes(l3_keyring)
    ).hexdigest()
    excluded_hashes = sorted(
        [
            public_key_sha256(t1_authority_key),
            public_key_sha256(l3_authority_key),
        ]
    )
    excluded_keyring_hashes = {
        "t1_release_keyring_sha256": t1_keyring_sha256,
        "l3_release_keyring_sha256": l3_keyring_sha256,
    }

    content = valid_content_attestation()
    content_raw = canonical_bytes(content)
    content_path = write_bytes(tmp_path / "content.json", content_raw)
    draft = valid_draft(
        content_raw,
        content,
        keyring_sha256,
        excluded_hashes,
        excluded_keyring_hashes,
    )
    if draft_mutator is not None:
        draft_mutator(draft)
    signed = signer.sign_provenance(
        draft,
        private_key,
        keyring,
        content_raw,
        content,
        expected_trusted_keyring_sha256=keyring_sha256,
        expected_runtime_source_commit_sha=(
            RUNTIME_SOURCE_COMMIT_SHA
        ),
        expected_image_digest=IMAGE_DIGEST,
        excluded_authority_key_hashes=excluded_hashes,
        excluded_authority_keyring_sha256s=(
            excluded_keyring_hashes
        ),
        now=NOW,
    )
    provenance_path = write_json(
        tmp_path / "provenance.signed.json",
        signed,
    )
    return (
        signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        ExcludedAuthorityFacts(
            t1_path=excluded_keyring_path,
            l3_path=l3_keyring_path,
            t1_keyring_sha256=t1_keyring_sha256,
            l3_keyring_sha256=l3_keyring_sha256,
            public_key_hashes=excluded_hashes,
            keyring_hashes=excluded_keyring_hashes,
        ),
    )


def verify_fixture(
    provenance_path: Path,
    keyring_path: Path,
    keyring_sha256: str,
    content_path: Path,
    excluded: ExcludedAuthorityFacts,
    *,
    now: datetime = NOW,
) -> dict[str, Any]:
    (
        excluded_public_key_hashes,
        excluded_keyring_hashes,
    ) = subject.load_excluded_authority_key_facts(
        t1_keyring_path=excluded.t1_path,
        expected_t1_keyring_sha256=(
            excluded.t1_keyring_sha256
        ),
        l3_keyring_path=excluded.l3_path,
        expected_l3_keyring_sha256=(
            excluded.l3_keyring_sha256
        ),
    )
    return subject.verify_provenance(
        provenance_path,
        keyring_path,
        content_path,
        expected_trusted_keyring_sha256=keyring_sha256,
        expected_runtime_source_commit_sha=(
            RUNTIME_SOURCE_COMMIT_SHA
        ),
        expected_image_digest=IMAGE_DIGEST,
        excluded_authority_key_hashes=excluded_public_key_hashes,
        excluded_authority_keyring_sha256s=(
            excluded_keyring_hashes
        ),
        now=now,
    )


def test_signed_provenance_binds_content_build_registry_and_no_authority(
    tmp_path: Path,
) -> None:
    (
        signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)

    receipt = verify_fixture(
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    )

    assert receipt["status"] == subject.RECEIPT_STATUS
    assert receipt["signed_build_assertion_verified"] is True
    assert receipt["signed_registry_assertion_verified"] is True
    assert receipt["external_facts_independently_reverified"] is False
    assert receipt["readiness_authorized"] is False
    assert receipt["production_query_authorized"] is False
    assert receipt["collection_authorized"] is False
    assert signed["excluded_authority_public_key_sha256s"]
    assert receipt["excluded_authority_keyring_sha256s"] == (
        signed["excluded_authority_keyring_sha256s"]
    )
    assert receipt["excluded_authority_public_key_sha256s"] == (
        signed["excluded_authority_public_key_sha256s"]
    )
    assert all(
        receipt[field] is False
        for field in subject.FALSE_AUTHORITY_FIELDS
    )

    for schema_path in (
        subject.PROVENANCE_SCHEMA_PATH,
        subject.RECEIPT_SCHEMA_PATH,
    ):
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        payload = (
            signed
            if schema_path == subject.PROVENANCE_SCHEMA_PATH
            else receipt
        )
        assert (
            list(
                Draft202012Validator(
                    schema,
                    format_checker=FormatChecker(),
                ).iter_errors(payload)
            )
            == []
        )


def test_template_is_invalid_by_design_and_preserves_permission_floor() -> None:
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))

    assert "signature" not in template
    for field in (
        "provenance_verifier_sha256",
        "signing_tool_sha256",
        "provenance_schema_sha256",
        "receipt_schema_sha256",
    ):
        assert field not in template
    assert template["provenance_id"].startswith("PENDING_")
    assert len(template["excluded_authority_public_key_sha256s"]) == 2
    assert all(
        template[field] is False
        for field in subject.FALSE_AUTHORITY_FIELDS
    )
    assert all(
        template[field] == 0
        for field in subject.ZERO_FACT_FIELDS
    )


def test_content_raw_byte_rewrite_fails_even_when_json_is_canonical_equal(
    tmp_path: Path,
) -> None:
    (
        _signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)
    content_path.write_bytes(content_path.read_bytes() + b"\n")

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="content attestation raw SHA256 binding mismatch",
    ):
        verify_fixture(
            provenance_path,
            keyring_path,
            keyring_sha256,
            content_path,
            excluded,
        )


def test_registry_manifest_must_match_content_digest(
    tmp_path: Path,
) -> None:
    def mutate(draft: dict[str, Any]) -> None:
        draft["registry"]["manifest_digest"] = "sha256:" + "6" * 64

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="registry manifest digest binding mismatch",
    ):
        sign_fixture(tmp_path, draft_mutator=mutate)


def test_true_authority_field_is_rejected_by_schema(
    tmp_path: Path,
) -> None:
    def mutate(draft: dict[str, Any]) -> None:
        draft["readiness_authorized"] = True

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="schema validation failed",
    ):
        sign_fixture(tmp_path, draft_mutator=mutate)


def test_provenance_signer_cannot_reuse_t1_authority_key(
    tmp_path: Path,
) -> None:
    reused = Ed25519PrivateKey.generate()

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="reuses an excluded authority public key",
    ):
        sign_fixture(
            tmp_path,
            provenance_key=reused,
            t1_key=reused,
        )


def test_t1_and_l3_authority_domains_cannot_reuse_public_key(
    tmp_path: Path,
) -> None:
    reused = Ed25519PrivateKey.generate()
    t1_keyring = keyring_for(
        reused,
        schema_version=subject.T1_KEYRING_VERSION,
        purpose=subject.T1_KEY_PURPOSE,
        key_id="c-fast-t1-release-key-a01",
    )
    l3_keyring = keyring_for(
        reused,
        schema_version=subject.L3_KEYRING_VERSION,
        purpose=subject.L3_KEY_PURPOSE,
        key_id="c-fast-l3-release-key-a01",
    )
    t1_path = write_json(tmp_path / "t1-keyring.json", t1_keyring)
    l3_path = write_json(tmp_path / "l3-keyring.json", l3_keyring)

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="authority key domains reuse a public key",
    ):
        subject.load_excluded_authority_key_facts(
            t1_keyring_path=t1_path,
            expected_t1_keyring_sha256=hashlib.sha256(
                canonical_bytes(t1_keyring)
            ).hexdigest(),
            l3_keyring_path=l3_path,
            expected_l3_keyring_sha256=hashlib.sha256(
                canonical_bytes(l3_keyring)
            ).hexdigest(),
        )


def test_excluded_authority_key_set_is_exactly_signed(
    tmp_path: Path,
) -> None:
    (
        _signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="excluded authority public-key hashes do not match",
    ):
        subject.verify_provenance(
            provenance_path,
            keyring_path,
            content_path,
            expected_trusted_keyring_sha256=keyring_sha256,
            expected_runtime_source_commit_sha=(
                RUNTIME_SOURCE_COMMIT_SHA
            ),
            expected_image_digest=IMAGE_DIGEST,
            excluded_authority_key_hashes=[],
            excluded_authority_keyring_sha256s=(
                excluded.keyring_hashes
            ),
            now=NOW,
        )


def test_wrong_independent_keyring_pin_fails(
    tmp_path: Path,
) -> None:
    (
        _signed,
        provenance_path,
        keyring_path,
        _keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="independently pinned trusted keyring binding mismatch",
    ):
        verify_fixture(
            provenance_path,
            keyring_path,
            "f" * 64,
            content_path,
            excluded,
        )


def test_tampered_signature_fails(
    tmp_path: Path,
) -> None:
    (
        signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)
    tampered = copy.deepcopy(signed)
    tampered["build"]["build_log_archive_sha256"] = "1" * 64
    write_json(provenance_path, tampered)

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="signature is invalid",
    ):
        verify_fixture(
            provenance_path,
            keyring_path,
            keyring_sha256,
            content_path,
            excluded,
        )


def test_inconsistent_timeline_fails(
    tmp_path: Path,
) -> None:
    def mutate(draft: dict[str, Any]) -> None:
        draft["registry"]["pushed_at"] = "2026-07-24T23:59:00Z"

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="times are inconsistent",
    ):
        sign_fixture(tmp_path, draft_mutator=mutate)


def test_pending_placeholder_fails_closed(
    tmp_path: Path,
) -> None:
    def mutate(draft: dict[str, Any]) -> None:
        draft["provenance_id"] = "PENDING_PROVENANCE_ID"

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="PENDING_ placeholders are forbidden",
    ):
        sign_fixture(tmp_path, draft_mutator=mutate)


def test_symlinked_content_attestation_is_rejected(
    tmp_path: Path,
) -> None:
    (
        _signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)
    symlink = tmp_path / "content-link.json"
    symlink.symlink_to(content_path)

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="must not be a symlink",
    ):
        verify_fixture(
            provenance_path,
            keyring_path,
            keyring_sha256,
            symlink,
            excluded,
        )


def test_naive_now_is_rejected(
    tmp_path: Path,
) -> None:
    (
        _signed,
        provenance_path,
        keyring_path,
        keyring_sha256,
        content_path,
        excluded,
    ) = sign_fixture(tmp_path)

    with pytest.raises(
        subject.BuildRegistryProvenanceError,
        match="now must include an explicit timezone",
    ):
        verify_fixture(
            provenance_path,
            keyring_path,
            keyring_sha256,
            content_path,
            excluded,
            now=datetime(2026, 7, 25, 1, 0),
        )
