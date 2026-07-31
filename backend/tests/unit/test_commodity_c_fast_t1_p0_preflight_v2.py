from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_p0_preflight_v2 as subject  # noqa: E402
import commodity_c_fast_t1_build_registry_provenance_v3 as provenance_v3  # noqa: E402
from c_fast_t1.validate_query_v4_runtime import validate_package  # noqa: E402
from commodity_c_fast_t1_readiness_v3 import (  # noqa: E402
    VerifiedReadinessPacket,
)


SHA = "a" * 64
COMMIT = "b" * 40
OCI_DIGEST = "sha256:" + "c" * 64
NOW = datetime(2026, 7, 31, 3, 0, tzinfo=timezone.utc)


def _readiness() -> VerifiedReadinessPacket:
    return VerifiedReadinessPacket(
        payload={
            "packet_id": "readiness-v3-" + "d" * 64,
            "expires_at": (
                NOW + timedelta(minutes=10)
            ).isoformat().replace("+00:00", "Z"),
            "source_namespaces": {
                "t1_runtime_source_commit_sha": COMMIT,
            },
            "digest_namespaces": {
                "questdb_image_digest": OCI_DIGEST,
            },
            "readonly_deployment_outcome": {
                "signed_outcome_raw_sha256": "e" * 64,
                "signed_outcome_canonical_sha256": "f" * 64,
                "questdb_target_identity_sha256": "1" * 64,
            },
        },
        raw_sha256="2" * 64,
        canonical_sha256="3" * 64,
    )


def _attestation() -> dict:
    return {
        "schema_version": (
            "commodity_c_fast_t1_query_v4_image_attestation_v1"
        ),
        "status": (
            "QUERY_V4_SOURCE_BUNDLE_AND_OCI_CONTENT_VERIFIED_"
            "NO_BUILD_OR_REGISTRY_PROVENANCE"
        ),
        "source_commit_sha": COMMIT,
        "source_bundle_archive_sha256": "4" * 64,
        "verifier_sha256": "5" * 64,
        "delegate_verifier_sha256": "9" * 64,
        "image_reference": (
            "registry.invalid/c-fast/query-v4@" + OCI_DIGEST
        ),
        "image_digest": OCI_DIGEST,
        "image_id": "sha256:" + "6" * 64,
        "runtime_bundle_index_sha256": "7" * 64,
        "containerfile_sha256": validate_package()["containerfile"][
            "containerfile_sha256"
        ],
        "authority_granted": False,
        "production_query_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
    }


def _provenance_receipt(attestation: dict, raw: bytes) -> dict:
    return {
        "schema_version": subject.PROVENANCE_RECEIPT_SCHEMA_VERSION,
        "status": subject.PROVENANCE_RECEIPT_STATUS,
        "provenance_id": "query-v4-build-001",
        "verified_at": NOW.isoformat(),
        "signed_provenance_raw_sha256": "8" * 64,
        "signed_provenance_canonical_sha256": "9" * 64,
        "content_attestation_raw_sha256": subject._hash(raw),
        "content_attestation_canonical_sha256": subject._hash(
            subject.canonical_json(attestation)
        ),
        "trusted_keyring_sha256": "a" * 64,
        "excluded_authority_keyring_sha256s": {
            "t1_release_keyring_sha256": "d" * 64,
            "l3_release_keyring_sha256": "e" * 64,
        },
        "excluded_authority_public_key_sha256s": [
            "f" * 64,
            "0" * 64,
        ],
        "signer_key_id": "query-v4-provenance-signer",
        "signer_public_key_sha256": "b" * 64,
        "signing_tool_source_path": (
            "scripts/"
            "commodity_c_fast_t1_build_registry_provenance_sign_v3.py"
        ),
        "signing_tool_source_commit_sha": COMMIT,
        "signing_tool_source_sha256": "c" * 64,
        "signing_tool_source_pin_verified": True,
        "signing_tool_source_bytes_revalidated_at_runtime": False,
        "signing_tool_execution_independently_verified": False,
        "signer_dependency_manifest_sha256": "6" * 64,
        "signer_dependency_manifest_pin_verified": True,
        "signer_runtime_image_digest": "sha256:" + "7" * 64,
        "signer_runtime_image_digest_pin_verified": True,
        "signer_runtime_execution_independently_verified": False,
        "runtime_source_commit_sha": COMMIT,
        "source_bundle_archive_sha256": attestation[
            "source_bundle_archive_sha256"
        ],
        "source_manifest_canonical_sha256": "1" * 64,
        "image_reference": attestation["image_reference"],
        "image_digest": attestation["image_digest"],
        "signed_build_assertion_verified": True,
        "signed_registry_assertion_verified": True,
        "external_facts_independently_reverified": False,
        "receipt_is_authority": False,
        **{
            field: False
            for field in provenance_v3.FALSE_AUTHORITY_FIELDS
        },
        **{
            field: 0
            for field in provenance_v3.ZERO_FACT_FIELDS
        },
    }


def _dsn() -> dict:
    return {
        "path_sha256": "d" * 64,
        "device": 1,
        "inode": 2,
        "owner_uid": 501,
        "mode": 0o600,
        "size_bytes": 32,
        "regular_non_symlink": True,
        "owned_by_current_user": True,
        "permissions_0600_or_stricter": True,
        "metadata_only": True,
        "content_read": False,
    }


def test_preflight_v2_consumes_exact_query_v4_signed_provenance() -> None:
    attestation = _attestation()
    raw = subject.canonical_json(attestation)
    packet = subject.build_preflight(
        _readiness(),
        attestation,
        raw,
        validate_package(),
        _dsn(),
        _provenance_receipt(attestation, raw),
        now=NOW,
    )

    assert packet["schema_version"] == subject.SCHEMA_VERSION
    assert packet["status"] == subject.STATUS
    assert packet["preflight_delegate_verifier_sha256"] == subject._hash(
        Path(subject.preflight_v1.__file__).resolve().read_bytes()
    )
    assert packet["query_v4"]["build_provenance_verified"] is True
    assert packet["query_v4"]["registry_provenance_verified"] is True
    assert packet["query_v4"]["provenance_id"] == "query-v4-build-001"
    assert packet["blocking_reasons"] == subject.BLOCKING_REASONS
    assert packet["ready_for_human_query_release_only"] is False
    assert packet["production_query_attempted"] is False
    assert packet["p0_verdict"] == "NOT_RUN"
    assert packet["authority_granted"] is False
    assert packet["network_authorized"] is False
    Draft202012Validator(
        json.loads(subject.SCHEMA_PATH.read_text(encoding="utf-8"))
    ).validate(packet)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("runtime_source_commit_sha", "0" * 40),
        ("source_bundle_archive_sha256", "0" * 64),
        ("content_attestation_raw_sha256", "0" * 64),
        ("content_attestation_canonical_sha256", "0" * 64),
        ("image_digest", "sha256:" + "0" * 64),
        ("image_reference", "registry.invalid/query@sha256:" + "0" * 64),
    ],
)
def test_provenance_receipt_splice_fails_closed(
    field: str,
    replacement: str,
) -> None:
    attestation = _attestation()
    raw = subject.canonical_json(attestation)
    receipt = _provenance_receipt(attestation, raw)
    receipt[field] = replacement

    with pytest.raises(
        subject.T1P0PreflightError,
        match=field,
    ):
        subject.build_preflight(
            _readiness(),
            attestation,
            raw,
            validate_package(),
            _dsn(),
            receipt,
            now=NOW,
        )


def test_provenance_receipt_authority_or_type_splice_fails_closed() -> None:
    attestation = _attestation()
    raw = subject.canonical_json(attestation)
    receipt = _provenance_receipt(attestation, raw)
    receipt["authority_granted"] = 0

    with pytest.raises(
        subject.T1P0PreflightError,
        match="schema validation failed",
    ):
        subject.build_preflight(
            _readiness(),
            attestation,
            raw,
            validate_package(),
            _dsn(),
            receipt,
            now=NOW,
        )


def test_preflight_v1_schema_cannot_accept_v2_packet() -> None:
    attestation = _attestation()
    raw = subject.canonical_json(attestation)
    packet = subject.build_preflight(
        _readiness(),
        attestation,
        raw,
        validate_package(),
        _dsn(),
        _provenance_receipt(attestation, raw),
        now=NOW,
    )
    v1_schema = json.loads(
        (
            ROOT
            / "docs/schemas/"
            "commodity-c-fast-t1-p0-preflight-v1.schema.json"
        ).read_text(encoding="utf-8")
    )

    assert list(Draft202012Validator(v1_schema).iter_errors(packet))


def test_blocker_boundary_is_exactly_readiness_and_human_release() -> None:
    assert subject.BLOCKING_REASONS == [
        "QUERY_V4_READINESS_AND_HUMAN_RELEASE_NOT_YET_DERIVED"
    ]
    assert "PROVENANCE_BLOCKED" not in subject.STATUS
