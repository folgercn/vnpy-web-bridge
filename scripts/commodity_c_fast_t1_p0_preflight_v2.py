#!/usr/bin/env python3
"""Verify query-v4 provenance and exact T1 inputs without granting P0."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hmac
from pathlib import Path
import sys
from typing import Any

from c_fast_t1.validate_query_v4_runtime import (
    QueryV4PackagingError,
    validate_package,
)
from c_fast_t1.verify_query_v4_image_attestation import (
    QueryV4ImageAttestationError,
    verify_query_v4_image_evidence,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    BuildRegistryProvenanceV3Error,
    RECEIPT_SCHEMA_PATH as PROVENANCE_RECEIPT_SCHEMA_PATH,
    load_excluded_authority_key_facts,
    verify_provenance,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    validate_json_schema,
)
from commodity_c_fast_t1_p0_preflight import (
    T1P0PreflightError,
    _hash,
    _preflight_identity,
    _read_content_attestation,
    _require_exact_content_attestation_rerun,
    build_preflight as build_preflight_v1,
    readonly_dsn_metadata,
    write_create_only,
)
import commodity_c_fast_t1_p0_preflight as preflight_v1
from commodity_c_fast_t1_query_v4 import (
    add_readiness_verification_arguments,
)
from commodity_c_fast_t1_readiness_v3 import (
    ReadinessV3Error,
    VerifiedReadinessPacket,
    _read_production_pins,
    inputs_from_args,
    verify_existing_readiness_packet,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-p0-preflight-v2.schema.json"
)
SCHEMA_VERSION = "commodity_c_fast_t1_p0_preflight_v2"
STATUS = (
    "QUERY_V4_SOURCE_OCI_PROVENANCE_AND_UPSTREAM_PREFLIGHT_"
    "VERIFIED_READINESS_BLOCKED"
)
PROVENANCE_RECEIPT_SCHEMA_VERSION = (
    "commodity_c_fast_t1_build_registry_provenance_receipt_v3"
)
PROVENANCE_RECEIPT_STATUS = (
    "SIGNED_QUERY_V4_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY"
)
BLOCKING_REASONS = [
    "QUERY_V4_READINESS_AND_HUMAN_RELEASE_NOT_YET_DERIVED",
]


def _validate_provenance_receipt_bindings(
    receipt: dict[str, Any],
    attestation: dict[str, Any],
    attestation_raw: bytes,
) -> None:
    try:
        validate_json_schema(
            receipt,
            PROVENANCE_RECEIPT_SCHEMA_PATH,
            "query-v4 build/registry provenance receipt v3",
        )
    except OneShotError as exc:
        raise T1P0PreflightError(str(exc)) from exc
    expected = {
        "runtime_source_commit_sha": attestation["source_commit_sha"],
        "source_bundle_archive_sha256": attestation[
            "source_bundle_archive_sha256"
        ],
        "content_attestation_raw_sha256": _hash(attestation_raw),
        "content_attestation_canonical_sha256": _hash(
            canonical_json(attestation)
        ),
        "image_reference": attestation["image_reference"],
        "image_digest": attestation["image_digest"],
    }
    for field, value in expected.items():
        actual = receipt.get(field)
        if not isinstance(actual, str) or not hmac.compare_digest(
            actual,
            str(value),
        ):
            raise T1P0PreflightError(
                f"query-v4 provenance receipt {field} binding mismatch"
            )
    if (
        receipt.get("schema_version")
        != PROVENANCE_RECEIPT_SCHEMA_VERSION
        or receipt.get("status") != PROVENANCE_RECEIPT_STATUS
        or receipt.get("signed_build_assertion_verified") is not True
        or receipt.get("signed_registry_assertion_verified") is not True
        or receipt.get("external_facts_independently_reverified")
        is not False
        or receipt.get("receipt_is_authority") is not False
        or receipt.get("authority_granted") is not False
        or receipt.get("production_query_authorized") is not False
        or receipt.get("database_mutations") != 0
        or receipt.get("orders_sent") != 0
        or receipt.get("positions_modified") != 0
    ):
        raise T1P0PreflightError(
            "query-v4 provenance receipt boundary is invalid"
        )


def build_preflight(
    readiness: VerifiedReadinessPacket,
    query_v4_attestation: dict[str, Any],
    query_v4_attestation_raw: bytes,
    packaging: dict[str, Any],
    dsn_metadata: dict[str, Any],
    provenance_receipt: dict[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    """Upgrade the v1 input join with exact signed query-v4 provenance."""

    _validate_provenance_receipt_bindings(
        provenance_receipt,
        query_v4_attestation,
        query_v4_attestation_raw,
    )
    payload = build_preflight_v1(
        readiness,
        query_v4_attestation,
        query_v4_attestation_raw,
        packaging,
        dsn_metadata,
        now=now,
    )
    payload["schema_version"] = SCHEMA_VERSION
    payload["status"] = STATUS
    payload["preflight_verifier_sha256"] = _hash(
        Path(__file__).resolve().read_bytes()
    )
    payload["preflight_delegate_verifier_sha256"] = _hash(
        Path(preflight_v1.__file__).resolve().read_bytes()
    )
    payload["preflight_schema_sha256"] = _hash(SCHEMA_PATH.read_bytes())
    payload["query_v4"].update(
        {
            "provenance_id": provenance_receipt["provenance_id"],
            "signed_provenance_raw_sha256": provenance_receipt[
                "signed_provenance_raw_sha256"
            ],
            "signed_provenance_canonical_sha256": provenance_receipt[
                "signed_provenance_canonical_sha256"
            ],
            "provenance_receipt_canonical_sha256": _hash(
                canonical_json(provenance_receipt)
            ),
            "provenance_trusted_keyring_sha256": provenance_receipt[
                "trusted_keyring_sha256"
            ],
            "provenance_signer_key_id": provenance_receipt[
                "signer_key_id"
            ],
            "provenance_signer_public_key_sha256": provenance_receipt[
                "signer_public_key_sha256"
            ],
            "provenance_signing_tool_source_commit_sha": (
                provenance_receipt["signing_tool_source_commit_sha"]
            ),
            "provenance_signing_tool_source_sha256": provenance_receipt[
                "signing_tool_source_sha256"
            ],
            "external_build_registry_facts_independently_reverified": (
                False
            ),
            "build_provenance_verified": True,
            "registry_provenance_verified": True,
        }
    )
    payload["checks"] = {
        **payload["checks"],
        "query_v4_signed_build_registry_provenance_verified": True,
        "query_v4_provenance_key_domain_separation_verified": True,
    }
    payload["blocking_reasons"] = BLOCKING_REASONS
    payload["preflight_id"] = "t1-p0-preflight-v2-" + _hash(
        canonical_json(_preflight_identity(payload))
    )
    try:
        validate_json_schema(payload, SCHEMA_PATH, "T1/P0 preflight v2")
    except OneShotError as exc:
        raise T1P0PreflightError(str(exc)) from exc
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--query-v4-external-image-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-source-bundle-archive",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-oci-layout-archive",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-content-attestation",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-build-registry-provenance",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-query-v4-source-commit-sha",
        required=True,
    )
    parser.add_argument(
        "--expected-query-v4-image-digest",
        required=True,
    )
    parser.add_argument(
        "--expected-query-v4-provenance-signing-tool-source-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-query-v4-provenance-signing-tool-source-commit-sha",
        required=True,
    )
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    add_readiness_verification_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        now = datetime.now(timezone.utc)
        pins = _read_production_pins()
        readiness_inputs = inputs_from_args(args)
        readiness = verify_existing_readiness_packet(
            readiness_inputs,
            pins,
            args.readiness_packet,
        )
        regenerated = verify_query_v4_image_evidence(
            args.query_v4_external_image_evidence,
            args.query_v4_source_bundle_archive,
            args.query_v4_oci_layout_archive,
            args.expected_query_v4_source_commit_sha,
        )
        supplied_raw, supplied = _read_content_attestation(
            args.query_v4_content_attestation
        )
        _require_exact_content_attestation_rerun(
            supplied_raw,
            supplied,
            regenerated,
        )
        if not hmac.compare_digest(
            str(regenerated["image_digest"]),
            args.expected_query_v4_image_digest,
        ):
            raise T1P0PreflightError(
                "query-v4 image digest does not match expected RepoDigest"
            )
        excluded_hashes, excluded_keyring_hashes = (
            load_excluded_authority_key_facts(
                t1_keyring_path=readiness_inputs.t1_keyring,
                expected_t1_keyring_sha256=(
                    pins.t1_authority_keyring_sha256
                ),
                l3_keyring_path=(
                    readiness_inputs.outcome_source.release_keyring
                ),
                expected_l3_keyring_sha256=(
                    pins.l3_authority_keyring_sha256
                ),
            )
        )
        provenance_signer_sha256 = getattr(
            args,
            "expected_query_v4_provenance_signing_tool_source_sha256",
        )
        provenance_signer_commit = getattr(
            args,
            "expected_query_v4_provenance_signing_tool_source_commit_sha",
        )
        provenance_receipt = verify_provenance(
            args.query_v4_build_registry_provenance,
            readiness_inputs.provenance_keyring,
            args.query_v4_content_attestation,
            expected_trusted_keyring_sha256=(
                pins.provenance_keyring_sha256
            ),
            expected_runtime_source_commit_sha=(
                args.expected_query_v4_source_commit_sha
            ),
            expected_image_digest=args.expected_query_v4_image_digest,
            expected_signing_tool_source_sha256=provenance_signer_sha256,
            expected_signing_tool_source_commit_sha=provenance_signer_commit,
            excluded_authority_key_hashes=excluded_hashes,
            excluded_authority_keyring_sha256s=excluded_keyring_hashes,
            now=now,
        )
        packet = build_preflight(
            readiness,
            regenerated,
            supplied_raw,
            validate_package(),
            readonly_dsn_metadata(args.dsn_file),
            provenance_receipt,
            now=now,
        )
        raw_sha256 = write_create_only(args.output, packet)
    except (
        BuildRegistryProvenanceV3Error,
        OSError,
        OneShotError,
        QueryV4ImageAttestationError,
        QueryV4PackagingError,
        ReadinessV3Error,
        T1P0PreflightError,
        ValueError,
    ) as exc:
        print(f"T1/P0 preflight v2 blocked: {exc}", file=sys.stderr)
        return 2
    print(f"status={packet['status']}")
    print(f"preflight_id={packet['preflight_id']}")
    print(f"preflight_raw_sha256={raw_sha256}")
    print("production_query_attempted=false")
    print("p0_verdict=NOT_RUN")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
