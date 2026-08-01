#!/usr/bin/env python3
"""Offline signer for the query-v6 no-query authority foundation."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import commodity_c_fast_t1_query_v5_release as query_v5
import commodity_c_fast_t1_query_v6_authority as authority
from commodity_c_fast_t1_one_shot import OneShotError, load_json_strict
from commodity_c_fast_t1_sign_release import (
    load_private_key,
    write_private_json_create_only,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _bind(payload: dict[str, Any], field: str, expected: Any) -> None:
    supplied = payload.get(field)
    if supplied is not None and supplied != expected and not (
        isinstance(supplied, str) and supplied.startswith("PENDING_")
    ):
        raise authority.QueryV6AuthorityError(f"{field} does not match verifier")
    payload[field] = expected


def _private_key_matches(
    private_key: Ed25519PrivateKey,
    public_key: object,
) -> None:
    try:
        actual = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        expected = public_key.public_bytes_raw()
    except (AttributeError, TypeError, ValueError) as exc:
        raise authority.QueryV6AuthorityError("query-v6 signer key is invalid") from exc
    if actual != expected:
        raise authority.QueryV6AuthorityError(
            "query-v6 private key does not match signer_key_id"
        )


def prepare_release(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    provenance: query_v5.VerifiedProvenance,
    provenance_key_materials: frozenset[str],
    evidence: authority.AuthorityEvidence,
    *,
    expected_keyring_sha256: str,
    now: datetime,
) -> tuple[dict[str, Any], object]:
    if "signature" in draft:
        raise authority.QueryV6AuthorityError(
            "unsigned query-v6 foundation must omit signature"
        )
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    _bind(payload, "attempt_id", authority.release_attempt_id(release_id))
    keyring_hash = authority.sha256_bytes(authority.canonical_json(keyring))
    authority._same(
        keyring_hash, expected_keyring_sha256, "pinned query-v6 keyring"
    )
    _bind(payload, "trusted_keyring_sha256", keyring_hash)
    custody_path = str(payload.get("custody_absolute_path") or "")
    for field, value in authority.expected_runtime_bindings(
        provenance,
        evidence,
        custody_absolute_path=custody_path,
    ).items():
        _bind(payload, field, value)
    fixed = {
        "maximum_release_ttl_seconds": 600,
        "connect_timeout_seconds": 10,
        "statement_timeout_ms": 60_000,
        "maximum_runtime_seconds": 600,
        "one_shot": True,
        "maximum_uses": 1,
        "replay_allowed": False,
        "offline_verification_only": True,
    }
    for field, value in fixed.items():
        _bind(payload, field, value)
    for field in authority.FALSE_AUTHORITY_FIELDS + authority.FALSE_FACT_FIELDS:
        _bind(payload, field, False)
    for field in authority.ZERO_FACT_FIELDS:
        _bind(payload, field, 0)
    payload["signature"] = PLACEHOLDER_SIGNATURE
    authority.validate_release_semantics(
        payload, provenance, evidence, now=now
    )
    public_key, _signer_hash, release_materials = authority._validate_keyring(
        keyring, str(payload["signer_key_id"])
    )
    if (
        provenance_key_materials & release_materials
        or authority.known_domain_public_key_hashes(provenance, evidence)
        & release_materials
    ):
        raise authority.QueryV6AuthorityError(
            "existing and query-v6 key domains overlap"
        )
    return payload, public_key


def sign_release(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    provenance: query_v5.VerifiedProvenance,
    provenance_key_materials: frozenset[str],
    evidence: authority.AuthorityEvidence,
    private_key: Ed25519PrivateKey,
    *,
    expected_keyring_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    payload, public_key = prepare_release(
        draft,
        keyring,
        provenance,
        provenance_key_materials,
        evidence,
        expected_keyring_sha256=expected_keyring_sha256,
        now=now,
    )
    _private_key_matches(private_key, public_key)
    payload["signature"] = base64.b64encode(
        private_key.sign(authority.canonical_json(authority.unsigned_payload(payload)))
    ).decode("ascii")
    authority.validate_release_semantics(
        payload, provenance, evidence, now=now
    )
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    authority._common_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc)
    replay = query_v5.CompositionReplayInputs(
        query_v4_external_image_evidence_path=args.query_v4_external_image_evidence,
        query_v4_source_bundle_path=args.query_v4_source_bundle_archive,
        query_v4_oci_layout_archive_path=args.query_v4_oci_layout_archive,
        query_v4_content_attestation_path=args.query_v4_content_attestation,
        expected_query_v4_source_commit_sha=args.expected_query_v4_source_commit_sha,
        external_image_evidence_path=args.external_image_evidence,
        source_bundle_path=args.source_bundle_archive,
        final_oci_layout_path=args.final_oci_layout,
    )
    try:
        provenance, provenance_materials = query_v5.verify_provenance(
            args.signed_provenance,
            args.provenance_keyring,
            args.composition_attestation,
            args.final_oci_layout,
            replay,
            expected_provenance_keyring_sha256=(
                args.expected_provenance_keyring_sha256
            ),
            expected_source_commit_sha=args.expected_source_commit_sha,
            expected_image_digest=args.expected_image_digest,
            now=now,
        )
        evidence = authority.load_authority_evidence(
            args.readiness_v4,
            args.l3_outcome,
            args.query_manifest,
            args.runtime_pin_manifest,
            args.dsn_file_identity_attestation,
            readiness_inputs=authority._readiness_inputs_from_args(args),
            now=now,
        )
        _keyring_raw = authority._read_bytes(
            args.release_keyring, "query-v6 keyring", private=True
        )
        keyring = authority.parse_json_bytes(_keyring_raw, "query-v6 keyring")
        signed = sign_release(
            load_json_strict(args.input, "unsigned query-v6 foundation"),
            keyring,
            provenance,
            provenance_materials,
            evidence,
            load_private_key(args.private_key_file),
            expected_keyring_sha256=args.expected_release_keyring_sha256,
            now=now,
        )
        write_private_json_create_only(args.output, signed)
    except (
        OSError,
        OneShotError,
        query_v5.QueryV5ReleaseError,
        authority.QueryV6AuthorityError,
        ValueError,
    ) as exc:
        print(f"query-v6 signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed query-v6 authority foundation: {args.output}")
    print(f"attempt_id={signed['attempt_id']}")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
