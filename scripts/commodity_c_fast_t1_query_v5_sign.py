#!/usr/bin/env python3
"""Offline signer for query-v5 provenance and one-shot release artifacts."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import commodity_c_fast_t1_query_v5_release as release_v5
from commodity_c_fast_t1_one_shot import OneShotError, load_json_strict
from commodity_c_fast_t1_sign_release import (
    load_private_key,
    write_private_json_create_only,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _bind(payload: dict[str, Any], field: str, expected: Any) -> None:
    supplied = payload.get(field)
    if supplied not in {None, expected}:
        raise release_v5.QueryV5ReleaseError(f"{field} does not match runtime")
    payload[field] = expected


def _private_key_matches(
    private_key: Ed25519PrivateKey,
    public_key: object,
    label: str,
) -> None:
    try:
        actual = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        expected = public_key.public_bytes_raw()
    except (AttributeError, TypeError, ValueError) as exc:
        raise release_v5.QueryV5ReleaseError(f"{label} key is invalid") from exc
    if actual != expected:
        raise release_v5.QueryV5ReleaseError(
            f"{label} private key does not match signer_key_id"
        )


def prepare_provenance(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    composition_raw: bytes,
    composition: dict[str, Any],
    final_oci: release_v5.VerifiedFinalOci,
    composition_replay: release_v5.CompositionReplayInputs,
    *,
    expected_keyring_sha256: str,
    expected_source_commit_sha: str,
    expected_image_digest: str,
    now: datetime,
) -> tuple[dict[str, Any], object]:
    if "signature" in draft:
        raise release_v5.QueryV5ReleaseError("unsigned provenance must omit signature")
    payload = dict(draft)
    keyring_hash = release_v5.sha256_bytes(release_v5.canonical_json(keyring))
    release_v5._same(
        keyring_hash,
        expected_keyring_sha256,
        "pinned provenance keyring",
    )
    _bind(payload, "trusted_keyring_sha256", keyring_hash)
    _bind(
        payload,
        "provenance_verifier_sha256",
        release_v5._source_sha256(
            release_v5.VERIFIER_PATH, "query-v5 provenance verifier"
        ),
    )
    _bind(
        payload,
        "provenance_schema_sha256",
        release_v5._schema_sha256(
            release_v5.PROVENANCE_SCHEMA_PATH, "query-v5 provenance schema"
        ),
    )
    _bind(
        payload,
        "release_schema_sha256",
        release_v5._schema_sha256(
            release_v5.RELEASE_SCHEMA_PATH, "query-v5 release schema"
        ),
    )
    _bind(
        payload,
        "pre_dsn_receipt_schema_sha256",
        release_v5._schema_sha256(
            release_v5.RECEIPT_SCHEMA_PATH, "query-v5 receipt schema"
        ),
    )
    _bind(
        payload,
        "signing_tool_source_path",
        "scripts/commodity_c_fast_t1_query_v5_sign.py",
    )
    _bind(
        payload,
        "signing_tool_source_sha256",
        release_v5._source_sha256(release_v5.SIGNER_PATH, "query-v5 signing tool"),
    )
    _bind(
        payload,
        "signing_tool_source_commit_sha",
        expected_source_commit_sha,
    )
    payload["signature"] = PLACEHOLDER_SIGNATURE
    release_v5.replay_composition_attestation(
        composition,
        composition_replay,
        expected_source_commit_sha=expected_source_commit_sha,
    )
    release_v5.validate_provenance_semantics(
        payload,
        composition_raw,
        composition,
        final_oci,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_image_digest=expected_image_digest,
        now=now,
    )
    public_key, _signer_hash, _materials = release_v5._validate_keyring(
        keyring,
        schema_version=release_v5.PROVENANCE_KEYRING_VERSION,
        purpose=release_v5.PROVENANCE_KEY_PURPOSE,
        signer_key_id=str(payload["signer_key_id"]),
    )
    return payload, public_key


def sign_provenance(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    composition_raw: bytes,
    composition: dict[str, Any],
    final_oci: release_v5.VerifiedFinalOci,
    composition_replay: release_v5.CompositionReplayInputs,
    private_key: Ed25519PrivateKey,
    *,
    expected_keyring_sha256: str,
    expected_source_commit_sha: str,
    expected_image_digest: str,
    now: datetime,
) -> dict[str, Any]:
    payload, public_key = prepare_provenance(
        draft,
        keyring,
        composition_raw,
        composition,
        final_oci,
        composition_replay,
        expected_keyring_sha256=expected_keyring_sha256,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_image_digest=expected_image_digest,
        now=now,
    )
    _private_key_matches(private_key, public_key, "provenance signer")
    payload["signature"] = base64.b64encode(
        private_key.sign(
            release_v5.canonical_json(release_v5.unsigned_payload(payload))
        )
    ).decode("ascii")
    release_v5._validate_schema(
        payload, release_v5.PROVENANCE_SCHEMA_PATH, "signed query-v5 provenance"
    )
    return payload


def prepare_release(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    provenance: release_v5.VerifiedProvenance,
    provenance_materials: frozenset[str],
    *,
    expected_keyring_sha256: str,
    now: datetime,
) -> tuple[dict[str, Any], object]:
    if "signature" in draft:
        raise release_v5.QueryV5ReleaseError("unsigned release must omit signature")
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    attempt_id = release_v5.release_attempt_id(release_id)
    _bind(payload, "attempt_id", attempt_id)
    keyring_hash = release_v5.sha256_bytes(release_v5.canonical_json(keyring))
    release_v5._same(
        keyring_hash,
        expected_keyring_sha256,
        "pinned release keyring",
    )
    _bind(payload, "trusted_keyring_sha256", keyring_hash)
    bindings = {
        "provenance_raw_sha256": provenance.raw_sha256,
        "provenance_canonical_sha256": provenance.canonical_sha256,
        "provenance_signer_public_key_sha256": (provenance.signer_public_key_sha256),
        "composition_attestation_raw_sha256": (provenance.composition_raw_sha256),
        "composition_attestation_canonical_sha256": (
            provenance.composition_canonical_sha256
        ),
        "runtime_source_commit_sha": provenance.payload["runtime_source_commit_sha"],
        "runtime_image_reference": provenance.payload["image_reference"],
        "runtime_image_digest": provenance.payload["image_digest"],
        "runtime_image_id": provenance.payload["image_id"],
        "provenance_schema_sha256": release_v5._schema_sha256(
            release_v5.PROVENANCE_SCHEMA_PATH, "query-v5 provenance schema"
        ),
        "composition_attestation_schema_sha256": release_v5._schema_sha256(
            release_v5.COMPOSITION_SCHEMA_PATH, "query-v5 composition schema"
        ),
        "release_schema_sha256": release_v5._schema_sha256(
            release_v5.RELEASE_SCHEMA_PATH, "query-v5 release schema"
        ),
        "pre_dsn_receipt_schema_sha256": release_v5._schema_sha256(
            release_v5.RECEIPT_SCHEMA_PATH, "query-v5 receipt schema"
        ),
        "pre_dsn_gate_source_sha256": release_v5._source_sha256(
            release_v5.VERIFIER_PATH, "query-v5 pre-DSN gate"
        ),
        "query_v5_code_only_launcher_sha256": release_v5._source_sha256(
            release_v5.LAUNCHER_PATH, "query-v5 code-only launcher"
        ),
    }
    for field, expected in bindings.items():
        _bind(payload, field, expected)
    payload["signature"] = PLACEHOLDER_SIGNATURE
    release_v5.validate_release_semantics(payload, provenance, now=now)
    public_key, _signer_hash, release_materials = release_v5._validate_keyring(
        keyring,
        schema_version="commodity_c_fast_t1_query_v5_trusted_keys_v1",
        purpose=release_v5.RELEASE_KEY_PURPOSE,
        signer_key_id=str(payload["signer_key_id"]),
    )
    if provenance_materials & release_materials:
        raise release_v5.QueryV5ReleaseError(
            "provenance and release key domains overlap"
        )
    return payload, public_key


def sign_release(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    provenance: release_v5.VerifiedProvenance,
    provenance_materials: frozenset[str],
    private_key: Ed25519PrivateKey,
    *,
    expected_keyring_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    payload, public_key = prepare_release(
        draft,
        keyring,
        provenance,
        provenance_materials,
        expected_keyring_sha256=expected_keyring_sha256,
        now=now,
    )
    _private_key_matches(private_key, public_key, "release signer")
    payload["signature"] = base64.b64encode(
        private_key.sign(
            release_v5.canonical_json(release_v5.unsigned_payload(payload))
        )
    ).decode("ascii")
    release_v5._validate_schema(
        payload, release_v5.RELEASE_SCHEMA_PATH, "signed query-v5 release"
    )
    return payload


def _common_provenance_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--expected-provenance-keyring-sha256", required=True)
    parser.add_argument("--composition-attestation", type=Path, required=True)
    parser.add_argument("--final-oci-layout", type=Path, required=True)
    parser.add_argument(
        "--query-v4-external-image-evidence", type=Path, required=True
    )
    parser.add_argument("--query-v4-source-bundle-archive", type=Path, required=True)
    parser.add_argument("--query-v4-oci-layout-archive", type=Path, required=True)
    parser.add_argument("--query-v4-content-attestation", type=Path, required=True)
    parser.add_argument("--expected-query-v4-source-commit-sha", required=True)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--source-bundle-archive", type=Path, required=True)
    parser.add_argument("--expected-source-commit-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)


def _composition_replay_inputs(args: argparse.Namespace) -> release_v5.CompositionReplayInputs:
    return release_v5.CompositionReplayInputs(
        query_v4_external_image_evidence_path=args.query_v4_external_image_evidence,
        query_v4_source_bundle_path=args.query_v4_source_bundle_archive,
        query_v4_oci_layout_archive_path=args.query_v4_oci_layout_archive,
        query_v4_content_attestation_path=args.query_v4_content_attestation,
        expected_query_v4_source_commit_sha=args.expected_query_v4_source_commit_sha,
        external_image_evidence_path=args.external_image_evidence,
        source_bundle_path=args.source_bundle_archive,
        final_oci_layout_path=args.final_oci_layout,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    provenance = commands.add_parser("sign-provenance")
    provenance.add_argument("--input", type=Path, required=True)
    provenance.add_argument("--private-key-file", type=Path, required=True)
    provenance.add_argument("--output", type=Path, required=True)
    _common_provenance_arguments(provenance)
    release = commands.add_parser("sign-release")
    release.add_argument("--input", type=Path, required=True)
    release.add_argument("--private-key-file", type=Path, required=True)
    release.add_argument("--output", type=Path, required=True)
    release.add_argument("--signed-provenance", type=Path, required=True)
    release.add_argument("--release-keyring", type=Path, required=True)
    release.add_argument("--expected-release-keyring-sha256", required=True)
    _common_provenance_arguments(release)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        now = datetime.now(timezone.utc)
        composition_raw, composition = release_v5._load_json(
            args.composition_attestation, "query-v5 composition attestation"
        )
        _provenance_keyring_raw, provenance_keyring = release_v5._load_json(
            args.provenance_keyring,
            "query-v5 provenance keyring",
            private=True,
        )
        if args.command == "sign-provenance":
            final_oci = release_v5.load_verified_final_oci(args.final_oci_layout)
            signed = sign_provenance(
                load_json_strict(args.input, "unsigned query-v5 provenance"),
                provenance_keyring,
                composition_raw,
                composition,
                final_oci,
                _composition_replay_inputs(args),
                load_private_key(args.private_key_file),
                expected_keyring_sha256=(args.expected_provenance_keyring_sha256),
                expected_source_commit_sha=args.expected_source_commit_sha,
                expected_image_digest=args.expected_image_digest,
                now=now,
            )
        else:
            verified, provenance_materials = release_v5.verify_provenance(
                args.signed_provenance,
                args.provenance_keyring,
                args.composition_attestation,
                args.final_oci_layout,
                _composition_replay_inputs(args),
                expected_provenance_keyring_sha256=(
                    args.expected_provenance_keyring_sha256
                ),
                expected_source_commit_sha=args.expected_source_commit_sha,
                expected_image_digest=args.expected_image_digest,
                now=now,
            )
            _release_keyring_raw, release_keyring = release_v5._load_json(
                args.release_keyring,
                "query-v5 release keyring",
                private=True,
            )
            signed = sign_release(
                load_json_strict(args.input, "unsigned query-v5 release"),
                release_keyring,
                verified,
                provenance_materials,
                load_private_key(args.private_key_file),
                expected_keyring_sha256=args.expected_release_keyring_sha256,
                now=now,
            )
        write_private_json_create_only(args.output, signed)
    except (
        OSError,
        OneShotError,
        release_v5.QueryV5ReleaseError,
        ValueError,
    ) as exc:
        print(f"query-v5 signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed query-v5 {args.command}: {args.output}")
    if args.command == "sign-release":
        print(f"attempt_id={signed['attempt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
