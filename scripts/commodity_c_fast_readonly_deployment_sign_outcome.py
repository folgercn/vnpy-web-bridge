#!/usr/bin/env python3
"""Sign a human-reviewed C_FAST readonly deployment post-outcome."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commodity_c_fast_readonly_deployment_outcome import (
    OUTCOME_KEYRING_VERSION,
    OUTCOME_KEY_PURPOSE,
    OUTCOME_SCHEMA_PATH,
    T1_KEYRING_VERSION,
    T1_KEY_PURPOSE,
    DeploymentOutcomeError,
    OutcomeSourcePaths,
    PostEvidencePaths,
    VerifiedSourceChain,
    _load_public_keys,
    _validate_receipt_chain,
    add_post_arguments,
    add_source_arguments,
    canonical_json,
    expected_outcome_payload,
    post_paths_from_args,
    source_paths_from_args,
    unsigned_outcome_payload,
    validate_outcome_custody_path,
    validate_outcome_semantics,
    verify_post_bundle,
    write_signed_outcome_create_only,
)
from commodity_c_fast_readonly_deployment_release import (
    DeploymentReleaseError,
    _load_json,
    _require_aware_datetime,
    _validate_schema,
)
from commodity_c_fast_readonly_deployment_sign_release import (
    load_private_key,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def sign_outcome(
    draft: dict,
    private_key: Ed25519PrivateKey,
    outcome_keyring_path: Path,
    t1_keyring_path: Path,
    source_paths: OutcomeSourcePaths,
    post_paths: PostEvidencePaths,
    *,
    expected_outcome_keyring_sha256: str,
    expected_release_keyring_sha256: str,
    expected_t1_keyring_sha256: str,
    expected_outcome_source_commit_sha: str,
    expected_release_source_commit_sha: str,
    expected_questdb_image_digest: str,
    now: datetime | None = None,
    return_verified_source: bool = False,
) -> dict | tuple[dict, VerifiedSourceChain]:
    if "signature" in draft:
        raise DeploymentOutcomeError(
            "unsigned outcome input must omit signature"
        )
    try:
        current_time = (
            datetime.now(timezone.utc)
            if now is None
            else _require_aware_datetime(now, "now")
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    source = _validate_receipt_chain(
        source_paths,
        expected_release_keyring_sha256=expected_release_keyring_sha256,
        expected_release_source_commit_sha=expected_release_source_commit_sha,
        expected_questdb_image_digest=expected_questdb_image_digest,
    )
    post = verify_post_bundle(source, source_paths.pre_evidence, post_paths)
    payload = expected_outcome_payload(
        draft,
        source,
        post,
        outcome_keyring_sha256=expected_outcome_keyring_sha256,
        t1_keyring_sha256=expected_t1_keyring_sha256,
        outcome_source_commit_assertion=expected_outcome_source_commit_sha,
    )
    payload["signature"] = PLACEHOLDER_SIGNATURE
    try:
        _validate_schema(
            payload,
            OUTCOME_SCHEMA_PATH,
            "unsigned deployment outcome draft",
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    validate_outcome_semantics(payload, now=current_time)

    outcome_keys, _outcome_hash = _load_public_keys(
        outcome_keyring_path,
        expected_sha256=expected_outcome_keyring_sha256,
        expected_version=OUTCOME_KEYRING_VERSION,
        purpose=OUTCOME_KEY_PURPOSE,
        label="readonly deployment outcome keyring",
    )
    t1_keys, _t1_hash = _load_public_keys(
        t1_keyring_path,
        expected_sha256=expected_t1_keyring_sha256,
        expected_version=T1_KEYRING_VERSION,
        purpose=T1_KEY_PURPOSE,
        label="T1 trusted keyring",
    )
    signer_id = str(payload["signer_key_id"])
    try:
        expected_public = outcome_keys[signer_id]
    except KeyError as exc:
        raise DeploymentOutcomeError(
            "outcome signer is absent from pinned outcome keyring"
        ) from exc
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise DeploymentOutcomeError(
            "private key does not match trusted outcome signer"
        )
    if actual_public in {
        source.release_signer_public_bytes,
        *t1_keys.values(),
    }:
        raise DeploymentOutcomeError(
            "outcome signer must be independent from release and T1 signers"
        )
    payload["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_outcome_payload(payload)))
    ).decode("ascii")
    try:
        _validate_schema(
            payload,
            OUTCOME_SCHEMA_PATH,
            "signed deployment outcome",
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    if return_verified_source:
        return payload, source
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--outcome-keyring", type=Path, required=True)
    parser.add_argument("--t1-keyring", type=Path, required=True)
    parser.add_argument("--expected-outcome-keyring-sha256", required=True)
    parser.add_argument("--expected-release-keyring-sha256", required=True)
    parser.add_argument("--expected-t1-keyring-sha256", required=True)
    parser.add_argument("--expected-outcome-source-commit-sha", required=True)
    parser.add_argument("--expected-release-source-commit-sha", required=True)
    parser.add_argument("--expected-questdb-image-digest", required=True)
    add_source_arguments(parser)
    add_post_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        _draft_raw, draft = _load_json(
            args.input,
            "unsigned deployment outcome",
        )
        signed_result = sign_outcome(
            draft,
            load_private_key(args.private_key_file),
            args.outcome_keyring,
            args.t1_keyring,
            source_paths_from_args(args),
            post_paths_from_args(args),
            expected_outcome_keyring_sha256=(
                args.expected_outcome_keyring_sha256
            ),
            expected_release_keyring_sha256=(
                args.expected_release_keyring_sha256
            ),
            expected_t1_keyring_sha256=args.expected_t1_keyring_sha256,
            expected_outcome_source_commit_sha=(
                args.expected_outcome_source_commit_sha
            ),
            expected_release_source_commit_sha=(
                args.expected_release_source_commit_sha
            ),
            expected_questdb_image_digest=(
                args.expected_questdb_image_digest
            ),
            return_verified_source=True,
        )
        if not isinstance(signed_result, tuple):
            raise DeploymentOutcomeError(
                "internal signed outcome source result is invalid"
            )
        signed, source = signed_result
        validate_outcome_custody_path(args.output, source)
        write_signed_outcome_create_only(args.output, signed, source)
    except (DeploymentOutcomeError, OSError, ValueError) as exc:
        print(f"readonly deployment outcome signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed readonly deployment outcome written: {args.output}")
    print(f"outcome_id={signed['outcome_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
