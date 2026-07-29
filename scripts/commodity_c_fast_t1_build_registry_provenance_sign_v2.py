#!/usr/bin/env python3
"""Sign a reviewed query-v3 build/registry provenance-v2 record."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import os
from pathlib import Path
import stat
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import commodity_c_fast_t1_build_registry_provenance_v2 as provenance_v2
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    read_regular_file_strict,
)


SIGNER_SOURCE_PATH = Path(__file__).resolve()
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        info = path.lstat()
    except OSError as exc:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "private key file is unavailable"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "private key must be a regular non-symlink file"
        )
    if info.st_uid != os.geteuid():
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "private key must be owned by the current user"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "private key permissions must be 0600 or stricter"
        )
    try:
        raw = read_regular_file_strict(
            path,
            "build/registry provenance v2 signing key",
            private=True,
            limit=provenance_v2.MAX_JSON_BYTES,
        ).strip()
    except OneShotError as exc:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            str(exc)
        ) from exc
    if raw.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as exc:
            raise provenance_v2.BuildRegistryProvenanceV2Error(
                "private key PEM is invalid or encrypted"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise provenance_v2.BuildRegistryProvenanceV2Error(
                "private key is not Ed25519"
            )
        return key
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "private key must be Ed25519 PEM or base64 raw bytes"
        ) from exc
    if len(decoded) != 32:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "raw Ed25519 private key must contain exactly 32 bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(decoded)


def _signing_tool_source_identity(
    *,
    expected_source_sha256: str,
    expected_source_commit_sha: str,
) -> dict[str, str]:
    provenance_v2._validate_sha256(
        expected_source_sha256,
        "expected signing-tool source SHA256",
    )
    provenance_v2._validate_commit(
        expected_source_commit_sha,
        "expected signing-tool source commit",
    )
    actual_sha256 = provenance_v2._hash_bytes(
        provenance_v2._read_file(
            SIGNER_SOURCE_PATH,
            "provenance v2 signing tool source",
        )
    )
    provenance_v2._compare(
        actual_sha256,
        expected_source_sha256,
        "independently pinned signing-tool source SHA256",
    )
    return {
        "path": provenance_v2.SIGNING_TOOL_SOURCE_PATH,
        "source_commit_sha": expected_source_commit_sha,
        "sha256": actual_sha256,
        "verification_scope": provenance_v2.SIGNING_TOOL_IDENTITY_SCOPE,
    }


def prepare_provenance(
    draft: dict[str, Any],
    trusted_keyring: dict[str, Any],
    content_raw: bytes,
    content: dict[str, Any],
    *,
    expected_trusted_keyring_sha256: str,
    expected_runtime_source_commit_sha: str,
    expected_image_digest: str,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
    excluded_authority_key_hashes: list[str],
    excluded_authority_keyring_sha256s: dict[str, str],
    now: datetime | None = None,
) -> tuple[dict[str, Any], Ed25519PublicKey]:
    if "signature" in draft:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "unsigned provenance input must omit signature"
        )
    if "signing_tool_source_identity" in draft:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "signing-tool source identity is signer-generated"
        )
    payload = provenance_v2.add_runtime_file_hashes(draft)
    payload["signing_tool_source_identity"] = (
        _signing_tool_source_identity(
            expected_source_sha256=expected_signing_tool_source_sha256,
            expected_source_commit_sha=(
                expected_signing_tool_source_commit_sha
            ),
        )
    )
    payload["signature"] = PLACEHOLDER_SIGNATURE
    provenance_v2._validate_schema(
        payload,
        provenance_v2.PROVENANCE_SCHEMA_PATH,
        "build and registry provenance v2 draft",
    )
    keyring_sha256 = provenance_v2._hash_bytes(
        provenance_v2.canonical_json(trusted_keyring)
    )
    provenance_v2._compare(
        keyring_sha256,
        expected_trusted_keyring_sha256,
        "independent signing keyring pin",
    )
    provenance_v2._compare(
        str(payload["trusted_keyring_sha256"]),
        keyring_sha256,
        "provenance trusted keyring",
    )
    trusted_public, provenance_key_hashes = provenance_v2._load_public_keyset(
        trusted_keyring,
        str(payload["signer_key_id"]),
    )
    provenance_v2._validate_signer_independence(
        payload,
        provenance_key_hashes,
        excluded_authority_key_hashes,
        excluded_authority_keyring_sha256s,
    )
    provenance_v2.validate_provenance_semantics(
        payload,
        content_raw,
        content,
        expected_runtime_source_commit_sha=(
            expected_runtime_source_commit_sha
        ),
        expected_image_digest=expected_image_digest,
        expected_signing_tool_source_sha256=(
            expected_signing_tool_source_sha256
        ),
        expected_signing_tool_source_commit_sha=(
            expected_signing_tool_source_commit_sha
        ),
        now=now,
    )
    return payload, trusted_public


def complete_signature(
    prepared_payload: dict[str, Any],
    private_key: Ed25519PrivateKey,
    trusted_public: Ed25519PublicKey,
) -> dict[str, Any]:
    payload = dict(prepared_payload)
    expected_public = trusted_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise provenance_v2.BuildRegistryProvenanceV2Error(
            "private key does not match trusted provenance signer"
        )
    payload["signature"] = base64.b64encode(
        private_key.sign(
            provenance_v2.canonical_json(
                provenance_v2.unsigned_provenance_payload(payload)
            )
        )
    ).decode("ascii")
    provenance_v2._validate_schema(
        payload,
        provenance_v2.PROVENANCE_SCHEMA_PATH,
        "signed build and registry provenance v2",
    )
    return payload


def sign_provenance(
    draft: dict[str, Any],
    private_key: Ed25519PrivateKey,
    trusted_keyring: dict[str, Any],
    content_raw: bytes,
    content: dict[str, Any],
    *,
    expected_trusted_keyring_sha256: str,
    expected_runtime_source_commit_sha: str,
    expected_image_digest: str,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
    excluded_authority_key_hashes: list[str],
    excluded_authority_keyring_sha256s: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    prepared, trusted_public = prepare_provenance(
        draft,
        trusted_keyring,
        content_raw,
        content,
        expected_trusted_keyring_sha256=expected_trusted_keyring_sha256,
        expected_runtime_source_commit_sha=expected_runtime_source_commit_sha,
        expected_image_digest=expected_image_digest,
        expected_signing_tool_source_sha256=(
            expected_signing_tool_source_sha256
        ),
        expected_signing_tool_source_commit_sha=(
            expected_signing_tool_source_commit_sha
        ),
        excluded_authority_key_hashes=excluded_authority_key_hashes,
        excluded_authority_keyring_sha256s=(
            excluded_authority_keyring_sha256s
        ),
        now=now,
    )
    return complete_signature(prepared, private_key, trusted_public)


def sign_provenance_from_private_key_path(
    draft: dict[str, Any],
    private_key_path: Path,
    trusted_keyring: dict[str, Any],
    content_raw: bytes,
    content: dict[str, Any],
    **public_validation: Any,
) -> dict[str, Any]:
    prepared, trusted_public = prepare_provenance(
        draft,
        trusted_keyring,
        content_raw,
        content,
        **public_validation,
    )
    return complete_signature(
        prepared,
        load_private_key(private_key_path),
        trusted_public,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--expected-trusted-keyring-sha256", required=True)
    parser.add_argument("--content-attestation", type=Path, required=True)
    parser.add_argument(
        "--expected-runtime-source-commit-sha",
        required=True,
    )
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument(
        "--expected-signing-tool-source-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-signing-tool-source-commit-sha",
        required=True,
    )
    parser.add_argument("--t1-authority-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-t1-authority-keyring-sha256",
        required=True,
    )
    parser.add_argument("--l3-authority-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-l3-authority-keyring-sha256",
        required=True,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        excluded_hashes, excluded_keyring_hashes = (
            provenance_v2.load_excluded_authority_key_facts(
                t1_keyring_path=args.t1_authority_keyring,
                expected_t1_keyring_sha256=(
                    args.expected_t1_authority_keyring_sha256
                ),
                l3_keyring_path=args.l3_authority_keyring,
                expected_l3_keyring_sha256=(
                    args.expected_l3_authority_keyring_sha256
                ),
            )
        )
        _draft_raw, draft = provenance_v2._load_json(
            args.input,
            "unsigned build and registry provenance v2",
        )
        _keyring_raw, keyring = provenance_v2._load_json(
            args.trusted_keyring,
            "build and registry provenance trusted keyring",
            private=True,
        )
        content_raw, content = provenance_v2._load_json(
            args.content_attestation,
            "query-v3 OCI content attestation",
        )
        signed = sign_provenance_from_private_key_path(
            draft,
            args.private_key_file,
            keyring,
            content_raw,
            content,
            expected_trusted_keyring_sha256=(
                args.expected_trusted_keyring_sha256
            ),
            expected_runtime_source_commit_sha=(
                args.expected_runtime_source_commit_sha
            ),
            expected_image_digest=args.expected_image_digest,
            expected_signing_tool_source_sha256=(
                args.expected_signing_tool_source_sha256
            ),
            expected_signing_tool_source_commit_sha=(
                args.expected_signing_tool_source_commit_sha
            ),
            excluded_authority_key_hashes=excluded_hashes,
            excluded_authority_keyring_sha256s=excluded_keyring_hashes,
        )
        provenance_v2.write_json_create_only(args.output, signed)
    except (
        provenance_v2.BuildRegistryProvenanceV2Error,
        OSError,
        ValueError,
    ) as exc:
        print(
            f"build/registry provenance v2 signing failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"signed build/registry provenance v2 written: {args.output}")
    print(f"provenance_id={signed['provenance_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
