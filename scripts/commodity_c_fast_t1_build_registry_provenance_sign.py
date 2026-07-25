#!/usr/bin/env python3
"""Sign a reviewed C_FAST T1 build and registry provenance record."""

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
)

from commodity_c_fast_t1_build_registry_provenance import (
    MAX_JSON_BYTES,
    PROVENANCE_SCHEMA_PATH,
    BuildRegistryProvenanceError,
    _hash_bytes,
    _load_json,
    _load_public_key,
    _validate_schema,
    add_runtime_file_hashes,
    canonical_json,
    load_excluded_authority_key_facts,
    unsigned_provenance_payload,
    validate_provenance_semantics,
    _validate_signer_independence,
    write_json_create_only,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    read_regular_file_strict,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BuildRegistryProvenanceError(
            "private key file is unavailable"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BuildRegistryProvenanceError(
            "private key must be a regular non-symlink file"
        )
    if info.st_uid != os.geteuid():
        raise BuildRegistryProvenanceError(
            "private key must be owned by the current user"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise BuildRegistryProvenanceError(
            "private key permissions must be 0600 or stricter"
        )
    try:
        raw = read_regular_file_strict(
            path,
            "build/registry provenance signing key",
            private=True,
            limit=MAX_JSON_BYTES,
        ).strip()
    except OneShotError as exc:
        raise BuildRegistryProvenanceError(str(exc)) from exc
    if raw.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(
                raw,
                password=None,
            )
        except (TypeError, ValueError) as exc:
            raise BuildRegistryProvenanceError(
                "private key PEM is invalid or encrypted"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise BuildRegistryProvenanceError(
                "private key is not Ed25519"
            )
        return key
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise BuildRegistryProvenanceError(
            "private key must be Ed25519 PEM or base64 raw bytes"
        ) from exc
    if len(decoded) != 32:
        raise BuildRegistryProvenanceError(
            "raw Ed25519 private key must contain exactly 32 bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(decoded)


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
    excluded_authority_key_hashes: list[str],
    excluded_authority_keyring_sha256s: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    if "signature" in draft:
        raise BuildRegistryProvenanceError(
            "unsigned provenance input must omit signature"
        )
    payload = add_runtime_file_hashes(draft)
    payload["signature"] = PLACEHOLDER_SIGNATURE
    _validate_schema(
        payload,
        PROVENANCE_SCHEMA_PATH,
        "build and registry provenance draft",
    )
    keyring_sha256 = _hash_bytes(canonical_json(trusted_keyring))
    if keyring_sha256 != expected_trusted_keyring_sha256:
        raise BuildRegistryProvenanceError(
            "trusted keyring does not match independent signing pin"
        )
    if payload["trusted_keyring_sha256"] != keyring_sha256:
        raise BuildRegistryProvenanceError(
            "trusted keyring does not match provenance"
        )
    trusted_public = _load_public_key(
        trusted_keyring,
        str(payload["signer_key_id"]),
    )
    _validate_signer_independence(
        payload,
        trusted_public,
        excluded_authority_key_hashes,
        excluded_authority_keyring_sha256s,
    )
    expected_public = trusted_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise BuildRegistryProvenanceError(
            "private key does not match trusted provenance signer"
        )
    validate_provenance_semantics(
        payload,
        content_raw,
        content,
        expected_runtime_source_commit_sha=(
            expected_runtime_source_commit_sha
        ),
        expected_image_digest=expected_image_digest,
        now=now,
    )
    payload["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(unsigned_provenance_payload(payload))
        )
    ).decode("ascii")
    _validate_schema(
        payload,
        PROVENANCE_SCHEMA_PATH,
        "signed build and registry provenance",
    )
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-trusted-keyring-sha256",
        required=True,
    )
    parser.add_argument(
        "--content-attestation",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-runtime-source-commit-sha",
        required=True,
    )
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument(
        "--t1-authority-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-t1-authority-keyring-sha256",
        required=True,
    )
    parser.add_argument(
        "--l3-authority-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-l3-authority-keyring-sha256",
        required=True,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        (
            excluded_key_hashes,
            excluded_keyring_hashes,
        ) = load_excluded_authority_key_facts(
            t1_keyring_path=args.t1_authority_keyring,
            expected_t1_keyring_sha256=(
                args.expected_t1_authority_keyring_sha256
            ),
            l3_keyring_path=args.l3_authority_keyring,
            expected_l3_keyring_sha256=(
                args.expected_l3_authority_keyring_sha256
            ),
        )
        _draft_raw, draft = _load_json(
            args.input,
            "unsigned build and registry provenance",
        )
        _keyring_raw, keyring = _load_json(
            args.trusted_keyring,
            "build and registry provenance trusted keyring",
            private=True,
        )
        content_raw, content = _load_json(
            args.content_attestation,
            "OCI content attestation",
        )
        signed = sign_provenance(
            draft,
            load_private_key(args.private_key_file),
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
            excluded_authority_key_hashes=excluded_key_hashes,
            excluded_authority_keyring_sha256s=(
                excluded_keyring_hashes
            ),
        )
        write_json_create_only(args.output, signed)
    except (
        BuildRegistryProvenanceError,
        OSError,
        ValueError,
    ) as exc:
        print(
            f"build/registry provenance signing failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"signed build/registry provenance written: {args.output}")
    print(f"provenance_id={signed['provenance_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
