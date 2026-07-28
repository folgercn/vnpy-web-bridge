#!/usr/bin/env python3
"""Sign one independently reviewed C_FAST collection-admission v1 release."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commodity_c_fast_execution_quality_collection_admission import (
    KEYRING_SCHEMA_PATH,
    PLACEHOLDER_SIGNATURE,
    RELEASE_SCHEMA_PATH,
    CollectionAdmissionError,
    _load_admission_keyring,
    add_source_arguments,
    canonical_json,
    source_kwargs_from_args,
    unsigned_admission_payload,
    validate_admission_bindings,
    verify_admission_sources,
)
from commodity_c_fast_p0_sign_acceptance_v2 import (
    write_private_json_create_only_verified,
)
from commodity_c_fast_t1_one_shot import (
    MAX_JSON_BYTES,
    OneShotError,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
)
from commodity_c_fast_t1_sign_release import load_private_key


def prepare_admission(
    draft: dict,
    admission_keyring_path: Path,
    *,
    expected_admission_keyring_sha256: str,
    custody_dir: Path,
    now: datetime,
    source_kwargs: dict,
) -> tuple[dict, object]:
    """Complete every public check before private-key material is loaded."""
    if "signature" in draft:
        raise CollectionAdmissionError(
            "unsigned collection-admission draft must omit signature"
        )
    sources = verify_admission_sources(**source_kwargs)
    candidate = {**draft, "signature": PLACEHOLDER_SIGNATURE}
    validate_admission_bindings(
        candidate,
        sources,
        custody_dir=custody_dir,
        now=now,
    )
    public_key, admission_materials, keyring_pin = (
        _load_admission_keyring(
            admission_keyring_path,
            expected_sha256=expected_admission_keyring_sha256,
            key_id=str(candidate["signer_key_id"]),
        )
    )
    if candidate["admission_keyring_sha256"] != keyring_pin:
        raise CollectionAdmissionError(
            "collection-admission keyring binding mismatch"
        )
    if admission_materials & sources.upstream_public_key_materials:
        raise CollectionAdmissionError(
            "collection-admission keyring reuses an upstream key"
        )
    validate_json_schema(
        parse_json_bytes(
            read_regular_file_strict(
                admission_keyring_path,
                "collection-admission trusted keyring",
                limit=MAX_JSON_BYTES,
                private=True,
            ),
            "collection-admission trusted keyring",
        ),
        KEYRING_SCHEMA_PATH,
        "collection-admission trusted keyring",
    )
    return candidate, public_key


def complete_signature(
    candidate: dict,
    public_key,
    private_key: Ed25519PrivateKey,
) -> dict:
    expected_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise CollectionAdmissionError(
            "private key does not match the trusted admission signer"
        )
    signed = dict(candidate)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_admission_payload(signed)))
    ).decode("ascii")
    validate_json_schema(
        signed,
        RELEASE_SCHEMA_PATH,
        "signed collection-admission release",
    )
    return signed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument(
        "--admission-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-admission-keyring-sha256",
        required=True,
    )
    parser.add_argument("--custody-dir", type=Path, required=True)
    add_source_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        draft = parse_json_bytes(
            read_regular_file_strict(
                args.input,
                "unsigned collection-admission draft",
                limit=MAX_JSON_BYTES,
                private=True,
            ),
            "unsigned collection-admission draft",
        )
        candidate, public_key = prepare_admission(
            draft,
            args.admission_trusted_keyring,
            expected_admission_keyring_sha256=(
                args.expected_admission_keyring_sha256
            ),
            custody_dir=args.custody_dir,
            now=datetime.now(timezone.utc),
            source_kwargs=source_kwargs_from_args(args),
        )
        signed = complete_signature(
            candidate,
            public_key,
            load_private_key(args.private_key_file),
        )
        write_private_json_create_only_verified(args.output, signed)
    except (
        CollectionAdmissionError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"collection-admission signing failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"signed collection-admission written: {args.output}")
    print(f"release_id: {signed['release_id']}")
    print("collection_authorized: false")
    print("runtime_activation_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
