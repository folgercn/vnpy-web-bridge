#!/usr/bin/env python3
"""Sign one independently reviewed C_FAST P0 terminal acceptance."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commodity_c_fast_p0_acceptance import (
    ACCEPTANCE_SCHEMA_PATH,
    PLACEHOLDER_SIGNATURE,
    P0AcceptanceError,
    P0BundlePaths,
    _load_acceptance_keyring,
    add_bundle_arguments,
    canonical_json,
    paths_from_args,
    unsigned_acceptance_payload,
    validate_acceptance_bindings,
    validate_json_schema,
    verify_t1_bundle,
)
from commodity_c_fast_t1_one_shot import OneShotError, load_json_strict
from commodity_c_fast_t1_sign_release import (
    load_private_key,
    write_private_json_create_only,
)


def sign_acceptance(
    draft: dict,
    private_key: Ed25519PrivateKey,
    acceptance_keyring_path: Path,
    paths: P0BundlePaths,
    *,
    expected_acceptance_keyring_sha256: str,
    expected_t1_keyring_sha256: str,
) -> dict:
    if "signature" in draft:
        raise P0AcceptanceError(
            "unsigned P0 acceptance must omit signature"
        )
    verified = verify_t1_bundle(
        paths,
        expected_t1_keyring_sha256=expected_t1_keyring_sha256,
    )
    candidate = {**draft, "signature": PLACEHOLDER_SIGNATURE}
    validate_acceptance_bindings(candidate, verified)
    _keyring, public_key, keyring_sha256 = _load_acceptance_keyring(
        acceptance_keyring_path,
        expected_sha256=expected_acceptance_keyring_sha256,
        key_id=str(candidate["signer_key_id"]),
    )
    if candidate["acceptance_keyring_sha256"] != keyring_sha256:
        raise P0AcceptanceError(
            "P0 acceptance keyring binding mismatch"
        )
    expected_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise P0AcceptanceError(
            "private key does not match the trusted acceptance signer"
        )
    candidate["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(unsigned_acceptance_payload(candidate))
        )
    ).decode("ascii")
    validate_json_schema(
        candidate,
        ACCEPTANCE_SCHEMA_PATH,
        "signed P0 acceptance",
    )
    return candidate


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument(
        "--acceptance-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-acceptance-keyring-sha256",
        required=True,
    )
    add_bundle_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        draft = load_json_strict(
            args.input,
            "unsigned P0 acceptance",
            private=True,
        )
        signed = sign_acceptance(
            draft,
            load_private_key(args.private_key_file),
            args.acceptance_trusted_keyring,
            paths_from_args(args),
            expected_acceptance_keyring_sha256=(
                args.expected_acceptance_keyring_sha256
            ),
            expected_t1_keyring_sha256=(
                args.expected_t1_keyring_sha256
            ),
        )
        write_private_json_create_only(args.output, signed)
    except (
        P0AcceptanceError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"P0 acceptance signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed P0 acceptance written: {args.output}")
    print(f"acceptance_id: {signed['acceptance_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
