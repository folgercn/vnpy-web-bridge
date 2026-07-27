#!/usr/bin/env python3
"""Sign one independently reviewed C_FAST query-v3 P0 acceptance v2."""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commodity_c_fast_p0_acceptance_v2 import (
    ACCEPTANCE_SCHEMA_PATH,
    PLACEHOLDER_SIGNATURE,
    P0AcceptanceV2Error,
    P0BundleV2Paths,
    _load_acceptance_keyring,
    add_bundle_arguments,
    canonical_json,
    expected_keyring_hashes_from_args,
    paths_from_args,
    require_independent_acceptance_signer,
    unsigned_acceptance_payload,
    validate_acceptance_bindings,
    validate_json_schema,
    verify_query_v3_bundle,
)
from commodity_c_fast_t1_one_shot import (
    MAX_JSON_BYTES,
    OneShotError,
    parse_json_bytes,
    read_regular_file_strict,
)
from commodity_c_fast_t1_sign_release import load_private_key


def prepare_acceptance(
    draft: dict,
    acceptance_keyring_path: Path,
    paths: P0BundleV2Paths,
    *,
    expected_acceptance_keyring_sha256: str,
    expected_keyring_sha256: dict[str, str],
) -> tuple[
    dict,
    object,
    str,
]:
    """Finish every public/evidence check before private-key material is read."""
    if "signature" in draft:
        raise P0AcceptanceV2Error(
            "unsigned P0 acceptance v2 must omit signature"
        )
    verified = verify_query_v3_bundle(
        paths,
        expected_keyring_sha256=expected_keyring_sha256,
    )
    candidate = {**draft, "signature": PLACEHOLDER_SIGNATURE}
    validate_acceptance_bindings(candidate, verified)
    public_key, acceptance_materials, keyring_digest = (
        _load_acceptance_keyring(
            acceptance_keyring_path,
            expected_sha256=expected_acceptance_keyring_sha256,
            key_id=str(candidate["signer_key_id"]),
        )
    )
    if acceptance_materials & verified.upstream_public_key_materials:
        raise P0AcceptanceV2Error(
            "acceptance-v2 keyring reuses an active or unused upstream key"
        )
    require_independent_acceptance_signer(
        verified.upstream_public_key_materials,
        public_key,
    )
    if candidate["acceptance_keyring_sha256"] != keyring_digest:
        raise P0AcceptanceV2Error(
            "acceptance-v2 keyring binding mismatch"
        )
    return candidate, public_key, keyring_digest


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
        raise P0AcceptanceV2Error(
            "private key does not match the trusted acceptance-v2 signer"
        )
    signed = dict(candidate)
    signed["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(unsigned_acceptance_payload(signed))
        )
    ).decode("ascii")
    validate_json_schema(
        signed,
        ACCEPTANCE_SCHEMA_PATH,
        "signed P0 acceptance v2",
    )
    return signed


def sign_acceptance(
    draft: dict,
    private_key: Ed25519PrivateKey,
    acceptance_keyring_path: Path,
    paths: P0BundleV2Paths,
    *,
    expected_acceptance_keyring_sha256: str,
    expected_keyring_sha256: dict[str, str],
) -> dict:
    candidate, public_key, _digest = prepare_acceptance(
        draft,
        acceptance_keyring_path,
        paths,
        expected_acceptance_keyring_sha256=(
            expected_acceptance_keyring_sha256
        ),
        expected_keyring_sha256=expected_keyring_sha256,
    )
    return complete_signature(candidate, public_key, private_key)


def write_private_json_create_only_verified(
    path: Path,
    payload: dict,
) -> None:
    expanded = path.expanduser()
    output = expanded if expanded.is_absolute() else Path.cwd() / expanded
    normalized = Path(os.path.normpath(str(output)))
    if normalized != output:
        raise P0AcceptanceV2Error(
            "signed output path must already be normalized"
        )
    parent = output.parent.resolve(strict=True)
    if output.parent != parent:
        raise P0AcceptanceV2Error(
            "signed output parent must not traverse a symlink"
        )
    output = parent / output.name
    parent_stat = parent.lstat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise P0AcceptanceV2Error(
            "signed output parent must be a pre-existing private owned directory"
        )
    raw = canonical_json(payload) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    observed = read_regular_file_strict(
        output,
        "signed P0 acceptance v2 output",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    if observed != raw:
        raise P0AcceptanceV2Error(
            "signed P0 acceptance v2 changed after create-only write"
        )
    reparsed = parse_json_bytes(
        observed,
        "signed P0 acceptance v2 output",
    )
    if reparsed != payload:
        raise P0AcceptanceV2Error(
            "signed P0 acceptance v2 output did not round-trip exactly"
        )


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
        draft_raw = read_regular_file_strict(
            args.input,
            "unsigned P0 acceptance v2",
            limit=MAX_JSON_BYTES,
            private=True,
        )
        draft = parse_json_bytes(draft_raw, "unsigned P0 acceptance v2")
        candidate, public_key, _digest = prepare_acceptance(
            draft,
            args.acceptance_trusted_keyring,
            paths_from_args(args),
            expected_acceptance_keyring_sha256=(
                args.expected_acceptance_keyring_sha256
            ),
            expected_keyring_sha256=expected_keyring_hashes_from_args(args),
        )
        signed = complete_signature(
            candidate,
            public_key,
            load_private_key(args.private_key_file),
        )
        write_private_json_create_only_verified(args.output, signed)
    except (
        P0AcceptanceV2Error,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"P0 acceptance v2 signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed P0 acceptance v2 written: {args.output}")
    print(f"acceptance_id: {signed['acceptance_id']}")
    print("trading_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
