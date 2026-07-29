#!/usr/bin/env python3
"""Offline-sign one human-reviewed C_FAST T1 query-v4 release."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization

from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    load_json_strict,
    read_root_owned_deployment_pin,
    release_attempt_id,
    validate_json_schema,
)
from commodity_c_fast_t1_query_v4 import (
    QUERY_KEYRING_SCHEMA_PATH,
    QUERY_V4_AUTHORITY_PIN_PATH,
    RELEASE_SCHEMA_PATH,
    QueryV4Error,
    _load_query_public_key,
    add_readiness_verification_arguments,
    unsigned_release_payload,
    validate_release_semantics,
    verify_query_key_domain_separation,
)
from commodity_c_fast_t1_readiness_v3 import (
    ReadinessV3Error,
    VerifiedReadinessPacket,
    _read_production_pins,
    inputs_from_args,
    verify_existing_readiness_packet,
)
from commodity_c_fast_t1_sign_release import (
    load_private_key,
    write_private_json_create_only,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def prepare_unsigned_payload(
    draft: dict,
    readiness: VerifiedReadinessPacket,
    *,
    now: datetime,
) -> dict:
    if "signature" in draft:
        raise QueryV4Error("unsigned query release must omit signature")
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    expected_attempt = release_attempt_id(release_id)
    supplied_attempt = payload.get("attempt_id")
    if supplied_attempt not in {None, expected_attempt}:
        raise QueryV4Error("attempt_id does not match release_id")
    payload["attempt_id"] = expected_attempt
    payload["signature"] = PLACEHOLDER_SIGNATURE
    validate_release_semantics(payload, readiness, now=now)
    return payload


def validate_signing_authority(
    draft: dict,
    query_keyring: dict,
    pinned_query_keyring_sha256: str,
) -> tuple[bytes, frozenset[bytes]]:
    validate_json_schema(
        query_keyring,
        QUERY_KEYRING_SCHEMA_PATH,
        "T1 query v4 keyring",
    )
    keyring_sha256 = hashlib.sha256(
        canonical_json(query_keyring)
    ).hexdigest()
    if (
        keyring_sha256 != pinned_query_keyring_sha256
        or keyring_sha256 != draft.get("trusted_keyring_sha256")
    ):
        raise QueryV4Error("query signing keyring does not match active pin")
    _public_key, expected_public_raw, materials = _load_query_public_key(
        query_keyring,
        str(draft.get("signer_key_id")),
    )
    return expected_public_raw, materials


def sign_release(
    draft: dict,
    readiness: VerifiedReadinessPacket,
    private_key: object,
    query_keyring: dict,
    pinned_query_keyring_sha256: str,
    *,
    now: datetime,
) -> dict:
    payload = prepare_unsigned_payload(draft, readiness, now=now)
    expected_public_raw, _materials = validate_signing_authority(
        payload,
        query_keyring,
        pinned_query_keyring_sha256,
    )
    try:
        private_public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise QueryV4Error("query signing private key is invalid") from exc
    if private_public_raw != expected_public_raw:
        raise QueryV4Error(
            "query signing private key does not match signer_key_id"
        )
    payload["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_release_payload(payload)))
    ).decode("ascii")
    validate_json_schema(payload, RELEASE_SCHEMA_PATH, "signed query release")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
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
            now=now,
        )
        query_keyring = load_json_strict(
            args.trusted_keyring,
            "T1 query v4 keyring",
            private=True,
        )
        query_pin = read_root_owned_deployment_pin(
            QUERY_V4_AUTHORITY_PIN_PATH,
            "query-v4 authority keyring",
        )
        draft = load_json_strict(args.input, "unsigned query release")
        prepare_unsigned_payload(draft, readiness, now=now)
        _expected_public_raw, query_materials = validate_signing_authority(
            draft,
            query_keyring,
            query_pin,
        )
        verify_query_key_domain_separation(
            query_materials,
            readiness_inputs,
            pins,
        )
        signed = sign_release(
            draft,
            readiness,
            load_private_key(args.private_key_file),
            query_keyring,
            query_pin,
            now=now,
        )
        write_private_json_create_only(args.output, signed)
    except (
        OSError,
        OneShotError,
        QueryV4Error,
        ReadinessV3Error,
        ValueError,
    ) as exc:
        print(f"T1 query-v4 signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed query release written: {args.output}")
    print(f"attempt_id={signed['attempt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
