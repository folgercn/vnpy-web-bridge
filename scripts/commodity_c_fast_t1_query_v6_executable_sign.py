#!/usr/bin/env python3
"""Offline signer for a distinct query-v6 executable one-shot release."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import commodity_c_fast_t1_query_v6_authority as foundation_v6
import commodity_c_fast_t1_query_v6_executable as executable
from commodity_c_fast_t1_one_shot import load_json_strict
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
        raise executable.QueryV6ExecutableError(
            f"{field} does not match executable verifier"
        )
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
        raise executable.QueryV6ExecutableError(
            "executable signer private key is invalid"
        ) from exc
    if actual != expected:
        raise executable.QueryV6ExecutableError(
            "executable private key does not match signer_key_id"
        )


def prepare_release(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    foundation_keyring_path: Path,
    foundation: foundation_v6.VerifiedAuthorityFoundation,
    pins: executable.ExecutablePins,
    *,
    now: datetime,
) -> tuple[dict[str, Any], object]:
    if "signature" in draft:
        raise executable.QueryV6ExecutableError(
            "unsigned executable release must omit signature"
        )
    executable.validate_pins(pins)
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    _bind(
        payload,
        "attempt_id",
        foundation_v6.release_attempt_id(release_id),
    )
    keyring_hash = executable.sha256_bytes(executable.canonical_json(keyring))
    executable._same(
        keyring_hash,
        str(pins.executable_keyring_sha256),
        "active executable keyring",
    )
    _bind(payload, "trusted_keyring_sha256", keyring_hash)
    _bind(
        payload,
        "foundation",
        executable.expected_foundation_binding(foundation),
    )
    _bind(payload, "execution", executable.expected_execution_binding(pins))
    for field in executable.TRUE_AUTHORITY_FIELDS:
        _bind(payload, field, True)
    for field in executable.FALSE_AUTHORITY_FIELDS:
        _bind(payload, field, False)
    for field, value in {
        "one_shot": True,
        "maximum_uses": 1,
        "replay_allowed": False,
        "server_enforced_readonly_required": True,
        "consume_before_dsn_secret_read": True,
        "consume_before_network": True,
        "final_revalidation_before_network": True,
        "pre_and_post_readonly_proof_required": True,
    }.items():
        _bind(payload, field, value)
    payload["signature"] = PLACEHOLDER_SIGNATURE
    executable.validate_release_semantics(payload, foundation, pins, now=now)
    public_key, _signer_hash, materials = executable._validate_keyring(
        keyring,
        str(payload["signer_key_id"]),
    )
    prior_materials = set(
        executable.foundation_key_materials(
            foundation_keyring_path,
            foundation,
        )
    )
    prior_materials.update(
        foundation_v6.known_domain_public_key_hashes(
            foundation.provenance,
            foundation.evidence,
        )
    )
    if prior_materials & set(materials):
        raise executable.QueryV6ExecutableError(
            "foundation and executable key domains overlap"
        )
    return payload, public_key


def sign_release(
    draft: dict[str, Any],
    keyring: dict[str, Any],
    foundation_keyring_path: Path,
    foundation: foundation_v6.VerifiedAuthorityFoundation,
    pins: executable.ExecutablePins,
    private_key: Ed25519PrivateKey,
    *,
    now: datetime,
) -> dict[str, Any]:
    payload, public_key = prepare_release(
        draft,
        keyring,
        foundation_keyring_path,
        foundation,
        pins,
        now=now,
    )
    _private_key_matches(private_key, public_key)
    payload["signature"] = base64.b64encode(
        private_key.sign(
            executable.canonical_json(executable.unsigned_payload(payload))
        )
    ).decode("ascii")
    executable.validate_release_semantics(payload, foundation, pins, now=now)
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--executable-keyring", type=Path, required=True)
    parser.add_argument(
        "--active-executable-pin-manifest",
        type=Path,
        default=executable.ACTIVE_PIN_MANIFEST_PATH,
    )
    foundation_v6._common_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc)
    try:
        foundation = foundation_v6.verify_offline_foundation(
            foundation_v6._paths(args),
            now=now,
        )
        pins = executable.read_active_pins(
            args.active_executable_pin_manifest
        )
        keyring = load_json_strict(
            args.executable_keyring,
            "query-v6 executable keyring",
            private=True,
        )
        signed = sign_release(
            load_json_strict(args.input, "unsigned query-v6 executable release"),
            keyring,
            args.release_keyring,
            foundation,
            pins,
            load_private_key(args.private_key_file),
            now=now,
        )
        write_private_json_create_only(args.output, signed)
    except (
        OSError,
        foundation_v6.QueryV6AuthorityError,
        executable.QueryV6ExecutableError,
        ValueError,
    ) as exc:
        print(f"query-v6 executable signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed query-v6 executable release: {args.output}")
    print(f"attempt_id={signed['attempt_id']}")
    print("foundation_is_authority=false")
    print("production_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
