#!/usr/bin/env python3
"""Offline-sign one human-reviewed C_FAST T1 query-v3 release."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys

from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    load_json_strict,
    parse_json_bytes,
    read_regular_file_strict,
    release_attempt_id,
    validate_json_schema,
)
from commodity_c_fast_t1_query_v3 import (
    RELEASE_SCHEMA_PATH,
    QueryV3Error,
    unsigned_release_payload,
    validate_release_semantics,
)
from commodity_c_fast_t1_readiness_v2 import (
    SCHEMA_PATH as READINESS_SCHEMA_PATH,
    VerifiedReadinessPacket,
)
from commodity_c_fast_t1_sign_release import (
    load_private_key,
    write_private_json_create_only,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def sign_release(
    draft: dict,
    readiness: VerifiedReadinessPacket,
    private_key: object,
    *,
    now: datetime,
) -> dict:
    if "signature" in draft:
        raise QueryV3Error("unsigned query release must omit signature")
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    expected_attempt = release_attempt_id(release_id)
    supplied_attempt = payload.get("attempt_id")
    if supplied_attempt not in {None, expected_attempt}:
        raise QueryV3Error("attempt_id does not match release_id")
    payload["attempt_id"] = expected_attempt
    payload["signature"] = PLACEHOLDER_SIGNATURE
    validate_release_semantics(payload, readiness, now=now)
    payload["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_release_payload(payload)))
    ).decode("ascii")
    validate_json_schema(payload, RELEASE_SCHEMA_PATH, "signed query release")
    return payload


def load_readiness(path: Path) -> VerifiedReadinessPacket:
    raw = read_regular_file_strict(path, "T1 readiness v2 packet")
    payload = parse_json_bytes(raw, "T1 readiness v2 packet")
    validate_json_schema(payload, READINESS_SCHEMA_PATH, "T1 readiness v2 packet")
    return VerifiedReadinessPacket(
        payload=payload,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_sha256=hashlib.sha256(canonical_json(payload)).hexdigest(),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--readiness-packet", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        signed = sign_release(
            load_json_strict(args.input, "unsigned query release"),
            load_readiness(args.readiness_packet),
            load_private_key(args.private_key_file),
            now=datetime.now(timezone.utc),
        )
        write_private_json_create_only(args.output, signed)
    except (OSError, OneShotError, QueryV3Error, ValueError) as exc:
        print(f"T1 query-v3 signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed query release written: {args.output}")
    print(f"attempt_id={signed['attempt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
