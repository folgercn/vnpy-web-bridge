#!/usr/bin/env python3
"""Sign a human-reviewed C_FAST T1 one-shot readonly-audit release."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commodity_c_fast_t1_one_shot import (
    RELEASE_SCHEMA_PATH,
    OneShotError,
    canonical_json,
    load_json_strict,
    read_regular_file_strict,
    release_attempt_id,
    unsigned_release_payload,
    validate_json_schema,
    validate_release_semantics,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OneShotError("private key file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OneShotError(
            "private key must be a regular non-symlink file"
        )
    if info.st_uid != os.geteuid():
        raise OneShotError(
            "private key must be owned by the current user"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise OneShotError(
            "private key permissions must be 0600 or stricter"
        )
    raw = read_regular_file_strict(
        path,
        "private key",
        private=True,
    ).strip()
    if raw.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as exc:
            raise OneShotError(
                "private key PEM is invalid or encrypted"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise OneShotError("private key is not Ed25519")
        return key
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise OneShotError(
            "private key must be Ed25519 PEM or base64 raw bytes"
        ) from exc
    if len(decoded) != 32:
        raise OneShotError(
            "raw Ed25519 private key must contain exactly 32 bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(decoded)


def sign_release(
    draft: dict,
    private_key: Ed25519PrivateKey,
    *,
    now: datetime | None = None,
) -> dict:
    if "signature" in draft:
        raise OneShotError("unsigned release input must omit signature")
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    computed_attempt_id = release_attempt_id(release_id)
    supplied_attempt_id = payload.get("attempt_id")
    if supplied_attempt_id not in {None, computed_attempt_id}:
        raise OneShotError(
            "attempt_id does not match the SHA256 of release_id"
        )
    payload["attempt_id"] = computed_attempt_id
    payload["signature"] = PLACEHOLDER_SIGNATURE
    validate_json_schema(payload, RELEASE_SCHEMA_PATH, "release draft")
    validate_release_semantics(
        payload,
        now=now or datetime.now(timezone.utc),
    )
    payload["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(unsigned_release_payload(payload))
        )
    ).decode("ascii")
    validate_json_schema(payload, RELEASE_SCHEMA_PATH, "signed release")
    return payload


def write_private_json_create_only(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    directory = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="unsigned release JSON; attempt_id may be omitted",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        draft = load_json_strict(args.input, "unsigned release draft")
        signed = sign_release(draft, load_private_key(args.private_key_file))
        write_private_json_create_only(args.output, signed)
    except (OneShotError, OSError, ValueError) as exc:
        print(f"T1 release signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed T1 release written: {args.output}")
    print(f"attempt_id: {signed['attempt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
