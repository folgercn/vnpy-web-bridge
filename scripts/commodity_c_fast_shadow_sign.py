#!/usr/bin/env python3
"""Bind and sign one read-only C_FAST monthly Shadow snapshot."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO  # noqa: E402
from app.services.commodity_c_fast_shadow_common import (  # noqa: E402
    canonical_json,
    formula_target_binding_sha256,
    unsigned_snapshot_payload,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError(
            f"private key file permissions must be 0600 or stricter: {oct(mode)}"
        )
    raw = path.read_bytes().strip()
    if raw.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as exc:
            raise ValueError("private key PEM is invalid or encrypted") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("private key is not Ed25519")
        return key
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise ValueError(
            "private key must be unencrypted Ed25519 PEM or base64 raw bytes"
        ) from exc
    if len(decoded) != 32:
        raise ValueError("raw Ed25519 private key must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(decoded)


def sign_snapshot(
    payload: dict, private_key: Ed25519PrivateKey
) -> tuple[dict, str]:
    draft = dict(payload)
    draft["formula_target_binding_sha256"] = "0" * 64
    draft["signature"] = PLACEHOLDER_SIGNATURE
    snapshot = CommodityCFastShadowDTO.model_validate(draft)
    draft["formula_target_binding_sha256"] = formula_target_binding_sha256(
        snapshot
    )
    snapshot = CommodityCFastShadowDTO.model_validate(draft)
    canonical = canonical_json(unsigned_snapshot_payload(snapshot))
    signed = snapshot.model_dump(mode="json")
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical)
    ).decode("ascii")
    CommodityCFastShadowDTO.model_validate(signed)
    return signed, hashlib.sha256(canonical).hexdigest()


def write_private_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", required=True, type=Path, help="unsigned snapshot JSON"
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="signed snapshot JSON"
    )
    parser.add_argument(
        "--private-key-file",
        required=True,
        type=Path,
        help="0600 Ed25519 PEM/base64 key file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("input must contain one JSON object")
        signed, snapshot_hash = sign_snapshot(
            payload, load_private_key(args.private_key_file)
        )
        write_private_json(args.output, signed)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed C_FAST shadow snapshot written: {args.output}")
    print(f"snapshot_hash: {snapshot_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
