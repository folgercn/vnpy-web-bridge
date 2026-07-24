#!/usr/bin/env python3
"""Sign one offline-only C_FAST execution-policy freeze artifact."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.commodity_c_fast_execution_policy import (  # noqa: E402
    CFastExecutionPolicyFreezeDTO,
    CFastExecutionPolicyFreezeV2DTO,
)
from app.services.commodity_c_fast_execution_policy import (  # noqa: E402
    MAX_POLICY_FREEZE_JSON_BYTES,
    execution_policy_freeze_sha256,
    execution_policy_freeze_v2_sha256,
    parse_unsigned_execution_policy_freeze_artifact_json,
    unsigned_execution_policy_freeze_payload,
    unsigned_execution_policy_freeze_v2_payload,
)
from app.services.commodity_c_fast_shadow_common import canonical_json  # noqa: E402


MAX_PRIVATE_KEY_BYTES = 64 * 1024


def _read_fd_bounded(fd: int, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining > 0:
        chunk = os.read(fd, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
) -> tuple[bytes, int, int]:
    try:
        path_before = path.lstat()
    except OSError as exc:
        raise ValueError(f"path must be a regular non-symlink file: {path}") from exc
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise ValueError(f"path must be a regular non-symlink file: {path}")
    if path_before.st_size > maximum_bytes:
        raise ValueError(f"path must be a bounded regular file: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"path must be a regular non-symlink file: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise ValueError(f"path must be a bounded regular file: {path}")
        first = _read_fd_bounded(fd, maximum_bytes)
        os.lseek(fd, 0, os.SEEK_SET)
        second = _read_fd_bounded(fd, maximum_bytes)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        path_after = path.lstat()
    except OSError as exc:
        raise ValueError(f"file changed while it was read: {path}") from exc
    if (
        len(
            {
                _file_identity(path_before),
                _file_identity(before),
                _file_identity(after),
                _file_identity(path_after),
            }
        )
        != 1
        or first != second
        or len(first) != before.st_size
    ):
        raise ValueError(f"file changed while it was read: {path}")
    if len(first) > maximum_bytes:
        raise ValueError(f"file exceeds size limit: {path}")
    return first, stat.S_IMODE(before.st_mode), before.st_uid


def load_private_key(path: Path) -> Ed25519PrivateKey:
    raw, mode, owner_uid = _read_regular_file(
        path,
        maximum_bytes=MAX_PRIVATE_KEY_BYTES,
    )
    if owner_uid != os.geteuid():
        raise ValueError("private key file must be owned by the current user")
    if mode & 0o077:
        raise ValueError(
            f"private key file permissions must be 0600 or stricter: {oct(mode)}"
        )
    raw = raw.strip()
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


def sign_policy_freeze(
    raw_unsigned_payload: str | bytes,
    private_key: Ed25519PrivateKey,
) -> tuple[dict[str, Any], str]:
    draft = parse_unsigned_execution_policy_freeze_artifact_json(raw_unsigned_payload)
    if isinstance(draft, CFastExecutionPolicyFreezeV2DTO):
        unsigned_payload = unsigned_execution_policy_freeze_v2_payload(draft)
    else:
        unsigned_payload = unsigned_execution_policy_freeze_payload(draft)
    signature = private_key.sign(canonical_json(unsigned_payload))
    signed = draft.model_dump(mode="json")
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    if isinstance(draft, CFastExecutionPolicyFreezeV2DTO):
        freeze_v2 = CFastExecutionPolicyFreezeV2DTO.model_validate(signed)
        return (
            freeze_v2.model_dump(mode="json"),
            execution_policy_freeze_v2_sha256(freeze_v2),
        )
    freeze_v1 = CFastExecutionPolicyFreezeDTO.model_validate(signed)
    return (
        freeze_v1.model_dump(mode="json"),
        execution_policy_freeze_sha256(freeze_v1),
    )


def write_private_json_create_only(
    path: Path,
    payload: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    created = False
    try:
        fd = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if fd is not None:
            os.close(fd)
        if created:
            path.unlink(missing_ok=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="unsigned policy-freeze JSON",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new create-only signed policy-freeze JSON",
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
        raw, _mode, _owner_uid = _read_regular_file(
            args.input,
            maximum_bytes=MAX_POLICY_FREEZE_JSON_BYTES,
        )
        signed, freeze_sha256 = sign_policy_freeze(
            raw,
            load_private_key(args.private_key_file),
        )
        write_private_json_create_only(args.output, signed)
    except (OSError, ValueError) as exc:
        print(f"signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed C_FAST execution-policy freeze written: {args.output}")
    print(f"freeze_sha256: {freeze_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
