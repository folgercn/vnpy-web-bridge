#!/usr/bin/env python3
"""Isolated Phase-B signer: the private key is accepted only as an unlinked RO FD."""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import stat
import sys
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.trust_contracts import (
    ContractError,
    build_signed_artifact,
    canonical_json_line,
    load_keyring,
    signing_bytes,
    validate_keyring,
    validate_signing_request,
)


class OfflineSignerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _read_canonical(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size <= 0
                or info.st_size > 20 * 1024 * 1024
            ):
                raise OfflineSignerError("SIGNER_INPUT_INVALID")
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise OfflineSignerError("SIGNER_INPUT_CHANGED")
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            if len(raw) != info.st_size or (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise OfflineSignerError("SIGNER_INPUT_CHANGED")
        finally:
            os.close(fd)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or canonical_json_line(value) != raw:
            raise OfflineSignerError("SIGNER_INPUT_NOT_CANONICAL")
        return value
    except OfflineSignerError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflineSignerError("SIGNER_INPUT_READ_FAILED") from exc


def _read_private_fd(key_fd: int) -> bytearray:
    try:
        access = fcntl.fcntl(key_fd, fcntl.F_GETFL) & os.O_ACCMODE
        info = os.fstat(key_fd)
    except OSError as exc:
        raise OfflineSignerError("SIGNER_KEY_FD_INVALID") from exc
    if access != os.O_RDONLY:
        raise OfflineSignerError("SIGNER_KEY_FD_NOT_READ_ONLY")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0 or info.st_size != 32:
        raise OfflineSignerError("SIGNER_KEY_FD_NOT_EPHEMERAL")
    if info.st_mode & 0o077:
        raise OfflineSignerError("SIGNER_KEY_FD_PERMISSIONS_INVALID")
    try:
        raw = bytearray(os.pread(key_fd, 33, 0))
        after = os.fstat(key_fd)
    except OSError as exc:
        raise OfflineSignerError("SIGNER_KEY_FD_READ_FAILED") from exc
    if len(raw) != 32 or (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        for index in range(len(raw)):
            raw[index] = 0
        raise OfflineSignerError("SIGNER_KEY_FD_CHANGED")
    fcntl.fcntl(
        key_fd, fcntl.F_SETFD, fcntl.fcntl(key_fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC
    )
    return raw


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError
    return parsed.astimezone(timezone.utc)


def sign_request(
    request: Mapping[str, Any],
    *,
    keyring: Mapping[str, Any],
    key_fd: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        validated = validate_signing_request(request)
        keyring = validate_keyring(keyring, expected_domain=validated["domain"])
    except ContractError as exc:
        raise OfflineSignerError(exc.code) from exc
    if (
        keyring.get("domain") != validated["domain"]
        or keyring.get("key_version") != validated["key_version"]
    ):
        raise OfflineSignerError("SIGNER_KEYRING_BINDING_MISMATCH")
    matches = [
        entry
        for entry in keyring.get("keys", [])
        if entry.get("key_id") == validated["key_id"]
        and entry.get("status") == "active"
    ]
    if len(matches) != 1 or matches[0].get("domain") != validated["domain"]:
        raise OfflineSignerError("SIGNER_ACTIVE_KEY_NOT_FOUND")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        if current < _parse_time(validated["requested_at"]) or current > _parse_time(
            validated["expires_at"]
        ):
            raise OfflineSignerError("SIGNER_REQUEST_OUTSIDE_VALIDITY")
    except ValueError as exc:
        raise OfflineSignerError("SIGNER_REQUEST_TIME_INVALID") from exc
    private_raw = _read_private_fd(key_fd)
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_raw))
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if (
            base64.b64encode(public_raw).decode("ascii")
            != matches[0]["public_key_base64"]
        ):
            raise OfflineSignerError("SIGNER_PRIVATE_KEY_MISMATCH")
        placeholder = build_signed_artifact(
            validated, signature_base64=base64.b64encode(b"\0" * 64).decode("ascii")
        )
        signature = private_key.sign(signing_bytes(placeholder))
        return build_signed_artifact(
            validated, signature_base64=base64.b64encode(signature).decode("ascii")
        )
    finally:
        for index in range(len(private_raw)):
            private_raw[index] = 0


def _write_create_only(path: Path, raw: bytes) -> None:
    parent = path.parent.resolve(strict=True)
    if path.parent.resolve() != parent:
        raise OfflineSignerError("SIGNER_OUTPUT_PARENT_INVALID")
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        dir_flags |= os.O_NOFOLLOW
    parent_fd = os.open(parent, dir_flags)
    temp = f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        fd = os.open(
            temp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                view = view[count:]
            os.fsync(fd)
            try:
                os.link(
                    temp,
                    path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise OfflineSignerError("SIGNER_OUTPUT_ALREADY_EXISTS") from exc
            os.fsync(parent_fd)
        finally:
            os.close(fd)
            os.unlink(temp, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--ready", action="store_true")
    parser.add_argument("--request", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--keyring-sha256")
    parser.add_argument("--key-fd", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.version or args.health or args.ready:
        print(json.dumps({
            "service": "signing-authority",
            "version": "phase-b-signing-authority-v1",
            "status": "ready" if args.ready else "ok",
            "private_key_access": False,
            "trade_rpc_access": False,
            "network_endpoint": None,
        }, sort_keys=True))
        return 0
    if any(value is None for value in (args.request, args.keyring, args.keyring_sha256, args.key_fd, args.output)):
        parser.error("request, keyring, keyring-sha256, key-fd and output are required for sign")
    try:
        request = _read_canonical(args.request)
        domain = request.get("domain")
        if not isinstance(domain, str):
            raise OfflineSignerError("SIGNER_REQUEST_DOMAIN_INVALID")
        keyring, _, _ = load_keyring(
            args.keyring,
            expected_domain=domain,
            expected_raw_sha256=args.keyring_sha256,
        )
        signed = sign_request(request, keyring=keyring, key_fd=args.key_fd)
        _write_create_only(args.output, canonical_json_line(signed))
    except (ContractError, OfflineSignerError) as exc:
        print(
            f"offline signer rejected request: {getattr(exc, 'code', str(exc))}",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "output": str(args.output),
                "request_id": signed["request_id"],
                "domain": signed["domain"],
                "production": False,
                "live": False,
                "countable_forward": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
