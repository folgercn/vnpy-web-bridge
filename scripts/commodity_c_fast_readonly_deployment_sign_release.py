#!/usr/bin/env python3
"""Sign a human-reviewed C_FAST readonly-principal deployment release."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from commodity_c_fast_readonly_deployment_release import (
    MAX_JSON_BYTES,
    RELEASE_SCHEMA_PATH,
    DeploymentEvidencePaths,
    DeploymentReleaseError,
    _load_json,
    _load_trusted_public_key,
    _validate_schema,
    add_evidence_arguments,
    canonical_json,
    evidence_paths_from_args,
    release_attempt_id,
    unsigned_release_payload,
    validate_release_semantics,
    validate_runtime_file_bindings,
    verify_evidence_bundle,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    read_regular_file_strict,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DeploymentReleaseError(
            "private key file is unavailable"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise DeploymentReleaseError(
            "private key must be a regular non-symlink file"
        )
    if info.st_uid != os.geteuid():
        raise DeploymentReleaseError(
            "private key must be owned by the current user"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise DeploymentReleaseError(
            "private key permissions must be 0600 or stricter"
        )
    try:
        raw = read_regular_file_strict(
            path,
            "readonly deployment signing key",
            private=True,
            limit=MAX_JSON_BYTES,
        ).strip()
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc
    if raw.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(
                raw,
                password=None,
            )
        except (TypeError, ValueError) as exc:
            raise DeploymentReleaseError(
                "private key PEM is invalid or encrypted"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise DeploymentReleaseError(
                "private key is not Ed25519"
            )
        return key
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise DeploymentReleaseError(
            "private key must be Ed25519 PEM or base64 raw bytes"
        ) from exc
    if len(decoded) != 32:
        raise DeploymentReleaseError(
            "raw Ed25519 private key must contain exactly 32 bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(decoded)


def sign_release(
    draft: dict,
    private_key: Ed25519PrivateKey,
    evidence_paths: DeploymentEvidencePaths,
    keyring_path: Path,
    *,
    expected_keyring_sha256: str,
    source_commit_sha: str,
    questdb_image_digest: str,
    now: datetime | None = None,
) -> dict:
    if "signature" in draft:
        raise DeploymentReleaseError(
            "unsigned release input must omit signature"
        )
    payload = dict(draft)
    release_id = str(payload.get("release_id") or "")
    computed_attempt_id = release_attempt_id(release_id)
    supplied_attempt_id = payload.get("attempt_id")
    if supplied_attempt_id not in {None, computed_attempt_id}:
        raise DeploymentReleaseError(
            "attempt_id does not match the SHA256 of release_id"
        )
    payload["attempt_id"] = computed_attempt_id
    payload["signature"] = PLACEHOLDER_SIGNATURE
    _validate_schema(
        payload,
        RELEASE_SCHEMA_PATH,
        "readonly deployment release draft",
    )
    validate_release_semantics(
        payload,
        now=now or datetime.now(timezone.utc),
    )
    validate_runtime_file_bindings(payload)
    verify_evidence_bundle(payload, evidence_paths)

    _keyring_raw, keyring = _load_json(
        keyring_path,
        "readonly deployment trusted keyring",
        private=True,
    )
    actual_keyring_sha256 = hashlib.sha256(
        canonical_json(keyring)
    ).hexdigest()
    if actual_keyring_sha256 != expected_keyring_sha256:
        raise DeploymentReleaseError(
            "trusted keyring does not match independent signing pin"
        )
    if payload["trusted_keyring_sha256"] != actual_keyring_sha256:
        raise DeploymentReleaseError(
            "trusted keyring does not match release"
        )
    trusted_public = _load_trusted_public_key(
        keyring,
        str(payload["signer_key_id"]),
    )
    expected_public = trusted_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise DeploymentReleaseError(
            "private key does not match trusted release signer"
        )
    if payload["source_commit_sha"] != source_commit_sha:
        raise DeploymentReleaseError(
            "source commit assertion does not match release"
        )
    if payload["questdb_image_digest"] != questdb_image_digest:
        raise DeploymentReleaseError(
            "QuestDB image assertion does not match release"
        )

    payload["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(unsigned_release_payload(payload))
        )
    ).decode("ascii")
    _validate_schema(
        payload,
        RELEASE_SCHEMA_PATH,
        "signed readonly deployment release",
    )
    return payload


def write_private_json_create_only(
    path: Path,
    payload: dict,
) -> None:
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
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-trusted-keyring-sha256",
        required=True,
    )
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--questdb-image-digest", required=True)
    add_evidence_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        _draft_raw, draft = _load_json(
            args.input,
            "unsigned readonly deployment release",
        )
        signed = sign_release(
            draft,
            load_private_key(args.private_key_file),
            evidence_paths_from_args(args),
            args.trusted_keyring,
            expected_keyring_sha256=(
                args.expected_trusted_keyring_sha256
            ),
            source_commit_sha=args.source_commit_sha,
            questdb_image_digest=args.questdb_image_digest,
        )
        write_private_json_create_only(args.output, signed)
    except (DeploymentReleaseError, OSError, ValueError) as exc:
        print(
            f"readonly deployment release signing failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"signed readonly deployment release written: {args.output}")
    print(f"attempt_id={signed['attempt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
