#!/usr/bin/env python3
"""Consume one signed C_FAST T1 readonly-audit release exactly once."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = Path(__file__).resolve()
AUDIT_SCRIPT_PATH = ROOT / "scripts/commodity_c_fast_l1_l5_audit.py"
MANIFEST_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
)
LEGACY_EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json"
)
READONLY_PROOF_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
)
RELEASE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-one-shot-release-v1.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-consume-v1.schema.json"
)
TERMINAL_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-terminal-seal-v1.schema.json"
)
LEGACY_EVIDENCE_RESOURCE_URI = (
    "urn:vnpy-web-bridge:schema:commodity-c-fast-l1-l5-audit-v1"
)

CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
RELEASE_SCHEMA_VERSION = "commodity_c_fast_t1_one_shot_release_v1"
CONSUME_SCHEMA_VERSION = "commodity_c_fast_t1_consume_v1"
TERMINAL_SCHEMA_VERSION = "commodity_c_fast_t1_terminal_seal_v1"
RELEASE_PURPOSE = "c_fast_l1_l5_t1_readonly_audit"
TRUSTED_KEY_PURPOSE = "t1_audit_release_signer"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RELEASE_TTL = timedelta(hours=24)
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
DEPLOYMENT_KEYRING_PIN_PATH = Path(
    "/run/c-fast-t1-pins/trusted-keyring.sha256"
)
DEPLOYMENT_CUSTODY_PIN_PATH = Path(
    "/run/c-fast-t1-pins/custody.path"
)


class OneShotError(RuntimeError):
    """Expected fail-closed release or custody error."""


@dataclass(frozen=True)
class VerifiedRelease:
    payload: dict[str, Any]
    release_sha256: str
    keyring_sha256: str
    manifest: dict[str, Any]
    bundle_files: dict[str, bytes]


@dataclass(frozen=True)
class ArtifactPaths:
    audit_json: Path
    audit_csv: Path
    audit_markdown: Path
    readonly_proof: Path

    def as_dict(self) -> dict[str, Path]:
        return {
            "audit_json": self.audit_json,
            "audit_csv": self.audit_csv,
            "audit_markdown": self.audit_markdown,
            "readonly_proof": self.readonly_proof,
        }


@dataclass
class CustodyGuard:
    path: Path
    descriptor: int
    identity: tuple[int, int, int, int, int]

    def assert_path_identity(self) -> None:
        try:
            current = self.path.lstat()
            opened = os.fstat(self.descriptor)
        except OSError as exc:
            raise OneShotError("custody directory identity is unavailable") from exc
        current_identity = (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            stat.S_IFMT(current.st_mode),
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            stat.S_IFMT(opened.st_mode),
        )
        if (
            current_identity != self.identity
            or opened_identity != self.identity
        ):
            raise OneShotError(
                "deployment-pinned custody directory identity changed"
            )

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def canonical_json(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OneShotError(f"payload is not canonical JSON: {exc}") from exc


def unsigned_release_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def release_attempt_id(release_id: str) -> str:
    return "attempt-" + hashlib.sha256(release_id.encode("utf-8")).hexdigest()


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _read_fd_bounded(descriptor: int, label: str, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > limit:
        raise OneShotError(f"{label} exceeds {limit} byte safety limit")
    return raw


def read_regular_file_strict(
    path: Path,
    label: str,
    *,
    limit: int = MAX_JSON_BYTES,
    private: bool = False,
) -> bytes:
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise OneShotError(f"{label} must not be a symlink")
        if not stat.S_ISREG(path_stat.st_mode):
            raise OneShotError(f"{label} must be a regular file")
        if private:
            if path_stat.st_uid != os.geteuid():
                raise OneShotError(
                    f"{label} must be owned by the current user"
                )
            if stat.S_IMODE(path_stat.st_mode) & 0o077:
                raise OneShotError(
                    f"{label} permissions must be 0600 or stricter"
                )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            first = _read_fd_bounded(descriptor, label, limit)
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_fd_bounded(descriptor, label, limit)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OneShotError:
        raise
    except OSError as exc:
        raise OneShotError(f"cannot read {label}: {exc}") from exc

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            stat.S_IFMT(value.st_mode),
            value.st_uid,
            stat.S_IMODE(value.st_mode),
        )

    identities = {
        identity(path_stat),
        identity(before),
        identity(after),
        identity(path_after),
    }
    if (
        len(identities) != 1
        or first != second
        or len(first) != before.st_size
    ):
        raise OneShotError(f"{label} changed while it was being read")
    return first


def load_json_strict(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> dict[str, Any]:
    raw = read_regular_file_strict(path, label, private=private)
    return parse_json_bytes(raw, label)


def parse_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise OneShotError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise OneShotError(f"{label} must contain one JSON object")
    return payload


def _deny_external_schema_retrieval(uri: str) -> Resource[Any]:
    raise NoSuchResource(ref=uri)


def validate_json_schema(
    payload: Any,
    schema_path: Path,
    label: str,
) -> None:
    schema_raw = read_regular_file_strict(
        schema_path,
        f"{label} schema",
    )
    legacy_raw = (
        read_regular_file_strict(
            LEGACY_EVIDENCE_SCHEMA_PATH,
            "legacy audit evidence schema",
        )
        if schema_path == EVIDENCE_SCHEMA_PATH
        else None
    )
    validate_json_schema_bytes(
        payload,
        schema_raw,
        label,
        legacy_schema_raw=legacy_raw,
    )


def validate_json_schema_bytes(
    payload: Any,
    schema_raw: bytes,
    label: str,
    *,
    legacy_schema_raw: bytes | None = None,
) -> None:
    schema = parse_json_bytes(schema_raw, f"{label} schema")
    try:
        Draft202012Validator.check_schema(schema)
        registry = Registry(retrieve=_deny_external_schema_retrieval)
        if legacy_schema_raw is not None:
            legacy = parse_json_bytes(
                legacy_schema_raw,
                "legacy audit evidence schema",
            )
            registry = registry.with_resource(
                LEGACY_EVIDENCE_RESOURCE_URI,
                Resource.from_contents(legacy),
            )
        validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
            registry=registry,
        )
        errors = sorted(
            validator.iter_errors(payload),
            key=lambda error: [
                str(part) for part in error.absolute_path
            ],
        )
    except (SchemaError, TypeError, Unresolvable, ValueError) as exc:
        raise OneShotError(
            f"{label} schema validation failed: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(
            str(part) for part in error.absolute_path
        ) or "$"
        raise OneShotError(
            f"{label} schema validation failed at "
            f"{location}: {error.message}"
        )


def parse_datetime(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise OneShotError(f"{label} must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OneShotError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def assert_audit_windows_equal(
    actual: dict[str, Any],
    expected: dict[str, Any],
    label: str,
) -> None:
    for field in ("start", "end_exclusive"):
        if parse_datetime(actual[field], f"{label}.{field}") != parse_datetime(
            expected[field],
            f"release.audit_window.{field}",
        ):
            raise OneShotError(f"{label} {field} does not match release")
    if actual["trading_day"] != expected["trading_day"]:
        raise OneShotError(f"{label} trading_day does not match release")


def sha256_regular_file(
    path: Path,
    label: str,
    *,
    limit: int = MAX_ARTIFACT_BYTES,
) -> str:
    return hashlib.sha256(
        read_regular_file_strict(path, label, limit=limit)
    ).hexdigest()


def validate_release_semantics(
    payload: dict[str, Any],
    *,
    now: datetime,
) -> None:
    if payload["schema_version"] != RELEASE_SCHEMA_VERSION:
        raise OneShotError("release schema version is invalid")
    if payload["purpose"] != RELEASE_PURPOSE:
        raise OneShotError("release purpose is invalid")
    release_id = str(payload["release_id"])
    if not ID_PATTERN.fullmatch(release_id):
        raise OneShotError("release_id is invalid")
    expected_attempt_id = release_attempt_id(release_id)
    if not hmac.compare_digest(payload["attempt_id"], expected_attempt_id):
        raise OneShotError(
            "attempt_id does not match the SHA256 of release_id"
        )
    human_signature = str(payload["human_signature"]).strip()
    if not human_signature or human_signature.startswith("PENDING_"):
        raise OneShotError("human_signature must contain final human text")
    if not str(payload["reviewer_role"]).strip():
        raise OneShotError("reviewer_role must not be empty")

    issued_at = parse_datetime(payload["issued_at"], "issued_at")
    not_before = parse_datetime(payload["not_before"], "not_before")
    expires_at = parse_datetime(payload["expires_at"], "expires_at")
    if not issued_at <= not_before < expires_at:
        raise OneShotError(
            "release times must satisfy issued_at <= not_before < expires_at"
        )
    if expires_at - issued_at > MAX_RELEASE_TTL:
        raise OneShotError("release TTL cannot exceed 24 hours")
    normalized_now = now.astimezone(timezone.utc)
    if normalized_now < not_before:
        raise OneShotError("release is not active yet")
    if normalized_now >= expires_at:
        raise OneShotError("release has expired")

    if not SHA256_PATTERN.fullmatch(payload["trusted_keyring_sha256"]):
        raise OneShotError("trusted keyring SHA256 is invalid")
    if not IMAGE_DIGEST_PATTERN.fullmatch(payload["runtime_image_digest"]):
        raise OneShotError("runtime image digest is invalid")
    if payload["max_runtime_seconds"] > 1800:
        raise OneShotError("max runtime cannot exceed 1800 seconds")

    required_true = (
        "network_authorized",
        "readonly_production_query_authorized",
    )
    required_false = (
        "write_probe_authorized",
        "database_mutation_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "deployment_mutation_authorized",
    )
    if any(payload[name] is not True for name in required_true):
        raise OneShotError("release is missing explicit readonly authority")
    if any(payload[name] is not False for name in required_false):
        raise OneShotError("release attempts to grant forbidden authority")


def _load_trusted_public_key(
    keyring: dict[str, Any],
    key_id: str,
) -> Ed25519PublicKey:
    if set(keyring) != {"schema_version", "keys"}:
        raise OneShotError("trusted keyring fields are invalid")
    if keyring["schema_version"] != "commodity_c_fast_t1_trusted_keys_v1":
        raise OneShotError("trusted keyring schema version is invalid")
    keys = keyring["keys"]
    if not isinstance(keys, list) or not keys:
        raise OneShotError("trusted keyring must contain at least one key")
    matched: dict[str, Any] | None = None
    seen: set[str] = set()
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise OneShotError("trusted keyring entry fields are invalid")
        current_id = str(entry["key_id"])
        if current_id in seen:
            raise OneShotError("trusted keyring contains duplicate key_id")
        seen.add(current_id)
        if current_id == key_id:
            matched = entry
    if matched is None:
        raise OneShotError("release signer key is not trusted")
    if matched["purpose"] != TRUSTED_KEY_PURPOSE:
        raise OneShotError("release signer key purpose is not authorized")
    try:
        raw = base64.b64decode(
            str(matched["public_key_base64"]),
            validate=True,
        )
        if len(raw) != 32:
            raise ValueError("wrong Ed25519 public key length")
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise OneShotError("trusted Ed25519 public key is invalid") from exc


def verify_release(
    release_path: Path,
    keyring_path: Path,
    manifest_path: Path,
    *,
    source_commit_sha: str,
    runtime_image_digest: str,
    pinned_keyring_sha256: str,
    now: datetime | None = None,
) -> VerifiedRelease:
    current_time = now or datetime.now(timezone.utc)
    release = load_json_strict(release_path, "signed T1 release")
    keyring = load_json_strict(
        keyring_path,
        "T1 trusted keyring",
        private=True,
    )
    manifest = load_json_strict(manifest_path, "signed audit manifest")
    validate_json_schema(release, RELEASE_SCHEMA_PATH, "signed T1 release")
    validate_release_semantics(release, now=current_time)
    validate_json_schema(
        manifest,
        MANIFEST_SCHEMA_PATH,
        "audit manifest",
    )

    keyring_sha256 = hashlib.sha256(canonical_json(keyring)).hexdigest()
    if not SHA256_PATTERN.fullmatch(pinned_keyring_sha256):
        raise OneShotError("deployment-pinned keyring SHA256 is invalid")
    if not hmac.compare_digest(
        keyring_sha256,
        pinned_keyring_sha256,
    ):
        raise OneShotError(
            "trusted keyring does not match the independent deployment pin"
        )
    if not hmac.compare_digest(
        keyring_sha256,
        release["trusted_keyring_sha256"],
    ):
        raise OneShotError("trusted keyring SHA256 does not match release")
    public_key = _load_trusted_public_key(
        keyring,
        str(release["signer_key_id"]),
    )
    try:
        signature = base64.b64decode(release["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("wrong Ed25519 signature length")
        public_key.verify(
            signature,
            canonical_json(unsigned_release_payload(release)),
        )
    except (InvalidSignature, ValueError) as exc:
        raise OneShotError("T1 release Ed25519 signature is invalid") from exc

    manifest_sha256 = hashlib.sha256(canonical_json(manifest)).hexdigest()
    if not hmac.compare_digest(
        manifest_sha256,
        release["manifest_sha256"],
    ):
        raise OneShotError("audit manifest SHA256 does not match release")
    if manifest["snapshot_id"] != release["snapshot_id"]:
        raise OneShotError("audit manifest snapshot_id does not match release")
    manifest_window = manifest["audit_window"]
    release_window = release["audit_window"]
    assert_audit_windows_equal(
        manifest_window,
        release_window,
        "audit manifest",
    )

    expected_files = {
        "runner_sha256": ("runner", RUNNER_PATH),
        "audit_script_sha256": (
            "scripts/commodity_c_fast_l1_l5_audit.py",
            AUDIT_SCRIPT_PATH,
        ),
        "manifest_schema_sha256": (
            "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
            MANIFEST_SCHEMA_PATH,
        ),
        "evidence_schema_sha256": (
            "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
            EVIDENCE_SCHEMA_PATH,
        ),
        "legacy_evidence_schema_sha256": (
            "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
            LEGACY_EVIDENCE_SCHEMA_PATH,
        ),
        "readonly_proof_schema_sha256": (
            "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
            READONLY_PROOF_SCHEMA_PATH,
        ),
    }
    bundle_files: dict[str, bytes] = {}
    for field, (relative_name, path) in expected_files.items():
        raw = read_regular_file_strict(
            path,
            field,
            limit=MAX_ARTIFACT_BYTES,
        )
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual, release[field]):
            raise OneShotError(f"{field} does not match runtime file")
        if relative_name != "runner":
            bundle_files[relative_name] = raw
    if not hmac.compare_digest(
        release["source_commit_sha"],
        source_commit_sha,
    ):
        raise OneShotError("source commit does not match release")
    if not hmac.compare_digest(
        release["runtime_image_digest"],
        runtime_image_digest,
    ):
        raise OneShotError("runtime image digest does not match release")

    release_sha256 = hashlib.sha256(canonical_json(release)).hexdigest()
    return VerifiedRelease(
        payload=release,
        release_sha256=release_sha256,
        keyring_sha256=keyring_sha256,
        manifest=manifest,
        bundle_files=bundle_files,
    )


def validate_private_dsn_metadata(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OneShotError("readonly DSN file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OneShotError("readonly DSN must be a regular non-symlink file")
    if info.st_uid != os.geteuid():
        raise OneShotError("readonly DSN must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise OneShotError(
            "readonly DSN permissions must be 0600 or stricter"
        )


def validate_custody_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OneShotError("custody directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OneShotError(
            "custody directory must be a non-symlink directory"
        )
    if info.st_uid != os.geteuid():
        raise OneShotError(
            "custody directory must be owned by the current user"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise OneShotError(
            "custody directory permissions must be 0700 or stricter"
        )


def open_custody_guard(
    path: Path,
    *,
    require_root_owned_parent: bool,
) -> CustodyGuard:
    validate_custody_directory(path)
    if require_root_owned_parent:
        try:
            parent = path.parent.lstat()
        except OSError as exc:
            raise OneShotError("custody parent is unavailable") from exc
        if (
            parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise OneShotError(
                "custody parent must be root-owned and not group/world writable"
            )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as exc:
        raise OneShotError("cannot open deployment-pinned custody") from exc
    identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        stat.S_IFMT(opened.st_mode),
    )
    current_identity = (
        current.st_dev,
        current.st_ino,
        current.st_uid,
        stat.S_IMODE(current.st_mode),
        stat.S_IFMT(current.st_mode),
    )
    if identity != current_identity:
        os.close(descriptor)
        raise OneShotError("custody changed while it was opened")
    guard = CustodyGuard(path=path, descriptor=descriptor, identity=identity)
    guard.assert_path_identity()
    return guard


def read_regular_file_at(
    guard: CustodyGuard,
    name: str,
    label: str,
    *,
    private: bool = True,
    limit: int = MAX_JSON_BYTES,
) -> bytes:
    if "/" in name or name in {"", ".", ".."}:
        raise OneShotError(f"{label} filename is invalid")
    guard.assert_path_identity()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=guard.descriptor)
        before = os.fstat(descriptor)
        first = _read_fd_bounded(descriptor, label, limit)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_bounded(descriptor, label, limit)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise OneShotError(f"cannot read {label}") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or first != second
        or len(first) != before.st_size
    ):
        raise OneShotError(f"{label} changed while it was being read")
    if private and (
        before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise OneShotError(
            f"{label} must be current-user-owned and 0600 or stricter"
        )
    guard.assert_path_identity()
    return first


def custody_entry_exists(guard: CustodyGuard, name: str) -> bool:
    guard.assert_path_identity()
    try:
        os.stat(name, dir_fd=guard.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OneShotError("cannot inspect custody entry") from exc
    return True


def validate_custody_identity(
    guard: CustodyGuard,
    expected_sha256: str,
) -> None:
    identity = parse_json_bytes(
        read_regular_file_at(
            guard,
            "custody-identity.json",
            "T1 custody identity",
        ),
        "T1 custody identity",
    )
    if set(identity) != {"schema_version", "custody_id"}:
        raise OneShotError("T1 custody identity fields are invalid")
    if identity["schema_version"] != "commodity_c_fast_t1_custody_identity_v1":
        raise OneShotError("T1 custody identity schema version is invalid")
    if not ID_PATTERN.fullmatch(str(identity["custody_id"])):
        raise OneShotError("T1 custody_id is invalid")
    actual_sha256 = hashlib.sha256(canonical_json(identity)).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise OneShotError("T1 custody identity SHA256 does not match release")


def custody_path_sha256(path: Path) -> str:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OneShotError("cannot resolve the pinned custody path") from exc
    return hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()


def read_root_owned_deployment_pin(path: Path, label: str) -> str:
    raw = read_regular_file_strict(path, label, limit=4096)
    info = path.stat(follow_symlinks=False)
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != 0 or mode & 0o022:
        raise OneShotError(
            f"{label} must be root-owned and not group/world writable"
        )
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise OneShotError(f"{label} must be UTF-8") from exc
    if not value or "\x00" in value or "\n" in value:
        raise OneShotError(f"{label} must contain one non-empty line")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_create_only(
    path: Path,
    payload: dict[str, Any],
    schema_path: Path,
    label: str,
) -> str:
    validate_json_schema(payload, schema_path, label)
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    if not rendered.endswith("\n"):
        rendered += "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def write_json_create_only_at(
    guard: CustodyGuard,
    name: str,
    payload: dict[str, Any],
    schema_path: Path,
    label: str,
) -> str:
    if "/" in name or name in {"", ".", ".."}:
        raise OneShotError(f"{label} filename is invalid")
    validate_json_schema(payload, schema_path, label)
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    if not rendered.endswith("\n"):
        rendered += "\n"
    guard.assert_path_identity()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(
        name,
        flags,
        0o600,
        dir_fd=guard.descriptor,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(name, dir_fd=guard.descriptor)
        except OSError:
            pass
        raise
    os.fsync(guard.descriptor)
    guard.assert_path_identity()
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def write_bytes_create_only(path: Path, raw: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def stage_verified_audit_bundle(
    verified: VerifiedRelease,
    attempt_dir: Path,
) -> tuple[Path, Path, Path, Path]:
    bundle_root = attempt_dir / "verified-bundle"
    artifacts_dir = attempt_dir / "artifacts"
    scripts_dir = bundle_root / "scripts"
    schemas_dir = bundle_root / "docs/schemas"
    release_dir = bundle_root / "release"
    try:
        bundle_root.mkdir(mode=0o700)
        scripts_dir.mkdir(mode=0o700)
        (bundle_root / "docs").mkdir(mode=0o700)
        schemas_dir.mkdir(mode=0o700)
        release_dir.mkdir(mode=0o700)
        artifacts_dir.mkdir(mode=0o700)
        for relative_name, raw in verified.bundle_files.items():
            path = bundle_root / relative_name
            write_bytes_create_only(
                path,
                raw,
                0o500 if relative_name.startswith("scripts/") else 0o400,
            )
        manifest_path = release_dir / "manifest.json"
        write_bytes_create_only(
            manifest_path,
            canonical_json(verified.manifest) + b"\n",
            0o400,
        )
        for directory in (
            scripts_dir,
            schemas_dir,
            bundle_root / "docs",
            release_dir,
            bundle_root,
        ):
            directory.chmod(0o500)
            _fsync_directory(directory.parent)
        attempt_dir.chmod(0o500)
        _fsync_directory(attempt_dir.parent)
    except (OSError, OneShotError) as exc:
        raise OneShotError("cannot stage the verified audit bundle") from exc
    return (
        bundle_root,
        scripts_dir / "commodity_c_fast_l1_l5_audit.py",
        manifest_path,
        artifacts_dir,
    )


def verify_staged_audit_bundle(
    verified: VerifiedRelease,
    bundle_root: Path,
) -> None:
    for relative_name, expected_raw in verified.bundle_files.items():
        actual_raw = read_regular_file_strict(
            bundle_root / relative_name,
            f"staged {relative_name}",
            limit=MAX_ARTIFACT_BYTES,
        )
        if not hmac.compare_digest(
            hashlib.sha256(actual_raw).digest(),
            hashlib.sha256(expected_raw).digest(),
        ):
            raise OneShotError(
                f"staged audit bundle changed: {relative_name}"
            )
    manifest_raw = read_regular_file_strict(
        bundle_root / "release/manifest.json",
        "staged audit manifest",
    )
    if not hmac.compare_digest(
        hashlib.sha256(manifest_raw).digest(),
        hashlib.sha256(
            canonical_json(verified.manifest) + b"\n"
        ).digest(),
    ):
        raise OneShotError("staged audit manifest changed")


def artifact_hashes(paths: ArtifactPaths) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name, path in paths.as_dict().items():
        if path.exists() and not path.is_symlink():
            try:
                result[name] = sha256_regular_file(
                    path,
                    name,
                    limit=MAX_ARTIFACT_BYTES,
                )
            except OneShotError:
                result[name] = None
        else:
            result[name] = None
    return result


def validate_completed_outputs(
    paths: ArtifactPaths,
    verified: VerifiedRelease,
    child_exit_code: int,
) -> tuple[bool, dict[str, str]]:
    release = verified.payload
    raw_artifacts = {
        name: read_regular_file_strict(
            path,
            name,
            limit=MAX_ARTIFACT_BYTES,
        )
        for name, path in paths.as_dict().items()
    }
    if not raw_artifacts["audit_csv"] or not raw_artifacts["audit_markdown"]:
        raise OneShotError("CSV and Markdown audit artifacts must not be empty")
    evidence = parse_json_bytes(
        raw_artifacts["audit_json"],
        "audit JSON evidence",
    )
    proof = parse_json_bytes(
        raw_artifacts["readonly_proof"],
        "readonly proof",
    )
    validate_json_schema_bytes(
        evidence,
        verified.bundle_files[
            "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
        ],
        "audit evidence",
        legacy_schema_raw=verified.bundle_files[
            "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json"
        ],
    )
    validate_json_schema_bytes(
        proof,
        verified.bundle_files[
            "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
        ],
        "readonly proof",
    )
    complete_hashes = {
        key: hashlib.sha256(raw).hexdigest()
        for key, raw in raw_artifacts.items()
    }

    if evidence["snapshot_id"] != release["snapshot_id"]:
        raise OneShotError("audit evidence snapshot_id does not match release")
    if evidence["manifest_sha256"] != release["manifest_sha256"]:
        raise OneShotError(
            "audit evidence manifest SHA256 does not match release"
        )
    evidence_window = evidence["audit_window"]
    release_window = release["audit_window"]
    assert_audit_windows_equal(
        evidence_window,
        release_window,
        "audit evidence",
    )
    if evidence["read_only"] is not True or evidence["database_mutations"] != 0:
        raise OneShotError("audit evidence violates readonly invariants")

    if proof["snapshot_id"] != release["snapshot_id"]:
        raise OneShotError("readonly proof snapshot_id does not match release")
    if proof["manifest_sha256"] != release["manifest_sha256"]:
        raise OneShotError(
            "readonly proof manifest SHA256 does not match release"
        )
    if proof["audit_evidence_sha256"] != complete_hashes["audit_json"]:
        raise OneShotError(
            "readonly proof does not bind exact audit JSON bytes"
        )
    if proof["endpoint_identity_sha256"] != release[
        "endpoint_identity_sha256"
    ]:
        raise OneShotError("readonly proof endpoint does not match release")
    if proof["endpoint_binding_verified"] is not True:
        raise OneShotError("readonly proof did not verify endpoint binding")
    if (
        proof["write_probe_attempted"] is not False
        or proof["database_mutations"] != 0
    ):
        raise OneShotError("readonly proof violates mutation invariants")
    if proof["preflight"] != proof["postflight"]:
        raise OneShotError("readonly proof pre/post metadata drifted")
    build_sha256 = hashlib.sha256(
        proof["preflight"]["questdb_build"].encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(
        build_sha256,
        release["questdb_build_sha256"],
    ):
        raise OneShotError("QuestDB build does not match release")

    p0_pass = evidence["summary"]["p0_pass"]
    if child_exit_code == 0 and p0_pass is not True:
        raise OneShotError("child exited 0 without P0 pass")
    if child_exit_code == 1 and p0_pass is not False:
        raise OneShotError("child exited 1 without a P0 blocker")
    if child_exit_code not in {0, 1}:
        raise OneShotError("completed output validation requires exit 0 or 1")
    return bool(p0_pass), complete_hashes


def child_environment() -> dict[str, str]:
    allowlist = (
        "LANG",
        "LC_ALL",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TZ",
    )
    return {
        key: os.environ[key]
        for key in allowlist
        if key in os.environ
    }


def build_child_invocation(
    release: dict[str, Any],
    audit_script_path: Path,
    manifest_path: Path,
    dsn_path: Path,
    paths: ArtifactPaths,
) -> list[str]:
    return [
        sys.executable,
        "-I",
        str(audit_script_path),
        "--manifest",
        str(manifest_path),
        "--start",
        release["audit_window"]["start"],
        "--end",
        release["audit_window"]["end_exclusive"],
        "--dsn-file",
        str(dsn_path),
        "--expected-endpoint-identity-sha256",
        release["endpoint_identity_sha256"],
        "--expected-manifest-sha256",
        release["manifest_sha256"],
        "--json-output",
        str(paths.audit_json),
        "--csv-output",
        str(paths.audit_csv),
        "--markdown-output",
        str(paths.audit_markdown),
        "--readonly-proof-output",
        str(paths.readonly_proof),
    ]


def _new_terminal(
    verified: VerifiedRelease,
    consume_sha256: str,
    invocation_sha256: str,
    started_at: datetime,
    *,
    terminal_state: str,
    error_code: str | None,
    child_exit_code: int | None,
    hashes: dict[str, str | None],
    p0_pass: bool | None,
    proof_verified: bool,
) -> dict[str, Any]:
    release = verified.payload
    return {
        "schema_version": TERMINAL_SCHEMA_VERSION,
        "candidate_id": CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "terminal_state": terminal_state,
        "error_code": error_code,
        "release_sha256": verified.release_sha256,
        "consume_marker_sha256": consume_sha256,
        "child_invocation_sha256": invocation_sha256,
        "child_exit_code": child_exit_code,
        "started_at": started_at.isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "artifact_sha256": hashes,
        "manifest_sha256": release["manifest_sha256"],
        "endpoint_identity_sha256": release["endpoint_identity_sha256"],
        "p0_pass": p0_pass,
        "proof_verified": proof_verified,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "replay_allowed": False,
        "p0_acceptance_authorized": False,
        "terminal_integrity_scope": (
            "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
        ),
    }


def validate_terminal_semantics(terminal: dict[str, Any]) -> None:
    state = terminal["terminal_state"]
    hashes_complete = all(
        isinstance(value, str)
        and SHA256_PATTERN.fullmatch(value) is not None
        for value in terminal["artifact_sha256"].values()
    )
    if state == "SUCCEEDED_P0_PASS":
        valid = (
            terminal["child_exit_code"] == 0
            and terminal["p0_pass"] is True
            and terminal["proof_verified"] is True
            and terminal["error_code"] is None
            and hashes_complete
        )
    elif state == "COMPLETED_P0_BLOCKED":
        valid = (
            terminal["child_exit_code"] == 1
            and terminal["p0_pass"] is False
            and terminal["proof_verified"] is True
            and terminal["error_code"] is None
            and hashes_complete
        )
    elif state == "FAILED_OUTPUT_VALIDATION":
        valid = (
            terminal["child_exit_code"] in {0, 1}
            and terminal["p0_pass"] is None
            and terminal["proof_verified"] is False
            and isinstance(terminal["error_code"], str)
        )
    elif state == "FAILED_CHILD":
        valid = (
            terminal["child_exit_code"] not in {0, 1}
            and terminal["p0_pass"] is None
            and terminal["proof_verified"] is False
            and isinstance(terminal["error_code"], str)
        )
    else:
        valid = (
            state in {"TIMED_OUT", "INTERRUPTED"}
            and terminal["child_exit_code"] is None
            and terminal["p0_pass"] is None
            and terminal["proof_verified"] is False
            and isinstance(terminal["error_code"], str)
        )
    if not valid:
        raise OneShotError(
            f"terminal state fields are inconsistent for {state}"
        )


def validate_existing_terminal(
    guard: CustodyGuard,
    consume_name: str,
    terminal_name: str,
    verified: VerifiedRelease,
) -> dict[str, Any]:
    consume_raw = read_regular_file_at(
        guard,
        consume_name,
        "existing consume marker",
    )
    terminal_raw = read_regular_file_at(
        guard,
        terminal_name,
        "existing terminal record",
    )
    consume = parse_json_bytes(consume_raw, "existing consume marker")
    terminal = parse_json_bytes(terminal_raw, "existing terminal record")
    validate_json_schema(
        consume,
        CONSUME_SCHEMA_PATH,
        "existing consume marker",
    )
    validate_json_schema(
        terminal,
        TERMINAL_SCHEMA_PATH,
        "existing terminal record",
    )
    validate_terminal_semantics(terminal)
    release = verified.payload
    for field in (
        "release_id",
        "attempt_id",
        "release_sha256",
        "manifest_sha256",
        "endpoint_identity_sha256",
    ):
        expected = (
            verified.release_sha256
            if field == "release_sha256"
            else release[field]
        )
        if consume[field] != expected or terminal[field] != expected:
            raise OneShotError(
                f"existing consume/terminal {field} binding is invalid"
            )
    for field in (
        "trusted_keyring_sha256",
        "custody_identity_sha256",
        "custody_path_sha256",
    ):
        expected = (
            verified.keyring_sha256
            if field == "trusted_keyring_sha256"
            else release[field]
        )
        if consume[field] != expected:
            raise OneShotError(
                f"existing consume marker {field} binding is invalid"
            )
    consume_sha256 = hashlib.sha256(consume_raw).hexdigest()
    if not hmac.compare_digest(
        consume_sha256,
        terminal["consume_marker_sha256"],
    ):
        raise OneShotError(
            "existing terminal does not bind exact consume marker bytes"
        )
    if terminal["terminal_state"] in {
        "SUCCEEDED_P0_PASS",
        "COMPLETED_P0_BLOCKED",
    }:
        artifacts_dir = (
            guard.path / release["attempt_id"] / "artifacts"
        )
        paths = ArtifactPaths(
            audit_json=artifacts_dir / "audit.json",
            audit_csv=artifacts_dir / "audit.csv",
            audit_markdown=artifacts_dir / "audit.md",
            readonly_proof=artifacts_dir / "readonly-proof.json",
        )
        current_hashes = artifact_hashes(paths)
        if current_hashes != terminal["artifact_sha256"]:
            raise OneShotError(
                "existing successful terminal artifact hashes no longer match"
            )
    return terminal


def execute_once(
    args: argparse.Namespace,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    output_validator: Callable[
        [ArtifactPaths, VerifiedRelease, int],
        tuple[bool, dict[str, str]],
    ] = validate_completed_outputs,
    now: datetime | None = None,
    pinned_keyring_sha256: str | None = None,
    pinned_custody_path: Path | None = None,
) -> tuple[int, dict[str, Any] | None]:
    current_time = now or datetime.now(timezone.utc)
    effective_keyring_pin = (
        pinned_keyring_sha256
        or read_root_owned_deployment_pin(
            DEPLOYMENT_KEYRING_PIN_PATH,
            "deployment keyring pin",
        )
    )
    effective_custody_path = (
        pinned_custody_path
        or Path(
            read_root_owned_deployment_pin(
                DEPLOYMENT_CUSTODY_PIN_PATH,
                "deployment custody path pin",
            )
        )
    )
    verified = verify_release(
        args.release,
        args.trusted_keyring,
        args.manifest,
        source_commit_sha=args.source_commit_sha,
        runtime_image_digest=args.runtime_image_digest,
        pinned_keyring_sha256=effective_keyring_pin,
        now=current_time,
    )
    try:
        requested_custody = args.custody_dir.resolve(strict=True)
        pinned_custody = effective_custody_path.resolve(strict=True)
    except OSError as exc:
        raise OneShotError("cannot resolve deployment-pinned custody") from exc
    if requested_custody != pinned_custody:
        raise OneShotError(
            "custody directory does not match the immutable deployment pin"
        )
    actual_custody_path_sha256 = custody_path_sha256(pinned_custody)
    if not hmac.compare_digest(
        actual_custody_path_sha256,
        verified.payload["custody_path_sha256"],
    ):
        raise OneShotError("custody path SHA256 does not match release")
    guard = open_custody_guard(
        args.custody_dir,
        require_root_owned_parent=pinned_custody_path is None,
    )
    try:
        validate_custody_identity(
            guard,
            verified.payload["custody_identity_sha256"],
        )
    except Exception:
        guard.close()
        raise
    release = verified.payload
    consume_name = f"{release['attempt_id']}.consumed.json"
    terminal_name = f"{release['attempt_id']}.terminal.json"
    if custody_entry_exists(guard, consume_name):
        if custody_entry_exists(guard, terminal_name):
            terminal = validate_existing_terminal(
                guard,
                consume_name,
                terminal_name,
                verified,
            )
            print(
                "release already consumed; existing terminal state: "
                f"{terminal['terminal_state']}"
            )
            guard.close()
            return 2, terminal
        guard.close()
        raise OneShotError(
            "CONSUMED_WITHOUT_TERMINAL_REQUIRES_NEW_RELEASE"
        )
    if custody_entry_exists(guard, terminal_name):
        guard.close()
        raise OneShotError("terminal seal exists without a consume marker")
    attempt_dir = args.custody_dir / release["attempt_id"]
    if custody_entry_exists(guard, release["attempt_id"]):
        guard.close()
        raise OneShotError(
            "attempt artifact directory exists before release consumption"
        )
    try:
        validate_private_dsn_metadata(args.dsn_file)
    except Exception:
        guard.close()
        raise
    bundle_root = attempt_dir / "verified-bundle"
    staged_audit_script = (
        bundle_root / "scripts/commodity_c_fast_l1_l5_audit.py"
    )
    staged_manifest = bundle_root / "release/manifest.json"
    artifacts_dir = attempt_dir / "artifacts"
    paths = ArtifactPaths(
        audit_json=artifacts_dir / "audit.json",
        audit_csv=artifacts_dir / "audit.csv",
        audit_markdown=artifacts_dir / "audit.md",
        readonly_proof=artifacts_dir / "readonly-proof.json",
    )
    invocation = build_child_invocation(
        release,
        staged_audit_script,
        staged_manifest,
        args.dsn_file,
        paths,
    )
    invocation_sha256 = hashlib.sha256(
        canonical_json(invocation)
    ).hexdigest()

    consume_marker = {
        "schema_version": CONSUME_SCHEMA_VERSION,
        "candidate_id": CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "release_sha256": verified.release_sha256,
        "consumed_at": current_time.isoformat(),
        "manifest_sha256": release["manifest_sha256"],
        "endpoint_identity_sha256": release[
            "endpoint_identity_sha256"
        ],
        "source_commit_sha": release["source_commit_sha"],
        "runtime_image_digest": release["runtime_image_digest"],
        "runner_sha256": release["runner_sha256"],
        "audit_script_sha256": release["audit_script_sha256"],
        "trusted_keyring_sha256": verified.keyring_sha256,
        "custody_identity_sha256": release["custody_identity_sha256"],
        "custody_path_sha256": release["custody_path_sha256"],
        "replay_allowed": False,
    }
    try:
        consume_sha256 = write_json_create_only_at(
            guard,
            consume_name,
            consume_marker,
            CONSUME_SCHEMA_PATH,
            "consume marker",
        )
    except FileExistsError as exc:
        guard.close()
        raise OneShotError("release was concurrently consumed") from exc

    try:
        guard.assert_path_identity()
        os.mkdir(
            release["attempt_id"],
            mode=0o700,
            dir_fd=guard.descriptor,
        )
        os.fsync(guard.descriptor)
        guard.assert_path_identity()
    except OSError:
        terminal = _new_terminal(
            verified,
            consume_sha256,
            invocation_sha256,
            current_time,
            terminal_state="FAILED_CHILD",
            error_code="ATTEMPT_DIRECTORY_CREATE_FAILED",
            child_exit_code=None,
            hashes={
                "audit_json": None,
                "audit_csv": None,
                "audit_markdown": None,
                "readonly_proof": None,
            },
            p0_pass=None,
            proof_verified=False,
        )
        validate_terminal_semantics(terminal)
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            TERMINAL_SCHEMA_PATH,
            "terminal seal",
        )
        guard.close()
        return 2, terminal
    try:
        (
            bundle_root,
            actual_staged_audit_script,
            actual_staged_manifest,
            actual_artifacts_dir,
        ) = stage_verified_audit_bundle(verified, attempt_dir)
        if (
            actual_staged_audit_script != staged_audit_script
            or actual_staged_manifest != staged_manifest
            or actual_artifacts_dir != artifacts_dir
        ):
            raise OneShotError("staged audit bundle paths are inconsistent")
        guard.assert_path_identity()
        verify_staged_audit_bundle(verified, bundle_root)
    except OneShotError:
        terminal = _new_terminal(
            verified,
            consume_sha256,
            invocation_sha256,
            current_time,
            terminal_state="FAILED_CHILD",
            error_code="VERIFIED_BUNDLE_STAGE_FAILED",
            child_exit_code=None,
            hashes=artifact_hashes(paths),
            p0_pass=None,
            proof_verified=False,
        )
        validate_terminal_semantics(terminal)
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            TERMINAL_SCHEMA_PATH,
            "terminal record",
        )
        guard.close()
        return 2, terminal
    started_at = datetime.now(timezone.utc)
    terminal: dict[str, Any]
    result: subprocess.CompletedProcess[str] | None = None
    try:
        result = runner(
            invocation,
            cwd=bundle_root,
            env=child_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=release["max_runtime_seconds"],
            check=False,
        )
        guard.assert_path_identity()
        if result.returncode not in {0, 1}:
            terminal = _new_terminal(
                verified,
                consume_sha256,
                invocation_sha256,
                started_at,
                terminal_state="FAILED_CHILD",
                error_code="CHILD_EXIT_NON_AUDIT",
                child_exit_code=result.returncode,
                hashes=artifact_hashes(paths),
                p0_pass=None,
                proof_verified=False,
            )
            exit_code = 2
        else:
            try:
                p0_pass, hashes = output_validator(
                    paths,
                    verified,
                    result.returncode,
                )
            except (OneShotError, OSError, KeyError, TypeError, ValueError):
                terminal = _new_terminal(
                    verified,
                    consume_sha256,
                    invocation_sha256,
                    started_at,
                    terminal_state="FAILED_OUTPUT_VALIDATION",
                    error_code="OUTPUT_VALIDATION_FAILED",
                    child_exit_code=result.returncode,
                    hashes=artifact_hashes(paths),
                    p0_pass=None,
                    proof_verified=False,
                )
                exit_code = 2
            else:
                terminal = _new_terminal(
                    verified,
                    consume_sha256,
                    invocation_sha256,
                    started_at,
                    terminal_state=(
                        "SUCCEEDED_P0_PASS"
                        if p0_pass
                        else "COMPLETED_P0_BLOCKED"
                    ),
                    error_code=None,
                    child_exit_code=result.returncode,
                    hashes=hashes,
                    p0_pass=p0_pass,
                    proof_verified=True,
                )
                exit_code = 0 if p0_pass else 1
    except subprocess.TimeoutExpired:
        terminal = _new_terminal(
            verified,
            consume_sha256,
            invocation_sha256,
            started_at,
            terminal_state="TIMED_OUT",
            error_code="CHILD_TIMEOUT",
            child_exit_code=None,
            hashes=artifact_hashes(paths),
            p0_pass=None,
            proof_verified=False,
        )
        exit_code = 2
    except KeyboardInterrupt:
        terminal = _new_terminal(
            verified,
            consume_sha256,
            invocation_sha256,
            started_at,
            terminal_state="INTERRUPTED",
            error_code="RUNNER_INTERRUPTED",
            child_exit_code=None,
            hashes=artifact_hashes(paths),
            p0_pass=None,
            proof_verified=False,
        )
        exit_code = 2
    except Exception:
        terminal = _new_terminal(
            verified,
            consume_sha256,
            invocation_sha256,
            started_at,
            terminal_state="FAILED_CHILD",
            error_code="CHILD_LAUNCH_FAILED",
            child_exit_code=None,
            hashes=artifact_hashes(paths),
            p0_pass=None,
            proof_verified=False,
        )
        exit_code = 2

    try:
        guard.assert_path_identity()
        try:
            verify_staged_audit_bundle(verified, bundle_root)
        except OneShotError:
            completed_audit_exit = (
                result.returncode
                if result is not None and result.returncode in {0, 1}
                else None
            )
            observed_child_exit = (
                result.returncode if result is not None else None
            )
            terminal = _new_terminal(
                verified,
                consume_sha256,
                invocation_sha256,
                started_at,
                terminal_state=(
                    "FAILED_OUTPUT_VALIDATION"
                    if completed_audit_exit is not None
                    else "FAILED_CHILD"
                ),
                error_code="STAGED_BUNDLE_CHANGED",
                child_exit_code=observed_child_exit,
                hashes=artifact_hashes(paths),
                p0_pass=None,
                proof_verified=False,
            )
            exit_code = 2
        validate_terminal_semantics(terminal)
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            TERMINAL_SCHEMA_PATH,
            "terminal seal",
        )
    except FileExistsError as exc:
        raise OneShotError("terminal seal already exists") from exc
    finally:
        guard.close()
    return exit_code, terminal


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--custody-dir", type=Path, required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--runtime-image-digest", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        exit_code, terminal = execute_once(args)
    except (OneShotError, OSError) as exc:
        print(f"T1 one-shot failed before execution: {exc}", file=sys.stderr)
        return 2
    if terminal is not None:
        print(f"terminal_state={terminal['terminal_state']}")
        print(f"attempt_id={terminal['attempt_id']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
