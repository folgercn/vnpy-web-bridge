#!/usr/bin/env python3
"""Offline verification for independently signed C_FAST P0 acceptance."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import os
from pathlib import Path
import re
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from commodity_c_fast_t1_one_shot import (
    ArtifactPaths,
    CONSUME_SCHEMA_PATH,
    EVIDENCE_SCHEMA_PATH,
    LEGACY_EVIDENCE_SCHEMA_PATH,
    MANIFEST_SCHEMA_PATH,
    MAX_ARTIFACT_BYTES,
    MAX_JSON_BYTES,
    MAX_RELEASE_TTL,
    READONLY_PROOF_SCHEMA_PATH,
    RELEASE_SCHEMA_PATH,
    TERMINAL_SCHEMA_PATH,
    OneShotError,
    VerifiedRelease,
    assert_audit_windows_equal,
    canonical_json,
    load_json_strict,
    parse_child_invocation_bytes,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    release_attempt_id,
    unsigned_release_payload,
    validate_completed_outputs,
    validate_json_schema,
    validate_terminal_semantics,
)


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-p0-acceptance-v1.schema.json"
)
ACCEPTANCE_SCHEMA_VERSION = "commodity_c_fast_p0_acceptance_v1"
ACCEPTANCE_PURPOSE = "c_fast_p0_terminal_acceptance"
ACCEPTANCE_KEY_PURPOSE = "c_fast_p0_acceptance_signer"
ACCEPTANCE_KEYRING_VERSION = (
    "commodity_c_fast_p0_acceptance_trusted_keys_v1"
)
EXTERNAL_CUSTODY_IDENTITY_VERSION = (
    "commodity_c_fast_p0_external_custody_identity_v1"
)
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
MAX_TERMINAL_OVERHEAD = timedelta(minutes=5)
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
BUNDLE_FILE_ORDER = (
    "t1_release",
    "t1_trusted_keyring",
    "manifest",
    "consume_marker",
    "terminal_seal",
    "child_invocation",
    "audit_json",
    "audit_csv",
    "audit_markdown",
    "readonly_proof",
)


class P0AcceptanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class P0BundlePaths:
    t1_release: Path
    t1_trusted_keyring: Path
    manifest: Path
    consume_marker: Path
    terminal_seal: Path
    child_invocation: Path
    audit_json: Path
    audit_csv: Path
    audit_markdown: Path
    readonly_proof: Path
    external_custody_identity: Path


@dataclass(frozen=True)
class VerifiedP0Bundle:
    release: dict[str, Any]
    manifest: dict[str, Any]
    consume: dict[str, Any]
    terminal: dict[str, Any]
    proof: dict[str, Any]
    raw_sha256: dict[str, str]
    canonical_sha256: dict[str, str]
    artifact_sha256: dict[str, str]
    bundle_index_sha256: str
    t1_keyring_sha256: str
    t1_authority_public_key_bytes: tuple[bytes, ...]
    external_custody_identity: dict[str, Any]
    external_custody_identity_raw_sha256: str
    external_custody_identity_canonical_sha256: str


def unsigned_acceptance_payload(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "signature"
    }


def acceptance_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def acceptance_id_for_terminal(terminal_raw_sha256: str) -> str:
    _validate_sha256(terminal_raw_sha256, "terminal raw")
    return f"p0-accept-{terminal_raw_sha256}"


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compare(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise P0AcceptanceError(f"{label} binding mismatch")


def _validate_sha256(value: str, label: str) -> None:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise P0AcceptanceError(f"{label} must be a lowercase SHA256")


def _validate_historical_release_semantics(
    release: dict[str, Any],
) -> tuple[datetime, datetime, datetime]:
    if release["purpose"] != "c_fast_l1_l5_t1_readonly_audit":
        raise P0AcceptanceError("T1 release purpose is invalid")
    release_id = str(release["release_id"])
    if ID_PATTERN.fullmatch(release_id) is None:
        raise P0AcceptanceError("T1 release_id is invalid")
    if release["attempt_id"] != release_attempt_id(release_id):
        raise P0AcceptanceError("T1 release attempt_id is invalid")
    human_signature = str(release["human_signature"]).strip()
    if not human_signature or human_signature.startswith("PENDING_"):
        raise P0AcceptanceError(
            "T1 release human_signature is not final"
        )
    issued_at = parse_datetime(release["issued_at"], "T1 issued_at")
    not_before = parse_datetime(
        release["not_before"],
        "T1 not_before",
    )
    expires_at = parse_datetime(release["expires_at"], "T1 expires_at")
    if not issued_at <= not_before < expires_at:
        raise P0AcceptanceError(
            "T1 release historical times are inconsistent"
        )
    if expires_at - issued_at > MAX_RELEASE_TTL:
        raise P0AcceptanceError("T1 release historical TTL exceeds 24 hours")
    for field in (
        "network_authorized",
        "readonly_production_query_authorized",
    ):
        if release[field] is not True:
            raise P0AcceptanceError(
                "T1 release lacks explicit readonly query authority"
            )
    for field in (
        "write_probe_authorized",
        "database_mutation_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "deployment_mutation_authorized",
    ):
        if release[field] is not False:
            raise P0AcceptanceError(
                f"T1 release granted forbidden authority: {field}"
            )
    return issued_at, not_before, expires_at


def _load_public_key(
    keyring: dict[str, Any],
    *,
    keyring_version: str,
    key_id: str,
    required_purpose: str,
) -> Ed25519PublicKey:
    if set(keyring) != {"schema_version", "keys"}:
        raise P0AcceptanceError("trusted keyring fields are invalid")
    if keyring["schema_version"] != keyring_version:
        raise P0AcceptanceError("trusted keyring schema version is invalid")
    entries = keyring["keys"]
    if not isinstance(entries, list) or not entries:
        raise P0AcceptanceError("trusted keyring must contain keys")
    matched: dict[str, Any] | None = None
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise P0AcceptanceError(
                "trusted keyring entry fields are invalid"
            )
        current_id = str(entry["key_id"])
        if current_id in seen:
            raise P0AcceptanceError(
                "trusted keyring contains duplicate key_id"
            )
        seen.add(current_id)
        if current_id == key_id:
            matched = entry
    if matched is None:
        raise P0AcceptanceError("signer key is not trusted")
    if matched["purpose"] != required_purpose:
        raise P0AcceptanceError("signer key purpose is not authorized")
    try:
        raw = base64.b64decode(
            str(matched["public_key_base64"]),
            validate=True,
        )
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error) as exc:
        raise P0AcceptanceError(
            "trusted Ed25519 public key is invalid"
        ) from exc


def _verify_ed25519(
    public_key: Ed25519PublicKey,
    signature_text: Any,
    message: bytes,
    label: str,
) -> None:
    try:
        signature = base64.b64decode(
            str(signature_text),
            validate=True,
        )
        if len(signature) != 64:
            raise ValueError
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise P0AcceptanceError(f"{label} signature is invalid") from exc


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _authorized_public_key_bytes(
    keyring: dict[str, Any],
    *,
    required_purpose: str,
) -> tuple[bytes, ...]:
    authorized: list[bytes] = []
    for entry in keyring["keys"]:
        if entry["purpose"] != required_purpose:
            continue
        try:
            raw = base64.b64decode(
                str(entry["public_key_base64"]),
                validate=True,
            )
            if len(raw) != 32:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, binascii.Error) as exc:
            raise P0AcceptanceError(
                "trusted Ed25519 public key is invalid"
            ) from exc
        authorized.append(raw)
    if not authorized:
        raise P0AcceptanceError(
            f"trusted keyring has no key for purpose {required_purpose}"
        )
    return tuple(authorized)


def require_independent_acceptance_signer(
    t1_authority_public_key_bytes: tuple[bytes, ...],
    acceptance_signer: Ed25519PublicKey,
) -> None:
    acceptance_public_key_bytes = _public_key_bytes(acceptance_signer)
    if any(
        hmac.compare_digest(t1_key, acceptance_public_key_bytes)
        for t1_key in t1_authority_public_key_bytes
    ):
        raise P0AcceptanceError(
            "P0 acceptance signer must be cryptographically distinct "
            "from every T1 audit release authority"
        )


def _validate_child_invocation(
    invocation: list[str],
    release: dict[str, Any],
) -> None:
    flags = (
        "--manifest",
        "--start",
        "--end",
        "--dsn-file",
        "--expected-endpoint-identity-sha256",
        "--expected-manifest-sha256",
        "--json-output",
        "--csv-output",
        "--markdown-output",
        "--readonly-proof-output",
    )
    if len(invocation) != 3 + 2 * len(flags):
        raise P0AcceptanceError(
            "child invocation has unexpected or missing arguments"
        )
    python_path = Path(invocation[0])
    if (
        not python_path.is_absolute()
        or re.fullmatch(
            r"python(?:3(?:\.[0-9]+)?)?",
            python_path.name,
        )
        is None
        or invocation[1] != "-I"
    ):
        raise P0AcceptanceError(
            "child invocation must use an absolute Python -I executable"
        )
    audit_script = Path(invocation[2])
    if (
        not audit_script.is_absolute()
        or ".." in audit_script.parts
        or audit_script.name != "commodity_c_fast_l1_l5_audit.py"
    ):
        raise P0AcceptanceError(
            "child invocation staged audit script is invalid"
        )
    values: dict[str, str] = {}
    for index, flag in enumerate(flags):
        offset = 3 + index * 2
        if invocation[offset] != flag:
            raise P0AcceptanceError(
                "child invocation argument order is invalid"
            )
        values[flag] = invocation[offset + 1]

    bundle_root = audit_script.parents[1]
    attempt_dir = bundle_root.parent
    if (
        bundle_root.name != "verified-bundle"
        or attempt_dir.name != release["attempt_id"]
        or audit_script
        != bundle_root / "scripts/commodity_c_fast_l1_l5_audit.py"
        or Path(values["--manifest"])
        != bundle_root / "release/manifest.json"
    ):
        raise P0AcceptanceError(
            "child invocation verified-bundle paths are invalid"
        )
    expected_scalars = {
        "--start": release["audit_window"]["start"],
        "--end": release["audit_window"]["end_exclusive"],
        "--expected-endpoint-identity-sha256": (
            release["endpoint_identity_sha256"]
        ),
        "--expected-manifest-sha256": release["manifest_sha256"],
    }
    for flag, expected in expected_scalars.items():
        if values[flag] != expected:
            raise P0AcceptanceError(
                f"child invocation {flag} binding mismatch"
            )
    dsn_path = Path(values["--dsn-file"])
    if not dsn_path.is_absolute() or ".." in dsn_path.parts:
        raise P0AcceptanceError(
            "child invocation DSN path must be absolute and normalized"
        )
    artifacts_dir = attempt_dir / "artifacts"
    expected_outputs = {
        "--json-output": artifacts_dir / "audit.json",
        "--csv-output": artifacts_dir / "audit.csv",
        "--markdown-output": artifacts_dir / "audit.md",
        "--readonly-proof-output": artifacts_dir / "readonly-proof.json",
    }
    for flag, expected in expected_outputs.items():
        actual = Path(values[flag])
        if (
            not actual.is_absolute()
            or ".." in actual.parts
            or actual != expected
        ):
            raise P0AcceptanceError(
                f"child invocation {flag} path is invalid"
            )
    if (
        Path(os.path.normpath(str(audit_script))) != audit_script
        or Path(os.path.normpath(str(dsn_path))) != dsn_path
    ):
        raise P0AcceptanceError(
            "child invocation paths must be normalized"
        )


def _validate_external_custody_identity(
    payload: dict[str, Any],
) -> None:
    expected = {
        "schema_version",
        "custody_id",
        "asserted_archive_type",
        "archive_locator_sha256",
        "independent_from_t1_runner",
        "immutability_asserted",
    }
    if set(payload) != expected:
        raise P0AcceptanceError(
            "external custody identity fields are invalid"
        )
    if payload["schema_version"] != EXTERNAL_CUSTODY_IDENTITY_VERSION:
        raise P0AcceptanceError(
            "external custody identity schema version is invalid"
        )
    if ID_PATTERN.fullmatch(str(payload["custody_id"])) is None:
        raise P0AcceptanceError("external custody_id is invalid")
    if payload["asserted_archive_type"] not in {
        "ASSERTED_WORM",
        "ASSERTED_APPEND_ONLY",
    }:
        raise P0AcceptanceError(
            "external asserted archive type is invalid"
        )
    _validate_sha256(
        str(payload["archive_locator_sha256"]),
        "external archive locator",
    )
    if (
        payload["independent_from_t1_runner"] is not True
        or payload["immutability_asserted"] is not True
    ):
        raise P0AcceptanceError(
            "external custody independence/immutability is not asserted"
        )


def _bundle_index_sha256(
    raw_files: dict[str, bytes],
) -> str:
    if tuple(raw_files) != BUNDLE_FILE_ORDER:
        raise P0AcceptanceError("P0 bundle file order is invalid")
    index = {
        "schema_version": "commodity_c_fast_p0_bundle_index_v1",
        "files": [
            {
                "name": name,
                "size_bytes": len(raw_files[name]),
                "sha256": _hash_bytes(raw_files[name]),
            }
            for name in BUNDLE_FILE_ORDER
        ],
    }
    return _hash_bytes(canonical_json(index))


def _read_bundle_raw(paths: P0BundlePaths) -> dict[str, bytes]:
    limits = {
        "t1_release": MAX_JSON_BYTES,
        "t1_trusted_keyring": MAX_JSON_BYTES,
        "manifest": MAX_JSON_BYTES,
        "consume_marker": MAX_JSON_BYTES,
        "terminal_seal": MAX_JSON_BYTES,
        "child_invocation": MAX_JSON_BYTES,
        "audit_json": MAX_ARTIFACT_BYTES,
        "audit_csv": MAX_ARTIFACT_BYTES,
        "audit_markdown": MAX_ARTIFACT_BYTES,
        "readonly_proof": MAX_ARTIFACT_BYTES,
    }
    return {
        name: read_regular_file_strict(
            getattr(paths, name),
            name,
            limit=limits[name],
        )
        for name in BUNDLE_FILE_ORDER
    }


def verify_t1_bundle(
    paths: P0BundlePaths,
    *,
    expected_t1_keyring_sha256: str,
) -> VerifiedP0Bundle:
    _validate_sha256(
        expected_t1_keyring_sha256,
        "independently pinned T1 keyring",
    )
    raw_files = _read_bundle_raw(paths)
    release = parse_json_bytes(raw_files["t1_release"], "T1 release")
    t1_keyring = parse_json_bytes(
        raw_files["t1_trusted_keyring"],
        "T1 trusted keyring",
    )
    manifest = parse_json_bytes(raw_files["manifest"], "audit manifest")
    consume = parse_json_bytes(
        raw_files["consume_marker"],
        "consume marker",
    )
    terminal = parse_json_bytes(
        raw_files["terminal_seal"],
        "terminal seal",
    )
    child_invocation = parse_child_invocation_bytes(
        raw_files["child_invocation"],
    )
    proof = parse_json_bytes(
        raw_files["readonly_proof"],
        "readonly proof",
    )
    evidence = parse_json_bytes(
        raw_files["audit_json"],
        "audit JSON evidence",
    )
    validate_json_schema(release, RELEASE_SCHEMA_PATH, "T1 release")
    validate_json_schema(manifest, MANIFEST_SCHEMA_PATH, "audit manifest")
    validate_json_schema(consume, CONSUME_SCHEMA_PATH, "consume marker")
    validate_json_schema(terminal, TERMINAL_SCHEMA_PATH, "terminal seal")
    validate_terminal_semantics(terminal)
    _issued_at, not_before, expires_at = (
        _validate_historical_release_semantics(release)
    )

    t1_keyring_sha256 = _hash_bytes(canonical_json(t1_keyring))
    _compare(
        t1_keyring_sha256,
        expected_t1_keyring_sha256,
        "independently pinned T1 keyring",
    )
    _compare(
        t1_keyring_sha256,
        release["trusted_keyring_sha256"],
        "T1 release keyring",
    )
    t1_public_key = _load_public_key(
        t1_keyring,
        keyring_version="commodity_c_fast_t1_trusted_keys_v1",
        key_id=str(release["signer_key_id"]),
        required_purpose="t1_audit_release_signer",
    )
    _verify_ed25519(
        t1_public_key,
        release["signature"],
        canonical_json(unsigned_release_payload(release)),
        "T1 release",
    )
    t1_authority_public_key_bytes = _authorized_public_key_bytes(
        t1_keyring,
        required_purpose="t1_audit_release_signer",
    )

    manifest_canonical_sha256 = _hash_bytes(canonical_json(manifest))
    _compare(
        manifest_canonical_sha256,
        release["manifest_sha256"],
        "manifest canonical",
    )
    if manifest["snapshot_id"] != release["snapshot_id"]:
        raise P0AcceptanceError("manifest snapshot_id mismatch")
    assert_audit_windows_equal(
        manifest["audit_window"],
        release["audit_window"],
        "audit manifest",
    )
    schema_bindings = (
        ("manifest_schema_sha256", MANIFEST_SCHEMA_PATH),
        ("evidence_schema_sha256", EVIDENCE_SCHEMA_PATH),
        ("legacy_evidence_schema_sha256", LEGACY_EVIDENCE_SCHEMA_PATH),
        ("readonly_proof_schema_sha256", READONLY_PROOF_SCHEMA_PATH),
    )
    bundle_schemas: dict[str, bytes] = {}
    for field, path in schema_bindings:
        raw = read_regular_file_strict(
            path,
            field,
            limit=MAX_ARTIFACT_BYTES,
        )
        _compare(_hash_bytes(raw), release[field], field)
        if path != MANIFEST_SCHEMA_PATH:
            bundle_schemas[str(path.relative_to(ROOT))] = raw

    release_canonical_sha256 = _hash_bytes(canonical_json(release))
    for field in (
        "release_id",
        "attempt_id",
        "manifest_sha256",
        "endpoint_identity_sha256",
    ):
        expected = release[field]
        if consume[field] != expected or terminal[field] != expected:
            raise P0AcceptanceError(
                f"consume/terminal {field} binding mismatch"
            )
    _compare(
        release_canonical_sha256,
        consume["release_sha256"],
        "consume release canonical",
    )
    _compare(
        release_canonical_sha256,
        terminal["release_sha256"],
        "terminal release canonical",
    )
    for field in (
        "source_commit_sha",
        "runtime_image_digest",
        "runner_sha256",
        "audit_script_sha256",
        "trusted_keyring_sha256",
        "custody_identity_sha256",
        "custody_path_sha256",
    ):
        expected = (
            t1_keyring_sha256
            if field == "trusted_keyring_sha256"
            else release[field]
        )
        if consume[field] != expected:
            raise P0AcceptanceError(
                f"consume marker {field} binding mismatch"
            )
    consume_raw_sha256 = _hash_bytes(raw_files["consume_marker"])
    _compare(
        consume_raw_sha256,
        terminal["consume_marker_sha256"],
        "terminal exact consume bytes",
    )
    _compare(
        _hash_bytes(raw_files["child_invocation"]),
        terminal["child_invocation_sha256"],
        "terminal exact child invocation bytes",
    )
    _validate_child_invocation(child_invocation, release)
    if (
        terminal["terminal_state"] != "SUCCEEDED_P0_PASS"
        or terminal["p0_pass"] is not True
        or terminal["proof_verified"] is not True
    ):
        raise P0AcceptanceError(
            "terminal is not a verified SUCCEEDED_P0_PASS result"
        )
    if (
        terminal["write_probe_attempted"] is not False
        or terminal["database_mutations"] != 0
        or terminal["orders_sent"] != 0
        or terminal["positions_modified"] != 0
        or terminal["dispatch_changed"] is not False
        or terminal["replay_allowed"] is not False
        or terminal["p0_acceptance_authorized"] is not False
    ):
        raise P0AcceptanceError(
            "terminal violates zero-mutation/zero-trading invariants"
        )

    consumed_at = parse_datetime(
        consume["consumed_at"],
        "consume.consumed_at",
    )
    started_at = parse_datetime(
        terminal["started_at"],
        "terminal.started_at",
    )
    ended_at = parse_datetime(
        terminal["ended_at"],
        "terminal.ended_at",
    )
    if not not_before <= consumed_at < expires_at:
        raise P0AcceptanceError(
            "consume marker was not created inside the original release window"
        )
    if started_at != consumed_at:
        raise P0AcceptanceError(
            "terminal start must equal the release consumption time"
        )
    if not_before > started_at or started_at >= expires_at:
        raise P0AcceptanceError(
            "terminal start is outside the consumed release window"
        )
    if ended_at < started_at:
        raise P0AcceptanceError("terminal ended before it started")
    maximum_elapsed = timedelta(
        seconds=int(release["max_runtime_seconds"])
    ) + MAX_TERMINAL_OVERHEAD
    if ended_at - started_at > maximum_elapsed:
        raise P0AcceptanceError(
            "terminal duration exceeds signed runtime plus overhead"
        )
    evidence_generated_at = parse_datetime(
        evidence["generated_at"],
        "audit evidence generated_at",
    )
    proof_generated_at = parse_datetime(
        proof["generated_at"],
        "readonly proof generated_at",
    )
    if not (
        started_at
        <= evidence_generated_at
        <= proof_generated_at
        <= ended_at
    ):
        raise P0AcceptanceError(
            "evidence/proof historical generation times are inconsistent"
        )

    verified_release = VerifiedRelease(
        payload=release,
        release_sha256=release_canonical_sha256,
        keyring_sha256=t1_keyring_sha256,
        manifest=manifest,
        bundle_files=bundle_schemas,
    )
    artifact_paths = ArtifactPaths(
        audit_json=paths.audit_json,
        audit_csv=paths.audit_csv,
        audit_markdown=paths.audit_markdown,
        readonly_proof=paths.readonly_proof,
    )
    try:
        p0_pass, artifact_hashes = validate_completed_outputs(
            artifact_paths,
            verified_release,
            0,
        )
    except OneShotError as exc:
        raise P0AcceptanceError(
            f"T1 completed output validation failed: {exc}"
        ) from exc
    if p0_pass is not True:
        raise P0AcceptanceError("T1 evidence does not pass P0")
    initial_artifact_hashes = {
        name: _hash_bytes(raw_files[name])
        for name in (
            "audit_json",
            "audit_csv",
            "audit_markdown",
            "readonly_proof",
        )
    }
    if artifact_hashes != initial_artifact_hashes:
        raise P0AcceptanceError(
            "T1 artifact bytes changed during acceptance validation"
        )
    if artifact_hashes != terminal["artifact_sha256"]:
        raise P0AcceptanceError(
            "terminal artifact hashes do not match exact artifact bytes"
        )

    external_raw = read_regular_file_strict(
        paths.external_custody_identity,
        "external custody identity",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    external_identity = parse_json_bytes(
        external_raw,
        "external custody identity",
    )
    _validate_external_custody_identity(external_identity)
    raw_sha256 = {
        name: _hash_bytes(raw)
        for name, raw in raw_files.items()
    }
    return VerifiedP0Bundle(
        release=release,
        manifest=manifest,
        consume=consume,
        terminal=terminal,
        proof=proof,
        raw_sha256=raw_sha256,
        canonical_sha256={
            "t1_release": release_canonical_sha256,
            "manifest": manifest_canonical_sha256,
            "terminal_seal": _hash_bytes(canonical_json(terminal)),
        },
        artifact_sha256=artifact_hashes,
        bundle_index_sha256=_bundle_index_sha256(raw_files),
        t1_keyring_sha256=t1_keyring_sha256,
        t1_authority_public_key_bytes=t1_authority_public_key_bytes,
        external_custody_identity=external_identity,
        external_custody_identity_raw_sha256=_hash_bytes(external_raw),
        external_custody_identity_canonical_sha256=_hash_bytes(
            canonical_json(external_identity)
        ),
    )


def validate_acceptance_bindings(
    acceptance: dict[str, Any],
    verified: VerifiedP0Bundle,
) -> None:
    validate_json_schema(
        acceptance,
        ACCEPTANCE_SCHEMA_PATH,
        "P0 acceptance",
    )
    if acceptance["schema_version"] != ACCEPTANCE_SCHEMA_VERSION:
        raise P0AcceptanceError("P0 acceptance schema version is invalid")
    if acceptance["purpose"] != ACCEPTANCE_PURPOSE:
        raise P0AcceptanceError("P0 acceptance purpose is invalid")
    if acceptance["candidate_id"] != CANDIDATE_ID:
        raise P0AcceptanceError("P0 acceptance candidate is invalid")
    if ID_PATTERN.fullmatch(str(acceptance["acceptance_id"])) is None:
        raise P0AcceptanceError("P0 acceptance_id is invalid")
    expected_acceptance_id = acceptance_id_for_terminal(
        verified.raw_sha256["terminal_seal"]
    )
    if acceptance["acceptance_id"] != expected_acceptance_id:
        raise P0AcceptanceError(
            "P0 acceptance_id does not bind exact terminal bytes"
        )
    human_signature = str(acceptance["human_signature"]).strip()
    if not human_signature or human_signature.startswith("PENDING_"):
        raise P0AcceptanceError(
            "P0 acceptance human_signature is not final"
        )
    if not str(acceptance["reviewer_role"]).strip():
        raise P0AcceptanceError("P0 reviewer_role is empty")

    release = verified.release
    consume = verified.consume
    terminal = verified.terminal
    expected_scalars = {
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "source_commit_sha": release["source_commit_sha"],
        "runtime_image_digest": release["runtime_image_digest"],
        "t1_trusted_keyring_sha256": verified.t1_keyring_sha256,
        "t1_release_raw_sha256": verified.raw_sha256["t1_release"],
        "t1_release_canonical_sha256": (
            verified.canonical_sha256["t1_release"]
        ),
        "manifest_raw_sha256": verified.raw_sha256["manifest"],
        "manifest_canonical_sha256": (
            verified.canonical_sha256["manifest"]
        ),
        "consume_marker_raw_sha256": (
            verified.raw_sha256["consume_marker"]
        ),
        "terminal_seal_raw_sha256": (
            verified.raw_sha256["terminal_seal"]
        ),
        "terminal_seal_canonical_sha256": (
            verified.canonical_sha256["terminal_seal"]
        ),
        "child_invocation_raw_sha256": (
            verified.raw_sha256["child_invocation"]
        ),
        "bundle_index_sha256": verified.bundle_index_sha256,
        "snapshot_id": release["snapshot_id"],
        "endpoint_identity_sha256": release["endpoint_identity_sha256"],
        "questdb_build_sha256": release["questdb_build_sha256"],
        "consumed_at": consume["consumed_at"],
        "started_at": terminal["started_at"],
        "ended_at": terminal["ended_at"],
        "terminal_state": terminal["terminal_state"],
        "source_terminal_integrity_scope": (
            terminal["terminal_integrity_scope"]
        ),
    }
    for field, expected in expected_scalars.items():
        actual = acceptance[field]
        if field in {"consumed_at", "started_at", "ended_at"}:
            if parse_datetime(actual, field) != parse_datetime(
                expected,
                f"source {field}",
            ):
                raise P0AcceptanceError(
                    f"P0 acceptance {field} binding mismatch"
                )
        elif actual != expected:
            raise P0AcceptanceError(
                f"P0 acceptance {field} binding mismatch"
            )
    assert_audit_windows_equal(
        acceptance["audit_window"],
        release["audit_window"],
        "P0 acceptance",
    )
    if acceptance["artifact_sha256"] != verified.artifact_sha256:
        raise P0AcceptanceError(
            "P0 acceptance artifact hash binding mismatch"
        )

    identity = verified.external_custody_identity
    archive = acceptance["external_archive"]
    expected_archive = {
        "custody_id": identity["custody_id"],
        "asserted_archive_type": identity["asserted_archive_type"],
        "archive_locator_sha256": identity[
            "archive_locator_sha256"
        ],
        "custody_identity_raw_sha256": (
            verified.external_custody_identity_raw_sha256
        ),
        "custody_identity_canonical_sha256": (
            verified.external_custody_identity_canonical_sha256
        ),
        "archived_bundle_index_sha256": verified.bundle_index_sha256,
        "independent_custody_asserted": True,
        "immutability_asserted": True,
    }
    for field, expected in expected_archive.items():
        if archive[field] != expected:
            raise P0AcceptanceError(
                f"external archive {field} binding mismatch"
            )
    if (
        acceptance["external_archive_verification_state"]
        != "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED"
    ):
        raise P0AcceptanceError(
            "external archive verification state is invalid"
        )
    accepted_at = parse_datetime(
        acceptance["accepted_at"],
        "accepted_at",
    )
    archived_at = parse_datetime(
        archive["archived_at"],
        "external_archive.archived_at",
    )
    ended_at = parse_datetime(terminal["ended_at"], "terminal.ended_at")
    if not ended_at <= archived_at <= accepted_at:
        raise P0AcceptanceError(
            "archive/acceptance historical times are inconsistent"
        )


def _load_acceptance_keyring(
    path: Path,
    *,
    expected_sha256: str,
    key_id: str,
) -> tuple[dict[str, Any], Ed25519PublicKey, str]:
    _validate_sha256(
        expected_sha256,
        "independently pinned acceptance keyring",
    )
    keyring = load_json_strict(
        path,
        "P0 acceptance trusted keyring",
        private=True,
    )
    keyring_sha256 = _hash_bytes(canonical_json(keyring))
    _compare(
        keyring_sha256,
        expected_sha256,
        "independently pinned acceptance keyring",
    )
    public_key = _load_public_key(
        keyring,
        keyring_version=ACCEPTANCE_KEYRING_VERSION,
        key_id=key_id,
        required_purpose=ACCEPTANCE_KEY_PURPOSE,
    )
    return keyring, public_key, keyring_sha256


def verify_signed_acceptance(
    acceptance_path: Path,
    acceptance_keyring_path: Path,
    paths: P0BundlePaths,
    *,
    expected_acceptance_keyring_sha256: str,
    expected_t1_keyring_sha256: str,
) -> tuple[dict[str, Any], str]:
    acceptance = load_json_strict(
        acceptance_path,
        "signed P0 acceptance",
        private=True,
    )
    verified = verify_t1_bundle(
        paths,
        expected_t1_keyring_sha256=expected_t1_keyring_sha256,
    )
    validate_acceptance_bindings(acceptance, verified)
    _keyring, public_key, keyring_sha256 = _load_acceptance_keyring(
        acceptance_keyring_path,
        expected_sha256=expected_acceptance_keyring_sha256,
        key_id=str(acceptance["signer_key_id"]),
    )
    require_independent_acceptance_signer(
        verified.t1_authority_public_key_bytes,
        public_key,
    )
    _compare(
        keyring_sha256,
        acceptance["acceptance_keyring_sha256"],
        "P0 acceptance keyring",
    )
    _verify_ed25519(
        public_key,
        acceptance["signature"],
        canonical_json(unsigned_acceptance_payload(acceptance)),
        "P0 acceptance",
    )
    return acceptance, acceptance_sha256(acceptance)


def add_bundle_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--t1-release", type=Path, required=True)
    parser.add_argument("--t1-trusted-keyring", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--consume-marker", type=Path, required=True)
    parser.add_argument("--terminal-seal", type=Path, required=True)
    parser.add_argument("--child-invocation", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--audit-csv", type=Path, required=True)
    parser.add_argument("--audit-markdown", type=Path, required=True)
    parser.add_argument("--readonly-proof", type=Path, required=True)
    parser.add_argument(
        "--external-custody-identity",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-t1-keyring-sha256",
        required=True,
    )


def paths_from_args(args: argparse.Namespace) -> P0BundlePaths:
    return P0BundlePaths(
        t1_release=args.t1_release,
        t1_trusted_keyring=args.t1_trusted_keyring,
        manifest=args.manifest,
        consume_marker=args.consume_marker,
        terminal_seal=args.terminal_seal,
        child_invocation=args.child_invocation,
        audit_json=args.audit_json,
        audit_csv=args.audit_csv,
        audit_markdown=args.audit_markdown,
        readonly_proof=args.readonly_proof,
        external_custody_identity=args.external_custody_identity,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, required=True)
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
        acceptance, digest = verify_signed_acceptance(
            args.acceptance,
            args.acceptance_trusted_keyring,
            paths_from_args(args),
            expected_acceptance_keyring_sha256=(
                args.expected_acceptance_keyring_sha256
            ),
            expected_t1_keyring_sha256=(
                args.expected_t1_keyring_sha256
            ),
        )
    except (
        P0AcceptanceError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"P0 acceptance verification failed: {exc}", file=sys.stderr)
        return 2
    print("P0 acceptance verification: PASS")
    print(f"acceptance_id: {acceptance['acceptance_id']}")
    print(f"acceptance_sha256: {digest}")
    print("collection_authorized: false")
    print("runtime_activation_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
