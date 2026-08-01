#!/usr/bin/env python3
"""Verify query-v5 final-image provenance and stop at the final pre-DSN gate."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from c_fast_t1 import verify_query_v5_image_attestation as composition_verifier
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
SIGNER_PATH = VERIFIER_PATH.with_name("commodity_c_fast_t1_query_v5_sign.py")
LAUNCHER_PATH = VERIFIER_PATH.with_name("commodity_c_fast_t1_query_v5_launcher.py")
COMPOSITION_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v5-image-attestation-v1.schema.json"
)
PROVENANCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-query-v5-build-registry-provenance-v1.schema.json"
)
RELEASE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v5.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-query-v5-pre-dsn-gate-receipt-v1.schema.json"
)
RELEASE_KEYRING_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v5-trusted-keys-v1.schema.json"
)

COMPOSITION_VERSION = "commodity_c_fast_t1_query_v5_image_attestation_v1"
COMPOSITION_STATUS = (
    "QUERY_V5_BASE_AND_OVERLAY_OCI_COMPOSITION_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE"
)
PROVENANCE_VERSION = "commodity_c_fast_t1_query_v5_build_registry_provenance_v1"
PROVENANCE_PURPOSE = "c_fast_t1_query_v5_exact_final_image_build_registry_provenance"
PROVENANCE_KEYRING_VERSION = (
    "commodity_c_fast_t1_build_registry_provenance_trusted_keys_v1"
)
PROVENANCE_KEY_PURPOSE = "t1_build_registry_provenance_signer"
RELEASE_VERSION = "commodity_c_fast_t1_one_shot_query_release_v5"
RELEASE_PURPOSE = "c_fast_t1_exact_final_image_readonly_query_authority_v5"
RELEASE_KEY_PURPOSE = "t1_exact_readonly_query_v5_release_signer"
RECEIPT_VERSION = "commodity_c_fast_t1_query_v5_pre_dsn_gate_receipt_v1"
RECEIPT_STATUS = "RELEASE_V5_AND_EXACT_FINAL_IMAGE_PROVENANCE_VERIFIED_PRE_DSN_STOP"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_BUILD_DURATION = timedelta(hours=6)
MAX_PROVENANCE_DELAY = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_RELEASE_TTL = timedelta(minutes=10)
ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

PROVENANCE_FALSE_FIELDS = (
    "sensitive_material_present",
    "authority_granted",
    "readiness_authorized",
    "network_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "production_query_authorized",
    "write_probe_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "replacement_authorized",
    "production_authorized",
    "dynamic_selection_allowed",
    "automatic_promotion_authorized",
    "t1_executed",
    "production_queried",
    "dispatch_changed",
)
PROVENANCE_ZERO_FIELDS = (
    "database_mutations",
    "orders_sent",
    "positions_modified",
)
RELEASE_TRUE_FIELDS = (
    "t1_one_shot_child_launch_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "local_query_evidence_write_authorized",
)
RELEASE_FALSE_FIELDS = (
    "write_probe_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
    "questdb_recreate_authorized",
    "questdb_image_change_authorized",
    "network_mutation_authorized",
    "web_bridge_deployment_authorized",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "strategy_activation_authorized",
    "replacement_authorized",
    "production_authorized",
    "dynamic_selection_allowed",
    "automatic_promotion_authorized",
    "p0_acceptance_authorized",
    "replay_allowed",
)


class QueryV5ReleaseError(RuntimeError):
    """Expected fail-closed query-v5 release validation error."""


@dataclass(frozen=True)
class VerifiedProvenance:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    signer_public_key_sha256: str
    composition_raw_sha256: str
    composition_canonical_sha256: str


@dataclass(frozen=True)
class VerifiedRelease:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    signer_public_key_sha256: str


@dataclass(frozen=True)
class VerifiedFinalOci:
    raw_sha256: str
    manifest_digest: str
    config_digest: str
    layer_digests: tuple[str, ...]
    diff_ids: tuple[str, ...]


@dataclass(frozen=True)
class CompositionReplayInputs:
    query_v4_external_image_evidence_path: Path
    query_v4_source_bundle_path: Path
    query_v4_oci_layout_archive_path: Path
    query_v4_content_attestation_path: Path
    expected_query_v4_source_commit_sha: str
    external_image_evidence_path: Path
    source_bundle_path: Path
    final_oci_layout_path: Path


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unsigned_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def release_attempt_id(release_id: str) -> str:
    if ID_RE.fullmatch(release_id) is None:
        raise QueryV5ReleaseError("release_id is invalid")
    return f"attempt-{sha256_bytes(release_id.encode('utf-8'))}"


def _contains_pending(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("PENDING_")
    if isinstance(value, list):
        return any(_contains_pending(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_pending(item) for item in value.values())
    return False


def _read_bytes(
    path: Path,
    label: str,
    *,
    private: bool = False,
    limit: int = MAX_JSON_BYTES,
) -> bytes:
    try:
        return read_regular_file_strict(
            path,
            label,
            private=private,
            limit=limit,
        )
    except OneShotError as exc:
        raise QueryV5ReleaseError(str(exc)) from exc


def _load_json(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    raw = _read_bytes(path, label, private=private)
    try:
        return raw, parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise QueryV5ReleaseError(str(exc)) from exc


def _validate_schema(payload: dict[str, Any], path: Path, label: str) -> None:
    try:
        validate_json_schema(payload, path, label)
    except OneShotError as exc:
        raise QueryV5ReleaseError(str(exc)) from exc


def _same(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise QueryV5ReleaseError(f"{label} binding mismatch")


def _aware_now(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise QueryV5ReleaseError("now must include an explicit timezone")
    return value.astimezone(timezone.utc)


def _schema_sha256(path: Path, label: str) -> str:
    return sha256_bytes(_read_bytes(path, label))


def _source_sha256(path: Path, label: str) -> str:
    return sha256_bytes(_read_bytes(path, label, limit=16 * 1024 * 1024))


def load_verified_final_oci(path: Path) -> VerifiedFinalOci:
    """Reuse #227's bounded OCI parser and retain its exact content identity."""

    try:
        state = composition_verifier._load_oci_state(path, "query-v5 final")
    except composition_verifier.QueryV5ImageAttestationError as exc:
        raise QueryV5ReleaseError(
            f"query-v5 final OCI content replay failed: {exc}"
        ) from exc
    return VerifiedFinalOci(
        raw_sha256=sha256_bytes(state["archive_raw"]),
        manifest_digest=state["manifest_digest"],
        config_digest=state["config_digest"],
        layer_digests=tuple(state["layer_digests"]),
        diff_ids=tuple(state["diff_ids"]),
    )


def _composition_runtime_identity(
    composition: dict[str, Any],
) -> composition_verifier.QueryV5AttestationRuntimeIdentity:
    supplied = dict(composition["attestation_runtime"])
    try:
        schema_version = supplied.pop("schema_version")
        supplied.pop("runtime_identity_sha256")
        identity = composition_verifier.QueryV5AttestationRuntimeIdentity(**supplied)
    except (KeyError, TypeError, ValueError) as exc:
        raise QueryV5ReleaseError(
            "composition attestation runtime identity is invalid"
        ) from exc
    if schema_version != composition_verifier.RUNTIME_IDENTITY_VERSION:
        raise QueryV5ReleaseError("composition attestation runtime version is invalid")
    if composition_verifier._runtime_identity_payload(identity) != composition[
        "attestation_runtime"
    ]:
        raise QueryV5ReleaseError(
            "composition attestation runtime identity binding mismatch"
        )
    return identity


def _revalidate_composition_verifier_sources(
    identity: composition_verifier.QueryV5AttestationRuntimeIdentity,
) -> None:
    paths = {
        "verifier_sha256": Path(composition_verifier.__file__).resolve(),
        "query_v4_verifier_sha256": Path(
            composition_verifier.query_v4.__file__
        ).resolve(),
        "query_v4_delegate_sha256": Path(
            composition_verifier._delegate.__file__
        ).resolve(),
        "query_v5_validator_sha256": (
            ROOT / "scripts/c_fast_t1/validate_query_v5_runtime.py"
        ),
        "query_v4_validator_sha256": (
            ROOT / "scripts/c_fast_t1/validate_query_v4_runtime.py"
        ),
        "launcher_sha256": (
            ROOT
            / "scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py"
        ),
    }
    for field, path in paths.items():
        _same(
            _source_sha256(path, f"query-v5 replay {field}"),
            str(getattr(identity, field)),
            f"query-v5 replay {field}",
        )


def replay_composition_attestation(
    supplied: dict[str, Any],
    replay: CompositionReplayInputs,
    *,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    """Recompute #227 from its complete content inputs and exact-match it."""

    identity = _composition_runtime_identity(supplied)
    _revalidate_composition_verifier_sources(identity)
    active = composition_verifier._ACTIVE_RUNTIME_IDENTITY
    if active is None:
        composition_verifier.install_runtime_identity_observation(
            identity,
            lambda: _revalidate_composition_verifier_sources(identity),
        )
    elif active != identity:
        raise QueryV5ReleaseError(
            "query-v5 replay runtime identity differs from active observation"
        )
    try:
        composition_verifier._require_runtime_identity()
        replayed = composition_verifier.verify_query_v5_image_evidence(
            replay.query_v4_external_image_evidence_path,
            replay.query_v4_source_bundle_path,
            replay.query_v4_oci_layout_archive_path,
            replay.query_v4_content_attestation_path,
            replay.expected_query_v4_source_commit_sha,
            replay.external_image_evidence_path,
            replay.source_bundle_path,
            replay.final_oci_layout_path,
            expected_source_commit_sha,
        )
        composition_verifier._require_runtime_identity()
    except composition_verifier.QueryV5ImageAttestationError as exc:
        raise QueryV5ReleaseError(
            f"query-v5 composition exact replay failed: {exc}"
        ) from exc
    if canonical_json(replayed) != canonical_json(supplied):
        raise QueryV5ReleaseError(
            "supplied composition does not match exact #227 content replay"
        )
    return replayed


def _validate_keyring(
    keyring: dict[str, Any],
    *,
    schema_version: str,
    purpose: str,
    signer_key_id: str,
) -> tuple[Ed25519PublicKey, str, frozenset[str]]:
    if set(keyring) != {"schema_version", "keys"}:
        raise QueryV5ReleaseError("trusted keyring fields are invalid")
    if keyring.get("schema_version") != schema_version:
        raise QueryV5ReleaseError("trusted keyring generation is invalid")
    entries = keyring.get("keys")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise QueryV5ReleaseError("trusted keyring must contain 1 to 32 keys")
    matched: Ed25519PublicKey | None = None
    matched_hash = ""
    material_hashes: set[str] = set()
    key_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise QueryV5ReleaseError("trusted key entry fields are invalid")
        key_id = entry["key_id"]
        if not isinstance(key_id, str) or ID_RE.fullmatch(key_id) is None:
            raise QueryV5ReleaseError("trusted key_id is invalid")
        if key_id in key_ids or entry["purpose"] != purpose:
            raise QueryV5ReleaseError(
                "trusted key_id is duplicated or purpose is invalid"
            )
        key_ids.add(key_id)
        try:
            raw = base64.b64decode(entry["public_key_base64"], validate=True)
            if len(raw) != 32:
                raise ValueError
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise QueryV5ReleaseError("trusted Ed25519 key is invalid") from exc
        material_hash = sha256_bytes(raw)
        if material_hash in material_hashes:
            raise QueryV5ReleaseError("trusted key material is duplicated")
        material_hashes.add(material_hash)
        if key_id == signer_key_id:
            matched = key
            matched_hash = material_hash
    if matched is None:
        raise QueryV5ReleaseError("signer_key_id is not trusted")
    return matched, matched_hash, frozenset(material_hashes)


def _verify_signature(
    payload: dict[str, Any], public_key: Ed25519PublicKey, label: str
) -> None:
    try:
        signature = base64.b64decode(payload["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError
        public_key.verify(signature, canonical_json(unsigned_payload(payload)))
    except (InvalidSignature, TypeError, ValueError, binascii.Error) as exc:
        raise QueryV5ReleaseError(f"{label} signature is invalid") from exc


def _validate_composition(
    raw: bytes,
    payload: dict[str, Any],
    *,
    expected_source_commit_sha: str,
    expected_image_digest: str,
) -> tuple[str, str]:
    _validate_schema(payload, COMPOSITION_SCHEMA_PATH, "query-v5 composition")
    if _contains_pending(payload):
        raise QueryV5ReleaseError("composition contains PENDING_ placeholders")
    if (
        payload["schema_version"] != COMPOSITION_VERSION
        or payload["status"] != COMPOSITION_STATUS
    ):
        raise QueryV5ReleaseError("composition generation is invalid")
    _same(payload["source_commit_sha"], expected_source_commit_sha, "source commit")
    _same(payload["image_digest"], expected_image_digest, "final image digest")
    _same(
        payload["image_reference"].rsplit("@", 1)[-1],
        payload["image_digest"],
        "composition immutable image reference",
    )
    _same(
        sha256_bytes(canonical_json(payload["runtime_bundle_sha256"])),
        payload["runtime_bundle_index_sha256"],
        "composition runtime bundle index",
    )
    runtime = dict(payload["attestation_runtime"])
    runtime_identity = runtime.pop("runtime_identity_sha256")
    _same(
        sha256_bytes(canonical_json(runtime)),
        runtime_identity,
        "composition attestation runtime identity",
    )
    _same(
        payload["verifier_sha256"],
        runtime["verifier_sha256"],
        "composition verifier runtime binding",
    )
    _same(
        payload["attestation_schema_sha256"],
        _schema_sha256(COMPOSITION_SCHEMA_PATH, "composition schema"),
        "composition schema",
    )
    return sha256_bytes(raw), sha256_bytes(canonical_json(payload))


def _validate_provenance_permission_floor(payload: dict[str, Any]) -> None:
    for field in PROVENANCE_FALSE_FIELDS:
        if payload[field] is not False:
            raise QueryV5ReleaseError(f"forbidden provenance fact: {field}")
    for field in PROVENANCE_ZERO_FIELDS:
        if type(payload[field]) is not int or payload[field] != 0:
            raise QueryV5ReleaseError(f"non-zero provenance fact: {field}")


def validate_provenance_semantics(
    payload: dict[str, Any],
    composition_raw: bytes,
    composition: dict[str, Any],
    final_oci: VerifiedFinalOci,
    *,
    expected_source_commit_sha: str,
    expected_image_digest: str,
    now: datetime | None = None,
) -> tuple[str, str]:
    _validate_schema(payload, PROVENANCE_SCHEMA_PATH, "query-v5 provenance")
    if _contains_pending(payload):
        raise QueryV5ReleaseError("provenance contains PENDING_ placeholders")
    if (
        payload["schema_version"] != PROVENANCE_VERSION
        or payload["purpose"] != PROVENANCE_PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
    ):
        raise QueryV5ReleaseError("provenance identity is invalid")
    composition_hashes = _validate_composition(
        composition_raw,
        composition,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_image_digest=expected_image_digest,
    )
    _same(
        payload["composition_attestation_raw_sha256"],
        composition_hashes[0],
        "composition raw SHA256",
    )
    _same(
        payload["composition_attestation_canonical_sha256"],
        composition_hashes[1],
        "composition canonical SHA256",
    )
    direct = {
        "runtime_source_commit_sha": "source_commit_sha",
        "source_bundle_archive_sha256": "source_bundle_archive_sha256",
        "source_manifest_raw_sha256": "source_manifest_raw_sha256",
        "source_manifest_canonical_sha256": "source_manifest_canonical_sha256",
        "source_manifest_schema_sha256": "source_manifest_schema_sha256",
        "containerfile_sha256": "containerfile_sha256",
        "image_reference": "image_reference",
        "image_digest": "image_digest",
        "image_id": "image_id",
        "rootfs_layer_digests": "rootfs_layer_digests",
        "rootfs_diff_ids": "rootfs_diff_ids",
        "runtime_bundle_index_sha256": "runtime_bundle_index_sha256",
        "composition_attestation_schema_sha256": "attestation_schema_sha256",
    }
    for provenance_field, composition_field in direct.items():
        if payload[provenance_field] != composition[composition_field]:
            raise QueryV5ReleaseError(
                f"{provenance_field} composition binding mismatch"
            )
    runtime = composition["attestation_runtime"]
    _same(
        payload["composition_attestation_runtime_image_digest"],
        runtime["runtime_image_digest"],
        "composition runtime RepoDigest",
    )
    _same(
        payload["composition_attestation_runtime_identity_sha256"],
        runtime["runtime_identity_sha256"],
        "composition runtime identity",
    )
    _same(
        payload["final_oci_layout_archive_sha256"],
        final_oci.raw_sha256,
        "final OCI layout archive",
    )
    _same(
        payload["runtime_source_commit_sha"],
        expected_source_commit_sha,
        "source commit",
    )
    _same(
        payload["signing_tool_source_commit_sha"],
        expected_source_commit_sha,
        "signing tool source commit",
    )
    _same(payload["image_digest"], expected_image_digest, "final image digest")
    _same(
        payload["image_digest"],
        final_oci.manifest_digest,
        "final OCI manifest digest",
    )
    _same(payload["image_id"], final_oci.config_digest, "final OCI config digest")
    if tuple(payload["rootfs_layer_digests"]) != final_oci.layer_digests:
        raise QueryV5ReleaseError("final OCI layer digests binding mismatch")
    if tuple(payload["rootfs_diff_ids"]) != final_oci.diff_ids:
        raise QueryV5ReleaseError("final OCI diff IDs binding mismatch")
    _same(
        payload["image_reference"],
        f"{payload['registry']['repository']}@{expected_image_digest}",
        "registry RepoDigest reference",
    )
    _same(
        payload["registry"]["immutable_reference"],
        payload["image_reference"],
        "registry immutable reference",
    )
    _same(
        payload["registry"]["manifest_digest"],
        payload["image_digest"],
        "registry manifest digest",
    )
    build = payload["build"]
    _same(
        build["output_oci_layout_archive_sha256"],
        payload["final_oci_layout_archive_sha256"],
        "build OCI archive",
    )
    _same(build["output_image_digest"], payload["image_digest"], "build image digest")
    _same(build["output_image_id"], payload["image_id"], "build image ID")
    current_hashes = {
        "provenance_verifier_sha256": _source_sha256(
            VERIFIER_PATH, "query-v5 provenance verifier"
        ),
        "provenance_schema_sha256": _schema_sha256(
            PROVENANCE_SCHEMA_PATH, "query-v5 provenance schema"
        ),
        "release_schema_sha256": _schema_sha256(
            RELEASE_SCHEMA_PATH, "query-v5 release schema"
        ),
        "pre_dsn_receipt_schema_sha256": _schema_sha256(
            RECEIPT_SCHEMA_PATH, "query-v5 receipt schema"
        ),
        "signing_tool_source_sha256": _source_sha256(
            SIGNER_PATH, "query-v5 signing tool"
        ),
    }
    for field, expected in current_hashes.items():
        _same(payload[field], expected, field)
    if payload["signing_tool_source_path"] != (
        "scripts/commodity_c_fast_t1_query_v5_sign.py"
    ):
        raise QueryV5ReleaseError("signing tool path is invalid")
    _validate_provenance_permission_floor(payload)
    current = _aware_now(now)
    try:
        issued = parse_datetime(payload["issued_at"], "issued_at")
        build_started = parse_datetime(build["started_at"], "build.started_at")
        build_completed = parse_datetime(build["completed_at"], "build.completed_at")
        pushed = parse_datetime(payload["registry"]["pushed_at"], "registry.pushed_at")
        observed = parse_datetime(
            payload["registry"]["observed_at"], "registry.observed_at"
        )
        attested = parse_datetime(
            composition["evidence_captured_at"], "evidence_captured_at"
        )
    except OneShotError as exc:
        raise QueryV5ReleaseError(str(exc)) from exc
    if not build_started < build_completed:
        raise QueryV5ReleaseError("build time order is invalid")
    if build_completed - build_started > MAX_BUILD_DURATION:
        raise QueryV5ReleaseError("build duration exceeds six hours")
    if not build_completed <= attested <= issued:
        raise QueryV5ReleaseError("composition attestation time order is invalid")
    if not build_completed <= pushed <= observed <= issued:
        raise QueryV5ReleaseError("registry time order is invalid")
    if issued - max(attested, observed) > MAX_PROVENANCE_DELAY:
        raise QueryV5ReleaseError("provenance was signed too late")
    if issued > current + MAX_FUTURE_SKEW:
        raise QueryV5ReleaseError("provenance issued_at is in the future")
    return composition_hashes


def verify_provenance(
    provenance_path: Path,
    provenance_keyring_path: Path,
    composition_path: Path,
    final_oci_layout_path: Path,
    composition_replay: CompositionReplayInputs,
    *,
    expected_provenance_keyring_sha256: str,
    expected_source_commit_sha: str,
    expected_image_digest: str,
    now: datetime | None = None,
) -> tuple[VerifiedProvenance, frozenset[str]]:
    provenance_raw, payload = _load_json(provenance_path, "signed query-v5 provenance")
    _validate_schema(payload, PROVENANCE_SCHEMA_PATH, "signed query-v5 provenance")
    if _contains_pending(payload):
        raise QueryV5ReleaseError("provenance contains PENDING_ placeholders")
    _keyring_raw, keyring = _load_json(
        provenance_keyring_path, "query-v5 provenance keyring", private=True
    )
    composition_raw, composition = _load_json(
        composition_path, "query-v5 composition attestation"
    )
    if composition_replay.final_oci_layout_path != final_oci_layout_path:
        raise QueryV5ReleaseError("composition replay final OCI path binding mismatch")
    keyring_hash = sha256_bytes(canonical_json(keyring))
    _same(keyring_hash, expected_provenance_keyring_sha256, "pinned provenance keyring")
    _same(keyring_hash, payload["trusted_keyring_sha256"], "signed provenance keyring")
    public_key, signer_hash, materials = _validate_keyring(
        keyring,
        schema_version=PROVENANCE_KEYRING_VERSION,
        purpose=PROVENANCE_KEY_PURPOSE,
        signer_key_id=str(payload.get("signer_key_id") or ""),
    )
    _verify_signature(payload, public_key, "query-v5 provenance")
    replay_composition_attestation(
        composition,
        composition_replay,
        expected_source_commit_sha=expected_source_commit_sha,
    )
    final_oci = load_verified_final_oci(final_oci_layout_path)
    composition_hashes = validate_provenance_semantics(
        payload,
        composition_raw,
        composition,
        final_oci,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_image_digest=expected_image_digest,
        now=now,
    )
    return (
        VerifiedProvenance(
            payload=payload,
            raw_sha256=sha256_bytes(provenance_raw),
            canonical_sha256=sha256_bytes(canonical_json(payload)),
            signer_public_key_sha256=signer_hash,
            composition_raw_sha256=composition_hashes[0],
            composition_canonical_sha256=composition_hashes[1],
        ),
        materials,
    )


def _validate_release_permission_floor(payload: dict[str, Any]) -> None:
    for field in RELEASE_TRUE_FIELDS:
        if payload[field] is not True:
            raise QueryV5ReleaseError(f"required release authority missing: {field}")
    for field in RELEASE_FALSE_FIELDS:
        if payload[field] is not False:
            raise QueryV5ReleaseError(f"forbidden release authority: {field}")


def validate_release_semantics(
    payload: dict[str, Any],
    provenance: VerifiedProvenance,
    *,
    now: datetime | None = None,
) -> None:
    _validate_schema(payload, RELEASE_SCHEMA_PATH, "query-v5 release")
    if _contains_pending(payload):
        raise QueryV5ReleaseError("release contains PENDING_ placeholders")
    if (
        payload["schema_version"] != RELEASE_VERSION
        or payload["purpose"] != RELEASE_PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
    ):
        raise QueryV5ReleaseError("release-v5 identity is invalid")
    if payload["attempt_id"] != release_attempt_id(payload["release_id"]):
        raise QueryV5ReleaseError("attempt_id does not match release_id")
    bindings = {
        "provenance_raw_sha256": provenance.raw_sha256,
        "provenance_canonical_sha256": provenance.canonical_sha256,
        "provenance_signer_public_key_sha256": provenance.signer_public_key_sha256,
        "composition_attestation_raw_sha256": provenance.composition_raw_sha256,
        "composition_attestation_canonical_sha256": provenance.composition_canonical_sha256,
        "runtime_source_commit_sha": provenance.payload["runtime_source_commit_sha"],
        "runtime_image_reference": provenance.payload["image_reference"],
        "runtime_image_digest": provenance.payload["image_digest"],
        "runtime_image_id": provenance.payload["image_id"],
        "provenance_schema_sha256": _schema_sha256(
            PROVENANCE_SCHEMA_PATH, "query-v5 provenance schema"
        ),
        "composition_attestation_schema_sha256": _schema_sha256(
            COMPOSITION_SCHEMA_PATH, "query-v5 composition schema"
        ),
        "release_schema_sha256": _schema_sha256(
            RELEASE_SCHEMA_PATH, "query-v5 release schema"
        ),
        "pre_dsn_receipt_schema_sha256": _schema_sha256(
            RECEIPT_SCHEMA_PATH, "query-v5 receipt schema"
        ),
        "pre_dsn_gate_source_sha256": _source_sha256(
            VERIFIER_PATH, "query-v5 pre-DSN gate"
        ),
        "query_v5_code_only_launcher_sha256": _source_sha256(
            LAUNCHER_PATH, "query-v5 code-only launcher"
        ),
    }
    for field, expected in bindings.items():
        _same(str(payload[field]), str(expected), field)
    _validate_release_permission_floor(payload)
    if payload["maximum_release_ttl_seconds"] != 600:
        raise QueryV5ReleaseError("maximum release TTL is invalid")
    current = _aware_now(now)
    try:
        issued = parse_datetime(payload["issued_at"], "issued_at")
        not_before = parse_datetime(payload["not_before"], "not_before")
        expires = parse_datetime(payload["expires_at"], "expires_at")
        provenance_issued = parse_datetime(
            provenance.payload["issued_at"], "provenance.issued_at"
        )
    except OneShotError as exc:
        raise QueryV5ReleaseError(str(exc)) from exc
    if not issued <= not_before <= current < expires:
        raise QueryV5ReleaseError("release time window is inactive")
    if issued < provenance_issued:
        raise QueryV5ReleaseError("release predates its signed provenance")
    if expires - issued > MAX_RELEASE_TTL:
        raise QueryV5ReleaseError("release TTL exceeds ten minutes")
    margin = timedelta(seconds=payload["minimum_launch_margin_seconds"])
    if current + margin >= expires:
        raise QueryV5ReleaseError("release launch margin is exhausted")


def verify_release(
    release_path: Path,
    release_keyring_path: Path,
    provenance: VerifiedProvenance,
    provenance_key_materials: frozenset[str],
    *,
    expected_release_keyring_sha256: str,
    now: datetime | None = None,
) -> VerifiedRelease:
    release_raw, payload = _load_json(release_path, "signed query-v5 release")
    _validate_schema(payload, RELEASE_SCHEMA_PATH, "signed query-v5 release")
    if _contains_pending(payload):
        raise QueryV5ReleaseError("release contains PENDING_ placeholders")
    _keyring_raw, keyring = _load_json(
        release_keyring_path, "query-v5 release keyring", private=True
    )
    _validate_schema(keyring, RELEASE_KEYRING_SCHEMA_PATH, "query-v5 release keyring")
    keyring_hash = sha256_bytes(canonical_json(keyring))
    _same(keyring_hash, expected_release_keyring_sha256, "pinned release keyring")
    _same(keyring_hash, payload["trusted_keyring_sha256"], "signed release keyring")
    public_key, signer_hash, release_materials = _validate_keyring(
        keyring,
        schema_version="commodity_c_fast_t1_query_v5_trusted_keys_v1",
        purpose=RELEASE_KEY_PURPOSE,
        signer_key_id=str(payload.get("signer_key_id") or ""),
    )
    if provenance_key_materials & release_materials:
        raise QueryV5ReleaseError("provenance and release key domains overlap")
    _verify_signature(payload, public_key, "query-v5 release")
    validate_release_semantics(payload, provenance, now=now)
    return VerifiedRelease(
        payload=payload,
        raw_sha256=sha256_bytes(release_raw),
        canonical_sha256=sha256_bytes(canonical_json(payload)),
        signer_public_key_sha256=signer_hash,
    )


def build_pre_dsn_receipt(
    release: VerifiedRelease,
    provenance: VerifiedProvenance,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": RECEIPT_VERSION,
        "status": RECEIPT_STATUS,
        "candidate_id": CANDIDATE_ID,
        "release_id": release.payload["release_id"],
        "attempt_id": release.payload["attempt_id"],
        "verified_at": _aware_now(now).isoformat(),
        "release_raw_sha256": release.raw_sha256,
        "release_canonical_sha256": release.canonical_sha256,
        "release_signer_public_key_sha256": release.signer_public_key_sha256,
        "provenance_raw_sha256": provenance.raw_sha256,
        "provenance_canonical_sha256": provenance.canonical_sha256,
        "provenance_signer_public_key_sha256": provenance.signer_public_key_sha256,
        "composition_attestation_raw_sha256": provenance.composition_raw_sha256,
        "composition_attestation_canonical_sha256": provenance.composition_canonical_sha256,
        "runtime_source_commit_sha": provenance.payload["runtime_source_commit_sha"],
        "runtime_image_reference": provenance.payload["image_reference"],
        "runtime_image_digest": provenance.payload["image_digest"],
        "runtime_image_id": provenance.payload["image_id"],
        "final_oci_layout_archive_sha256": provenance.payload[
            "final_oci_layout_archive_sha256"
        ],
        "registry_identity_sha256": provenance.payload["registry"][
            "registry_identity_sha256"
        ],
        "registry_push_receipt_sha256": provenance.payload["registry"][
            "push_receipt_sha256"
        ],
        "composition_attestation_runtime_image_digest": provenance.payload[
            "composition_attestation_runtime_image_digest"
        ],
        "composition_attestation_runtime_identity_sha256": provenance.payload[
            "composition_attestation_runtime_identity_sha256"
        ],
        "composition_attestation_runtime_repo_digest_verified": True,
        "exact_registry_repo_digest_bound": True,
        "key_domains_separated": True,
        "release_consumed": False,
        "query_child_implemented": False,
        "dsn_read": False,
        "network_attempted": False,
        "production_query_attempted": False,
        "production_query_completed": False,
        "receipt_is_authority": False,
        "authority_granted": False,
        "runtime_activation_authorized": False,
        "database_mutation_authorized": False,
        "collection_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }
    _validate_schema(payload, RECEIPT_SCHEMA_PATH, "query-v5 pre-DSN receipt")
    return payload


def write_json_create_only(path: Path, payload: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise QueryV5ReleaseError("output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        raw = canonical_json(payload) + b"\n"
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    directory = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_pre_dsn_gate(
    *,
    provenance_path: Path,
    provenance_keyring_path: Path,
    composition_path: Path,
    final_oci_layout_path: Path,
    composition_replay: CompositionReplayInputs,
    release_path: Path,
    release_keyring_path: Path,
    expected_provenance_keyring_sha256: str,
    expected_release_keyring_sha256: str,
    expected_source_commit_sha: str,
    expected_image_digest: str,
    output_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    verified_provenance, provenance_materials = verify_provenance(
        provenance_path,
        provenance_keyring_path,
        composition_path,
        final_oci_layout_path,
        composition_replay,
        expected_provenance_keyring_sha256=expected_provenance_keyring_sha256,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_image_digest=expected_image_digest,
        now=now,
    )
    verified_release = verify_release(
        release_path,
        release_keyring_path,
        verified_provenance,
        provenance_materials,
        expected_release_keyring_sha256=expected_release_keyring_sha256,
        now=now,
    )
    final_now = _aware_now(now)
    validate_release_semantics(
        verified_release.payload,
        verified_provenance,
        now=final_now,
    )
    receipt = build_pre_dsn_receipt(
        verified_release,
        verified_provenance,
        now=final_now,
    )
    write_json_create_only(output_path, receipt)
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--signed-provenance", dest="provenance", type=Path, required=True
    )
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--composition-attestation", type=Path, required=True)
    parser.add_argument("--final-oci-layout", type=Path, required=True)
    parser.add_argument(
        "--query-v4-external-image-evidence", type=Path, required=True
    )
    parser.add_argument("--query-v4-source-bundle-archive", type=Path, required=True)
    parser.add_argument("--query-v4-oci-layout-archive", type=Path, required=True)
    parser.add_argument("--query-v4-content-attestation", type=Path, required=True)
    parser.add_argument("--expected-query-v4-source-commit-sha", required=True)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--source-bundle-archive", type=Path, required=True)
    parser.add_argument("--signed-release", dest="release", type=Path, required=True)
    parser.add_argument("--release-keyring", type=Path, required=True)
    parser.add_argument("--expected-provenance-keyring-sha256", required=True)
    parser.add_argument("--expected-release-keyring-sha256", required=True)
    parser.add_argument("--expected-source-commit-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        receipt = run_pre_dsn_gate(
            provenance_path=args.provenance,
            provenance_keyring_path=args.provenance_keyring,
            composition_path=args.composition_attestation,
            final_oci_layout_path=args.final_oci_layout,
            composition_replay=CompositionReplayInputs(
                query_v4_external_image_evidence_path=(
                    args.query_v4_external_image_evidence
                ),
                query_v4_source_bundle_path=args.query_v4_source_bundle_archive,
                query_v4_oci_layout_archive_path=args.query_v4_oci_layout_archive,
                query_v4_content_attestation_path=(
                    args.query_v4_content_attestation
                ),
                expected_query_v4_source_commit_sha=(
                    args.expected_query_v4_source_commit_sha
                ),
                external_image_evidence_path=args.external_image_evidence,
                source_bundle_path=args.source_bundle_archive,
                final_oci_layout_path=args.final_oci_layout,
            ),
            release_path=args.release,
            release_keyring_path=args.release_keyring,
            expected_provenance_keyring_sha256=(
                args.expected_provenance_keyring_sha256
            ),
            expected_release_keyring_sha256=args.expected_release_keyring_sha256,
            expected_source_commit_sha=args.expected_source_commit_sha,
            expected_image_digest=args.expected_image_digest,
            output_path=args.output,
        )
    except (OSError, QueryV5ReleaseError, ValueError) as exc:
        print(f"query-v5 pre-DSN gate failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={receipt['status']}")
    print("release_consumed=false")
    print("query_child_implemented=false")
    print("dsn_read=false")
    print("network_attempted=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
