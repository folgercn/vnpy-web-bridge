#!/usr/bin/env python3
"""Derive a non-authoritative C_FAST T1 release-v2 readiness packet."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import stat
import sys
from typing import Any

from c_fast_t1.verify_image_attestation import (
    ImageAttestationError,
    verify_image_evidence,
)
from commodity_c_fast_readonly_deployment_outcome import (
    DeploymentOutcomeError,
    OutcomeSourcePaths,
    PostEvidencePaths,
    add_post_arguments,
    add_source_arguments,
    post_paths_from_args,
    source_paths_from_args,
    verify_signed_outcome,
)
from commodity_c_fast_t1_build_registry_provenance import (
    BuildRegistryProvenanceError,
    load_excluded_authority_key_facts,
    verify_provenance,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    custody_path_sha256,
    open_custody_guard,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    read_root_owned_deployment_pin,
    validate_json_schema,
    write_json_create_only_at,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-readiness-v2.schema.json"
)
PIN_ROOT = Path("/run/c-fast-t1-readiness-v2-pins")
PIN_PATHS = {
    "provenance_keyring_sha256": PIN_ROOT / "provenance-keyring.sha256",
    "t1_authority_keyring_sha256": PIN_ROOT / "t1-authority-keyring.sha256",
    "l3_authority_keyring_sha256": PIN_ROOT / "l3-authority-keyring.sha256",
    "outcome_keyring_sha256": PIN_ROOT / "outcome-keyring.sha256",
    "packet_custody_path": PIN_ROOT / "packet-custody.path",
}

SCHEMA_VERSION = "commodity_c_fast_t1_readiness_v2"
STATUS = "READY_FOR_T1_RELEASE_V2_HUMAN_SIGNATURE_ONLY"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
PACKET_TTL = timedelta(minutes=15)
MAX_OUTCOME_AGE = timedelta(hours=1)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_OCI_BYTES = 256 * 1024 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

FALSE_AUTHORITY_FIELDS = (
    "sensitive_material_present",
    "packet_is_authority",
    "receipt_is_authority",
    "outcome_is_authority",
    "authority_granted",
    "readiness_authorized",
    "ready_for_human_t1_release_signature_only",
    "replay_allowed",
    "network_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "production_query_authorized",
    "write_probe_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
    "questdb_recreate_authorized",
    "questdb_image_change_authorized",
    "writer_identity_mutation_authorized",
    "writer_secret_mutation_authorized",
    "network_mutation_authorized",
    "unscoped_deployment_mutation_authorized",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
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
    "t1_executed",
    "production_queried",
    "readonly_query_authorized",
    "web_bridge_deployment_authorized",
    "dispatch_changed",
)
ZERO_FACT_FIELDS = (
    "production_queries_executed",
    "readonly_queries_executed",
    "write_probes_attempted",
    "database_mutations",
    "web_bridge_rpc_calls",
    "orders_sent",
    "positions_modified",
)


class ReadinessV2Error(RuntimeError):
    """Expected fail-closed readiness derivation error."""


@dataclass(frozen=True)
class ReadinessPins:
    provenance_keyring_sha256: str
    t1_authority_keyring_sha256: str
    l3_authority_keyring_sha256: str
    outcome_keyring_sha256: str
    packet_custody_path: Path


@dataclass(frozen=True)
class ReadinessInputs:
    external_image_evidence: Path
    oci_layout_archive: Path
    source_root: Path
    content_attestation: Path
    provenance: Path
    provenance_keyring: Path
    t1_keyring: Path
    outcome: Path
    outcome_keyring: Path
    outcome_source: OutcomeSourcePaths
    post_evidence: PostEvidencePaths
    t1_runtime_source_commit_sha: str
    t1_runtime_image_digest: str
    l3_contract_source_commit_sha: str
    outcome_contract_source_commit_assertion: str
    questdb_image_digest: str


@dataclass(frozen=True)
class VerifiedReadinessPacket:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pin_root_path_sha256() -> str:
    return _hash_bytes(str(PIN_ROOT).encode("utf-8"))


def _require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReadinessV2Error(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _read(path: Path, label: str, *, limit: int = MAX_JSON_BYTES) -> bytes:
    try:
        return read_regular_file_strict(path, label, limit=limit)
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc


def _load_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    raw = _read(path, label)
    try:
        return raw, parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc


def _validate_pins(pins: ReadinessPins) -> None:
    for field in (
        "provenance_keyring_sha256",
        "t1_authority_keyring_sha256",
        "l3_authority_keyring_sha256",
        "outcome_keyring_sha256",
    ):
        if SHA256_PATTERN.fullmatch(str(getattr(pins, field))) is None:
            raise ReadinessV2Error(f"{field} must be a lowercase SHA256")
    if not pins.packet_custody_path.is_absolute():
        raise ReadinessV2Error("packet custody path must be absolute")


def _validate_expected_namespaces(inputs: ReadinessInputs) -> None:
    for field in (
        "t1_runtime_source_commit_sha",
        "l3_contract_source_commit_sha",
        "outcome_contract_source_commit_assertion",
    ):
        if COMMIT_PATTERN.fullmatch(str(getattr(inputs, field))) is None:
            raise ReadinessV2Error(f"{field} is invalid")
    for field in (
        "t1_runtime_image_digest",
        "questdb_image_digest",
    ):
        if OCI_DIGEST_PATTERN.fullmatch(str(getattr(inputs, field))) is None:
            raise ReadinessV2Error(f"{field} is invalid")


def _validate_outcome_freshness_for_packet_window(
    generated_at: datetime,
    expires_at: datetime,
    outcome_issued_at: datetime,
    deployment_ended_at: datetime,
) -> None:
    if (
        not deployment_ended_at <= outcome_issued_at <= generated_at
        or expires_at - outcome_issued_at > MAX_OUTCOME_AGE
        or expires_at - deployment_ended_at > MAX_OUTCOME_AGE
    ):
        raise ReadinessV2Error(
            "deployment outcome is stale or has an invalid time relation"
        )


def _read_production_pins() -> ReadinessPins:
    try:
        info = PIN_ROOT.lstat()
    except OSError as exc:
        raise ReadinessV2Error("readiness pin root is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ReadinessV2Error(
            "readiness pin root must be root-owned, non-symlink and not writable"
        )
    try:
        values = {
            field: read_root_owned_deployment_pin(path, field)
            for field, path in PIN_PATHS.items()
        }
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    pins = ReadinessPins(
        provenance_keyring_sha256=values["provenance_keyring_sha256"],
        t1_authority_keyring_sha256=values[
            "t1_authority_keyring_sha256"
        ],
        l3_authority_keyring_sha256=values[
            "l3_authority_keyring_sha256"
        ],
        outcome_keyring_sha256=values["outcome_keyring_sha256"],
        packet_custody_path=Path(values["packet_custody_path"]),
    )
    _validate_pins(pins)
    return pins


def _reload_and_match_active_pins(
    derived_pins: ReadinessPins,
) -> tuple[ReadinessPins, Path]:
    active_pins = _read_production_pins()
    _validate_pins(active_pins)
    try:
        derived_custody = derived_pins.packet_custody_path.resolve(
            strict=True
        )
        active_custody = active_pins.packet_custody_path.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV2Error("packet custody cannot be resolved") from exc
    if (
        derived_pins.provenance_keyring_sha256
        != active_pins.provenance_keyring_sha256
        or derived_pins.t1_authority_keyring_sha256
        != active_pins.t1_authority_keyring_sha256
        or derived_pins.l3_authority_keyring_sha256
        != active_pins.l3_authority_keyring_sha256
        or derived_pins.outcome_keyring_sha256
        != active_pins.outcome_keyring_sha256
        or derived_custody != active_custody
    ):
        raise ReadinessV2Error(
            "active readiness pins changed before protected use"
        )
    return active_pins, active_custody


def _validate_packet(packet: dict[str, Any]) -> None:
    try:
        validate_json_schema(packet, SCHEMA_PATH, "T1 readiness v2 packet")
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    if packet["status"] != STATUS or packet["blocking_reasons"] != []:
        raise ReadinessV2Error("readiness status or blocker derivation is invalid")
    if packet["ready_for_t1_release_v2_human_signature_only"] is not True:
        raise ReadinessV2Error("human-signature-only readiness fact is missing")
    if any(packet[field] is not False for field in FALSE_AUTHORITY_FIELDS):
        raise ReadinessV2Error("readiness packet attempts to grant authority")
    if any(
        type(packet[field]) is not int or packet[field] != 0
        for field in ZERO_FACT_FIELDS
    ):
        raise ReadinessV2Error("readiness packet contains non-zero side effects")
    try:
        generated_at = parse_datetime(packet["generated_at"], "generated_at")
        expires_at = parse_datetime(packet["expires_at"], "expires_at")
        outcome_issued_at = parse_datetime(
            packet["readonly_deployment_outcome"]["outcome_issued_at"],
            "readonly_deployment_outcome.outcome_issued_at",
        )
        deployment_ended_at = parse_datetime(
            packet["readonly_deployment_outcome"]["deployment_ended_at"],
            "readonly_deployment_outcome.deployment_ended_at",
        )
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    if expires_at - generated_at != PACKET_TTL:
        raise ReadinessV2Error("readiness packet TTL is not exactly 15 minutes")
    _validate_outcome_freshness_for_packet_window(
        generated_at,
        expires_at,
        outcome_issued_at,
        deployment_ended_at,
    )
    identity = _packet_identity(packet)
    expected_id = "readiness-v2-" + _hash_bytes(canonical_json(identity))
    if packet["packet_id"] != expected_id:
        raise ReadinessV2Error("readiness packet ID does not bind exact facts")
    if (
        packet["verifier_sha256"]
        != _hash_bytes(_read(VERIFIER_PATH, "readiness verifier"))
        or packet["schema_sha256"]
        != _hash_bytes(_read(SCHEMA_PATH, "readiness schema"))
        or packet["pin_root_path_sha256"] != pin_root_path_sha256()
    ):
        raise ReadinessV2Error("readiness runtime binding is invalid")


def _packet_identity(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        field: packet[field]
        for field in (
            "generated_at",
            "expires_at",
            "verifier_sha256",
            "schema_sha256",
            "pin_root_path_sha256",
            "packet_custody_path_sha256",
            "source_namespaces",
            "digest_namespaces",
            "t1_runtime",
            "build_registry_provenance",
            "readonly_deployment_outcome",
        )
    }


def derive_readiness_packet(
    inputs: ReadinessInputs,
    pins: ReadinessPins,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_pins(pins)
    _validate_expected_namespaces(inputs)
    generated_at = _require_aware(
        datetime.now(timezone.utc) if now is None else now,
        "now",
    )

    content_raw, content = _load_json(
        inputs.content_attestation,
        "exact T1 content attestation",
    )
    external_raw = _read(
        inputs.external_image_evidence,
        "external T1 image evidence",
    )
    oci_raw = _read(
        inputs.oci_layout_archive,
        "T1 OCI layout archive",
        limit=MAX_OCI_BYTES,
    )
    try:
        regenerated_content = verify_image_evidence(
            inputs.external_image_evidence,
            inputs.oci_layout_archive,
            inputs.source_root,
            inputs.t1_runtime_source_commit_sha,
        )
    except ImageAttestationError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    if regenerated_content != content:
        raise ReadinessV2Error(
            "supplied content attestation is not the exact regenerated report"
        )
    if content.get("image_digest") != inputs.t1_runtime_image_digest:
        raise ReadinessV2Error("T1 runtime image digest namespace mismatch")
    if content.get("source_commit_sha") != inputs.t1_runtime_source_commit_sha:
        raise ReadinessV2Error("T1 runtime source namespace mismatch")
    if content.get("external_evidence_sha256") != _hash_bytes(external_raw):
        raise ReadinessV2Error("external image evidence raw hash mismatch")
    if content.get("oci_layout_archive_sha256") != _hash_bytes(oci_raw):
        raise ReadinessV2Error("OCI layout archive raw hash mismatch")

    try:
        excluded_key_hashes, excluded_keyring_hashes = (
            load_excluded_authority_key_facts(
                t1_keyring_path=inputs.t1_keyring,
                expected_t1_keyring_sha256=(
                    pins.t1_authority_keyring_sha256
                ),
                l3_keyring_path=inputs.outcome_source.release_keyring,
                expected_l3_keyring_sha256=(
                    pins.l3_authority_keyring_sha256
                ),
            )
        )
        provenance_receipt = verify_provenance(
            inputs.provenance,
            inputs.provenance_keyring,
            inputs.content_attestation,
            expected_trusted_keyring_sha256=(
                pins.provenance_keyring_sha256
            ),
            expected_runtime_source_commit_sha=(
                inputs.t1_runtime_source_commit_sha
            ),
            expected_image_digest=inputs.t1_runtime_image_digest,
            excluded_authority_key_hashes=excluded_key_hashes,
            excluded_authority_keyring_sha256s=excluded_keyring_hashes,
            now=generated_at,
        )
    except BuildRegistryProvenanceError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    content_raw_sha256 = _hash_bytes(content_raw)
    if (
        provenance_receipt["content_attestation_raw_sha256"]
        != content_raw_sha256
        or provenance_receipt["runtime_source_commit_sha"]
        != inputs.t1_runtime_source_commit_sha
        or provenance_receipt["image_digest"]
        != inputs.t1_runtime_image_digest
    ):
        raise ReadinessV2Error(
            "provenance receipt does not bind the exact T1 runtime report"
        )

    try:
        outcome = verify_signed_outcome(
            inputs.outcome,
            inputs.outcome_keyring,
            inputs.t1_keyring,
            inputs.outcome_source,
            inputs.post_evidence,
            expected_outcome_keyring_sha256=(
                pins.outcome_keyring_sha256
            ),
            expected_release_keyring_sha256=(
                pins.l3_authority_keyring_sha256
            ),
            expected_t1_keyring_sha256=(
                pins.t1_authority_keyring_sha256
            ),
            expected_outcome_source_commit_sha=(
                inputs.outcome_contract_source_commit_assertion
            ),
            expected_release_source_commit_sha=(
                inputs.l3_contract_source_commit_sha
            ),
            expected_questdb_image_digest=inputs.questdb_image_digest,
            now=generated_at,
        )
    except DeploymentOutcomeError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    outcome_payload = outcome.payload
    provenance_signer_hash = provenance_receipt[
        "signer_public_key_sha256"
    ]
    outcome_signer_hash = outcome.outcome_signer_public_key_sha256
    if (
        SHA256_PATTERN.fullmatch(str(provenance_signer_hash)) is None
        or SHA256_PATTERN.fullmatch(str(outcome_signer_hash)) is None
        or provenance_signer_hash == outcome_signer_hash
    ):
        raise ReadinessV2Error(
            "provenance and outcome witnesses require distinct signer keys"
        )
    if (
        outcome_payload["questdb_image_digest"]
        != inputs.questdb_image_digest
        or outcome_payload["release_source_commit_sha"]
        != inputs.l3_contract_source_commit_sha
        or outcome_payload["outcome_contract_source_commit_assertion"]
        != inputs.outcome_contract_source_commit_assertion
    ):
        raise ReadinessV2Error("deployment outcome namespace mismatch")
    try:
        outcome_issued_at = parse_datetime(
            outcome_payload["issued_at"],
            "outcome.issued_at",
        )
        deployment_ended_at = parse_datetime(
            outcome_payload["deployment_ended_at"],
            "outcome.deployment_ended_at",
        )
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    expires_at = generated_at + PACKET_TTL
    _validate_outcome_freshness_for_packet_window(
        generated_at,
        expires_at,
        outcome_issued_at,
        deployment_ended_at,
    )

    verifier_sha256 = _hash_bytes(_read(VERIFIER_PATH, "readiness verifier"))
    schema_sha256 = _hash_bytes(_read(SCHEMA_PATH, "readiness schema"))
    runtime_bundle_index = _hash_bytes(
        canonical_json(content["runtime_bundle_sha256"])
    )
    source_namespaces = {
        "t1_runtime_source_commit_sha": (
            inputs.t1_runtime_source_commit_sha
        ),
        "l3_contract_source_commit_sha": (
            inputs.l3_contract_source_commit_sha
        ),
        "outcome_contract_source_commit_assertion": (
            inputs.outcome_contract_source_commit_assertion
        ),
    }
    digest_namespaces = {
        "t1_runtime_image_digest": inputs.t1_runtime_image_digest,
        "questdb_image_digest": inputs.questdb_image_digest,
    }
    t1_runtime = {
        "content_attestation_raw_sha256": content_raw_sha256,
        "content_attestation_canonical_sha256": _hash_bytes(
            canonical_json(content)
        ),
        "external_image_evidence_raw_sha256": _hash_bytes(external_raw),
        "oci_layout_archive_raw_sha256": _hash_bytes(oci_raw),
        "image_reference": content["image_reference"],
        "image_id": content["image_id"],
        "runtime_bundle_index_sha256": runtime_bundle_index,
        "content_verifier_sha256": content["verifier_sha256"],
    }
    build_registry = {
        "signed_provenance_raw_sha256": provenance_receipt[
            "signed_provenance_raw_sha256"
        ],
        "signed_provenance_canonical_sha256": provenance_receipt[
            "signed_provenance_canonical_sha256"
        ],
        "provenance_keyring_sha256": pins.provenance_keyring_sha256,
        "t1_authority_keyring_sha256": (
            pins.t1_authority_keyring_sha256
        ),
        "l3_authority_keyring_sha256": (
            pins.l3_authority_keyring_sha256
        ),
        "signer_key_id": provenance_receipt["signer_key_id"],
        "signer_public_key_sha256": provenance_signer_hash,
        "signed_build_assertion_verified": True,
        "signed_registry_assertion_verified": True,
        "external_facts_independently_reverified": False,
    }
    deployment = {
        "signed_outcome_raw_sha256": outcome.raw_sha256,
        "signed_outcome_canonical_sha256": outcome.canonical_sha256,
        "outcome_keyring_sha256": pins.outcome_keyring_sha256,
        "signer_key_id": outcome_payload["signer_key_id"],
        "signer_public_key_sha256": outcome_signer_hash,
        "release_raw_sha256": outcome.source.release_raw_sha256,
        "release_canonical_sha256": (
            outcome.source.release_canonical_sha256
        ),
        "consume_marker_raw_sha256": outcome.source.consume_raw_sha256,
        "receipt_raw_sha256": outcome.source.receipt_raw_sha256,
        "pre_evidence_bundle_index_sha256": (
            outcome.source.pre_evidence_bundle_index_sha256
        ),
        "post_evidence_bundle_index_sha256": (
            outcome.post.bundle_index_sha256
        ),
        "release_id": outcome_payload["release_id"],
        "attempt_id": outcome_payload["attempt_id"],
        "questdb_target_identity_sha256": outcome_payload[
            "questdb_target_identity_sha256"
        ],
        "outcome_issued_at": outcome_payload["issued_at"],
        "deployment_ended_at": outcome_payload["deployment_ended_at"],
        "deployment_executed": True,
        "restart_count": 1,
    }
    packet_custody_sha256 = custody_path_sha256(pins.packet_custody_path)
    identity = {
        "generated_at": generated_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "verifier_sha256": verifier_sha256,
        "schema_sha256": schema_sha256,
        "pin_root_path_sha256": pin_root_path_sha256(),
        "packet_custody_path_sha256": packet_custody_sha256,
        "source_namespaces": source_namespaces,
        "digest_namespaces": digest_namespaces,
        "t1_runtime": t1_runtime,
        "build_registry_provenance": build_registry,
        "readonly_deployment_outcome": deployment,
    }
    packet_id = "readiness-v2-" + _hash_bytes(canonical_json(identity))
    packet: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "candidate_id": CANDIDATE_ID,
        "issue_number": 114,
        "packet_id": packet_id,
        **identity,
        "requirements": {
            "requires_t1_release_v2": True,
            "t1_release_v1_accepted": False,
            "raw_readiness_packet_binding_required": True,
            "human_signature_required": True,
            "one_shot_runtime_required": True,
        },
        "blocking_reasons": [],
        "sensitive_material_present": False,
        "packet_is_authority": False,
        "receipt_is_authority": False,
        "outcome_is_authority": False,
        "authority_granted": False,
        "readiness_authorized": False,
        "ready_for_human_t1_release_signature_only": False,
        "replay_allowed": False,
        "ready_for_t1_release_v2_human_signature_only": True,
        "network_authorized": False,
        "network_query_authorized": False,
        "readonly_production_query_authorized": False,
        "production_query_authorized": False,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "readonly_principal_deployment_authorized": False,
        "readonly_secret_file_installation_authorized": False,
        "questdb_restart_authorized": False,
        "questdb_recreate_authorized": False,
        "questdb_image_change_authorized": False,
        "writer_identity_mutation_authorized": False,
        "writer_secret_mutation_authorized": False,
        "network_mutation_authorized": False,
        "unscoped_deployment_mutation_authorized": False,
        "collection_authorized": False,
        "execution_quality_collection_authorized": False,
        "runtime_activation_authorized": False,
        "order_authorized": False,
        "order_submission_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "strategy_activation_authorized": False,
        "replacement_authorized": False,
        "production_authorized": False,
        "dynamic_selection_allowed": False,
        "automatic_promotion_authorized": False,
        "t1_executed": False,
        "production_queried": False,
        "readonly_query_authorized": False,
        "web_bridge_deployment_authorized": False,
        "production_queries_executed": 0,
        "readonly_queries_executed": 0,
        "write_probes_attempted": 0,
        "database_mutations": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }
    _validate_packet(packet)
    return packet


def write_packet_create_only(
    packet: dict[str, Any],
    pins: ReadinessPins,
    output: Path,
    *,
    require_root_owned_parent: bool = True,
    now: datetime | None = None,
) -> str:
    _validate_pins(pins)
    _validate_packet(packet)
    write_time = _require_aware(
        datetime.now(timezone.utc) if now is None else now,
        "write time",
    )
    try:
        generated_at = parse_datetime(packet["generated_at"], "generated_at")
        expires_at = parse_datetime(packet["expires_at"], "expires_at")
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    if not generated_at <= write_time < expires_at:
        raise ReadinessV2Error(
            "readiness packet is not current at create-only write time"
        )
    active_pins, active_custody = _reload_and_match_active_pins(pins)
    expected_name = f"{packet['packet_id']}.json"
    try:
        pinned = active_custody
        output_parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV2Error("packet custody cannot be resolved") from exc
    if (
        packet["packet_custody_path_sha256"]
        != _hash_bytes(str(pinned).encode("utf-8"))
        or packet["build_registry_provenance"][
            "provenance_keyring_sha256"
        ]
        != active_pins.provenance_keyring_sha256
        or packet["build_registry_provenance"][
            "t1_authority_keyring_sha256"
        ]
        != active_pins.t1_authority_keyring_sha256
        or packet["build_registry_provenance"][
            "l3_authority_keyring_sha256"
        ]
        != active_pins.l3_authority_keyring_sha256
        or packet["readonly_deployment_outcome"][
            "outcome_keyring_sha256"
        ]
        != active_pins.outcome_keyring_sha256
    ):
        raise ReadinessV2Error(
            "readiness packet does not bind the active pins and custody"
        )
    if output.name != expected_name or output_parent != pinned:
        raise ReadinessV2Error(
            "readiness output must use the exact pinned custody and packet ID"
        )
    try:
        guard = open_custody_guard(
            pinned,
            require_root_owned_parent=require_root_owned_parent,
        )
        try:
            raw_sha256 = write_json_create_only_at(
                guard,
                expected_name,
                packet,
                SCHEMA_PATH,
                "T1 readiness v2 packet",
            )
        finally:
            guard.close()
    except (OneShotError, FileExistsError) as exc:
        raise ReadinessV2Error(str(exc)) from exc
    return raw_sha256


def verify_existing_readiness_packet(
    inputs: ReadinessInputs,
    pins: ReadinessPins,
    packet_path: Path,
    *,
    now: datetime | None = None,
    require_root_owned_parent: bool = True,
) -> VerifiedReadinessPacket:
    """Re-derive and validate one exact, current readiness packet."""
    _validate_pins(pins)
    active_pins, pinned = _reload_and_match_active_pins(pins)
    current_time = _require_aware(
        datetime.now(timezone.utc) if now is None else now,
        "verification time",
    )
    try:
        supplied_parent = packet_path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV2Error("packet custody cannot be resolved") from exc
    if supplied_parent != pinned:
        raise ReadinessV2Error(
            "readiness packet is outside the exact pinned custody"
        )
    try:
        guard = open_custody_guard(
            pinned,
            require_root_owned_parent=require_root_owned_parent,
        )
        try:
            raw = read_regular_file_at(
                guard,
                packet_path.name,
                "existing T1 readiness v2 packet",
            )
        finally:
            guard.close()
        packet = parse_json_bytes(raw, "existing T1 readiness v2 packet")
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    _validate_packet(packet)
    if packet_path.name != f"{packet['packet_id']}.json":
        raise ReadinessV2Error(
            "readiness packet filename does not match packet ID"
        )
    if (
        packet["packet_custody_path_sha256"]
        != custody_path_sha256(pinned)
        or packet["build_registry_provenance"][
            "provenance_keyring_sha256"
        ]
        != active_pins.provenance_keyring_sha256
        or packet["build_registry_provenance"][
            "t1_authority_keyring_sha256"
        ]
        != active_pins.t1_authority_keyring_sha256
        or packet["build_registry_provenance"][
            "l3_authority_keyring_sha256"
        ]
        != active_pins.l3_authority_keyring_sha256
        or packet["readonly_deployment_outcome"][
            "outcome_keyring_sha256"
        ]
        != active_pins.outcome_keyring_sha256
    ):
        raise ReadinessV2Error(
            "readiness packet does not match active pins and custody"
        )
    try:
        generated_at = parse_datetime(packet["generated_at"], "generated_at")
        expires_at = parse_datetime(packet["expires_at"], "expires_at")
        outcome_issued_at = parse_datetime(
            packet["readonly_deployment_outcome"]["outcome_issued_at"],
            "outcome_issued_at",
        )
        deployment_ended_at = parse_datetime(
            packet["readonly_deployment_outcome"]["deployment_ended_at"],
            "deployment_ended_at",
        )
    except OneShotError as exc:
        raise ReadinessV2Error(str(exc)) from exc
    if not generated_at <= current_time < expires_at:
        raise ReadinessV2Error("readiness packet is not currently active")
    if (
        current_time - outcome_issued_at > MAX_OUTCOME_AGE
        or current_time - deployment_ended_at > MAX_OUTCOME_AGE
    ):
        raise ReadinessV2Error(
            "deployment outcome is stale at readiness consumption"
        )
    regenerated = derive_readiness_packet(
        inputs,
        active_pins,
        now=generated_at,
    )
    if regenerated != packet:
        raise ReadinessV2Error(
            "existing readiness packet is not the exact re-derived object"
        )
    return VerifiedReadinessPacket(
        payload=packet,
        raw_sha256=_hash_bytes(raw),
        canonical_sha256=_hash_bytes(canonical_json(packet)),
    )


def inputs_from_args(args: argparse.Namespace) -> ReadinessInputs:
    return ReadinessInputs(
        external_image_evidence=args.external_image_evidence,
        oci_layout_archive=args.oci_layout_archive,
        source_root=args.source_root,
        content_attestation=args.content_attestation,
        provenance=args.provenance,
        provenance_keyring=args.provenance_keyring,
        t1_keyring=args.t1_keyring,
        outcome=args.outcome,
        outcome_keyring=args.outcome_keyring,
        outcome_source=source_paths_from_args(args),
        post_evidence=post_paths_from_args(args),
        t1_runtime_source_commit_sha=(
            args.expected_t1_runtime_source_commit_sha
        ),
        t1_runtime_image_digest=args.expected_t1_runtime_image_digest,
        l3_contract_source_commit_sha=(
            args.expected_l3_contract_source_commit_sha
        ),
        outcome_contract_source_commit_assertion=(
            args.expected_outcome_contract_source_commit_assertion
        ),
        questdb_image_digest=args.expected_questdb_image_digest,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--oci-layout-archive", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--content-attestation", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--t1-keyring", type=Path, required=True)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--outcome-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-t1-runtime-source-commit-sha",
        required=True,
    )
    parser.add_argument("--expected-t1-runtime-image-digest", required=True)
    parser.add_argument(
        "--expected-l3-contract-source-commit-sha",
        required=True,
    )
    parser.add_argument(
        "--expected-outcome-contract-source-commit-assertion",
        required=True,
    )
    parser.add_argument("--expected-questdb-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    add_source_arguments(parser)
    add_post_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pins = _read_production_pins()
        packet = derive_readiness_packet(inputs_from_args(args), pins)
        raw_sha256 = write_packet_create_only(packet, pins, args.output)
    except (
        ReadinessV2Error,
        OSError,
        ValueError,
    ) as exc:
        print(f"T1 readiness v2 derivation failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={packet['status']}")
    print(f"packet_id={packet['packet_id']}")
    print(f"packet_raw_sha256={raw_sha256}")
    print("authority_granted=false")
    print("production_query_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
