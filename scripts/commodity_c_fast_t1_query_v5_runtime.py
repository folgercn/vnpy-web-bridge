#!/usr/bin/env python3
"""Verify query-v5 pre-DSN evidence and report the runtime blockers.

This slice defines the future consume/child-started/terminal records, but it
cannot safely consume a release or read a DSN: release-v5 does not bind the
readiness, query plan, custody, DSN identity, or exact child closure required
at that irreversible boundary.  The CLI therefore performs only the full
#231 replay and always stops before custody or secret access.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
from typing import Any

from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
)
from commodity_c_fast_t1_query_v5_release import (
    RECEIPT_SCHEMA_PATH as PRE_DSN_RECEIPT_SCHEMA_PATH,
    CompositionReplayInputs,
    QueryV5ReleaseError,
    VerifiedProvenance,
    VerifiedRelease,
    build_pre_dsn_receipt,
    validate_release_semantics,
    verify_provenance,
    verify_release,
)


ROOT = Path(__file__).resolve().parents[1]
CONSUME_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-consume-v5.schema.json"
)
CHILD_STARTED_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-child-started-v5.schema.json"
)
TERMINAL_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v5.schema.json"
)
STATUS = "QUERY_V5_PRE_DSN_REPLAY_VERIFIED_RUNTIME_CONTRACT_BLOCKED"
MAX_JSON_BYTES = 8 * 1024 * 1024

# These are deliberately absent from the immutable release-v5 schema in #231.
# A later, independently reviewed authority version must bind every group before
# any consume burn, DSN metadata inspection, child claim, or child launch.
REQUIRED_FUTURE_RELEASE_BINDINGS = frozenset(
    {
        "readiness_v4_raw_sha256",
        "readiness_v4_canonical_sha256",
        "l3_outcome_raw_sha256",
        "l3_outcome_canonical_sha256",
        "query_manifest_raw_sha256",
        "query_manifest_canonical_sha256",
        "runtime_pin_generation_id",
        "runtime_pin_manifest_sha256",
        "runtime_identity_sha256",
        "custody_path_sha256",
        "custody_id",
        "custody_identity_sha256",
        "custody_directory_identity_sha256",
        "dsn_file_identity_attestation_raw_sha256",
        "dsn_file_identity_attestation_canonical_sha256",
        "dsn_file_identity_attestation_schema_sha256",
        "expected_readonly_principal_sha256",
        "expected_endpoint_identity_sha256",
        "query_manifest_schema_sha256",
        "connect_timeout_seconds",
        "statement_timeout_ms",
        "maximum_runtime_seconds",
        "runtime_runner_sha256",
        "query_child_sha256",
        "audit_script_sha256",
        "consume_schema_sha256",
        "child_started_schema_sha256",
        "terminal_schema_sha256",
        "readonly_proof_schema_sha256",
    }
)


class QueryV5RuntimeError(RuntimeError):
    """Expected fail-closed query-v5 lifecycle validation error."""


@dataclass(frozen=True)
class GateReplayPaths:
    provenance_path: Path
    provenance_keyring_path: Path
    composition_path: Path
    final_oci_layout_path: Path
    composition_replay: CompositionReplayInputs
    release_path: Path
    release_keyring_path: Path
    expected_provenance_keyring_sha256: str
    expected_release_keyring_sha256: str
    expected_source_commit_sha: str
    expected_image_digest: str


@dataclass(frozen=True)
class VerifiedGateReplay:
    release: VerifiedRelease
    provenance: VerifiedProvenance
    receipt: dict[str, Any]
    receipt_raw_sha256: str
    receipt_canonical_sha256: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QueryV5RuntimeError(f"{label} must include an explicit timezone")
    return value.astimezone(timezone.utc)


def _read_json_private(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = read_regular_file_strict(
            path,
            label,
            private=True,
            limit=MAX_JSON_BYTES,
        )
        return raw, parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise QueryV5RuntimeError(str(exc)) from exc


def replay_pre_dsn_gate(
    paths: GateReplayPaths,
    receipt_path: Path,
    *,
    now: datetime | None = None,
) -> VerifiedGateReplay:
    """Recompute #231's complete gate and exact-match its receipt."""

    receipt_raw, receipt = _read_json_private(
        receipt_path,
        "query-v5 pre-DSN receipt",
    )
    try:
        validate_json_schema(
            receipt,
            PRE_DSN_RECEIPT_SCHEMA_PATH,
            "query-v5 pre-DSN receipt",
        )
        receipt_time = parse_datetime(receipt["verified_at"], "receipt verified_at")
        provenance, provenance_materials = verify_provenance(
            paths.provenance_path,
            paths.provenance_keyring_path,
            paths.composition_path,
            paths.final_oci_layout_path,
            paths.composition_replay,
            expected_provenance_keyring_sha256=(
                paths.expected_provenance_keyring_sha256
            ),
            expected_source_commit_sha=paths.expected_source_commit_sha,
            expected_image_digest=paths.expected_image_digest,
            now=receipt_time,
        )
        release = verify_release(
            paths.release_path,
            paths.release_keyring_path,
            provenance,
            provenance_materials,
            expected_release_keyring_sha256=(paths.expected_release_keyring_sha256),
            now=receipt_time,
        )
        expected_receipt = build_pre_dsn_receipt(
            release,
            provenance,
            now=receipt_time,
        )
        if canonical_json(receipt) != canonical_json(expected_receipt):
            raise QueryV5RuntimeError(
                "pre-DSN receipt does not match exact gate replay"
            )
        validate_release_semantics(
            release.payload,
            provenance,
            now=_utc(now or datetime.now(timezone.utc), "runtime time"),
        )
    except (OneShotError, QueryV5ReleaseError) as exc:
        raise QueryV5RuntimeError(str(exc)) from exc
    return VerifiedGateReplay(
        release=release,
        provenance=provenance,
        receipt=receipt,
        receipt_raw_sha256=_sha256(receipt_raw),
        receipt_canonical_sha256=_sha256(canonical_json(receipt)),
    )


def validate_lifecycle_contract_schemas() -> dict[str, str]:
    """Validate the future-state schemas and return their exact byte hashes."""

    hashes: dict[str, str] = {}
    for name, path in {
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "child_started_schema_sha256": CHILD_STARTED_SCHEMA_PATH,
        "terminal_schema_sha256": TERMINAL_SCHEMA_PATH,
    }.items():
        try:
            raw = read_regular_file_strict(
                path,
                f"query-v5 {name}",
                limit=MAX_JSON_BYTES,
            )
            payload = parse_json_bytes(raw, f"query-v5 {name}")
            # Loading the schema through the existing validator checks that the
            # document is itself a valid Draft 2020-12 schema.
            validate_json_schema({}, path, f"query-v5 {name} self-check")
        except OneShotError as exc:
            # An empty instance is expected to fail; malformed/unavailable
            # schemas fail before producing the ordinary "required property"
            # validation message.
            if "required property" not in str(exc):
                raise QueryV5RuntimeError(str(exc)) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("additionalProperties") is not False
        ):
            raise QueryV5RuntimeError(f"query-v5 {name} is not strict")
        hashes[name] = _sha256(raw)
    return hashes


def runtime_blockers(replay: VerifiedGateReplay) -> tuple[str, ...]:
    """Return the exact authority bindings missing from release-v5."""

    missing = sorted(REQUIRED_FUTURE_RELEASE_BINDINGS - set(replay.release.payload))
    if not missing:
        raise QueryV5RuntimeError(
            "release-v5 unexpectedly contains future runtime authority bindings"
        )
    return tuple(missing)


def validate_terminal_semantics(payload: dict[str, Any]) -> None:
    """Apply the conservative lifecycle semantics beyond JSON shape checks."""

    try:
        validate_json_schema(payload, TERMINAL_SCHEMA_PATH, "query-v5 terminal")
    except OneShotError as exc:
        raise QueryV5RuntimeError(str(exc)) from exc
    state = payload["terminal_state"]
    artifacts = payload["artifact_sha256"]
    try:
        started_at = parse_datetime(payload["started_at"], "terminal started_at")
        ended_at = parse_datetime(payload["ended_at"], "terminal ended_at")
        final_at = (
            parse_datetime(
                payload["final_revalidation_at"],
                "terminal final_revalidation_at",
            )
            if payload["final_revalidation_at"] is not None
            else None
        )
    except OneShotError as exc:
        raise QueryV5RuntimeError(str(exc)) from exc
    chronology_valid = ended_at >= started_at and (
        final_at is None or started_at <= final_at <= ended_at
    )
    if state in {"COMPLETED_PASS", "COMPLETED_BLOCKED"}:
        valid = (
            chronology_valid
            and payload["error_code"] is None
            and payload["query_execution_state"] == "COMPLETE"
            and final_at is not None
            and payload["child_exit_code"] == (0 if state == "COMPLETED_PASS" else 1)
            and payload["child_signal"] is None
            and payload["launch_marker_integrity"] == "VERIFIED"
            and payload["production_query_attempted"] is True
            and payload["production_query_completed"] is True
            and payload["readonly_proof_verified"] is True
            and payload["readonly_principal_verified"] is True
            and payload["endpoint_verified"] is True
            and payload["p0_pass"] == (state == "COMPLETED_PASS")
            and payload["database_mutations_observed"] == 0
            and all(artifacts.values())
        )
    elif state == "FAILED_BEFORE_CHILD":
        valid = (
            chronology_valid
            and isinstance(payload["error_code"], str)
            and bool(payload["error_code"])
            and payload["query_execution_state"] == "NOT_STARTED"
            and payload["final_revalidation_at"] is None
            and payload["child_exit_code"] is None
            and payload["child_signal"] is None
            and payload["production_query_attempted"] is False
            and payload["production_query_completed"] is False
            and payload["readonly_proof_verified"] is False
            and payload["readonly_principal_verified"] is False
            and payload["endpoint_verified"] is False
            and payload["p0_pass"] is None
            and payload["database_mutations_observed"] is None
            and not any(artifacts.values())
            and payload["launch_marker_integrity"] == "NOT_CREATED"
            and all(
                payload[field] is None
                for field in (
                    "query_child_started_raw_sha256",
                    "query_child_started_canonical_sha256",
                    "query_child_invocation_raw_sha256",
                    "query_child_invocation_canonical_sha256",
                    "audit_invocation_raw_sha256",
                    "audit_invocation_canonical_sha256",
                    "pre_connect_gate_raw_sha256",
                    "pre_connect_gate_canonical_sha256",
                    "parent_launch_capability_sha256",
                    "launch_marker_identity_sha256",
                    "launch_capability_binding_sha256",
                    "readonly_preflight_canonical_sha256",
                    "readonly_postflight_canonical_sha256",
                )
            )
        )
    elif state == "OUTCOME_UNKNOWN":
        valid = (
            chronology_valid
            and isinstance(payload["error_code"], str)
            and bool(payload["error_code"])
            and payload["query_execution_state"] == "OUTCOME_UNKNOWN"
            and payload["production_query_attempted"] is True
            and payload["production_query_completed"] is None
            and payload["readonly_proof_verified"] is False
            and payload["readonly_principal_verified"] is False
            and payload["endpoint_verified"] is False
            and payload["p0_pass"] is None
            and payload["database_mutations_observed"] is None
            and not (
                payload["child_exit_code"] is not None
                and payload["child_signal"] is not None
            )
            and (
                (payload["query_child_started_raw_sha256"] is None)
                == (payload["query_child_started_canonical_sha256"] is None)
            )
            and payload["launch_marker_integrity"] != "NOT_CREATED"
            and (
                payload["launch_marker_integrity"] != "VERIFIED"
                or payload["query_child_started_raw_sha256"] is not None
            )
        )
    else:  # pragma: no cover - schema validation already rejects this.
        valid = False
    if not valid:
        raise QueryV5RuntimeError(
            "query-v5 terminal lifecycle semantics are contradictory"
        )


def build_blocked_report(replay: VerifiedGateReplay) -> dict[str, Any]:
    schemas = validate_lifecycle_contract_schemas()
    missing = runtime_blockers(replay)
    return {
        "status": STATUS,
        "candidate_id": replay.receipt["candidate_id"],
        "release_id": replay.release.payload["release_id"],
        "attempt_id": replay.release.payload["attempt_id"],
        "pre_dsn_receipt_raw_sha256": replay.receipt_raw_sha256,
        "pre_dsn_receipt_canonical_sha256": replay.receipt_canonical_sha256,
        **schemas,
        "missing_release_bindings": list(missing),
        "runtime_execution_ready": False,
        "fact_scope": "THIS_VERIFY_ONLY_RUNNER_PROCESS_ONLY",
        "attempt_state": "NOT_INSPECTED",
        "this_runner_release_consumed": False,
        "this_runner_custody_opened": False,
        "this_runner_dsn_metadata_read": False,
        "this_runner_dsn_secret_read": False,
        "this_runner_query_child_started": False,
        "this_runner_network_attempted": False,
        "this_runner_production_query_attempted": False,
        "authority_granted": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--signed-provenance", dest="provenance", type=Path, required=True
    )
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--composition-attestation", type=Path, required=True)
    parser.add_argument("--final-oci-layout", type=Path, required=True)
    parser.add_argument("--query-v4-external-image-evidence", type=Path, required=True)
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
    parser.add_argument("--pre-dsn-receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = GateReplayPaths(
        provenance_path=args.provenance,
        provenance_keyring_path=args.provenance_keyring,
        composition_path=args.composition_attestation,
        final_oci_layout_path=args.final_oci_layout,
        composition_replay=CompositionReplayInputs(
            query_v4_external_image_evidence_path=args.query_v4_external_image_evidence,
            query_v4_source_bundle_path=args.query_v4_source_bundle_archive,
            query_v4_oci_layout_archive_path=args.query_v4_oci_layout_archive,
            query_v4_content_attestation_path=args.query_v4_content_attestation,
            expected_query_v4_source_commit_sha=args.expected_query_v4_source_commit_sha,
            external_image_evidence_path=args.external_image_evidence,
            source_bundle_path=args.source_bundle_archive,
            final_oci_layout_path=args.final_oci_layout,
        ),
        release_path=args.release,
        release_keyring_path=args.release_keyring,
        expected_provenance_keyring_sha256=args.expected_provenance_keyring_sha256,
        expected_release_keyring_sha256=args.expected_release_keyring_sha256,
        expected_source_commit_sha=args.expected_source_commit_sha,
        expected_image_digest=args.expected_image_digest,
    )
    try:
        report = build_blocked_report(replay_pre_dsn_gate(paths, args.pre_dsn_receipt))
    except (OSError, QueryV5RuntimeError) as exc:
        print(f"query-v5 runtime verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={report['status']}")
    print(f"attempt_id={report['attempt_id']}")
    print(f"missing_release_bindings={len(report['missing_release_bindings'])}")
    print("runtime_execution_ready=false")
    print("fact_scope=THIS_VERIFY_ONLY_RUNNER_PROCESS_ONLY")
    print("attempt_state=NOT_INSPECTED")
    print("this_runner_release_consumed=false")
    print("this_runner_custody_opened=false")
    print("this_runner_dsn_secret_read=false")
    print("this_runner_network_attempted=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
