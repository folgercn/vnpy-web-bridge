#!/usr/bin/env python3
"""Verify exact query-v4 T1 inputs without querying QuestDB or granting P0."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from c_fast_t1.validate_query_v4_runtime import (
    QueryV4PackagingError,
    validate_package,
)
from c_fast_t1.verify_query_v4_image_attestation import (
    QueryV4ImageAttestationError,
    verify_query_v4_image_evidence,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
    validate_private_dsn_metadata,
)
from commodity_c_fast_t1_query_v4 import (
    add_readiness_verification_arguments,
)
from commodity_c_fast_t1_readiness_v3 import (
    ReadinessV3Error,
    VerifiedReadinessPacket,
    _read_production_pins,
    inputs_from_args,
    verify_existing_readiness_packet,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-p0-preflight-v1.schema.json"
)
SCHEMA_VERSION = "commodity_c_fast_t1_p0_preflight_v1"
STATUS = (
    "QUERY_V4_SOURCE_OCI_AND_UPSTREAM_PREFLIGHT_VERIFIED_"
    "PROVENANCE_BLOCKED"
)
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
PARENT_ISSUE_NUMBER = 114
ISSUE_NUMBER = 216
MAX_ATTESTATION_BYTES = 8 * 1024 * 1024
MAX_DSN_BYTES = 64 * 1024
PREFLIGHT_TTL = timedelta(minutes=5)
BLOCKING_REASONS = [
    "QUERY_V4_SIGNED_BUILD_REGISTRY_PROVENANCE_NOT_YET_VERIFIED",
    "QUERY_V4_READINESS_AND_HUMAN_RELEASE_NOT_YET_DERIVED",
]


class T1P0PreflightError(RuntimeError):
    """Expected fail-closed T1/P0 preflight error."""


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise T1P0PreflightError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_content_attestation(
    path: Path,
) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = read_regular_file_strict(
            path,
            "query-v4 content attestation",
            limit=MAX_ATTESTATION_BYTES,
        )
        payload = parse_json_bytes(raw, "query-v4 content attestation")
    except OneShotError as exc:
        raise T1P0PreflightError(str(exc)) from exc
    return raw, payload


def readonly_dsn_metadata(path: Path) -> dict[str, Any]:
    """Validate DSN file metadata without opening or reading the secret."""

    try:
        validate_private_dsn_metadata(path)
        before = path.lstat()
    except (OneShotError, OSError) as exc:
        raise T1P0PreflightError(str(exc)) from exc
    if before.st_size <= 0 or before.st_size > MAX_DSN_BYTES:
        raise T1P0PreflightError("readonly DSN size is invalid")
    try:
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError as exc:
        raise T1P0PreflightError(
            "readonly DSN identity cannot be resolved"
        ) from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        stat.S_IFMT(before.st_mode),
        stat.S_IMODE(before.st_mode),
        before.st_size,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        stat.S_IFMT(after.st_mode),
        stat.S_IMODE(after.st_mode),
        after.st_size,
    )
    if identity_before != identity_after:
        raise T1P0PreflightError(
            "readonly DSN metadata changed during preflight"
        )
    return {
        "path_sha256": _hash(str(resolved).encode("utf-8")),
        "device": before.st_dev,
        "inode": before.st_ino,
        "owner_uid": before.st_uid,
        "mode": stat.S_IMODE(before.st_mode),
        "size_bytes": before.st_size,
        "regular_non_symlink": True,
        "owned_by_current_user": True,
        "permissions_0600_or_stricter": True,
        "metadata_only": True,
        "content_read": False,
    }


def _preflight_identity(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "preflight_id"
    }


def build_preflight(
    readiness: VerifiedReadinessPacket,
    query_v4_attestation: dict[str, Any],
    query_v4_attestation_raw: bytes,
    packaging: dict[str, Any],
    dsn_metadata: dict[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    """Join independently verified inputs into a non-authority artifact."""

    current = _utc(now, "preflight time")
    readiness_payload = readiness.payload
    source_commit = query_v4_attestation.get("source_commit_sha")
    readiness_commit = readiness_payload.get("source_namespaces", {}).get(
        "t1_runtime_source_commit_sha"
    )
    if not isinstance(source_commit, str) or not hmac.compare_digest(
        source_commit,
        str(readiness_commit),
    ):
        raise T1P0PreflightError(
            "query-v4 source commit does not match readiness-v3"
        )
    if (
        query_v4_attestation.get("schema_version")
        != "commodity_c_fast_t1_query_v4_image_attestation_v1"
        or query_v4_attestation.get("status")
        != (
            "QUERY_V4_SOURCE_BUNDLE_AND_OCI_CONTENT_VERIFIED_"
            "NO_BUILD_OR_REGISTRY_PROVENANCE"
        )
        or query_v4_attestation.get("authority_granted") is not False
        or query_v4_attestation.get("production_query_authorized")
        is not False
        or query_v4_attestation.get("database_mutations") != 0
        or query_v4_attestation.get("orders_sent") != 0
        or query_v4_attestation.get("positions_modified") != 0
    ):
        raise T1P0PreflightError(
            "query-v4 content attestation boundary is invalid"
        )
    if (
        packaging.get("status")
        != "QUERY_V4_CODE_ONLY_PACKAGING_VALID_RUNTIME_BLOCKED"
        or packaging.get("authority_granted") is not False
        or packaging.get("production_queried") is not False
        or packaging.get("containerfile", {}).get("containerfile_sha256")
        != query_v4_attestation.get("containerfile_sha256")
    ):
        raise T1P0PreflightError(
            "query-v4 runtime packaging does not match OCI content"
        )
    try:
        readiness_expires = parse_datetime(
            readiness_payload["expires_at"],
            "readiness-v3 expires_at",
        )
    except (KeyError, OneShotError) as exc:
        raise T1P0PreflightError(
            "readiness-v3 expiry is invalid"
        ) from exc
    expires_at = min(current + PREFLIGHT_TTL, readiness_expires)
    if expires_at <= current:
        raise T1P0PreflightError("readiness-v3 expired before preflight")
    outcome = readiness_payload["readonly_deployment_outcome"]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "candidate_id": CANDIDATE_ID,
        "parent_issue_number": PARENT_ISSUE_NUMBER,
        "issue_number": ISSUE_NUMBER,
        "preflight_id": "",
        "generated_at": _timestamp(current),
        "expires_at": _timestamp(expires_at),
        "preflight_verifier_sha256": _hash(
            Path(__file__).resolve().read_bytes()
        ),
        "preflight_schema_sha256": _hash(SCHEMA_PATH.read_bytes()),
        "query_v4": {
            "source_commit_sha": source_commit,
            "source_bundle_archive_sha256": query_v4_attestation[
                "source_bundle_archive_sha256"
            ],
            "content_attestation_raw_sha256": _hash(
                query_v4_attestation_raw
            ),
            "content_attestation_canonical_sha256": _hash(
                canonical_json(query_v4_attestation)
            ),
            "content_verifier_sha256": query_v4_attestation[
                "verifier_sha256"
            ],
            "content_verifier_delegate_sha256": query_v4_attestation[
                "delegate_verifier_sha256"
            ],
            "image_reference": query_v4_attestation["image_reference"],
            "image_digest": query_v4_attestation["image_digest"],
            "image_id": query_v4_attestation["image_id"],
            "runtime_bundle_index_sha256": query_v4_attestation[
                "runtime_bundle_index_sha256"
            ],
            "containerfile_sha256": query_v4_attestation[
                "containerfile_sha256"
            ],
            "runtime_packaging_report_canonical_sha256": _hash(
                canonical_json(packaging)
            ),
            "runtime_template_sha256": packaging["runtime_template"][
                "runtime_template_sha256"
            ],
            "build_provenance_verified": False,
            "registry_provenance_verified": False,
        },
        "upstream_readiness": {
            "packet_id": readiness_payload["packet_id"],
            "packet_raw_sha256": readiness.raw_sha256,
            "packet_canonical_sha256": readiness.canonical_sha256,
            "packet_expires_at": readiness_payload["expires_at"],
            "shared_source_commit_sha": readiness_commit,
            "signed_l3_outcome_raw_sha256": outcome[
                "signed_outcome_raw_sha256"
            ],
            "signed_l3_outcome_canonical_sha256": outcome[
                "signed_outcome_canonical_sha256"
            ],
            "questdb_target_identity_sha256": outcome[
                "questdb_target_identity_sha256"
            ],
            "questdb_image_digest": readiness_payload[
                "digest_namespaces"
            ]["questdb_image_digest"],
        },
        "readonly_dsn": dsn_metadata,
        "checks": {
            "query_v4_source_bundle_exact_commit_verified": True,
            "query_v4_oci_content_recomputed": True,
            "query_v4_attestation_exact_rerun_matched": True,
            "query_v4_runtime_packaging_closure_verified": True,
            "readiness_v3_active_and_exactly_rederived": True,
            "l3_signed_outcome_chain_verified_by_readiness_v3": True,
            "query_v4_and_readiness_share_exact_source_commit": True,
            "readonly_dsn_private_metadata_verified": True,
            "readonly_dsn_content_not_read": True,
            "production_query_not_attempted": True,
            "p0_not_evaluated": True,
        },
        "blocking_reasons": BLOCKING_REASONS,
        "ready_for_human_query_release_only": False,
        "sensitive_material_present": False,
        "artifact_is_authority": False,
        "authority_granted": False,
        "network_authorized": False,
        "readonly_production_query_authorized": False,
        "production_query_authorized": False,
        "p0_acceptance_authorized": False,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_query_attempted": False,
        "production_query_completed": False,
        "p0_verdict": "NOT_RUN",
        "production_queries_executed": 0,
        "readonly_queries_executed": 0,
        "database_mutations": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
    }
    payload["preflight_id"] = "t1-p0-preflight-v1-" + _hash(
        canonical_json(_preflight_identity(payload))
    )
    try:
        validate_json_schema(payload, SCHEMA_PATH, "T1/P0 preflight")
    except OneShotError as exc:
        raise T1P0PreflightError(str(exc)) from exc
    return payload


def write_create_only(path: Path, payload: dict[str, Any]) -> str:
    if not path.is_absolute():
        raise T1P0PreflightError("preflight output path must be absolute")
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    try:
        parent = path.parent.resolve(strict=True)
        parent_info = parent.lstat()
    except OSError as exc:
        raise T1P0PreflightError(
            "preflight output parent is unavailable"
        ) from exc
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(
        parent_info.st_mode
    ):
        raise T1P0PreflightError(
            "preflight output parent must be a non-symlink directory"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent / path.name, flags, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise T1P0PreflightError(
            "cannot create preflight output"
        ) from exc
    return _hash(raw)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--query-v4-external-image-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-source-bundle-archive",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-oci-layout-archive",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--query-v4-content-attestation",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-query-v4-source-commit-sha",
        required=True,
    )
    parser.add_argument(
        "--expected-query-v4-image-digest",
        required=True,
    )
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    add_readiness_verification_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pins = _read_production_pins()
        readiness = verify_existing_readiness_packet(
            inputs_from_args(args),
            pins,
            args.readiness_packet,
        )
        regenerated = verify_query_v4_image_evidence(
            args.query_v4_external_image_evidence,
            args.query_v4_source_bundle_archive,
            args.query_v4_oci_layout_archive,
            args.expected_query_v4_source_commit_sha,
        )
        supplied_raw, supplied = _read_content_attestation(
            args.query_v4_content_attestation
        )
        if supplied != regenerated:
            raise T1P0PreflightError(
                "query-v4 content attestation is not the exact rerun"
            )
        if not hmac.compare_digest(
            str(regenerated["image_digest"]),
            args.expected_query_v4_image_digest,
        ):
            raise T1P0PreflightError(
                "query-v4 image digest does not match expected RepoDigest"
            )
        packet = build_preflight(
            readiness,
            regenerated,
            supplied_raw,
            validate_package(),
            readonly_dsn_metadata(args.dsn_file),
            now=datetime.now(timezone.utc),
        )
        raw_sha256 = write_create_only(args.output, packet)
    except (
        OSError,
        OneShotError,
        QueryV4ImageAttestationError,
        QueryV4PackagingError,
        ReadinessV3Error,
        T1P0PreflightError,
        ValueError,
    ) as exc:
        print(f"T1/P0 preflight blocked: {exc}", file=sys.stderr)
        return 2
    print(f"status={packet['status']}")
    print(f"preflight_id={packet['preflight_id']}")
    print(f"preflight_raw_sha256={raw_sha256}")
    print("production_query_attempted=false")
    print("p0_verdict=NOT_RUN")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
