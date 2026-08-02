#!/usr/bin/env python3
"""Build one keyless, create-only query-v6 P0 acceptance draft.

This offline tool only reads an already completed query-v6 evidence bundle. It
does not load private keys, open a network client, grant authority, or sign the
result. The separately reviewed runtime-artifact signer remains the only path
from this unsigned draft to a signed P0 envelope.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import stat
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.commodity_c_fast_execution_quality_production_artifacts import (  # noqa: E402
    CFastExecutionQualityP0AcceptanceV6DTO,
)
from app.services.commodity_c_fast_execution_quality_production_verifier import (  # noqa: E402
    CommodityCFastExecutionQualityProductionArtifactVerifier,
    P0_QUERY_V6_BUNDLE_FILE_ORDER,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (  # noqa: E402
    canonical_json,
)
from app.services.commodity_c_fast_shadow import PRODUCTS  # noqa: E402

from commodity_c_fast_t1_one_shot import (  # noqa: E402
    OneShotError,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
    write_json_create_only,
)
from app.services.commodity_c_fast_l1_l5_audit_semantic_replay import (  # noqa: E402
    AuditSemanticReplayError,
    replay_audit_evidence_semantics,
)


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024
EXTERNAL_CUSTODY_IDENTITY_VERSION = (
    "commodity_c_fast_p0_external_custody_identity_v1"
)
DRAFT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-execution-quality-p0-unsigned-draft-v6.schema.json"
)
LAUNCH_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-child-launched-v6.schema.json"
)
SCHEMA_BY_ROLE = {
    "foundation_release": (
        ROOT
        / "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v6.schema.json"
    ),
    "foundation_keyring": (
        ROOT
        / "docs/schemas/commodity-c-fast-t1-query-v6-trusted-keys-v1.schema.json"
    ),
    "executable_release": (
        ROOT
        / "docs/schemas/"
        "commodity-c-fast-t1-one-shot-query-executable-release-v6.schema.json"
    ),
    "executable_keyring": (
        ROOT
        / "docs/schemas/"
        "commodity-c-fast-t1-query-v6-executable-trusted-keys-v1.schema.json"
    ),
    "active_pin_set": (
        ROOT
        / "docs/schemas/"
        "commodity-c-fast-t1-query-v6-executable-pin-set-v1.schema.json"
    ),
    "manifest": (
        ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json"
    ),
    "consume_marker": (
        ROOT / "docs/schemas/commodity-c-fast-t1-query-consume-v6.schema.json"
    ),
    "terminal": (
        ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json"
    ),
    "audit_json": (
        ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
    ),
    "readonly_proof": (
        ROOT / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
    ),
}
JSON_BUNDLE_ROLES = frozenset(
    set(P0_QUERY_V6_BUNDLE_FILE_ORDER) - {"audit_csv", "audit_markdown"}
)
LAUNCH_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "candidate_id",
        "release_id",
        "attempt_id",
        "claimed_at",
        "consume_marker_raw_sha256",
        "consume_marker_canonical_sha256",
        "executable_release_raw_sha256",
        "foundation_raw_sha256",
        "pin_set_manifest_sha256",
        "execution_adapter_sha256",
        "adapter_package_manifest_sha256",
        "adapter_package_root_identity_sha256",
        "python_executable_sha256",
        "python_dependency_closure_sha256",
        "invocation_binding_sha256",
        "launch_capability_sha256",
        "consume_verified_before_claim",
        "final_revalidation_completed_before_claim",
        "launch_claimed",
        "dsn_secret_read",
        "network_attempted",
        "production_query_attempted",
        "launch_marker_is_authority",
        "database_mutation_authorized",
        "web_bridge_rpc_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "trading_authorized",
        "production_authorized",
        "replay_allowed",
    }
)


class P0BundleV6Error(ValueError):
    """Expected fail-closed P0 bundle construction error."""


@dataclass(frozen=True)
class P0BundleV6Paths:
    foundation_release: Path
    foundation_keyring: Path
    executable_release: Path
    executable_keyring: Path
    active_pin_set: Path
    manifest: Path
    consume_marker: Path
    launch_marker: Path
    terminal: Path
    audit_json: Path
    audit_csv: Path
    audit_markdown: Path
    readonly_proof: Path
    external_custody_identity: Path


@dataclass(frozen=True)
class ExactBundle:
    raw: dict[str, bytes]
    payloads: dict[str, dict[str, Any]]
    raw_sha256: dict[str, str]
    canonical_sha256: dict[str, str | None]
    size_bytes: dict[str, int]
    bundle_index_sha256: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _same(actual: object, expected: object, label: str) -> None:
    if not hmac.compare_digest(str(actual), str(expected)):
        raise P0BundleV6Error(f"{label} binding mismatch")


def _utc(value: str | datetime, label: str) -> datetime:
    try:
        parsed = parse_datetime(value, label)
    except OneShotError as exc:
        raise P0BundleV6Error(str(exc)) from exc
    return parsed.astimezone(timezone.utc)


def _read_bundle_once(paths: P0BundleV6Paths) -> dict[str, bytes]:
    identities: dict[tuple[int, int], str] = {}
    result: dict[str, bytes] = {}
    for role in P0_QUERY_V6_BUNDLE_FILE_ORDER:
        path = getattr(paths, role)
        try:
            info = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise P0BundleV6Error(f"cannot stat {role}") from exc
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise P0BundleV6Error(
                f"bundle roles {identities[identity]} and {role} alias"
            )
        identities[identity] = role
        try:
            result[role] = read_regular_file_strict(
                path,
                role,
                private=True,
                limit=MAX_BUNDLE_FILE_BYTES,
            )
        except OneShotError as exc:
            raise P0BundleV6Error(str(exc)) from exc
    return result


def _validate_launch_marker(payload: dict[str, Any]) -> None:
    if set(payload) != LAUNCH_REQUIRED_FIELDS:
        raise P0BundleV6Error("query-v6 launch marker fields are invalid")
    if (
        payload["schema_version"] != "commodity_c_fast_t1_query_child_launched_v6"
        or payload["purpose"] != "c_fast_t1_query_v6_one_shot_launch_claim"
        or payload["candidate_id"] != "C_FAST_CROSS_SECTION_NEUTRAL"
        or payload["consume_verified_before_claim"] is not True
        or payload["final_revalidation_completed_before_claim"] is not True
        or payload["launch_claimed"] is not True
        or any(
            payload[field] is not False
            for field in (
                "dsn_secret_read",
                "network_attempted",
                "production_query_attempted",
                "launch_marker_is_authority",
                "database_mutation_authorized",
                "web_bridge_rpc_authorized",
                "order_authorized",
                "position_mutation_authorized",
                "dispatch_authorized",
                "trading_authorized",
                "production_authorized",
                "replay_allowed",
            )
        )
    ):
        raise P0BundleV6Error("query-v6 launch marker semantics are invalid")
    _utc(payload["claimed_at"], "launch_marker.claimed_at")
    if LAUNCH_SCHEMA_PATH.exists():
        try:
            validate_json_schema(payload, LAUNCH_SCHEMA_PATH, "query-v6 launch marker")
        except OneShotError as exc:
            raise P0BundleV6Error(str(exc)) from exc


def _validate_external_custody_identity(payload: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "custody_id",
        "asserted_archive_type",
        "archive_locator_sha256",
        "independent_from_t1_runner",
        "immutability_asserted",
    }
    if set(payload) != required:
        raise P0BundleV6Error("external custody identity fields are invalid")
    if (
        payload["schema_version"] != EXTERNAL_CUSTODY_IDENTITY_VERSION
        or payload["asserted_archive_type"]
        not in {"ASSERTED_WORM", "ASSERTED_APPEND_ONLY"}
        or payload["independent_from_t1_runner"] is not True
        or payload["immutability_asserted"] is not True
    ):
        raise P0BundleV6Error("external custody identity is invalid")
    if not isinstance(payload["custody_id"], str) or not (
        8 <= len(payload["custody_id"]) <= 128
        and all(character.isalnum() or character in "._-" for character in payload["custody_id"])
    ):
        raise P0BundleV6Error("external custody id is invalid")
    locator = payload["archive_locator_sha256"]
    if (
        not isinstance(locator, str)
        or len(locator) != 64
        or any(character not in "0123456789abcdef" for character in locator)
    ):
        raise P0BundleV6Error("external archive locator is invalid")


def _verify_release_signature(
    release: dict[str, Any],
    keyring: dict[str, Any],
    *,
    required_purpose: str,
    label: str,
) -> frozenset[str]:
    selected: Ed25519PublicKey | None = None
    key_ids: set[str] = set()
    materials: set[str] = set()
    for entry in keyring["keys"]:
        key_id = str(entry["key_id"])
        if key_id in key_ids:
            raise P0BundleV6Error(f"{label} key id is duplicated")
        key_ids.add(key_id)
        try:
            raw = base64.b64decode(entry["public_key_base64"], validate=True)
            if len(raw) != 32:
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(raw)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise P0BundleV6Error(f"{label} keyring material is invalid") from exc
        material_hash = _sha256(raw)
        if material_hash in materials:
            raise P0BundleV6Error(f"{label} keyring material is duplicated")
        materials.add(material_hash)
        if key_id == release["signer_key_id"]:
            if entry["purpose"] != required_purpose:
                raise P0BundleV6Error(f"{label} signer purpose is invalid")
            selected = public_key
    if selected is None:
        raise P0BundleV6Error(f"{label} signer is not trusted")
    try:
        signature = base64.b64decode(release["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError
        selected.verify(
            signature,
            canonical_json(
                {key: value for key, value in release.items() if key != "signature"}
            ),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise P0BundleV6Error(f"{label} signature is invalid") from exc
    return frozenset(materials)


def load_exact_bundle(paths: P0BundleV6Paths) -> ExactBundle:
    raw = _read_bundle_once(paths)
    payloads: dict[str, dict[str, Any]] = {}
    for role in JSON_BUNDLE_ROLES:
        try:
            payloads[role] = parse_json_bytes(raw[role], role)
        except OneShotError as exc:
            raise P0BundleV6Error(str(exc)) from exc
    for role, schema_path in SCHEMA_BY_ROLE.items():
        try:
            validate_json_schema(payloads[role], schema_path, role)
        except OneShotError as exc:
            raise P0BundleV6Error(str(exc)) from exc
    _validate_launch_marker(payloads["launch_marker"])
    _validate_external_custody_identity(payloads["external_custody_identity"])
    if not raw["audit_csv"] or not raw["audit_markdown"]:
        raise P0BundleV6Error("query-v6 rendered audit artifacts must be non-empty")
    if _read_bundle_once(paths) != raw:
        raise P0BundleV6Error("query-v6 P0 bundle changed during stable re-read")
    raw_sha256 = {role: _sha256(raw[role]) for role in P0_QUERY_V6_BUNDLE_FILE_ORDER}
    canonical_sha256 = {
        role: (
            _sha256(canonical_json(payloads[role]))
            if role in JSON_BUNDLE_ROLES
            else None
        )
        for role in P0_QUERY_V6_BUNDLE_FILE_ORDER
    }
    size_bytes = {role: len(raw[role]) for role in P0_QUERY_V6_BUNDLE_FILE_ORDER}
    index = {
        "schema_version": "commodity_c_fast_execution_quality_p0_bundle_index_v6_v1",
        "files": [
            {
                "name": role,
                "size_bytes": size_bytes[role],
                "raw_sha256": raw_sha256[role],
                "canonical_sha256": canonical_sha256[role],
            }
            for role in P0_QUERY_V6_BUNDLE_FILE_ORDER
        ],
    }
    return ExactBundle(
        raw=raw,
        payloads=payloads,
        raw_sha256=raw_sha256,
        canonical_sha256=canonical_sha256,
        size_bytes=size_bytes,
        bundle_index_sha256=_sha256(canonical_json(index)),
    )


def _validate_exact_bundle_joins(bundle: ExactBundle) -> None:
    payloads = bundle.payloads
    foundation = payloads["foundation_release"]
    executable = payloads["executable_release"]
    pins = payloads["active_pin_set"]
    manifest = payloads["manifest"]
    consume = payloads["consume_marker"]
    launch = payloads["launch_marker"]
    terminal = payloads["terminal"]
    audit = payloads["audit_json"]
    proof = payloads["readonly_proof"]

    try:
        replay_audit_evidence_semantics(audit, manifest)
    except AuditSemanticReplayError as exc:
        raise P0BundleV6Error("query-v6 audit semantic replay failed") from exc

    foundation_materials = _verify_release_signature(
        foundation,
        payloads["foundation_keyring"],
        required_purpose="t1_query_v6_authority_foundation_signer",
        label="foundation release",
    )
    executable_materials = _verify_release_signature(
        executable,
        payloads["executable_keyring"],
        required_purpose="t1_query_v6_executable_release_signer",
        label="executable release",
    )
    if foundation_materials & executable_materials:
        raise P0BundleV6Error("foundation and executable key domains overlap")

    _same(
        foundation["trusted_keyring_sha256"],
        bundle.canonical_sha256["foundation_keyring"],
        "foundation keyring",
    )
    _same(
        executable["trusted_keyring_sha256"],
        bundle.canonical_sha256["executable_keyring"],
        "executable keyring",
    )
    _same(
        pins["executable_keyring_sha256"],
        bundle.canonical_sha256["executable_keyring"],
        "active executable keyring",
    )
    exact_foundation = executable["foundation"]
    for field, expected in (
        ("raw_sha256", bundle.raw_sha256["foundation_release"]),
        ("canonical_sha256", bundle.canonical_sha256["foundation_release"]),
    ):
        _same(exact_foundation[field], expected, f"executable foundation {field}")
    _same(
        executable["execution"]["pin_set_manifest_sha256"],
        bundle.canonical_sha256["active_pin_set"],
        "executable active pin set",
    )
    _same(
        exact_foundation["query_manifest_raw_sha256"],
        bundle.raw_sha256["manifest"],
        "foundation manifest raw",
    )
    _same(
        exact_foundation["query_manifest_canonical_sha256"],
        bundle.canonical_sha256["manifest"],
        "foundation manifest canonical",
    )

    for marker_name, marker in (("consume", consume), ("terminal", terminal)):
        _same(marker["release_id"], executable["release_id"], f"{marker_name} release")
        _same(marker["attempt_id"], executable["attempt_id"], f"{marker_name} attempt")
        for field, expected in (
            ("executable_release_raw_sha256", bundle.raw_sha256["executable_release"]),
            (
                "executable_release_canonical_sha256",
                bundle.canonical_sha256["executable_release"],
            ),
            ("foundation_raw_sha256", bundle.raw_sha256["foundation_release"]),
            (
                "foundation_canonical_sha256",
                bundle.canonical_sha256["foundation_release"],
            ),
            (
                "execution_adapter_sha256",
                executable["execution"]["execution_adapter_sha256"],
            ),
        ):
            _same(marker[field], expected, f"{marker_name} {field}")
    _same(
        consume["executable_keyring_sha256"],
        bundle.canonical_sha256["executable_keyring"],
        "consume executable keyring",
    )
    _same(
        consume["pin_set_manifest_sha256"],
        bundle.canonical_sha256["active_pin_set"],
        "consume active pin set",
    )
    _same(
        consume["query_manifest_raw_sha256"],
        bundle.raw_sha256["manifest"],
        "consume manifest raw",
    )

    for field, expected in (
        ("release_id", executable["release_id"]),
        ("attempt_id", executable["attempt_id"]),
        ("consume_marker_raw_sha256", bundle.raw_sha256["consume_marker"]),
        (
            "consume_marker_canonical_sha256",
            bundle.canonical_sha256["consume_marker"],
        ),
        ("executable_release_raw_sha256", bundle.raw_sha256["executable_release"]),
        ("foundation_raw_sha256", bundle.raw_sha256["foundation_release"]),
        ("pin_set_manifest_sha256", bundle.canonical_sha256["active_pin_set"]),
        (
            "execution_adapter_sha256",
            executable["execution"]["execution_adapter_sha256"],
        ),
    ):
        _same(launch[field], expected, f"launch {field}")
    _same(
        terminal["consume_marker_raw_sha256"],
        bundle.raw_sha256["consume_marker"],
        "terminal consume raw",
    )
    _same(
        terminal["consume_marker_canonical_sha256"],
        bundle.canonical_sha256["consume_marker"],
        "terminal consume canonical",
    )
    for role in ("audit_json", "audit_csv", "audit_markdown", "readonly_proof"):
        _same(
            terminal["artifact_sha256"][role],
            bundle.raw_sha256[role],
            f"terminal artifact {role}",
        )
    _same(audit["snapshot_id"], manifest["snapshot_id"], "audit snapshot")
    _same(proof["snapshot_id"], manifest["snapshot_id"], "proof snapshot")
    _same(
        audit["manifest_sha256"],
        bundle.canonical_sha256["manifest"],
        "audit manifest",
    )
    _same(
        proof["manifest_sha256"],
        bundle.canonical_sha256["manifest"],
        "proof manifest",
    )
    _same(
        proof["audit_evidence_sha256"],
        bundle.raw_sha256["audit_json"],
        "proof audit evidence",
    )
    foundation_issued = _utc(foundation["issued_at"], "foundation.issued_at")
    foundation_not_before = _utc(
        foundation["not_before"], "foundation.not_before"
    )
    foundation_expires = _utc(foundation["expires_at"], "foundation.expires_at")
    executable_issued = _utc(executable["issued_at"], "executable.issued_at")
    executable_not_before = _utc(
        executable["not_before"], "executable.not_before"
    )
    executable_expires = _utc(executable["expires_at"], "executable.expires_at")
    consumed_at = _utc(consume["consumed_at"], "consume.consumed_at")
    launch_claimed_at = _utc(launch["claimed_at"], "launch.claimed_at")
    if not (
        foundation_issued
        <= foundation_not_before
        <= executable_issued
        <= executable_not_before
        <= consumed_at
        <= launch_claimed_at
        < executable_expires
        <= foundation_expires
    ):
        raise P0BundleV6Error("query-v6 release and execution timeline is invalid")


def build_unsigned_p0_draft(
    paths: P0BundleV6Paths,
    *,
    generation_id: str | None,
    issued_at: datetime,
    valid_until: datetime,
    archived_at: datetime,
    signer_key_id: str,
    reviewer_role: str,
    human_signature: str,
) -> dict[str, Any]:
    bundle = load_exact_bundle(paths)
    _validate_exact_bundle_joins(bundle)
    payloads = bundle.payloads
    terminal = payloads["terminal"]
    audit = payloads["audit_json"]
    proof = payloads["readonly_proof"]
    launch = payloads["launch_marker"]
    external_identity = payloads["external_custody_identity"]
    current_rows = [item for item in audit["contracts"] if item["role"] == "current"]
    exact_contracts = tuple(sorted(item["exact_contract"] for item in current_rows))
    if len(exact_contracts) != len(PRODUCTS) or len(set(exact_contracts)) != len(PRODUCTS):
        raise P0BundleV6Error("audit does not contain ten unique current contracts")

    consumed_at = _utc(payloads["consume_marker"]["consumed_at"], "consumed_at")
    started_at = _utc(terminal["started_at"], "started_at")
    final_revalidation_at = _utc(
        terminal["final_revalidation_at"], "final_revalidation_at"
    )
    launch_claimed_at = _utc(launch["claimed_at"], "launch_claimed_at")
    audit_generated_at = _utc(audit["generated_at"], "audit.generated_at")
    proof_generated_at = _utc(proof["generated_at"], "proof.generated_at")
    ended_at = _utc(terminal["ended_at"], "ended_at")
    if not (
        consumed_at
        == started_at
        <= final_revalidation_at
        <= launch_claimed_at
        <= audit_generated_at
        <= proof_generated_at
        <= ended_at
        <= archived_at
        <= issued_at
        < valid_until
    ):
        raise P0BundleV6Error("query-v6 P0 evidence timeline is invalid")

    generation = generation_id or f"query-v6-p0-{bundle.raw_sha256['terminal'][:24]}"
    draft: dict[str, Any] = {
        "schema_version": "commodity_c_fast_execution_quality_p0_acceptance_v6_v1",
        "artifact_role": "signed_p0_acceptance",
        "purpose": "c_fast_query_v6_exact_terminal_p0_acceptance",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "generation_id": generation,
        "snapshot_id": audit["snapshot_id"],
        "issued_at_utc": issued_at.isoformat(),
        "valid_until_utc": valid_until.isoformat(),
        "exact_contracts": exact_contracts,
        "signer_key_id": signer_key_id,
        "terminal_exact_json_base64": base64.b64encode(bundle.raw["terminal"]).decode(),
        "terminal_raw_sha256": bundle.raw_sha256["terminal"],
        "terminal_canonical_sha256": bundle.canonical_sha256["terminal"],
        "readonly_proof_exact_json_base64": base64.b64encode(
            bundle.raw["readonly_proof"]
        ).decode(),
        "readonly_proof_raw_sha256": bundle.raw_sha256["readonly_proof"],
        "readonly_proof_canonical_sha256": bundle.canonical_sha256[
            "readonly_proof"
        ],
        "audit_exact_json_base64": base64.b64encode(bundle.raw["audit_json"]).decode(),
        "audit_raw_sha256": bundle.raw_sha256["audit_json"],
        "audit_canonical_sha256": bundle.canonical_sha256["audit_json"],
        "manifest_exact_json_base64": base64.b64encode(bundle.raw["manifest"]).decode(),
        "executable_release_raw_sha256": bundle.raw_sha256["executable_release"],
        "executable_release_canonical_sha256": bundle.canonical_sha256[
            "executable_release"
        ],
        "foundation_raw_sha256": bundle.raw_sha256["foundation_release"],
        "foundation_canonical_sha256": bundle.canonical_sha256[
            "foundation_release"
        ],
        "execution_adapter_sha256": terminal["execution_adapter_sha256"],
        "bundle_raw_sha256": bundle.raw_sha256,
        "bundle_canonical_sha256": bundle.canonical_sha256,
        "bundle_size_bytes": bundle.size_bytes,
        "bundle_index_sha256": bundle.bundle_index_sha256,
        "external_archive": {
            "custody_id": external_identity["custody_id"],
            "asserted_archive_type": external_identity["asserted_archive_type"],
            "archive_locator_sha256": external_identity["archive_locator_sha256"],
            "custody_identity_raw_sha256": bundle.raw_sha256[
                "external_custody_identity"
            ],
            "custody_identity_canonical_sha256": bundle.canonical_sha256[
                "external_custody_identity"
            ],
            "archived_bundle_index_sha256": bundle.bundle_index_sha256,
            "archived_at_utc": archived_at.isoformat(),
            "independent_custody_asserted": True,
            "immutability_asserted": True,
            "verification_state": "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED",
        },
        "consumed_at_utc": consumed_at.isoformat(),
        "launch_claimed_at_utc": launch_claimed_at.isoformat(),
        "started_at_utc": started_at.isoformat(),
        "final_revalidation_at_utc": final_revalidation_at.isoformat(),
        "ended_at_utc": ended_at.isoformat(),
        "archived_at_utc": archived_at.isoformat(),
        "p0_accepted": True,
        "exact_terminal_replayed": True,
        "exact_readonly_proof_replayed": True,
        "exact_audit_replayed": True,
        "signer_type": "human",
        "reviewer_role": reviewer_role,
        "human_signature": human_signature,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    try:
        model = CFastExecutionQualityP0AcceptanceV6DTO.model_validate(
            {**draft, "signature": PLACEHOLDER_SIGNATURE}
        )
        CommodityCFastExecutionQualityProductionArtifactVerifier().verify_p0_semantics(
            model
        )
    except (ValidationError, ValueError) as exc:
        raise P0BundleV6Error("query-v6 P0 semantic replay failed") from exc
    return model.model_dump(mode="json", exclude={"signature"})


def write_unsigned_p0_draft(path: Path, draft: dict[str, Any]) -> str:
    output = path.expanduser()
    output = output if output.is_absolute() else Path.cwd() / output
    if Path(os.path.normpath(str(output))) != output:
        raise P0BundleV6Error("output path must already be normalized")
    parent = output.parent.resolve(strict=True)
    info = parent.stat()
    if (
        output.parent != parent
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise P0BundleV6Error("output parent must be a private owned directory")
    return write_json_create_only(
        output,
        draft,
        DRAFT_SCHEMA_PATH,
        "query-v6 unsigned P0 draft",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for role in P0_QUERY_V6_BUNDLE_FILE_ORDER:
        parser.add_argument(f"--{role.replace('_', '-')}", type=Path, required=True)
    parser.add_argument("--generation-id")
    parser.add_argument("--issued-at", required=True)
    parser.add_argument("--valid-until", required=True)
    parser.add_argument("--archived-at", required=True)
    parser.add_argument("--signer-key-id", required=True)
    parser.add_argument("--reviewer-role", required=True)
    parser.add_argument("--human-signature", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        paths = P0BundleV6Paths(
            **{role: getattr(args, role) for role in P0_QUERY_V6_BUNDLE_FILE_ORDER}
        )
        draft = build_unsigned_p0_draft(
            paths,
            generation_id=args.generation_id,
            issued_at=_utc(args.issued_at, "issued_at"),
            valid_until=_utc(args.valid_until, "valid_until"),
            archived_at=_utc(args.archived_at, "archived_at"),
            signer_key_id=args.signer_key_id,
            reviewer_role=args.reviewer_role,
            human_signature=args.human_signature,
        )
        digest = write_unsigned_p0_draft(args.output, draft)
    except (OSError, P0BundleV6Error, ValueError) as exc:
        print(f"query-v6 P0 draft construction failed: {exc}", file=sys.stderr)
        return 2
    print(f"unsigned query-v6 P0 draft written: {args.output}")
    print(f"raw_sha256: {digest}")
    print("private_key_loaded: false")
    print("network_accessed: false")
    print("authority_granted: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
