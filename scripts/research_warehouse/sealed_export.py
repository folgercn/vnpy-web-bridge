"""Create and read-only verify one C_FAST nine-artifact sealed export."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN
from .sealed_export_contracts import (
    EXPORT_FALSE_AUTHORITY_FIELDS,
    MANIFEST_SCHEMA,
    PLACEHOLDER_SIGNATURE,
    PURPOSE,
    RECEIPT_SCHEMA,
    artifact_bindings,
    derive_export_id,
    false_authority,
    replay_exact_artifact_set,
    validate_artifact_set,
    validate_lineage,
)
from .sealed_export_crypto import (
    load_export_keyring,
    verify_export_signature,
)
from .sealed_export_custody import (
    create_and_publish_export,
    read_export_directory,
    read_source_artifacts,
    require_symlink_free_path,
)
from .signing import load_private_key, sign_payload
from .timeutil import format_utc, parse_utc, require_utc

MANIFEST_KEYS = {
    "schema_version",
    "export_id",
    "purpose",
    "created_at",
    "lineage_raw_sha256",
    "lineage_sha256",
    "lineage",
    "producer_replay",
    "artifact_index_sha256",
    "artifacts",
    "authority",
    "signer_key_id",
    "signer_public_key_sha256",
    "keyring_raw_sha256",
    "signature",
}
RECEIPT_KEYS = {
    "schema_version",
    "export_id",
    "purpose",
    "receipt_created_at",
    "manifest_filename",
    "manifest_raw_sha256",
    "artifact_index_sha256",
    "lineage_sha256",
    "authority",
    "signer_key_id",
    "signer_public_key_sha256",
    "keyring_raw_sha256",
    "signature",
}


@dataclass(frozen=True)
class VerifiedSealedExport:
    export_id: str
    output: Path
    receipt_raw_sha256: str
    manifest_raw_sha256: str
    artifact_index_sha256: str
    lineage: dict[str, str]
    artifact_raw: dict[str, bytes]


def _load_lineage(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> tuple[dict[str, str], str]:
    if (
        not isinstance(expected_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_raw_sha256) is None
    ):
        raise RegistryError("trusted sealed-export lineage SHA256 is invalid")
    raw = read_regular_strict(path, "sealed export lineage", limit=1024 * 1024)
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("sealed export lineage raw hash mismatch")
    payload = parse_json_strict(raw, "sealed export lineage")
    if not isinstance(payload, dict) or canonical_json_line(payload) != raw:
        raise RegistryError("sealed export lineage is not canonical JSON line")
    return validate_lineage(payload), sha256(canonical_json(payload))


def _require_authority(value: object) -> None:
    expected = false_authority()
    if value != expected or set(expected) != set(EXPORT_FALSE_AUTHORITY_FIELDS):
        raise RegistryError("sealed export authority must remain all false")


def _validate_manifest_shape(payload: object) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or set(payload) != MANIFEST_KEYS
        or payload["schema_version"] != MANIFEST_SCHEMA
        or payload["purpose"] != PURPOSE
    ):
        raise RegistryError("sealed export manifest contract mismatch")
    _require_authority(payload["authority"])
    parse_utc(payload["created_at"], "sealed export created_at")
    return payload


def _validate_receipt_shape(payload: object) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or set(payload) != RECEIPT_KEYS
        or payload["schema_version"] != RECEIPT_SCHEMA
        or payload["purpose"] != PURPOSE
        or payload["manifest_filename"] != "sealed-export-manifest.json"
    ):
        raise RegistryError("sealed export receipt contract mismatch")
    _require_authority(payload["authority"])
    parse_utc(
        payload["receipt_created_at"],
        "sealed export receipt_created_at",
    )
    return payload


def create_sealed_export(
    *,
    artifact_paths: dict[str, Path],
    source_view_path: Path,
    lineage_path: Path,
    expected_lineage_raw_sha256: str,
    keyring_path: Path,
    expected_keyring_raw_sha256: str,
    signer_key_id: str,
    private_key_path: Path,
    export_root: Path,
    now: datetime,
) -> VerifiedSealedExport:
    created_at = require_utc(now, "sealed export created_at")
    require_symlink_free_path(lineage_path, "sealed export lineage")
    require_symlink_free_path(source_view_path, "sealed export source view")
    require_symlink_free_path(keyring_path, "sealed export keyring")
    require_symlink_free_path(private_key_path, "sealed export private key")
    artifact_raw = read_source_artifacts(artifact_paths)
    source_view_raw = read_regular_strict(
        source_view_path,
        "sealed export source view",
        limit=16 * 1024 * 1024,
    )
    lineage, lineage_sha = _load_lineage(
        lineage_path,
        expected_raw_sha256=expected_lineage_raw_sha256,
    )
    payloads = validate_artifact_set(artifact_raw, lineage=lineage)
    producer_replay = replay_exact_artifact_set(
        source_view_raw,
        artifact_raw,
        lineage=lineage,
    )
    generated_at = max(
        datetime.fromisoformat(
            str(payload["generated_at"]).replace("Z", "+00:00")
        )
        for payload in payloads.values()
    )
    if (
        created_at < parse_utc(lineage["pit_cutoff_at"], "sealed export PIT cutoff")
        or created_at < generated_at
    ):
        raise RegistryError("sealed export was created before its source facts")
    trusted_key = load_export_keyring(
        keyring_path,
        expected_raw_sha256=expected_keyring_raw_sha256,
        key_id=signer_key_id,
    )
    bindings = artifact_bindings(
        artifact_raw,
        lineage_sha256=lineage_sha,
        pit_cutoff_at=lineage["pit_cutoff_at"],
    )
    artifact_index = sha256(canonical_json(bindings))
    unsigned_manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "export_id": "",
        "purpose": PURPOSE,
        "created_at": format_utc(created_at, "sealed export created_at"),
        "lineage_raw_sha256": expected_lineage_raw_sha256,
        "lineage_sha256": lineage_sha,
        "lineage": lineage,
        "producer_replay": producer_replay,
        "artifact_index_sha256": artifact_index,
        "artifacts": bindings,
        "authority": false_authority(),
        "signer_key_id": trusted_key.key_id,
        "signer_public_key_sha256": trusted_key.public_key_sha256,
        "keyring_raw_sha256": trusted_key.keyring_raw_sha256,
    }
    unsigned_manifest["export_id"] = derive_export_id(unsigned_manifest)
    candidate = {**unsigned_manifest, "signature": PLACEHOLDER_SIGNATURE}
    _validate_manifest_shape(candidate)
    private_key = load_private_key(private_key_path)
    actual_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    trusted_public = trusted_key.public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if actual_public != trusted_public:
        raise RegistryError("sealed export private key is not trusted")
    manifest = sign_payload(unsigned_manifest, private_key)
    verify_export_signature(manifest, trusted_key=trusted_key)
    manifest_raw = canonical_json_line(manifest)
    unsigned_receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "export_id": manifest["export_id"],
        "purpose": PURPOSE,
        "receipt_created_at": format_utc(
            created_at,
            "sealed export receipt_created_at",
        ),
        "manifest_filename": "sealed-export-manifest.json",
        "manifest_raw_sha256": sha256(manifest_raw),
        "artifact_index_sha256": artifact_index,
        "lineage_sha256": lineage_sha,
        "authority": false_authority(),
        "signer_key_id": trusted_key.key_id,
        "signer_public_key_sha256": trusted_key.public_key_sha256,
        "keyring_raw_sha256": trusted_key.keyring_raw_sha256,
    }
    receipt = sign_payload(unsigned_receipt, private_key)
    _validate_receipt_shape(receipt)
    verify_export_signature(receipt, trusted_key=trusted_key)
    receipt_raw = canonical_json_line(receipt)
    output = create_and_publish_export(
        export_root,
        manifest["export_id"],
        artifact_raw=artifact_raw,
        manifest_raw=manifest_raw,
        receipt_raw=receipt_raw,
    )
    return verify_sealed_export(
        output=output,
        keyring_path=keyring_path,
        expected_keyring_raw_sha256=expected_keyring_raw_sha256,
        expected_receipt_raw_sha256=sha256(receipt_raw),
    )


def verify_sealed_export(
    *,
    output: Path,
    keyring_path: Path,
    expected_keyring_raw_sha256: str,
    expected_receipt_raw_sha256: str,
) -> VerifiedSealedExport:
    if (
        not isinstance(expected_receipt_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_receipt_raw_sha256) is None
    ):
        raise RegistryError("trusted sealed export receipt SHA256 is invalid")
    artifact_raw, manifest_raw, receipt_raw = read_export_directory(output)
    require_symlink_free_path(keyring_path, "sealed export keyring")
    if sha256(receipt_raw) != expected_receipt_raw_sha256:
        raise RegistryError("sealed export receipt hash mismatch")
    receipt = _validate_receipt_shape(
        parse_json_strict(receipt_raw, "sealed export receipt")
    )
    if canonical_json_line(receipt) != receipt_raw:
        raise RegistryError("sealed export receipt is not canonical")
    trusted_key = load_export_keyring(
        keyring_path,
        expected_raw_sha256=expected_keyring_raw_sha256,
        key_id=receipt["signer_key_id"],
    )
    verify_export_signature(receipt, trusted_key=trusted_key)
    if receipt["manifest_raw_sha256"] != sha256(manifest_raw):
        raise RegistryError("sealed export manifest hash mismatch")
    manifest = _validate_manifest_shape(
        parse_json_strict(manifest_raw, "sealed export manifest")
    )
    if canonical_json_line(manifest) != manifest_raw:
        raise RegistryError("sealed export manifest is not canonical")
    verify_export_signature(manifest, trusted_key=trusted_key)
    if (
        receipt["export_id"] != manifest["export_id"]
        or receipt["artifact_index_sha256"]
        != manifest["artifact_index_sha256"]
        or receipt["lineage_sha256"] != manifest["lineage_sha256"]
        or output.name != manifest["export_id"]
        or derive_export_id(manifest) != manifest["export_id"]
    ):
        raise RegistryError("sealed export manifest/receipt identity mismatch")
    lineage = validate_lineage(manifest["lineage"])
    if sha256(canonical_json(lineage)) != manifest["lineage_sha256"]:
        raise RegistryError("sealed export lineage hash mismatch")
    replay = manifest["producer_replay"]
    if (
        not isinstance(replay, dict)
        or set(replay)
        != {
            "status",
            "producer_kernel_id",
            "source_view_raw_sha256",
            "source_view_canonical_sha256",
        }
        or replay["status"] != "EXACT_NINE_ARTIFACT_REPLAY_VERIFIED"
        or replay["producer_kernel_id"]
        != "commodity_c_fast_pure_producer_kernel_v1"
        or SHA256_PATTERN.fullmatch(str(replay["source_view_raw_sha256"]))
        is None
        or replay["source_view_canonical_sha256"]
        != lineage["source_view_canonical_sha256"]
    ):
        raise RegistryError("sealed export producer replay claim mismatch")
    payloads = validate_artifact_set(artifact_raw, lineage=lineage)
    created_at = parse_utc(manifest["created_at"], "sealed export created_at")
    if created_at < parse_utc(lineage["pit_cutoff_at"], "sealed export PIT cutoff"):
        raise RegistryError("sealed export manifest predates PIT cutoff")
    if any(
        created_at
        < datetime.fromisoformat(
            str(payload["generated_at"]).replace("Z", "+00:00")
        )
        for payload in payloads.values()
    ):
        raise RegistryError("sealed export manifest predates producer artifacts")
    expected_bindings = artifact_bindings(
        artifact_raw,
        lineage_sha256=manifest["lineage_sha256"],
        pit_cutoff_at=lineage["pit_cutoff_at"],
    )
    if (
        manifest["artifacts"] != expected_bindings
        or sha256(canonical_json(expected_bindings))
        != manifest["artifact_index_sha256"]
    ):
        raise RegistryError("sealed export exact artifact binding mismatch")
    if parse_utc(
        receipt["receipt_created_at"],
        "sealed export receipt_created_at",
    ) < parse_utc(manifest["created_at"], "sealed export created_at"):
        raise RegistryError("sealed export receipt predates manifest")
    return VerifiedSealedExport(
        export_id=manifest["export_id"],
        output=output,
        receipt_raw_sha256=expected_receipt_raw_sha256,
        manifest_raw_sha256=sha256(manifest_raw),
        artifact_index_sha256=manifest["artifact_index_sha256"],
        lineage=lineage,
        artifact_raw=artifact_raw,
    )
