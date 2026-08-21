"""Signed, read-only Docker projection attestation for the #362 runner.

This is deliberately not a custody identity.  Physical custody continues to
use :mod:`custody_transition`; this receipt only authorizes one immutable,
read-only container view to *read* legacy observations from that custody.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .backup_contracts import false_authority, require_identifier, require_sha256
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .custody_paths import CustodyTransitionTrust, WarehousePaths
from .custody_transition import _read_root_managed_transition_receipt
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_acl_custody import require_acl_free_fd
from .m2_operator_defaults import BACKUP_SIGNER_KEY_ID
from .m2_runtime_input import require_root_managed
from .signing import load_public_key, public_key_sha256, sign_payload, verify_payload
from .timeutil import format_utc, parse_utc, require_utc

PROJECTED_ROOT_SCHEMA = "vnpy_research_readonly_projected_root_attestation_v1"
PROJECTED_ROOT_DOMAIN = "vnpy-research-readonly-projected-root-attestation-v1"
PROJECTED_ROOT_KEYS = {
    "schema_version", "attestation_id", "attested_at",
    "source_root_path", "source_stable_identity_sha256",
    "source_transition_id", "source_transition_raw_sha256",
    "projection_root_path", "projection_st_dev", "projection_st_ino",
    "projection_uid", "projection_gid", "projection_mode", "projection_only",
    "mutation_authorized", "publication_authorized", "recovery_authorized",
    "trading_authorized", "signer_key_id", "signer_public_key_sha256",
    "authority", "signature",
}


def _attestation_id(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    unsigned["attestation_id"] = ""
    return "readonly-projected-root-" + sha256(
        canonical_json({"domain": PROJECTED_ROOT_DOMAIN, "payload": unsigned})
    )


def _stat_fields(info: os.stat_result) -> dict[str, int]:
    return {
        "projection_st_dev": info.st_dev,
        "projection_st_ino": info.st_ino,
        "projection_uid": info.st_uid,
        "projection_gid": info.st_gid,
        "projection_mode": stat.S_IMODE(info.st_mode),
    }


def _validate_root_managed_attestation_fd(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o444
    ):
        raise RegistryError("projected root attestation root custody is unsafe")
    require_acl_free_fd(descriptor, "projected root attestation")


def _read_attestation(path: Path) -> bytes:
    require_root_managed(path)
    return read_regular_strict(
        path, "projected root attestation", limit=1024 * 1024, private=False,
        descriptor_validator=_validate_root_managed_attestation_fd,
    )


def build_readonly_projected_root_attestation(
    *, physical_paths: WarehousePaths, transition_trust: CustodyTransitionTrust,
    projection_root: Path, projection_info: os.stat_result, signer_key_id: str, private_key: Ed25519PrivateKey,
    attested_at: datetime,
) -> dict[str, Any]:
    """Sign the root-observed identity of one already-mounted projection."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RegistryError("projected root signing key is invalid")
    if (
        require_identifier(signer_key_id, "projected root signer key ID")
        != BACKUP_SIGNER_KEY_ID
    ):
        raise RegistryError("projected root signer key ID is not the pinned backup signer")
    transition_raw = _read_root_managed_transition_receipt(transition_trust)
    transition = parse_json_strict(transition_raw, "custody reboot transition receipt")
    if not isinstance(transition, dict):
        raise RegistryError("custody transition receipt is invalid")
    # Physical verification is intentionally required at issuance, before a
    # projection can be authorized.  Import locally to avoid a module cycle.
    from .custody_transition import verify_custody_transition

    verified = verify_custody_transition(physical_paths, transition_trust)
    if transition != verified:
        raise RegistryError("custody transition changed while being attested")
    root = projection_root.expanduser()
    if not root.is_absolute() or str(root) != os.path.normpath(str(root)):
        raise RegistryError("projection root logical path is unsafe")
    if not stat.S_ISDIR(projection_info.st_mode):
        raise RegistryError("projection root is not a directory")
    payload: dict[str, Any] = {
        "schema_version": PROJECTED_ROOT_SCHEMA,
        "attestation_id": "",
        "attested_at": format_utc(require_utc(attested_at, "attested_at"), "attested_at"),
        "source_root_path": str(physical_paths.root),
        "source_stable_identity_sha256": verified["stable_identity_sha256"],
        "source_transition_id": verified["transition_id"],
        "source_transition_raw_sha256": sha256(transition_raw),
        "projection_root_path": str(root),
        **_stat_fields(projection_info),
        "projection_only": True,
        "mutation_authorized": False,
        "publication_authorized": False,
        "recovery_authorized": False,
        "trading_authorized": False,
        "signer_key_id": signer_key_id,
        "signer_public_key_sha256": public_key_sha256(private_key.public_key()),
        "authority": false_authority(),
    }
    payload["attestation_id"] = _attestation_id(payload)
    return sign_payload(payload, private_key)


def _verify_transition_source(
    trust: CustodyTransitionTrust, payload: dict[str, Any]
) -> dict[str, Any]:
    """Verify exact signed transition bytes without treating projection as physical."""
    raw = _read_root_managed_transition_receipt(trust)
    transition = parse_json_strict(raw, "custody reboot transition receipt")
    if not isinstance(transition, dict):
        raise RegistryError("custody transition receipt is invalid")
    # Reuse its normal signature/pin contract; do not call the physical-root
    # verifier here because the caller is deliberately a projection.
    from .custody_transition import TRANSITION_KEYS, TRANSITION_SCHEMA, _transition_id

    if set(transition) != TRANSITION_KEYS or transition.get("schema_version") != TRANSITION_SCHEMA:
        raise RegistryError("custody transition fields do not match v1")
    public_key = load_public_key(trust.public_key_path)
    expected = require_sha256(trust.expected_public_key_sha256, "trusted custody transition public key")
    if public_key_sha256(public_key) != expected or transition.get("signer_public_key_sha256") != expected:
        raise RegistryError("custody transition signer public key pin mismatch")
    unsigned = verify_payload(transition, public_key)
    if transition.get("transition_id") != _transition_id(unsigned) or raw != canonical_json_line(transition):
        raise RegistryError("custody transition receipt binding mismatch")
    if (
        payload["source_transition_id"] != transition["transition_id"]
        or payload["source_transition_raw_sha256"] != sha256(raw)
        or payload["source_stable_identity_sha256"] != transition["stable_identity_sha256"]
        or payload["source_root_path"] != transition["root_path"]
    ):
        raise RegistryError("projected root source transition binding mismatch")
    return transition


def verify_readonly_projected_root_attestation(
    *, paths: WarehousePaths, attestation_path: Path,
    transition_trust: CustodyTransitionTrust, public_key_path: Path,
    expected_public_key_sha256: str,
) -> dict[str, Any]:
    """Verify one projection, without allowing it to become physical custody."""
    raw = _read_attestation(attestation_path)
    payload = parse_json_strict(raw, "projected root attestation")
    if not isinstance(payload, dict) or set(payload) != PROJECTED_ROOT_KEYS:
        raise RegistryError("projected root attestation fields do not match v1")
    if payload.get("schema_version") != PROJECTED_ROOT_SCHEMA or raw != canonical_json_line(payload):
        raise RegistryError("projected root attestation schema/canonical mismatch")
    if (
        payload.get("projection_only") is not True
        or any(payload.get(field) is not False for field in (
            "mutation_authorized", "publication_authorized", "recovery_authorized", "trading_authorized"
        ))
        or payload.get("authority") != false_authority()
    ):
        raise RegistryError("projected root attestation grants authority")
    parse_utc(payload["attested_at"], "projected root attested_at")
    if (
        require_identifier(payload.get("signer_key_id"), "projected root signer key ID")
        != BACKUP_SIGNER_KEY_ID
    ):
        raise RegistryError("projected root signer key ID is not the pinned backup signer")
    expected = require_sha256(expected_public_key_sha256, "trusted projected root public key")
    public_key = load_public_key(public_key_path)
    if public_key_sha256(public_key) != expected or payload.get("signer_public_key_sha256") != expected:
        raise RegistryError("projected root signer public key pin mismatch")
    unsigned = verify_payload(payload, public_key)
    if payload.get("attestation_id") != _attestation_id(unsigned):
        raise RegistryError("projected root attestation ID binding mismatch")
    _verify_transition_source(transition_trust, payload)
    info = paths.root.lstat()
    if (
        payload["projection_root_path"] != str(paths.root)
        or any(payload[key] != value for key, value in _stat_fields(info).items())
    ):
        raise RegistryError("projected root identity binding mismatch")
    try:
        flags = os.statvfs(paths.root).f_flag
    except OSError as exc:
        raise RegistryError("projected root mount facts are unavailable") from exc
    if not flags & getattr(os, "ST_RDONLY", 1):
        raise RegistryError("projected root mount is writable")
    return payload


def projected_root_authorized_legacy_identities(
    *,
    paths: WarehousePaths,
    attestation_path: Path,
    transition_trust: CustodyTransitionTrust,
    public_key_path: Path,
    expected_public_key_sha256: str,
) -> frozenset[str]:
    """Return only the two signed v1 identities authorized for this view."""
    payload = verify_readonly_projected_root_attestation(
        paths=paths,
        attestation_path=attestation_path,
        transition_trust=transition_trust,
        public_key_path=public_key_path,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    transition = _verify_transition_source(transition_trust, payload)
    return frozenset(
        {
            transition["source_legacy_identity_sha256"],
            transition["destination_legacy_identity_sha256"],
        }
    )
