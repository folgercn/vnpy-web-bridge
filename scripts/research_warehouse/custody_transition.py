"""Signed continuity evidence for legacy device-bound custody identities."""

from __future__ import annotations

import stat
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .backup_contracts import (
    false_authority,
    require_identifier,
    require_sha256,
)
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .custody_locks import (
    custody_identity,
    legacy_custody_identity_for_device,
    stable_custody_identity,
)
from .custody_paths import CustodyTransitionTrust, WarehousePaths
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .signing import load_public_key, public_key_sha256, sign_payload, verify_payload
from .timeutil import format_utc, parse_utc, require_utc

TRANSITION_SCHEMA = "vnpy_research_custody_reboot_transition_v1"
TRANSITION_DOMAIN = "vnpy-research-custody-reboot-transition-v1"
TRANSITION_KEYS = {
    "schema_version",
    "transition_id",
    "attested_at",
    "root_path",
    "source_st_dev",
    "destination_st_dev",
    "inode",
    "uid",
    "gid",
    "mode",
    "source_legacy_identity_sha256",
    "destination_legacy_identity_sha256",
    "stable_identity_sha256",
    "signer_key_id",
    "signer_public_key_sha256",
    "authority",
    "signature",
}


def _transition_id(payload: dict[str, Any]) -> str:
    value = {
        key: item
        for key, item in payload.items()
        if key != "signature"
    }
    value["transition_id"] = ""
    return "custody-transition-" + sha256(
        canonical_json({"domain": TRANSITION_DOMAIN, "payload": value})
    )


def build_custody_transition(
    *,
    paths: WarehousePaths,
    source_st_dev: int,
    expected_source_legacy_identity_sha256: str,
    expected_destination_legacy_identity_sha256: str,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
    attested_at: datetime,
) -> dict[str, Any]:
    """Attest one reviewed APFS device drift into the stable v2 identity."""
    if not isinstance(source_st_dev, int) or isinstance(source_st_dev, bool):
        raise RegistryError("custody transition source device is invalid")
    if source_st_dev < 0:
        raise RegistryError("custody transition source device is invalid")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RegistryError("custody transition signing key is invalid")
    reviewed_source = require_sha256(
        expected_source_legacy_identity_sha256,
        "reviewed custody transition source identity",
    )
    reviewed_destination = require_sha256(
        expected_destination_legacy_identity_sha256,
        "reviewed custody transition destination identity",
    )
    trusted_signer_key_id = require_identifier(
        signer_key_id,
        "custody transition signer key ID",
    )
    info = paths.root.lstat()
    if source_st_dev == info.st_dev:
        raise RegistryError("custody transition must change legacy device identity")
    source_identity = legacy_custody_identity_for_device(paths, source_st_dev)
    destination_identity = custody_identity(paths)
    if source_identity != reviewed_source:
        raise RegistryError("custody transition source identity does not match review")
    if destination_identity != reviewed_destination:
        raise RegistryError("custody transition destination identity does not match review")
    stable_identity = stable_custody_identity(paths)
    public_hash = public_key_sha256(private_key.public_key())
    unsigned: dict[str, Any] = {
        "schema_version": TRANSITION_SCHEMA,
        "transition_id": "",
        "attested_at": format_utc(require_utc(attested_at, "attested_at"), "attested_at"),
        "root_path": str(paths.root),
        "source_st_dev": source_st_dev,
        "destination_st_dev": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "source_legacy_identity_sha256": source_identity,
        "destination_legacy_identity_sha256": destination_identity,
        "stable_identity_sha256": stable_identity,
        "signer_key_id": trusted_signer_key_id,
        "signer_public_key_sha256": public_hash,
        "authority": false_authority(),
    }
    unsigned["transition_id"] = _transition_id(unsigned)
    return sign_payload(unsigned, private_key)


def verify_custody_transition(
    paths: WarehousePaths,
    trust: CustodyTransitionTrust,
) -> dict[str, Any]:
    """Verify a root-pinned signed transition against the current stable root."""
    raw = read_regular_strict(
        trust.receipt_path,
        "custody reboot transition receipt",
        limit=1024 * 1024,
        private=False,
    )
    payload = parse_json_strict(raw, "custody reboot transition receipt")
    if not isinstance(payload, dict) or set(payload) != TRANSITION_KEYS:
        raise RegistryError("custody transition fields do not match v1")
    if payload["schema_version"] != TRANSITION_SCHEMA:
        raise RegistryError("custody transition schema mismatch")
    if payload["authority"] != false_authority():
        raise RegistryError("custody transition grants authority")
    trusted_hash = require_sha256(
        trust.expected_public_key_sha256,
        "trusted custody transition public key",
    )
    public_key = load_public_key(trust.public_key_path)
    require_identifier(payload["signer_key_id"], "custody transition signer key ID")
    claimed_signer_hash = require_sha256(
        payload["signer_public_key_sha256"],
        "custody transition signer public key",
    )
    if (
        public_key_sha256(public_key) != trusted_hash
        or claimed_signer_hash != trusted_hash
    ):
        raise RegistryError("custody transition signer public key pin mismatch")
    unsigned = verify_payload(payload, public_key)
    if payload["transition_id"] != _transition_id(unsigned):
        raise RegistryError("custody transition ID binding mismatch")
    if raw != canonical_json_line(payload):
        raise RegistryError("custody transition receipt is not canonical JSON")
    parse_utc(payload["attested_at"], "custody transition attested_at")
    info = paths.root.lstat()
    expected_stable = stable_custody_identity(paths)
    claimed_source_identity = require_sha256(
        payload["source_legacy_identity_sha256"],
        "custody transition source legacy identity",
    )
    claimed_destination_identity = require_sha256(
        payload["destination_legacy_identity_sha256"],
        "custody transition destination legacy identity",
    )
    claimed_stable_identity = require_sha256(
        payload["stable_identity_sha256"],
        "custody transition stable identity",
    )
    if (
        payload["root_path"] != str(paths.root)
        or payload["inode"] != info.st_ino
        or payload["uid"] != info.st_uid
        or payload["gid"] != info.st_gid
        or payload["mode"] != stat.S_IMODE(info.st_mode)
        or claimed_stable_identity != expected_stable
    ):
        raise RegistryError("custody transition stable root binding mismatch")
    source_device = payload["source_st_dev"]
    destination_device = payload["destination_st_dev"]
    if (
        not isinstance(source_device, int)
        or isinstance(source_device, bool)
        or source_device < 0
        or not isinstance(destination_device, int)
        or isinstance(destination_device, bool)
        or destination_device < 0
        or source_device == destination_device
    ):
        raise RegistryError("custody transition device binding is invalid")
    if claimed_source_identity != legacy_custody_identity_for_device(
        paths, source_device
    ):
        raise RegistryError("custody transition source legacy identity mismatch")
    if claimed_destination_identity != legacy_custody_identity_for_device(
        paths, destination_device
    ):
        raise RegistryError("custody transition destination legacy identity mismatch")
    return payload


def legacy_custody_identity_is_authorized(
    paths: WarehousePaths,
    claimed_identity_sha256: str,
) -> bool:
    """Accept legacy identity only directly or through explicit signed continuity."""
    if claimed_identity_sha256 == custody_identity(paths):
        return True
    trust = paths.custody_transition
    if trust is None:
        return False
    receipt = verify_custody_transition(paths, trust)
    return claimed_identity_sha256 in {
        receipt["source_legacy_identity_sha256"],
        receipt["destination_legacy_identity_sha256"],
    }
