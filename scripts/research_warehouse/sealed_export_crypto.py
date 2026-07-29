"""Independent keyring and Ed25519 checks for sealed exports."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN
from .sealed_export_contracts import (
    KEYRING_SCHEMA,
    SIGNING_PURPOSE,
    validate_signer_id,
)
from .signing import public_key_sha256, verify_payload

KEYRING_KEYS = {"schema_version", "keyring_id", "purpose", "keys"}
KEY_KEYS = {
    "key_id",
    "algorithm",
    "public_key_base64",
    "public_key_sha256",
    "enabled",
}


@dataclass(frozen=True)
class TrustedExportKey:
    key_id: str
    public_key: Ed25519PublicKey
    public_key_sha256: str
    keyring_raw_sha256: str


def load_export_keyring(
    path: Path,
    *,
    expected_raw_sha256: str,
    key_id: str,
) -> TrustedExportKey:
    if (
        not isinstance(expected_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_raw_sha256) is None
    ):
        raise RegistryError("trusted export keyring SHA256 is invalid")
    requested = validate_signer_id(key_id)
    raw = read_regular_strict(path, "sealed export keyring", limit=1024 * 1024)
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("sealed export keyring hash mismatch")
    payload = parse_json_strict(raw, "sealed export keyring")
    if (
        not isinstance(payload, dict)
        or set(payload) != KEYRING_KEYS
        or payload["schema_version"] != KEYRING_SCHEMA
        or payload["purpose"] != SIGNING_PURPOSE
        or raw != canonical_json_line(payload)
        or not isinstance(payload["keys"], list)
        or not payload["keys"]
    ):
        raise RegistryError("sealed export keyring contract mismatch")
    validate_signer_id(payload["keyring_id"])
    matches = []
    seen = set()
    for item in payload["keys"]:
        if not isinstance(item, dict) or set(item) != KEY_KEYS:
            raise RegistryError("sealed export key fields do not match v1")
        current_id = validate_signer_id(item["key_id"])
        if current_id in seen:
            raise RegistryError("sealed export keyring repeats a key ID")
        seen.add(current_id)
        if (
            item["algorithm"] != "Ed25519"
            or not isinstance(item["enabled"], bool)
            or not isinstance(item["public_key_sha256"], str)
            or SHA256_PATTERN.fullmatch(item["public_key_sha256"]) is None
        ):
            raise RegistryError("sealed export key contract is invalid")
        try:
            decoded = base64.b64decode(
                item["public_key_base64"],
                validate=True,
            )
            public = Ed25519PublicKey.from_public_bytes(decoded)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise RegistryError("sealed export public key is invalid") from exc
        if len(decoded) != 32 or public_key_sha256(public) != item["public_key_sha256"]:
            raise RegistryError("sealed export public-key binding mismatch")
        if current_id == requested and item["enabled"]:
            matches.append((public, item["public_key_sha256"]))
    if len(matches) != 1:
        raise RegistryError("sealed export signer is not uniquely trusted")
    public, digest = matches[0]
    return TrustedExportKey(
        key_id=requested,
        public_key=public,
        public_key_sha256=digest,
        keyring_raw_sha256=expected_raw_sha256,
    )


def verify_export_signature(
    payload: dict,
    *,
    trusted_key: TrustedExportKey,
) -> None:
    if (
        payload.get("signer_key_id") != trusted_key.key_id
        or payload.get("signer_public_key_sha256")
        != trusted_key.public_key_sha256
        or payload.get("keyring_raw_sha256")
        != trusted_key.keyring_raw_sha256
    ):
        raise RegistryError("sealed export signer/keyring binding mismatch")
    verify_payload(payload, trusted_key.public_key)
