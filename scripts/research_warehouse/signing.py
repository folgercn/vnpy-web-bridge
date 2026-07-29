"""Independent Ed25519 manifest signing and verification."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json, sha256
from .errors import RegistryError
from .filesystem import read_regular_strict


def load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = read_regular_strict(path, "manifest signing key", limit=64)
    if len(raw) != 32:
        raise RegistryError("manifest signing key must contain 32 raw bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise RegistryError("manifest signing key is invalid") from exc


def load_public_key(path: Path) -> Ed25519PublicKey:
    encoded = read_regular_strict(
        path, "manifest public key", limit=128, private=False
    ).strip()
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RegistryError("manifest public key must be base64") from exc
    if len(raw) != 32:
        raise RegistryError("manifest public key must encode 32 raw bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise RegistryError("manifest public key is invalid") from exc


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_sha256(public_key: Ed25519PublicKey) -> str:
    return sha256(public_key_raw(public_key))


def sign_payload(
    payload: dict,
    private_key: Ed25519PrivateKey,
) -> dict:
    signed = dict(payload)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_json(payload))
    ).decode("ascii")
    return signed


def verify_payload(
    payload: dict,
    public_key: Ed25519PublicKey,
) -> dict:
    signature = payload.get("signature")
    if not isinstance(signature, str):
        raise RegistryError("signed payload has no signature")
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    try:
        decoded = base64.b64decode(signature, validate=True)
        public_key.verify(decoded, canonical_json(unsigned))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise RegistryError("manifest signature is invalid") from exc
    return unsigned
