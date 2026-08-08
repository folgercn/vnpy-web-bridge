from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.phase_b_offline_signer import (
    OfflineSignerError,
    _read_canonical,
    sign_request,
)
from shared.artifact_contracts import new_artifact_envelope
from shared.trust_contracts import (
    KEY_DOMAINS,
    ContractError,
    build_signing_request,
    validate_domain_keyrings,
    verify_signed_artifact,
)


def artifact(domain: str = "research", *, live: bool = False) -> dict:
    return new_artifact_envelope(
        artifact_type="acceptance-evidence",
        trust_domain=domain,
        producer_id="unit-test",
        producer_version="v1",
        schema_ref="test-schema-v1",
        payload={
            "result": "pass",
            "production": False,
            "live": live,
            "countable_forward": False,
        },
        generated_at="2026-08-05T00:00:00Z",
        scope={"production": False, "live": False, "countable_forward": False},
        predecessor_refs=[],
        lineage=[],
    )


def keyring(domain: str, private: Ed25519PrivateKey, suffix: str = "1") -> dict:
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "schema_version": "web-bridge-trust-keyring-v1",
        "domain": domain,
        "key_version": "v1",
        "keys": [
            {
                "key_id": f"{domain}-{suffix}",
                "domain": domain,
                "purpose": f"{domain}-only",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "status": "active",
            }
        ],
    }


def ephemeral_key_fd(
    tmp_path: Path, raw: bytes, *, writable: bool = False, unlink: bool = True
) -> int:
    path = tmp_path / "private-key"
    path.write_bytes(raw)
    path.chmod(0o600)
    fd = os.open(path, os.O_RDWR if writable else os.O_RDONLY)
    if unlink:
        path.unlink()
    return fd


def request(domain: str = "research", *, live: bool = False) -> dict:
    return build_signing_request(
        artifact(domain, live=live),
        domain=domain,
        key_id=f"{domain}-1",
        key_version="v1",
        request_id=f"request-{domain}-1",
        requested_at="2026-08-05T00:00:00Z",
        expires_at="2026-08-05T00:10:00Z",
    )


def test_all_five_domains_require_distinct_keys() -> None:
    rings = {
        domain: keyring(domain, Ed25519PrivateKey.generate()) for domain in KEY_DOMAINS
    }
    assert tuple(validate_domain_keyrings(rings)) == KEY_DOMAINS
    shared = Ed25519PrivateKey.generate()
    reused = {domain: keyring(domain, shared) for domain in KEY_DOMAINS}
    with pytest.raises(
        ContractError, match="TRUST_KEY_MATERIAL_CROSS_DOMAIN_COLLISION"
    ):
        validate_domain_keyrings(reused)


def test_offline_signer_accepts_only_ephemeral_readonly_fd_and_verifies(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ring = keyring("research", private)
    fd = ephemeral_key_fd(tmp_path, raw)
    try:
        signed = sign_request(
            request(),
            keyring=ring,
            key_fd=fd,
            key_sha256=hashlib.sha256(raw).hexdigest(),
            now=datetime(2026, 8, 5, 0, 5, tzinfo=timezone.utc),
        )
    finally:
        os.close(fd)
    assert (
        verify_signed_artifact(
            signed,
            keyring=ring,
            expected_domain="research",
            now=datetime(2026, 8, 5, 0, 5, tzinfo=timezone.utc),
        )
        == signed
    )
    assert signed["domain"] == "research"


@pytest.mark.parametrize(
    "writable,unlink,code",
    [
        (True, True, "SIGNER_KEY_FD_NOT_READ_ONLY"),
        (False, False, "SIGNER_KEY_FD_NOT_EPHEMERAL"),
    ],
)
def test_offline_signer_rejects_nonisolated_key_fd(
    tmp_path: Path,
    writable: bool,
    unlink: bool,
    code: str,
) -> None:
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    fd = ephemeral_key_fd(tmp_path, raw, writable=writable, unlink=unlink)
    try:
        with pytest.raises(OfflineSignerError, match=code):
            sign_request(
                request(),
                keyring=keyring("research", private),
                key_fd=fd,
                key_sha256=hashlib.sha256(raw).hexdigest(),
                now=datetime(2026, 8, 5, 0, 5, tzinfo=timezone.utc),
            )
    finally:
        os.close(fd)


def test_cross_domain_wrong_key_expired_and_authority_escalation_fail_closed(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    fd = ephemeral_key_fd(tmp_path, raw)
    try:
        with pytest.raises(OfflineSignerError, match="SIGNER_PRIVATE_KEY_MISMATCH"):
            sign_request(
                request(),
                keyring=keyring("research", other),
                key_fd=fd,
                key_sha256=hashlib.sha256(raw).hexdigest(),
                now=datetime(2026, 8, 5, 0, 5, tzinfo=timezone.utc),
            )
    finally:
        os.close(fd)
    fd = ephemeral_key_fd(tmp_path, raw)
    try:
        with pytest.raises(OfflineSignerError, match="SIGNER_REQUEST_OUTSIDE_VALIDITY"):
            sign_request(
                request(),
                keyring=keyring("research", private),
                key_fd=fd,
                key_sha256=hashlib.sha256(raw).hexdigest(),
                now=datetime(2026, 8, 5, 0, 11, tzinfo=timezone.utc),
            )
    finally:
        os.close(fd)
    with pytest.raises(ContractError, match="TRUST_AUTHORITY_FLAG_MUST_BE_FALSE"):
        request(live=True)


def test_unsealed_key_fd_requires_hash_pin(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    fd = ephemeral_key_fd(tmp_path, raw)
    try:
        with pytest.raises(OfflineSignerError, match="SIGNER_KEY_FD_PIN_REQUIRED"):
            sign_request(
                request(), keyring=keyring("research", private), key_fd=fd,
                now=datetime(2026, 8, 5, 0, 5, tzinfo=timezone.utc),
            )
        with pytest.raises(OfflineSignerError, match="SIGNER_KEY_HASH_MISMATCH"):
            sign_request(
                request(),
                keyring=keyring("research", private),
                key_fd=fd,
                key_sha256="0" * 64,
                now=datetime(2026, 8, 5, 0, 5, tzinfo=timezone.utc),
            )
    finally:
        os.close(fd)


def test_signer_request_path_requires_exact_hash_pin(tmp_path: Path) -> None:
    path = tmp_path / "request.json"
    raw = b'{"request":"pinned"}\n'
    path.write_bytes(raw)
    with pytest.raises(OfflineSignerError, match="SIGNER_REQUEST_PIN_REQUIRED"):
        _read_canonical(path)
    with pytest.raises(OfflineSignerError, match="SIGNER_REQUEST_HASH_MISMATCH"):
        _read_canonical(path, expected_sha256="0" * 64)
    assert _read_canonical(path, expected_sha256=hashlib.sha256(raw).hexdigest()) == {
        "request": "pinned"
    }


def test_signing_request_rejects_domain_confusion_and_unknown_fields() -> None:
    with pytest.raises(ContractError, match="SIGNING_REQUEST_ARTIFACT_DOMAIN_MISMATCH"):
        build_signing_request(
            artifact("research"),
        domain="execution_permit",
            key_id="permit-1",
            key_version="v1",
            request_id="request-1",
            requested_at="2026-08-05T00:00:00Z",
            expires_at="2026-08-05T00:10:00Z",
        )
    payload = request() | {"unsigned_extension": True}
    from shared.trust_contracts import validate_signing_request

    with pytest.raises(ContractError, match="SIGNING_REQUEST_FIELDS_INVALID"):
        validate_signing_request(payload)
