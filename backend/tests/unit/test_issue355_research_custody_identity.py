# ruff: noqa: E402
from __future__ import annotations

import base64
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse.canonical import canonical_json_line
from research_warehouse.custody_locks import (
    custody_identity,
    legacy_custody_identity_for_device,
    stable_custody_identity,
)
from research_warehouse.custody_paths import (
    CustodyTransitionTrust,
    WarehousePaths,
)
from research_warehouse.custody_transition import (
    build_custody_transition,
    legacy_custody_identity_is_authorized,
    verify_custody_transition,
)
from research_warehouse.errors import RegistryError
from research_warehouse.signing import public_key_sha256

ATTESTED_AT = datetime(2026, 8, 17, 5, 0, tzinfo=timezone.utc)


def _public_key_file(tmp_path: Path, private_key: Ed25519PrivateKey) -> Path:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    path = tmp_path / "backup-public-key.b64"
    path.write_bytes(base64.b64encode(raw) + b"\n")
    path.chmod(0o444)
    return path


def _transition_fixture(tmp_path: Path):
    paths = WarehousePaths.initialize(tmp_path / "warehouse")
    private_key = Ed25519PrivateKey.generate()
    public_key_path = _public_key_file(tmp_path, private_key)
    current_device = paths.root.lstat().st_dev
    source_device = current_device + 17
    source_identity = legacy_custody_identity_for_device(paths, source_device)
    destination_identity = custody_identity(paths)
    payload = build_custody_transition(
        paths=paths,
        source_st_dev=source_device,
        expected_source_legacy_identity_sha256=source_identity,
        expected_destination_legacy_identity_sha256=destination_identity,
        signer_key_id="m2-backup-prod-test",
        private_key=private_key,
        attested_at=ATTESTED_AT,
    )
    receipt_path = tmp_path / "custody-transition-v1.json"
    receipt_path.write_bytes(canonical_json_line(payload))
    receipt_path.chmod(0o444)
    trust = CustodyTransitionTrust(
        receipt_path=receipt_path,
        public_key_path=public_key_path,
        expected_public_key_sha256=public_key_sha256(private_key.public_key()),
    )
    trusted_paths = WarehousePaths.open(
        paths.root,
        custody_transition=trust,
    )
    return (
        paths,
        trusted_paths,
        trust,
        payload,
        source_identity,
        destination_identity,
    )


def test_missing_transition_keeps_legacy_device_drift_fail_closed(tmp_path: Path) -> None:
    paths = WarehousePaths.initialize(tmp_path / "warehouse")
    unrelated = legacy_custody_identity_for_device(
        paths,
        paths.root.lstat().st_dev + 1,
    )

    assert legacy_custody_identity_is_authorized(paths, custody_identity(paths))
    assert not legacy_custody_identity_is_authorized(paths, unrelated)


def test_signed_transition_authorizes_only_reviewed_legacy_identities(
    tmp_path: Path,
) -> None:
    (
        _paths,
        trusted_paths,
        trust,
        payload,
        source_identity,
        destination_identity,
    ) = _transition_fixture(tmp_path)

    verified = verify_custody_transition(trusted_paths, trust)

    assert verified["transition_id"] == payload["transition_id"]
    assert verified["stable_identity_sha256"] == stable_custody_identity(trusted_paths)
    assert legacy_custody_identity_is_authorized(trusted_paths, source_identity)
    assert legacy_custody_identity_is_authorized(trusted_paths, destination_identity)
    assert not legacy_custody_identity_is_authorized(
        trusted_paths,
        legacy_custody_identity_for_device(
            trusted_paths,
            trusted_paths.root.lstat().st_dev + 999,
        ),
    )


def test_tampered_transition_is_rejected(tmp_path: Path) -> None:
    paths, _trusted_paths, trust, payload, _source, _destination = _transition_fixture(
        tmp_path
    )
    tampered = dict(payload)
    tampered["source_st_dev"] += 1
    trust.receipt_path.chmod(0o644)
    trust.receipt_path.write_bytes(canonical_json_line(tampered))
    trust.receipt_path.chmod(0o444)
    tampered_paths = WarehousePaths.open(paths.root, custody_transition=trust)

    with pytest.raises(RegistryError, match="signature"):
        verify_custody_transition(tampered_paths, trust)


def test_transition_replay_on_unrelated_root_is_rejected(tmp_path: Path) -> None:
    _paths, _trusted_paths, trust, _payload, _source, _destination = _transition_fixture(
        tmp_path
    )
    unrelated = WarehousePaths.initialize(tmp_path / "unrelated-warehouse")
    replayed = WarehousePaths.open(unrelated.root, custody_transition=trust)

    with pytest.raises(RegistryError, match="stable root binding mismatch"):
        verify_custody_transition(replayed, trust)


def test_transition_rejects_unreviewed_destination_identity(tmp_path: Path) -> None:
    paths = WarehousePaths.initialize(tmp_path / "warehouse")
    private_key = Ed25519PrivateKey.generate()
    source_device = paths.root.lstat().st_dev + 7
    source_identity = legacy_custody_identity_for_device(paths, source_device)
    unrelated_destination = "0" * 64

    with pytest.raises(RegistryError, match="destination identity does not match review"):
        build_custody_transition(
            paths=paths,
            source_st_dev=source_device,
            expected_source_legacy_identity_sha256=source_identity,
            expected_destination_legacy_identity_sha256=unrelated_destination,
            signer_key_id="m2-backup-prod-test",
            private_key=private_key,
            attested_at=ATTESTED_AT,
        )


def test_transition_payload_binds_both_devices_to_stable_identity(
    tmp_path: Path,
) -> None:
    paths, _trusted_paths, _trust, payload, source_identity, destination_identity = (
        _transition_fixture(tmp_path)
    )

    assert payload["source_legacy_identity_sha256"] == source_identity
    assert payload["destination_legacy_identity_sha256"] == destination_identity
    assert payload["source_st_dev"] != payload["destination_st_dev"]
    assert payload["stable_identity_sha256"] == stable_custody_identity(paths)
    assert payload["root_path"] == str(paths.root)
    assert payload["inode"] == paths.root.lstat().st_ino
    assert all(value is False for value in payload["authority"].values())
