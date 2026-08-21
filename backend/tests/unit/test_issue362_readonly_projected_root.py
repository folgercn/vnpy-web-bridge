"""#362: a Docker view may be authorized to read, never to be custody."""

from __future__ import annotations

import base64
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import custody_transition as transition_module
from research_warehouse import m2_runtime_loader
from research_warehouse import readonly_projected_root as projected
from research_warehouse.acquisition import acquire_daily
from research_warehouse.canonical import canonical_json_line
from research_warehouse.custody_locks import (
    custody_identity,
    legacy_custody_identity_for_device,
)
from research_warehouse.custody_paths import (
    CustodyTransitionTrust,
    ReadonlyProjectedRootTrust,
    WarehousePaths,
)
from research_warehouse.custody_transition import (
    build_custody_transition,
    verify_custody_transition,
)
from research_warehouse.errors import RegistryError
from research_warehouse.file_integrity import read_regular_strict
from research_warehouse.m2_operator_defaults import BACKUP_SIGNER_KEY_ID
from research_warehouse.observation_contracts import OBSERVATION_SCHEMA, observation_id
from research_warehouse.observations import load_observations_readonly
from research_warehouse.registry import load_registry
from research_warehouse.signing import public_key_sha256, sign_payload
from test_issue355_research_custody_identity import (
    REGISTRY_PATH,
    _official_raw,
    _OfficialTransport,
)

NOW = datetime(2026, 8, 22, tzinfo=timezone.utc)


def _public(tmp_path: Path, key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "backup-public-key.b64"
    path.write_bytes(base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )) + b"\n")
    path.chmod(0o444)
    return path


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    physical = WarehousePaths.initialize(tmp_path / "physical")
    projection_paths = WarehousePaths.initialize(tmp_path / "projection")
    key = Ed25519PrivateKey.generate()
    public = _public(tmp_path, key)
    source_dev = physical.root.lstat().st_dev + 17
    transition = build_custody_transition(
        paths=physical, source_st_dev=source_dev,
        expected_source_legacy_identity_sha256=legacy_custody_identity_for_device(physical, source_dev),
        expected_destination_legacy_identity_sha256=custody_identity(physical),
        signer_key_id=BACKUP_SIGNER_KEY_ID, private_key=key, attested_at=NOW,
    )
    transition_path = tmp_path / "transition.json"
    transition_path.write_bytes(canonical_json_line(transition)); transition_path.chmod(0o444)
    trust = CustodyTransitionTrust(transition_path, public, public_key_sha256(key.public_key()))
    physical = WarehousePaths.open(physical.root, custody_transition=trust)
    monkeypatch.setattr(
        projected, "_read_root_managed_transition_receipt",
        lambda value: read_regular_strict(value.receipt_path, "transition", private=False),
    )
    monkeypatch.setattr(
        transition_module, "_read_root_managed_transition_receipt",
        lambda value: read_regular_strict(value.receipt_path, "transition", private=False),
    )
    attestation = projected.build_readonly_projected_root_attestation(
        physical_paths=physical, transition_trust=trust, projection_root=projection_paths.root,
        projection_info=projection_paths.root.lstat(), signer_key_id=BACKUP_SIGNER_KEY_ID,
        private_key=key, attested_at=NOW,
    )
    receipt = tmp_path / "projection.json"
    receipt.write_bytes(canonical_json_line(attestation)); receipt.chmod(0o444)
    monkeypatch.setattr(projected, "_read_attestation", lambda _path: receipt.read_bytes())
    monkeypatch.setattr(projected.os, "statvfs", lambda _path: type("V", (), {"f_flag": 1})())
    return physical, projection_paths, trust, public, key, receipt, attestation


def _verify(paths, trust, public, receipt):
    return projected.verify_readonly_projected_root_attestation(
        paths=paths, attestation_path=receipt, transition_trust=trust,
        public_key_path=public, expected_public_key_sha256=trust.expected_public_key_sha256,
    )


def _replace_receipt(path: Path, payload: dict) -> None:
    path.chmod(0o600)
    path.write_bytes(canonical_json_line(payload))
    path.chmod(0o444)


def test_readonly_runtime_projection_requires_explicit_runner_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bool] = []

    def fake_loader(_path: Path, **kwargs):
        calls.append(kwargs["allow_readonly_projected_root"])
        return object()

    monkeypatch.setattr(m2_runtime_loader, "_load_runtime_context", fake_loader)
    assert m2_runtime_loader.load_runtime_context_readonly(Path("/runtime"))
    assert m2_runtime_loader.load_runtime_context_readonly(
        Path("/runtime"), allow_readonly_projected_root=True
    )
    assert calls == [False, True]


def test_physical_transition_remains_physical_and_projection_is_exact_readonly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    physical, projection_paths, trust, public, _key, receipt, attestation = _fixture(tmp_path, monkeypatch)
    assert verify_custody_transition(physical, trust)["transition_id"] == attestation["source_transition_id"]
    assert _verify(projection_paths, trust, public, receipt)["projection_only"] is True
    with pytest.raises(RegistryError, match="stable root binding mismatch"):
        verify_custody_transition(projection_paths, trust)


@pytest.mark.parametrize("field", ["projection_st_ino", "projection_st_dev", "projection_uid", "projection_gid", "projection_mode"])
def test_projection_identity_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    _physical, projection_paths, trust, public, _key, receipt, attestation = _fixture(tmp_path, monkeypatch)
    tampered = dict(attestation); tampered[field] += 1
    _replace_receipt(receipt, tampered)
    with pytest.raises(RegistryError):
        _verify(projection_paths, trust, public, receipt)


def test_signature_pin_authority_and_writable_mount_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _physical, projection_paths, trust, public, _key, receipt, attestation = _fixture(tmp_path, monkeypatch)
    tampered = dict(attestation); tampered["mutation_authorized"] = True
    _replace_receipt(receipt, tampered)
    with pytest.raises(RegistryError, match="grants authority"):
        _verify(projection_paths, trust, public, receipt)
    _replace_receipt(receipt, attestation)
    with pytest.raises(RegistryError, match="public key pin mismatch"):
        projected.verify_readonly_projected_root_attestation(
            paths=projection_paths,
            attestation_path=receipt,
            transition_trust=trust,
            public_key_path=public,
            expected_public_key_sha256="0" * 64,
        )
    monkeypatch.setattr(projected.os, "statvfs", lambda _path: type("V", (), {"f_flag": 0})())
    with pytest.raises(RegistryError, match="writable"):
        _verify(projection_paths, trust, public, receipt)


def test_re_signed_non_backup_signer_key_id_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _physical, projection_paths, trust, public, key, receipt, attestation = _fixture(
        tmp_path, monkeypatch
    )
    unsigned = dict(attestation)
    unsigned.pop("signature")
    unsigned["signer_key_id"] = "another-valid-signer-id"
    unsigned["attestation_id"] = projected._attestation_id(unsigned)
    _replace_receipt(receipt, sign_payload(unsigned, key))
    with pytest.raises(RegistryError, match="pinned backup signer"):
        _verify(projection_paths, trust, public, receipt)


def test_tampered_attestation_and_unrelated_root_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _physical, projection_paths, trust, public, _key, receipt, attestation = _fixture(tmp_path, monkeypatch)
    tampered = dict(attestation); tampered["source_transition_raw_sha256"] = "0" * 64
    _replace_receipt(receipt, tampered)
    with pytest.raises(RegistryError):
        _verify(projection_paths, trust, public, receipt)
    _replace_receipt(receipt, attestation)
    unrelated = WarehousePaths.initialize(tmp_path / "unrelated")
    with pytest.raises(RegistryError, match="identity binding mismatch"):
        _verify(unrelated, trust, public, receipt)


def test_runner_readonly_loader_accepts_only_attested_v1_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    physical, projection, trust, public, _key, receipt, _attestation = _fixture(
        tmp_path, monkeypatch
    )
    registry = load_registry(REGISTRY_PATH)
    acquired = acquire_daily(
        paths=physical,
        registry=registry,
        source_id="shfe-daily-market-data-v1",
        trade_day="2026-07-28",
        collector_version="issue362-projected-root-test",
        observed_at=NOW,
        transport=_OfficialTransport(_official_raw()),
    )
    receipt_path = (
        physical.observations
        / "shfe"
        / "2026-07-28"
        / "shfe-daily-market-data-v1"
        / f"{acquired.observation_id}.json"
    )
    legacy = json.loads(receipt_path.read_bytes())
    legacy.pop("custody_identity_scheme")
    legacy["schema_version"] = OBSERVATION_SCHEMA
    legacy["custody_identity_sha256"] = legacy_custody_identity_for_device(
        physical, physical.root.lstat().st_dev + 17
    )
    legacy["observation_id"] = ""
    legacy["observation_id"] = observation_id(legacy)
    receipt_path.unlink()
    legacy_path = receipt_path.with_name(f"{legacy['observation_id']}.json")
    legacy_path.write_bytes(canonical_json_line(legacy))
    legacy_path.chmod(0o600)
    shutil.copytree(physical.raw, projection.raw, dirs_exist_ok=True)
    shutil.copytree(physical.observations, projection.observations, dirs_exist_ok=True)
    projected_paths = WarehousePaths.open(
        projection.root,
        custody_transition=trust,
        readonly_projected_root=ReadonlyProjectedRootTrust(
            receipt, public, trust.expected_public_key_sha256
        ),
    )
    loaded = load_observations_readonly(
        projected_paths,
        registry,
        source_id="shfe-daily-market-data-v1",
        trade_day="2026-07-28",
    )
    assert [item["observation_id"] for item in loaded] == [legacy["observation_id"]]
