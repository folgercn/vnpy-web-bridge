from __future__ import annotations

import base64
import json
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import custody_transition as custody_transition_module
from research_warehouse.acquisition import acquire_daily
from research_warehouse.acquisition_models import HttpResponse
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
from research_warehouse.file_integrity import read_regular_strict
from research_warehouse.observation_contracts import OBSERVATION_SCHEMA, observation_id
from research_warehouse.observations import load_observations
from research_warehouse.registry import load_registry
from research_warehouse.signing import public_key_sha256

ATTESTED_AT = datetime(2026, 8, 17, 5, 0, tzinfo=timezone.utc)
REGISTRY_PATH = ROOT / "deployments/research-warehouse/source-registry-v1.json"
READ_ROOT_MANAGED_TRANSITION_RECEIPT = (
    custody_transition_module._read_root_managed_transition_receipt
)


@pytest.fixture(autouse=True)
def _test_receipts_bypass_m2_root_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unit fixtures cannot create root:root files outside the M2 operator."""
    monkeypatch.setattr(
        custody_transition_module,
        "_read_root_managed_transition_receipt",
        lambda trust: read_regular_strict(
            trust.receipt_path,
            "test custody reboot transition receipt",
            limit=1024 * 1024,
            private=False,
        ),
    )


class _OfficialTransport:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    @contextmanager
    def open(self, _url: str, **_kwargs):
        yield HttpResponse(
            final_url=(
                "https://www.shfe.com.cn/data/tradedata/future/"
                "dailydata/kx20260728.dat"
            ),
            status=200,
            headers={
                "content-length": str(len(self._raw)),
                "content-type": "application/json",
                "etag": '"issue355"',
                "last-modified": "Tue, 28 Jul 2026 08:00:00 GMT",
            },
            chunks=iter((self._raw,)),
        )


def _official_raw() -> bytes:
    return json.dumps(
        {
            "o_curinstrument": [
                {
                    "DELIVERYMONTH": "2608",
                    "PRODUCTID": "cu_f",
                    "OPENPRICE": "80000",
                    "HIGHESTPRICE": "80100",
                    "LOWESTPRICE": "79900",
                    "CLOSEPRICE": "80050",
                    "SETTLEMENTPRICE": "80020",
                    "VOLUME": "100",
                    "OPENINTEREST": "200",
                }
            ],
            "report_date": "20260728",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


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


def test_transition_receipt_requires_root_managed_parent_and_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, trusted_paths, trust, _payload, _source, _destination = (
        _transition_fixture(tmp_path)
    )
    monkeypatch.setattr(
        custody_transition_module,
        "_read_root_managed_transition_receipt",
        READ_ROOT_MANAGED_TRANSITION_RECEIPT,
    )

    def reject_root_custody(_path: Path) -> None:
        raise RegistryError("transition receipt parent/path is unsafe")

    monkeypatch.setattr(
        custody_transition_module,
        "require_root_managed",
        reject_root_custody,
    )
    with pytest.raises(RegistryError, match="parent/path is unsafe"):
        verify_custody_transition(trusted_paths, trust)


def test_transition_receipt_fd_requires_exact_root_create_only_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        custody_transition_module.os,
        "fstat",
        lambda _descriptor: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_uid=0,
            st_nlink=1,
        ),
    )

    with pytest.raises(RegistryError, match="root custody is unsafe"):
        custody_transition_module._validate_root_managed_transition_receipt_fd(7)


def test_transition_receipt_fd_requires_acl_free_opened_inode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked: list[tuple[int, str]] = []
    monkeypatch.setattr(
        custody_transition_module.os,
        "fstat",
        lambda _descriptor: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444,
            st_uid=0,
            st_nlink=1,
        ),
    )
    monkeypatch.setattr(
        custody_transition_module,
        "require_acl_free_fd",
        lambda descriptor, label: checked.append((descriptor, label)),
    )

    custody_transition_module._validate_root_managed_transition_receipt_fd(7)

    assert checked == [(7, "custody reboot transition receipt")]


def test_transition_receipt_replacement_during_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, trusted_paths, trust, _payload, _source, _destination = (
        _transition_fixture(tmp_path)
    )
    displaced = tmp_path / "displaced-transition.json"
    replacement = tmp_path / "replacement-transition.json"
    replacement.write_bytes(trust.receipt_path.read_bytes())
    replacement.chmod(0o444)
    original_fstat = custody_transition_module.os.fstat
    original_inode = trust.receipt_path.lstat().st_ino
    replaced = False

    def replacing_fstat(descriptor: int):
        nonlocal replaced
        metadata = original_fstat(descriptor)
        if not replaced and metadata.st_ino == original_inode:
            trust.receipt_path.rename(displaced)
            replacement.rename(trust.receipt_path)
            replaced = True
        return metadata

    monkeypatch.setattr(custody_transition_module.os, "fstat", replacing_fstat)

    with pytest.raises(RegistryError, match="changed while being read"):
        verify_custody_transition(trusted_paths, trust)


def test_legacy_v1_observation_validates_only_through_signed_transition(
    tmp_path: Path,
) -> None:
    (
        paths,
        trusted_paths,
        _trust,
        _payload,
        source_identity,
        _destination,
    ) = _transition_fixture(tmp_path)
    registry = load_registry(REGISTRY_PATH)
    acquired = acquire_daily(
        paths=paths,
        registry=registry,
        source_id="shfe-daily-market-data-v1",
        trade_day="2026-07-28",
        collector_version="issue355-test-v1",
        observed_at=ATTESTED_AT,
        transport=_OfficialTransport(_official_raw()),
    )
    receipt_path = (
        paths.observations
        / "shfe"
        / "2026-07-28"
        / "shfe-daily-market-data-v1"
        / f"{acquired.observation_id}.json"
    )
    legacy = json.loads(receipt_path.read_bytes())
    legacy.pop("custody_identity_scheme")
    legacy["schema_version"] = OBSERVATION_SCHEMA
    legacy["custody_identity_sha256"] = source_identity
    legacy["observation_id"] = ""
    legacy["observation_id"] = observation_id(legacy)
    receipt_path.unlink()
    legacy_path = receipt_path.with_name(f"{legacy['observation_id']}.json")
    legacy_path.write_bytes(canonical_json_line(legacy))
    legacy_path.chmod(0o600)

    loaded = load_observations(
        trusted_paths,
        registry,
        source_id="shfe-daily-market-data-v1",
        trade_day="2026-07-28",
    )

    assert [item["observation_id"] for item in loaded] == [
        legacy["observation_id"]
    ]
    assert loaded[0]["schema_version"] == OBSERVATION_SCHEMA
