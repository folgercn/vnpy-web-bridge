from __future__ import annotations

import base64
import json
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse.acquisition import acquire_daily
from research_warehouse.acquisition_models import HttpResponse
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.catalog_lock import single_writer_lock
from research_warehouse.catalog_schema import CATALOG_FILENAME
from research_warehouse.commit_anchors import (
    ANCHOR_SCHEMA,
    CommitAnchorLedger,
    load_commit_anchor_ledger,
)
from research_warehouse.derived_paths import DerivedPaths
from research_warehouse.errors import RegistryError
from research_warehouse.filesystem import WarehousePaths
from research_warehouse.manifests import seal_daily_batch
from research_warehouse.normalization_contracts import (
    NORMALIZED_COLUMNS,
    SORT_KEYS,
    contract_document,
)
from research_warehouse.normalization_models import NormalizationBinding
from research_warehouse.rebuild import (
    rebuild_empty_catalog,
    verify_rebuilt_catalog,
)
from research_warehouse.rebuild_binding import load_normalization_binding
from research_warehouse.registry import load_registry

REGISTRY_PATH = ROOT / "deployments/research-warehouse/source-registry-v1.json"
LOCK_PATH = ROOT / "backend/requirements.txt"
CONTRACT_SCHEMA_PATH = (
    ROOT
    / "deployments/research-warehouse/normalization-contract-v1.schema.json"
)
SOURCE_ID = "shfe-daily-market-data-v1"
TRADE_DAY = "2026-07-28"
T1 = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 7, 28, 8, 5, tzinfo=timezone.utc)
T3 = datetime(2026, 7, 28, 8, 10, tzinfo=timezone.utc)
TOOL_COMMIT = "a" * 40


class FakeTransport:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    @contextmanager
    def open(self, _url: str, **_kwargs):
        yield HttpResponse(
            final_url=(
                "https://www.shfe.com.cn/data/tradedata/future/"
                "dailydata/kx20260728.dat"
            ),
            status=200,
            headers={
                "content-length": str(len(self.raw)),
                "content-type": "application/json",
                "etag": '"catalog-v1"',
                "last-modified": "Tue, 28 Jul 2026 08:00:00 GMT",
            },
            chunks=iter([self.raw]),
        )


def official_raw(*, invalid_price: bool = False) -> bytes:
    rows = [
        {
            "DELIVERYMONTH": "2609",
            "PRODUCTID": "zn_f",
            "OPENPRICE": [] if invalid_price else "22000.5",
            "HIGHESTPRICE": "22100",
            "LOWESTPRICE": "21900",
            "CLOSEPRICE": "22050",
            "SETTLEMENTPRICE": "22020",
            "VOLUME": "8",
            "OPENINTEREST": 11,
        },
        {
            "DELIVERYMONTH": "2608",
            "PRODUCTID": "cu_f",
            "OPENPRICE": "80000",
            "HIGHESTPRICE": "80100",
            "LOWESTPRICE": "79900",
            "CLOSEPRICE": "80050",
            "SETTLEMENTPRICE": "80020",
            "VOLUME": 100,
            "OPENINTEREST": "200",
        },
    ]
    return json.dumps(
        {"o_curinstrument": rows, "report_date": "20260728"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def signing_keys(tmp_path: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "public.key"
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        base64.b64encode(
            private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        + b"\n"
    )
    private_path.chmod(0o600)
    public_path.chmod(0o600)
    return private_path, public_path


def sealed_evidence(
    tmp_path: Path,
    *,
    invalid_price: bool = False,
) -> tuple[
    WarehousePaths,
    Path,
    str,
    str,
    CommitAnchorLedger,
    NormalizationBinding,
]:
    evidence = WarehousePaths.initialize(tmp_path / "evidence")
    trusted_registry = load_registry(REGISTRY_PATH)
    raw = official_raw(invalid_price=invalid_price)
    acquire_daily(
        paths=evidence,
        registry=trusted_registry,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        collector_version="issue-168-test-v1",
        observed_at=T1,
        transport=FakeTransport(raw),
    )
    private_key, public_key = signing_keys(tmp_path)
    manifest_path = seal_daily_batch(
        paths=evidence,
        registry=trusted_registry,
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        expected_parent_batch_seal_sha256=None,
        expected_parent_commit_seal_sha256=None,
        trusted_clock=lambda: T2,
    )
    manifest = json.loads(manifest_path.read_bytes())
    batch_seal = manifest["batch_seal_sha256"]
    receipt_path = manifest_path.parent / f"commit-{manifest['batch_id']}.json"
    commit_seal = sha256(receipt_path.read_bytes())
    ledger_payload = {
        "schema_version": ANCHOR_SCHEMA,
        "entries": [
            {
                "sequence": 1,
                "batch_seal_sha256": batch_seal,
                "commit_seal_sha256": commit_seal,
                "available_at": T3.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
            }
        ],
    }
    ledger_raw = canonical_json_line(ledger_payload)
    ledger_path = tmp_path / "commit-anchors.json"
    ledger_path.write_bytes(ledger_raw)
    ledger_path.chmod(0o600)
    ledger = load_commit_anchor_ledger(
        ledger_path,
        expected_raw_sha256=sha256(ledger_raw),
    )
    lock_hash = sha256(LOCK_PATH.read_bytes())
    binding = load_normalization_binding(
        tool_commit_sha=TOOL_COMMIT,
        dependency_lock_path=LOCK_PATH,
        expected_dependency_lock_sha256=lock_hash,
        registry_raw_sha256=trusted_registry.raw_sha256,
    )
    return (
        evidence,
        public_key,
        batch_seal,
        commit_seal,
        ledger,
        binding,
    )


def rebuild(
    evidence: WarehousePaths,
    public_key: Path,
    batch_seal: str,
    commit_seal: str,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
    root: Path,
) -> dict[str, object]:
    return rebuild_empty_catalog(
        evidence=evidence,
        derived_root=root,
        public_key_path=public_key,
        registry=load_registry(REGISTRY_PATH),
        expected_genesis_seal_sha256=batch_seal,
        expected_head_seal_sha256=batch_seal,
        expected_head_commit_seal_sha256=commit_seal,
        ledger=ledger,
        binding=binding,
    )


def test_empty_rebuild_is_deterministic_from_raw_and_signed_manifests(
    tmp_path: Path,
) -> None:
    values = sealed_evidence(tmp_path)
    evidence = values[0]
    for path in evidence.observations.rglob("obs-*.json"):
        path.unlink()

    first = rebuild(*values, tmp_path / "derived-a")
    second = rebuild(*values, tmp_path / "derived-b")

    assert first["partition_count"] == 1
    assert first["revision_count"] == 1
    assert first["partition_hashes"] == second["partition_hashes"]
    assert first["status"] == "EMPTY_ROOT_REBUILD_VALID"
    first_paths = DerivedPaths.open(tmp_path / "derived-a")
    verified = verify_rebuilt_catalog(
        evidence=evidence,
        derived=first_paths,
        public_key_path=values[1],
        registry=load_registry(REGISTRY_PATH),
        expected_genesis_seal_sha256=values[2],
        expected_head_seal_sha256=values[2],
        expected_head_commit_seal_sha256=values[3],
        ledger=values[4],
        binding=values[5],
    )
    assert verified["status"] == "REBUILT_CATALOG_VALID"

    catalog = duckdb.connect(
        str(first_paths.catalog / CATALOG_FILENAME),
        read_only=True,
    )
    try:
        assert {
            row[0] for row in catalog.execute("SHOW TABLES").fetchall()
        } == {
            "batches",
            "catalog_meta",
            "normalized_partitions",
            "revisions",
        }
        rows = catalog.execute(
            "SELECT product_id, delivery_month FROM read_parquet(?)",
            [str(next(first_paths.parquet.rglob("*.parquet")))],
        ).fetchall()
        assert rows == [("cu_f", "2608"), ("zn_f", "2609")]
    finally:
        catalog.close()


def test_normalizer_schema_drift_fails_closed(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path, invalid_price=True)
    with pytest.raises(RegistryError, match="OPENPRICE"):
        rebuild(*values, tmp_path / "derived")
    assert not list((tmp_path / "derived" / "catalog").glob("*.duckdb"))


def test_corrupt_catalog_fails_closed(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path)
    rebuild(*values, tmp_path / "derived")
    derived = DerivedPaths.open(tmp_path / "derived")
    catalog = derived.catalog / CATALOG_FILENAME
    catalog.write_bytes(b"corrupt")
    with pytest.raises(RegistryError, match="catalog|DuckDB"):
        verify_rebuilt_catalog(
            evidence=values[0],
            derived=derived,
            public_key_path=values[1],
            registry=load_registry(REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[2],
            expected_head_commit_seal_sha256=values[3],
            ledger=values[4],
            binding=values[5],
        )


def test_corrupt_parquet_fails_closed(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path)
    rebuild(*values, tmp_path / "derived")
    derived = DerivedPaths.open(tmp_path / "derived")
    parquet = next(derived.parquet.rglob("*.parquet"))
    parquet.write_bytes(b"corrupt")

    with pytest.raises(RegistryError, match="Parquet hash/size mismatch"):
        verify_rebuilt_catalog(
            evidence=values[0],
            derived=derived,
            public_key_path=values[1],
            registry=load_registry(REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[2],
            expected_head_commit_seal_sha256=values[3],
            ledger=values[4],
            binding=values[5],
        )


def test_tool_commit_changes_partition_identity(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path)
    first = rebuild(*values, tmp_path / "derived-a")
    alternate = NormalizationBinding(
        tool_commit_sha="b" * 40,
        dependency_lock_sha256=values[5].dependency_lock_sha256,
        registry_raw_sha256=values[5].registry_raw_sha256,
    )
    second = rebuild(
        *values[:5],
        alternate,
        tmp_path / "derived-b",
    )

    assert first["partition_hashes"] != second["partition_hashes"]
    assert set(first["partition_hashes"]) != set(second["partition_hashes"])


def test_normalization_contract_matches_json_schema() -> None:
    schema = json.loads(CONTRACT_SCHEMA_PATH.read_bytes())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(contract_document())

    column_names = {name for name, _sql_type in NORMALIZED_COLUMNS}
    assert set(SORT_KEYS) <= column_names


def test_concurrent_catalog_writer_fails_closed(tmp_path: Path) -> None:
    paths = DerivedPaths.initialize(tmp_path / "derived")
    with (
        single_writer_lock(paths),
        pytest.raises(RegistryError, match="another catalog writer"),
        single_writer_lock(paths),
    ):
        pytest.fail("second writer unexpectedly acquired lock")


def test_dependency_lock_hash_drift_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(RegistryError, match="dependency lock hash mismatch"):
        load_normalization_binding(
            tool_commit_sha=TOOL_COMMIT,
            dependency_lock_path=LOCK_PATH,
            expected_dependency_lock_sha256="f" * 64,
            registry_raw_sha256=load_registry(REGISTRY_PATH).raw_sha256,
        )
