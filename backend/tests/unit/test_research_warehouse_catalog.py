from __future__ import annotations

import base64
import errno
import json
import os
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

from research_warehouse import catalog_validation, publication
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
    PARQUET_COMPRESSION,
    PARQUET_COMPRESSION_LEVEL,
    PARQUET_DICTIONARY_PAGE_SIZE,
    PARQUET_ROW_GROUP_SIZE,
    PARQUET_VERSION,
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
T4 = datetime(2026, 7, 28, 8, 15, tzinfo=timezone.utc)
T5 = datetime(2026, 7, 28, 8, 20, tzinfo=timezone.utc)
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


def changed_market_parquet(source: Path, destination: Path) -> None:
    source_literal = "'" + str(source).replace("'", "''") + "'"
    destination_literal = "'" + str(destination).replace("'", "''") + "'"
    order = ", ".join(f'"{key}" ASC NULLS FIRST' for key in SORT_KEYS)
    connection = duckdb.connect(":memory:")
    try:
        connection.execute(
            "COPY (SELECT * REPLACE (open_price + 1 AS open_price) "
            f"FROM read_parquet({source_literal}) ORDER BY {order}) "
            f"TO {destination_literal} (FORMAT parquet, "
            f"COMPRESSION {PARQUET_COMPRESSION}, "
            f"COMPRESSION_LEVEL {PARQUET_COMPRESSION_LEVEL}, "
            f"ROW_GROUP_SIZE {PARQUET_ROW_GROUP_SIZE}, "
            f"PARQUET_VERSION '{PARQUET_VERSION}', "
            "STRING_DICTIONARY_PAGE_SIZE_LIMIT "
            f"{PARQUET_DICTIONARY_PAGE_SIZE})"
        )
    finally:
        connection.close()
    destination.chmod(0o600)


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
    repeat_same_raw: bool = False,
) -> tuple[
    WarehousePaths,
    Path,
    str,
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
    manifests = [json.loads(manifest_path.read_bytes())]
    if repeat_same_raw:
        acquire_daily(
            paths=evidence,
            registry=trusted_registry,
            source_id=SOURCE_ID,
            trade_day=TRADE_DAY,
            collector_version="issue-168-test-v1",
            observed_at=T3,
            transport=FakeTransport(raw),
        )
        parent = manifests[-1]
        parent_receipt = (
            manifest_path.parent / f"commit-{parent['batch_id']}.json"
        )
        manifest_path = seal_daily_batch(
            paths=evidence,
            registry=trusted_registry,
            trade_day=TRADE_DAY,
            private_key_path=private_key,
            signer_key_id="research-key-v1",
            expected_parent_batch_seal_sha256=parent["batch_seal_sha256"],
            expected_parent_commit_seal_sha256=sha256(
                parent_receipt.read_bytes()
            ),
            trusted_clock=lambda: T4,
        )
        manifests.append(json.loads(manifest_path.read_bytes()))
    seals = []
    for manifest in manifests:
        receipt_path = (
            manifest_path.parent / f"commit-{manifest['batch_id']}.json"
        )
        seals.append(
            (
                manifest["batch_seal_sha256"],
                sha256(receipt_path.read_bytes()),
            )
        )
    ledger_payload = {
        "schema_version": ANCHOR_SCHEMA,
        "entries": [
            {
                "sequence": sequence,
                "batch_seal_sha256": batch_seal,
                "commit_seal_sha256": commit_seal,
                "available_at": available_at.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
            }
            for sequence, ((batch_seal, commit_seal), available_at) in enumerate(
                zip(seals, (T3, T5), strict=False),
                start=1,
            )
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
        seals[0][0],
        seals[-1][0],
        seals[-1][1],
        ledger,
        binding,
    )


def rebuild(
    evidence: WarehousePaths,
    public_key: Path,
    genesis_seal: str,
    head_seal: str,
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
        expected_genesis_seal_sha256=genesis_seal,
        expected_head_seal_sha256=head_seal,
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
        expected_head_seal_sha256=values[3],
        expected_head_commit_seal_sha256=values[4],
        ledger=values[5],
        binding=values[6],
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
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
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
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
        )


def test_market_value_and_catalog_hash_tamper_fails_replay(
    tmp_path: Path,
) -> None:
    values = sealed_evidence(tmp_path)
    rebuild(*values, tmp_path / "derived")
    derived = DerivedPaths.open(tmp_path / "derived")
    parquet = next(derived.parquet.rglob("*.parquet"))
    changed = derived.temporary / "changed.parquet"
    changed_market_parquet(parquet, changed)
    os.replace(changed, parquet)
    changed_raw = parquet.read_bytes()
    catalog = duckdb.connect(str(derived.catalog / CATALOG_FILENAME))
    try:
        catalog.execute(
            "UPDATE normalized_partitions "
            "SET parquet_sha256 = ?, parquet_bytes = ?",
            [sha256(changed_raw), len(changed_raw)],
        )
        catalog.execute("CHECKPOINT")
    finally:
        catalog.close()

    with pytest.raises(RegistryError, match="partition replay mismatch"):
        verify_rebuilt_catalog(
            evidence=values[0],
            derived=derived,
            public_key_path=values[1],
            registry=load_registry(REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
        )


def test_partition_path_swap_during_validation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = sealed_evidence(tmp_path)
    rebuild(*values, tmp_path / "derived")
    derived = DerivedPaths.open(tmp_path / "derived")
    parquet = next(derived.parquet.rglob("*.parquet"))
    changed = derived.temporary / "changed.parquet"
    changed_market_parquet(parquet, changed)
    real_read = catalog_validation.read_regular_strict
    swapped = False

    def swap_after_verified_read(
        path: Path,
        label: str,
        **kwargs,
    ) -> bytes:
        nonlocal swapped
        raw = real_read(path, label, **kwargs)
        if label == "catalog normalized Parquet" and not swapped:
            swapped = True
            os.replace(changed, path)
        return raw

    monkeypatch.setattr(
        catalog_validation,
        "read_regular_strict",
        swap_after_verified_read,
    )
    with pytest.raises(RegistryError, match="changed during validation"):
        verify_rebuilt_catalog(
            evidence=values[0],
            derived=derived,
            public_key_path=values[1],
            registry=load_registry(REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
        )
    assert swapped is True


def test_same_revision_snapshot_extension_rebuilds(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path, repeat_same_raw=True)
    for path in values[0].observations.rglob("obs-*.json"):
        path.unlink()
    rebuilt = rebuild(*values, tmp_path / "derived")

    assert rebuilt["manifest_count"] == 2
    assert rebuilt["revision_count"] == 1
    derived = DerivedPaths.open(tmp_path / "derived")
    catalog = duckdb.connect(
        str(derived.catalog / CATALOG_FILENAME),
        read_only=True,
    )
    try:
        assert catalog.execute(
            "SELECT first_batch_sequence, last_seen_at FROM revisions"
        ).fetchone() == (
            1,
            T3.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        )
    finally:
        catalog.close()


def test_registry_binding_must_match_signed_chain(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path)
    mismatched = NormalizationBinding(
        tool_commit_sha=values[6].tool_commit_sha,
        dependency_lock_sha256=values[6].dependency_lock_sha256,
        registry_raw_sha256="f" * 64,
    )
    with pytest.raises(RegistryError, match="registry provenance mismatch"):
        rebuild(
            *values[:6],
            mismatched,
            tmp_path / "derived",
        )


def test_parquet_fsync_failure_preserves_incomplete_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = sealed_evidence(tmp_path)
    derived_root = tmp_path / "derived"
    real_fsync_dir = publication._fsync_dir
    failed = False

    def fail_parquet_parent(path: Path) -> None:
        nonlocal failed
        if (
            not failed
            and derived_root / "parquet" in path.parents
            and list(path.glob("*.parquet"))
        ):
            failed = True
            raise OSError(errno.ENOSPC, "forced Parquet parent fsync failure")
        real_fsync_dir(path)

    monkeypatch.setattr(publication, "_fsync_dir", fail_parquet_parent)
    with pytest.raises(RegistryError, match="Parquet publication"):
        rebuild(*values, derived_root)

    final = next((derived_root / "parquet").rglob("*.parquet"))
    temporary = next((derived_root / "tmp").glob(".normalize-*.partial"))
    assert final.lstat().st_nlink == 2
    assert temporary.lstat().st_ino == final.lstat().st_ino
    assert not list((derived_root / "catalog").glob("*.duckdb"))


def test_catalog_fsync_failure_preserves_incomplete_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = sealed_evidence(tmp_path)
    derived_root = tmp_path / "derived"
    catalog_parent = derived_root / "catalog"
    real_fsync_dir = publication._fsync_dir
    failed = False

    def fail_catalog_parent(path: Path) -> None:
        nonlocal failed
        if (
            not failed
            and path == catalog_parent
            and (path / CATALOG_FILENAME).exists()
        ):
            failed = True
            raise OSError(errno.ENOSPC, "forced catalog parent fsync failure")
        real_fsync_dir(path)

    monkeypatch.setattr(publication, "_fsync_dir", fail_catalog_parent)
    with pytest.raises(RegistryError, match="catalog publication"):
        rebuild(*values, derived_root)

    final = catalog_parent / CATALOG_FILENAME
    temporary = next((derived_root / "tmp").glob(".catalog-*.partial"))
    assert final.lstat().st_nlink == 2
    assert temporary.lstat().st_ino == final.lstat().st_ino
    with pytest.raises(RegistryError, match="exactly one hard link"):
        verify_rebuilt_catalog(
            evidence=values[0],
            derived=DerivedPaths.open(derived_root),
            public_key_path=values[1],
            registry=load_registry(REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
        )


def test_tool_commit_changes_partition_identity(tmp_path: Path) -> None:
    values = sealed_evidence(tmp_path)
    first = rebuild(*values, tmp_path / "derived-a")
    alternate = NormalizationBinding(
        tool_commit_sha="b" * 40,
        dependency_lock_sha256=values[6].dependency_lock_sha256,
        registry_raw_sha256=values[6].registry_raw_sha256,
    )
    second = rebuild(
        *values[:6],
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
