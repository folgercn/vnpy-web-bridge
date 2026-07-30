from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import (
    backup_service,
    held_custody,
    migration_service,
    restore_service,
)
from research_warehouse.backup_anchor import verify_backup_anchor
from research_warehouse.backup_custody import BackupPaths
from research_warehouse.backup_service import create_append_only_backup
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.commit_anchors import (
    ANCHOR_SCHEMA,
    load_commit_anchor_ledger,
)
from research_warehouse.derived_paths import DerivedPaths
from research_warehouse.errors import RegistryError
from research_warehouse.filesystem import WarehousePaths
from research_warehouse.manifests import seal_daily_batch
from research_warehouse.migration_receipt import MigrationReceiptPaths
from research_warehouse.migration_service import (
    migrate_warehouse,
    verify_completed_migration,
)
from research_warehouse.registry import load_registry
from research_warehouse.restore_service import restore_and_verify
from research_warehouse.signing import load_public_key, public_key_sha256

BACKUP_SCHEMA = (
    ROOT / "deployments/research-warehouse/backup-anchor-v1.schema.json"
)
MIGRATION_SCHEMA = (
    ROOT / "deployments/research-warehouse/migration-receipt-v1.schema.json"
)
NOW = datetime(2026, 8, 4, 2, 0, tzinfo=timezone.utc)


def _catalog_fixture_module():
    path = ROOT / "backend/tests/unit/test_research_warehouse_catalog.py"
    spec = importlib.util.spec_from_file_location("catalog_fixture_173", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_key_pair(tmp_path: Path):
    fixture = _catalog_fixture_module()
    tmp_path.mkdir(mode=0o700)
    private_path, public_path = fixture.signing_keys(tmp_path)
    return (
        private_path,
        public_path,
        public_key_sha256(load_public_key(public_path)),
    )


def _revised_fixture(tmp_path: Path):
    fixture = _catalog_fixture_module()
    tmp_path.mkdir(mode=0o700)
    values = list(fixture.sealed_evidence(tmp_path))
    evidence = values[0]
    first_manifest_path = next(evidence.manifests.rglob("batch-*.json"))
    first_manifest = json.loads(first_manifest_path.read_bytes())
    changed = json.loads(fixture.official_raw())
    changed["o_curinstrument"][0]["OPENPRICE"] = "22001.5"
    changed_raw = json.dumps(
        changed,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    fixture.acquire_daily(
        paths=evidence,
        registry=load_registry(fixture.REGISTRY_PATH),
        source_id=fixture.SOURCE_ID,
        trade_day=fixture.TRADE_DAY,
        collector_version="issue-173-revision-drill-v1",
        observed_at=fixture.T3,
        transport=fixture.FakeTransport(changed_raw),
    )
    first_commit_path = (
        first_manifest_path.parent
        / f"commit-{first_manifest['batch_id']}.json"
    )
    second_path = seal_daily_batch(
        paths=evidence,
        registry=load_registry(fixture.REGISTRY_PATH),
        trade_day=fixture.TRADE_DAY,
        private_key_path=tmp_path / "private.key",
        signer_key_id="research-key-v1",
        expected_parent_batch_seal_sha256=first_manifest[
            "batch_seal_sha256"
        ],
        expected_parent_commit_seal_sha256=sha256(
            first_commit_path.read_bytes()
        ),
        trusted_clock=lambda: fixture.T4,
    )
    second_manifest = json.loads(second_path.read_bytes())
    second_commit = second_path.parent / f"commit-{second_manifest['batch_id']}.json"
    ledger_payload = {
        "schema_version": ANCHOR_SCHEMA,
        "entries": [
            {
                "sequence": 1,
                "batch_seal_sha256": first_manifest["batch_seal_sha256"],
                "commit_seal_sha256": sha256(first_commit_path.read_bytes()),
                "available_at": fixture.T3.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
            },
            {
                "sequence": 2,
                "batch_seal_sha256": second_manifest["batch_seal_sha256"],
                "commit_seal_sha256": sha256(second_commit.read_bytes()),
                "available_at": fixture.T5.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
            },
        ],
    }
    ledger_raw = canonical_json_line(ledger_payload)
    ledger_path = tmp_path / "commit-anchors-v2.json"
    ledger_path.write_bytes(ledger_raw)
    ledger_path.chmod(0o600)
    values[3] = second_manifest["batch_seal_sha256"]
    values[4] = sha256(second_commit.read_bytes())
    values[5] = load_commit_anchor_ledger(
        ledger_path,
        expected_raw_sha256=sha256(ledger_raw),
    )
    derived_root = tmp_path / "source-derived"
    fixture.rebuild(*values, derived_root)
    return fixture, values, DerivedPaths.open(derived_root)


def _backup_fixture(tmp_path: Path):
    fixture, values, source_derived = _revised_fixture(tmp_path / "source")
    backup_keys = _private_key_pair(tmp_path / "backup-keys")
    backup = BackupPaths.initialize(tmp_path / "off-host-backup")
    anchor = create_append_only_backup(
        source=values[0],
        source_derived=source_derived,
        backup=backup,
        public_key_path=values[1],
        registry=load_registry(fixture.REGISTRY_PATH),
        expected_genesis_seal_sha256=values[2],
        expected_head_seal_sha256=values[3],
        expected_head_commit_seal_sha256=values[4],
        ledger=values[5],
        binding=values[6],
        expected_parent_anchor_raw_sha256=None,
        backup_signer_key_id="research-backup-key-v1",
        backup_private_key_path=backup_keys[0],
        backup_public_key_path=backup_keys[1],
        expected_backup_public_key_sha256=backup_keys[2],
        minimum_free_bytes_after=0,
        now=NOW,
    )
    return fixture, values, backup, backup_keys, anchor


def test_append_only_backup_restore_migration_and_schema(
    tmp_path: Path,
) -> None:
    fixture, values, backup, backup_keys, anchor = _backup_fixture(tmp_path)
    restore = restore_and_verify(
        backup=backup,
        expected_backup_anchor_raw_sha256=anchor.raw_sha256,
        backup_public_key_path=backup_keys[1],
        expected_backup_public_key_sha256=backup_keys[2],
        restore_root=tmp_path / "restored-evidence",
        restore_derived_root=tmp_path / "restored-derived",
        manifest_public_key_path=values[1],
        registry=load_registry(fixture.REGISTRY_PATH),
        ledger=values[5],
        binding=values[6],
        minimum_free_bytes_after=0,
    )
    assert restore.rebuild_result["status"] == "EMPTY_ROOT_REBUILD_VALID"
    assert anchor.rebuild.catalog_logical_sha256
    migration_keys = _private_key_pair(tmp_path / "migration-keys")
    receipt_paths = MigrationReceiptPaths.initialize(tmp_path / "receipts")
    migrated = migrate_warehouse(
        source=restore.evidence,
        destination_root=tmp_path / "independent-research-host",
        receipt_paths=receipt_paths,
        manifest_public_key_path=values[1],
        registry=load_registry(fixture.REGISTRY_PATH),
        expected_genesis_seal_sha256=values[2],
        expected_head_seal_sha256=values[3],
        expected_head_commit_seal_sha256=values[4],
        migration_signer_key_id="research-migration-key-v1",
        migration_private_key_path=migration_keys[0],
        migration_public_key_path=migration_keys[1],
        expected_migration_public_key_sha256=migration_keys[2],
        minimum_free_bytes_after=0,
        now=NOW,
    )
    verified = verify_completed_migration(
        source=restore.evidence,
        destination=migrated.destination,
        receipt_path=migrated.receipt.path,
        expected_receipt_raw_sha256=migrated.receipt.raw_sha256,
        manifest_public_key_path=values[1],
        registry=load_registry(fixture.REGISTRY_PATH),
        migration_public_key_path=migration_keys[1],
        expected_migration_public_key_sha256=migration_keys[2],
    )
    assert verified.lineage.record_count == 2
    assert {
        item["original_batch_seal_sha256"]
        for item in verified.lineage.records
    } == {values[2], values[3]}
    assert verified.payload["original_batches_resigned"] is False
    for schema_path, payload in (
        (BACKUP_SCHEMA, anchor.payload),
        (MIGRATION_SCHEMA, verified.payload),
    ):
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(payload)


def test_tamper_and_replay_fail_closed(tmp_path: Path) -> None:
    _fixture, _values, backup, backup_keys, anchor = _backup_fixture(tmp_path)
    with pytest.raises(RegistryError, match="trusted pin"):
        verify_backup_anchor(
            paths=backup,
            public_key_path=backup_keys[1],
            expected_public_key_sha256=backup_keys[2],
            expected_head_anchor_raw_sha256="0" * 64,
        )
    target = next((backup.objects / "raw").rglob("*.raw"))
    target.write_bytes(target.read_bytes() + b"tamper")
    target.chmod(0o600)
    with pytest.raises(RegistryError, match="trusted head|object store"):
        verify_backup_anchor(
            paths=backup,
            public_key_path=backup_keys[1],
            expected_public_key_sha256=backup_keys[2],
            expected_head_anchor_raw_sha256=anchor.raw_sha256,
        )


def test_disk_low_and_migration_failure_publish_no_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, values, source_derived = _revised_fixture(tmp_path / "source")
    backup_keys = _private_key_pair(tmp_path / "backup-keys")
    backup = BackupPaths.initialize(tmp_path / "off-host-backup")
    monkeypatch.setattr(
        held_custody.os,
        "fstatvfs",
        lambda _descriptor: SimpleNamespace(f_bavail=0, f_frsize=1),
    )
    with pytest.raises(RegistryError, match="insufficient destination capacity"):
        create_append_only_backup(
            source=values[0],
            source_derived=source_derived,
            backup=backup,
            public_key_path=values[1],
            registry=load_registry(fixture.REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
            expected_parent_anchor_raw_sha256=None,
            backup_signer_key_id="research-backup-key-v1",
            backup_private_key_path=backup_keys[0],
            backup_public_key_path=backup_keys[1],
            expected_backup_public_key_sha256=backup_keys[2],
            minimum_free_bytes_after=1,
            now=NOW,
        )
    assert not list(backup.anchors.iterdir())
    monkeypatch.undo()
    migration_keys = _private_key_pair(tmp_path / "migration-keys")
    receipt_paths = MigrationReceiptPaths.initialize(tmp_path / "receipts")

    def fail_copy(**_kwargs):
        raise RegistryError("injected migration copy failure")

    monkeypatch.setattr(
        migration_service,
        "materialize_held_snapshot",
        fail_copy,
    )
    with pytest.raises(RegistryError, match="injected migration copy failure"):
        migrate_warehouse(
            source=values[0],
            destination_root=tmp_path / "failed-destination",
            receipt_paths=receipt_paths,
            manifest_public_key_path=values[1],
            registry=load_registry(fixture.REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            migration_signer_key_id="research-migration-key-v1",
            migration_private_key_path=migration_keys[0],
            migration_public_key_path=migration_keys[1],
            expected_migration_public_key_sha256=migration_keys[2],
            minimum_free_bytes_after=0,
            now=NOW,
        )
    assert not list(receipt_paths.receipts.iterdir())


def test_restore_rereads_actual_parquet_after_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, values, backup, backup_keys, anchor = _backup_fixture(tmp_path)
    real_rebuild = restore_service.rebuild_empty_catalog

    def corrupt_after_rebuild(**kwargs):
        result = real_rebuild(**kwargs)
        target = next(Path(kwargs["derived_root"]).rglob("*.parquet"))
        target.write_bytes(target.read_bytes() + b"post-rebuild-tamper")
        target.chmod(0o600)
        return result

    monkeypatch.setattr(
        restore_service,
        "rebuild_empty_catalog",
        corrupt_after_rebuild,
    )
    with pytest.raises(
        RegistryError,
        match="actual Parquet lineage hashes changed",
    ):
        restore_and_verify(
            backup=backup,
            expected_backup_anchor_raw_sha256=anchor.raw_sha256,
            backup_public_key_path=backup_keys[1],
            expected_backup_public_key_sha256=backup_keys[2],
            restore_root=tmp_path / "restored-evidence",
            restore_derived_root=tmp_path / "restored-derived",
            manifest_public_key_path=values[1],
            registry=load_registry(fixture.REGISTRY_PATH),
            ledger=values[5],
            binding=values[6],
            minimum_free_bytes_after=0,
        )


def _swap_root(original: Path, replacement: Path) -> Path:
    moved = original.with_name(original.name + "-held-original")
    original.rename(moved)
    replacement.rename(original)
    return moved


@pytest.mark.parametrize("target", ["source", "backup"])
def test_backup_root_replacement_publishes_no_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    fixture, values, source_derived = _revised_fixture(tmp_path / "source")
    backup_keys = _private_key_pair(tmp_path / "backup-keys")
    backup = BackupPaths.initialize(tmp_path / "off-host-backup")
    if target == "source":
        replacement = WarehousePaths.initialize(tmp_path / "replacement-source")
        root = values[0].root
    else:
        replacement = BackupPaths.initialize(tmp_path / "replacement-backup")
        root = backup.root
    real_create = backup_service._create_backup_anchor
    moved = None

    def replace_before_signing(**kwargs):
        nonlocal moved
        moved = _swap_root(root, replacement.root)
        return real_create(**kwargs)

    monkeypatch.setattr(
        backup_service,
        "_create_backup_anchor",
        replace_before_signing,
    )
    with pytest.raises(RegistryError, match="pathname identity changed"):
        create_append_only_backup(
            source=values[0],
            source_derived=source_derived,
            backup=backup,
            public_key_path=values[1],
            registry=load_registry(fixture.REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            ledger=values[5],
            binding=values[6],
            expected_parent_anchor_raw_sha256=None,
            backup_signer_key_id="research-backup-key-v1",
            backup_private_key_path=backup_keys[0],
            backup_public_key_path=backup_keys[1],
            expected_backup_public_key_sha256=backup_keys[2],
            minimum_free_bytes_after=0,
            now=NOW,
        )
    assert moved is not None
    anchor_root = moved if target == "backup" else backup.root
    assert not list((anchor_root / "anchors").iterdir())


def test_migration_destination_replacement_publishes_no_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, values, _source_derived = _revised_fixture(tmp_path / "source")
    migration_keys = _private_key_pair(tmp_path / "migration-keys")
    receipt_paths = MigrationReceiptPaths.initialize(tmp_path / "receipts")
    replacement = WarehousePaths.initialize(tmp_path / "replacement-destination")
    real_create = migration_service._create_migration_receipt

    def replace_before_signing(**kwargs):
        destination_held = kwargs["destination_held"]
        _swap_root(destination_held.path, replacement.root)
        return real_create(**kwargs)

    monkeypatch.setattr(
        migration_service,
        "_create_migration_receipt",
        replace_before_signing,
    )
    with pytest.raises(RegistryError, match="pathname identity changed"):
        migrate_warehouse(
            source=values[0],
            destination_root=tmp_path / "migration-destination",
            receipt_paths=receipt_paths,
            manifest_public_key_path=values[1],
            registry=load_registry(fixture.REGISTRY_PATH),
            expected_genesis_seal_sha256=values[2],
            expected_head_seal_sha256=values[3],
            expected_head_commit_seal_sha256=values[4],
            migration_signer_key_id="research-migration-key-v1",
            migration_private_key_path=migration_keys[0],
            migration_public_key_path=migration_keys[1],
            expected_migration_public_key_sha256=migration_keys[2],
            minimum_free_bytes_after=0,
            now=NOW,
        )
    assert not list(receipt_paths.receipts.iterdir())
