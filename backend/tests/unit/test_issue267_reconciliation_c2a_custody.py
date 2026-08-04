from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.schemas.deployment_drain import (
    DeploymentLegacyMigrationSourceArchiveDTO,
    DeploymentReconciliationCustodyInventoryDTO,
)
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)
from app.services.deployment_reconciliation_custody import (
    DeploymentReconciliationCustodyError,
    DeploymentReconciliationCustodyRepository,
    DeploymentReconciliationCustodySession,
)
from app.services.deployment_state_commitment import (
    build_state_commitment,
    parse_exact_state_commitment,
)

V1 = "web_bridge_deployment_drain_state_v1"
V2 = "web_bridge_deployment_drain_state_v2"
ANCHOR_V1 = "web_bridge_deployment_drain_epoch_anchor_v1"
AUTHORITY_FIELDS = (
    "clean_migration_eligibility_verified",
    "custody_inventory_verified",
    "external_high_water_verified",
    "target_runtime_verified",
    "reconciliation_completed",
    "windows_fence_released",
    "authority_restore_allowed",
    "consume_authorized",
    "reconciliation_authorized",
    "deployment_authorized",
    "automatic_deploy_allowed",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 5, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _service(root: Path, clock: Clock, runtime: str) -> DeploymentDrainService:
    return DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id=runtime,
        allow_initial_bootstrap=True,
    )


def _write_legacy_source(
    root: Path,
    clock: Clock,
    version: str,
    *,
    source_raw_transform=lambda raw: raw,
) -> tuple[DeploymentDrainService, bytes, bytes]:
    old = _service(root, clock, "legacy-runtime-old")
    old.status()
    state = old._load_state()
    for field in (
        "state_generation",
        "previous_state_commitment_raw_sha256",
        "consumed_receipt_id",
        "consume_intent_raw_sha256",
        "consume_marker_raw_sha256",
        "consume_state_projection_sha256",
        "consumed_online_recheck_id",
        "consumed_online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
    ):
        state.pop(field)
    if version == V1:
        for field in (
            "active_online_recheck_id",
            "active_online_recheck_raw_sha256",
            "active_recheck_checkpoint_raw_sha256",
            "online_rechecked_at",
            "last_invalidated_online_recheck_id",
        ):
            state.pop(field)
    state["schema_version"] = version
    source_raw = source_raw_transform(_canonical(state))
    anchor_raw = _canonical(
        {
            "schema_version": ANCHOR_V1,
            "drain_epoch": state["drain_epoch"],
            "execution_epoch": state["execution_epoch"],
        }
    )
    for path in old.state_commitment_dir.iterdir():
        path.unlink()
    old._atomic_write(old.state_path, source_raw)
    old._atomic_write(old.epoch_anchor_path, anchor_raw)
    return old, source_raw, anchor_raw


def _archive_files(
    service: DeploymentDrainService,
) -> dict[str, tuple[Path, bytes]]:
    result: dict[str, tuple[Path, bytes]] = {}
    for path in sorted(service.migration_source_dir.iterdir()):
        if path.name.startswith("source-state-"):
            kind = "state"
        elif path.name.startswith("source-epoch-anchor-"):
            kind = "anchor"
        elif path.name.startswith("archive-"):
            kind = "archive"
        else:  # pragma: no cover - a production regression should fail loudly
            raise AssertionError(f"unexpected migration source artifact: {path.name}")
        result[kind] = (path, path.read_bytes())
    return result


def _migrated_legacy_custody(root: Path, version: str = V2) -> DeploymentDrainService:
    clock = Clock()
    old, _, _ = _write_legacy_source(root, clock, version)
    migrated = _service(old.root, clock, "legacy-runtime-migrated")
    migrated.status()
    return migrated


def _fresh_frozen_custody(root: Path, clock: Clock) -> DeploymentDrainService:
    bootstrap = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="bootstrap-frozen-runtime",
        allow_initial_bootstrap=True,
        initial_bootstrap_state="RESTARTED_FROZEN",
    )
    bootstrap.status()
    current = _service(root, clock, "fresh-runtime-online")
    current.status()
    return current


def _assert_custody_error(
    root: Path,
    expected_code: str,
) -> None:
    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        DeploymentReconciliationCustodyRepository(root).snapshot(
            captured_at=datetime(2026, 8, 5, 1, tzinfo=timezone.utc)
        )
    assert caught.value.code == expected_code


@pytest.mark.parametrize("version", [V1, V2])
def test_legacy_migration_seals_exact_three_file_archive_before_v3(
    tmp_path: Path,
    version: str,
) -> None:
    clock = Clock()
    old, source_raw, anchor_raw = _write_legacy_source(
        tmp_path / version,
        clock,
        version,
    )

    migrated = _service(old.root, clock, "legacy-runtime-migrated")
    status = migrated.status()

    files = _archive_files(migrated)
    assert set(files) == {"state", "anchor", "archive"}
    assert files["state"][1] == source_raw
    assert files["anchor"][1] == anchor_raw
    archive = DeploymentLegacyMigrationSourceArchiveDTO.model_validate_json(
        files["archive"][1]
    )
    assert files["archive"][1] == _canonical(archive.model_dump(mode="json"))
    assert archive.source_schema_version == version
    assert archive.source_state_raw_sha256 == _sha256(source_raw)
    assert archive.source_epoch_anchor_raw_sha256 == _sha256(anchor_raw)
    assert old.root / archive.source_state_path == files["state"][0]
    assert old.root / archive.source_epoch_anchor_path == files["anchor"][0]
    assert old.root / archive.archive_path == files["archive"][0]
    for field in AUTHORITY_FIELDS:
        assert getattr(archive, field) is False

    genesis_path = min(migrated.state_commitment_dir.iterdir())
    genesis = parse_exact_state_commitment(genesis_path.read_bytes())
    assert genesis.genesis_source == (
        "v1_migration" if version == V1 else "v2_migration"
    )
    assert genesis.source_state_raw_sha256 == archive.source_state_raw_sha256
    assert (
        genesis.source_epoch_anchor_raw_sha256 == archive.source_epoch_anchor_raw_sha256
    )
    assert status["schema_version"] == "web_bridge_deployment_drain_state_v3"
    assert status["state"] == "RESTARTED_FROZEN"


@pytest.mark.parametrize("version", [V1, V2])
def test_exact_source_archive_is_idempotent_across_migration_retry(
    tmp_path: Path,
    version: str,
) -> None:
    clock = Clock()
    old, source_raw, anchor_raw = _write_legacy_source(
        tmp_path / version,
        clock,
        version,
    )
    first = old._persist_legacy_migration_source_archive(
        source_schema_version=version,
        source_state_raw=source_raw,
        source_epoch_anchor_raw=anchor_raw,
    )
    before = {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in old.migration_source_dir.iterdir()
    }

    migrated = _service(old.root, clock, "legacy-runtime-migrated")
    migrated.status()
    after = {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in migrated.migration_source_dir.iterdir()
    }

    assert after == before
    assert set(after) == {
        Path(first.source_state_path).name,
        Path(first.source_epoch_anchor_path).name,
        Path(first.archive_path).name,
    }


@pytest.mark.parametrize("version", [V1, V2])
@pytest.mark.parametrize("collision_kind", ["state", "anchor", "archive"])
def test_source_archive_collision_does_not_overwrite_legacy_state_or_anchor(
    tmp_path: Path,
    version: str,
    collision_kind: str,
) -> None:
    clock = Clock()
    probe, source_raw, anchor_raw = _write_legacy_source(
        tmp_path / "probe" / version,
        clock,
        version,
    )
    probe._persist_legacy_migration_source_archive(
        source_schema_version=version,
        source_state_raw=source_raw,
        source_epoch_anchor_raw=anchor_raw,
    )
    expected = _archive_files(probe)

    target, target_source_raw, target_anchor_raw = _write_legacy_source(
        tmp_path / "target" / version,
        clock,
        version,
    )
    assert target_source_raw == source_raw
    assert target_anchor_raw == anchor_raw
    collision_path = target.migration_source_dir / expected[collision_kind][0].name
    target._write_create_only_atomic(collision_path, b"different-bytes\n")

    with pytest.raises(DeploymentDrainError) as caught:
        _service(target.root, clock, "legacy-runtime-migrated").status()

    assert caught.value.code == "DEPLOYMENT_LEGACY_MIGRATION_SOURCE_COLLISION"
    assert target.state_path.read_bytes() == source_raw
    assert target.epoch_anchor_path.read_bytes() == anchor_raw
    assert json.loads(target.state_path.read_bytes())["schema_version"] == version
    assert not any(target.state_commitment_dir.iterdir())
    assert collision_path.read_bytes() == b"different-bytes\n"


@pytest.mark.parametrize("version", [V1, V2])
def test_noncanonical_legacy_source_is_rejected_before_archive_or_v3(
    tmp_path: Path,
    version: str,
) -> None:
    clock = Clock()
    old, source_raw, anchor_raw = _write_legacy_source(
        tmp_path / version,
        clock,
        version,
        source_raw_transform=lambda raw: raw[:-1] + b" \n",
    )

    with pytest.raises(DeploymentDrainError) as caught:
        _service(old.root, clock, "legacy-runtime-migrated").status()

    assert caught.value.code == "DEPLOYMENT_LEGACY_MIGRATION_SOURCE_NONCANONICAL"
    assert old.state_path.read_bytes() == source_raw
    assert old.epoch_anchor_path.read_bytes() == anchor_raw
    assert not any(old.migration_source_dir.iterdir())
    assert not any(old.state_commitment_dir.iterdir())


@pytest.mark.parametrize("version", [V1, V2])
@pytest.mark.parametrize("fail_after_exact_files", [1, 2])
def test_interrupted_archive_publish_is_completed_deterministically_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
    fail_after_exact_files: int,
) -> None:
    clock = Clock()
    old, source_raw, anchor_raw = _write_legacy_source(
        tmp_path / version,
        clock,
        version,
    )
    original = DeploymentDrainService._write_create_only_atomic
    calls = 0

    def interrupted_write(
        service: DeploymentDrainService,
        path: Path,
        data: bytes,
        *,
        before_publish=None,
    ) -> None:
        nonlocal calls
        if path.parent == service.migration_source_dir:
            calls += 1
            if calls > fail_after_exact_files:
                raise OSError("injected migration source archive interruption")
        original(
            service,
            path,
            data,
            before_publish=before_publish,
        )

    monkeypatch.setattr(
        DeploymentDrainService,
        "_write_create_only_atomic",
        interrupted_write,
    )
    with pytest.raises(OSError, match="injected"):
        _service(old.root, clock, "legacy-runtime-interrupted").status()
    partial = _archive_files(old)
    assert len(partial) == fail_after_exact_files
    assert old.state_path.read_bytes() == source_raw
    assert old.epoch_anchor_path.read_bytes() == anchor_raw
    assert not any(old.state_commitment_dir.iterdir())

    monkeypatch.setattr(
        DeploymentDrainService,
        "_write_create_only_atomic",
        original,
    )
    completed = _service(old.root, clock, "legacy-runtime-completed")
    completed.status()

    files = _archive_files(completed)
    assert set(files) == {"state", "anchor", "archive"}
    assert files["state"][1] == source_raw
    assert files["anchor"][1] == anchor_raw
    archive = DeploymentLegacyMigrationSourceArchiveDTO.model_validate_json(
        files["archive"][1]
    )
    assert archive.source_state_raw_sha256 == _sha256(source_raw)
    assert archive.source_epoch_anchor_raw_sha256 == _sha256(anchor_raw)


def test_published_migration_source_hardlink_temp_is_recovered(tmp_path: Path) -> None:
    clock = Clock()
    old, source_raw, anchor_raw = _write_legacy_source(
        tmp_path / "published-temp",
        clock,
        V2,
    )
    archive = old._persist_legacy_migration_source_archive(
        source_schema_version=V2,
        source_state_raw=source_raw,
        source_epoch_anchor_raw=anchor_raw,
    )
    final = old.root / archive.archive_path
    temporary = final.with_name(f".{final.name}.{'e' * 32}.tmp")
    os.link(final, temporary)
    assert final.stat().st_nlink == 2

    restarted = _service(old.root, clock, "legacy-runtime-recovered")
    status = restarted.status()

    assert not temporary.exists()
    assert final.stat().st_nlink == 1
    assert status["state"] == "RESTARTED_FROZEN"


@pytest.mark.parametrize("version", [V1, V2])
def test_legacy_migration_custody_snapshot_binds_exact_live_inventory(
    tmp_path: Path,
    version: str,
) -> None:
    service = _migrated_legacy_custody(tmp_path / version, version)
    captured_at = datetime(2026, 8, 5, 1, tzinfo=timezone.utc)

    snapshot = DeploymentReconciliationCustodyRepository(service.root).snapshot(
        captured_at=captured_at
    )
    inventory = snapshot.inventory
    paths = {entry.relative_path for entry in inventory.entries}

    assert inventory.mode == "LEGACY_MIGRATION_BASELINE"
    assert inventory.captured_at == captured_at
    assert paths == {
        "state.json",
        "epoch-anchor.json",
        "state-commitments/00000000000000000001.json",
        "state-commitments/00000000000000000002.json",
        *(
            str(path.relative_to(service.root))
            for path in service.migration_source_dir.iterdir()
        ),
    }
    assert set(snapshot.files) == paths
    assert snapshot.raw_for("state.json") == service.state_path.read_bytes()
    assert inventory.genesis_commitment.genesis_source == (
        "v1_migration" if version == V1 else "v2_migration"
    )
    archive = DeploymentLegacyMigrationSourceArchiveDTO.model_validate_json(
        next(service.migration_source_dir.glob("archive-*.json")).read_bytes()
    )
    assert (
        inventory.genesis_commitment.source_state_raw_sha256
        == archive.source_state_raw_sha256
    )
    assert (
        inventory.genesis_commitment.source_epoch_anchor_raw_sha256
        == archive.source_epoch_anchor_raw_sha256
    )
    for field in (
        "external_high_water_verified",
        "target_runtime_verified",
        "reconciliation_completed",
        "windows_fence_released",
        "authority_restore_allowed",
        "consume_authorized",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        assert getattr(inventory, field) is False


def test_fresh_bootstrap_custody_snapshot_is_initial_non_authorizing_baseline(
    tmp_path: Path,
) -> None:
    clock = Clock()
    current = _fresh_frozen_custody(tmp_path / "fresh", clock)

    snapshot = DeploymentReconciliationCustodyRepository(current.root).snapshot(
        captured_at=datetime(2026, 8, 5, 1, tzinfo=timezone.utc)
    )
    inventory = snapshot.inventory

    assert inventory.mode == "INITIAL_BASELINE"
    assert inventory.genesis_commitment.genesis_source == "fresh_bootstrap"
    assert not any(current.migration_source_dir.iterdir())
    assert inventory.actual_state_generation == 3
    assert inventory.actual_head_commitment.state == inventory.actual_state
    for field in (
        "external_high_water_verified",
        "target_runtime_verified",
        "reconciliation_completed",
        "windows_fence_released",
        "authority_restore_allowed",
        "consume_authorized",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        assert getattr(inventory, field) is False


def test_custody_rejects_missing_legacy_archive_instead_of_downgrading_mode(
    tmp_path: Path,
) -> None:
    service = _migrated_legacy_custody(tmp_path / "missing-archive")
    next(service.migration_source_dir.glob("archive-*.json")).unlink()

    _assert_custody_error(service.root, "CUSTODY_LEGACY_ARCHIVE_INCOMPLETE")


def test_custody_rejects_extra_allowlisted_legacy_archive_file(tmp_path: Path) -> None:
    service = _migrated_legacy_custody(tmp_path / "extra-archive")
    extra = service.migration_source_dir / f"archive-{'1' * 64}.json"
    extra.write_bytes(_canonical({"unexpected": True}))
    extra.chmod(0o600)

    _assert_custody_error(service.root, "CUSTODY_LEGACY_ARCHIVE_INCOMPLETE")


def test_custody_rejects_temporary_file(tmp_path: Path) -> None:
    service = _migrated_legacy_custody(tmp_path / "temporary")
    temporary = service.migration_source_dir / ".archive-write.tmp"
    temporary.write_bytes(_canonical({"partial": True}))
    temporary.chmod(0o600)

    _assert_custody_error(
        service.root,
        "CUSTODY_TEMPORARY_OR_BACKUP_FORBIDDEN",
    )


def test_custody_rejects_symlinked_inventory_file(tmp_path: Path) -> None:
    service = _migrated_legacy_custody(tmp_path / "symlink")
    link = service.receipt_dir / f"safe-restart-{'1' * 64}.json"
    link.symlink_to(service.state_path)

    _assert_custody_error(service.root, "CUSTODY_FILE_OPEN_FAILED")


def test_custody_rejects_hardlinked_inventory_file(tmp_path: Path) -> None:
    service = _migrated_legacy_custody(tmp_path / "hardlink")
    link = service.receipt_dir / f"safe-restart-{'1' * 64}.json"
    os.link(service.state_path, link)

    _assert_custody_error(service.root, "CUSTODY_FILE_INSECURE")


def test_custody_rejects_commitment_generation_gap(tmp_path: Path) -> None:
    service = _migrated_legacy_custody(tmp_path / "gap")
    generation_two = service.state_commitment_dir / "00000000000000000002.json"
    generation_two.rename(service.state_commitment_dir / "00000000000000000003.json")

    _assert_custody_error(service.root, "CUSTODY_COMMITMENT_CHAIN_GAP")


def test_custody_rejects_epoch_anchor_head_mismatch(tmp_path: Path) -> None:
    service = _migrated_legacy_custody(tmp_path / "anchor-mismatch")
    anchor = json.loads(service.epoch_anchor_path.read_bytes())
    anchor["drain_epoch"] += 1
    service.epoch_anchor_path.write_bytes(_canonical(anchor))

    _assert_custody_error(service.root, "CUSTODY_CURRENT_HEAD_MISMATCH")


def test_custody_rejects_coherent_genesis_mode_downgrade_with_legacy_archive(
    tmp_path: Path,
) -> None:
    service = _migrated_legacy_custody(tmp_path / "mode-downgrade")
    genesis_path = service.state_commitment_dir / "00000000000000000001.json"
    head_path = service.state_commitment_dir / "00000000000000000002.json"
    genesis = parse_exact_state_commitment(genesis_path.read_bytes())
    downgraded_genesis = build_state_commitment(
        genesis.state,
        genesis_source="fresh_bootstrap",
    )
    downgraded_genesis_raw = _canonical(downgraded_genesis.model_dump(mode="json"))
    genesis_path.write_bytes(downgraded_genesis_raw)

    head = parse_exact_state_commitment(head_path.read_bytes())
    downgraded_state = dict(head.state)
    downgraded_state["previous_state_commitment_raw_sha256"] = _sha256(
        downgraded_genesis_raw
    )
    downgraded_head = build_state_commitment(downgraded_state)
    downgraded_head_raw = _canonical(downgraded_head.model_dump(mode="json"))
    head_path.write_bytes(downgraded_head_raw)
    service.state_path.write_bytes(_canonical(downgraded_state))
    anchor = json.loads(service.epoch_anchor_path.read_bytes())
    anchor["state_commitment_raw_sha256"] = _sha256(downgraded_head_raw)
    service.epoch_anchor_path.write_bytes(_canonical(anchor))

    _assert_custody_error(service.root, "CUSTODY_INITIAL_BASELINE_INCOMPLETE")


@pytest.mark.parametrize("baseline", ["fresh", "legacy"])
def test_unconsumed_baseline_rejects_business_inventory(
    tmp_path: Path,
    baseline: str,
) -> None:
    clock = Clock()
    if baseline == "fresh":
        service = _fresh_frozen_custody(tmp_path / baseline, clock)
    else:
        service = _migrated_legacy_custody(tmp_path / baseline)
    receipt = service.receipt_dir / f"safe-restart-{'1' * 64}.json"
    receipt.write_bytes(_canonical({"unexpected": "baseline artifact"}))
    receipt.chmod(0o600)

    _assert_custody_error(service.root, "CUSTODY_BASELINE_INVENTORY_NOT_EMPTY")


def test_custody_entry_limit_blocks_before_any_file_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _fresh_frozen_custody(tmp_path / "bounded-enumeration", Clock())

    def unexpected_read(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("bounded enumeration must fail before reading files")

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession,
        "_read_file",
        unexpected_read,
    )
    repository = DeploymentReconciliationCustodyRepository(
        current.root,
        max_entries=2,
    )

    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        repository.snapshot()

    assert caught.value.code == "CUSTODY_ENTRY_LIMIT_EXCEEDED"


def test_custody_rejects_in_place_file_change_after_complete_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _fresh_frozen_custody(tmp_path / "post-read-change", Clock())
    original = DeploymentReconciliationCustodySession._read_inventory

    def mutate_after_read(
        session: DeploymentReconciliationCustodySession,
        directories: object,
    ) -> object:
        files = original(session, directories)  # type: ignore[arg-type]
        current.state_path.write_bytes(b"{}\n")
        current.state_path.chmod(0o600)
        return files

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession,
        "_read_inventory",
        mutate_after_read,
    )

    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        DeploymentReconciliationCustodyRepository(current.root).snapshot()

    assert caught.value.code == "CUSTODY_FILE_CHANGED_AFTER_READ"


def test_custody_rejects_ancestor_symlink_swap_during_anchored_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_parent = tmp_path / "actual-parent"
    pinned_parent = tmp_path / "actual-parent-pinned"
    replacement_parent = tmp_path / "replacement-parent"
    current = _fresh_frozen_custody(actual_parent / "custody", Clock())
    _fresh_frozen_custody(replacement_parent / "custody", Clock())
    original_open = os.open
    swapped = False

    def swap_after_component_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == actual_parent.name and dir_fd is not None and not swapped:
            actual_parent.rename(pinned_parent)
            actual_parent.symlink_to(replacement_parent, target_is_directory=True)
            swapped = True
        return descriptor

    monkeypatch.setattr(os, "open", swap_after_component_open)

    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        DeploymentReconciliationCustodyRepository(current.root).snapshot()

    assert swapped is True
    assert caught.value.code == "CUSTODY_ROOT_REPLACED"


def test_inventory_dto_rejects_rehashed_missing_middle_commitment(
    tmp_path: Path,
) -> None:
    current = _fresh_frozen_custody(tmp_path / "inventory-middle-gap", Clock())
    payload = (
        DeploymentReconciliationCustodyRepository(current.root)
        .snapshot()
        .inventory.model_dump(mode="json")
    )
    payload["entries"] = [
        entry
        for entry in payload["entries"]
        if entry["relative_path"] != "state-commitments/00000000000000000002.json"
    ]
    payload["inventory_digest_sha256"] = _sha256(_canonical(payload["entries"])[:-1])
    core = dict(payload)
    core.pop("inventory_id")
    core.pop("inventory_core_sha256")
    digest = _sha256(_canonical(core)[:-1])
    payload["inventory_core_sha256"] = digest
    payload["inventory_id"] = f"deployment-reconciliation-custody-inventory-{digest}"

    with pytest.raises(ValueError, match="commitment entries are not exact"):
        DeploymentReconciliationCustodyInventoryDTO.model_validate(payload)
