# ruff: noqa: E402

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import research_warehouse.daily_roll_predecessor_catalog as catalog
from research_warehouse.canonical import canonical_json_line, sha256
import research_warehouse.verified_daily_pit_main_roll_source as verified_roll
from test_research_warehouse_verified_daily_pit_main_roll_source import (
    _kwargs,
    _state,
    _verified_input,
)


def _root_harness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state_holder: dict[str, object],
) -> None:
    @contextmanager
    def unlocked(*_args, **_kwargs):
        yield

    def prepare(path: Path) -> None:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)

    def create_only(path: Path, raw: bytes, *, create_only: bool = False) -> None:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if create_only and path.exists():
            raise catalog.DailyRollPredecessorCatalogError("test create-only collision")
        path.write_bytes(raw)
        path.chmod(0o444)

    def root_link_info(path: Path) -> SimpleNamespace:
        info = path.lstat()
        return SimpleNamespace(
            st_uid=0,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
        )

    def verified_retry_root(**values):
        state = values["operator_state"]
        verified = state_holder["inputs"][state.payload["last_trade_day"]]
        manifest = dict(verified.manifest)
        manifest["revisions"] = [
            {**row, "observation_ids": [row["observation_id"]]}
            for row in verified.manifest["revisions"]
        ]
        return (
            manifest,
            verified.manifest_raw_sha256,
            verified.commit_receipt_raw_sha256,
        )

    monkeypatch.setattr(catalog, "_require_root", lambda: None)
    monkeypatch.setattr(catalog, "_prepare_public_root_directory", prepare)
    monkeypatch.setattr(catalog, "_require_root_parent", lambda _path: None)
    monkeypatch.setattr(catalog, "require_root_managed", lambda _path: None)
    monkeypatch.setattr(catalog, "_validate_root_file_fd", lambda _fd: None)
    monkeypatch.setattr(catalog, "_validate_recovery_root_file_fd", lambda _fd: None)
    monkeypatch.setattr(catalog, "_validate_unpublished_partial_fd", lambda _fd: None)
    monkeypatch.setattr(catalog, "_recovery_link_info", root_link_info)
    monkeypatch.setattr(catalog, "_verified_retry_root", verified_retry_root)
    monkeypatch.setattr(catalog, "operator_state_lock", unlocked)
    monkeypatch.setattr(
        catalog,
        "load_operator_state",
        lambda _path: state_holder["state"],
    )
    monkeypatch.setattr(catalog, "_atomic_root_write", create_only)


def _genesis_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict, dict[str, verified_roll._VerifiedDailyInput], dict[str, object]]:
    kwargs, inputs, _private = _kwargs(monkeypatch, tmp_path)
    state = replace(kwargs["operator_state"], path=tmp_path / "operator-state.json")
    kwargs["operator_state"] = state
    holder: dict[str, object] = {"state": state, "inputs": inputs}
    _root_harness(monkeypatch, tmp_path, holder)
    return kwargs, inputs, holder


def _linked_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict, dict, dict[str, object], catalog.CatalogEntry, catalog.CatalogEntry]:
    kwargs, inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    genesis_entry = catalog.publish_predecessor_artifact(**kwargs)
    head = "9" * 64
    commit = "a" * 64
    state = _state("2026-07-02", head, commit, sequence=2)
    state = replace(state, path=kwargs["operator_state"].path)
    holder["state"] = state
    current = _verified_input(
        "2026-07-02",
        head_seal=head,
        head_commit=commit,
        parent_seal=genesis_entry.artifact["verified_lineage"]["manifest"][
            "batch_seal_sha256"
        ],
        parent_commit=genesis_entry.artifact["verified_lineage"]["manifest"][
            "commit_seal_sha256"
        ],
        expected_genesis_baseline=None,
    )
    current = replace(current, predecessor_entry=genesis_entry)
    inputs["2026-07-02"] = current
    kwargs.update(
        operator_state=state,
        official_day="2026-07-02",
        genesis=None,
        predecessor=verified_roll.PredecessorContinuity(),
    )
    linked_entry = catalog.publish_predecessor_artifact(**kwargs)
    return kwargs, inputs, holder, genesis_entry, linked_entry


def _replace_catalog_artifact(
    root: Path,
    entry: catalog.CatalogEntry,
    artifact: dict,
) -> catalog.CatalogEntry:
    artifact["artifact_id"] = verified_roll._artifact_id(artifact)
    artifact_raw = canonical_json_line(artifact)
    old_artifact_path = root / entry.receipt["artifact_relative_path"]
    new_artifact_path = root / catalog._artifact_relative_path(artifact["artifact_id"])
    old_artifact_path.unlink()
    new_artifact_path.write_bytes(artifact_raw)
    new_artifact_path.chmod(0o444)
    receipt = dict(entry.receipt)
    receipt.update(
        artifact_id=artifact["artifact_id"],
        artifact_raw_sha256=sha256(artifact_raw),
        artifact_raw_bytes=len(artifact_raw),
        artifact_relative_path=catalog._artifact_relative_path(artifact["artifact_id"]),
    )
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_raw = canonical_json_line(receipt)
    receipt_path = root / "receipts" / f"{receipt['official_day']}.json"
    receipt_path.chmod(0o644)
    receipt_path.write_bytes(receipt_raw)
    receipt_path.chmod(0o444)
    return catalog.CatalogEntry(receipt_raw, receipt, artifact_raw, artifact)


def test_publication_replays_builder_and_is_create_only_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)

    first = catalog.publish_predecessor_artifact(**kwargs)
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("same-day retry rebuilt the artifact"),
    )
    second = catalog.publish_predecessor_artifact(**kwargs)

    assert second == first
    assert first.receipt["sequence"] == 1
    assert first.receipt["previous_receipt_raw_sha256"] is None
    assert first.receipt["artifact_raw_sha256"] == sha256(first.artifact_raw)
    assert first.receipt["artifact_id"] == first.artifact["artifact_id"]
    assert first.receipt["authority"] == first.artifact["authority"]
    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert sorted(path.name for path in (root / "receipts").iterdir()) == [
        "2026-07-01.json"
    ]
    assert sorted(path.name for path in (root / "artifacts").iterdir()) == [
        f"{first.artifact['artifact_id']}.json"
    ]


def test_publication_cannot_accept_forged_structural_raw_with_current_labels(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    forged = json.loads(built.artifact_raw)
    forged["verified_lineage"]["runtime"]["runtime_input_raw_sha256"] = "f" * 64
    forged["artifact_id"] = verified_roll._artifact_id(forged)
    forged_raw = canonical_json_line(forged)
    # The forgery is structurally coherent and retains all current operator
    # labels, but no public catalog API accepts caller-selected raw bytes.
    verified_roll.validate_structural_daily_pit_main_roll_source(forged_raw)

    with pytest.raises(TypeError, match="artifact_raw"):
        catalog.publish_predecessor_artifact(
            operator_state=kwargs["operator_state"],
            artifact_raw=forged_raw,
        )

    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert not root.exists()


def test_catalog_load_rejects_receipt_artifact_hash_tamper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    entry = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipt_path = root / "receipts" / "2026-07-01.json"
    receipt = json.loads(entry.receipt_raw)
    receipt["artifact_raw_sha256"] = "f" * 64
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_path.chmod(0o644)
    receipt_path.write_bytes(canonical_json_line(receipt))
    receipt_path.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="receipt/artifact binding mismatch",
    ):
        catalog._load_catalog(root)


def test_catalog_load_rejects_non_contiguous_sequence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    entry = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipt_path = root / "receipts" / "2026-07-01.json"
    receipt = json.loads(entry.receipt_raw)
    receipt["sequence"] = 2
    receipt["previous_receipt_raw_sha256"] = "e" * 64
    receipt["previous_artifact_id"] = "verified-daily-roll-" + "d" * 64
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_path.chmod(0o644)
    receipt_path.write_bytes(canonical_json_line(receipt))
    receipt_path.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="sequence is not contiguous",
    ):
        catalog._load_catalog(root)


def test_same_day_different_root_replayed_result_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    kwargs["context"] = SimpleNamespace(
        **{
            **vars(kwargs["context"]),
            "runtime_input": SimpleNamespace(raw_sha256="f" * 64),
        }
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="retry inputs do not match stored artifact",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_same_day_retry_rejects_forged_genesis_caller_bundle_before_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    kwargs["genesis"] = replace(kwargs["genesis"], source_month="2026-05")
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("forged retry reached the builder"),
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="retry input verification failed",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_publication_rejects_operator_root_change_after_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    original = verified_roll.build_verified_daily_pit_main_roll_source

    def build_then_rotate(**values):
        built = original(**values)
        state = values["operator_state"]
        holder["state"] = replace(state, raw_sha256="f" * 64)
        return built

    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        build_then_rotate,
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="operator state changed before publication",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert not list((root / "artifacts").iterdir())
    assert not list((root / "receipts").iterdir())


def test_exact_orphan_artifact_is_recovered_but_conflict_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    artifact_path = root / catalog._artifact_relative_path(built.artifact_id)
    artifact_path.write_bytes(built.artifact_raw)
    artifact_path.chmod(0o444)

    recovered = catalog.publish_predecessor_artifact(**kwargs)
    assert recovered.artifact_raw == built.artifact_raw

    receipt_path = root / "receipts" / "2026-07-01.json"
    receipt_path.unlink()
    artifact_path.chmod(0o644)
    artifact_path.write_bytes(b"{}\n")
    artifact_path.chmod(0o444)
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="orphan artifact conflicts",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_artifact_link_before_unlink_crash_is_strictly_recovered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    target.write_bytes(built.artifact_raw)
    target.chmod(0o444)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    os.link(target, partial)
    assert target.stat().st_nlink == 2
    original = verified_roll.build_verified_daily_pit_main_roll_source

    def build_after_recovery(**values):
        assert not partial.exists()
        assert not target.exists()
        return original(**values)

    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        build_after_recovery,
    )

    entry = catalog.publish_predecessor_artifact(**kwargs)

    assert entry.artifact_raw == built.artifact_raw
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_receipt_link_before_unlink_crash_is_strictly_recovered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    first = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    target = root / "receipts" / "2026-07-01.json"
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    os.link(target, partial)
    assert target.stat().st_nlink == 2
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("receipt-commit retry rebuilt the artifact"),
    )

    recovered = catalog.publish_predecessor_artifact(**kwargs)

    assert recovered == first
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_complete_artifact_before_link_partial_is_validated_and_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(built.artifact_raw)
    partial.chmod(0o444)
    assert not target.exists()
    original = verified_roll.build_verified_daily_pit_main_roll_source

    def build_after_recovery(**values):
        assert not partial.exists()
        assert not target.exists()
        return original(**values)

    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        build_after_recovery,
    )

    entry = catalog.publish_predecessor_artifact(**kwargs)

    assert entry.artifact_raw == built.artifact_raw
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_complete_receipt_before_link_partial_is_validated_and_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    first = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    target = root / "receipts" / "2026-07-01.json"
    target.unlink()
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(first.receipt_raw)
    partial.chmod(0o444)

    recovered = catalog.publish_predecessor_artifact(**kwargs)

    assert recovered == first
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_incomplete_private_before_link_partial_is_safely_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(b'{"interrupted":')
    partial.chmod(0o600)

    recovered = catalog.publish_predecessor_artifact(**kwargs)

    assert recovered.artifact_raw == built.artifact_raw
    assert not partial.exists()


@pytest.mark.parametrize("directory", ["artifacts", "receipts"])
def test_invalid_completed_before_link_partial_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    directory: str,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    if directory == "artifacts":
        target = root / catalog._artifact_relative_path(built.artifact_id)
    else:
        target = root / "receipts" / "2026-07-01.json"
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(b"{}\n")
    partial.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="completed unpublished partial is invalid",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    assert partial.exists()
    assert not target.exists()


def test_conflicting_separate_partial_inode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    target.write_bytes(built.artifact_raw)
    target.chmod(0o444)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(built.artifact_raw)
    partial.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="recovery link identity mismatch",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    assert partial.exists()
    assert not (root / "receipts" / "2026-07-01.json").exists()


def test_recovery_rejects_target_with_more_than_one_partial_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    target.write_bytes(built.artifact_raw)
    target.chmod(0o444)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    extra = target.with_name(f"{target.name}.extra-link")
    os.link(target, partial)
    os.link(target, extra)
    assert target.stat().st_nlink == 3

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="recovery link identity mismatch",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    assert partial.exists()
    assert extra.exists()


def test_linked_day_uses_catalog_head_and_extends_receipt_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    genesis_entry = catalog.publish_predecessor_artifact(**kwargs)

    head = "9" * 64
    commit = "a" * 64
    state = _state("2026-07-02", head, commit, sequence=2)
    state = replace(state, path=kwargs["operator_state"].path)
    holder["state"] = state
    current = _verified_input(
        "2026-07-02",
        head_seal=head,
        head_commit=commit,
        parent_seal=genesis_entry.artifact["verified_lineage"]["manifest"][
            "batch_seal_sha256"
        ],
        parent_commit=genesis_entry.artifact["verified_lineage"]["manifest"][
            "commit_seal_sha256"
        ],
        expected_genesis_baseline=None,
    )
    loaded = catalog._load_linked_predecessor_locked(
        operator_state=state,
        current_official_day=verified_roll._day("2026-07-02", "test day"),
        current_execution_day=verified_roll._day("2026-07-03", "test day"),
        current_manifest=current.manifest,
        runtime_input_raw_sha256=kwargs["context"].runtime_input.raw_sha256,
        calendar_raw_sha256=kwargs["context"].calendar.raw_sha256,
        calendar_availability_anchor_raw_sha256=kwargs[
            "context"
        ].availability.raw_sha256,
        isolation_policy_raw_sha256=kwargs["context"].policy.raw_sha256,
        warehouse_registry_raw_sha256=kwargs["context"].registry.raw_sha256,
        contract_registry_raw_sha256=kwargs["expected_contract_registry_raw_sha256"],
    )
    assert loaded == genesis_entry
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="predecessor/current-root continuity mismatch",
    ):
        catalog._load_linked_predecessor_locked(
            operator_state=state,
            current_official_day=verified_roll._day("2026-07-02", "test day"),
            current_execution_day=verified_roll._day("2026-07-03", "test day"),
            current_manifest=current.manifest,
            runtime_input_raw_sha256="f" * 64,
            calendar_raw_sha256=kwargs["context"].calendar.raw_sha256,
            calendar_availability_anchor_raw_sha256=kwargs[
                "context"
            ].availability.raw_sha256,
            isolation_policy_raw_sha256=kwargs["context"].policy.raw_sha256,
            warehouse_registry_raw_sha256=kwargs["context"].registry.raw_sha256,
            contract_registry_raw_sha256=kwargs[
                "expected_contract_registry_raw_sha256"
            ],
        )
    inputs["2026-07-02"] = replace(current, predecessor_entry=loaded)
    kwargs.update(
        operator_state=state,
        official_day="2026-07-02",
        genesis=None,
        predecessor=verified_roll.PredecessorContinuity(),
    )

    linked = catalog.publish_predecessor_artifact(**kwargs)

    assert linked.receipt["sequence"] == 2
    assert linked.receipt["previous_receipt_raw_sha256"] == sha256(
        genesis_entry.receipt_raw
    )
    assert (
        linked.receipt["previous_artifact_id"] == genesis_entry.artifact["artifact_id"]
    )
    assert linked.artifact["verified_lineage"]["continuity"]["mode"] == (
        "LINKED_ROOT_CATALOG"
    )
    assert (
        linked.artifact["verified_lineage"]["continuity"]["predecessor_artifact_id"]
        == genesis_entry.artifact["artifact_id"]
    )


def test_catalog_rejects_nonfirst_genesis_cross_branch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, genesis_entry, linked_entry = _linked_setup(
        monkeypatch, tmp_path
    )
    root = catalog.catalog_root(kwargs["operator_state"].path)
    artifact = json.loads(linked_entry.artifact_raw)
    forged_continuity = dict(genesis_entry.artifact["verified_lineage"]["continuity"])
    forged_continuity["baseline_execution_day"] = artifact["official_day"]
    forged_continuity["predecessor_exact_contract_map_sha256"] = artifact[
        "verified_lineage"
    ]["continuity"]["predecessor_exact_contract_map_sha256"]
    artifact["verified_lineage"]["continuity"] = forged_continuity
    forged = _replace_catalog_artifact(root, linked_entry, artifact)
    verified_roll.validate_structural_daily_pit_main_roll_source(forged.artifact_raw)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="non-first artifact is not linked continuity",
    ):
        catalog._load_catalog(root)


def test_linked_same_day_retry_returns_existing_before_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, _genesis_entry, linked_entry = _linked_setup(
        monkeypatch, tmp_path
    )
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("linked same-day retry rebuilt the artifact"),
    )

    assert catalog.publish_predecessor_artifact(**kwargs) == linked_entry


def test_catalog_rejects_linked_continuity_spliced_from_another_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, _genesis_entry, linked_entry = _linked_setup(
        monkeypatch, tmp_path
    )
    root = catalog.catalog_root(kwargs["operator_state"].path)
    artifact = json.loads(linked_entry.artifact_raw)
    artifact["verified_lineage"]["continuity"]["catalog_receipt_id"] = (
        "daily-roll-catalog-receipt-" + "f" * 64
    )
    forged = _replace_catalog_artifact(root, linked_entry, artifact)
    verified_roll.validate_structural_daily_pit_main_roll_source(forged.artifact_raw)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="linked artifact/predecessor binding mismatch",
    ):
        catalog._load_catalog(root)


def test_publisher_rejects_appending_genesis_before_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    kwargs["official_day"] = "2026-07-02"
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("non-empty Genesis reached the builder"),
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="cannot append Genesis to a non-empty catalog",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_linked_load_rejects_current_manifest_cross_splice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    state = _state("2026-07-02", "9" * 64, "a" * 64, sequence=2)
    state = replace(state, path=kwargs["operator_state"].path)
    holder["state"] = state
    current = _verified_input(
        "2026-07-02",
        head_seal="9" * 64,
        head_commit="a" * 64,
        parent_seal="f" * 64,
        parent_commit="e" * 64,
        expected_genesis_baseline=None,
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="predecessor/current-root continuity mismatch",
    ):
        catalog._load_linked_predecessor_locked(
            operator_state=state,
            current_official_day=verified_roll._day("2026-07-02", "test day"),
            current_execution_day=verified_roll._day("2026-07-03", "test day"),
            current_manifest=current.manifest,
            runtime_input_raw_sha256=kwargs["context"].runtime_input.raw_sha256,
            calendar_raw_sha256=kwargs["context"].calendar.raw_sha256,
            calendar_availability_anchor_raw_sha256=kwargs[
                "context"
            ].availability.raw_sha256,
            isolation_policy_raw_sha256=kwargs["context"].policy.raw_sha256,
            warehouse_registry_raw_sha256=kwargs["context"].registry.raw_sha256,
            contract_registry_raw_sha256=kwargs[
                "expected_contract_registry_raw_sha256"
            ],
        )


@pytest.mark.parametrize(
    ("uid", "mode", "nlink"),
    [
        (501, stat.S_IFREG | 0o444, 1),
        (0, stat.S_IFREG | 0o644, 1),
        (0, stat.S_IFREG | 0o444, 2),
        (0, stat.S_IFLNK | 0o444, 1),
    ],
)
def test_root_catalog_file_descriptor_contract_is_strict(
    monkeypatch: pytest.MonkeyPatch,
    uid: int,
    mode: int,
    nlink: int,
) -> None:
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _descriptor: SimpleNamespace(
            st_uid=uid,
            st_mode=mode,
            st_nlink=nlink,
        ),
    )
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="not immutable root custody",
    ):
        catalog._validate_root_file_fd(7)


@pytest.mark.parametrize(
    "relative",
    ["/artifacts/x.json", "../x.json", "artifacts/../x.json", "other/x.json"],
)
def test_catalog_artifact_path_rejects_escape(tmp_path: Path, relative: str) -> None:
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="artifact path is unsafe",
    ):
        catalog._artifact_path(tmp_path, relative)
