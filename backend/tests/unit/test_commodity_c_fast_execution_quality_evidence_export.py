from __future__ import annotations

import ast
from datetime import timedelta
import importlib.util
import os
from pathlib import Path
import sys
import threading

import pytest

import app.services.commodity_c_fast_execution_quality_evidence_export as export_module
from app.services.commodity_c_fast_execution_quality_evidence_export import (
    CFastExecutionQualityEvidenceExportError,
    CreateOnlyExecutionQualityEvidenceExportStore,
    build_execution_quality_evidence_export,
    canonical_evidence_export_json_line,
    execution_quality_evidence_export_json_bytes,
    reload_and_verify_execution_quality_evidence_export,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    CFastExecutionQualitySidecarError,
    CreateOnlyExecutionQualityJournal,
    OfflineExecutionQualitySidecar,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


ROOT = Path(__file__).resolve().parents[3]
SIDECAR_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py"
)


def _load_test_helpers(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SIDECAR = _load_test_helpers("evidence_export_sidecar_helpers", SIDECAR_TEST_PATH)
FALSE_AUTHORITY = {
    "collection_authorized",
    "runtime_activation_authorized",
    "authority_granted",
    "dispatch_allowed",
    "order_authorized",
    "position_mutation_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "replacement_allowed",
    "production_allowed",
}


def _registered(tmp_path: Path) -> OfflineExecutionQualitySidecar:
    tmp_path.mkdir(parents=True, exist_ok=True)
    subject = SIDECAR.sidecar(tmp_path)
    SIDECAR.register(subject)
    return subject


def _export_root(tmp_path: Path) -> Path:
    root = tmp_path / "evidence-exports"
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return root


def _complete_window(subject: OfflineExecutionQualitySidecar) -> None:
    intent_id = next(iter(subject.recover().intents))
    for row in [
        *SIDECAR.SCORER.full_horizon_books(),
        SIDECAR.SCORER.book(62_000, cumulative_volume="120"),
    ]:
        subject.append_preverified_snapshot(row)
    assert len(subject.seal_ready_evidence(intent_id)) == 6


def test_pending_projection_is_deterministic_across_restart_and_not_m2(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path)

    first = build_execution_quality_evidence_export(subject)
    restarted = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(subject.journal.root)
    )
    second = build_execution_quality_evidence_export(restarted)

    assert second == first
    assert first.source_journal_record_count == 2
    assert first.snapshot_record_count == 0
    assert first.evidence_record_count == 0
    assert first.pending_target_count == 6
    assert first.journal_window_state == ("PENDING_TARGETS_PRESENT_LOCAL_JOURNAL_ONLY")
    assert first.m2_acceptance_state == (
        "NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW"
    )
    assert first.real_execution_window_verified is False
    assert first.zero_order_t2_evidence_accepted is False
    assert first.execution_quality_implemented is False
    assert first.runtime_active is False
    assert first.orders_sent == 0
    assert first.positions_modified == 0
    assert all(getattr(first, field) is False for field in FALSE_AUTHORITY)


def test_complete_local_window_exports_all_scores_without_point_probability(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path)
    _complete_window(subject)

    exported = build_execution_quality_evidence_export(subject)

    assert exported.evidence_record_count == 6
    assert exported.pending_target_count == 0
    assert exported.journal_window_state == ("ALL_TARGETS_SEALED_LOCAL_JOURNAL_ONLY")
    assert tuple(row.target_key for row in exported.evidence) == (
        "decision",
        "250",
        "1000",
        "5000",
        "30000",
        "60000",
    )
    for evidence in exported.evidence:
        assert all(
            horizon.passive_fill_bounds.point_probability_output == "FORBIDDEN"
            and horizon.passive_fill_bounds.calibrated_point_probability_allowed
            is False
            for horizon in evidence.score.horizons
        )
    assert exported.real_tick_source_attestation_state == (
        "NOT_INCLUDED_LOCAL_JOURNAL_CANNOT_PROVE_SOURCE"
    )
    assert exported.zero_order_t2_evidence_accepted is False


def test_missing_not_imputed_window_exports_sealed_missing_not_pending(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path)
    intent_id = next(iter(subject.recover().intents))
    subject.append_preverified_snapshot(SIDECAR.SCORER.book(0))
    subject.append_preverified_snapshot(SIDECAR.SCORER.book(62_000))
    assert len(subject.seal_ready_evidence(intent_id)) == 6

    exported = build_execution_quality_evidence_export(subject)
    intent = exported.intents[0]
    evidence_by_target = {row.target_key: row for row in exported.evidence}

    assert exported.pending_target_count == 0
    assert exported.evidence_record_count == 6
    assert intent.targets[0].completion_state == "SEALED_SELECTED_EVIDENCE"
    assert all(
        target.completion_state == "SEALED_MISSING_NOT_IMPUTED"
        for target in intent.targets[1:]
    )
    for target in intent.targets:
        evidence = evidence_by_target[target.target_key]
        assert evidence.evidence_record_hash == target.evidence_record_hash
        assert evidence.score.score_hash == target.score_hash
        assert evidence.completion_state == target.completion_state
    for evidence in exported.evidence[1:]:
        horizon = next(
            row
            for row in evidence.score.horizons
            if row.horizon_ms == evidence.horizon_ms
        )
        assert horizon.selection_state == "MISSING_HORIZON_NOT_IMPUTED"
        assert horizon.passive_fill_bounds.state == ("UNIDENTIFIED_MISSING_HORIZON")
        assert horizon.passive_fill_bounds.point_probability_output == "FORBIDDEN"
    assert exported.m2_acceptance_state == (
        "NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW"
    )


def test_journal_growth_changes_tip_and_export_but_not_generation(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path / "source")
    store = CreateOnlyExecutionQualityEvidenceExportStore(_export_root(tmp_path))
    before = build_execution_quality_evidence_export(subject)
    first_receipt = store.publish(subject)

    subject.append_preverified_snapshot(SIDECAR.SCORER.book(0))
    after = build_execution_quality_evidence_export(subject)
    historical = store.load(
        str(first_receipt["artifact_filename"]),
        source=subject,
    )
    second_receipt = store.publish(subject)

    assert historical == before
    assert after.generation_id == before.generation_id
    assert after.generation_basis_sha256 == before.generation_basis_sha256
    assert after.source_journal_record_count == before.source_journal_record_count + 1
    assert after.source_journal_tip_record_hash != (
        before.source_journal_tip_record_hash
    )
    assert after.export_sha256 != before.export_sha256
    assert second_receipt["artifact_state"] == "CREATED"
    assert len(list(store.root.glob("*.json"))) == 2


def test_create_only_publish_is_restart_idempotent_and_source_verified(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path / "source")
    root = _export_root(tmp_path)
    first_store = CreateOnlyExecutionQualityEvidenceExportStore(root)

    created = first_store.publish(subject)
    reopened_store = CreateOnlyExecutionQualityEvidenceExportStore(root)
    repeated = reopened_store.publish(subject)
    loaded = reopened_store.load(
        str(created["artifact_filename"]),
        source=subject,
    )

    assert created["artifact_state"] == "CREATED"
    assert repeated["artifact_state"] == "ALREADY_PRESENT"
    assert repeated["export_sha256"] == created["export_sha256"]
    assert loaded.export_sha256 == created["export_sha256"]
    files = list(root.glob("*.json"))
    assert len(files) == 1
    assert files[0].stat().st_mode & 0o777 == 0o600
    assert all(created[field] is False for field in FALSE_AUTHORITY)
    assert created["orders_sent"] == 0
    assert created["positions_modified"] == 0


def test_short_temp_write_never_exposes_partial_final_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _registered(tmp_path / "source")
    root = _export_root(tmp_path)
    store = CreateOnlyExecutionQualityEvidenceExportStore(root)
    real_write = export_module.os.write
    calls = 0

    def write_one_byte_then_fail(descriptor: int, value: object) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, memoryview(value)[:1])
        raise OSError("injected short write")

    with monkeypatch.context() as patch:
        patch.setattr(export_module.os, "write", write_one_byte_then_fail)
        with pytest.raises(
            CFastExecutionQualityEvidenceExportError,
            match="EVIDENCE_EXPORT_CREATE_ONLY_WRITE_FAILED",
        ):
            store.publish(subject)

    assert not list(root.glob("*.json"))
    assert not list(root.glob(".*.tmp-*"))
    assert store.publish(subject)["artifact_state"] == "CREATED"


def test_restart_recovers_interrupted_temp_before_and_after_atomic_link(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path / "source")
    root = _export_root(tmp_path)
    CreateOnlyExecutionQualityEvidenceExportStore(root)
    exported = build_execution_quality_evidence_export(subject)
    raw = canonical_evidence_export_json_line(exported.model_dump(mode="json"))
    filename = (
        "cfast-execution-quality-evidence-export-v1-"
        f"{exported.generation_basis_sha256}-"
        f"{exported.source_journal_tip_record_hash}.json"
    )
    temporary = root / f".{filename}.tmp-{'a' * 32}"

    temporary.write_bytes(raw[:17])
    temporary.chmod(0o600)
    reopened = CreateOnlyExecutionQualityEvidenceExportStore(root)
    assert not temporary.exists()
    assert not (root / filename).exists()

    temporary.write_bytes(raw)
    temporary.chmod(0o600)
    os.link(temporary, root / filename)
    assert temporary.stat().st_nlink == 2
    restarted_after_link = CreateOnlyExecutionQualityEvidenceExportStore(root)

    assert not temporary.exists()
    assert (root / filename).stat().st_nlink == 1
    assert restarted_after_link.load(filename, source=subject) == exported
    assert reopened.root == restarted_after_link.root


def test_constructor_waits_for_publish_flock_before_validating_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _registered(tmp_path / "source")
    root = _export_root(tmp_path)
    store = CreateOnlyExecutionQualityEvidenceExportStore(root)
    original_write = store._write_create_only
    original_flock = export_module.fcntl.flock
    write_complete = threading.Event()
    release_publisher = threading.Event()
    constructor_lock_attempted = threading.Event()
    constructor_complete = threading.Event()
    errors: list[BaseException] = []

    def write_then_hold(root_fd: int, filename: str, raw: bytes) -> str:
        state = original_write(root_fd, filename, raw)
        write_complete.set()
        if not release_publisher.wait(timeout=5):
            raise RuntimeError("test publisher release timed out")
        return state

    def observed_flock(descriptor: int, operation: int) -> None:
        if threading.current_thread().name == "evidence-store-reopen":
            constructor_lock_attempted.set()
        original_flock(descriptor, operation)

    def publish() -> None:
        try:
            store.publish(subject)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def reopen() -> None:
        try:
            CreateOnlyExecutionQualityEvidenceExportStore(root)
            constructor_complete.set()
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    monkeypatch.setattr(store, "_write_create_only", write_then_hold)
    monkeypatch.setattr(export_module.fcntl, "flock", observed_flock)
    publisher = threading.Thread(target=publish, name="evidence-publisher")
    publisher.start()
    assert write_complete.wait(timeout=5)

    constructor = threading.Thread(target=reopen, name="evidence-store-reopen")
    constructor.start()
    assert constructor_lock_attempted.wait(timeout=5)
    assert not constructor_complete.wait(timeout=0.1)

    release_publisher.set()
    publisher.join(timeout=5)
    constructor.join(timeout=5)
    assert not publisher.is_alive()
    assert not constructor.is_alive()
    assert constructor_complete.is_set()
    assert errors == []


def test_concurrent_publishers_have_one_create_only_winner(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path / "source")
    root = _export_root(tmp_path)
    stores = (
        CreateOnlyExecutionQualityEvidenceExportStore(root),
        CreateOnlyExecutionQualityEvidenceExportStore(root),
    )
    start = threading.Barrier(2)
    receipts: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def publish(store: CreateOnlyExecutionQualityEvidenceExportStore) -> None:
        try:
            start.wait(timeout=5)
            receipts.append(store.publish(subject))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    workers = [threading.Thread(target=publish, args=(store,)) for store in stores]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)

    assert not any(worker.is_alive() for worker in workers)
    assert errors == []
    assert sorted(str(row["artifact_state"]) for row in receipts) == [
        "ALREADY_PRESENT",
        "CREATED",
    ]
    assert len({str(row["artifact_filename"]) for row in receipts}) == 1
    assert len(list(root.glob("*.json"))) == 1
    assert not list(root.glob(".*.tmp-*"))


def test_canonical_reload_rejects_coordinated_export_splice_against_source(
    tmp_path: Path,
) -> None:
    subject = _registered(tmp_path)
    payload = build_execution_quality_evidence_export(subject).model_dump(mode="json")
    payload["ordered_journal_record_hashes_sha256"] = "f" * 64
    core = {key: value for key, value in payload.items() if key != "export_sha256"}
    payload["export_sha256"] = sha256_json(core)
    forged = canonical_evidence_export_json_line(payload)

    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_FRESH_SOURCE_MISMATCH",
    ):
        reload_and_verify_execution_quality_evidence_export(
            forged,
            source=subject,
        )
    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_NOT_CANONICAL",
    ):
        reload_and_verify_execution_quality_evidence_export(
            execution_quality_evidence_export_json_bytes(subject) + b"\n",
            source=subject,
        )


@pytest.mark.parametrize(
    "field",
    [
        "zero_order_t2_evidence_accepted",
        "real_execution_window_verified",
        "execution_quality_implemented",
        "runtime_active",
        "order_authorized",
        "position_mutation_authorized",
    ],
)
def test_export_cannot_be_rehashed_into_m2_or_authority_claim(
    tmp_path: Path,
    field: str,
) -> None:
    subject = _registered(tmp_path)
    payload = build_execution_quality_evidence_export(subject).model_dump(mode="json")
    payload[field] = True
    core = {key: value for key, value in payload.items() if key != "export_sha256"}
    payload["export_sha256"] = sha256_json(core)

    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_DTO_INVALID",
    ):
        reload_and_verify_execution_quality_evidence_export(
            canonical_evidence_export_json_line(payload),
            source=subject,
        )


def test_publish_remains_exact_prefix_if_source_advances_during_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _registered(tmp_path / "source")
    store = CreateOnlyExecutionQualityEvidenceExportStore(_export_root(tmp_path))
    expected = build_execution_quality_evidence_export(subject)
    original_write = store._write_create_only

    def write_then_advance(root_fd: int, filename: str, raw: bytes) -> str:
        state = original_write(root_fd, filename, raw)
        subject.append_preverified_snapshot(SIDECAR.SCORER.book(0))
        return state

    monkeypatch.setattr(store, "_write_create_only", write_then_advance)

    receipt = store.publish(subject)
    loaded = store.load(str(receipt["artifact_filename"]), source=subject)

    assert receipt["artifact_state"] == "CREATED"
    assert loaded == expected
    assert len(list(store.root.glob("*.json"))) == 1
    assert (
        build_execution_quality_evidence_export(subject).source_journal_record_count
        == 3
    )


def test_incomplete_durable_plan_is_not_exportable(tmp_path: Path) -> None:
    observations = iter(
        (
            SIDECAR.ANCHOR,
            SIDECAR.ANCHOR - timedelta(seconds=1),
        )
    )
    repository = SIDECAR.journal(tmp_path)
    subject = OfflineExecutionQualitySidecar(
        repository,
        clock=lambda: next(observations),
    )
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="DURABLE_INTENT_CLOCK_REGRESSION",
    ):
        SIDECAR.register(subject)

    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_DURABLE_PLAN_INCOMPLETE",
    ):
        build_execution_quality_evidence_export(subject)


def test_historical_prefix_requires_exact_count_and_tip(tmp_path: Path) -> None:
    subject = _registered(tmp_path)
    initial = subject.recover()
    subject.append_preverified_snapshot(SIDECAR.SCORER.book(0))

    prefix = subject.recover_at_tip(
        record_count=len(initial.records),
        tip_record_hash=initial.records[-1].record_hash,
    )

    assert prefix.records == initial.records
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_PREFIX_TIP_MISMATCH",
    ):
        subject.recover_at_tip(
            record_count=len(initial.records),
            tip_record_hash="f" * 64,
        )
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_PREFIX_NOT_FOUND",
    ):
        subject.recover_at_tip(
            record_count=99,
            tip_record_hash="f" * 64,
        )
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_PREFIX_IDENTITY_INVALID",
    ):
        subject.recover_at_tip(
            record_count=True,
            tip_record_hash=None,  # type: ignore[arg-type]
        )


def test_store_rejects_insecure_or_unknown_custody(tmp_path: Path) -> None:
    insecure = tmp_path / "insecure"
    insecure.mkdir(mode=0o755)
    insecure.chmod(0o755)
    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_ROOT_INVALID",
    ):
        CreateOnlyExecutionQualityEvidenceExportStore(insecure)

    unknown = _export_root(tmp_path)
    artifact = unknown / "unexpected"
    artifact.write_text("x")
    artifact.chmod(0o600)
    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_UNKNOWN_ARTIFACT",
    ):
        CreateOnlyExecutionQualityEvidenceExportStore(unknown)
    lock = unknown / ".export.lock"
    assert lock.is_file()
    assert lock.stat().st_mode & 0o777 == 0o600
    assert lock.stat().st_size == 0


def test_store_rejects_lock_downgrade_and_source_root_overlap(
    tmp_path: Path,
) -> None:
    downgraded = _export_root(tmp_path / "downgraded")
    lock = downgraded / ".export.lock"
    lock.write_bytes(b"")
    lock.chmod(0o644)
    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_LOCK_INVALID",
    ):
        CreateOnlyExecutionQualityEvidenceExportStore(downgraded)

    root = _export_root(tmp_path / "overlap")
    store = CreateOnlyExecutionQualityEvidenceExportStore(root)
    subject = _registered(root / "nested-source")
    with pytest.raises(
        CFastExecutionQualityEvidenceExportError,
        match="EVIDENCE_EXPORT_SOURCE_ROOT_OVERLAP",
    ):
        store.publish(subject)


def test_export_modules_have_no_runtime_database_or_execution_capability() -> None:
    paths = (
        ROOT
        / "backend/app/schemas/commodity_c_fast_execution_quality_evidence_export.py",
        ROOT
        / "backend/app/services/commodity_c_fast_execution_quality_evidence_export.py",
    )
    forbidden_imports = {
        "app.core.config",
        "app.main",
        "app.services.commodity_simnow",
        "app.services.market_data_service",
        "app.services.trade_service",
        "app.services.vnpy_rpc_service",
        "psycopg",
        "questdb",
        "vnpy",
    }
    forbidden_names = {
        "TradeService",
        "account",
        "cancel_order",
        "gateway",
        "position",
        "rpc_service",
        "send_order",
        "subscribe_market",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imports.add(module)
                imports.update(f"{module}.{alias.name}" for alias in node.names)
        assert imports.isdisjoint(forbidden_imports)
        assert not any(
            (isinstance(node, ast.Name) and node.id in forbidden_names)
            or (isinstance(node, ast.Attribute) and node.attr in forbidden_names)
            for node in ast.walk(tree)
        )


def test_export_source_declares_non_m2_and_zero_authority_literals() -> None:
    source = export_module.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8")
    assert "NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW" in text
    assert '"execution_quality_implemented": False' in text
    assert '"runtime_active": False' in text
    assert '"orders_sent": 0' in text
    assert '"positions_modified": 0' in text
