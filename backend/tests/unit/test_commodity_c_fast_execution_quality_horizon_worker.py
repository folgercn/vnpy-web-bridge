from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest

from app.schemas.commodity_c_fast_execution_quality import CFastVirtualIntentDTO
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastL1L5BookSnapshotDTO,
)
from app.services.commodity_c_fast_execution_quality_horizon_worker import (
    CFastExecutionQualityHorizonWorkerError,
    PreverifiedTickHorizonWorker,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    CFastExecutionQualitySidecarError,
    CreateOnlyExecutionQualityJournal,
    OfflineExecutionQualitySidecar,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


ROOT = Path(__file__).resolve().parents[3]
SIDECAR_TEST_PATH = (
    ROOT
    / "backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py"
)
SCORER_TEST_PATH = (
    ROOT
    / "backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py"
)


def _load_test_helpers(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SIDECAR = _load_test_helpers("horizon_worker_sidecar_helpers", SIDECAR_TEST_PATH)
SCORER = _load_test_helpers("horizon_worker_scorer_helpers", SCORER_TEST_PATH)
ANCHOR = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)


def sidecar(tmp_path: Path) -> OfflineExecutionQualitySidecar:
    root = tmp_path / "quality-worker-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(root),
        clock=lambda: ANCHOR,
    )


def worker(tmp_path: Path) -> PreverifiedTickHorizonWorker:
    return PreverifiedTickHorizonWorker(sidecar(tmp_path))


def registration_inputs() -> dict:
    accepted = SIDECAR.plan()
    policy = SCORER.policy()
    return {
        "preverified_plan": accepted,
        "source_snapshot_receipt_sha256": accepted.snapshot_hash,
        "score_policy": policy,
        "score_policy_hash": sha256_json(policy.model_dump(mode="json")),
        "contract_specs": (SCORER.contract_spec(),),
    }


def two_intent_registration_inputs() -> dict:
    inputs = registration_inputs()
    plan = inputs["preverified_plan"]
    first = plan.intents[0]
    second_core = {
        **first.model_dump(
            mode="json",
            exclude={"intent_id", "leg_id"},
        ),
        "leg_sequence": 2,
        "intent_sequence": 2,
    }
    leg_core = {
        key: second_core[key]
        for key in (
            "schema_version",
            "snapshot_id",
            "snapshot_hash",
            "formula_target_binding_sha256",
            "policy_hash",
            "product",
            "phase",
            "position_effect",
            "exact_contract",
            "signed_quantity_delta",
            "leg_sequence",
        )
    }
    leg_core["schema_version"] = "commodity_c_fast_virtual_leg_v1"
    second_with_leg = {
        **second_core,
        "leg_id": f"cfast-virtual-leg-v1-{sha256_json(leg_core)}",
    }
    second = CFastVirtualIntentDTO.model_validate(
        {
            **second_with_leg,
            "intent_id": (
                "cfast-virtual-intent-v1-"
                f"{sha256_json(second_with_leg)}"
            ),
        }
    )
    plan_core = {
        **plan.model_dump(mode="json", exclude={"plan_hash"}),
        "intents": [
            first.model_dump(mode="json"),
            second.model_dump(mode="json"),
        ],
    }
    inputs["preverified_plan"] = type(plan).model_validate(
        {**plan_core, "plan_hash": sha256_json(plan_core)}
    )
    return inputs


def register(subject: PreverifiedTickHorizonWorker) -> str:
    receipt = subject.register_preverified_plan(**registration_inputs())
    assert receipt["runtime_active"] is False
    assert receipt["execution_quality_implemented"] is False
    assert receipt["dispatch_allowed"] is False
    assert receipt["order_authorized"] is False
    return receipt["registered_intent_ids"][0]


def test_preverified_ticks_drive_all_horizons_once(tmp_path: Path) -> None:
    subject = worker(tmp_path)
    intent_id = register(subject)

    created = 0
    for row in [
        *SCORER.full_horizon_books(),
        SCORER.book(62_000, cumulative_volume="120"),
    ]:
        created += subject.accept_preverified_tick(row)[
            "created_evidence_count"
        ]

    assert created == 6
    assert subject._sidecar.status(intent_id)["completion"] == {
        "decision": "SEALED_SELECTED_EVIDENCE",
        "250": "SEALED_SELECTED_EVIDENCE",
        "1000": "SEALED_SELECTED_EVIDENCE",
        "5000": "SEALED_SELECTED_EVIDENCE",
        "30000": "SEALED_SELECTED_EVIDENCE",
        "60000": "SEALED_SELECTED_EVIDENCE",
    }
    status = subject.status()
    assert status["evidence_record_count"] == 6
    assert status["completion_counts"] == {
        "SEALED_SELECTED_EVIDENCE": 6,
        "SEALED_MISSING_NOT_IMPUTED": 0,
        "PENDING_NOT_SEALED": 0,
    }
    assert status["runtime_active"] is False
    assert status["execution_quality_implemented"] is False
    assert status["orders_sent"] == 0
    assert status["positions_modified"] == 0


def test_restart_recovery_seals_ready_watermark_without_duplicates(
    tmp_path: Path,
) -> None:
    first = worker(tmp_path)
    register(first)
    for row in [
        *SCORER.full_horizon_books(),
        SCORER.book(62_000, cumulative_volume="120"),
    ]:
        first._sidecar.append_preverified_snapshot(row)
    assert len(first._sidecar.recover().evidence) == 0

    restarted_sidecar = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(first._sidecar.journal.root)
    )
    restarted = PreverifiedTickHorizonWorker(restarted_sidecar)
    first_recovery = restarted.recover()
    assert first_recovery["created_evidence_count"] == 6
    before = len(restarted_sidecar.recover().records)
    second_recovery = restarted.recover()
    assert second_recovery["created_evidence_count"] == 0
    assert len(restarted_sidecar.recover().records) == before


def test_duplicate_tick_is_idempotent(tmp_path: Path) -> None:
    subject = worker(tmp_path)
    register(subject)
    row = SCORER.book(0)

    first = subject.accept_preverified_tick(row)
    second = subject.accept_preverified_tick(row)

    assert first["snapshot_created"] is True
    assert second["snapshot_created"] is False
    assert second["snapshot_record_hash"] == first["snapshot_record_hash"]
    assert len(subject._sidecar.recover().snapshots) == 1


def test_partial_multi_intent_registration_retries_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = worker(tmp_path)
    inputs = two_intent_registration_inputs()
    original = subject._sidecar.register_preverified_intent
    calls = 0

    def fail_second_registration(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CFastExecutionQualitySidecarError(
                "FORCED_SECOND_INTENT_REGISTRATION_FAILURE"
            )
        return original(**kwargs)

    monkeypatch.setattr(
        subject._sidecar,
        "register_preverified_intent",
        fail_second_registration,
    )
    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="FORCED_SECOND_INTENT_REGISTRATION_FAILURE",
    ):
        subject.register_preverified_plan(**inputs)
    partial = subject._sidecar.recover()
    assert len(partial.intents) == 1
    assert len(partial.anchors) == 1

    restarted_sidecar = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(subject._sidecar.journal.root),
        clock=lambda: ANCHOR,
    )
    restarted = PreverifiedTickHorizonWorker(restarted_sidecar)
    receipt = restarted.register_preverified_plan(**inputs)

    assert len(receipt["registered_intent_ids"]) == 2
    recovered = restarted_sidecar.recover()
    assert len(recovered.intents) == 2
    assert len(recovered.anchors) == 2
    assert len(recovered.records) == 4


def test_orphan_intent_anchor_is_repaired_by_same_full_plan(
    tmp_path: Path,
) -> None:
    observations = iter((ANCHOR, ANCHOR - timedelta(seconds=1)))
    repository = sidecar(tmp_path)
    repository.clock = lambda: next(observations)
    subject = PreverifiedTickHorizonWorker(repository)
    inputs = registration_inputs()

    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="DURABLE_INTENT_CLOCK_REGRESSION",
    ):
        subject.register_preverified_plan(**inputs)
    orphaned = repository.recover()
    assert len(orphaned.intents) == 1
    assert orphaned.anchors == {}
    assert subject.status()["blocked_fail_closed"] is True
    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="WORKER_BLOCKED_REQUIRES_EXPLICIT_RECOVERY",
    ):
        subject.accept_preverified_tick(SCORER.book(0))

    repository.clock = lambda: ANCHOR + timedelta(seconds=1)
    receipt = subject.register_preverified_plan(**inputs)

    assert len(receipt["registered_intent_ids"]) == 1
    assert subject.status()["blocked_fail_closed"] is False
    repaired = repository.recover()
    assert len(repaired.intents) == 1
    assert len(repaired.anchors) == 1
    assert len(repaired.records) == 2


def test_restarted_worker_rejects_tick_when_any_intent_is_orphaned(
    tmp_path: Path,
) -> None:
    observations = iter(
        (
            ANCHOR,
            ANCHOR,
            ANCHOR,
            ANCHOR - timedelta(seconds=1),
        )
    )
    repository = sidecar(tmp_path)
    repository.clock = lambda: next(observations)
    first = PreverifiedTickHorizonWorker(repository)
    inputs = two_intent_registration_inputs()
    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="DURABLE_INTENT_CLOCK_REGRESSION",
    ):
        first.register_preverified_plan(**inputs)
    partial = repository.recover()
    assert len(partial.intents) == 2
    assert len(partial.anchors) == 1

    restarted_sidecar = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(repository.journal.root),
        clock=lambda: ANCHOR + timedelta(seconds=1),
    )
    restarted = PreverifiedTickHorizonWorker(restarted_sidecar)
    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="DURABLE_INTENT_ANCHOR_MISSING",
    ):
        restarted.accept_preverified_tick(SCORER.book(0))

    recovered = restarted_sidecar.recover()
    assert recovered.snapshots == ()
    assert recovered.evidence == {}
    status = restarted.status()
    assert status["blocked_fail_closed"] is True
    assert status["registered_intent_count"] == 1


def test_status_reports_journal_failure_as_fail_closed(
    tmp_path: Path,
) -> None:
    subject = worker(tmp_path)
    register(subject)
    unexpected = subject._sidecar.journal.root / "unexpected"
    unexpected.write_text("tampered")
    unexpected.chmod(0o600)

    status = subject.status()

    assert status["worker_state"] == "BLOCKED_FAIL_CLOSED"
    assert status["blocked_fail_closed"] is True
    assert status["last_error"] == "JOURNAL_SEQUENCE_INVALID"
    assert status["registered_intent_count"] is None
    assert status["snapshot_record_count"] is None
    assert status["runtime_active"] is False
    assert status["execution_quality_implemented"] is False
    assert status["dispatch_allowed"] is False


def test_missing_horizons_are_sealed_missing_not_imputed(
    tmp_path: Path,
) -> None:
    subject = worker(tmp_path)
    intent_id = register(subject)
    subject.accept_preverified_tick(SCORER.book(0))
    subject.accept_preverified_tick(SCORER.book(62_000))

    completion = subject._sidecar.status(intent_id)["completion"]
    assert completion["decision"] == "SEALED_SELECTED_EVIDENCE"
    assert set(completion.values()) == {
        "SEALED_SELECTED_EVIDENCE",
        "SEALED_MISSING_NOT_IMPUTED",
    }


def test_tick_outside_durable_exact_contracts_is_not_persisted(
    tmp_path: Path,
) -> None:
    subject = worker(tmp_path)
    register(subject)
    original = SCORER.book(0)
    core = {
        **original.model_dump(mode="json", exclude={"book_snapshot_hash"}),
        "exact_contract": "SHFE.au2612",
    }
    other = CFastL1L5BookSnapshotDTO.model_validate(
        {**core, "book_snapshot_hash": sha256_json(core)}
    )

    receipt = subject.accept_preverified_tick(other)

    assert receipt["tick_state"] == (
        "IGNORED_OUTSIDE_DURABLY_ACCEPTED_EXACT_CONTRACTS"
    )
    assert receipt["snapshot_created"] is False
    assert subject._sidecar.recover().snapshots == ()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            {"source_snapshot_receipt_sha256": "f" * 64},
            "PREVERIFIED_SNAPSHOT_RECEIPT_MISMATCH",
        ),
        (
            {"contract_specs": ()},
            "PREVERIFIED_CONTRACT_SPEC_SET_MISMATCH",
        ),
    ],
)
def test_registration_binding_failures_block_before_journal_mutation(
    tmp_path: Path,
    change: dict,
    message: str,
) -> None:
    subject = worker(tmp_path)
    inputs = {**registration_inputs(), **change}

    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match=message,
    ):
        subject.register_preverified_plan(**inputs)

    status = subject.status()
    assert status["blocked_fail_closed"] is True
    assert status["registered_intent_count"] == 0
    assert subject._sidecar.recover().records == ()


def test_raw_or_mutated_typed_tick_fails_closed(tmp_path: Path) -> None:
    subject = worker(tmp_path)
    register(subject)
    row = SCORER.book(0)

    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="PREVERIFIED_TICK_TYPE_INVALID",
    ):
        subject.accept_preverified_tick(row.model_dump(mode="json"))  # type: ignore[arg-type]
    assert subject.status()["blocked_fail_closed"] is True

    subject.recover()
    object.__setattr__(row, "ingest_id", "mutated-after-validation")
    with pytest.raises(
        CFastExecutionQualityHorizonWorkerError,
        match="PREVERIFIED_TICK_TYPE_INVALID",
    ):
        subject.accept_preverified_tick(row)


def test_source_has_no_runtime_or_execution_dependencies() -> None:
    source = (
        ROOT
        / "backend/app/services/commodity_c_fast_execution_quality_"
        "horizon_worker.py"
    ).read_text()
    forbidden = (
        "app.core.config",
        "app.main",
        "market_data_service",
        "tick_persistence",
        "VnpyRpcService",
        "TradeService",
        "Gateway",
        "send_order",
        "cancel_order",
        "get_accounts",
        "get_positions",
    )
    assert all(token not in source for token in forbidden)
    assert "runtime_active\": False" in source
    assert "execution_quality_implemented\": False" in source
