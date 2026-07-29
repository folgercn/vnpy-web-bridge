from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from threading import Event

import pytest

import app.services.commodity_c_fast_execution_quality_sidecar as sidecar_module
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPlanDTO,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    CFastExecutionQualitySidecarError,
    CreateOnlyExecutionQualityJournal,
    OfflineExecutionQualitySidecar,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


ROOT = Path(__file__).resolve().parents[3]
SCORER_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py"
)
POLICY_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py"
)


def _load_test_helpers(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCORER = _load_test_helpers("sidecar_scorer_helpers", SCORER_TEST_PATH)
POLICY = _load_test_helpers("sidecar_policy_helpers", POLICY_TEST_PATH)
ANCHOR = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)


def plan() -> CFastVirtualIntentPlanDTO:
    virtual_intent = SCORER.intent(lots=3)
    foundation_policy = POLICY._foundation_policy()
    foundation_hash = sha256_json(
        foundation_policy.model_dump(mode="json")
    )
    assert foundation_hash == virtual_intent.policy_hash
    core = {
        "schema_version": "commodity_c_fast_virtual_intent_plan_v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_id": virtual_intent.snapshot_id,
        "snapshot_hash": virtual_intent.snapshot_hash,
        "formula_target_binding_sha256": (
            virtual_intent.formula_target_binding_sha256
        ),
        "source_month": "2026-08",
        "execution_day": "2026-09-01",
        "policy": foundation_policy.model_dump(mode="json"),
        "policy_hash": foundation_hash,
        "intents": [virtual_intent.model_dump(mode="json")],
        "activation_state": "FOUNDATION_ONLY_NOT_ACTIVATABLE",
        "source_validation_scope": (
            "IDENTITY_BINDING_ONLY_CALLER_MUST_REQUIRE_ACCEPTED_SIGNED_SHADOW"
        ),
        "p0_pass_required_before_collection": True,
        "collection_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    return CFastVirtualIntentPlanDTO.model_validate(
        {**core, "plan_hash": sha256_json(core)}
    )


def journal(tmp_path: Path) -> CreateOnlyExecutionQualityJournal:
    root = tmp_path / "quality-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return CreateOnlyExecutionQualityJournal(root)


def sidecar(tmp_path: Path) -> OfflineExecutionQualitySidecar:
    return OfflineExecutionQualitySidecar(
        journal(tmp_path),
        clock=lambda: ANCHOR,
    )


def register(service: OfflineExecutionQualitySidecar) -> str:
    accepted = plan()
    policy = SCORER.policy()
    policy_hash = sha256_json(policy.model_dump(mode="json"))
    service.register_preverified_intent(
        preverified_plan=accepted,
        intent_id=accepted.intents[0].intent_id,
        source_snapshot_receipt_sha256=accepted.snapshot_hash,
        score_policy=policy,
        score_policy_hash=policy_hash,
        contract_spec=SCORER.contract_spec(),
    )
    return accepted.intents[0].intent_id


def test_registration_is_create_only_durable_and_restart_idempotent(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    intent_id = register(service)

    state = service.recover()
    assert [row.payload["record_type"] for row in state.records] == [
        "PREVERIFIED_VIRTUAL_INTENT_INPUT",
        "DURABLE_INTENT_ANCHOR",
    ]
    assert all(
        (service.journal.root / path.name).stat().st_mode & 0o777 == 0o600
        for path in service.journal.root.iterdir()
    )

    restarted = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(service.journal.root),
        clock=lambda: ANCHOR,
    )
    assert register(restarted) == intent_id
    assert len(restarted.recover().records) == 2
    status = restarted.status(intent_id)
    assert status["runtime_activation_authorized"] is False
    assert status["collection_authorized"] is False
    assert status["dispatch_allowed"] is False
    assert status["order_authorized"] is False


def test_snapshot_ingest_and_event_identities_dedupe_across_restart(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    row = SCORER.book(0)
    first = service.append_preverified_snapshot(row)
    second = service.append_preverified_snapshot(row)
    assert first.record_hash == second.record_hash

    restarted = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(service.journal.root)
    )
    third = restarted.append_preverified_snapshot(row)
    assert third.record_hash == first.record_hash
    assert len(restarted.recover().snapshots) == 1


def test_conflicting_ingest_id_fails_closed_without_append(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    original = SCORER.book(0, ingest_id="stable-ingest")
    service.append_preverified_snapshot(original)
    conflict = SCORER.book(
        1,
        ingest_seq=2,
        ingest_id="stable-ingest",
        cumulative_volume="999",
    )

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="SNAPSHOT_IDENTITY_REUSE_CONFLICT",
    ):
        service.append_preverified_snapshot(conflict)
    assert len(service.recover().snapshots) == 1


def test_conflicting_event_key_fails_closed(tmp_path: Path) -> None:
    service = sidecar(tmp_path)
    original = SCORER.book(0, ingest_seq=9, ingest_id="event-a")
    service.append_preverified_snapshot(original)
    conflict_payload = original.model_dump(mode="json")
    conflict_payload["ingest_id"] = "event-b"
    conflict_payload["cumulative_volume"] = "999"
    conflict_payload["book_snapshot_hash"] = sha256_json(
        {
            key: value
            for key, value in conflict_payload.items()
            if key != "book_snapshot_hash"
        }
    )
    conflict = type(original).model_validate(conflict_payload)

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="SNAPSHOT_IDENTITY_REUSE_CONFLICT",
    ):
        service.append_preverified_snapshot(conflict)


def test_received_time_regression_is_rejected(tmp_path: Path) -> None:
    service = sidecar(tmp_path)
    service.append_preverified_snapshot(SCORER.book(1_000))
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="SNAPSHOT_RECEIVED_TIME_REGRESSION",
    ):
        service.append_preverified_snapshot(SCORER.book(999))


def test_all_horizons_seal_once_and_replay_fresh_after_restart(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    intent_id = register(service)
    for row in [
        *SCORER.full_horizon_books(),
        SCORER.book(62_000, cumulative_volume="120"),
    ]:
        service.append_preverified_snapshot(row)

    created = service.seal_ready_evidence(intent_id)
    assert len(created) == 6
    status = service.status(intent_id)
    assert status["completion"] == {
        "decision": "SEALED_SELECTED_EVIDENCE",
        "250": "SEALED_SELECTED_EVIDENCE",
        "1000": "SEALED_SELECTED_EVIDENCE",
        "5000": "SEALED_SELECTED_EVIDENCE",
        "30000": "SEALED_SELECTED_EVIDENCE",
        "60000": "SEALED_SELECTED_EVIDENCE",
    }

    restarted = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(service.journal.root)
    )
    before = len(restarted.recover().records)
    assert restarted.seal_ready_evidence(intent_id) == ()
    assert len(restarted.recover().records) == before


def test_missing_horizons_are_sealed_missing_not_imputed(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    intent_id = register(service)
    service.append_preverified_snapshot(SCORER.book(0))
    service.append_preverified_snapshot(SCORER.book(62_000))

    service.seal_ready_evidence(intent_id)
    completion = service.status(intent_id)["completion"]
    assert completion["decision"] == "SEALED_SELECTED_EVIDENCE"
    assert set(completion.values()) == {
        "SEALED_SELECTED_EVIDENCE",
        "SEALED_MISSING_NOT_IMPUTED",
    }


def test_truncated_crash_record_blocks_recovery(tmp_path: Path) -> None:
    service = sidecar(tmp_path)
    register(service)
    path = sorted(service.journal.root.glob("*.json"))[0]
    path.write_bytes(path.read_bytes()[:20])
    path.chmod(0o600)

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_RECORD_(JSON|BYTES)_INVALID",
    ):
        service.recover()


def test_content_tamper_blocks_recovery(tmp_path: Path) -> None:
    service = sidecar(tmp_path)
    register(service)
    path = sorted(service.journal.root.glob("*.json"))[0]
    payload = json.loads(path.read_text())
    payload["payload"]["dispatch_allowed"] = True
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    path.chmod(0o600)

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_RECORD_HASH_MISMATCH",
    ):
        service.recover()


def test_unexpected_file_or_sequence_gap_blocks_recovery(
    tmp_path: Path,
) -> None:
    repository = journal(tmp_path)
    (repository.root / "unexpected").write_text("x")
    (repository.root / "unexpected").chmod(0o600)
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_SEQUENCE_INVALID",
    ):
        repository.recover()


def test_directory_fsync_failure_is_recoverable_without_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = journal(tmp_path)
    real_fsync = sidecar_module.os.fsync
    calls = 0
    directory_fsyncs = 0

    def fail_directory(fd: int) -> None:
        nonlocal calls, directory_fsyncs
        calls += 1
        if stat_is_directory(fd):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                raise OSError("forced post-record directory fsync failure")
        real_fsync(fd)

    def stat_is_directory(fd: int) -> bool:
        return bool(os.fstat(fd).st_mode & 0o040000)

    monkeypatch.setattr(sidecar_module.os, "fsync", fail_directory)
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_CREATE_ONLY_WRITE_FAILED",
    ):
        repository.append(
            operation_id="test:lost-response",
            payload={
                "record_type": "test",
                **sidecar_module._FALSE_AUTHORITY,
            },
        )
    assert calls >= 2
    assert directory_fsyncs == 2

    monkeypatch.setattr(sidecar_module.os, "fsync", real_fsync)
    recovered = repository.append(
        operation_id="test:lost-response",
        payload={
            "record_type": "test",
            **sidecar_module._FALSE_AUTHORITY,
        },
    )
    assert recovered.sequence == 1
    assert len(repository.recover()) == 1


def test_incomplete_reservation_fails_closed_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = journal(tmp_path)
    real_fsync = sidecar_module.os.fsync

    def fail_first_directory_fsync(fd: int) -> None:
        if stat_is_directory(fd):
            raise OSError("forced reservation directory fsync failure")
        real_fsync(fd)

    def stat_is_directory(fd: int) -> bool:
        return bool(os.fstat(fd).st_mode & 0o040000)

    monkeypatch.setattr(
        sidecar_module.os,
        "fsync",
        fail_first_directory_fsync,
    )
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_RESERVATION_WRITE_FAILED",
    ):
        repository.append(
            operation_id="test:incomplete-reservation",
            payload={
                "record_type": "test",
                **sidecar_module._FALSE_AUTHORITY,
            },
        )

    monkeypatch.setattr(sidecar_module.os, "fsync", real_fsync)
    restarted = CreateOnlyExecutionQualityJournal(repository.root)
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_INCOMPLETE_RESERVATION",
    ):
        restarted.recover()
    assert len(list(repository.root.glob("*.reservation"))) == 1
    assert not list(repository.root.glob("*.json"))


def test_two_writer_instances_serialize_distinct_create_only_appends(
    tmp_path: Path,
) -> None:
    first = journal(tmp_path)
    writers = [
        CreateOnlyExecutionQualityJournal(first.root) for _ in range(16)
    ]

    def append(index: int):
        return writers[index].append(
            operation_id=f"writer:{index}",
            payload={
                "record_type": "writer-test",
                "writer": index,
                **sidecar_module._FALSE_AUTHORITY,
            },
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        receipts = list(pool.map(append, range(16)))

    recovered = first.recover()
    assert len(recovered) == 16
    assert {row.sequence for row in receipts} == set(range(1, 17))
    assert [row.sequence for row in recovered] == list(range(1, 17))
    assert len({row.record_hash for row in recovered}) == 16


def test_lock_rotation_cannot_commit_same_sequence_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = journal(tmp_path)
    reached_reservation = Event()
    allow_first_writer = Event()
    original_create_reservation = (
        CreateOnlyExecutionQualityJournal._create_reservation
    )

    def block_first_reservation(
        self: CreateOnlyExecutionQualityJournal,
        filename: str,
        raw: bytes,
    ) -> None:
        if self is first:
            reached_reservation.set()
            assert allow_first_writer.wait(timeout=10)
        original_create_reservation(self, filename, raw)

    monkeypatch.setattr(
        CreateOnlyExecutionQualityJournal,
        "_create_reservation",
        block_first_reservation,
    )

    def append(
        writer: CreateOnlyExecutionQualityJournal,
        index: int,
    ):
        try:
            return writer.append(
                operation_id=f"lock-rotation:{index}",
                payload={
                    "record_type": "lock-rotation-test",
                    "writer": index,
                    **sidecar_module._FALSE_AUTHORITY,
                },
            )
        except CFastExecutionQualitySidecarError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(append, first, 1)
        assert reached_reservation.wait(timeout=10)
        lock = first.root / sidecar_module._LOCK_NAME
        lock.unlink()
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        second = CreateOnlyExecutionQualityJournal(first.root)
        second_future = pool.submit(append, second, 2)
        second_result = second_future.result(timeout=10)
        allow_first_writer.set()
        first_result = first_future.result(timeout=10)

    outcomes = [first_result, second_result]
    assert sum(not isinstance(row, str) for row in outcomes) == 1
    assert "JOURNAL_SEQUENCE_COLLISION" in outcomes
    recovered = CreateOnlyExecutionQualityJournal(first.root).recover()
    assert len(recovered) == 1
    assert recovered[0].sequence == 1
    assert len(list(first.root.glob("00000000000000000001-*.json"))) == 1
    assert len(list(first.root.glob("00000000000000000001.reservation"))) == 1


def test_lock_rotation_after_reservation_leaves_fail_closed_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = journal(tmp_path)
    original_create_reservation = (
        CreateOnlyExecutionQualityJournal._create_reservation
    )

    def rotate_after_reservation(
        self: CreateOnlyExecutionQualityJournal,
        filename: str,
        raw: bytes,
    ) -> None:
        original_create_reservation(self, filename, raw)
        lock = self.root / sidecar_module._LOCK_NAME
        lock.unlink()
        lock.touch(mode=0o600)
        lock.chmod(0o600)

    monkeypatch.setattr(
        CreateOnlyExecutionQualityJournal,
        "_create_reservation",
        rotate_after_reservation,
    )
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_LOCK_CHANGED",
    ):
        repository.append(
            operation_id="lock-rotation:after-reservation",
            payload={
                "record_type": "lock-rotation-test",
                **sidecar_module._FALSE_AUTHORITY,
            },
        )

    restarted = CreateOnlyExecutionQualityJournal(repository.root)
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_INCOMPLETE_RESERVATION",
    ):
        restarted.recover()


def test_two_sidecars_cannot_commit_conflicting_ingest_identity(
    tmp_path: Path,
) -> None:
    repository = journal(tmp_path)
    services = [
        OfflineExecutionQualitySidecar(
            CreateOnlyExecutionQualityJournal(repository.root)
        )
        for _ in range(2)
    ]
    first = SCORER.book(0, ingest_id="concurrent-stable-id")
    second = SCORER.book(
        1,
        ingest_id="concurrent-stable-id",
        cumulative_volume="999",
    )

    def append(index: int):
        try:
            return services[index].append_preverified_snapshot(
                (first, second)[index]
            )
        except CFastExecutionQualitySidecarError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(append, range(2)))

    assert sum(isinstance(row, str) for row in outcomes) == 1
    assert "SNAPSHOT_IDENTITY_REUSE_CONFLICT" in outcomes
    recovered = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(repository.root)
    ).recover()
    assert len(recovered.snapshots) == 1


def test_lock_artifact_replacement_or_content_fails_closed(
    tmp_path: Path,
) -> None:
    repository = journal(tmp_path)
    lock = repository.root / sidecar_module._LOCK_NAME
    lock.write_text("tampered")
    lock.chmod(0o600)

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_LOCK_(INVALID|CHANGED)",
    ):
        repository.recover()


def test_root_path_swap_during_append_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = journal(tmp_path)
    original_root = repository.root
    detached_root = tmp_path / "detached-journal"
    real_fsync = sidecar_module.os.fsync
    directory_fsyncs = 0

    def swap_before_directory_fsync(fd: int) -> None:
        nonlocal directory_fsyncs
        if bool(os.fstat(fd).st_mode & 0o040000):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                original_root.rename(detached_root)
                original_root.mkdir(mode=0o700)
                original_root.chmod(0o700)
        real_fsync(fd)

    monkeypatch.setattr(
        sidecar_module.os,
        "fsync",
        swap_before_directory_fsync,
    )
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_ROOT_CHANGED",
    ):
        repository.append(
            operation_id="root-swap:append",
            payload={
                "record_type": "root-swap-test",
                **sidecar_module._FALSE_AUTHORITY,
            },
        )
    assert not list(original_root.glob("*.json"))
    assert len(list(detached_root.glob("*.json"))) == 1
    assert len(list(detached_root.glob("*.reservation"))) == 1


def test_root_path_swap_before_recover_fails_closed(tmp_path: Path) -> None:
    repository = journal(tmp_path)
    detached_root = tmp_path / "detached-before-recover"
    repository.root.rename(detached_root)
    repository.root.mkdir(mode=0o700)
    repository.root.chmod(0o700)

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_ROOT_CHANGED",
    ):
        repository.recover()


def test_non_private_or_symlink_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "unsafe"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_ROOT_INVALID",
    ):
        CreateOnlyExecutionQualityJournal(root)

    safe = tmp_path / "safe"
    safe.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(safe, target_is_directory=True)
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="JOURNAL_ROOT_INVALID",
    ):
        CreateOnlyExecutionQualityJournal(link)


def test_registration_rejects_snapshot_receipt_or_plan_mismatch(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    accepted = plan()
    policy = SCORER.policy()
    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="INTENT_SOURCE_BINDING_INVALID",
    ):
        service.register_preverified_intent(
            preverified_plan=accepted,
            intent_id=accepted.intents[0].intent_id,
            source_snapshot_receipt_sha256="a" * 64,
            score_policy=policy,
            score_policy_hash=sha256_json(
                policy.model_dump(mode="json")
            ),
            contract_spec=SCORER.contract_spec(),
        )


def test_coordinated_evidence_and_outer_hash_rewrite_fails_fresh_replay(
    tmp_path: Path,
) -> None:
    service = sidecar(tmp_path)
    intent_id = register(service)
    service.append_preverified_snapshot(SCORER.book(0))
    service.append_preverified_snapshot(SCORER.book(62_000))
    service.seal_ready_evidence(intent_id)
    evidence_path = sorted(service.journal.root.glob("*.json"))[-1]
    envelope = json.loads(evidence_path.read_text())
    score = envelope["payload"]["score"]
    score["decision_metrics"]["spread_ticks"] = "999"
    score["score_hash"] = sha256_json(
        {
            key: value
            for key, value in score.items()
            if key != "score_hash"
        }
    )
    envelope["record_hash"] = sha256_json(
        {
            key: value
            for key, value in envelope.items()
            if key != "record_hash"
        }
    )
    replacement = evidence_path.with_name(
        f"{envelope['sequence']:020d}-{envelope['record_hash']}.json"
    )
    replacement.write_text(
        json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    replacement.chmod(0o600)
    evidence_path.unlink()
    reservation_path = service.journal.root / (
        f"{envelope['sequence']:020d}.reservation"
    )
    reservation = json.loads(reservation_path.read_text())
    reservation["record_hash"] = envelope["record_hash"]
    reservation["record_filename"] = replacement.name
    reservation["record_bytes_sha256"] = hashlib.sha256(
        replacement.read_bytes()
    ).hexdigest()
    reservation["reservation_hash"] = sha256_json(
        {
            key: value
            for key, value in reservation.items()
            if key != "reservation_hash"
        }
    )
    reservation_path.write_text(
        json.dumps(
            reservation,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    reservation_path.chmod(0o600)

    with pytest.raises(
        CFastExecutionQualitySidecarError,
        match="SCORE_EVIDENCE_DERIVATION_INVALID",
    ):
        service.recover()
