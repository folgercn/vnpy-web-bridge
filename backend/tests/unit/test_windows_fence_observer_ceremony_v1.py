"""Offline contract tests only; they never claim Windows production acceptance."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from backend.tests.unit import test_issue267_windows_fence_foundation_schemas as fixture
from backend.tests.unit.test_windows_fence_signing_closure_e2e_v1 import (
    _chain_artifacts,
)
from scripts.windows_fence_foundation.ceremony_runner_v1 import (
    CeremonyEventEvidenceV1,
    CeremonyQueryEvidenceV1,
    CeremonyReservationEvidenceV1,
    CeremonyStepContextV1,
    NativeWindowsFenceCeremonyActionsV1,
    WindowsFenceCeremonyError,
    WindowsFenceCeremonyRunnerV1,
)
from scripts.windows_fence_foundation.host_observer_v1 import (
    NativeWindowsHostObserverV1,
    WindowsHostObservationError,
)

ATTEMPT_ID = fixture.ATTEMPT_ID
SERVICE_NAME = "VnpyRpcService"


def _unsigned(
    factory, identity: tuple[str, str]
) -> tuple[dict[str, object], dict[str, bytes]]:
    facts = factory()
    for key in (*identity, "signature"):
        facts.pop(key)
    raw_bindings = {
        key: f"offline-contract:{key}".encode()
        for key in facts
        if key.endswith("_raw_sha256")
    }
    facts.update(
        {key: hashlib.sha256(raw).hexdigest() for key, raw in raw_bindings.items()}
    )
    return facts, raw_bindings


class _OfflineReadOnlyFacts:
    """Strict named seam; deliberately not a production native adapter."""

    def __init__(self) -> None:
        self.publish = _unsigned(
            fixture._publish_receipt, ("receipt_id", "receipt_core_sha256")
        )
        self.scm = _unsigned(
            fixture._scm_dispatch_evidence, ("evidence_id", "evidence_core_sha256")
        )
        self.startup = _unsigned(
            fixture._startup_receipt, ("receipt_id", "receipt_core_sha256")
        )
        self.attestation = _unsigned(
            fixture._attestation, ("attestation_id", "attestation_core_sha256")
        )

    def capture_publish_receipt_facts(self):
        return self.publish

    def capture_scm_dispatch_evidence_facts(self):
        return self.scm

    def capture_startup_receipt_facts(self):
        return self.startup

    def capture_attestation_facts(self):
        return self.attestation


@pytest.mark.parametrize(
    ("method", "schema_version"),
    [
        ("capture_publish_receipt", "windows_rpc_durable_fence_publish_receipt_v1"),
        (
            "capture_scm_dispatch_evidence",
            "windows_rpc_durable_fence_scm_dispatch_evidence_v1",
        ),
        ("capture_startup_receipt", "windows_rpc_durable_fence_startup_receipt_v1"),
        ("capture_attestation", "windows_rpc_durable_fence_foundation_attestation_v1"),
    ],
)
def test_observer_explicit_methods_emit_existing_v1_unsigned_drafts_offline_contract(
    method: str, schema_version: str
) -> None:
    raw = getattr(NativeWindowsHostObserverV1(), method)(
        offline_contract=_OfflineReadOnlyFacts()
    )
    assert json.loads(raw)["schema_version"] == schema_version


def test_observer_raw_fact_hash_mismatch_fails_closed() -> None:
    contract = _OfflineReadOnlyFacts()
    contract.publish[1]["install_manifest_raw_sha256"] = "0" * 64
    with pytest.raises(WindowsHostObservationError, match="RAW_BINDING_MISMATCH"):
        NativeWindowsHostObserverV1().capture_publish_receipt(offline_contract=contract)


def test_observer_default_requires_real_windows_native_capability() -> None:
    with pytest.raises(WindowsHostObservationError, match="NATIVE_SOURCE_REQUIRED"):
        NativeWindowsHostObserverV1().capture_attestation()


def test_observer_production_constructor_has_no_command_or_fact_arguments() -> None:
    with pytest.raises(TypeError):
        NativeWindowsHostObserverV1(
            service_name=SERVICE_NAME,
            store_path=r"C:\\ProgramData\\vnpy-web-bridge\\windows-fence\\store",
            execution_facts_command=("untrusted.exe",),  # type: ignore[call-arg]
        )


def _unsigned_observer_draft(raw: bytes) -> bytes:
    value = json.loads(raw)
    value.pop("signature")
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class _Actions:
    def __init__(
        self, observer_artifacts: dict[str, bytes], fail_at: str | None = None
    ) -> None:
        self.calls: list[str] = []
        self.fail_at = fail_at
        self.restart_dispatches = 0
        self.observer_artifacts = observer_artifacts
        self.signed_joins: dict[int, str] = {}

    @staticmethod
    def _event(
        context: CeremonyStepContextV1, sequence: int
    ) -> CeremonyEventEvidenceV1:
        return CeremonyEventEvidenceV1(
            event_sequence=sequence,
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            raw=f"event-{sequence}".encode(),
            previous_event_raw_sha256=(
                None
                if context.previous_event is None
                else context.previous_event.raw_sha256
            ),
        )

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise TimeoutError(name)

    def run_events_1_to_2(self, *, context: CeremonyStepContextV1):
        self._call("events_1_to_2")
        one = self._event(context, 1)
        return one, self._event(
            CeremonyStepContextV1(
                context.install_attempt_id, context.service_name, one
            ),
            2,
        )

    def reserve_event_3_durable_create_only(self, *, context: CeremonyStepContextV1):
        self._call("event_3")
        return CeremonyReservationEvidenceV1(
            self._event(context, 3), "journal-event-3", True
        )

    def run_event_4(self, *, context: CeremonyStepContextV1):
        self._call("event_4")
        return self._event(context, 4)

    def dispatch_restart_once_for_event_5(
        self,
        *,
        context: CeremonyStepContextV1,
        signed_restart_authorization: bytes,
    ):
        del context
        assert signed_restart_authorization
        self._call("event_5_dispatch")
        self.restart_dispatches += 1

    def append_event_5(
        self, *, context: CeremonyStepContextV1, scm_dispatch_evidence_raw: bytes
    ):
        assert (
            scm_dispatch_evidence_raw
            == self.observer_artifacts["scm_dispatch_evidence"]
        )
        self._call("event_5_append")
        self.signed_joins[5] = hashlib.sha256(scm_dispatch_evidence_raw).hexdigest()
        return self._event(context, 5)

    def capture_scm_dispatch_evidence_draft(self, *, context: CeremonyStepContextV1):
        del context
        self._call("capture_scm")
        return _unsigned_observer_draft(
            self.observer_artifacts["scm_dispatch_evidence"]
        )

    def await_event_6(
        self, *, context: CeremonyStepContextV1, startup_receipt_raw: bytes
    ):
        assert startup_receipt_raw == self.observer_artifacts["startup_receipt"]
        self._call("event_6_append")
        self.signed_joins[6] = hashlib.sha256(startup_receipt_raw).hexdigest()
        return self._event(context, 6)

    def capture_startup_receipt_draft(self, *, context: CeremonyStepContextV1):
        del context
        self._call("capture_startup")
        return _unsigned_observer_draft(self.observer_artifacts["startup_receipt"])

    def await_event_7(self, *, context: CeremonyStepContextV1, attestation_raw: bytes):
        assert attestation_raw == self.observer_artifacts["attestation"]
        self._call("event_7_append")
        self.signed_joins[7] = hashlib.sha256(attestation_raw).hexdigest()
        return self._event(context, 7)

    def capture_attestation_draft(self, *, context: CeremonyStepContextV1):
        del context
        self._call("capture_attestation")
        return _unsigned_observer_draft(self.observer_artifacts["attestation"])

    def query_same_attempt_only(self, *, context: CeremonyStepContextV1, cause: str):
        self.calls.append(f"query:{cause}")
        return CeremonyQueryEvidenceV1(
            context.install_attempt_id,
            context.service_name,
            b"installer-journal-query",
            0 if cause == "attempt_frontier" else 3,
        )


def _runner(keyring: bytes) -> WindowsFenceCeremonyRunnerV1:
    return WindowsFenceCeremonyRunnerV1(
        public_keyring_raw=keyring,
        expected_public_keyring_sha256=hashlib.sha256(keyring).hexdigest(),
        now=datetime(2026, 8, 5, 0, 0, 25, tzinfo=timezone.utc),
    )


def _live_artifacts(tmp_path):
    chain, keyring = _chain_artifacts(tmp_path)
    return {
        key: chain[key]
        for key in (
            "zero_preflight",
            "manifest",
            "publish_receipt",
            "restart_authorization",
            "scm_dispatch_evidence",
            "startup_receipt",
            "attestation",
        )
    }, keyring


def test_live_admission_requires_signed_v1_artifacts_and_reuses_event_journal(
    tmp_path,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(artifacts)
    result = _runner(keyring).run_once(
        artifacts=artifacts, dry_run=False, actions=actions
    )
    assert result.completed_events == (1, 2, 3, 4, 5, 6, 7)
    assert actions.restart_dispatches == result.restart_dispatches == 1
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "event_3",
        "event_4",
        "event_5_dispatch",
        "capture_scm",
        "event_5_append",
        "capture_startup",
        "event_6_append",
        "capture_attestation",
        "event_7_append",
    ]
    assert actions.signed_joins == {
        5: hashlib.sha256(artifacts["scm_dispatch_evidence"]).hexdigest(),
        6: hashlib.sha256(artifacts["startup_receipt"]).hexdigest(),
        7: hashlib.sha256(artifacts["attestation"]).hexdigest(),
    }


def test_live_event3_failure_is_query_only_and_never_restarts(tmp_path) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(artifacts, fail_at="event_3")
    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "event_3",
        "query:event_3_unknown",
    ]
    assert actions.restart_dispatches == 0


@pytest.mark.parametrize(
    ("fail_at", "expected_calls", "restart_dispatches"),
    [
        (
            "event_4",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "event_3",
                "event_4",
                "query:event_4_unknown",
            ],
            0,
        ),
        (
            "event_5_dispatch",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "query:event_5_restart_unknown",
            ],
            0,
        ),
        (
            "event_6_append",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "capture_scm",
                "event_5_append",
                "capture_startup",
                "event_6_append",
                "query:event_6_unknown",
            ],
            1,
        ),
        (
            "event_7_append",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "capture_scm",
                "event_5_append",
                "capture_startup",
                "event_6_append",
                "capture_attestation",
                "event_7_append",
                "query:event_7_unknown",
            ],
            1,
        ),
    ],
)
def test_live_event4_to_7_failures_are_query_only_and_never_retry_restart(
    tmp_path, fail_at, expected_calls, restart_dispatches
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(artifacts, fail_at=fail_at)
    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == expected_calls
    assert actions.restart_dispatches == restart_dispatches


def test_live_rejects_signed_observer_artifact_for_a_different_draft(tmp_path) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    actions.observer_artifacts["startup_receipt"] = artifacts["attestation"]
    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "event_3",
        "event_4",
        "event_5_dispatch",
        "capture_scm",
        "event_5_append",
        "capture_startup",
        "query:event_6_unknown",
    ]
    assert actions.restart_dispatches == 1


def test_concrete_native_actions_reject_test_doubles() -> None:
    with pytest.raises(WindowsFenceCeremonyError, match="NATIVE_ACTIONS_REQUIRED"):
        NativeWindowsFenceCeremonyActionsV1(
            installer=object(),  # type: ignore[arg-type]
            observer=object(),  # type: ignore[arg-type]
            bundle_raw=b"bundle",
        )


def test_live_missing_event5_signed_handoff_fails_closed_after_dispatch(
    tmp_path,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    artifacts.pop("scm_dispatch_evidence")
    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "event_3",
        "event_4",
        "event_5_dispatch",
        "capture_scm",
        "query:event_5_restart_unknown",
    ]
    assert actions.restart_dispatches == 1


@pytest.mark.parametrize(
    ("missing", "expected_calls", "expected_joins"),
    [
        (
            "startup_receipt",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "capture_scm",
                "event_5_append",
                "capture_startup",
                "query:event_6_unknown",
            ],
            (5,),
        ),
        (
            "attestation",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "capture_scm",
                "event_5_append",
                "capture_startup",
                "event_6_append",
                "capture_attestation",
                "query:event_7_unknown",
            ],
            (5, 6),
        ),
    ],
)
def test_live_missing_later_signed_handoff_fails_closed_after_observation(
    tmp_path,
    missing,
    expected_calls,
    expected_joins,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    artifacts.pop(missing)
    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == expected_calls
    assert tuple(actions.signed_joins) == expected_joins
    assert actions.restart_dispatches == 1


def test_live_event5_raw_hash_join_mismatch_fails_closed_after_dispatch(
    tmp_path,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    actions.observer_artifacts["scm_dispatch_evidence"] = artifacts["attestation"]
    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "event_3",
        "event_4",
        "event_5_dispatch",
        "capture_scm",
        "query:event_5_restart_unknown",
    ]
    assert actions.signed_joins == {}
    assert actions.restart_dispatches == 1


def test_existing_v1_closure_remains_dry_run_verifiable(tmp_path) -> None:
    chain, keyring = _chain_artifacts(tmp_path)
    result = _runner(keyring).verify_dry_run(chain)
    assert result.mode == "dry-run"
    assert result.completed_events == (1, 2, 3, 4, 5, 6, 7)
