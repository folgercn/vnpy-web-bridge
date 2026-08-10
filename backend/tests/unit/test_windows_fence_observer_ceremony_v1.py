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
    NativeWindowsReadOnlyFactsAdapterV1,
    WindowsHostObservationError,
)
from scripts.windows_fence_foundation.native_windows_installer_host_v1 import (
    NativeWindowsFenceInstallerHostV1,
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
        key: json.dumps(
            {"raw_binding": key}, separators=(",", ":"), sort_keys=True
        ).encode()
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


def test_observer_noncanonical_raw_binding_fails_closed() -> None:
    contract = _OfflineReadOnlyFacts()
    raw = b'{"z":0,"a":1}'
    contract.publish[0]["install_manifest_raw_sha256"] = hashlib.sha256(raw).hexdigest()
    contract.publish = (
        contract.publish[0],
        {**contract.publish[1], "install_manifest_raw_sha256": raw},
    )
    with pytest.raises(
        WindowsHostObservationError, match="RAW_BINDING_CANONICAL_INVALID"
    ):
        NativeWindowsHostObserverV1().capture_publish_receipt(offline_contract=contract)


def test_native_capture_methods_reduce_only_private_native_fixture(monkeypatch) -> None:
    """The fixture replaces no public/caller production seam."""
    contracts = _OfflineReadOnlyFacts()
    native_host = object.__new__(NativeWindowsFenceInstallerHostV1)
    source = NativeWindowsReadOnlyFactsAdapterV1(
        service_name=SERVICE_NAME,
        store_path=r"C:\\ProgramData\\vnpy-web-bridge\\windows-fence\\store",
        installer_host=native_host,
    )
    event_raws = {
        sequence: json.dumps(
            {"event_sequence": sequence}, separators=(",", ":"), sort_keys=True
        ).encode()
        for sequence in range(1, 7)
    }
    seen: list[tuple[str, tuple[int, ...]]] = []

    def native_readbacks(*, event_sequences: tuple[int, ...]):
        return {"event_raws": {key: event_raws[key] for key in event_sequences}}

    def reduce_native(*, kind: str, readbacks):
        seen.append((kind, tuple(readbacks["event_raws"])))
        return {
            "publish_receipt": contracts.publish,
            "scm_dispatch_evidence": contracts.scm,
            "startup_receipt": contracts.startup,
            "attestation": contracts.attestation,
        }[kind]

    monkeypatch.setattr(source, "_native_readbacks", native_readbacks)
    monkeypatch.setattr(source, "_facts_from_native_readbacks", reduce_native)
    captures = {
        "publish_receipt": source.capture_publish_receipt_facts(),
        "scm_dispatch_evidence": source.capture_scm_dispatch_evidence_facts(),
        "startup_receipt": source.capture_startup_receipt_facts(),
        "attestation": source.capture_attestation_facts(),
    }
    assert seen == [
        ("publish_receipt", (1, 2)),
        ("scm_dispatch_evidence", (3, 4)),
        ("startup_receipt", (3, 4, 5)),
        ("attestation", (3, 4, 5, 6)),
    ]
    for kind, captured in captures.items():
        draft = NativeWindowsHostObserverV1._draft_from_read_only_facts(kind, captured)
        value = json.loads(draft)
        identity, core, prefix = {
            "publish_receipt": (
                "receipt_id",
                "receipt_core_sha256",
                "windows-fence-publish-receipt-",
            ),
            "scm_dispatch_evidence": (
                "evidence_id",
                "evidence_core_sha256",
                "windows-fence-scm-dispatch-evidence-",
            ),
            "startup_receipt": (
                "receipt_id",
                "receipt_core_sha256",
                "windows-fence-startup-receipt-",
            ),
            "attestation": (
                "attestation_id",
                "attestation_core_sha256",
                "windows-fence-foundation-attestation-",
            ),
        }[kind]
        unsigned = dict(value)
        unsigned.pop(identity)
        unsigned.pop(core)
        assert (
            value[core]
            == hashlib.sha256(
                json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode()
            ).hexdigest()
        )
        assert value[identity] == prefix + value[core]


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        ("publish_receipt", "PUBLISH_CUSTODY_UNAVAILABLE"),
        ("scm_dispatch_evidence", "SCM_AUDIT_TRACE_UNAVAILABLE"),
        ("startup_receipt", "SCM_AUDIT_TRACE_UNAVAILABLE"),
        ("attestation", "M2_ATTESTATION_FACTS_UNAVAILABLE"),
    ],
)
def test_native_reducer_fails_closed_when_required_production_source_is_absent(
    kind: str, code: str
) -> None:
    with pytest.raises(WindowsHostObservationError, match=code):
        NativeWindowsReadOnlyFactsAdapterV1._facts_from_native_readbacks(
            kind=kind,
            readbacks={"event_raws": {1: b'{"event_sequence":1}'}},
        )


def test_native_reducer_rejects_noncanonical_journal_raw() -> None:
    with pytest.raises(
        WindowsHostObservationError, match="RAW_BINDING_CANONICAL_INVALID"
    ):
        NativeWindowsReadOnlyFactsAdapterV1._facts_from_native_readbacks(
            kind="publish_receipt",
            readbacks={"event_raws": {1: b'{"z":0,"a":1}'}},
        )


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


def test_fake_facts_source_cannot_enter_production_selection(monkeypatch) -> None:
    native_host = object.__new__(NativeWindowsFenceInstallerHostV1)
    observer = NativeWindowsHostObserverV1(
        service_name=SERVICE_NAME,
        store_path=r"C:\\ProgramData\\vnpy-web-bridge\\windows-fence\\store",
        installer_host=native_host,
        facts_source=_OfflineReadOnlyFacts(),
    )
    monkeypatch.setattr(
        "scripts.windows_fence_foundation.host_observer_v1.os.name", "nt"
    )
    with pytest.raises(WindowsHostObservationError, match="NATIVE_SOURCE_REQUIRED"):
        observer._source(None)


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
        self.frontier_sequence = 0
        self.frontier_raw = b"installer-journal-empty"

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

    def _record(self, event: CeremonyEventEvidenceV1) -> CeremonyEventEvidenceV1:
        self.frontier_sequence = event.event_sequence
        self.frontier_raw = event.raw
        return event

    def run_events_1_to_2(self, *, context: CeremonyStepContextV1):
        self._call("events_1_to_2")
        one = self._event(context, 1)
        return one, self._record(
            self._event(
                CeremonyStepContextV1(
                    context.install_attempt_id, context.service_name, one
                ),
                2,
            )
        )

    def capture_publish_receipt_draft(self, *, context: CeremonyStepContextV1):
        del context
        self._call("capture_publish")
        return _unsigned_observer_draft(self.observer_artifacts["publish_receipt"])

    def reserve_event_3_durable_create_only(self, *, context: CeremonyStepContextV1):
        self._call("event_3")
        return CeremonyReservationEvidenceV1(
            self._record(self._event(context, 3)), "journal-event-3", True
        )

    def run_event_4(self, *, context: CeremonyStepContextV1):
        self._call("event_4")
        return self._record(self._event(context, 4))

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
        return self._record(self._event(context, 5))

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
        return self._record(self._event(context, 6))

    def capture_startup_receipt_draft(self, *, context: CeremonyStepContextV1):
        del context
        self._call("capture_startup")
        return _unsigned_observer_draft(self.observer_artifacts["startup_receipt"])

    def await_event_7(self, *, context: CeremonyStepContextV1, attestation_raw: bytes):
        assert attestation_raw == self.observer_artifacts["attestation"]
        self._call("event_7_append")
        self.signed_joins[7] = hashlib.sha256(attestation_raw).hexdigest()
        return self._record(self._event(context, 7))

    def capture_attestation_draft(self, *, context: CeremonyStepContextV1):
        del context
        self._call("capture_attestation")
        return _unsigned_observer_draft(self.observer_artifacts["attestation"])

    def query_same_attempt_only(self, *, context: CeremonyStepContextV1, cause: str):
        self.calls.append(f"query:{cause}")
        return CeremonyQueryEvidenceV1(
            context.install_attempt_id,
            context.service_name,
            self.frontier_raw,
            self.frontier_sequence,
            self.restart_dispatches,
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
        "capture_publish",
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
        "capture_publish",
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
                "capture_publish",
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
                "capture_publish",
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
                "capture_publish",
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
                "capture_publish",
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
    with pytest.raises(
        WindowsFenceCeremonyError, match="OBSERVER_HANDOFF_VERIFICATION"
    ):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "capture_publish",
        "event_3",
        "event_4",
        "event_5_dispatch",
        "capture_scm",
        "event_5_append",
        "capture_startup",
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
    result = _runner(keyring).run_once(
        artifacts=artifacts, dry_run=False, actions=actions
    )
    assert result.status == "WAITING_SCM_SIGNATURE"
    assert result.completed_events == (1, 2, 3, 4)
    assert result.missing_artifacts == ("scm_dispatch_evidence",)
    assert actions.restart_dispatches == 1


@pytest.mark.parametrize(
    ("missing", "expected_calls", "expected_joins"),
    [
        (
            "startup_receipt",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "capture_publish",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "capture_scm",
                "event_5_append",
                "capture_startup",
            ],
            (5,),
        ),
        (
            "attestation",
            [
                "query:attempt_frontier",
                "events_1_to_2",
                "capture_publish",
                "event_3",
                "event_4",
                "event_5_dispatch",
                "capture_scm",
                "event_5_append",
                "capture_startup",
                "event_6_append",
                "capture_attestation",
            ],
            (5, 6),
        ),
    ],
)
def test_live_missing_later_signed_handoff_returns_waiting_after_observation(
    tmp_path,
    missing,
    expected_calls,
    expected_joins,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    artifacts.pop(missing)
    result = _runner(keyring).run_once(
        artifacts=artifacts, dry_run=False, actions=actions
    )
    assert (
        result.status
        == {
            "startup_receipt": "WAITING_STARTUP_SIGNATURE",
            "attestation": "WAITING_ATTESTATION_SIGNATURE",
        }[missing]
    )
    assert actions.calls == [
        call for call in expected_calls if not call.startswith("query:event_")
    ]
    assert tuple(actions.signed_joins) == expected_joins
    assert actions.restart_dispatches == 1


def test_live_event5_raw_hash_join_mismatch_fails_closed_after_dispatch(
    tmp_path,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    actions.observer_artifacts["scm_dispatch_evidence"] = artifacts["attestation"]
    with pytest.raises(
        WindowsFenceCeremonyError, match="OBSERVER_HANDOFF_VERIFICATION"
    ):
        _runner(keyring).run_once(artifacts=artifacts, dry_run=False, actions=actions)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "capture_publish",
        "event_3",
        "event_4",
        "event_5_dispatch",
        "capture_scm",
    ]
    assert actions.signed_joins == {}
    assert actions.restart_dispatches == 1


def test_live_waiting_signatures_resume_same_attempt_without_replaying_mutations(
    tmp_path,
) -> None:
    artifacts, keyring = _live_artifacts(tmp_path)
    actions = _Actions(dict(artifacts))
    base = {key: artifacts[key] for key in ("zero_preflight", "manifest")}

    publish = _runner(keyring).run_once(artifacts=base, dry_run=False, actions=actions)
    assert publish.status == "WAITING_PUBLISH_SIGNATURE"
    assert publish.completed_events == (1, 2)
    assert publish.observer_draft == _unsigned_observer_draft(
        artifacts["publish_receipt"]
    )
    assert publish.missing_artifacts == ("publish_receipt",)
    assert actions.calls == [
        "query:attempt_frontier",
        "events_1_to_2",
        "capture_publish",
    ]

    no_restart = _runner(keyring).run_once(
        artifacts={**base, "publish_receipt": artifacts["publish_receipt"]},
        dry_run=False,
        actions=actions,
    )
    assert no_restart.status == "WAITING_PUBLISH_SIGNATURE"
    assert no_restart.missing_artifacts == ("restart_authorization",)
    assert actions.calls.count("events_1_to_2") == 1
    assert actions.calls.count("event_3") == 0

    scm = _runner(keyring).run_once(
        artifacts={
            **base,
            "publish_receipt": artifacts["publish_receipt"],
            "restart_authorization": artifacts["restart_authorization"],
        },
        dry_run=False,
        actions=actions,
    )
    assert scm.status == "WAITING_SCM_SIGNATURE"
    assert scm.completed_events == (1, 2, 3, 4)
    assert scm.restart_dispatches == actions.restart_dispatches == 1

    startup = _runner(keyring).run_once(
        artifacts={
            **base,
            "publish_receipt": artifacts["publish_receipt"],
            "restart_authorization": artifacts["restart_authorization"],
            "scm_dispatch_evidence": artifacts["scm_dispatch_evidence"],
        },
        dry_run=False,
        actions=actions,
    )
    assert startup.status == "WAITING_STARTUP_SIGNATURE"
    assert startup.completed_events == (1, 2, 3, 4, 5)
    assert actions.calls.count("event_3") == 1
    assert actions.calls.count("event_5_dispatch") == 1

    attestation = _runner(keyring).run_once(
        artifacts={
            **base,
            "publish_receipt": artifacts["publish_receipt"],
            "restart_authorization": artifacts["restart_authorization"],
            "scm_dispatch_evidence": artifacts["scm_dispatch_evidence"],
            "startup_receipt": artifacts["startup_receipt"],
        },
        dry_run=False,
        actions=actions,
    )
    assert attestation.status == "WAITING_ATTESTATION_SIGNATURE"
    assert attestation.completed_events == (1, 2, 3, 4, 5, 6)

    completed = _runner(keyring).run_once(
        artifacts=artifacts, dry_run=False, actions=actions
    )
    duplicate = _runner(keyring).run_once(
        artifacts=artifacts, dry_run=False, actions=actions
    )
    assert completed.status == duplicate.status == "COMPLETED"
    assert actions.calls.count("events_1_to_2") == 1
    assert actions.calls.count("event_3") == 1
    assert actions.calls.count("event_5_dispatch") == 1
    assert actions.restart_dispatches == 1


def test_existing_v1_closure_remains_dry_run_verifiable(tmp_path) -> None:
    chain, keyring = _chain_artifacts(tmp_path)
    result = _runner(keyring).verify_dry_run(chain)
    assert result.mode == "dry-run"
    assert result.completed_events == (1, 2, 3, 4, 5, 6, 7)
