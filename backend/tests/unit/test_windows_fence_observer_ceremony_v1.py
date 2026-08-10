from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from scripts.windows_fence_foundation.ceremony_runner_v1 import (
    CeremonyEventEvidenceV1,
    CeremonyQueryEvidenceV1,
    CeremonyReservationEvidenceV1,
    CeremonyStepContextV1,
    ImmediateLiveAuthorizationV1,
    WindowsFenceCeremonyError,
    WindowsFenceCeremonyRunnerV1,
)
from scripts.windows_fence_foundation.host_observer_v1 import (
    NativeWindowsHostObserverV1,
    NativeWindowsReadOnlyFactsAdapterV1,
    WindowsHostObservationError,
    _canonical_observer_draft_v1,
)


def test_observer_rejects_caller_supplied_identity() -> None:
    with pytest.raises(WindowsHostObservationError, match="IDENTITY_SUPPLIED"):
        _canonical_observer_draft_v1(
            "zero_preflight",
            {"receipt_id": "hand-authored", "receipt_core_sha256": "a" * 64},
        )


def test_observer_rejects_stale_zero_preflight() -> None:
    now = datetime.now(timezone.utc)
    with pytest.raises(WindowsHostObservationError, match="NOT_FRESH"):
        _canonical_observer_draft_v1(
            "zero_preflight",
            {
                "observed_at_utc": (now - timedelta(seconds=30))
                .isoformat()
                .replace("+00:00", "Z"),
                "challenge_issued_at_utc": (now - timedelta(seconds=40))
                .isoformat()
                .replace("+00:00", "Z"),
                "snapshot_served_at_utc": (now - timedelta(seconds=61))
                .isoformat()
                .replace("+00:00", "Z"),
                "challenge_expires_at_utc": (now + timedelta(seconds=10))
                .isoformat()
                .replace("+00:00", "Z"),
            },
        )


ATTEMPT_ID = "windows-fence-install-" + "a" * 64
SERVICE_NAME = "VnpyRpcService"


def _runner() -> WindowsFenceCeremonyRunnerV1:
    return WindowsFenceCeremonyRunnerV1(
        public_keyring_raw=b"",
        expected_public_keyring_sha256=hashlib.sha256(b"").hexdigest(),
        now=datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )


def _authorization() -> ImmediateLiveAuthorizationV1:
    return ImmediateLiveAuthorizationV1(
        authorization_id="manual-ceremony-approval-1",
        install_attempt_id=ATTEMPT_ID,
        service_name=SERVICE_NAME,
        issued_at=datetime(2026, 8, 10, 11, tzinfo=timezone.utc),
        expires_at=datetime(2026, 8, 10, 13, tzinfo=timezone.utc),
        restart_authorized=True,
        automatic_restart_allowed=False,
        maximum_restart_dispatches=1,
    )


class _Actions:
    def __init__(self, *, fail_at: str | None = None) -> None:
        self.calls: list[str] = []
        self.contexts: list[CeremonyStepContextV1] = []
        self.fail_at = fail_at
        self.restart_dispatches = 0

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

    def _call(self, name: str, context: CeremonyStepContextV1) -> None:
        self.calls.append(name)
        self.contexts.append(context)
        if self.fail_at == name:
            raise TimeoutError(name)

    def run_events_1_to_2(
        self, *, context: CeremonyStepContextV1
    ) -> tuple[CeremonyEventEvidenceV1, CeremonyEventEvidenceV1]:
        self._call("events_1_to_2", context)
        event_1 = self._event(context, 1)
        return event_1, self._event(
            CeremonyStepContextV1(
                install_attempt_id=context.install_attempt_id,
                service_name=context.service_name,
                previous_event=event_1,
            ),
            2,
        )

    def reserve_event_3_durable_create_only(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyReservationEvidenceV1:
        self._call("event_3", context)
        return CeremonyReservationEvidenceV1(
            event=self._event(context, 3),
            reservation_id="create-only-reservation-1",
            durable_create_only=True,
        )

    def run_event_4(self, *, context: CeremonyStepContextV1) -> CeremonyEventEvidenceV1:
        self._call("event_4", context)
        return self._event(context, 4)

    def dispatch_restart_once_for_event_5(
        self,
        *,
        context: CeremonyStepContextV1,
        authorization: ImmediateLiveAuthorizationV1,
    ) -> CeremonyEventEvidenceV1:
        assert authorization == _authorization()
        self.restart_dispatches += 1
        self._call("event_5", context)
        return self._event(context, 5)

    def await_event_6(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyEventEvidenceV1:
        self._call("event_6", context)
        return self._event(context, 6)

    def await_event_7(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyEventEvidenceV1:
        self._call("event_7", context)
        return self._event(context, 7)

    def query_same_attempt_only(
        self, *, context: CeremonyStepContextV1, cause: str
    ) -> CeremonyQueryEvidenceV1:
        self.calls.append(f"query:{cause}")
        self.contexts.append(context)
        return CeremonyQueryEvidenceV1(
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            raw=b"same-attempt-query",
        )


def test_ceremony_live_requires_explicit_immediate_authorization() -> None:
    actions = _Actions()
    with pytest.raises(
        WindowsFenceCeremonyError, match="IMMEDIATE_LIVE_AUTHORIZATION_REQUIRED"
    ):
        _runner().run_once(artifacts={}, dry_run=False, actions=actions)
    assert actions.calls == []


def test_ceremony_defaults_to_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _runner()
    monkeypatch.setattr(
        runner,
        "_verify_closure",
        lambda _artifacts: {
            "install_attempt_id": ATTEMPT_ID,
            "service_name": SERVICE_NAME,
        },
    )

    result = runner.run_once(artifacts={})

    assert result.mode == "dry-run"
    assert result.restart_dispatches == 0


def test_ceremony_live_orchestrates_returned_event_evidence_without_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    monkeypatch.setattr(
        runner,
        "_verify_closure",
        lambda _artifacts: pytest.fail("live must not require an event-5/6/7 closure"),
    )
    actions = _Actions()

    result = runner.run_once(
        artifacts={},
        dry_run=False,
        actions=actions,
        live_authorization=_authorization(),
    )

    assert result.mode == "live"
    assert result.completed_events == (1, 2, 3, 4, 5, 6, 7)
    assert result.restart_dispatches == actions.restart_dispatches == 1
    assert actions.calls == [
        "events_1_to_2",
        "event_3",
        "event_4",
        "event_5",
        "event_6",
        "event_7",
    ]
    assert [
        None if item.previous_event is None else item.previous_event.event_sequence
        for item in actions.contexts
    ] == [None, 2, 3, 4, 5, 6]


@pytest.mark.parametrize(
    ("fail_at", "cause", "expected_calls"),
    [
        (
            "event_3",
            "event_3_unknown",
            ["events_1_to_2", "event_3", "query:event_3_unknown"],
        ),
        (
            "event_4",
            "event_4_unknown",
            ["events_1_to_2", "event_3", "event_4", "query:event_4_unknown"],
        ),
        (
            "event_5",
            "event_5_restart_unknown",
            [
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5",
                "query:event_5_restart_unknown",
            ],
        ),
        (
            "event_6",
            "event_6_unknown",
            [
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5",
                "event_6",
                "query:event_6_unknown",
            ],
        ),
        (
            "event_7",
            "event_7_unknown",
            [
                "events_1_to_2",
                "event_3",
                "event_4",
                "event_5",
                "event_6",
                "event_7",
                "query:event_7_unknown",
            ],
        ),
    ],
)
def test_ceremony_post_event3_unknown_is_same_attempt_query_only(
    fail_at: str, cause: str, expected_calls: list[str]
) -> None:
    actions = _Actions(fail_at=fail_at)

    with pytest.raises(WindowsFenceCeremonyError, match="POST_EVENT3_QUERY_ONLY"):
        _runner().run_once(
            artifacts={},
            dry_run=False,
            actions=actions,
            live_authorization=_authorization(),
        )

    assert actions.calls == expected_calls
    assert actions.contexts[-1].install_attempt_id == ATTEMPT_ID
    assert actions.contexts[-1].service_name == SERVICE_NAME
    assert actions.restart_dispatches <= 1


def test_capture_draft_rejects_self_reported_real_host() -> None:
    class Fake:
        is_real_windows_host = True

        def capture_observer_facts(self, _kind):
            return {}

    with pytest.raises(WindowsHostObservationError, match="REAL_WINDOWS_HOST_REQUIRED"):
        NativeWindowsHostObserverV1().capture_draft("zero_preflight", seam=Fake())


def test_native_adapter_requires_both_canonical_source_commands() -> None:
    adapter = NativeWindowsReadOnlyFactsAdapterV1(
        service_name="VnpyRpcService", store_path=r"C:\fence"
    )
    with pytest.raises(WindowsHostObservationError, match="NATIVE_SOURCE_REQUIRED|REAL_WINDOWS"):
        # The adapter is intentionally not usable as a fixture on this host.
        NativeWindowsHostObserverV1(facts_source=adapter).capture_draft(
            "zero_preflight", seam=NativeWindowsHostObserverV1(facts_source=adapter)
        )
