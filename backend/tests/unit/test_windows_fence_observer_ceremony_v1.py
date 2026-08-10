from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from scripts.windows_fence_foundation.ceremony_runner_v1 import (
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


def test_ceremony_requires_immediate_mutation_authorization() -> None:
    runner = WindowsFenceCeremonyRunnerV1(
        public_keyring_raw=b"",
        expected_public_keyring_sha256=hashlib.sha256(b"").hexdigest(),
        now=datetime.now(timezone.utc),
    )
    with pytest.raises(WindowsFenceCeremonyError, match="ARTIFACT_SET_REQUIRED"):
        runner.run_once(artifacts={}, dry_run=False)


def test_ceremony_live_path_is_disabled_after_verification(monkeypatch) -> None:
    runner = WindowsFenceCeremonyRunnerV1(
        public_keyring_raw=b"",
        expected_public_keyring_sha256=hashlib.sha256(b"").hexdigest(),
        now=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(
        runner,
        "_verify_closure",
        lambda _artifacts: {
            "install_attempt_id": "windows-fence-install-" + "a" * 64,
            "service_name": "VnpyRpcService",
        },
    )
    with pytest.raises(WindowsFenceCeremonyError, match="LIVE_MUTATION_PATH_DISABLED"):
        runner.run_once(artifacts={}, dry_run=False)


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
