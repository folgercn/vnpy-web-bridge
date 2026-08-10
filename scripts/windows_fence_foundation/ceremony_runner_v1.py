"""One-shot, fail-closed Windows fence ceremony coordinator.

The runner never signs.  Its CLI is verification-only by design; a reviewed
    live mutation is intentionally disabled; a later reviewed command must
    provide its own immediate authorization and execution boundary.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .contracts import canonical_json_bytes
from .installer_trust_anchor_v1 import (
    load_production_installer_trust_anchor_v1,
    validate_anchor_keyring_bytes_v1,
)
from .offline_signing_v1 import OfflineSigningError
from .release_bundle_v1 import CHAIN_ORDER, verify_signing_closure_chain_v1


class WindowsFenceCeremonyError(RuntimeError):
    """Stable fail-closed ceremony error."""


class WindowsFenceCeremonyActionsV1(Protocol):
    """Explicitly injected mutation seam; never exposed by the safe CLI."""

    def run_events_1_to_2(self) -> None: ...

    def run_events_3_to_4(self) -> None: ...

    def dispatch_restart_once_for_event_5(self) -> None: ...

    def await_event_6(self) -> None: ...

    def await_event_7(self) -> Mapping[str, bytes]: ...

    def query_same_attempt_only(self) -> None: ...


@dataclass(frozen=True)
class CeremonyResultV1:
    mode: str
    install_attempt_id: str
    service_name: str
    completed_events: tuple[int, ...]
    restart_dispatches: int


class WindowsFenceCeremonyRunnerV1:
    """Advance 1→7 once, turning every post-event-3 uncertainty into query-only."""

    def __init__(
        self,
        *,
        public_keyring_raw: bytes,
        expected_public_keyring_sha256: str,
        now: datetime,
    ) -> None:
        self._public_keyring_raw = public_keyring_raw
        self._expected_keyring_sha256 = expected_public_keyring_sha256
        self._now = now

    def verify_dry_run(self, artifacts: Mapping[str, bytes]) -> CeremonyResultV1:
        closure = self._verify_closure(artifacts)
        return CeremonyResultV1(
            mode="dry-run",
            install_attempt_id=str(closure["install_attempt_id"]),
            service_name=str(closure["service_name"]),
            completed_events=(1, 2, 3, 4, 5, 6, 7),
            restart_dispatches=0,
        )

    def run_once(
        self,
        *,
        artifacts: Mapping[str, bytes],
        dry_run: bool = True,
    ) -> CeremonyResultV1:
        closure = self._verify_closure(artifacts)
        if not dry_run:
            raise WindowsFenceCeremonyError("CEREMONY_LIVE_MUTATION_PATH_DISABLED")
        return CeremonyResultV1(
            mode="dry-run",
            install_attempt_id=str(closure["install_attempt_id"]),
            service_name=str(closure["service_name"]),
            completed_events=(1, 2, 3, 4, 5, 6, 7),
            restart_dispatches=0,
        )

    def _verify_closure(self, artifacts: Mapping[str, bytes]) -> Mapping[str, object]:
        if (
            hashlib.sha256(self._public_keyring_raw).hexdigest()
            != self._expected_keyring_sha256
        ):
            raise WindowsFenceCeremonyError("CEREMONY_TRUST_KEYRING_PIN_MISMATCH")
        if set(artifacts) != set(CHAIN_ORDER) or any(
            type(raw) is not bytes for raw in artifacts.values()
        ):
            raise WindowsFenceCeremonyError("CEREMONY_SIGNED_ARTIFACT_SET_REQUIRED")
        try:
            return verify_signing_closure_chain_v1(
                artifacts, public_keyring_raw=self._public_keyring_raw, now=self._now
            )
        except OfflineSigningError as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_SIGNED_ARTIFACT_VERIFICATION_FAILED"
            ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    options = parser.parse_args(argv)
    try:
        now = datetime.fromisoformat(options.now_utc.replace("Z", "+00:00"))
        anchor = load_production_installer_trust_anchor_v1()
        public_keyring_raw = anchor.keyring_path.read_bytes()
        validate_anchor_keyring_bytes_v1(anchor, public_keyring_raw)
        artifacts = {
            name: (options.inputs_dir / f"{name}.json").read_bytes()
            for name in CHAIN_ORDER
        }
        result = WindowsFenceCeremonyRunnerV1(
            public_keyring_raw=public_keyring_raw,
            expected_public_keyring_sha256=anchor.keyring_raw_sha256,
            now=now,
        ).verify_dry_run(artifacts)
    except (OSError, ValueError, WindowsFenceCeremonyError) as exc:
        parser.error(f"dry-run ceremony verification failed: {exc}")
    print(canonical_json_bytes(result.__dict__).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CeremonyResultV1",
    "WindowsFenceCeremonyActionsV1",
    "WindowsFenceCeremonyError",
    "WindowsFenceCeremonyRunnerV1",
]
