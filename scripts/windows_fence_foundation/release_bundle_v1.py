"""Build a create-only, offline Windows-fence signing closure bundle.

This is a verifier/bundler only.  It neither signs nor invokes Windows, M2,
RPC, SCM, containers, or any order path.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .installer_trust_anchor_v1 import canonical_public_keyring_v1
from .offline_signing_v1 import (
    OfflineSigningError,
    _strict_object,
    read_canonical_artifact_v1,
    require_fresh_zero_preflight_v1,
    verify_public_artifact_v1,
    write_audit_create_only_v1,
    write_canonical_create_only_v1,
)

CHAIN_ORDER = (
    "zero_preflight",
    "manifest",
    "event_1_prepared",
    "publish_receipt",
    "event_2_published",
    "restart_authorization",
    "event_3_reserved",
    "transition_receipt",
    "event_4_transition",
    "scm_dispatch_evidence",
    "event_5_dispatched",
    "startup_receipt",
    "event_6_started",
    "attestation",
    "event_7_verified",
)


def _raw_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _event(raw: bytes, *, sequence: int, event_type: str, previous_raw: bytes | None) -> dict[str, Any]:
    value = _strict_object(raw)
    if (
        value.get("schema_version") != "windows_rpc_durable_fence_install_event_v1"
        or value.get("event_sequence") != sequence
        or value.get("event_type") != event_type
        or value.get("event_core_sha256") != hashlib.sha256(
            __import__("scripts.windows_fence_foundation.contracts", fromlist=["canonical_json_bytes"]).canonical_json_bytes(
                {key: item for key, item in value.items() if key not in {"event_id", "event_core_sha256"}}
            )
        ).hexdigest()
        or value.get("event_id") != "windows-fence-install-event-" + value["event_core_sha256"]
        or value.get("previous_event_raw_sha256") != (None if previous_raw is None else _raw_sha(previous_raw))
    ):
        raise OfflineSigningError("SIGNING_CHAIN_EVENT_INVALID")
    return value


def verify_signing_closure_chain_v1(
    artifacts: Mapping[str, bytes], *, public_keyring_raw: bytes, now: datetime
) -> dict[str, Any]:
    """Verify the exact signed/unsigned artifact order and all raw-byte joins."""
    if set(artifacts) != set(CHAIN_ORDER):
        raise OfflineSigningError("SIGNING_CHAIN_ARTIFACT_SET_INVALID")
    pins = canonical_public_keyring_v1(
        public_keyring_raw, hashlib.sha256(public_keyring_raw).hexdigest()
    )
    preflight = require_fresh_zero_preflight_v1(artifacts["zero_preflight"], pin=pins.observer, now=now).value
    manifest = verify_public_artifact_v1(artifacts["manifest"], pin=pins.manifest).value
    publish = verify_public_artifact_v1(artifacts["publish_receipt"], pin=pins.observer).value
    restart = verify_public_artifact_v1(artifacts["restart_authorization"], pin=pins.restart).value
    scm = verify_public_artifact_v1(artifacts["scm_dispatch_evidence"], pin=pins.observer).value
    startup = verify_public_artifact_v1(artifacts["startup_receipt"], pin=pins.observer).value
    attestation = verify_public_artifact_v1(artifacts["attestation"], pin=pins.observer).value
    if manifest.get("restart_authorized") is not False or manifest.get("automatic_restart_allowed") is not False:
        raise OfflineSigningError("SIGNING_CHAIN_MANIFEST_RESTART_FORBIDDEN")
    events: list[dict[str, Any]] = []
    previous: bytes | None = None
    for sequence, event_type, name in (
        (1, "INSTALL_PREPARED", "event_1_prepared"),
        (2, "FILES_PUBLISHED", "event_2_published"),
        (3, "RESTART_DISPATCH_RESERVED", "event_3_reserved"),
        (4, "SERVICE_CONFIG_TRANSITION_VERIFIED", "event_4_transition"),
        (5, "RESTART_DISPATCHED", "event_5_dispatched"),
        (6, "START_OBSERVED", "event_6_started"),
        (7, "FOUNDATION_VERIFIED", "event_7_verified"),
    ):
        event = _event(artifacts[name], sequence=sequence, event_type=event_type, previous_raw=previous)
        events.append(event)
        previous = artifacts[name]
    transition = _strict_object(artifacts["transition_receipt"])
    bindings = (
        (manifest, "preflight_receipt_raw_sha256", artifacts["zero_preflight"]),
        (publish, "install_manifest_raw_sha256", artifacts["manifest"]),
        (publish, "preflight_receipt_raw_sha256", artifacts["zero_preflight"]),
        (restart, "install_manifest_raw_sha256", artifacts["manifest"]),
        (restart, "preflight_receipt_raw_sha256", artifacts["zero_preflight"]),
        (restart, "publish_receipt_raw_sha256", artifacts["publish_receipt"]),
        (events[1], "publish_receipt_raw_sha256", artifacts["publish_receipt"]),
        (events[2], "restart_authorization_raw_sha256", artifacts["restart_authorization"]),
        (transition, "reservation_event_raw_sha256", artifacts["event_3_reserved"]),
        (transition, "restart_authorization_raw_sha256", artifacts["restart_authorization"]),
        (events[3], "service_config_transition_receipt_raw_sha256", artifacts["transition_receipt"]),
        (scm, "service_config_transition_receipt_raw_sha256", artifacts["transition_receipt"]),
        (events[4], "scm_dispatch_evidence_raw_sha256", artifacts["scm_dispatch_evidence"]),
        (startup, "scm_dispatch_evidence_raw_sha256", artifacts["scm_dispatch_evidence"]),
        (startup, "restart_dispatched_event_raw_sha256", artifacts["event_5_dispatched"]),
        (events[5], "startup_receipt_raw_sha256", artifacts["startup_receipt"]),
        (attestation, "startup_receipt_raw_sha256", artifacts["startup_receipt"]),
        (attestation, "start_observed_event_raw_sha256", artifacts["event_6_started"]),
        (events[6], "foundation_attestation_raw_sha256", artifacts["attestation"]),
    )
    for owner, field, raw in bindings:
        if owner.get(field) != _raw_sha(raw):
            raise OfflineSigningError("SIGNING_CHAIN_RAW_BINDING_MISMATCH")
    install_attempt = str(preflight["install_attempt_id"])
    service_name = str(preflight["service_name"])
    for item in (manifest, publish, restart, transition, scm, startup, attestation, *events):
        if item.get("install_attempt_id") != install_attempt or item.get("service_name") != service_name:
            raise OfflineSigningError("SIGNING_CHAIN_IDENTITY_MISMATCH")
    return {
        "schema_version": "windows_rpc_durable_fence_signing_closure_bundle_v1",
        "purpose": "record_verified_offline_windows_fence_signing_closure_without_execution_authority",
        "install_attempt_id": install_attempt,
        "service_name": service_name,
        "chain_order": list(CHAIN_ORDER),
        "artifact_raw_sha256": {name: _raw_sha(artifacts[name]) for name in CHAIN_ORDER},
        "restart_authorized": False,
        "automatic_restart_allowed": False,
        "live_trading_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--public-keyring", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        now = datetime.fromisoformat(options.now_utc.replace("Z", "+00:00"))
        artifacts = {name: (options.inputs_dir / f"{name}.json").read_bytes() for name in CHAIN_ORDER}
        result = verify_signing_closure_chain_v1(
            artifacts, public_keyring_raw=options.public_keyring.read_bytes(), now=now
        )
        raw = write_canonical_create_only_v1(options.output, result)
        write_audit_create_only_v1(options.audit_output, artifact_raw=raw, action="verify-signing-closure")
    except (OfflineSigningError, OSError, ValueError) as exc:
        parser.error(f"offline signing closure failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
