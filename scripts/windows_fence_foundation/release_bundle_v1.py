"""Build a create-only, offline Windows-fence signing closure bundle.

This is a verifier/bundler only.  It neither signs nor invokes Windows, M2,
RPC, SCM, containers, or any order path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from .contracts import parse_frozen_none_state
from .installer_trust_anchor_v1 import canonical_public_keyring_v1
from .offline_signing_v1 import (
    OfflineSigningError,
    _strict_object,
    require_fresh_zero_preflight_v1,
    verify_public_artifact_v1,
    write_audit_create_only_v1,
    write_canonical_create_only_v1,
)

CHAIN_ORDER = (
    "preflight_challenge_reservation",
    "preflight_replay_guard_reservation",
    "zero_preflight",
    "manifest_attempt_nonce_reservation",
    "manifest_install_attempt_reservation",
    "manifest",
    "fence_state",
    "event_1_prepared",
    "publish_receipt",
    "event_2_published",
    "restart_dispatch_reservation",
    "restart_authorization_reservation",
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

_RESERVATION_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "schemas"
    / "windows-rpc-durable-fence-signing-reservation-receipt-v1.schema.json"
)


def _raw_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineSigningError("SIGNING_CHAIN_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OfflineSigningError("SIGNING_CHAIN_TIME_INVALID")
    return parsed


def _event(
    raw: bytes,
    *,
    sequence: int,
    event_type: str,
    previous_raw: bytes | None,
    previous_id: str | None,
) -> dict[str, Any]:
    value = _strict_object(raw)
    if (
        value.get("schema_version") != "windows_rpc_durable_fence_install_event_v1"
        or value.get("event_sequence") != sequence
        or value.get("event_type") != event_type
        or value.get("event_core_sha256")
        != hashlib.sha256(
            __import__(
                "scripts.windows_fence_foundation.contracts",
                fromlist=["canonical_json_bytes"],
            ).canonical_json_bytes(
                {
                    key: item
                    for key, item in value.items()
                    if key not in {"event_id", "event_core_sha256"}
                }
            )
        ).hexdigest()
        or value.get("event_id")
        != "windows-fence-install-event-" + value["event_core_sha256"]
        or value.get("previous_event_raw_sha256")
        != (None if previous_raw is None else _raw_sha(previous_raw))
        or value.get("previous_event_id") != previous_id
    ):
        raise OfflineSigningError("SIGNING_CHAIN_EVENT_INVALID")
    return value


def _verify_reservation(
    raw: bytes,
    *,
    reservation_kind: str,
    token_sha256: str,
    artifact: Mapping[str, Any],
) -> None:
    """Verify the exact raw create-only ledger receipt for one signed draft."""
    value = _strict_object(raw)
    try:
        Draft202012Validator(
            json.loads(_RESERVATION_SCHEMA.read_text(encoding="utf-8"))
        ).validate(value)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise OfflineSigningError("SIGNING_CHAIN_RESERVATION_SCHEMA_INVALID") from exc
    core_fields = {
        "windows_rpc_durable_fence_zero_order_preflight_v1": (
            "receipt_id",
            "receipt_core_sha256",
        ),
        "windows_rpc_durable_fence_install_manifest_v1": (
            "manifest_id",
            "manifest_core_sha256",
        ),
        "windows_rpc_durable_fence_restart_authorization_v1": (
            "authorization_id",
            "authorization_core_sha256",
        ),
    }
    try:
        id_field, core_field = core_fields[str(artifact["schema_version"])]
        expected = {
            "reservation_kind": reservation_kind,
            "token_sha256": token_sha256,
            "reserved_artifact_schema_version": artifact["schema_version"],
            "reserved_artifact_id": artifact[id_field],
            "reserved_artifact_core_sha256": artifact[core_field],
            "reserved_signature_domain_separator": artifact[
                "signature_domain_separator"
            ],
        }
    except (KeyError, TypeError) as exc:
        raise OfflineSigningError("SIGNING_CHAIN_RESERVATION_ARTIFACT_INVALID") from exc
    if any(
        value.get(key) != expected_value for key, expected_value in expected.items()
    ):
        raise OfflineSigningError("SIGNING_CHAIN_RESERVATION_BINDING_MISMATCH")


def verify_signing_closure_chain_v1(
    artifacts: Mapping[str, bytes], *, public_keyring_raw: bytes, now: datetime
) -> dict[str, Any]:
    """Verify the exact signed/unsigned artifact order and all raw-byte joins."""
    if set(artifacts) != set(CHAIN_ORDER):
        raise OfflineSigningError("SIGNING_CHAIN_ARTIFACT_SET_INVALID")
    pins = canonical_public_keyring_v1(
        public_keyring_raw, hashlib.sha256(public_keyring_raw).hexdigest()
    )
    preflight = require_fresh_zero_preflight_v1(
        artifacts["zero_preflight"], pin=pins.observer, now=now
    ).value
    manifest = verify_public_artifact_v1(artifacts["manifest"], pin=pins.manifest).value
    publish = verify_public_artifact_v1(
        artifacts["publish_receipt"], pin=pins.observer
    ).value
    restart = verify_public_artifact_v1(
        artifacts["restart_authorization"], pin=pins.restart
    ).value
    scm = verify_public_artifact_v1(
        artifacts["scm_dispatch_evidence"], pin=pins.observer
    ).value
    startup = verify_public_artifact_v1(
        artifacts["startup_receipt"], pin=pins.observer
    ).value
    attestation = verify_public_artifact_v1(
        artifacts["attestation"], pin=pins.observer
    ).value
    _verify_reservation(
        artifacts["preflight_challenge_reservation"],
        reservation_kind="preflight_challenge",
        token_sha256=str(preflight["challenge_nonce_sha256"]),
        artifact=preflight,
    )
    _verify_reservation(
        artifacts["preflight_replay_guard_reservation"],
        reservation_kind="preflight_replay_guard",
        token_sha256=hashlib.sha256(
            str(preflight["replay_guard_id"]).encode()
        ).hexdigest(),
        artifact=preflight,
    )
    _verify_reservation(
        artifacts["manifest_attempt_nonce_reservation"],
        reservation_kind="manifest_attempt_nonce",
        token_sha256=str(manifest["attempt_nonce_sha256"]),
        artifact=manifest,
    )
    _verify_reservation(
        artifacts["manifest_install_attempt_reservation"],
        reservation_kind="manifest_install_attempt",
        token_sha256=hashlib.sha256(
            str(manifest["install_attempt_id"]).encode()
        ).hexdigest(),
        artifact=manifest,
    )
    _verify_reservation(
        artifacts["restart_dispatch_reservation"],
        reservation_kind="restart_dispatch",
        token_sha256=str(restart["dispatch_nonce_sha256"]),
        artifact=restart,
    )
    _verify_reservation(
        artifacts["restart_authorization_reservation"],
        reservation_kind="restart_authorization",
        token_sha256=hashlib.sha256(
            str(restart["authorization_id"]).encode()
        ).hexdigest(),
        artifact=restart,
    )
    if (
        manifest.get("restart_authorized") is not False
        or manifest.get("automatic_restart_allowed") is not False
    ):
        raise OfflineSigningError("SIGNING_CHAIN_MANIFEST_RESTART_FORBIDDEN")
    state = parse_frozen_none_state(artifacts["fence_state"])
    if state["install_manifest_raw_sha256"] != _raw_sha(artifacts["manifest"]) or state[
        "preflight_receipt_raw_sha256"
    ] != _raw_sha(artifacts["zero_preflight"]):
        raise OfflineSigningError("SIGNING_CHAIN_FROZEN_STATE_BINDING_MISMATCH")
    events: list[dict[str, Any]] = []
    previous: bytes | None = None
    previous_id: str | None = None
    for sequence, event_type, name in (
        (1, "INSTALL_PREPARED", "event_1_prepared"),
        (2, "FILES_PUBLISHED", "event_2_published"),
        (3, "RESTART_DISPATCH_RESERVED", "event_3_reserved"),
        (4, "SERVICE_CONFIG_TRANSITION_VERIFIED", "event_4_transition"),
        (5, "RESTART_DISPATCHED", "event_5_dispatched"),
        (6, "START_OBSERVED", "event_6_started"),
        (7, "FOUNDATION_VERIFIED", "event_7_verified"),
    ):
        event = _event(
            artifacts[name],
            sequence=sequence,
            event_type=event_type,
            previous_raw=previous,
            previous_id=previous_id,
        )
        events.append(event)
        previous = artifacts[name]
        previous_id = str(event["event_id"])
    transition = _strict_object(artifacts["transition_receipt"])
    now_utc = now
    if (
        restart.get("restart_authorized") is not True
        or restart.get("automatic_restart_allowed") is not False
        or restart.get("maximum_restart_dispatches") != 1
        or restart.get("dispatch_consumption_required") is not True
        or not _utc(restart["not_before_utc"])
        <= now_utc
        < _utc(restart["expires_at_utc"])
        or restart.get("install_event_head_raw_sha256")
        != _raw_sha(artifacts["event_2_published"])
        or restart.get("service_control_operation_id")
        != events[2].get("service_control_operation_id")
        or restart.get("dispatch_nonce_sha256")
        != events[2].get("restart_dispatch_nonce_sha256")
    ):
        raise OfflineSigningError("SIGNING_CHAIN_RESTART_AUTHORIZATION_INVALID")
    nonce = restart["dispatch_nonce_sha256"]
    operation = restart["service_control_operation_id"]
    for item in (
        events[2],
        transition,
        scm,
        events[3],
        events[4],
        startup,
        events[5],
        attestation,
        events[6],
    ):
        if (
            item.get("restart_dispatch_nonce_sha256") != nonce
            or item.get("service_control_operation_id") != operation
        ):
            raise OfflineSigningError("SIGNING_CHAIN_RESTART_DISPATCH_BINDING_MISMATCH")
    bindings = (
        (manifest, "preflight_receipt_raw_sha256", artifacts["zero_preflight"]),
        (publish, "install_manifest_raw_sha256", artifacts["manifest"]),
        (publish, "preflight_receipt_raw_sha256", artifacts["zero_preflight"]),
        (restart, "install_manifest_raw_sha256", artifacts["manifest"]),
        (restart, "preflight_receipt_raw_sha256", artifacts["zero_preflight"]),
        (restart, "publish_receipt_raw_sha256", artifacts["publish_receipt"]),
        (events[1], "publish_receipt_raw_sha256", artifacts["publish_receipt"]),
        (
            events[2],
            "restart_authorization_raw_sha256",
            artifacts["restart_authorization"],
        ),
        (transition, "reservation_event_raw_sha256", artifacts["event_3_reserved"]),
        (
            transition,
            "restart_authorization_raw_sha256",
            artifacts["restart_authorization"],
        ),
        (
            events[3],
            "service_config_transition_receipt_raw_sha256",
            artifacts["transition_receipt"],
        ),
        (
            scm,
            "service_config_transition_receipt_raw_sha256",
            artifacts["transition_receipt"],
        ),
        (
            events[4],
            "scm_dispatch_evidence_raw_sha256",
            artifacts["scm_dispatch_evidence"],
        ),
        (
            startup,
            "scm_dispatch_evidence_raw_sha256",
            artifacts["scm_dispatch_evidence"],
        ),
        (
            startup,
            "restart_dispatched_event_raw_sha256",
            artifacts["event_5_dispatched"],
        ),
        (events[5], "startup_receipt_raw_sha256", artifacts["startup_receipt"]),
        (attestation, "startup_receipt_raw_sha256", artifacts["startup_receipt"]),
        (attestation, "start_observed_event_raw_sha256", artifacts["event_6_started"]),
        (events[6], "foundation_attestation_raw_sha256", artifacts["attestation"]),
    )
    for owner, field, raw in bindings:
        if owner.get(field) != _raw_sha(raw):
            raise OfflineSigningError("SIGNING_CHAIN_RAW_BINDING_MISMATCH")
    for event in events:
        if (
            event.get("install_manifest_raw_sha256") != _raw_sha(artifacts["manifest"])
            or event.get("preflight_receipt_raw_sha256")
            != _raw_sha(artifacts["zero_preflight"])
            or event.get("fence_state_raw_sha256") != _raw_sha(artifacts["fence_state"])
            or event.get("admission_state") != "FROZEN"
            or event.get("token_state") != "NONE"
            or event.get("staged_token") is not None
            or event.get("active_token") is not None
            or event.get("authority_grant") is not None
        ):
            raise OfflineSigningError("SIGNING_CHAIN_EVENT_FROZEN_BINDING_MISMATCH")
    # Static subset of the frozen architecture contract's temporal rules.
    ordered_times = (
        _utc(publish["sealed_at_utc"]),
        _utc(restart["issued_at_utc"]),
        _utc(restart["not_before_utc"]),
        _utc(events[2]["observed_at_utc"]),
        _utc(transition["applied_at_utc"]),
        _utc(transition["readback_at_utc"]),
        _utc(events[3]["observed_at_utc"]),
        _utc(scm["trace_challenge_issued_at_utc"]),
        _utc(scm["stop_call_started_at_utc"]),
        _utc(scm["stop_call_returned_at_utc"]),
        _utc(scm["start_call_started_at_utc"]),
        _utc(startup["service_process_started_at_utc"]),
        _utc(scm["start_call_returned_at_utc"]),
        _utc(scm["trace_captured_at_utc"]),
        _utc(events[4]["observed_at_utc"]),
        _utc(restart["expires_at_utc"]),
    )
    if any(left > right for left, right in pairwise(ordered_times)):
        raise OfflineSigningError("SIGNING_CHAIN_TIME_ORDER_INVALID")
    install_attempt = str(preflight["install_attempt_id"])
    service_name = str(preflight["service_name"])
    for item in (
        manifest,
        publish,
        restart,
        transition,
        scm,
        startup,
        attestation,
        *events,
    ):
        if (
            item.get("install_attempt_id") != install_attempt
            or item.get("service_name") != service_name
        ):
            raise OfflineSigningError("SIGNING_CHAIN_IDENTITY_MISMATCH")
    return {
        "schema_version": "windows_rpc_durable_fence_signing_closure_bundle_v1",
        "purpose": "record_verified_offline_windows_fence_signing_closure_without_execution_authority",
        "install_attempt_id": install_attempt,
        "service_name": service_name,
        "chain_order": list(CHAIN_ORDER),
        "artifact_raw_sha256": {
            name: _raw_sha(artifacts[name]) for name in CHAIN_ORDER
        },
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
        artifacts = {
            name: (options.inputs_dir / f"{name}.json").read_bytes()
            for name in CHAIN_ORDER
        }
        result = verify_signing_closure_chain_v1(
            artifacts, public_keyring_raw=options.public_keyring.read_bytes(), now=now
        )
        raw = write_canonical_create_only_v1(options.output, result)
        write_audit_create_only_v1(
            options.audit_output, artifact_raw=raw, action="verify-signing-closure"
        )
    except (OfflineSigningError, OSError, ValueError) as exc:
        parser.error(f"offline signing closure failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
