from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.services.deployment_consume_wal import (
    DeploymentConsumeWalError,
    build_consume_intent,
    build_consume_marker,
    canonical_consume_intent_bytes,
    canonical_consume_marker_bytes,
    parse_exact_consume_intent,
    parse_exact_consume_marker,
)


NOW = datetime(2026, 8, 4, tzinfo=timezone.utc)


def sha(char: str) -> str:
    return char * 64


def intent_core(*, receipt: str = "1") -> dict[str, object]:
    core: dict[str, object] = {
        "schema_version": "web_bridge_safe_restart_consume_intent_v1",
        "purpose": "prepare_one_shot_safe_restart_consumption",
        "receipt_id": f"safe-restart-{sha(receipt)}",
        "receipt_raw_sha256": sha("2"),
        "receipt_core_sha256": sha("3"),
        "online_recheck_id": f"safe-restart-online-recheck-{sha('4')}",
        "online_recheck_raw_sha256": sha("5"),
        "online_recheck_core_sha256": sha("6"),
        "preconsume_state_commitment_id": (
            f"deployment-drain-state-commitment-{sha('7')}"
        ),
        "preconsume_state_commitment_raw_sha256": sha("8"),
        "preconsume_state_generation": 7,
        "consume_state_projection": {
            "schema_version": (
                "web_bridge_safe_restart_consume_state_projection_v1"
            ),
            "state": "SAFE_TO_RESTART",
            "receipt_consumed": True,
            "receipt_id": f"safe-restart-{sha(receipt)}",
            "receipt_raw_sha256": sha("2"),
            "online_recheck_id": f"safe-restart-online-recheck-{sha('4')}",
            "online_recheck_raw_sha256": sha("5"),
            "preconsume_state_commitment_raw_sha256": sha("8"),
            "preconsume_state_generation": 7,
            "runtime_instance_id": "runtime-12345678",
            "drain_epoch": 2,
            "execution_epoch": 3,
            "consumer_run_id": "consumer-12345678",
            "operator": "test-operator",
            "planned_consumed_at": "2026-08-04T00:00:01Z",
            "consume_authorized": False,
            "reconciliation_authorized": False,
            "deployment_authorized": False,
            "automatic_deploy_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        "consume_state_projection_sha256": "PLACEHOLDER",
        "request_id": "request-12345678",
        "runtime_instance_id": "runtime-12345678",
        "deployment_attempt_id": "attempt-12345678",
        "release_plan_core_sha256": sha("a"),
        "restart_action_sha256": sha("b"),
        "drain_epoch": 2,
        "execution_epoch": 3,
        "prepared_at": NOW,
        "consume_not_after": NOW + timedelta(seconds=30),
        "consumer_run_id": "consumer-12345678",
        "operator": "test-operator",
        "consume_intent_prepared": True,
        "one_shot_consume_committed": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    core["consume_state_projection_sha256"] = hashlib.sha256(
        json.dumps(
            core["consume_state_projection"],
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return core


def test_build_and_parse_canonical_wal_with_exact_intent_binding() -> None:
    intent = build_consume_intent(intent_core())
    intent_raw = canonical_consume_intent_bytes(intent)
    marker = build_consume_marker(
        intent_raw,
        committed_at=NOW + timedelta(seconds=1),
    )
    marker_raw = canonical_consume_marker_bytes(marker)

    assert intent_raw.endswith(b"\n")
    assert marker_raw.endswith(b"\n")
    assert parse_exact_consume_intent(intent_raw) == intent
    assert parse_exact_consume_marker(marker_raw, intent_raw=intent_raw) == marker
    assert marker.consume_intent_raw_sha256 == hashlib.sha256(
        intent_raw
    ).hexdigest()
    assert marker.one_shot_consume_committed is True
    assert marker.restart_execution_started is False
    for field in (
        "consume_authorized",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        assert getattr(intent, field) is False
        assert getattr(marker, field) is False


def test_exact_parsers_reject_noncanonical_and_identity_tampering() -> None:
    intent = build_consume_intent(intent_core())
    intent_raw = canonical_consume_intent_bytes(intent)
    marker = build_consume_marker(
        intent_raw,
        committed_at=NOW + timedelta(seconds=1),
    )
    marker_raw = canonical_consume_marker_bytes(marker)

    with pytest.raises(DeploymentConsumeWalError, match="not canonical"):
        parse_exact_consume_intent(intent_raw[:-1] + b"  \n")

    tampered = json.loads(intent_raw)
    tampered["receipt_raw_sha256"] = sha("c")
    tampered_raw = (
        json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )
    with pytest.raises(DeploymentConsumeWalError, match="invalid"):
        parse_exact_consume_intent(tampered_raw)

    marker_tampered = json.loads(marker_raw)
    marker_tampered["consume_marker_id"] = (
        f"safe-restart-consume-marker-{sha('d')}"
    )
    marker_tampered_raw = (
        json.dumps(marker_tampered, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )
    with pytest.raises(DeploymentConsumeWalError, match="invalid"):
        parse_exact_consume_marker(
            marker_tampered_raw,
            intent_raw=intent_raw,
        )


def test_marker_rejects_other_intent_and_time_before_prepare() -> None:
    intent = build_consume_intent(intent_core())
    intent_raw = canonical_consume_intent_bytes(intent)
    marker_raw = canonical_consume_marker_bytes(
        build_consume_marker(
            intent_raw,
            committed_at=NOW + timedelta(seconds=1),
        )
    )
    other_raw = canonical_consume_intent_bytes(
        build_consume_intent(intent_core(receipt="c"))
    )

    with pytest.raises(DeploymentConsumeWalError, match="exact consume intent"):
        parse_exact_consume_marker(marker_raw, intent_raw=other_raw)
    with pytest.raises(DeploymentConsumeWalError, match="cannot precede"):
        build_consume_marker(
            intent_raw,
            committed_at=NOW - timedelta(microseconds=1),
        )

    circular = intent_core()
    circular["consume_state_projection"] = {
        "consume_marker_raw_sha256": None
    }
    circular["consume_state_projection_sha256"] = hashlib.sha256(
        b'{"consume_marker_raw_sha256":null}'
    ).hexdigest()
    with pytest.raises(DeploymentConsumeWalError, match="invalid"):
        build_consume_intent(circular)
