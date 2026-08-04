from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from app.schemas.deployment_drain import (
    DeploymentOnlineRecheckCheckpointDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.deployment_consume_wal import (
    build_consume_intent,
    build_consume_marker,
    canonical_consume_intent_bytes,
    canonical_consume_marker_bytes,
    parse_exact_consume_intent,
    parse_exact_consume_marker,
)
from app.services.deployment_drain import DeploymentDrainService
from app.services import deployment_restart_reconciliation as reconciliation_module
from app.services.deployment_restart_reconciliation import (
    DeploymentRestartReconciliationError,
    build_post_restart_checkpoint,
    build_restart_reconciliation_evidence,
    canonical_post_restart_checkpoint_bytes,
    canonical_restart_reconciliation_bytes,
    derive_post_restart_recheck_identity,
    verify_post_restart_checkpoint,
    verify_restart_reconciliation_evidence,
)
from app.services.deployment_state_commitment import (
    build_state_commitment,
    parse_exact_state_commitment,
)
from test_issue267_deployment_drain_b2b_consume import prepared


AUTHORITY_FIELDS = (
    "consume_authorized",
    "reconciliation_authorized",
    "deployment_authorized",
    "automatic_deploy_allowed",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
)
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _restore_reconciliation_clock():
    original = reconciliation_module._utc_now
    yield
    reconciliation_module._utc_now = original


def _evidence(tmp_path, *, restart_count: int = 1):
    old, commodity, receipt, consumed_online = prepared(tmp_path)
    marker = commodity.consume_deployment_drain(
        consumer_run_id="consumer-c1a-0001",
        operator="test-operator",
    )
    intent_raw = old._consume_intent_path(marker.receipt_id).read_bytes()
    marker_raw = old._consume_marker_path(marker.receipt_id).read_bytes()
    marker = parse_exact_consume_marker(marker_raw, intent_raw=intent_raw)
    receipt_raw = old._receipt_path(marker.receipt_id).read_bytes()
    original_raw = old._checkpoint_path(
        receipt["snapshot"]["checkpoint_sha256"]
    ).read_bytes()
    online_raw = old._online_recheck_path(marker.receipt_id).read_bytes()
    consumed_checkpoint_raw = old._checkpoint_path(
        consumed_online.recheck_checkpoint_raw_sha256
    ).read_bytes()
    consumed_checkpoint = DeploymentOnlineRecheckCheckpointDTO.model_validate_json(
        consumed_checkpoint_raw
    )
    precommit_raw = old._state_commitment_path(
        marker.preconsume_state_generation
    ).read_bytes()

    current = old
    for index in range(restart_count):
        current = DeploymentDrainService(
            old.root,
            runtime_instance_id=f"runtime-c1a-restarted-{index + 1}",
            allow_initial_bootstrap=True,
        )
        current.status()

    chain = []
    for path in sorted(current.state_commitment_dir.iterdir()):
        raw = path.read_bytes()
        artifact = parse_exact_state_commitment(raw)
        if artifact.state_generation >= marker.preconsume_state_generation:
            chain.append(raw)
    reconciliation_run_id = "reconciliation-run-c1a-0001"
    post_recheck_id, post_challenge = derive_post_restart_recheck_identity(
        reconciliation_run_id=reconciliation_run_id,
        receipt_id=marker.receipt_id,
        consume_marker_raw_sha256=hashlib.sha256(marker_raw).hexdigest(),
        current_state_commitment_raw_sha256=hashlib.sha256(chain[-1]).hexdigest(),
        current_runtime_instance_id=current.runtime_instance_id,
        current_execution_epoch=current.execution_epoch,
    )
    rpc = consumed_checkpoint.rpc.model_copy(
        update={
            "recheck_id": post_recheck_id,
            "fresh_challenge": post_challenge,
            "captured_at": datetime.now(timezone.utc),
        }
    )
    captured_at = max(
        rpc.captured_at,
        parse_exact_state_commitment(chain[-1]).created_at,
        marker.committed_at,
    )
    reconciliation_module._utc_now = lambda: captured_at
    arguments = {
        "receipt_raw": receipt_raw,
        "original_checkpoint_raw": original_raw,
        "consumed_recheck_checkpoint_raw": consumed_checkpoint_raw,
        "consume_intent_raw": intent_raw,
        "consume_marker_raw": marker_raw,
        "consumed_online_recheck_raw": online_raw,
        "preconsume_state_commitment_raw": precommit_raw,
        "state_commitment_chain_raw": chain,
        "current_epoch_anchor_raw": current.epoch_anchor_path.read_bytes(),
        "reconciliation_run_id": reconciliation_run_id,
        "current_runtime_instance_id": current.runtime_instance_id,
        "current_execution_epoch": current.execution_epoch,
        "windows_rpc": rpc,
    }
    return arguments, consumed_checkpoint, marker, current


def _build_all(arguments):
    checkpoint = build_post_restart_checkpoint(**arguments)
    checkpoint_raw = canonical_post_restart_checkpoint_bytes(checkpoint)
    chain_arguments = {
        key: value
        for key, value in arguments.items()
        if key
        not in {
            "current_runtime_instance_id",
            "current_execution_epoch",
            "windows_rpc",
            "reconciliation_run_id",
        }
    }
    evidence = build_restart_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw,
        **chain_arguments,
    )
    evidence_raw = canonical_restart_reconciliation_bytes(evidence)
    return checkpoint, checkpoint_raw, evidence, evidence_raw, chain_arguments


def _with_recomputed_execution_hash(
    rpc: DeploymentRpcRecheckFactsDTO, **updates
) -> DeploymentRpcRecheckFactsDTO:
    value = rpc.model_dump(mode="python")
    value.update(updates)
    facts = DeploymentRpcFactsDTO.model_validate(
        {
            "schema_version": "windows_rpc_deployment_safety_snapshot_v1",
            "request_id": value["request_id"],
            "challenge": value["owner_challenge"],
            "server_instance_id": value["server_instance_id"],
            "fact_generation": value["fact_generation"],
            "captured_at": value["captured_at"],
            "execution_admission_frozen": value["execution_admission_frozen"],
            "pending_send_outcomes": value["pending_send_outcomes"],
            "strategy_execution_enabled": value["strategy_execution_enabled"],
            "account_hashes": value["account_hashes"],
            "orders": value["orders"],
            "active_orders": value["active_orders"],
            "trades": value["trades"],
            "positions": value["positions"],
        }
    )
    value["execution_facts_canonical_sha256"] = deployment_rpc_execution_facts_sha256(
        facts
    )
    return DeploymentRpcRecheckFactsDTO.model_validate(value)


def _canonical_artifact(value) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _replace_current_state(arguments, **updates) -> None:
    chain = list(arguments["state_commitment_chain_raw"])
    current = parse_exact_state_commitment(chain[-1])
    state = dict(current.state)
    state.update(updates)
    rebuilt_raw = _canonical_artifact(build_state_commitment(state))
    chain[-1] = rebuilt_raw
    arguments["state_commitment_chain_raw"] = chain
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = hashlib.sha256(rebuilt_raw).hexdigest()
    arguments["current_epoch_anchor_raw"] = (
        json.dumps(
            anchor,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _rewrite_chain_state(arguments, index: int, **updates) -> None:
    chain = list(arguments["state_commitment_chain_raw"])
    for position in range(index, len(chain)):
        commitment = parse_exact_state_commitment(chain[position])
        state = dict(commitment.state)
        if position == index:
            state.update(updates)
        state["previous_state_commitment_raw_sha256"] = hashlib.sha256(
            chain[position - 1]
        ).hexdigest()
        chain[position] = _canonical_artifact(build_state_commitment(state))
    arguments["state_commitment_chain_raw"] = chain
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = hashlib.sha256(chain[-1]).hexdigest()
    arguments["current_epoch_anchor_raw"] = (
        json.dumps(
            anchor,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def test_planned_restart_exact_chain_builds_non_authorizing_evidence(tmp_path) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)

    checkpoint, checkpoint_raw, evidence, evidence_raw, chain_arguments = _build_all(
        arguments
    )

    assert (
        verify_post_restart_checkpoint(
            checkpoint_raw=checkpoint_raw,
            **chain_arguments,
        )
        == checkpoint
    )
    assert (
        verify_restart_reconciliation_evidence(
            evidence_raw=evidence_raw,
            checkpoint_raw=checkpoint_raw,
            **chain_arguments,
        )
        == evidence
    )
    for schema_name, artifact in (
        (
            "web-bridge-deployment-post-restart-checkpoint-v1.schema.json",
            checkpoint,
        ),
        ("web-bridge-safe-restart-reconciliation-v1.schema.json", evidence),
    ):
        schema = json.loads((ROOT / "docs" / "schemas" / schema_name).read_text())
        assert not list(
            Draft202012Validator(schema).iter_errors(artifact.model_dump(mode="json"))
        )
    assert checkpoint.execution_facts_reconciliation_completed is True
    assert checkpoint.reconciliation_completed is False
    assert evidence.reconciliation_completed is False
    assert checkpoint.target_runtime_verified is False
    assert evidence.target_runtime_verified is False
    assert checkpoint.windows_fence_released is False
    assert evidence.windows_fence_released is False
    assert checkpoint.authority_restore_allowed is False
    assert evidence.authority_restore_allowed is False
    for field in AUTHORITY_FIELDS:
        assert getattr(checkpoint, field) is False
        assert getattr(evidence, field) is False


def test_second_restart_can_reconcile_with_new_head_but_not_stale_runtime(
    tmp_path,
) -> None:
    arguments, _consumed_checkpoint, marker, _current = _evidence(
        tmp_path, restart_count=2
    )

    checkpoint = build_post_restart_checkpoint(**arguments)

    assert checkpoint.current_execution_epoch > marker.execution_epoch + 1
    stale = dict(arguments)
    stale["current_runtime_instance_id"] = "runtime-c1a-restarted-1"
    stale["current_execution_epoch"] = marker.execution_epoch + 1
    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**stale)


@pytest.mark.parametrize("replay", ["recheck_id", "fresh_challenge"])
def test_consumed_b1_rpc_identity_cannot_be_replayed(tmp_path, replay) -> None:
    arguments, consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    rpc = arguments["windows_rpc"]
    arguments["windows_rpc"] = rpc.model_copy(
        update={replay: getattr(consumed_checkpoint.rpc, replay)}
    )

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


def test_arbitrary_post_restart_recheck_identity_is_rejected(tmp_path) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    arguments["windows_rpc"] = arguments["windows_rpc"].model_copy(
        update={"recheck_id": f"deployment-recheck-{'e' * 64}"}
    )

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


@pytest.mark.parametrize("mutation", ["server", "pending", "positions"])
def test_windows_fact_drift_is_rejected(tmp_path, mutation) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    rpc = arguments["windows_rpc"]
    if mutation == "server":
        rpc = rpc.model_copy(update={"server_instance_id": "windows-rpc-changed"})
    elif mutation == "pending":
        rpc = rpc.model_copy(update={"pending_send_outcomes": 1})
    else:
        rpc = _with_recomputed_execution_hash(
            rpc,
            positions=[{"direction": "long", "volume": 1, "vt_symbol": "rb2610.SHFE"}],
        )
    arguments["windows_rpc"] = rpc

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


@pytest.mark.parametrize("account_count", [0, 2])
def test_account_hash_cardinality_is_exactly_one(tmp_path, account_count) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    rpc = arguments["windows_rpc"]
    hashes = [] if account_count == 0 else ["a" * 64, "b" * 64]
    arguments["windows_rpc"] = _with_recomputed_execution_hash(
        rpc, account_hashes=hashes
    )

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


def test_pre_restart_rpc_timestamp_cannot_be_wrapped_after_restart(tmp_path) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    current = parse_exact_state_commitment(arguments["state_commitment_chain_raw"][-1])
    arguments["windows_rpc"] = arguments["windows_rpc"].model_copy(
        update={"captured_at": current.created_at - timedelta(microseconds=1)}
    )
    reconciliation_module._utc_now = lambda: current.created_at

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


def test_previous_c1_rpc_cannot_be_replayed_after_another_restart(tmp_path) -> None:
    arguments, _consumed_checkpoint, marker, current = _evidence(tmp_path)
    previous_rpc = arguments["windows_rpc"]
    restarted_again = DeploymentDrainService(
        current.root,
        runtime_instance_id="runtime-c1a-restarted-again",
        allow_initial_bootstrap=True,
    )
    restarted_again.status()
    chain = []
    for path in sorted(restarted_again.state_commitment_dir.iterdir()):
        raw = path.read_bytes()
        if (
            parse_exact_state_commitment(raw).state_generation
            >= marker.preconsume_state_generation
        ):
            chain.append(raw)
    replay = dict(arguments)
    replay.update(
        state_commitment_chain_raw=chain,
        current_epoch_anchor_raw=restarted_again.epoch_anchor_path.read_bytes(),
        current_runtime_instance_id=restarted_again.runtime_instance_id,
        current_execution_epoch=restarted_again.execution_epoch,
        windows_rpc=previous_rpc,
    )
    reconciliation_module._utc_now = lambda: max(
        previous_rpc.captured_at, parse_exact_state_commitment(chain[-1]).created_at
    )

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**replay)


def test_epoch_anchor_must_bind_supplied_chain_head(tmp_path) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = "f" * 64
    arguments["current_epoch_anchor_raw"] = (
        json.dumps(
            anchor,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active_request_sha256", "e" * 64),
        ("expires_at", "2099-01-01T00:00:00+00:00"),
        ("blockers", ["unexpected_reconciliation_blocker"]),
    ],
)
def test_current_restart_state_cannot_drift(tmp_path, field, value) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    _replace_current_state(arguments, **{field: value})

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("state", "RUNNING"),
        ("receipt_consumed", False),
        ("execution_epoch", 1),
    ],
)
def test_illegal_intermediate_transition_cannot_be_hidden_by_valid_head(
    tmp_path, field, value
) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(
        tmp_path, restart_count=2
    )
    _rewrite_chain_state(arguments, 2, **{field: value})

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active_request_sha256", 123),
        ("expires_at", None),
        ("receipt_consumed", 1),
    ],
)
def test_state_v3_python_validator_rejects_schema_invalid_values(
    tmp_path, field, value
) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    _replace_current_state(arguments, **{field: value})

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_state_v3_python_validator_requires_exact_fields(tmp_path, mutation) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    state = dict(
        parse_exact_state_commitment(
            arguments["state_commitment_chain_raw"][-1]
        ).state
    )
    if mutation == "extra":
        state["unexpected"] = False
    else:
        state.pop("freeze_reason")

    with pytest.raises(DeploymentRestartReconciliationError):
        reconciliation_module._require_exact_state_v3(state)


def test_consume_outer_identity_must_match_exact_receipt(tmp_path) -> None:
    arguments, _consumed_checkpoint, marker, _current = _evidence(tmp_path)
    intent = parse_exact_consume_intent(arguments["consume_intent_raw"])
    intent_core = intent.model_dump(mode="python")
    intent_core.pop("consume_intent_id")
    intent_core.pop("consume_intent_core_sha256")
    intent_core["release_plan_core_sha256"] = "e" * 64
    forged_intent = build_consume_intent(intent_core)
    forged_intent_raw = canonical_consume_intent_bytes(forged_intent)
    forged_marker = build_consume_marker(
        forged_intent_raw, committed_at=marker.committed_at
    )
    arguments["consume_intent_raw"] = forged_intent_raw
    arguments["consume_marker_raw"] = canonical_consume_marker_bytes(forged_marker)

    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**arguments)


def test_noncanonical_chain_and_commitment_gap_are_rejected(tmp_path) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    tampered = dict(arguments)
    tampered["consume_marker_raw"] += b" "
    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**tampered)

    assert len(arguments["state_commitment_chain_raw"]) >= 3
    gap = dict(arguments)
    gap["state_commitment_chain_raw"] = [
        arguments["state_commitment_chain_raw"][0],
        arguments["state_commitment_chain_raw"][-1],
    ]
    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**gap)


def test_clock_rollback_and_stale_windows_capture_are_rejected(tmp_path) -> None:
    arguments, _consumed_checkpoint, marker, _current = _evidence(tmp_path)
    current = parse_exact_state_commitment(arguments["state_commitment_chain_raw"][-1])
    rollback = dict(arguments)
    reconciliation_module._utc_now = lambda: min(
        current.created_at, marker.committed_at
    ) - timedelta(microseconds=1)
    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**rollback)

    stale = dict(arguments)
    rpc: DeploymentRpcRecheckFactsDTO = stale["windows_rpc"]
    reconciliation_module._utc_now = lambda: rpc.captured_at + timedelta(
        seconds=30, microseconds=1
    )
    with pytest.raises(DeploymentRestartReconciliationError):
        build_post_restart_checkpoint(**stale)


def test_exact_evidence_tamper_is_rejected(tmp_path) -> None:
    arguments, _consumed_checkpoint, _marker, _current = _evidence(tmp_path)
    (
        _checkpoint,
        checkpoint_raw,
        _built_evidence,
        evidence_raw,
        chain_arguments,
    ) = _build_all(arguments)

    with pytest.raises(DeploymentRestartReconciliationError):
        verify_restart_reconciliation_evidence(
            evidence_raw=evidence_raw + b"\n",
            checkpoint_raw=checkpoint_raw,
            **chain_arguments,
        )
