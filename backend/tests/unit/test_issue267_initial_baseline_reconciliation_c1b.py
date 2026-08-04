from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from app.schemas.deployment_drain import (
    CommodityInitialBaselineStateDTO,
    DeploymentInitialBaselineCommodityCheckpointDTO,
    DeploymentInitialBaselineDrainStateDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services import deployment_initial_baseline_reconciliation as baseline_module
from app.services.deployment_drain import DeploymentDrainService
from app.services.deployment_initial_baseline_reconciliation import (
    DeploymentInitialBaselineError,
    build_initial_baseline_checkpoint,
    build_initial_baseline_commodity_checkpoint,
    build_initial_baseline_reconciliation_evidence,
    canonical_initial_baseline_checkpoint_bytes,
    canonical_initial_baseline_commodity_checkpoint_bytes,
    canonical_initial_baseline_evidence_bytes,
    derive_initial_baseline_rpc_identity,
    verify_initial_baseline_checkpoint,
    verify_initial_baseline_reconciliation_evidence,
)
from app.services.deployment_state_commitment import (
    build_state_commitment,
    parse_exact_state_commitment,
)


ACCOUNT_HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[3]
AUTHORITY_FIELDS = (
    "consume_authorized",
    "reconciliation_authorized",
    "deployment_authorized",
    "automatic_deploy_allowed",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 4, 14, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture(autouse=True)
def _restore_clock():
    original = baseline_module._utc_now
    yield
    baseline_module._utc_now = original


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _artifact_bytes(value) -> bytes:
    return _canonical_bytes(value.model_dump(mode="json")) + b"\n"


def _fixture(tmp_path: Path, *, restart_count: int = 1):
    clock = Clock()
    root = tmp_path / "fresh-baseline"
    bootstrap = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="bootstrap-frozen-runtime",
        allow_initial_bootstrap=True,
        initial_bootstrap_state="RESTARTED_FROZEN",
        require_fresh_bootstrap=True,
    )
    bootstrap.status()
    current = bootstrap
    for index in range(restart_count):
        current = DeploymentDrainService(
            root,
            clock=clock,
            runtime_instance_id=f"runtime-initial-baseline-{index + 1}",
            allow_initial_bootstrap=True,
        )
        current.status()
    chain = [path.read_bytes() for path in sorted(current.state_commitment_dir.iterdir())]
    genesis_raw = chain[0]
    run_id = "initial-baseline-run-0001"
    request_id, owner_challenge, recheck_id, fresh_challenge = (
        derive_initial_baseline_rpc_identity(
            reconciliation_run_id=run_id,
            genesis_commitment_raw_sha256=hashlib.sha256(genesis_raw).hexdigest(),
            current_state_commitment_raw_sha256=hashlib.sha256(chain[-1]).hexdigest(),
            current_runtime_instance_id=current.runtime_instance_id,
            current_execution_epoch=current.execution_epoch,
            expected_account_hash=ACCOUNT_HASH,
        )
    )
    orders = [{"status": "all_traded", "vt_orderid": "SIM.1"}]
    trades = [{"volume": 1, "vt_tradeid": "SIM.T1"}]
    positions = [{"direction": "long", "volume": 1, "vt_symbol": "rb2610.SHFE"}]
    initial = DeploymentRpcFactsDTO(
        schema_version="windows_rpc_deployment_safety_snapshot_v1",
        request_id=request_id,
        challenge=owner_challenge,
        server_instance_id="windows-rpc-baseline-0001",
        fact_generation=7,
        captured_at=clock(),
        execution_admission_frozen=True,
        pending_send_outcomes=0,
        strategy_execution_enabled=False,
        account_hashes=[ACCOUNT_HASH],
        orders=orders,
        active_orders=[],
        trades=trades,
        positions=positions,
    )
    execution_sha = deployment_rpc_execution_facts_sha256(initial)
    fresh = DeploymentRpcRecheckFactsDTO(
        schema_version="windows_rpc_deployment_safety_recheck_v1",
        request_id=request_id,
        owner_challenge=owner_challenge,
        recheck_id=recheck_id,
        fresh_challenge=fresh_challenge,
        original_server_instance_id=initial.server_instance_id,
        original_fact_generation=initial.fact_generation,
        original_execution_facts_canonical_sha256=execution_sha,
        server_instance_id=initial.server_instance_id,
        fact_generation=initial.fact_generation,
        execution_facts_canonical_sha256=execution_sha,
        captured_at=clock(),
        execution_admission_frozen=True,
        pending_send_outcomes=0,
        strategy_execution_enabled=False,
        account_hashes=[ACCOUNT_HASH],
        orders=orders,
        active_orders=[],
        trades=trades,
        positions=positions,
    )
    baseline_module._utc_now = clock
    commodity_checkpoint = build_initial_baseline_commodity_checkpoint(
        reconciliation_run_id=run_id,
        genesis_commitment_raw_sha256=hashlib.sha256(genesis_raw).hexdigest(),
        current_state_commitment_raw_sha256=hashlib.sha256(chain[-1]).hexdigest(),
        current_runtime_instance_id=current.runtime_instance_id,
        current_execution_epoch=current.execution_epoch,
        expected_account_hash=ACCOUNT_HASH,
        commodity_state={
            "schema_version": "web_bridge_initial_baseline_commodity_state_v1",
            "commodity_state_version": "commodity-simnow-v1",
            "commodity_state_checkpoint_sha256": "b" * 64,
            "execution_plan_status": "IDLE",
            "execution_plan_hash": None,
            "plan_version": 0,
            "web_trade_enabled": False,
            "execution_authority_revoked": True,
            "auto_dispatch_stopped": True,
            "unknown_outcome": False,
            "reconcile_required": False,
            "rpc_generation": initial.fact_generation,
            "active_orders_snapshot_sha256": hashlib.sha256(
                _canonical_bytes(initial.active_orders)
            ).hexdigest(),
            "positions_snapshot_sha256": hashlib.sha256(
                _canonical_bytes(initial.positions)
            ).hexdigest(),
        },
        initial_rpc=initial,
    )
    commodity_checkpoint_raw = canonical_initial_baseline_commodity_checkpoint_bytes(
        commodity_checkpoint
    )
    arguments = {
        "genesis_state_commitment_raw": genesis_raw,
        "state_commitment_chain_raw": chain,
        "current_epoch_anchor_raw": current.epoch_anchor_path.read_bytes(),
        "reconciliation_run_id": run_id,
        "current_runtime_instance_id": current.runtime_instance_id,
        "current_execution_epoch": current.execution_epoch,
        "expected_account_hash": ACCOUNT_HASH,
        "commodity_checkpoint_raw": commodity_checkpoint_raw,
        "fresh_rpc": fresh,
    }
    return arguments, current, clock


def _replace_commodity_checkpoint(
    arguments, *, initial_rpc=None, commodity_state=None, captured_at=None
) -> None:
    old = DeploymentInitialBaselineCommodityCheckpointDTO.model_validate_json(
        arguments["commodity_checkpoint_raw"]
    )
    rebuilt = baseline_module._build_initial_baseline_commodity_checkpoint(
        reconciliation_run_id=old.reconciliation_run_id,
        genesis_commitment_raw_sha256=old.genesis_commitment_raw_sha256,
        current_state_commitment_raw_sha256=(
            old.current_state_commitment_raw_sha256
        ),
        current_runtime_instance_id=old.current_runtime_instance_id,
        current_execution_epoch=old.current_execution_epoch,
        expected_account_hash=old.initial_rpc.account_hashes[0],
        commodity_state=commodity_state or old.state,
        initial_rpc=initial_rpc or old.initial_rpc,
        captured_at=captured_at or old.captured_at,
    )
    arguments["commodity_checkpoint_raw"] = (
        canonical_initial_baseline_commodity_checkpoint_bytes(rebuilt)
    )


def _build_all(arguments):
    checkpoint = build_initial_baseline_checkpoint(**arguments)
    checkpoint_raw = canonical_initial_baseline_checkpoint_bytes(checkpoint)
    evidence = build_initial_baseline_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw, **arguments
    )
    evidence_raw = canonical_initial_baseline_evidence_bytes(evidence)
    return checkpoint, checkpoint_raw, evidence, evidence_raw


def _rebuild_chain(arguments, index: int, **updates) -> None:
    chain = list(arguments["state_commitment_chain_raw"])
    for position in range(index, len(chain)):
        old = parse_exact_state_commitment(chain[position])
        state = dict(old.state)
        if position == index:
            state.update(updates)
        if position:
            state["previous_state_commitment_raw_sha256"] = hashlib.sha256(
                chain[position - 1]
            ).hexdigest()
        kwargs = {}
        if position == 0:
            kwargs = {
                "genesis_source": old.genesis_source,
                "source_state_raw_sha256": old.source_state_raw_sha256,
                "source_epoch_anchor_raw_sha256": (
                    old.source_epoch_anchor_raw_sha256
                ),
            }
        chain[position] = _artifact_bytes(build_state_commitment(state, **kwargs))
    arguments["state_commitment_chain_raw"] = chain
    arguments["genesis_state_commitment_raw"] = chain[0]
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = hashlib.sha256(chain[-1]).hexdigest()
    arguments["current_epoch_anchor_raw"] = _canonical_bytes(anchor) + b"\n"


def test_fresh_initial_baseline_builds_two_capture_non_authorizing_evidence(
    tmp_path,
) -> None:
    arguments, _current, _clock = _fixture(tmp_path)

    checkpoint, checkpoint_raw, evidence, evidence_raw = _build_all(arguments)

    assert verify_initial_baseline_checkpoint(
        checkpoint_raw=checkpoint_raw, **arguments
    ) == checkpoint
    assert verify_initial_baseline_reconciliation_evidence(
        evidence_raw=evidence_raw,
        checkpoint_raw=checkpoint_raw,
        **arguments,
    ) == evidence
    assert checkpoint.initial_execution_facts_baseline_recorded is True
    assert checkpoint.execution_facts_reconciliation_completed is True
    assert checkpoint.semantic_safety_unchanged is False
    assert checkpoint.custody_inventory_verified is False
    assert evidence.reconciliation_completed is False
    for schema_name, artifact in (
        (
            "web-bridge-deployment-initial-baseline-checkpoint-v1.schema.json",
            checkpoint,
        ),
        ("web-bridge-initial-baseline-reconciliation-v1.schema.json", evidence),
    ):
        schema = json.loads((ROOT / "docs" / "schemas" / schema_name).read_text())
        assert set(schema["properties"]) == set(type(artifact).model_fields)
        assert not list(
            Draft202012Validator(schema).iter_errors(artifact.model_dump(mode="json"))
        )
    checkpoint_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-deployment-initial-baseline-checkpoint-v1.schema.json"
        ).read_text()
    )
    assert set(checkpoint_schema["$defs"]["drainState"]["properties"]) == set(
        DeploymentInitialBaselineDrainStateDTO.model_fields
    )
    commodity_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-deployment-initial-baseline-commodity-checkpoint-v1.schema.json"
        ).read_text()
    )
    assert set(commodity_schema["properties"]) == set(
        DeploymentInitialBaselineCommodityCheckpointDTO.model_fields
    )
    assert set(commodity_schema["$defs"]["commodityState"]["properties"]) == set(
        CommodityInitialBaselineStateDTO.model_fields
    )
    assert not list(
        Draft202012Validator(commodity_schema).iter_errors(
            checkpoint.commodity_checkpoint.model_dump(mode="json")
        )
    )
    for field in AUTHORITY_FIELDS:
        assert getattr(checkpoint, field) is False
        assert getattr(evidence, field) is False


def test_multiple_clean_frozen_restarts_use_only_latest_head(tmp_path) -> None:
    arguments, current, _clock = _fixture(tmp_path, restart_count=3)

    checkpoint = build_initial_baseline_checkpoint(**arguments)

    assert checkpoint.current_execution_epoch == 4
    stale = dict(arguments)
    stale["current_runtime_instance_id"] = "runtime-initial-baseline-2"
    stale["current_execution_epoch"] = 3
    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**stale)
    assert checkpoint.current_runtime_instance_id == current.runtime_instance_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("state", "RUNNING"),
        ("receipt_consumed", True),
        ("freeze_reason", "state_materialization_recovered_from_commitment"),
        ("drain_epoch", 1),
    ],
)
def test_illegal_intermediate_state_cannot_be_hidden_by_rechained_head(
    tmp_path, field, value
) -> None:
    arguments, _current, _clock = _fixture(tmp_path, restart_count=2)
    _rebuild_chain(arguments, 2, **{field: value})

    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**arguments)


def test_bootstrap_only_chain_and_stale_anchor_are_rejected(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    only_bootstrap = dict(arguments)
    only_bootstrap["state_commitment_chain_raw"] = arguments[
        "state_commitment_chain_raw"
    ][:2]
    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**only_bootstrap)

    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = "d" * 64
    arguments["current_epoch_anchor_raw"] = _canonical_bytes(anchor) + b"\n"
    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**arguments)


def test_migration_genesis_cannot_be_used_as_fresh_baseline(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    genesis = parse_exact_state_commitment(
        arguments["state_commitment_chain_raw"][0]
    )
    state = dict(genesis.state)
    migrated = build_state_commitment(
        state,
        genesis_source="v2_migration",
        source_state_raw_sha256="d" * 64,
        source_epoch_anchor_raw_sha256="e" * 64,
    )
    arguments["state_commitment_chain_raw"][0] = _artifact_bytes(migrated)
    _rebuild_chain(arguments, 1)

    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**arguments)


@pytest.mark.parametrize("mutation", ["expected_account", "zero", "two"])
def test_account_scope_must_match_trusted_expected_hash(tmp_path, mutation) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    with pytest.raises(DeploymentInitialBaselineError):
        if mutation == "expected_account":
            arguments["expected_account_hash"] = "b" * 64
        else:
            old = DeploymentInitialBaselineCommodityCheckpointDTO.model_validate_json(
                arguments["commodity_checkpoint_raw"]
            )
            accounts = [] if mutation == "zero" else [ACCOUNT_HASH, "b" * 64]
            _replace_commodity_checkpoint(
                arguments,
                initial_rpc=old.initial_rpc.model_copy(
                    update={"account_hashes": accounts}
                ),
            )
        build_initial_baseline_checkpoint(**arguments)


@pytest.mark.parametrize("mutation", ["identity", "server", "pending", "positions"])
def test_two_capture_windows_drift_is_rejected(tmp_path, mutation) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    fresh = arguments["fresh_rpc"]
    if mutation == "identity":
        fresh = fresh.model_copy(update={"fresh_challenge": "arbitrary-fresh-challenge"})
    elif mutation == "server":
        fresh = fresh.model_copy(update={"server_instance_id": "windows-rpc-changed"})
    elif mutation == "pending":
        fresh = fresh.model_copy(update={"pending_send_outcomes": 1})
    else:
        fresh = fresh.model_copy(update={"positions": []})
    arguments["fresh_rpc"] = fresh

    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**arguments)


def test_prehead_stale_and_clock_rollback_are_rejected(tmp_path) -> None:
    arguments, _current, clock = _fixture(tmp_path)
    current = parse_exact_state_commitment(arguments["state_commitment_chain_raw"][-1])
    old = DeploymentInitialBaselineCommodityCheckpointDTO.model_validate_json(
        arguments["commodity_checkpoint_raw"]
    )
    _replace_commodity_checkpoint(
        arguments,
        initial_rpc=old.initial_rpc.model_copy(
            update={"captured_at": current.created_at - timedelta(microseconds=1)}
        ),
    )
    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**arguments)

    arguments, _current, clock = _fixture(tmp_path / "rollback")
    baseline_module._utc_now = lambda: clock() - timedelta(microseconds=1)
    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**arguments)


def test_old_two_capture_identity_cannot_replay_after_restart(tmp_path) -> None:
    arguments, current, clock = _fixture(tmp_path)
    restarted = DeploymentDrainService(
        current.root,
        clock=clock,
        runtime_instance_id="runtime-initial-baseline-new-head",
        allow_initial_bootstrap=True,
    )
    restarted.status()
    replay = dict(arguments)
    replay.update(
        state_commitment_chain_raw=[
            path.read_bytes() for path in sorted(restarted.state_commitment_dir.iterdir())
        ],
        current_epoch_anchor_raw=restarted.epoch_anchor_path.read_bytes(),
        current_runtime_instance_id=restarted.runtime_instance_id,
        current_execution_epoch=restarted.execution_epoch,
    )

    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**replay)


def test_noncanonical_and_authorizing_evidence_are_rejected(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    checkpoint, checkpoint_raw, evidence, evidence_raw = _build_all(arguments)
    with pytest.raises(DeploymentInitialBaselineError):
        verify_initial_baseline_checkpoint(
            checkpoint_raw=checkpoint_raw + b" ", **arguments
        )
    payload = evidence.model_dump(mode="json")
    payload["deployment_authorized"] = True
    tampered = _canonical_bytes(payload) + b"\n"
    with pytest.raises(DeploymentInitialBaselineError):
        verify_initial_baseline_reconciliation_evidence(
            evidence_raw=tampered,
            checkpoint_raw=checkpoint_raw,
            **arguments,
        )
    assert evidence_raw == canonical_initial_baseline_evidence_bytes(evidence)
    assert checkpoint_raw == canonical_initial_baseline_checkpoint_bytes(checkpoint)


def test_commodity_checkpoint_requires_exact_raw_and_frozen_schema(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    noncanonical = dict(arguments)
    noncanonical["commodity_checkpoint_raw"] += b" "
    with pytest.raises(DeploymentInitialBaselineError):
        build_initial_baseline_checkpoint(**noncanonical)

    commodity = DeploymentInitialBaselineCommodityCheckpointDTO.model_validate_json(
        arguments["commodity_checkpoint_raw"]
    )
    payload = commodity.model_dump(mode="json")
    payload["state_version"] = "arbitrary-unbound-state-v9"
    with pytest.raises(ValueError):
        DeploymentInitialBaselineCommodityCheckpointDTO.model_validate(payload)
    payload = commodity.model_dump(mode="json")
    payload["state"]["execution_plan_status"] = "ACTIVE"
    with pytest.raises(ValueError):
        DeploymentInitialBaselineCommodityCheckpointDTO.model_validate(payload)


@pytest.mark.parametrize(
    "mutation", ["active_request", "schema", "extra", "previous", "updated_at"]
)
def test_checkpoint_dto_itself_rejects_nonpristine_current_state(
    tmp_path, mutation
) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    checkpoint = build_initial_baseline_checkpoint(**arguments)
    payload = checkpoint.model_dump(mode="json")
    if mutation == "active_request":
        payload["current_drain_state"]["active_request_id"] = (
            "request-forged-0001"
        )
        payload["current_drain_state"]["active_request_sha256"] = "d" * 64
    elif mutation == "schema":
        payload["current_drain_state"]["schema_version"] = "forged-v999"
    elif mutation == "previous":
        payload["current_drain_state"]["previous_state_commitment_raw_sha256"] = None
    elif mutation == "updated_at":
        payload["current_drain_state"]["updated_at"] = "not-a-time"
    else:
        payload["current_drain_state"]["extra_forged"] = True
    payload["current_drain_state_raw_sha256"] = hashlib.sha256(
        _canonical_bytes(payload["current_drain_state"]) + b"\n"
    ).hexdigest()
    payload.pop("checkpoint_id")
    payload.pop("checkpoint_core_sha256")
    digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    payload["checkpoint_id"] = f"deployment-initial-baseline-checkpoint-{digest}"
    payload["checkpoint_core_sha256"] = digest

    with pytest.raises(ValueError):
        type(checkpoint).model_validate(payload)
