from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from app.schemas.deployment_drain import (
    CommodityInitialBaselineStateDTO,
    DeploymentDrainStateCommitmentDTO,
    DeploymentEpochAnchorV2DTO,
    DeploymentLegacyMigrationCheckpointDTO,
    DeploymentLegacyMigrationCommodityCheckpointDTO,
    DeploymentLegacyMigrationDrainStateDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    LegacyEpochAnchorV1DTO,
    LegacyMigrationEmptyInventoryDTO,
    LegacyMigrationReconciliationEvidenceDTO,
    LegacyMigrationSourceStateV1DTO,
    LegacyMigrationSourceStateV2DTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services import deployment_legacy_migration_reconciliation as legacy_module
from app.services.deployment_drain import DeploymentDrainService
from app.services.deployment_legacy_migration_reconciliation import (
    DeploymentLegacyMigrationError,
    build_legacy_migration_checkpoint,
    build_legacy_migration_commodity_checkpoint,
    build_legacy_migration_empty_inventory,
    build_legacy_migration_reconciliation_evidence,
    canonical_legacy_migration_checkpoint_bytes,
    canonical_legacy_migration_commodity_checkpoint_bytes,
    canonical_legacy_migration_evidence_bytes,
    canonical_legacy_migration_inventory_bytes,
    derive_legacy_migration_rpc_identity,
    verify_legacy_migration_checkpoint,
    verify_legacy_migration_reconciliation_evidence,
)
from app.services.deployment_state_commitment import (
    build_state_commitment,
    parse_exact_state_commitment,
)


ACCOUNT_HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[3]
V1 = "web_bridge_deployment_drain_state_v1"
V2 = "web_bridge_deployment_drain_state_v2"
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
        self.value = datetime(2026, 8, 4, 16, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture(autouse=True)
def _restore_clock():
    original = legacy_module._utc_now
    yield
    legacy_module._utc_now = original


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _artifact_bytes(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _service(root: Path, clock: Clock, runtime: str) -> DeploymentDrainService:
    return DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id=runtime,
        allow_initial_bootstrap=True,
    )


def _legacy_source(
    state: dict[str, object], version: str, **updates: object
) -> dict[str, object]:
    value = dict(state)
    for field in (
        "state_generation",
        "previous_state_commitment_raw_sha256",
        "consumed_receipt_id",
        "consume_intent_raw_sha256",
        "consume_marker_raw_sha256",
        "consume_state_projection_sha256",
        "consumed_online_recheck_id",
        "consumed_online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
    ):
        value.pop(field)
    if version == V1:
        for field in (
            "active_online_recheck_id",
            "active_online_recheck_raw_sha256",
            "active_recheck_checkpoint_raw_sha256",
            "online_rechecked_at",
            "last_invalidated_online_recheck_id",
        ):
            value.pop(field)
    value.update(schema_version=version, **updates)
    return value


def _fixture(
    tmp_path: Path,
    *,
    version: str = V2,
    restarts: int = 0,
    source_updates: dict[str, object] | None = None,
    anchor_execution_delta: int = 0,
):
    clock = Clock()
    root = tmp_path / "legacy-baseline"
    old = _service(root, clock, "legacy-runtime-old")
    old.status()
    source = _legacy_source(old._load_state(), version, **(source_updates or {}))
    source_raw = _artifact_bytes(source)
    anchor = {
        "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
        "drain_epoch": source["drain_epoch"],
        "execution_epoch": int(source["execution_epoch"])
        + anchor_execution_delta,
    }
    anchor_raw = _artifact_bytes(anchor)
    for path in old.state_commitment_dir.iterdir():
        path.unlink()
    old._atomic_write(old.state_path, source_raw)
    old._atomic_write(old.epoch_anchor_path, anchor_raw)

    inventory = build_legacy_migration_empty_inventory(
        source_state_raw=source_raw,
        source_epoch_anchor_raw=anchor_raw,
    )
    inventory_raw = canonical_legacy_migration_inventory_bytes(inventory)
    current = _service(root, clock, "legacy-runtime-migrated-1")
    current.status()
    for index in range(restarts):
        current = _service(root, clock, f"legacy-runtime-migrated-{index + 2}")
        current.status()
    chain = [path.read_bytes() for path in sorted(current.state_commitment_dir.iterdir())]
    genesis_raw = chain[0]
    current_raw = chain[-1]
    current_anchor_raw = current.epoch_anchor_path.read_bytes()
    run_id = "legacy-migration-run-0001"
    request_id, owner_challenge, recheck_id, fresh_challenge = (
        derive_legacy_migration_rpc_identity(
            reconciliation_run_id=run_id,
            source_schema_version=version,
            source_state_raw_sha256=_sha(source_raw),
            source_epoch_anchor_raw_sha256=_sha(anchor_raw),
            inventory_raw_sha256=_sha(inventory_raw),
            genesis_commitment_raw_sha256=_sha(genesis_raw),
            current_state_commitment_raw_sha256=_sha(current_raw),
            current_epoch_anchor_raw_sha256=_sha(current_anchor_raw),
            current_runtime_instance_id=current.runtime_instance_id,
            current_execution_epoch=current.execution_epoch,
            expected_account_hash=ACCOUNT_HASH,
        )
    )
    orders = [{"status": "all_traded", "vt_orderid": "SIM.LEGACY.1"}]
    trades = [{"volume": 1, "vt_tradeid": "SIM.LEGACY.T1"}]
    positions = [{"direction": "long", "volume": 1, "vt_symbol": "rb2610.SHFE"}]
    initial = DeploymentRpcFactsDTO(
        schema_version="windows_rpc_deployment_safety_snapshot_v1",
        request_id=request_id,
        challenge=owner_challenge,
        server_instance_id="windows-rpc-legacy-baseline",
        fact_generation=11,
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
    legacy_module._utc_now = clock
    commodity = build_legacy_migration_commodity_checkpoint(
        reconciliation_run_id=run_id,
        source_schema_version=version,
        source_state_raw_sha256=_sha(source_raw),
        source_epoch_anchor_raw_sha256=_sha(anchor_raw),
        inventory_raw_sha256=_sha(inventory_raw),
        inventory_id=inventory.inventory_id,
        inventory_core_sha256=inventory.inventory_core_sha256,
        genesis_commitment_raw_sha256=_sha(genesis_raw),
        current_state_commitment_raw_sha256=_sha(current_raw),
        current_epoch_anchor_raw_sha256=_sha(current_anchor_raw),
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
            "active_orders_snapshot_sha256": _sha(_canonical_bytes([])),
            "positions_snapshot_sha256": _sha(_canonical_bytes(positions)),
        },
        initial_rpc=initial,
    )
    commodity_raw = canonical_legacy_migration_commodity_checkpoint_bytes(commodity)
    arguments = {
        "source_state_raw": source_raw,
        "source_epoch_anchor_raw": anchor_raw,
        "inventory_manifest_raw": inventory_raw,
        "genesis_state_commitment_raw": genesis_raw,
        "state_commitment_chain_raw": chain,
        "current_epoch_anchor_raw": current_anchor_raw,
        "reconciliation_run_id": run_id,
        "current_runtime_instance_id": current.runtime_instance_id,
        "current_execution_epoch": current.execution_epoch,
        "expected_account_hash": ACCOUNT_HASH,
        "commodity_checkpoint_raw": commodity_raw,
        "fresh_rpc": fresh,
    }
    return arguments, current, clock


def _build_all(arguments):
    checkpoint = build_legacy_migration_checkpoint(**arguments)
    checkpoint_raw = canonical_legacy_migration_checkpoint_bytes(checkpoint)
    evidence = build_legacy_migration_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw, **arguments
    )
    evidence_raw = canonical_legacy_migration_evidence_bytes(evidence)
    return checkpoint, checkpoint_raw, evidence, evidence_raw


@pytest.mark.parametrize("version", [V1, V2])
def test_clean_v1_v2_build_exact_non_authorizing_baseline(tmp_path, version) -> None:
    arguments, _current, _clock = _fixture(tmp_path, version=version)

    checkpoint, checkpoint_raw, evidence, evidence_raw = _build_all(arguments)

    assert verify_legacy_migration_checkpoint(
        checkpoint_raw=checkpoint_raw, **arguments
    ) == checkpoint
    assert verify_legacy_migration_reconciliation_evidence(
        evidence_raw=evidence_raw,
        checkpoint_raw=checkpoint_raw,
        **arguments,
    ) == evidence
    assert checkpoint.source_schema_version == version
    assert checkpoint.source_state.schema_version == version
    assert checkpoint.legacy_migration_baseline_verified is True
    assert checkpoint.semantic_safety_unchanged is False
    assert checkpoint.custody_inventory_verified is False
    assert checkpoint.external_high_water_verified is False
    assert checkpoint.positions_snapshot_sha256 == _sha(
        _canonical_bytes(checkpoint.fresh_rpc.positions)
    )
    for artifact in (checkpoint, checkpoint.commodity_checkpoint, evidence):
        for field in AUTHORITY_FIELDS:
            assert getattr(artifact, field) is False


def test_c1c_artifacts_match_exact_published_schemas(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    checkpoint, _checkpoint_raw, evidence, _evidence_raw = _build_all(arguments)
    cases = (
        (
            "web-bridge-legacy-migration-empty-inventory-v1.schema.json",
            checkpoint.inventory,
        ),
        (
            "web-bridge-deployment-legacy-migration-commodity-checkpoint-v1.schema.json",
            checkpoint.commodity_checkpoint,
        ),
        (
            "web-bridge-deployment-legacy-migration-checkpoint-v1.schema.json",
            checkpoint,
        ),
        (
            "web-bridge-legacy-migration-reconciliation-v1.schema.json",
            evidence,
        ),
    )
    for schema_name, artifact in cases:
        schema = json.loads((ROOT / "docs/schemas" / schema_name).read_text())
        assert set(schema["properties"]) == set(type(artifact).model_fields)
        assert not list(
            Draft202012Validator(schema).iter_errors(
                artifact.model_dump(mode="json")
            )
        )
    checkpoint_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-deployment-legacy-migration-checkpoint-v1.schema.json"
        ).read_text()
    )
    expected_defs = {
        "CommodityInitialBaselineStateDTO": CommodityInitialBaselineStateDTO,
        "DeploymentLegacyMigrationCommodityCheckpointDTO": (
            DeploymentLegacyMigrationCommodityCheckpointDTO
        ),
        "DeploymentLegacyMigrationDrainStateDTO": (
            DeploymentLegacyMigrationDrainStateDTO
        ),
        "DeploymentDrainStateCommitmentDTO": DeploymentDrainStateCommitmentDTO,
        "DeploymentEpochAnchorV2DTO": DeploymentEpochAnchorV2DTO,
        "LegacyEpochAnchorV1DTO": LegacyEpochAnchorV1DTO,
        "LegacyMigrationEmptyInventoryDTO": LegacyMigrationEmptyInventoryDTO,
        "LegacyMigrationSourceStateV1DTO": LegacyMigrationSourceStateV1DTO,
        "LegacyMigrationSourceStateV2DTO": LegacyMigrationSourceStateV2DTO,
    }
    for definition, model in expected_defs.items():
        assert set(checkpoint_schema["$defs"][definition]["properties"]) == set(
            model.model_fields
        )
    assert set(DeploymentLegacyMigrationCheckpointDTO.model_fields) == set(
        checkpoint_schema["properties"]
    )
    assert set(LegacyMigrationReconciliationEvidenceDTO.model_fields) == set(
        json.loads(
            (
                ROOT
                / "docs/schemas/web-bridge-legacy-migration-reconciliation-v1.schema.json"
            ).read_text()
        )["properties"]
    )


def test_multiple_frozen_restarts_keep_exact_migration_lineage(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path, restarts=3)

    checkpoint = build_legacy_migration_checkpoint(**arguments)

    assert checkpoint.current_state_generation == 5
    assert checkpoint.current_execution_epoch == 5
    assert checkpoint.current_drain_state.blockers == [
        "legacy_state_migrated_to_v3_requires_reconciliation"
    ]


@pytest.mark.parametrize("version", [V1, V2])
@pytest.mark.parametrize(
    "updates",
    [
        {"receipt_consumed": True},
        {"active_request_id": "legacy-active-request", "active_request_sha256": "b" * 64},
        {"last_invalidated_receipt_id": "safe-restart-" + "b" * 64},
        {"blockers": ["legacy-unknown-history"]},
    ],
)
def test_consumption_pointer_or_partial_history_cannot_be_declared_clean(
    tmp_path, version, updates
) -> None:
    clock = Clock()
    root = tmp_path / "unsafe-source"
    old = _service(root, clock, "legacy-runtime-old")
    old.status()
    source_raw = _artifact_bytes(_legacy_source(old._load_state(), version, **updates))
    anchor_raw = _artifact_bytes(
        {
            "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
            "drain_epoch": 0,
            "execution_epoch": 1,
        }
    )

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_empty_inventory(
            source_state_raw=source_raw,
            source_epoch_anchor_raw=anchor_raw,
        )


def test_source_ahead_of_legacy_anchor_is_not_baseline_eligible(tmp_path) -> None:
    arguments, _current, _clock = _fixture(
        tmp_path, anchor_execution_delta=-1
    )

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


@pytest.mark.parametrize("target", ["source", "anchor", "inventory", "genesis"])
def test_exact_source_roots_reject_noncanonical_or_spliced_bytes(
    tmp_path, target
) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    keys = {
        "source": "source_state_raw",
        "anchor": "source_epoch_anchor_raw",
        "inventory": "inventory_manifest_raw",
        "genesis": "genesis_state_commitment_raw",
    }
    arguments[keys[target]] += b" "

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


def test_fresh_bootstrap_commitment_cannot_cross_replay_into_c1c(tmp_path) -> None:
    arguments, _current, clock = _fixture(tmp_path / "legacy")
    fresh = _service(tmp_path / "fresh", clock, "fresh-runtime")
    fresh.status()
    chain = [path.read_bytes() for path in sorted(fresh.state_commitment_dir.iterdir())]
    arguments.update(
        genesis_state_commitment_raw=chain[0],
        state_commitment_chain_raw=chain,
        current_epoch_anchor_raw=fresh.epoch_anchor_path.read_bytes(),
        current_runtime_instance_id=fresh.runtime_instance_id,
        current_execution_epoch=fresh.execution_epoch,
    )

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


def test_current_anchor_must_exactly_bind_head(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = "f" * 64
    arguments["current_epoch_anchor_raw"] = _artifact_bytes(anchor)

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


def test_rehashed_intermediate_running_state_is_rejected(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path, restarts=1)
    chain = list(arguments["state_commitment_chain_raw"])
    old = parse_exact_state_commitment(chain[1])
    state = dict(old.state)
    state["state"] = "RUNNING"
    rebuilt = build_state_commitment(state)
    chain[1] = _artifact_bytes(rebuilt.model_dump(mode="json"))
    for index in range(2, len(chain)):
        old = parse_exact_state_commitment(chain[index])
        state = dict(old.state)
        state["previous_state_commitment_raw_sha256"] = _sha(chain[index - 1])
        chain[index] = _artifact_bytes(build_state_commitment(state).model_dump(mode="json"))
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = _sha(chain[-1])
    arguments["state_commitment_chain_raw"] = chain
    arguments["current_epoch_anchor_raw"] = _artifact_bytes(anchor)

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


def test_semantically_equal_z_timestamp_cannot_reidentify_commitment_chain(
    tmp_path,
) -> None:
    arguments, _current, _clock = _fixture(tmp_path, restarts=1)
    chain = list(arguments["state_commitment_chain_raw"])
    genesis = parse_exact_state_commitment(chain[0])
    state = dict(genesis.state)
    state["updated_at"] = state["updated_at"].replace("+00:00", "Z")
    chain[0] = _artifact_bytes(
        build_state_commitment(
            state,
            genesis_source=genesis.genesis_source,
            source_state_raw_sha256=genesis.source_state_raw_sha256,
            source_epoch_anchor_raw_sha256=genesis.source_epoch_anchor_raw_sha256,
        ).model_dump(mode="json")
    )
    for index in range(1, len(chain)):
        old = parse_exact_state_commitment(chain[index])
        state = dict(old.state)
        state["previous_state_commitment_raw_sha256"] = _sha(chain[index - 1])
        chain[index] = _artifact_bytes(
            build_state_commitment(state).model_dump(mode="json")
        )
    anchor = json.loads(arguments["current_epoch_anchor_raw"])
    anchor["state_commitment_raw_sha256"] = _sha(chain[-1])
    arguments["genesis_state_commitment_raw"] = chain[0]
    arguments["state_commitment_chain_raw"] = chain
    arguments["current_epoch_anchor_raw"] = _artifact_bytes(anchor)

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


@pytest.mark.parametrize("field", ["server_instance_id", "positions", "account_hashes"])
def test_second_windows_capture_cannot_drift_even_when_rehashed(
    tmp_path, field
) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    fresh = arguments["fresh_rpc"].model_dump(mode="json")
    if field == "server_instance_id":
        fresh[field] = "windows-rpc-other-server"
    elif field == "positions":
        fresh[field] = []
    else:
        fresh[field] = ["c" * 64]
    facts = DeploymentRpcFactsDTO(
        schema_version="windows_rpc_deployment_safety_snapshot_v1",
        request_id=fresh["request_id"],
        challenge=fresh["owner_challenge"],
        server_instance_id=fresh["server_instance_id"],
        fact_generation=fresh["fact_generation"],
        captured_at=fresh["captured_at"],
        execution_admission_frozen=True,
        pending_send_outcomes=fresh["pending_send_outcomes"],
        strategy_execution_enabled=False,
        account_hashes=fresh["account_hashes"],
        orders=fresh["orders"],
        active_orders=fresh["active_orders"],
        trades=fresh["trades"],
        positions=fresh["positions"],
    )
    fresh["execution_facts_canonical_sha256"] = (
        deployment_rpc_execution_facts_sha256(facts)
    )
    arguments["fresh_rpc"] = fresh

    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)


def test_stale_capture_and_authority_rehash_are_rejected(tmp_path) -> None:
    arguments, _current, clock = _fixture(tmp_path)
    clock.value += timedelta(seconds=31)
    with pytest.raises(DeploymentLegacyMigrationError):
        build_legacy_migration_checkpoint(**arguments)

    clock.value -= timedelta(seconds=31)
    checkpoint = build_legacy_migration_checkpoint(**arguments)
    payload = checkpoint.model_dump(mode="json")
    payload["deployment_authorized"] = True
    payload.pop("checkpoint_id")
    payload.pop("checkpoint_core_sha256")
    digest = _sha(_canonical_bytes(payload))
    payload["checkpoint_id"] = f"deployment-legacy-migration-checkpoint-{digest}"
    payload["checkpoint_core_sha256"] = digest
    with pytest.raises(ValueError):
        type(checkpoint).model_validate(payload)


@pytest.mark.parametrize(
    "mutation",
    ["source", "inventory", "commodity", "predecessor", "timestamp", "anchor"],
)
def test_checkpoint_dto_rejects_rehashed_inner_root_or_state_attack(
    tmp_path, mutation
) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    checkpoint = build_legacy_migration_checkpoint(**arguments)
    payload = checkpoint.model_dump(mode="json")
    if mutation == "source":
        payload["source_state"]["updated_at"] = "2026-08-04T15:59:59+00:00"
    elif mutation == "inventory":
        payload["inventory"]["receipts"] = [
            {"path": "receipts/hidden.json", "raw_sha256": "b" * 64}
        ]
    elif mutation == "commodity":
        payload["commodity_checkpoint"]["state"]["plan_version"] = 1
    elif mutation == "predecessor":
        payload["current_drain_state"][
            "previous_state_commitment_raw_sha256"
        ] = "c" * 64
        payload["current_drain_state_raw_sha256"] = _sha(
            _artifact_bytes(payload["current_drain_state"])
        )
    elif mutation == "timestamp":
        payload["current_drain_state"]["updated_at"] = "not-a-time"
    else:
        payload["current_epoch_anchor"]["execution_epoch"] -= 1
        payload["current_epoch_anchor_raw_sha256"] = _sha(
            _artifact_bytes(payload["current_epoch_anchor"])
        )
    payload.pop("checkpoint_id")
    payload.pop("checkpoint_core_sha256")
    digest = _sha(_canonical_bytes(payload))
    payload["checkpoint_id"] = f"deployment-legacy-migration-checkpoint-{digest}"
    payload["checkpoint_core_sha256"] = digest

    with pytest.raises(ValueError):
        type(checkpoint).model_validate(payload)


def test_evidence_dto_rejects_rehashed_checkpoint_root_attack(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    _checkpoint, _checkpoint_raw, evidence, _evidence_raw = _build_all(arguments)
    payload = evidence.model_dump(mode="json")
    payload["checkpoint_raw_sha256"] = "d" * 64
    payload.pop("reconciliation_id")
    payload.pop("reconciliation_core_sha256")
    digest = _sha(_canonical_bytes(payload))
    payload["reconciliation_id"] = f"legacy-migration-reconciliation-{digest}"
    payload["reconciliation_core_sha256"] = digest

    with pytest.raises(ValueError):
        type(evidence).model_validate(payload)


def test_checkpoint_dto_rejects_rehashed_pre_head_capture_window(tmp_path) -> None:
    arguments, _current, _clock = _fixture(tmp_path)
    checkpoint = build_legacy_migration_checkpoint(**arguments)
    payload = checkpoint.model_dump(mode="json")
    before_head = "2026-08-04T15:59:59Z"
    commodity = payload["commodity_checkpoint"]
    commodity["initial_rpc"]["captured_at"] = before_head
    commodity["captured_at"] = before_head
    commodity.pop("checkpoint_id")
    commodity.pop("checkpoint_core_sha256")
    commodity_digest = _sha(_canonical_bytes(commodity))
    commodity["checkpoint_id"] = (
        f"deployment-legacy-migration-commodity-checkpoint-{commodity_digest}"
    )
    commodity["checkpoint_core_sha256"] = commodity_digest
    payload["commodity_checkpoint_id"] = commodity["checkpoint_id"]
    payload["commodity_checkpoint_core_sha256"] = commodity_digest
    payload["commodity_checkpoint_raw_sha256"] = _sha(_artifact_bytes(commodity))
    payload["fresh_rpc"]["captured_at"] = before_head
    payload["captured_at"] = before_head
    payload.pop("checkpoint_id")
    payload.pop("checkpoint_core_sha256")
    digest = _sha(_canonical_bytes(payload))
    payload["checkpoint_id"] = f"deployment-legacy-migration-checkpoint-{digest}"
    payload["checkpoint_core_sha256"] = digest

    with pytest.raises(ValueError):
        type(checkpoint).model_validate(payload)
