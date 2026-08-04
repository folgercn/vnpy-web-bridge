from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)
from app.services.deployment_state_commitment import (
    build_state_commitment,
    parse_exact_state_commitment,
)


V2 = "web_bridge_deployment_drain_state_v2"
ANCHOR_V1 = "web_bridge_deployment_drain_epoch_anchor_v1"
AUTHORITY_FIELDS = (
    "deployment_authorized",
    "consume_authorized",
    "reconciliation_authorized",
    "countable_forward",
    "automatic_deploy_allowed",
    "production_allowed",
    "live_trading_authorized",
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 4, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


def service(root: Path, clock: Clock, runtime: str) -> DeploymentDrainService:
    return DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id=runtime,
        allow_initial_bootstrap=True,
    )


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def commitments(
    drain: DeploymentDrainService,
) -> list[tuple[object, bytes]]:
    result: list[tuple[object, bytes]] = []
    for path in sorted(drain.state_commitment_dir.iterdir()):
        raw = path.read_bytes()
        result.append((parse_exact_state_commitment(raw), raw))
    return result


def assert_no_authority(value: object) -> None:
    for field in AUTHORITY_FIELDS:
        if isinstance(value, dict):
            assert value[field] is False
        else:
            assert getattr(value, field) is False


def next_committed_state(drain: DeploymentDrainService) -> dict[str, object]:
    current = drain._load_state()
    anchor = drain._load_epoch_anchor_v2()
    return {
        **current,
        "state_generation": current["state_generation"] + 1,
        "previous_state_commitment_raw_sha256": anchor["state_commitment_raw_sha256"],
        "updated_at": drain._now().isoformat(),
    }


def write_legacy_v2(
    drain: DeploymentDrainService,
) -> tuple[bytes, bytes]:
    state = drain._load_state()
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
        state.pop(field)
    state["schema_version"] = V2
    for path in drain.state_commitment_dir.iterdir():
        path.unlink()
    state_raw = canonical(state)
    anchor_raw = canonical(
        {
            "schema_version": ANCHOR_V1,
            "drain_epoch": state["drain_epoch"],
            "execution_epoch": state["execution_epoch"],
        }
    )
    drain._atomic_write(drain.state_path, state_raw)
    drain._atomic_write(drain.epoch_anchor_path, anchor_raw)
    return state_raw, anchor_raw


def assert_recovered_frozen(status: dict[str, object]) -> None:
    assert status["state"] == "RESTARTED_FROZEN"
    assert status["blockers"] == ["state_materialization_recovered_from_commitment"]
    assert status["freeze_reason"] == (
        "state_materialization_recovered_from_commitment"
    )
    assert_no_authority(status)


def test_fresh_chain_is_contiguous_and_binds_exact_state_without_authority(
    tmp_path: Path,
) -> None:
    clock = Clock()
    drain = service(tmp_path / "fresh", clock, "runtime-fresh")
    status = drain.status()

    with drain._exclusive():
        state = drain._load_state()
        state["updated_at"] = drain._now().isoformat()
        drain._write_state(state)

    chain = commitments(drain)
    assert [artifact.state_generation for artifact, _raw in chain] == [1, 2, 3]
    previous_raw_sha: str | None = None
    for artifact, raw in chain:
        assert artifact.previous_state_commitment_raw_sha256 == previous_raw_sha
        assert artifact.state["previous_state_commitment_raw_sha256"] == (
            previous_raw_sha
        )
        assert artifact.state_raw_sha256 == sha256(canonical(artifact.state))
        assert_no_authority(artifact)
        previous_raw_sha = sha256(raw)

    assert status["schema_version"] == ("web_bridge_deployment_drain_state_v3")
    assert_no_authority(status)
    anchor = read_json(drain.epoch_anchor_path)
    assert anchor["schema_version"] == ("web_bridge_deployment_drain_epoch_anchor_v2")
    assert anchor["state_generation"] == 3
    assert anchor["state_commitment_raw_sha256"] == previous_raw_sha


def test_v2_migration_genesis_commits_exact_source_hashes(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "v2-migration"
    old = service(root, clock, "runtime-old")
    old.status()
    state_raw, anchor_raw = write_legacy_v2(old)

    status = service(root, clock, "runtime-new").status()

    genesis, _raw = commitments(old)[0]
    assert genesis.state_generation == 1
    assert genesis.genesis_source == "v2_migration"
    assert genesis.source_state_raw_sha256 == sha256(state_raw)
    assert genesis.source_epoch_anchor_raw_sha256 == sha256(anchor_raw)
    assert_no_authority(genesis)
    assert status["state"] == "RESTARTED_FROZEN"
    assert status["freeze_reason"] == (
        "legacy_state_migrated_to_v3_requires_reconciliation"
    )
    assert_no_authority(status)


def test_v2_state_ahead_of_legacy_anchor_migrates_frozen(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "v2-state-ahead"
    old = service(root, clock, "runtime-old")
    old.status()
    _state_raw, anchor_raw = write_legacy_v2(old)
    anchor = json.loads(anchor_raw)
    anchor["execution_epoch"] = int(anchor["execution_epoch"]) - 1
    old._atomic_write(old.epoch_anchor_path, canonical(anchor))

    status = service(root, clock, "runtime-new").status()

    assert status["state"] == "RESTARTED_FROZEN"
    assert status["freeze_reason"] == (
        "legacy_state_migrated_to_v3_requires_reconciliation"
    )
    assert_no_authority(status)


def test_commitment_before_state_is_recovered_and_frozen(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "commitment-before-state"
    old = service(root, clock, "runtime-old")
    old.status()
    next_state = next_committed_state(old)
    old._persist_state_commitment(next_state)

    status = service(root, clock, "runtime-new").status()

    assert_recovered_frozen(status)
    assert read_json(old.state_path)["state_generation"] == 5


def test_state_before_anchor_is_recovered_and_frozen(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "state-before-anchor"
    old = service(root, clock, "runtime-old")
    old.status()
    next_state = next_committed_state(old)
    old._persist_state_commitment(next_state)
    old._atomic_write(old.state_path, canonical(next_state))

    status = service(root, clock, "runtime-new").status()

    assert_recovered_frozen(status)
    anchor = read_json(old.epoch_anchor_path)
    assert anchor["state_generation"] == 5


def test_state_rollback_to_prior_commitment_is_recovered_and_frozen(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "state-rollback"
    old = service(root, clock, "runtime-old")
    old.status()
    prior_state = commitments(old)[0][0].state
    old._atomic_write(old.state_path, canonical(prior_state))

    status = service(root, clock, "runtime-new").status()

    assert_recovered_frozen(status)


def test_crash_after_recovery_fence_cannot_restore_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    root = tmp_path / "recovery-fence-crash"
    old = service(root, clock, "runtime-old")
    old.status()
    next_state = next_committed_state(old)
    old._persist_state_commitment(next_state)
    original = DeploymentDrainService._persist_state_recovery_fence

    def crash_after_fence(
        self: DeploymentDrainService,
        state: dict[str, object],
        *,
        previous_commitment_raw_sha256: str,
    ) -> dict[str, object]:
        original(
            self,
            state,
            previous_commitment_raw_sha256=previous_commitment_raw_sha256,
        )
        raise RuntimeError("simulated crash after durable recovery fence")

    monkeypatch.setattr(
        DeploymentDrainService,
        "_persist_state_recovery_fence",
        crash_after_fence,
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        service(root, clock, "runtime-crashed").status()
    monkeypatch.undo()

    status = service(root, clock, "runtime-after-crash").status()

    assert_recovered_frozen(status)
    with pytest.raises(DeploymentDrainError) as caught:
        with service(root, clock, "runtime-third").mutation_guard():
            pass
    assert caught.value.code == "DEPLOYMENT_DRAIN_ACTIVE"


@pytest.mark.parametrize("crash_point", ["before-state", "before-anchor"])
def test_recovery_fence_internal_crash_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
) -> None:
    clock = Clock()
    root = tmp_path / crash_point
    old = service(root, clock, "runtime-old")
    old.status()
    old._persist_state_commitment(next_committed_state(old))

    if crash_point == "before-state":
        original_atomic_write = DeploymentDrainService._atomic_write

        def crash_before_state(
            self: DeploymentDrainService, path: Path, data: bytes
        ) -> None:
            if path == self.state_path and (
                b"state_materialization_recovered_from_commitment" in data
            ):
                raise RuntimeError("simulated crash before recovery state")
            original_atomic_write(self, path, data)

        monkeypatch.setattr(DeploymentDrainService, "_atomic_write", crash_before_state)
    else:
        original_write_anchor = DeploymentDrainService._write_epoch_anchor_v2

        def crash_before_anchor(
            self: DeploymentDrainService,
            state: dict[str, object],
            commitment_raw_sha256: str,
        ) -> None:
            if state.get("freeze_reason") == (
                "state_materialization_recovered_from_commitment"
            ):
                raise RuntimeError("simulated crash before recovery anchor")
            original_write_anchor(self, state, commitment_raw_sha256)

        monkeypatch.setattr(
            DeploymentDrainService,
            "_write_epoch_anchor_v2",
            crash_before_anchor,
        )

    with pytest.raises(RuntimeError, match="simulated crash"):
        service(root, clock, "runtime-crashed").status()
    monkeypatch.undo()

    status = service(root, clock, "runtime-recovered").status()

    assert_recovered_frozen(status)
    assert status["deployment_authorized"] is False


def test_uncommitted_state_tamper_is_rejected(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "state-tamper"
    old = service(root, clock, "runtime-old")
    old.status()
    tampered = read_json(old.state_path)
    tampered["blockers"] = ["uncommitted-tamper"]
    old._atomic_write(old.state_path, canonical(tampered))

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_DRAIN_STATE_ROLLBACK"


def test_commitment_chain_gap_is_rejected(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "chain-gap"
    old = service(root, clock, "runtime-old")
    old.status()
    old._state_commitment_path(1).unlink()

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_STATE_COMMITMENT_INVENTORY_INVALID"


@pytest.mark.parametrize("kind", ["corrupt", "noncanonical"])
def test_invalid_commitment_bytes_are_rejected(tmp_path: Path, kind: str) -> None:
    clock = Clock()
    root = tmp_path / kind
    old = service(root, clock, "runtime-old")
    old.status()
    path = old._state_commitment_path(2)
    if kind == "corrupt":
        raw = b"{not-json}\n"
    else:
        raw = json.dumps(json.loads(path.read_bytes()), indent=2).encode() + b"\n"
    old._atomic_write(path, raw)

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_STATE_COMMITMENT_INVALID"


def test_commitment_predecessor_mismatch_is_rejected(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "predecessor-mismatch"
    old = service(root, clock, "runtime-old")
    old.status()
    path = old._state_commitment_path(2)
    state = dict(parse_exact_state_commitment(path.read_bytes()).state)
    state["previous_state_commitment_raw_sha256"] = "f" * 64
    artifact = build_state_commitment(state)
    old._atomic_write(path, canonical(artifact.model_dump(mode="json")))

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_STATE_COMMITMENT_CHAIN_INVALID"


def test_epoch_anchor_ahead_of_commitment_chain_is_rejected(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "anchor-ahead"
    old = service(root, clock, "runtime-old")
    old.status()
    anchor = read_json(old.epoch_anchor_path)
    anchor["state_generation"] = int(anchor["state_generation"]) + 1
    old._atomic_write(old.epoch_anchor_path, canonical(anchor))

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_DRAIN_EPOCH_ROLLBACK"


@pytest.mark.parametrize("kind", ["forged-stale", "same-generation-mismatch"])
def test_epoch_anchor_must_exactly_bind_its_committed_generation(
    tmp_path: Path, kind: str
) -> None:
    clock = Clock()
    root = tmp_path / kind
    old = service(root, clock, "runtime-old")
    old.status()
    anchor = read_json(old.epoch_anchor_path)
    if kind == "forged-stale":
        anchor["state_generation"] = int(anchor["state_generation"]) - 1
        anchor["drain_epoch"] = 999
        anchor["execution_epoch"] = 999
    anchor["state_commitment_raw_sha256"] = "f" * 64
    old._atomic_write(old.epoch_anchor_path, canonical(anchor))

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_DRAIN_EPOCH_ROLLBACK"


@pytest.mark.parametrize("kind", ["missing", "corrupt"])
def test_established_epoch_anchor_cannot_be_recreated_from_chain(
    tmp_path: Path, kind: str
) -> None:
    clock = Clock()
    root = tmp_path / kind
    old = service(root, clock, "runtime-old")
    old.status()
    if kind == "missing":
        old.epoch_anchor_path.unlink()
    else:
        old._atomic_write(old.epoch_anchor_path, b"{not-json}\n")

    with pytest.raises(DeploymentDrainError) as caught:
        service(root, clock, "runtime-new").status()

    assert caught.value.code == "DEPLOYMENT_DRAIN_EPOCH_ANCHOR_INVALID"
