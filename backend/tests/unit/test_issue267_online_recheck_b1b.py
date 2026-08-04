from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from app.core.config import Settings
from app.schemas.deployment_drain import (
    DeploymentOnlineRecheckCheckpointDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    SafeRestartOnlineRecheckDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.commodity_simnow import CommoditySimNowService
from app.services.deployment_drain import DeploymentDrainError

SHA_A = "a" * 64
ACCOUNT_ID = "sim-account-b1b"
ACCOUNT_HASH = hashlib.sha256(ACCOUNT_ID.encode()).hexdigest()
RECHECK_ID = f"deployment-recheck-{SHA_A}"


def _execution_hash(*, pending_send_outcomes: int = 0) -> str:
    return deployment_rpc_execution_facts_sha256(
        DeploymentRpcFactsDTO(
            schema_version="windows_rpc_deployment_safety_snapshot_v1",
            request_id="request-online-b1b-0001",
            challenge="owner-challenge-b1b-0001",
            server_instance_id="windows-rpc-b1b-instance",
            fact_generation=9,
            captured_at=datetime.now(timezone.utc),
            execution_admission_frozen=True,
            pending_send_outcomes=pending_send_outcomes,
            strategy_execution_enabled=False,
            account_hashes=[ACCOUNT_HASH],
            orders=[],
            active_orders=[],
            trades=[],
            positions=[],
        )
    )


class StubDrain:
    def __init__(self) -> None:
        self.provider: Callable[[], DeploymentOnlineRecheckCheckpointDTO] | None = None
        self.owner: object | None = None
        self.provider_checkpoint: DeploymentOnlineRecheckCheckpointDTO | None = None
        self.result = SafeRestartOnlineRecheckDTO.model_construct()
        self.context = {
            "request_id": "request-online-b1b-0001",
            "runtime_instance_id": "runtime-online-b1b-0001",
            "drain_epoch": 3,
            "execution_epoch": 4,
            "recheck_id": RECHECK_ID,
            "fresh_challenge": "fresh-challenge-b1b-0001",
            "owner_challenge": "owner-challenge-b1b-0001",
            "original_checkpoint_raw_sha256": SHA_A,
            "original_server_instance_id": "windows-rpc-b1b-instance",
            "original_fact_generation": 9,
            "original_execution_facts_canonical_sha256": _execution_hash(),
        }

    def bind_online_recheck_provider(
        self,
        owner: object,
        bound_provider: Callable[[], DeploymentOnlineRecheckCheckpointDTO],
    ) -> None:
        self.owner = owner
        self.provider = bound_provider

    def capture_online_recheck(self, *, owner: object) -> SafeRestartOnlineRecheckDTO:
        assert owner is self.owner
        assert self.provider is not None
        self.provider_checkpoint = self.provider()
        return self.result

    def online_recheck_capture_context(self) -> dict[str, Any]:
        return dict(self.context)


class FakeRpc:
    def __init__(self, drain: StubDrain) -> None:
        self.deployment_drain = drain
        self.calls: list[dict[str, Any]] = []
        self.server_instance_id = "windows-rpc-b1b-instance"
        self.fact_generation = 9
        self.pending_send_outcomes = 0

    def bind_c_fast_terminal_publication_owner(self, _owner: object) -> object:
        return object()

    def capture_deployment_recheck_facts(
        self, **kwargs: Any
    ) -> DeploymentRpcRecheckFactsDTO:
        self.calls.append(kwargs)
        return DeploymentRpcRecheckFactsDTO(
            schema_version="windows_rpc_deployment_safety_recheck_v1",
            request_id=kwargs["request_id"],
            owner_challenge=kwargs["owner_challenge"],
            recheck_id=kwargs["recheck_id"],
            fresh_challenge=kwargs["fresh_challenge"],
            original_server_instance_id=kwargs["original_server_instance_id"],
            original_fact_generation=kwargs["original_fact_generation"],
            original_execution_facts_canonical_sha256=(
                kwargs["original_execution_facts_canonical_sha256"]
            ),
            server_instance_id=self.server_instance_id,
            fact_generation=self.fact_generation,
            execution_facts_canonical_sha256=_execution_hash(
                pending_send_outcomes=self.pending_send_outcomes
            ),
            captured_at=datetime.now(timezone.utc),
            execution_admission_frozen=True,
            pending_send_outcomes=self.pending_send_outcomes,
            strategy_execution_enabled=False,
            account_hashes=[ACCOUNT_HASH],
            orders=[],
            active_orders=[],
            trades=[],
            positions=[],
        )


class FakeTrade:
    def __init__(self, drain: StubDrain, rpc: FakeRpc) -> None:
        self.deployment_drain = drain
        self.rpc = rpc


class FakeRisk:
    def __init__(self, drain: StubDrain) -> None:
        self.deployment_drain = drain

    def status(self) -> dict[str, object]:
        return {
            "web_trade_enabled": False,
            "emergency_stopped": False,
            "rules_version": 1,
        }


class FakeAudit:
    def record(self, **_kwargs: object) -> None:
        return None


class FakeRuntimeAuthorization:
    def status(self) -> dict[str, str]:
        return {"state": "REVOKED"}


def service(tmp_path) -> tuple[CommoditySimNowService, StubDrain, FakeRpc]:
    drain = StubDrain()
    rpc = FakeRpc(drain)
    commodity = CommoditySimNowService(
        settings=Settings(
            app_env="test",
            commodity_simnow_enabled=True,
            commodity_simnow_account_hashes=ACCOUNT_HASH,
            commodity_simnow_state_path=str(tmp_path / "commodity.json"),
            commodity_c_fast_simnow_state_path=str(tmp_path / "c-fast.json"),
            commodity_position_manager_shadow_state_path=str(
                tmp_path / "position-shadow.json"
            ),
        ),
        rpc=rpc,  # type: ignore[arg-type]
        trade=FakeTrade(drain, rpc),  # type: ignore[arg-type]
        risk=FakeRisk(drain),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=object(),
        clock=lambda: datetime.now(timezone.utc),
        c_fast_runtime_authorization=(
            FakeRuntimeAuthorization()  # type: ignore[arg-type]
        ),
        deployment_drain=drain,  # type: ignore[arg-type]
    )
    return commodity, drain, rpc


def test_public_recheck_is_owner_bound_and_forwards_only_trusted_context(
    tmp_path,
) -> None:
    commodity, drain, rpc = service(tmp_path)

    result = commodity.recheck_deployment_drain()

    assert drain.owner is commodity
    assert result is drain.result
    checkpoint = drain.provider_checkpoint
    assert checkpoint is not None
    assert rpc.calls == [
        {
            "request_id": drain.context["request_id"],
            "owner_challenge": drain.context["owner_challenge"],
            "recheck_id": drain.context["recheck_id"],
            "fresh_challenge": drain.context["fresh_challenge"],
            "original_server_instance_id": drain.context["original_server_instance_id"],
            "original_fact_generation": drain.context["original_fact_generation"],
            "original_execution_facts_canonical_sha256": drain.context[
                "original_execution_facts_canonical_sha256"
            ],
        }
    ]
    assert checkpoint.request_id == drain.context["request_id"]
    assert checkpoint.recheck_id == drain.context["recheck_id"]
    assert checkpoint.deployment_authorized is False
    assert checkpoint.one_shot_consume_allowed is False
    assert checkpoint.production_allowed is False
    assert checkpoint.live_trading_authorized is False
    assert checkpoint.countable_forward is False


@pytest.mark.parametrize(
    ("attribute", "value", "code"),
    [
        (
            "server_instance_id",
            "windows-rpc-b1b-restarted",
            "DEPLOYMENT_RECHECK_SERVER_DRIFT",
        ),
        ("fact_generation", 10, "DEPLOYMENT_RECHECK_GENERATION_DRIFT"),
        ("pending_send_outcomes", 1, "DEPLOYMENT_RECHECK_FACTS_DRIFT"),
    ],
)
def test_recheck_rejects_windows_semantic_drift(
    tmp_path, attribute: str, value: object, code: str
) -> None:
    commodity, _drain, rpc = service(tmp_path)
    setattr(rpc, attribute, value)

    with pytest.raises(DeploymentDrainError) as exc_info:
        commodity.recheck_deployment_drain()

    assert exc_info.value.code == code


def test_public_recheck_does_not_accept_a_caller_dto(tmp_path) -> None:
    commodity, _drain, _rpc = service(tmp_path)

    with pytest.raises(TypeError):
        commodity.recheck_deployment_drain(object())  # type: ignore[call-arg]
