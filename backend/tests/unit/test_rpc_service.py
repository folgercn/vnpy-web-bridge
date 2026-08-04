from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from threading import Event, Thread

import pytest
from app.services import vnpy_rpc_service as rpc_module
from app.core.errors import RpcCallError, RpcTimeoutError, RpcUnavailableError
from app.schemas.deployment_drain import (
    DeploymentRpcFactsDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.vnpy_rpc_service import VnpyRpcService
from app.stores.memory_store import memory_store


class TimeoutClient:
    def get_all_contracts(self, *, timeout: int):
        raise TimeoutError("timeout")


class TimeoutRestartClient:
    def __init__(self) -> None:
        self.stopped = False
        self.joined = False

    def get_all_contracts(self, *, timeout: int):
        raise TimeoutError("timeout")

    def stop(self) -> None:
        self.stopped = True

    def join(self) -> None:
        self.joined = True


class BrokenClient:
    def get_all_contracts(self, *, timeout: int):
        raise RuntimeError("boom")


class BadStateClient:
    def __init__(self) -> None:
        self.stopped = False
        self.joined = False

    def get_all_contracts(self, *, timeout: int):
        raise RuntimeError("Operation cannot be accomplished in current state")

    def send_order(self, *args, timeout: int):
        raise RuntimeError("Operation cannot be accomplished in current state")

    def stop(self) -> None:
        self.stopped = True

    def join(self) -> None:
        self.joined = True


class HealthyClient:
    def get_all_contracts(self, *, timeout: int):
        return [{"symbol": "rb2610"}]


class ProbeClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_all_accounts(self, *, timeout: int):
        self.calls += 1
        return []


class DeploymentSnapshotClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def get_deployment_safety_snapshot_v1(
        self,
        request_id: str,
        challenge: str,
        *,
        timeout: int,
    ):
        return self.payload


class DeploymentRecheckClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.calls: list[tuple[object, ...]] = []

    def recheck_deployment_safety_snapshot_v1(
        self,
        *args: object,
        timeout: int,
    ):
        self.calls.append((*args, timeout))
        return self.payload


class BlockingDeploymentRecheckClient(DeploymentRecheckClient):
    def __init__(self, payload: dict[str, object]) -> None:
        super().__init__(payload)
        self.entered = Event()
        self.release = Event()

    def recheck_deployment_safety_snapshot_v1(
        self,
        *args: object,
        timeout: int,
    ):
        self.calls.append((*args, timeout))
        self.entered.set()
        assert self.release.wait(timeout=2)
        return self.payload

    def stop(self) -> None:
        return None

    def join(self) -> None:
        return None


def deployment_snapshot_payload() -> dict[str, object]:
    served_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": "windows_rpc_deployment_safety_snapshot_v1",
        "request_id": "request-rpc-snapshot-0001",
        "challenge": "rpc-snapshot-challenge-0001",
        "server_instance_id": "windows-rpc-test-instance",
        "fact_generation": 11,
        "captured_at_utc": served_at,
        "cache_replayed": False,
        "served_at_utc": served_at,
        "served_fact_generation": 11,
        "execution_admission_frozen": True,
        "pending_send_outcomes": 0,
        "strategy_execution_enabled": False,
        "accounts": [{"accountid": "account-a", "gateway_name": "CTP"}],
        "orders": [
            {"vt_orderid": "CTP.2", "status": "cancelled"},
            {"vt_orderid": "CTP.1", "status": "all_traded"},
        ],
        "active_orders": [],
        "trades": [],
        "positions": [],
    }


def deployment_recheck_payload() -> dict[str, object]:
    account_hash = hashlib.sha256(b"account-a").hexdigest()
    facts = DeploymentRpcFactsDTO(
        schema_version="windows_rpc_deployment_safety_snapshot_v1",
        request_id="request-rpc-snapshot-0001",
        challenge="rpc-snapshot-challenge-0001",
        server_instance_id="windows-rpc-test-instance",
        fact_generation=11,
        captured_at=datetime.now(timezone.utc),
        execution_admission_frozen=True,
        pending_send_outcomes=0,
        strategy_execution_enabled=False,
        account_hashes=[account_hash],
        orders=[{"status": "all_traded", "vt_orderid": "CTP.1"}],
        active_orders=[],
        trades=[],
        positions=[],
    )
    facts_sha = deployment_rpc_execution_facts_sha256(facts)
    served_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": "windows_rpc_deployment_safety_recheck_v1",
        "owner_request_id": facts.request_id,
        "owner_challenge": facts.challenge,
        "recheck_id": f"deployment-recheck-{'c' * 64}",
        "fresh_challenge": "fresh-rpc-recheck-challenge-0001",
        "expected_generation": 11,
        "current_generation": 11,
        "server_instance_id": facts.server_instance_id,
        "original_server_instance_id": facts.server_instance_id,
        "original_fact_generation": 11,
        "original_execution_facts_canonical_sha256": facts_sha,
        "execution_facts_canonical_sha256": facts_sha,
        "captured_at_utc": served_at,
        "cache_replayed": False,
        "served_at_utc": served_at,
        "served_fact_generation": 11,
        "admission": {
            "execution_frozen": True,
            "send_order_frozen": True,
            "cancel_order_frozen": True,
        },
        "pending": {"send_outcomes": 0},
        "facts": {
            "accounts": [{"accountid": "account-a"}],
            "orders": [{"vt_orderid": "CTP.1", "status": "all_traded"}],
            "active_orders": [],
            "trades": [],
            "positions": [],
        },
    }


class FlakyProbeClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_all_accounts(self, *, timeout: int):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("timeout")
        return []


class TickEvent:
    type = "eTick.UNIT999.SHFE"

    def __init__(self) -> None:
        self.data = TickPayload()


class TickPayload:
    def __init__(self) -> None:
        self.symbol = "UNIT999"
        self.exchange = "SHFE"
        self.last_price = 3126

    @property
    def vt_symbol(self) -> str:
        return f"{self.symbol}.{self.exchange}"


class TradeEvent:
    type = "eTrade.CTP.T1"
    data = {
        "vt_tradeid": "CTP.T1",
        "vt_orderid": "CTP.1",
        "vt_symbol": "ag2612.SHFE",
    }


def test_rpc_call_timeout_is_normalized(monkeypatch) -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = TimeoutClient()  # type: ignore[assignment]
    monkeypatch.setattr(
        VnpyRpcService,
        "start",
        lambda _service: (_ for _ in ()).throw(RpcUnavailableError("start failed")),
    )

    with pytest.raises(RpcTimeoutError):
        service.call("get_all_contracts", timeout=1)


def test_deployment_snapshot_client_hashes_accounts_and_sorts_facts() -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentSnapshotClient(  # type: ignore[assignment]
        deployment_snapshot_payload()
    )

    facts = service.capture_deployment_facts(
        request_id="request-rpc-snapshot-0001",
        challenge="rpc-snapshot-challenge-0001",
    )

    assert facts.account_hashes == [hashlib.sha256(b"account-a").hexdigest()]
    assert [row["vt_orderid"] for row in facts.orders] == ["CTP.1", "CTP.2"]
    assert facts.fact_generation == 11


def test_deployment_snapshot_client_rejects_contract_drift() -> None:
    payload = deployment_snapshot_payload()
    payload["unexpected"] = True
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentSnapshotClient(payload)  # type: ignore[assignment]

    with pytest.raises(RpcCallError, match="fields are invalid"):
        service.capture_deployment_facts(
            request_id="request-rpc-snapshot-0001",
            challenge="rpc-snapshot-challenge-0001",
        )


@pytest.mark.parametrize("failure", ["stale", "challenge"])
def test_deployment_snapshot_client_rejects_replay(failure: str) -> None:
    payload = deployment_snapshot_payload()
    if failure == "stale":
        payload["captured_at_utc"] = (
            (datetime.now(timezone.utc) - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
    else:
        payload["challenge"] = "different-rpc-challenge-0001"
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentSnapshotClient(payload)  # type: ignore[assignment]

    with pytest.raises(RpcCallError):
        service.capture_deployment_facts(
            request_id="request-rpc-snapshot-0001",
            challenge="rpc-snapshot-challenge-0001",
        )


def test_deployment_snapshot_client_rejects_stale_non_cache_with_replay_flag() -> None:
    payload = deployment_snapshot_payload()
    payload["captured_at_utc"] = (
        (datetime.now(timezone.utc) - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentSnapshotClient(payload)  # type: ignore[assignment]

    with pytest.raises(RpcCallError, match="freshness window"):
        service.capture_deployment_facts(
            request_id="request-rpc-snapshot-0001",
            challenge="rpc-snapshot-challenge-0001",
            allow_cached_replay=True,
        )


def test_deployment_recheck_client_binds_echoes_and_normalizes_facts() -> None:
    payload = deployment_recheck_payload()
    client = DeploymentRecheckClient(payload)
    service = VnpyRpcService()
    service.started = True
    service.client = client  # type: ignore[assignment]

    result = service.capture_deployment_recheck_facts(
        request_id=str(payload["owner_request_id"]),
        owner_challenge=str(payload["owner_challenge"]),
        recheck_id=str(payload["recheck_id"]),
        fresh_challenge=str(payload["fresh_challenge"]),
        original_server_instance_id=str(payload["original_server_instance_id"]),
        original_fact_generation=11,
        original_execution_facts_canonical_sha256=str(
            payload["original_execution_facts_canonical_sha256"]
        ),
    )

    assert client.calls == [
        (
            payload["owner_request_id"],
            payload["owner_challenge"],
            payload["recheck_id"],
            payload["fresh_challenge"],
            11,
            service.settings.vnpy_rpc_timeout_ms,
        )
    ]
    assert result.execution_admission_frozen is True
    assert result.strategy_execution_enabled is False
    assert result.pending_send_outcomes == 0
    assert result.account_hashes == [hashlib.sha256(b"account-a").hexdigest()]
    assert (
        result.execution_facts_canonical_sha256
        == (payload["execution_facts_canonical_sha256"])
    )


def test_deployment_recheck_client_explicitly_accepts_stale_cached_replay() -> None:
    payload = deployment_recheck_payload()
    payload["captured_at_utc"] = (
        (datetime.now(timezone.utc) - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    payload["cache_replayed"] = True
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentRecheckClient(payload)  # type: ignore[assignment]
    result = service.capture_deployment_recheck_facts(
        request_id=str(payload["owner_request_id"]),
        owner_challenge=str(payload["owner_challenge"]),
        recheck_id=str(payload["recheck_id"]),
        fresh_challenge=str(payload["fresh_challenge"]),
        original_server_instance_id=str(payload["original_server_instance_id"]),
        original_fact_generation=11,
        original_execution_facts_canonical_sha256=str(
            payload["original_execution_facts_canonical_sha256"]
        ),
        allow_cached_replay=True,
    )

    assert result.recheck_id == payload["recheck_id"]
    assert result.fresh_challenge == payload["fresh_challenge"]


@pytest.mark.parametrize("cache_replayed", [False, True])
def test_deployment_recheck_served_proof_preserves_exact_transport_evidence(
    cache_replayed: bool,
) -> None:
    payload = deployment_recheck_payload()
    if cache_replayed:
        payload["captured_at_utc"] = (
            (datetime.now(timezone.utc) - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
        payload["cache_replayed"] = True
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentRecheckClient(payload)  # type: ignore[assignment]
    service._deployment_transport_binding = (
        service.settings.vnpy_rpc_req_address,
        service.settings.vnpy_rpc_pub_address,
        service.settings.vnpy_gateway_name,
    )
    service._deployment_transport_generation = 1
    service.last_connected_at = datetime.now(timezone.utc)

    capture = service.capture_deployment_recheck_served_proof(
        request_id=str(payload["owner_request_id"]),
        owner_challenge=str(payload["owner_challenge"]),
        recheck_id=str(payload["recheck_id"]),
        fresh_challenge=str(payload["fresh_challenge"]),
        original_server_instance_id=str(payload["original_server_instance_id"]),
        original_fact_generation=11,
        original_execution_facts_canonical_sha256=str(
            payload["original_execution_facts_canonical_sha256"]
        ),
    )

    proof = capture.served_proof
    assert capture.facts.recheck_id == payload["recheck_id"]
    assert proof.cache_replayed is cache_replayed
    assert proof.captured_at_utc_raw == payload["captured_at_utc"]
    assert proof.served_at_utc_raw == payload["served_at_utc"]
    assert proof.served_fact_generation == payload["served_fact_generation"]
    fresh_raw = (
        json.dumps(
            capture.facts.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    assert proof.fresh_rpc_raw_sha256 == hashlib.sha256(fresh_raw).hexdigest()
    assert proof.freshness_basis == (
        "SERVED_AT_CACHE_REPLAY" if cache_replayed else "CAPTURED_AT_NON_CACHE"
    )
    assert proof.linux_rpc_adapter_response_verified is True
    assert proof.windows_response_authenticated is False
    assert proof.rpc_connection_generation == 1
    proof_raw = json.dumps(
        proof.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert "account-a" not in proof_raw
    assert hashlib.sha256(b"account-a").hexdigest() not in proof_raw


def test_deployment_recheck_served_proof_rejects_connection_generation_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = deployment_recheck_payload()
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentRecheckClient(payload)  # type: ignore[assignment]
    service._deployment_transport_binding = (
        service.settings.vnpy_rpc_req_address,
        service.settings.vnpy_rpc_pub_address,
        service.settings.vnpy_gateway_name,
    )
    service._deployment_transport_generation = 1
    service.last_connected_at = datetime.now(timezone.utc)
    original = rpc_module.build_deployment_rpc_recheck_served_proof

    def drift_generation(**kwargs):
        proof = original(**kwargs)
        service._deployment_transport_generation += 1
        return proof

    monkeypatch.setattr(
        rpc_module,
        "build_deployment_rpc_recheck_served_proof",
        drift_generation,
    )
    with pytest.raises(RpcCallError, match="changed during capture"):
        service.capture_deployment_recheck_served_proof(
            request_id=str(payload["owner_request_id"]),
            owner_challenge=str(payload["owner_challenge"]),
            recheck_id=str(payload["recheck_id"]),
            fresh_challenge=str(payload["fresh_challenge"]),
            original_server_instance_id=str(payload["original_server_instance_id"]),
            original_fact_generation=11,
            original_execution_facts_canonical_sha256=str(
                payload["original_execution_facts_canonical_sha256"]
            ),
        )


def test_deployment_recheck_served_proof_serializes_stop_across_raw_response() -> None:
    payload = deployment_recheck_payload()
    client = BlockingDeploymentRecheckClient(payload)
    service = VnpyRpcService()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._deployment_transport_binding = (
        service.settings.vnpy_rpc_req_address,
        service.settings.vnpy_rpc_pub_address,
        service.settings.vnpy_gateway_name,
    )
    service._deployment_transport_generation = 1
    service.last_connected_at = datetime.now(timezone.utc)
    captures: list[object] = []
    errors: list[BaseException] = []
    stop_attempted = Event()
    stop_completed = Event()

    def capture() -> None:
        try:
            captures.append(
                service.capture_deployment_recheck_served_proof(
                    request_id=str(payload["owner_request_id"]),
                    owner_challenge=str(payload["owner_challenge"]),
                    recheck_id=str(payload["recheck_id"]),
                    fresh_challenge=str(payload["fresh_challenge"]),
                    original_server_instance_id=str(
                        payload["original_server_instance_id"]
                    ),
                    original_fact_generation=11,
                    original_execution_facts_canonical_sha256=str(
                        payload["original_execution_facts_canonical_sha256"]
                    ),
                )
            )
        except BaseException as exc:
            errors.append(exc)

    def stop() -> None:
        stop_attempted.set()
        service.stop()
        stop_completed.set()

    capture_thread = Thread(target=capture)
    capture_thread.start()
    assert client.entered.wait(timeout=1)
    stop_thread = Thread(target=stop)
    stop_thread.start()
    assert stop_attempted.wait(timeout=1)
    assert stop_completed.wait(timeout=0.05) is False
    client.release.set()
    capture_thread.join(timeout=2)
    stop_thread.join(timeout=2)

    assert errors == []
    assert len(captures) == 1
    assert stop_completed.is_set()
    assert service._deployment_transport_generation == 2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(cache_replayed=1),
        lambda value: value.update(served_fact_generation=True),
        lambda value: value.update(served_at_utc="2026-08-05T01:00:00+00:00"),
    ],
    ids=["bool-coercion", "int-coercion", "non-z-time"],
)
def test_deployment_recheck_served_proof_rejects_lexical_or_type_drift(
    mutation,
) -> None:
    payload = deployment_recheck_payload()
    mutation(payload)
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentRecheckClient(payload)  # type: ignore[assignment]

    with pytest.raises(RpcCallError):
        service.capture_deployment_recheck_served_proof(
            request_id=str(payload["owner_request_id"]),
            owner_challenge=str(payload["owner_challenge"]),
            recheck_id=str(payload["recheck_id"]),
            fresh_challenge=str(payload["fresh_challenge"]),
            original_server_instance_id=str(payload["original_server_instance_id"]),
            original_fact_generation=11,
            original_execution_facts_canonical_sha256=str(
                payload["original_execution_facts_canonical_sha256"]
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "allow_cached_replay"),
    [
        (lambda value: value.update(cache_replayed=False), True),
        (lambda value: value.update(cache_replayed=True), False),
        (lambda value: value.update(served_fact_generation=12), True),
        (
            lambda value: value.update(
                served_at_utc=(datetime.now(timezone.utc) - timedelta(minutes=1))
                .isoformat()
                .replace("+00:00", "Z")
            ),
            True,
        ),
    ],
    ids=[
        "non-cache-response",
        "caller-did-not-allow-cache",
        "served-generation-mismatch",
        "stale-served-proof",
    ],
)
def test_deployment_recheck_stale_capture_requires_complete_replay_proof(
    mutation,
    allow_cached_replay: bool,
) -> None:
    payload = deployment_recheck_payload()
    payload["captured_at_utc"] = (
        (datetime.now(timezone.utc) - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    payload["cache_replayed"] = True
    mutation(payload)
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentRecheckClient(payload)  # type: ignore[assignment]

    with pytest.raises(RpcCallError, match="freshness window"):
        service.capture_deployment_recheck_facts(
            request_id=str(payload["owner_request_id"]),
            owner_challenge=str(payload["owner_challenge"]),
            recheck_id=str(payload["recheck_id"]),
            fresh_challenge=str(payload["fresh_challenge"]),
            original_server_instance_id=str(payload["original_server_instance_id"]),
            original_fact_generation=11,
            original_execution_facts_canonical_sha256=str(
                payload["original_execution_facts_canonical_sha256"]
            ),
            allow_cached_replay=allow_cached_replay,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(unexpected=True), "fields are invalid"),
        (
            lambda value: value.update(owner_request_id="request-wrong-0001"),
            "owner binding is invalid",
        ),
        (
            lambda value: value.update(fresh_challenge="different-fresh-challenge"),
            "owner binding is invalid",
        ),
        (
            lambda value: value.update(
                original_server_instance_id="windows-other-instance"
            ),
            "owner binding is invalid",
        ),
        (
            lambda value: value.update(expected_generation=12),
            "owner binding is invalid",
        ),
        (
            lambda value: value.update(
                original_execution_facts_canonical_sha256="d" * 64
            ),
            "owner binding is invalid",
        ),
        (
            lambda value: value.update(
                captured_at_utc=(datetime.now(timezone.utc) - timedelta(minutes=1))
                .isoformat()
                .replace("+00:00", "Z")
            ),
            "freshness window",
        ),
        (
            lambda value: value["admission"].update(  # type: ignore[union-attr]
                send_order_frozen=False
            ),
            "fence is invalid",
        ),
        (
            lambda value: value.update(execution_facts_canonical_sha256="e" * 64),
            "execution facts hash mismatch",
        ),
    ],
    ids=[
        "extra-field",
        "request-echo",
        "fresh-challenge-echo",
        "original-server-echo",
        "generation-echo",
        "original-hash-echo",
        "stale-time",
        "fence-open",
        "facts-hash",
    ],
)
def test_deployment_recheck_client_fails_closed(
    mutation,
    message: str,
) -> None:
    payload = deployment_recheck_payload()
    mutation(payload)
    service = VnpyRpcService()
    service.started = True
    service.client = DeploymentRecheckClient(payload)  # type: ignore[assignment]

    with pytest.raises((RpcCallError, ValueError), match=message):
        service.capture_deployment_recheck_facts(
            request_id="request-rpc-snapshot-0001",
            owner_challenge="rpc-snapshot-challenge-0001",
            recheck_id=f"deployment-recheck-{'c' * 64}",
            fresh_challenge="fresh-rpc-recheck-challenge-0001",
            original_server_instance_id="windows-rpc-test-instance",
            original_fact_generation=11,
            original_execution_facts_canonical_sha256=str(
                deployment_recheck_payload()[
                    "original_execution_facts_canonical_sha256"
                ]
            ),
        )


def test_rpc_call_timeout_rebuilds_client_before_next_request(monkeypatch) -> None:
    service = VnpyRpcService()
    client = TimeoutRestartClient()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._last_probe_at = 123.0
    service._last_probe_connected = False

    def start() -> None:
        service.started = True
        service.client = HealthyClient()  # type: ignore[assignment]
        service.last_error = None

    monkeypatch.setattr(VnpyRpcService, "start", lambda _service: start())

    with pytest.raises(RpcTimeoutError):
        service.call("get_all_contracts", timeout=1)

    assert client.stopped is True
    assert client.joined is True
    assert isinstance(service.client, HealthyClient)
    assert service.started is True
    assert service._last_probe_at == 0.0
    assert service._last_probe_connected is None


def test_rpc_call_error_is_normalized() -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = BrokenClient()  # type: ignore[assignment]

    with pytest.raises(RpcCallError):
        service.call("get_all_contracts", timeout=1)


def test_rpc_call_reconnects_and_retries_idempotent_bad_client_state(
    monkeypatch,
) -> None:
    service = VnpyRpcService()
    client = BadStateClient()
    service.started = True
    service.client = client  # type: ignore[assignment]

    def start() -> None:
        service.started = True
        service.client = HealthyClient()  # type: ignore[assignment]

    monkeypatch.setattr(VnpyRpcService, "start", lambda _service: start())

    result = service.call("get_all_contracts", timeout=1)

    assert result == [{"symbol": "rb2610"}]
    assert client.stopped is True
    assert client.joined is True
    assert service.last_error is None


def test_rpc_call_rebuilds_but_does_not_retry_non_idempotent_bad_client_state(
    monkeypatch,
) -> None:
    service = VnpyRpcService()
    client = BadStateClient()
    service.started = True
    service.client = client  # type: ignore[assignment]

    def start() -> None:
        service.started = True
        service.client = HealthyClient()  # type: ignore[assignment]

    monkeypatch.setattr(VnpyRpcService, "start", lambda _service: start())

    with pytest.raises(RpcCallError) as exc_info:
        service.call("send_order", object(), "CTP", timeout=1)

    assert client.stopped is True
    assert client.joined is True
    assert exc_info.value.detail["client_rebuilt"] is True
    assert exc_info.value.detail["retry_suppressed"] == "non_idempotent_method"


def test_rpc_restart_client_clears_state_when_start_fails(monkeypatch) -> None:
    service = VnpyRpcService()
    client = TimeoutRestartClient()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._last_probe_at = 123.0
    service._last_probe_connected = False

    def start() -> None:
        service.started = False
        service.client = None
        raise RpcUnavailableError("start failed")

    monkeypatch.setattr(VnpyRpcService, "start", lambda _service: start())

    with pytest.raises(RpcUnavailableError):
        service._restart_client()

    assert client.stopped is True
    assert client.joined is True
    assert service.started is False
    assert service.client is None
    assert service._last_probe_at == 0.0
    assert service._last_probe_connected is None


def test_rpc_status_probe_marks_connection_false_on_probe_failure(monkeypatch) -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = TimeoutClient()  # type: ignore[assignment]
    monkeypatch.setattr(
        VnpyRpcService,
        "start",
        lambda _service: (_ for _ in ()).throw(RpcUnavailableError("start failed")),
    )

    status = service.status(probe=True)

    assert status["connected"] is False
    assert status["last_error"]


def test_rpc_status_probe_recovers_after_single_timeout(monkeypatch) -> None:
    service = VnpyRpcService()
    client = FlakyProbeClient()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._probe_ttl_seconds = 0

    def start() -> None:
        service.started = True
        service.client = client  # type: ignore[assignment]

    monkeypatch.setattr(VnpyRpcService, "start", lambda _service: start())

    failed = service.status(probe=True)
    recovered = service.status(probe=True)

    assert failed["connected"] is False
    assert recovered["connected"] is True
    assert recovered["last_error"] is None
    assert service.started is True
    assert client.calls == 2


def test_rpc_status_probe_uses_ttl() -> None:
    service = VnpyRpcService()
    client = ProbeClient()
    service.started = True
    service.client = client  # type: ignore[assignment]

    service.status(probe=True)
    service.status(probe=True)

    assert client.calls == 1


def test_handle_tick_event_saves_computed_vt_symbol() -> None:
    service = VnpyRpcService()
    service._market_subscriptions.add("UNIT999.SHFE")

    service.handle_event("", TickEvent())

    tick = memory_store.get_tick("UNIT999.SHFE")
    assert tick
    assert tick["vt_symbol"] == "UNIT999.SHFE"
    assert tick["last_price"] == 3126


def test_handle_tick_event_ignores_unsubscribed_symbol() -> None:
    service = VnpyRpcService()
    memory_store.delete_tick("UNIT999.SHFE")

    service.handle_event("", TickEvent())

    assert memory_store.get_tick("UNIT999.SHFE") is None


def test_handle_tick_event_enqueues_unsubscribed_symbol_for_persistence(
    monkeypatch,
) -> None:
    saved: list[dict] = []
    monkeypatch.setattr(
        "app.services.vnpy_rpc_service.tick_persistence_service.enqueue_tick",
        saved.append,
    )
    service = VnpyRpcService()

    service.handle_event("", TickEvent())

    assert saved[0]["vt_symbol"] == "UNIT999.SHFE"


def test_handle_tick_event_fans_out_copy_without_market_subscription() -> None:
    observed: list[dict] = []
    service = VnpyRpcService()
    service.bind_readonly_tick_listener(observed.append)

    service.handle_event("", TickEvent())

    assert observed == [
        {
            "symbol": "UNIT999",
            "exchange": "SHFE",
            "last_price": 3126,
            "vt_symbol": "UNIT999.SHFE",
        }
    ]


def test_readonly_tick_listener_failure_isolated_from_existing_tick_path() -> None:
    service = VnpyRpcService()
    service._market_subscriptions.add("UNIT999.SHFE")
    service.bind_readonly_tick_listener(
        lambda _payload: (_ for _ in ()).throw(RuntimeError("listener failed"))
    )

    service.handle_event("", TickEvent())

    assert memory_store.get_tick("UNIT999.SHFE") is not None


def test_readonly_tick_listener_binding_is_prestart_and_idempotent() -> None:
    service = VnpyRpcService()

    def listener(_payload) -> None:
        return None

    service.bind_readonly_tick_listener(listener)
    service.bind_readonly_tick_listener(listener)
    assert service._readonly_tick_listeners == [listener]

    service.started = True
    with pytest.raises(ValueError, match="before start"):
        service.bind_readonly_tick_listener(lambda _payload: None)


def test_c_fast_terminal_ticket_rejects_callback_generation_drift() -> None:
    service = VnpyRpcService()
    owner = object()
    capability = service.bind_c_fast_terminal_publication_owner(owner)
    ticket = service.prepare_c_fast_terminal_publication(
        capability,
        session_id=f"cfast-shakedown-{'a' * 32}",
    )

    service.handle_event("", TradeEvent())

    with pytest.raises(RpcCallError, match="generation drifted"):
        service.publish_c_fast_terminal_archive(
            capability,
            ticket,
            session_id=f"cfast-shakedown-{'a' * 32}",
            publisher=lambda generation: generation,
        )


def test_c_fast_terminal_ticket_rejects_reconnect_generation_drift() -> None:
    service = VnpyRpcService()
    owner = object()
    capability = service.bind_c_fast_terminal_publication_owner(owner)
    session_id = f"cfast-shakedown-{'e' * 32}"
    ticket = service.prepare_c_fast_terminal_publication(
        capability,
        session_id=session_id,
    )

    service._record_connected_generation(datetime.now(timezone.utc))

    with pytest.raises(RpcCallError, match="generation drifted"):
        service.publish_c_fast_terminal_archive(
            capability,
            ticket,
            session_id=session_id,
            publisher=lambda generation: generation,
        )


def test_c_fast_terminal_publisher_detects_callback_mutation_before_commit() -> None:
    service = VnpyRpcService()
    owner = object()
    capability = service.bind_c_fast_terminal_publication_owner(owner)
    session_id = f"cfast-shakedown-{'b' * 32}"
    ticket = service.prepare_c_fast_terminal_publication(
        capability,
        session_id=session_id,
    )

    with pytest.raises(RpcCallError, match="changed before commit"):
        service.publish_c_fast_terminal_archive(
            capability,
            ticket,
            session_id=session_id,
            publisher=lambda _generation: service.handle_event("", TradeEvent()),
        )


def test_c_fast_terminal_committer_blocks_reentrant_callback_mutation() -> None:
    service = VnpyRpcService()
    owner = object()
    capability = service.bind_c_fast_terminal_publication_owner(owner)
    session_id = f"cfast-shakedown-{'f' * 32}"
    ticket = service.prepare_c_fast_terminal_publication(
        capability,
        session_id=session_id,
    )

    with pytest.raises(RpcCallError, match="reentrant terminal mutation"):
        service.publish_c_fast_terminal_archive(
            capability,
            ticket,
            session_id=session_id,
            publisher=lambda _generation: "candidate",
            committer=lambda _candidate: service.handle_event("", TradeEvent()),
        )


def test_c_fast_terminal_publication_does_not_deadlock_reconnect_callback() -> None:
    service = VnpyRpcService()
    owner = object()
    capability = service.bind_c_fast_terminal_publication_owner(owner)
    session_id = f"cfast-shakedown-{'d' * 32}"
    ticket = service.prepare_c_fast_terminal_publication(
        capability,
        session_id=session_id,
    )
    publisher_started = Event()
    reconnect_holds_call_lock = Event()
    callback_joined = Event()
    outcomes: list[object] = []

    def publisher(_generation: int) -> str:
        publisher_started.set()
        assert reconnect_holds_call_lock.wait(2)
        with service._call_lock:
            return "candidate"

    def publication() -> None:
        try:
            outcomes.append(
                service.publish_c_fast_terminal_archive(
                    capability,
                    ticket,
                    session_id=session_id,
                    publisher=publisher,
                    committer=lambda value: value,
                )
            )
        except Exception as exc:
            outcomes.append(exc)

    def reconnect_joining_callback() -> None:
        assert publisher_started.wait(2)
        with service._call_lock:
            reconnect_holds_call_lock.set()
            callback = Thread(target=lambda: service.handle_event("", TradeEvent()))
            callback.start()
            callback.join(2)
            assert not callback.is_alive()
            callback_joined.set()

    publish_thread = Thread(target=publication)
    reconnect_thread = Thread(target=reconnect_joining_callback)
    publish_thread.start()
    reconnect_thread.start()
    publish_thread.join(3)
    reconnect_thread.join(3)

    assert not publish_thread.is_alive()
    assert not reconnect_thread.is_alive()
    assert callback_joined.is_set()
    assert len(outcomes) == 1
    assert isinstance(outcomes[0], RpcCallError)
    assert "changed before commit" in str(outcomes[0])


def test_c_fast_terminal_capability_is_owner_bound_and_ticket_one_shot() -> None:
    service = VnpyRpcService()
    owner = object()
    capability = service.bind_c_fast_terminal_publication_owner(owner)
    assert service.bind_c_fast_terminal_publication_owner(owner) is capability
    with pytest.raises(ValueError, match="already bound"):
        service.bind_c_fast_terminal_publication_owner(object())
    session_id = f"cfast-shakedown-{'c' * 32}"
    ticket = service.prepare_c_fast_terminal_publication(
        capability,
        session_id=session_id,
    )

    assert (
        service.publish_c_fast_terminal_archive(
            capability,
            ticket,
            session_id=session_id,
            publisher=lambda generation: generation,
        )
        == 0
    )
    with pytest.raises(ValueError, match="ticket is invalid"):
        service.publish_c_fast_terminal_archive(
            capability,
            ticket,
            session_id=session_id,
            publisher=lambda generation: generation,
        )


def test_unsubscribe_market_removes_subscription_and_tick() -> None:
    service = VnpyRpcService()
    service._market_subscriptions.add("UNIT999.SHFE")
    memory_store.save_tick("UNIT999.SHFE", {"vt_symbol": "UNIT999.SHFE"})

    result = service.unsubscribe_market("UNIT999", "SHFE")

    assert result["subscribed"] is False
    assert result["vt_symbol"] == "UNIT999.SHFE"
    assert memory_store.get_tick("UNIT999.SHFE") is None
    assert "UNIT999.SHFE" not in service._market_subscriptions
