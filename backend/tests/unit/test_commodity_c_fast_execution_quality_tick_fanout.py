from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from threading import Event, Thread

import pytest

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.services.commodity_c_fast_execution_quality_horizon_worker import (
    PreverifiedTickHorizonWorker,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    CreateOnlyExecutionQualityJournal,
    OfflineExecutionQualitySidecar,
)
from app.services.commodity_c_fast_execution_quality_tick_fanout import (
    CFastExecutionQualityTickFanoutError,
    CommodityCFastExecutionQualityTickFanout,
)
from app.services.commodity_c_fast_shadow_common import sha256_json
from app.services.vnpy_rpc_service import VnpyRpcService


ROOT = Path(__file__).resolve().parents[3]
SIDECAR_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py"
)
SCORER_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py"
)
NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


def _load_test_helpers(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SIDECAR = _load_test_helpers("tick_fanout_sidecar_helpers", SIDECAR_TEST_PATH)
SCORER = _load_test_helpers("tick_fanout_scorer_helpers", SCORER_TEST_PATH)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _receipt(
    *,
    exact_contracts: list[str] | None = None,
    expires_at: datetime | None = None,
) -> CFastExecutionQualityRuntimeRevalidationDTO:
    core = {
        "schema_version": (
            "commodity_c_fast_execution_quality_runtime_revalidation_v1"
        ),
        "trigger": "startup",
        "revalidated_at_utc": NOW.isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (expires_at or NOW + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
        "exact_contracts": exact_contracts or ["SHFE.cu2612"],
        "signed_p0_acceptance_sha256": "1" * 64,
        "collection_admission_sha256": "2" * 64,
        "execution_policy_sha256": "3" * 64,
        "signed_snapshot_sha256": "4" * 64,
        "virtual_intent_plan_sha256": "5" * 64,
        "contract_spec_set_sha256": "6" * 64,
        "custody_binding_sha256": "7" * 64,
        "verified_signer_domains": {
            "signed_p0_acceptance": ["8" * 64],
            "collection_admission": ["9" * 64],
            "execution_policy": ["a" * 64],
            "signed_snapshot": ["b" * 64],
            "virtual_intent_plan": ["c" * 64],
            "contract_spec_set": ["d" * 64],
            "custody_binding": ["e" * 64],
        },
        "p0_acceptance_state": "VERIFIED",
        "collection_admission_state": "VERIFIED",
        "execution_policy_state": "VERIFIED",
        "signed_snapshot_state": "VERIFIED",
        "virtual_intent_plan_state": "VERIFIED",
        "contract_spec_state": "VERIFIED",
        "custody_state": "VERIFIED",
        **FALSE_AUTHORITY,
    }
    return CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
        {**core, "receipt_sha256": _sha256_json(core)}
    )


def _worker(tmp_path: Path) -> PreverifiedTickHorizonWorker:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "fanout-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    sidecar = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(root),
        clock=lambda: NOW,
    )
    worker = PreverifiedTickHorizonWorker(sidecar)
    plan = SIDECAR.plan()
    policy = SCORER.policy()
    worker.register_preverified_plan(
        preverified_plan=plan,
        source_snapshot_receipt_sha256=plan.snapshot_hash,
        score_policy=policy,
        score_policy_hash=sha256_json(policy.model_dump(mode="json")),
        contract_specs=(SCORER.contract_spec(),),
    )
    return worker


def _enabled() -> Settings:
    return Settings(commodity_c_fast_execution_quality_runtime_enabled=True)


def _fanout(
    tmp_path: Path,
    *,
    clock=None,
) -> tuple[CommodityCFastExecutionQualityTickFanout, PreverifiedTickHorizonWorker]:
    worker = _worker(tmp_path)
    subject = CommodityCFastExecutionQualityTickFanout(
        settings=_enabled(),
        clock=clock or (lambda: NOW),
        queue_size=8,
        session_id="fanout-test-session",
    )
    subject.bind_preverified_subscription(
        worker=worker,
        revalidation_receipt=_receipt(),
    )
    assert subject.start()["fanout_state"] == (
        "RUNNING_READONLY_PREVERIFIED_EXACT_CONTRACTS"
    )
    return subject, worker


def _tick(
    *,
    symbol: str = "cu2612",
    exchange: str = "SHFE",
    vt_symbol: str | None = None,
    bad_depth: bool = False,
) -> dict:
    return {
        "symbol": symbol,
        "exchange": exchange,
        "vt_symbol": vt_symbol or f"{symbol}.{exchange}",
        "datetime": (NOW - timedelta(milliseconds=100)).isoformat(),
        "volume": 100,
        **{
            f"bid_price_{level}": (
                float("nan") if bad_depth and level == 1 else 1_001 - level
            )
            for level in range(1, 6)
        },
        **{f"ask_price_{level}": 1_001 + level for level in range(1, 6)},
        **{f"bid_volume_{level}": 2.0 for level in range(1, 6)},
        **{f"ask_volume_{level}": 2.0 for level in range(1, 6)},
    }


def test_default_off_never_starts_or_delivers(tmp_path: Path) -> None:
    subject = CommodityCFastExecutionQualityTickFanout(
        settings=Settings(),
        clock=lambda: NOW,
        session_id="fanout-test-default-off",
    )

    status = subject.start()
    offered = subject.offer_tick(_tick(vt_symbol="spliced2612.SHFE"))

    assert status["fanout_state"] == "DISABLED_DEFAULT_OFF"
    assert status["worker_thread_running"] is False
    assert offered["offer_state"] == "IGNORED_DEFAULT_OFF"
    assert subject.status()["blocked_fail_closed"] is False
    assert offered["orders_sent"] == 0
    assert all(offered[field] is False for field in FALSE_AUTHORITY)


def test_subscription_requires_exact_worker_receipt_contract_join(
    tmp_path: Path,
) -> None:
    worker = _worker(tmp_path)
    subject = CommodityCFastExecutionQualityTickFanout(
        settings=_enabled(),
        clock=lambda: NOW,
        session_id="fanout-test-mismatch",
    )

    with pytest.raises(
        CFastExecutionQualityTickFanoutError,
        match="EXACT_CONTRACT_SUBSCRIPTION_MISMATCH",
    ):
        subject.bind_preverified_subscription(
            worker=worker,
            revalidation_receipt=_receipt(exact_contracts=["SHFE.ag2612"]),
        )

    assert subject.status()["local_exact_contract_subscription_built"] is False


def test_real_tick_publication_reaches_preverified_worker_readonly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject, worker = _fanout(tmp_path)
    service = VnpyRpcService()
    service.bind_readonly_tick_listener(subject.offer_tick)
    monkeypatch.setattr(
        "app.services.vnpy_rpc_service.tick_persistence_service.enqueue_tick",
        lambda _payload: False,
    )

    class TickEvent:
        type = "eTick.cu2612.SHFE"
        data = _tick()

    service.handle_event("", TickEvent())
    subject.wait_until_idle()

    status = subject.status()
    worker_status = worker.status()
    assert status["delivered_ticks"] == 1
    assert status["subscribed_exact_contracts"] == ["SHFE.cu2612"]
    assert status["external_market_subscription_requested"] is False
    assert worker_status["exact_contract_subscription_frozen"] is True
    assert worker_status["frozen_exact_contracts"] == ["SHFE.cu2612"]
    assert worker_status["snapshot_record_count"] == 1
    assert status["runtime_active"] is False
    assert status["execution_quality_implemented"] is False
    assert all(status[field] is False for field in FALSE_AUTHORITY)
    assert subject.stop()["worker_thread_running"] is False


def test_outside_contract_is_filtered_before_worker(tmp_path: Path) -> None:
    subject, worker = _fanout(tmp_path)

    result = subject.offer_tick(_tick(symbol="ag2612"))
    subject.wait_until_idle()

    assert result["offer_state"] == "IGNORED_OUTSIDE_EXACT_CONTRACTS"
    assert subject.status()["ignored_outside_exact_contracts"] == 1
    assert worker.status()["snapshot_record_count"] == 0
    subject.stop()


def test_identity_splice_and_invalid_subscribed_tick_fail_closed(
    tmp_path: Path,
) -> None:
    spliced, first_worker = _fanout(tmp_path / "splice")
    result = spliced.offer_tick(_tick(vt_symbol="ag2612.SHFE"))

    assert result["offer_state"] == "BLOCKED_FAIL_CLOSED"
    assert spliced.status()["last_error"] == ("TICK_EXACT_CONTRACT_IDENTITY_SPLICE")
    assert first_worker.status()["snapshot_record_count"] == 0
    spliced.stop()

    invalid, second_worker = _fanout(tmp_path / "invalid")
    assert invalid.offer_tick(_tick(bad_depth=True))["offer_state"] == (
        "ENQUEUED_PREVERIFIED_EXACT_CONTRACT"
    )
    invalid.wait_until_idle()

    assert invalid.status()["fanout_state"] == "BLOCKED_FAIL_CLOSED"
    assert invalid.status()["last_error"] == "TICK_DECIMAL_FIELD_INVALID"
    assert second_worker.status()["snapshot_record_count"] == 0
    invalid.stop()


def test_expiry_blocks_before_queue_or_worker_write(tmp_path: Path) -> None:
    now = [NOW]
    subject, worker = _fanout(tmp_path, clock=lambda: now[0])
    now[0] = NOW + timedelta(minutes=6)

    result = subject.offer_tick(_tick())

    assert result["offer_state"] == "BLOCKED_FAIL_CLOSED"
    assert subject.status()["last_error"] == "REVALIDATION_RECEIPT_EXPIRED"
    assert worker.status()["snapshot_record_count"] == 0
    subject.stop()


def test_worker_contract_drift_blocks_before_tick_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject, worker = _fanout(tmp_path)
    original_status = worker.status

    def drifted_status() -> dict:
        return {
            **original_status(),
            "accepted_exact_contracts": [
                "SHFE.ag2612",
                "SHFE.cu2612",
            ],
        }

    monkeypatch.setattr(worker, "status", drifted_status)
    subject.offer_tick(_tick())
    subject.wait_until_idle()

    assert subject.status()["last_error"] == ("PREVERIFIED_WORKER_CONTRACT_SET_DRIFT")
    assert worker._sidecar.recover().snapshots == ()
    subject.stop()


def test_stop_between_offer_checks_cannot_enqueue_after_worker_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject, worker = _fanout(tmp_path)
    route_entered = Event()
    release_route = Event()
    original_route = subject._route_exact_contract

    def paused_route(payload):
        route_entered.set()
        assert release_route.wait(timeout=2)
        return original_route(payload)

    monkeypatch.setattr(subject, "_route_exact_contract", paused_route)
    offered: list[dict[str, object]] = []
    publisher = Thread(target=lambda: offered.append(subject.offer_tick(_tick())))
    publisher.start()
    assert route_entered.wait(timeout=2)

    stopped = subject.stop()
    release_route.set()
    publisher.join(timeout=2)

    assert not publisher.is_alive()
    assert offered[0]["offer_state"] == "REJECTED_FANOUT_NOT_RUNNING"
    assert stopped["worker_thread_running"] is False
    assert subject.status()["queue_size"] == 0
    assert subject.status()["enqueued_ticks"] == 0
    assert worker.status()["snapshot_record_count"] == 0


def test_queue_full_blocks_only_fanout_without_blocking_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker(tmp_path)
    started = Event()
    release = Event()
    original_accept = worker.accept_preverified_tick

    def slow_accept(snapshot):
        started.set()
        assert release.wait(timeout=2)
        return original_accept(snapshot)

    monkeypatch.setattr(worker, "accept_preverified_tick", slow_accept)
    subject = CommodityCFastExecutionQualityTickFanout(
        settings=_enabled(),
        clock=lambda: NOW,
        queue_size=1,
        session_id="fanout-test-queue-full",
    )
    subject.bind_preverified_subscription(
        worker=worker,
        revalidation_receipt=_receipt(),
    )
    subject.start()

    assert subject.offer_tick(_tick())["offer_state"] == (
        "ENQUEUED_PREVERIFIED_EXACT_CONTRACT"
    )
    assert started.wait(timeout=2)
    assert subject.offer_tick(_tick())["offer_state"] == (
        "ENQUEUED_PREVERIFIED_EXACT_CONTRACT"
    )
    overflow = subject.offer_tick(_tick())

    assert overflow["offer_state"] == "BLOCKED_FAIL_CLOSED"
    assert subject.status()["last_error"] == "TICK_FANOUT_QUEUE_FULL"
    assert subject.status()["tick_input_accepting"] is False
    release.set()
    subject.wait_until_idle()
    assert subject.status()["delivered_ticks"] == 1
    subject.stop()


def test_fanout_module_has_no_source_connection_or_trading_capability() -> None:
    service_path = (
        ROOT / "backend/app/services/commodity_c_fast_execution_quality_tick_fanout.py"
    )
    tree = ast.parse(service_path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.add(module)
            imports.update(f"{module}.{alias.name}" for alias in node.names)

    forbidden_imports = {
        "app.services.commodity_simnow",
        "app.services.market_data_service",
        "app.services.tick_persistence",
        "app.services.trade_service",
        "app.services.vnpy_rpc_service",
        "psycopg",
        "questdb",
        "vnpy",
    }
    forbidden_names = {
        "TradeService",
        "account",
        "cancel_order",
        "gateway",
        "position",
        "rpc_service",
        "send_order",
        "subscribe_market",
    }

    assert imports.isdisjoint(forbidden_imports)
    assert not any(
        (isinstance(node, ast.Name) and node.id in forbidden_names)
        or (isinstance(node, ast.Attribute) and node.attr in forbidden_names)
        for node in ast.walk(tree)
    )
