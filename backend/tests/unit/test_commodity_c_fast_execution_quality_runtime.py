from __future__ import annotations

import ast
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.services.commodity_c_fast_execution_quality_runtime import (
    CommodityCFastExecutionQualityRuntime,
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


def revalidation(
    trigger: str,
    observed_at_utc: datetime,
    *,
    expires_at: datetime | None = None,
) -> CFastExecutionQualityRuntimeRevalidationDTO:
    core = {
        "schema_version": (
            "commodity_c_fast_execution_quality_runtime_revalidation_v1"
        ),
        "trigger": trigger,
        "revalidated_at_utc": observed_at_utc.isoformat().replace(
            "+00:00", "Z"
        ),
        "valid_until_utc": (
            expires_at or observed_at_utc + timedelta(minutes=5)
        ).isoformat().replace("+00:00", "Z"),
        "exact_contracts": ["SHFE.ag2612", "SHFE.cu2612"],
        "signed_p0_acceptance_sha256": "1" * 64,
        "collection_admission_sha256": "2" * 64,
        "execution_policy_sha256": "3" * 64,
        "signed_snapshot_sha256": "4" * 64,
        "virtual_intent_plan_sha256": "5" * 64,
        "contract_spec_set_sha256": "6" * 64,
        "custody_binding_sha256": "7" * 64,
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


def enabled_settings() -> Settings:
    return Settings(
        commodity_c_fast_execution_quality_runtime_enabled=True
    )


def test_default_off_does_not_call_verifier_or_acquire_capability() -> None:
    calls: list[str] = []
    service = CommodityCFastExecutionQualityRuntime(
        settings=Settings(),
        clock=lambda: NOW,
    )
    service.bind_full_revalidation_verifier(
        lambda trigger, observed: calls.append(trigger)
        or revalidation(trigger, observed)
    )

    status = service.start()

    assert calls == []
    assert status["runtime_state"] == "DISABLED_DEFAULT_OFF"
    assert status["configured_enabled"] is False
    assert status["execution_quality_implemented"] is False
    assert status["full_revalidation_complete"] is False
    assert status["orders_sent"] == 0
    assert status["positions_modified"] == 0
    assert all(status[key] is False for key in FALSE_AUTHORITY)
    assert status["denied_capabilities"] == [
        "account",
        "cancel_order",
        "gateway",
        "position",
        "rpc",
        "send_order",
        "trade_service",
    ]


def test_enabled_without_full_verifier_isolated_and_fail_closed() -> None:
    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )

    status = service.start()

    assert status["runtime_state"] == (
        "BLOCKED_FULL_REVALIDATION_VERIFIER_NOT_BOUND"
    )
    assert status["last_error"] == "FULL_REVALIDATION_VERIFIER_NOT_BOUND"
    assert status["full_revalidation_complete"] is False
    assert status["execution_quality_implemented"] is False
    assert all(value is False for value in status["capabilities"].values())


def test_each_lifecycle_entry_performs_full_revalidation() -> None:
    calls: list[tuple[str, datetime]] = []

    def verify(trigger: str, observed: datetime):
        calls.append((trigger, observed))
        return revalidation(trigger, observed)

    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )
    service.bind_full_revalidation_verifier(verify)

    for generation, operation in enumerate(
        (service.start, service.reload, service.recover),
        start=1,
    ):
        status = operation()
        assert status["runtime_state"] == (
            "REVALIDATED_FOUNDATION_ONLY_TICK_RUNTIME_NOT_BUILT"
        )
        assert status["full_revalidation_complete"] is True
        assert status["revalidation_generation"] == generation
        assert status["runtime_active"] is False
        assert status["execution_quality_implemented"] is False
        assert status["exact_contracts"] == [
            "SHFE.ag2612",
            "SHFE.cu2612",
        ]
        assert status["capabilities"] == {
            "full_revalidation_verifier_bound": True,
            "tick_input_bound": False,
            "tick_subscription_built": False,
            "horizon_worker_built": False,
            "durable_sidecar_runtime_bound": False,
            "readonly_repository_bound": False,
            "questdb_evidence_adapter_bound": False,
        }
        assert set(status["revalidation_checks"].values()) == {"VERIFIED"}
        assert status["revalidation_bindings_sha256"] == {
            "signed_p0_acceptance": "1" * 64,
            "collection_admission": "2" * 64,
            "execution_policy": "3" * 64,
            "signed_snapshot": "4" * 64,
            "virtual_intent_plan": "5" * 64,
            "contract_spec_set": "6" * 64,
            "custody_binding": "7" * 64,
        }

    assert [trigger for trigger, _ in calls] == [
        "startup",
        "reload",
        "recovery",
    ]


def test_spliced_or_expired_receipt_blocks_only_this_runtime() -> None:
    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )

    def wrong_trigger(_trigger: str, observed: datetime):
        return revalidation("reload", observed)

    service.bind_full_revalidation_verifier(wrong_trigger)
    status = service.start()
    assert status["runtime_state"] == "BLOCKED_FULL_REVALIDATION_FAILED"
    assert status["last_error"] == "REVALIDATION_TRIGGER_MISMATCH"
    assert status["orders_sent"] == 0
    assert all(status[key] is False for key in FALSE_AUTHORITY)

    expired = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )
    expired.bind_full_revalidation_verifier(
        lambda trigger, observed: revalidation(
            trigger,
            observed - timedelta(minutes=10),
            expires_at=observed - timedelta(minutes=5),
        )
    )
    expired_status = expired.start()
    assert expired_status["runtime_state"] == (
        "BLOCKED_FULL_REVALIDATION_FAILED"
    )
    assert expired_status["last_error"] == (
        "REVALIDATION_CLOCK_BINDING_MISMATCH"
    )


def test_receipt_rejects_coercive_authority_and_hash_rewrite() -> None:
    valid = revalidation("startup", NOW).model_dump(mode="json")
    valid["collection_authorized"] = 0
    with pytest.raises(ValidationError):
        CFastExecutionQualityRuntimeRevalidationDTO.model_validate(valid)

    rewritten = revalidation("startup", NOW).model_dump(mode="json")
    rewritten["signed_snapshot_sha256"] = "9" * 64
    with pytest.raises(ValidationError, match="receipt_sha256 mismatch"):
        CFastExecutionQualityRuntimeRevalidationDTO.model_validate(rewritten)


def test_runtime_revalidates_an_already_constructed_receipt_instance() -> None:
    candidate = revalidation("startup", NOW)
    object.__setattr__(candidate, "signed_snapshot_sha256", "9" * 64)
    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )
    service.bind_full_revalidation_verifier(
        lambda _trigger, _observed: candidate
    )

    status = service.start()

    assert status["runtime_state"] == "BLOCKED_FULL_REVALIDATION_FAILED"
    assert status["last_error"] == "ValidationError"
    assert status["full_revalidation_complete"] is False
    assert status["revalidation_receipt_sha256"] is None
    assert all(status[key] is False for key in FALSE_AUTHORITY)


def test_invalid_runtime_clock_is_contained() -> None:
    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW.replace(tzinfo=None),
    )
    service.bind_full_revalidation_verifier(revalidation)

    status = service.start()

    assert status["runtime_state"] == "BLOCKED_FULL_REVALIDATION_FAILED"
    assert status["last_error"] == "RUNTIME_CLOCK_MUST_USE_UTC"
    assert status["execution_quality_implemented"] is False
    assert all(status[key] is False for key in FALSE_AUTHORITY)


def test_verifier_failure_is_contained_and_retryable_on_reload() -> None:
    should_fail = True

    def verify(trigger: str, observed: datetime):
        nonlocal should_fail
        if should_fail:
            raise RuntimeError("external verifier unavailable")
        return revalidation(trigger, observed)

    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )
    service.bind_full_revalidation_verifier(verify)

    failed = service.start()
    assert failed["runtime_state"] == "BLOCKED_FULL_REVALIDATION_FAILED"
    assert failed["last_error"] == "RuntimeError"

    should_fail = False
    recovered = service.reload()
    assert recovered["runtime_state"] == (
        "REVALIDATED_FOUNDATION_ONLY_TICK_RUNTIME_NOT_BUILT"
    )
    assert recovered["revalidation_generation"] == 1


def test_stop_drops_receipt_and_preserves_zero_authority() -> None:
    service = CommodityCFastExecutionQualityRuntime(
        settings=enabled_settings(),
        clock=lambda: NOW,
    )
    service.bind_full_revalidation_verifier(revalidation)
    assert service.start()["full_revalidation_complete"] is True

    stopped = service.stop()

    assert stopped["runtime_state"] == "STOPPED_NO_CAPABILITY"
    assert stopped["lifecycle_started"] is False
    assert stopped["runtime_active"] is False
    assert stopped["full_revalidation_complete"] is False
    assert stopped["revalidation_receipt_sha256"] is None
    assert all(stopped[key] is False for key in FALSE_AUTHORITY)


def test_runtime_foundation_has_no_market_or_trading_dependencies() -> None:
    service_path = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "services"
        / "commodity_c_fast_execution_quality_runtime.py"
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
    }
    forbidden_runtime_names = {
        "TradeService",
        "account",
        "cancel_order",
        "gateway",
        "position",
        "rpc_service",
        "send_order",
    }

    assert imports.isdisjoint(forbidden_imports)
    assert not any(
        (
            isinstance(node, ast.Name)
            and node.id in forbidden_runtime_names
        )
        or (
            isinstance(node, ast.Attribute)
            and node.attr in forbidden_runtime_names
        )
        for node in ast.walk(tree)
    )
