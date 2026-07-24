from __future__ import annotations

import base64
import copy
import importlib.util
import json
import stat
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import Settings
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO
from app.services.commodity_c_fast_shadow import (
    C_FAST_PRODUCT_SPECS_V1,
    C_FAST_SECTOR_MAP_V1,
    PRODUCTS,
    CommodityCFastShadowService,
    normalize_rpc_contracts,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    formula_target_binding_sha256,
    unsigned_snapshot_payload,
)


PRICES = {
    "ag": 7500.0,
    "al": 20000.0,
    "au": 600.0,
    "bu": 3500.0,
    "cu": 80000.0,
    "rb": 3500.0,
    "ru": 16000.0,
    "sc": 600.0,
    "sp": 6000.0,
    "zn": 25000.0,
}
SIGNS = {
    "ag": (1, 1, 1),
    "al": (1, 0, 0),
    "au": (1, 1, 0),
    "bu": (-1, -1, -1),
    "cu": (1, 1, 1),
    "rb": (-1, 0, 0),
    "ru": (-1, -1, 0),
    "sc": (1, 0, -1),
    "sp": (-1, -1, -1),
    "zn": (1, 0, 0),
}
TEST_NOW = datetime(2026, 9, 1, 2, tzinfo=timezone.utc)
POST_GENESIS_NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
LINKED_NOW = datetime(2026, 10, 1, 2, tzinfo=timezone.utc)


def fixed_clock() -> datetime:
    return TEST_NOW


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def public_key_json(private_key: Ed25519PrivateKey) -> str:
    encoded = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return json.dumps(
        {
            "c-fast-research-1": {
                "public_key_base64": encoded,
                "purpose": "research_snapshot_signer",
            }
        }
    )


def settings(
    tmp_path: Path, private_key: Ed25519PrivateKey, snapshot_path: Path
) -> Settings:
    return Settings(
        commodity_c_fast_shadow_enabled=True,
        commodity_c_fast_shadow_snapshot_path=str(snapshot_path),
        commodity_c_fast_shadow_state_path=str(tmp_path / "state.json"),
        commodity_c_fast_shadow_evidence_path=str(tmp_path / "evidence.jsonl"),
        commodity_c_fast_shadow_trusted_public_keys_json=public_key_json(
            private_key
        ),
    )


def contract_loader(exacts: set[str]) -> dict[str, dict]:
    result = {}
    for exact in exacts:
        _exchange, symbol = exact.split(".", 1)
        product = "".join(character for character in symbol if character.isalpha())
        spec = C_FAST_PRODUCT_SPECS_V1[product]
        result[exact] = {
            "multiplier": spec["multiplier"],
            "price_tick": spec["price_tick"],
        }
    return result


def unsigned_payload(
    *,
    snapshot_id: str = "c-fast-2026-08-genesis",
    source_month: str = "2026-08",
    source_day: str = "2026-08-31",
    execution_day: str = "2026-09-01",
    input_cutoff: str = "2026-08-31T07:00:00Z",
    previous_snapshot_hash: str | None = None,
    previous_targets: dict[str, dict] | None = None,
) -> dict:
    # Synthetic schema fixture only.  The 2612 contracts/LTD are deliberately
    # not presented as a historical or current PIT-main market assertion.
    execution_date = date.fromisoformat(execution_day)
    following_date = execution_date + timedelta(days=1)
    last_trading_day = date(2026, 12, 15)
    dte = (last_trading_day - execution_date).days
    following_dte = (last_trading_day - following_date).days
    row_inputs = {}
    for index, product in enumerate(PRODUCTS):
        signs = SIGNS[product]
        score = sum(signs) / 3.0
        volatility = 0.10 + index * 0.01
        raw = score / max(volatility, 0.05)
        row_inputs[product] = (signs, score, volatility, raw)
    direction = {
        "ag": 1,
        "al": 1,
        "au": 1,
        "bu": -1,
        "cu": 1,
        "rb": -1,
        "ru": -1,
        "sc": -1,
        "sp": -1,
        "zn": 1,
    }
    source_weights = {
        product: 0.10 * direction[product] for product in PRODUCTS
    }
    buffered_weights = {
        product: 0.08 * direction[product] for product in PRODUCTS
    }
    targets = []
    for product in PRODUCTS:
        signs, score, volatility, raw = row_inputs[product]
        spec = C_FAST_PRODUCT_SPECS_V1[product]
        exact = f"{spec['exchange']}.{product}2612"
        previous = (previous_targets or {}).get(product)
        previous_exact = previous["exact_contract"] if previous else None
        previous_quantity = previous["target_quantity"] if previous else 0
        unit_weight = (
            PRICES[product] * spec["multiplier"] / 20_000_000
        )
        quantity = round(buffered_weights[product] / unit_weight)
        targets.append(
            {
                "product": product,
                "sector": C_FAST_SECTOR_MAP_V1[product],
                "trend_21_sign": signs[0],
                "trend_63_sign": signs[1],
                "trend_126_sign": signs[2],
                "source_score": score,
                "vol60_annualized": volatility,
                "raw_risk_score": raw,
                "source_target_weight": source_weights[product],
                "buffered_target_weight": buffered_weights[product],
                "previous_exact_contract": previous_exact,
                "exact_contract": exact,
                "previous_target_quantity": previous_quantity,
                "target_quantity": quantity,
                "reference_open_price": PRICES[product],
                "reference_price_field": "official_open",
                "reference_price_observed_at_utc": (
                    f"{execution_day}T01:01:00Z"
                ),
                "reference_price_source_sha256": "f" * 64,
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "pit_main_exact_contract": exact,
                "pit_main_dte": dte,
                "pit_main_official_last_trading_day": (
                    last_trading_day.isoformat()
                ),
                "pit_main_following_official_day": (
                    following_date.isoformat()
                ),
                "pit_main_following_dte": following_dte,
                "pit_main_target_position_allowed": True,
                "pit_main_roll": bool(previous_exact and previous_exact != exact),
            }
        )
    return {
        "schema_version": "commodity_c_fast_cross_section_neutral_shadow_v1",
        "snapshot_id": snapshot_id,
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "frozen_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "frozen_rule_sha256": (
            "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
        ),
        "mode": "shadow_only",
        "execution_lane": "official_forward",
        "frequency": "MONTHLY",
        "pit_main_definition": "DAILY_PIT_OI_MAIN",
        "trend_horizons_official_days": [21, 63, 126],
        "volatility_lookback_official_days": 60,
        "volatility_floor": 0.05,
        "virtual_nav_cny": 20_000_000,
        "source_month": source_month,
        "source_official_day": source_day,
        "execution_day": execution_day,
        "input_cutoff_at_utc": input_cutoff,
        "snapshot_created_at_utc": f"{execution_day}T01:02:00Z",
        "source_is_month_last_official_day": True,
        "execution_is_next_cross_month_official_day": True,
        "input_cutoff_after_source_close": True,
        "calendar_alignment": "SIGNED_ASSERTION_NOT_RUNTIME_VERIFIED",
        "allocator_output_validation": (
            "SIGNED_ALLOCATOR_OUTPUT_NOT_RECOMPUTED"
        ),
        "daily_roll_alignment": (
            "SIGNED_DAILY_ROLL_ASSERTION_NOT_RUNTIME_VERIFIED"
        ),
        "previous_snapshot_hash": previous_snapshot_hash,
        "research_bindings": {
            "research_contract_sha256": (
                "c1639d5f7714fd3989da799ece2743ca392ac8a8edad64a7f1238dd2e51c9d31"
            ),
            "formula_builder_sha256": (
                "7ebe1529173b46cbae17680d872680c7bb7bae39863d09b2d9a37183828a43a9"
            ),
            "target_builder_sha256": (
                "40fd1a27bb1e6dedf483a4c7dcec6d181d325d9c9958d6620f79f04fbdb696db"
            ),
            "historical_fresh_exact_runner_sha256": (
                "7e75ad73a8b037b80937cb449b863305753ec7b2860568422906fd55bb2a2fbe"
            ),
            "snapshot_producer_status": (
                "NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY"
            ),
            "research_manifest_sha256": "c" * 64,
            "calendar_authority_sha256": (
                "57b5341b45cb92d7e991f028d780580ab712e87c9cc86c7036917b638cddc76f"
            ),
            "allocator_runner_sha256": (
                "66497283d1c35383d620ef3c92f2c23316046a9b4b0cbe6f1dcf3f361041f307"
            ),
            "guardband_runner_sha256": (
                "e9871b26af4f0ebebed6e697e8fa1c3064bc3d6557df739bcef9b80697eab353"
            ),
            "allocator_manifest_sha256": (
                "8595fb3d4df57e4b6db0e8a64b02bbc0e90d243d0e6a93060837f5a748c8057f"
            ),
            "allocation_evidence_sha256": "a" * 64,
            "daily_roll_evidence_sha256": "b" * 64,
        },
        "guardrails": {
            "source_product_abs_cap": 0.20,
            "source_sector_gross_cap": 0.35,
            "source_portfolio_gross_cap": 1.0,
            "source_target_net": 0.0,
            "buffered_product_abs_cap": 0.12,
            "buffered_sector_gross_cap": 0.27,
            "buffered_portfolio_gross_cap": 0.80,
            "buffered_target_net": 0.0,
            "integer_product_abs_hard_cap": 0.15,
            "integer_sector_gross_hard_cap": 0.35,
            "integer_portfolio_gross_hard_cap": 1.0,
            "integer_abs_net_hard_cap": 0.10,
        },
        "allocator": {
            "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": 2,
            "beam_width": 2048,
            "net_error_penalty": 1.0,
            "monthly_target_dates_only": True,
            "daily_auto_reweight": False,
            "roll_preserves_integer_lots": True,
        },
        "formula_target_binding_sha256": "0" * 64,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "dynamic_selection_allowed": False,
        "production_allowed": False,
        "targets": targets,
        "signer_key_id": "c-fast-research-1",
    }


def sign_payload(
    payload: dict, private_key: Ed25519PrivateKey
) -> tuple[dict, str]:
    draft = copy.deepcopy(payload)
    draft["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    snapshot = CommodityCFastShadowDTO.model_validate(draft)
    draft["formula_target_binding_sha256"] = formula_target_binding_sha256(
        snapshot
    )
    snapshot = CommodityCFastShadowDTO.model_validate(draft)
    canonical = canonical_json(unsigned_snapshot_payload(snapshot))
    signed = snapshot.model_dump(mode="json")
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical)
    ).decode("ascii")
    return signed, __import__("hashlib").sha256(canonical).hexdigest()


def write_snapshot(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def accepted_targets(state_path: Path) -> dict[str, dict]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    return {row["product"]: row for row in state["targets"]}


def rewrite_state(path: Path, mutator) -> None:
    state = json.loads(path.read_text(encoding="utf-8"))
    mutator(state)
    path.write_text(json.dumps(state), encoding="utf-8")


def corrupt_state_json(path: Path) -> None:
    path.write_text("{", encoding="utf-8")


def corrupt_state_schema(path: Path) -> None:
    rewrite_state(path, lambda state: state.pop("snapshot_id"))


def corrupt_state_checksum(path: Path) -> None:
    rewrite_state(
        path,
        lambda state: state["targets"][0].update(
            {"target_quantity": state["targets"][0]["target_quantity"] + 1}
        ),
    )


def corrupt_state_universe(path: Path) -> None:
    rewrite_state(
        path,
        lambda state: state["targets"][-1].update({"product": "ag"}),
    )


def test_valid_genesis_reload_is_read_only_and_persists_independent_state(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, snapshot_hash = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    before = service.status()
    result = service.reload(
        operator="admin", role="admin", source_ip="127.0.0.1"
    )

    assert before["loaded"] is False
    assert result["valid"] is True
    assert result["validation_valid"] is True
    assert result["accepted"] is True
    assert result["snapshot_hash"] == snapshot_hash
    assert result["continuity_state"] == "genesis"
    assert result["contract_alignment"] == "RPC_SPEC_VERIFIED"
    assert result["authority_granted"] is False
    assert result["dispatch_allowed"] is False
    assert result["snapshot_producer_status"] == (
        "NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY"
    )
    assert result["orders_capability"] is False
    assert not hasattr(service, "trade")
    assert not hasattr(service, "send_order")
    assert not hasattr(service, "cancel_order")
    state_path = Path(service.settings.commodity_c_fast_shadow_state_path)
    evidence_path = Path(
        service.settings.commodity_c_fast_shadow_evidence_path
    )
    assert state_path.exists() and evidence_path.exists()
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert service.status() == result


def test_stale_first_acceptance_is_rejected_but_existing_receipt_can_reload(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, snapshot_hash = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    configured = settings(tmp_path, private_key, snapshot_path)
    stale = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=lambda: POST_GENESIS_NOW,
    )

    rejected = stale.reload(operator="admin", role="admin", source_ip=None)

    assert rejected["valid"] is False
    assert rejected["error_code"] == "SNAPSHOT_ACCEPTANCE_WINDOW_CLOSED"
    assert not Path(configured.commodity_c_fast_shadow_state_path).exists()

    current = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )
    assert current.reload(
        operator="admin", role="admin", source_ip=None
    )["accepted"]
    recovered = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=lambda: POST_GENESIS_NOW,
    )

    repeated = recovered.reload(
        operator="system-startup", role="system", source_ip=None
    )

    assert repeated["valid"] is True
    assert repeated["idempotent"] is True
    assert repeated["snapshot_hash"] == snapshot_hash


def test_invalid_reload_does_not_replace_last_accepted_snapshot(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, snapshot_hash = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=fixed_clock,
    )
    assert service.reload(
        operator="admin", role="admin", source_ip=None
    )["valid"]
    corrupted = copy.deepcopy(signed)
    corrupted["unexpected"] = True
    write_snapshot(snapshot_path, corrupted)

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["error_code"] == "SNAPSHOT_SCHEMA_INVALID"
    assert result["last_accepted"]["snapshot_hash"] == snapshot_hash
    stored = json.loads(
        Path(service.settings.commodity_c_fast_shadow_state_path).read_text()
    )
    assert stored["snapshot_hash"] == snapshot_hash


def test_linked_snapshot_requires_hash_month_and_previous_target_continuity(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    genesis, genesis_hash = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, genesis)
    clock = MutableClock(TEST_NOW)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=clock,
    )
    assert service.reload(
        operator="admin", role="admin", source_ip=None
    )["valid"]
    previous = accepted_targets(
        Path(service.settings.commodity_c_fast_shadow_state_path)
    )
    linked_payload = unsigned_payload(
        snapshot_id="c-fast-2026-09-linked",
        source_month="2026-09",
        source_day="2026-09-30",
        execution_day="2026-10-01",
        input_cutoff="2026-09-30T07:00:00Z",
        previous_snapshot_hash=genesis_hash,
        previous_targets=previous,
    )
    linked, linked_hash = sign_payload(linked_payload, private_key)
    write_snapshot(snapshot_path, linked)
    clock.now = LINKED_NOW

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is True
    assert result["continuity_state"] == "verified"
    assert result["snapshot_hash"] == linked_hash
    state_path = Path(service.settings.commodity_c_fast_shadow_state_path)
    state_before_idempotent_reload = state_path.read_bytes()
    repeated = service.reload(
        operator="admin", role="admin", source_ip=None
    )
    assert repeated["continuity_state"] == "verified"
    assert repeated["idempotent"] is True
    assert state_path.read_bytes() == state_before_idempotent_reload


@pytest.mark.parametrize(
    ("mutator", "expected"),
    [
        (
            lambda payload: payload["targets"][0].update(
                {"source_score": -1.0}
            ),
            "SOURCE_SCORE_FORMULA_MISMATCH",
        ),
        (
            lambda payload: payload.update({"source_month": "2026-07"}),
            "SOURCE_MONTH_BEFORE_FORWARD_BOUNDARY",
        ),
    ],
)
def test_signed_internal_drift_fails_closed(
    tmp_path: Path, mutator, expected: str
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    payload = unsigned_payload()
    mutator(payload)
    signed, _ = sign_payload(payload, private_key)
    write_snapshot(snapshot_path, signed)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["error_code"] == expected


def test_future_snapshot_is_rejected_against_service_clock(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["error_code"] == "SNAPSHOT_CREATED_IN_FUTURE"


def test_snapshot_created_after_execution_day_is_rejected(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    payload = unsigned_payload()
    payload["snapshot_created_at_utc"] = "2026-09-02T01:02:00Z"
    signed, _ = sign_payload(payload, private_key)
    write_snapshot(snapshot_path, signed)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["error_code"] == "SNAPSHOT_CREATED_DAY_MISMATCH"


def test_rpc_contract_mismatch_and_missing_loader_fail_closed(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    no_loader = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        clock=fixed_clock,
    )
    mismatch = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=lambda exacts: {
            exact: {"multiplier": 999, "price_tick": 1}
            for exact in exacts
        },
        clock=fixed_clock,
    )

    assert no_loader.reload(
        operator="admin", role="admin", source_ip=None
    )["error_code"] == "CONTRACT_LOADER_UNAVAILABLE"
    assert mismatch.reload(
        operator="admin", role="admin", source_ip=None
    )["error_code"] == "RPC_CONTRACT_SPEC_MISMATCH"


def test_bad_signature_fails_before_acceptance(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    signed["targets"][0]["reference_open_price"] += 1
    write_snapshot(snapshot_path, signed)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["error_code"] == "SIGNATURE_INVALID"


def test_signer_key_requires_research_snapshot_purpose(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    configured = settings(tmp_path, private_key, snapshot_path)
    trusted = json.loads(
        configured.commodity_c_fast_shadow_trusted_public_keys_json
    )
    trusted["c-fast-research-1"]["purpose"] = "execution_release_signer"
    configured = configured.model_copy(
        update={
            "commodity_c_fast_shadow_trusted_public_keys_json": json.dumps(
                trusted
            )
        }
    )
    service = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["validation_valid"] is False
    assert result["error_code"] == "TRUSTED_KEY_PURPOSE_INVALID"


def test_disabled_reload_validates_without_mutating_state_or_evidence(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    disabled_settings = settings(
        tmp_path, private_key, snapshot_path
    ).model_copy(update={"commodity_c_fast_shadow_enabled": False})
    service = CommodityCFastShadowService(
        settings=disabled_settings,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["validation_valid"] is True
    assert result["accepted"] is False
    assert not Path(disabled_settings.commodity_c_fast_shadow_state_path).exists()
    assert not Path(
        disabled_settings.commodity_c_fast_shadow_evidence_path
    ).exists()


def test_disabled_reload_does_not_reactivate_existing_receipt(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, snapshot_hash = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    configured = settings(tmp_path, private_key, snapshot_path)
    enabled = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )
    assert enabled.reload(
        operator="admin", role="admin", source_ip=None
    )["accepted"]
    disabled = CommodityCFastShadowService(
        settings=configured.model_copy(
            update={"commodity_c_fast_shadow_enabled": False}
        ),
        contract_loader=contract_loader,
        clock=lambda: POST_GENESIS_NOW,
    )

    result = disabled.reload(
        operator="admin", role="admin", source_ip=None
    )

    assert result["valid"] is False
    assert result["validation_valid"] is True
    assert result["accepted"] is False
    assert result["last_accepted"]["snapshot_hash"] == snapshot_hash


def test_enabled_paths_must_be_isolated_even_after_model_copy(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    base = settings(tmp_path, private_key, snapshot_path)
    unsafe = base.model_copy(
        update={"commodity_c_fast_shadow_state_path": str(snapshot_path)}
    )
    service = CommodityCFastShadowService(
        settings=unsafe, contract_loader=contract_loader, clock=fixed_clock
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is False
    assert result["error_code"] == "C_FAST_PATHS_NOT_DISTINCT"
    assert json.loads(snapshot_path.read_text())["snapshot_id"] == (
        "c-fast-2026-08-genesis"
    )


def test_linked_snapshot_with_wrong_previous_hash_is_rejected(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    genesis, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, genesis)
    clock = MutableClock(TEST_NOW)
    service = CommodityCFastShadowService(
        settings=settings(tmp_path, private_key, snapshot_path),
        contract_loader=contract_loader,
        clock=clock,
    )
    assert service.reload(
        operator="admin", role="admin", source_ip=None
    )["valid"]
    previous = accepted_targets(
        Path(service.settings.commodity_c_fast_shadow_state_path)
    )
    linked, _ = sign_payload(
        unsigned_payload(
            snapshot_id="c-fast-2026-09-wrong-hash",
            source_month="2026-09",
            source_day="2026-09-30",
            execution_day="2026-10-01",
            input_cutoff="2026-09-30T07:00:00Z",
            previous_snapshot_hash="f" * 64,
            previous_targets=previous,
        ),
        private_key,
    )
    write_snapshot(snapshot_path, linked)
    clock.now = LINKED_NOW

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["error_code"] == "PREVIOUS_SNAPSHOT_HASH_MISMATCH"


@pytest.mark.parametrize(
    ("mutator", "expected_state_error"),
    [
        (corrupt_state_json, "STATE_JSON_INVALID"),
        (corrupt_state_schema, "STATE_SCHEMA_INVALID"),
        (corrupt_state_checksum, "STATE_CHECKSUM_MISMATCH"),
        (corrupt_state_universe, "STATE_TARGET_UNIVERSE_INVALID"),
    ],
)
def test_corrupt_state_reason_is_preserved_in_status_and_evidence(
    tmp_path: Path, mutator, expected_state_error: str
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    configured = settings(tmp_path, private_key, snapshot_path)
    service = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )
    assert service.reload(
        operator="admin", role="admin", source_ip=None
    )["valid"]
    state_path = Path(configured.commodity_c_fast_shadow_state_path)
    mutator(state_path)

    recovered = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )
    result = recovered.reload(
        operator="admin", role="admin", source_ip=None
    )

    assert result["valid"] is False
    assert result["validation_valid"] is False
    assert result["error_code"] == "CONTINUITY_STATE_CORRUPT"
    assert result["state_load_error"] == expected_state_error
    evidence = [
        json.loads(line)
        for line in Path(
            configured.commodity_c_fast_shadow_evidence_path
        ).read_text(encoding="utf-8").splitlines()
    ]
    assert evidence[-1]["error_code"] == "CONTINUITY_STATE_CORRUPT"
    assert evidence[-1]["state_load_error"] == expected_state_error


def test_state_receipt_remains_authoritative_when_reload_log_is_unavailable(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    signed, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, signed)
    base = settings(tmp_path, private_key, snapshot_path)
    evidence_directory = tmp_path / "evidence-directory"
    evidence_directory.mkdir()
    configured = base.model_copy(
        update={
            "commodity_c_fast_shadow_evidence_path": str(evidence_directory)
        }
    )
    service = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )

    result = service.reload(operator="admin", role="admin", source_ip=None)

    assert result["valid"] is True
    assert result["state_receipt_authoritative"] is True
    assert result["reload_evidence_persisted"] is False
    assert Path(configured.commodity_c_fast_shadow_state_path).exists()


def test_dte_arithmetic_and_fractional_rpc_multiplier_fail_closed(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot_path = tmp_path / "snapshot.json"
    bad_dte = unsigned_payload()
    bad_dte["targets"][0]["pit_main_dte"] -= 1
    signed, _ = sign_payload(bad_dte, private_key)
    write_snapshot(snapshot_path, signed)
    configured = settings(tmp_path, private_key, snapshot_path)
    dte_service = CommodityCFastShadowService(
        settings=configured,
        contract_loader=contract_loader,
        clock=fixed_clock,
    )
    assert dte_service.reload(
        operator="admin", role="admin", source_ip=None
    )["error_code"] == "PIT_DTE_ARITHMETIC_MISMATCH"

    valid, _ = sign_payload(unsigned_payload(), private_key)
    write_snapshot(snapshot_path, valid)

    def fractional_loader(exacts: set[str]) -> dict[str, dict]:
        contracts = contract_loader(exacts)
        contracts["SHFE.ag2612"]["multiplier"] = 15.9
        return contracts

    rpc_service = CommodityCFastShadowService(
        settings=configured,
        contract_loader=fractional_loader,
        clock=fixed_clock,
    )
    assert rpc_service.reload(
        operator="admin", role="admin", source_ip=None
    )["error_code"] == "RPC_CONTRACT_SPEC_MISMATCH"


def test_rpc_normalizer_canonicalizes_and_rejects_duplicates() -> None:
    required = {"SHFE.ag2612"}
    normalized = normalize_rpc_contracts(
        [
            {
                "symbol": "AG2612",
                "exchange": "shfe",
                "size": 15,
                "pricetick": 1,
            }
        ],
        required,
    )
    assert normalized == {
        "SHFE.ag2612": {"multiplier": 15, "price_tick": 1}
    }
    with pytest.raises(ValueError, match="RPC_CONTRACT_DUPLICATE"):
        normalize_rpc_contracts(
            [
                {
                    "symbol": "ag2612",
                    "exchange": "SHFE",
                    "size": 15,
                    "pricetick": 1,
                },
                {
                    "vt_symbol": "ag2612.SHFE",
                    "size": 15,
                    "pricetick": 1,
                },
            ],
            required,
        )


def test_signer_binds_formula_and_requires_private_key_permissions(
    tmp_path: Path,
) -> None:
    script_path = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "commodity_c_fast_shadow_sign.py"
    )
    spec = importlib.util.spec_from_file_location(
        "commodity_c_fast_shadow_sign", script_path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    private_key = Ed25519PrivateKey.generate()
    raw_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "key"
    key_path.write_bytes(base64.b64encode(raw_key))
    key_path.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        module.load_private_key(key_path)
    key_path.chmod(0o600)

    signed, snapshot_hash = module.sign_snapshot(
        unsigned_payload(), module.load_private_key(key_path)
    )
    output = tmp_path / "signed.json"
    module.write_private_json(output, signed)

    snapshot = CommodityCFastShadowDTO.model_validate(signed)
    assert snapshot.formula_target_binding_sha256 == (
        formula_target_binding_sha256(snapshot)
    )
    assert snapshot_hash == __import__("hashlib").sha256(
        canonical_json(unsigned_snapshot_payload(snapshot))
    ).hexdigest()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_production_enabled_shadow_requires_dedicated_trust_set(
    tmp_path: Path,
) -> None:
    common = {
        "app_env": "production",
        "jwt_secret_key": "x" * 32,
        "auth_users_json": json.dumps(
            [{"username": "admin", "role": "admin"}]
        ),
        "commodity_c_fast_shadow_enabled": True,
        "commodity_c_fast_shadow_snapshot_path": str(tmp_path / "snapshot.json"),
    }
    with pytest.raises(
        ValueError,
        match="COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON",
    ):
        Settings(**common)


def test_production_enabled_shadow_rejects_wrong_key_purpose(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    trusted = json.loads(public_key_json(private_key))
    trusted["c-fast-research-1"]["purpose"] = "execution_release_signer"
    with pytest.raises(ValueError, match="purpose must be"):
        Settings(
            app_env="production",
            jwt_secret_key="x" * 32,
            auth_users_json=json.dumps(
                [{"username": "admin", "role": "admin"}]
            ),
            commodity_c_fast_shadow_enabled=True,
            commodity_c_fast_shadow_snapshot_path=str(
                tmp_path / "snapshot.json"
            ),
            commodity_c_fast_shadow_trusted_public_keys_json=json.dumps(
                trusted
            ),
        )


def test_enabled_shadow_rejects_path_collision_at_config_load(
    tmp_path: Path,
) -> None:
    shared = str(tmp_path / "shared.json")
    with pytest.raises(ValueError, match="paths must be distinct"):
        Settings(
            commodity_c_fast_shadow_enabled=True,
            commodity_c_fast_shadow_snapshot_path=shared,
            commodity_c_fast_shadow_state_path=shared,
        )
