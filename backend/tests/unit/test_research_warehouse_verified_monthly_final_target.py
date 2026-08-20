# ruff: noqa: E402

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import base64
import json
import math
from pathlib import Path
from types import SimpleNamespace
import inspect
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.execution.executable_target_adapter import (
    _position_manager_final_projection,
    _static_core_equal_outputs,
    build_full_portfolio_quote_requests,
    build_static_core_equal_full_portfolio_keyless_decision,
)
import commodity_c_fast_pure_producer_kernel as frozen
from research_warehouse.calendar_models import CalendarDay, OfficialCalendar
from research_warehouse.canonical import canonical_json, canonical_json_line, sha256
from research_warehouse.daily_roll_predecessor_catalog import CurrentCatalogHeadProof
from research_warehouse.errors import RegistryError
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_operator_state import OperatorState
from research_warehouse.m2_runtime_paths import RuntimePaths
from research_warehouse.signing import public_key_sha256
from research_warehouse.static_core_baseline import (
    VerifiedStaticBaselineDailySources,
    build_historical_baseline,
)
from research_warehouse.pit_source_view import PitSourceViewError
import research_warehouse.verified_monthly_final_target as monthly
import research_warehouse.continuous_event_selector as selector
from research_warehouse.verified_daily_pit_main_roll_source import (
    BuiltVerifiedDailyPitMainRollSource,
)
from shared.commodity_execution import KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
from test_research_warehouse_pit_source_view import PRODUCT_BASE, _TestAnchor, _inputs
from test_research_warehouse_static_core_baseline import _contract_registry
from test_issue353_static_core_keyless import _snapshot
from test_issue362_full_portfolio_planner import _formal_quote

RUNTIME_SHA = "9" * 64
OPERATOR_SHA = "4" * 64
HISTORY_SHA = "3" * 64
MANIFEST_KEY_SHA = "a" * 64
BUSINESS_SIGNER_KEY_ID = "monthly-business-key-v1"


def _trending_inputs():
    calendar, history, daily_raw, _key = _inputs()
    rows = dict(calendar.days)
    current = max(rows) + timedelta(days=1)
    while current <= date(2027, 3, 20):
        rows[current] = CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    calendar = OfficialCalendar.create(
        calendar_id=calendar.calendar_id,
        raw_sha256=calendar.raw_sha256,
        valid_from=calendar.valid_from,
        valid_to=date(2027, 3, 20),
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )
    products = list(frozen.PRODUCTS)
    for day_index, raw_day in enumerate(sorted(daily_raw)):
        for exchange in ("SHFE", "INE"):
            payload = json.loads(daily_raw[raw_day][exchange])
            for row in payload["o_curinstrument"]:
                if row["DELIVERYMONTH"] == "小计":
                    continue
                product = row["PRODUCTID"].removesuffix("_f")
                product_index = products.index(product)
                contract_index = ("2612", "2701", "2702").index(row["DELIVERYMONTH"])
                slope = (product_index - 4.5) * 0.0004
                mid = PRODUCT_BASE[product] * (1 + 0.01 * contract_index)
                mid *= math.exp(slope * day_index)
                tick = float(frozen.PRODUCT_SPECS[product]["price_tick"])
                mid = round(mid / tick) * tick
                row.update(
                    {
                        "OPENPRICE": str(mid),
                        "HIGHESTPRICE": str(mid + 2 * tick),
                        "LOWESTPRICE": str(max(tick, mid - 2 * tick)),
                        "CLOSEPRICE": str(mid + tick),
                        "SETTLEMENTPRICE": str(mid),
                    }
                )
            daily_raw[raw_day][exchange] = canonical_json(payload)
    return calendar, history, daily_raw


def _state() -> OperatorState:
    return OperatorState(
        path=Path("/operator-state"),
        raw_sha256=OPERATOR_SHA,
        payload={
            "manifest_sequence": 186,
            "manifest_genesis_seal_sha256": "5" * 64,
            "manifest_head_seal_sha256": "6" * 64,
            "manifest_head_commit_seal_sha256": "7" * 64,
            "commit_anchor_ledger_raw_sha256": "8" * 64,
            "last_trade_day": "2026-07-01",
        },
    )


def _catalog(state: OperatorState) -> CurrentCatalogHeadProof:
    receipt_raw = canonical_json_line({"catalog": "receipt"})
    artifact_raw = canonical_json_line({"catalog": "artifact"})
    return CurrentCatalogHeadProof(
        receipt_raw=receipt_raw,
        receipt_raw_sha256=sha256(receipt_raw),
        artifact_raw=artifact_raw,
        artifact_raw_sha256=sha256(artifact_raw),
        operator_state_raw_sha256=state.raw_sha256,
        operator_manifest_sequence=state.payload["manifest_sequence"],
        manifest_genesis_seal_sha256=state.payload["manifest_genesis_seal_sha256"],
        manifest_head_seal_sha256=state.payload["manifest_head_seal_sha256"],
        manifest_head_commit_seal_sha256=state.payload[
            "manifest_head_commit_seal_sha256"
        ],
        commit_anchor_ledger_raw_sha256=state.payload[
            "commit_anchor_ledger_raw_sha256"
        ],
        last_trade_day=state.payload["last_trade_day"],
        authority=false_authority(),
    )


def _install_root_mocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict, OperatorState]:
    calendar, history, daily_raw = _trending_inputs()
    state = _state()
    context = SimpleNamespace(
        runtime_input=SimpleNamespace(raw_sha256=RUNTIME_SHA),
        calendar=calendar,
        availability=_TestAnchor(),
        registry=SimpleNamespace(raw_sha256=history["registry_raw_sha256"]),
    )

    @contextmanager
    def shared_lock(_path: Path, *, exclusive: bool):
        assert exclusive is False
        yield

    monkeypatch.setattr(monthly, "load_runtime_context_readonly", lambda _path: context)
    monkeypatch.setattr(
        monthly, "load_current_catalog_head", lambda _path: _catalog(state)
    )
    monkeypatch.setattr(monthly, "operator_state_lock", shared_lock)
    monkeypatch.setattr(monthly, "load_operator_state", lambda _path: state)
    monkeypatch.setattr(
        monthly,
        "verify_root_pins",
        lambda **_kwargs: (history, []),
    )
    monkeypatch.setattr(
        monthly,
        "verified_static_baseline_daily_sources",
        lambda **_kwargs: VerifiedStaticBaselineDailySources(
            daily_raw=daily_raw,
            supplemental_daily_receipts=(),
        ),
    )
    registry_raw = _contract_registry()
    registry_path = tmp_path / "static-core-contract-registry.json"
    registry_path.write_bytes(registry_raw)
    registry_path.chmod(0o600)
    unsigned = build_historical_baseline(
        calendar=calendar,
        calendar_anchor_raw_sha256=context.availability.raw_sha256,
        warehouse_registry_raw_sha256=context.registry.raw_sha256,
        history_receipt=history,
        history_receipt_raw_sha256=HISTORY_SHA,
        operator_pins=monthly._root_pins(state),
        daily_source_raw=daily_raw,
        contract_registry_raw=registry_raw,
        source_month="2026-06",
        signer_key_id=BUSINESS_SIGNER_KEY_ID,
        execution_lane="simnow_shakedown",
    )
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signed_baseline = json.loads(unsigned.unsigned_batch_raw)
    signed_baseline["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(
                {
                    key: value
                    for key, value in signed_baseline.items()
                    if key != "signature"
                }
            )
        )
    ).decode("ascii")
    signed_baseline_path = tmp_path / "signed-monthly-baseline.json"
    signed_baseline_path.write_bytes(canonical_json(signed_baseline))
    signed_baseline_path.chmod(0o600)
    public_key = private_key.public_key()
    public_key_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    business_key_path = tmp_path / "business-public.b64"
    business_key_path.write_bytes(base64.b64encode(public_key_raw) + b"\n")
    business_key_path.chmod(0o600)
    proof = _catalog(state)
    genesis_entry = SimpleNamespace(
        receipt_raw=proof.receipt_raw,
        artifact_raw=proof.artifact_raw,
        artifact={
            "verified_lineage": {
                "continuity": {
                    "mode": "GENESIS_STATIC_CORE_EQUAL",
                    "baseline_public_key_sha256": public_key_sha256(public_key),
                    "baseline_signer_key_id": BUSINESS_SIGNER_KEY_ID,
                    "baseline_source_month": "2026-06",
                    "baseline_batch_raw_sha256": sha256(
                        signed_baseline_path.read_bytes()
                    ),
                }
            }
        },
    )
    monkeypatch.setattr(
        monthly,
        "_load_catalog",
        lambda _root: SimpleNamespace(
            entries=(genesis_entry,),
            head=genesis_entry,
        ),
    )
    kwargs = {
        "runtime_input_path": tmp_path / "runtime-input.json",
        "expected_runtime_input_raw_sha256": RUNTIME_SHA,
        "operator_state_path": tmp_path / "operator-state.json",
        "expected_operator_state_raw_sha256": OPERATOR_SHA,
        "history_receipt_path": tmp_path / "history-receipt.json",
        "expected_history_receipt_raw_sha256": HISTORY_SHA,
        "manifest_public_key_path": tmp_path / "manifest-public.b64",
        "expected_manifest_public_key_raw_sha256": MANIFEST_KEY_SHA,
        "signed_baseline_batch_path": signed_baseline_path,
        "business_public_key_path": business_key_path,
        "expected_business_public_key_raw_sha256": public_key_sha256(public_key),
        "expected_business_signer_key_id": BUSINESS_SIGNER_KEY_ID,
        "contract_registry_path": registry_path,
        "expected_contract_registry_raw_sha256": sha256(registry_raw),
        "source_month": "2026-06",
    }
    return kwargs, state


def _tree(root: Path) -> tuple[tuple[str, int, int], ...]:
    return tuple(
        sorted(
            (
                str(path.relative_to(root)),
                path.lstat().st_mode,
                path.lstat().st_size,
            )
            for path in root.rglob("*")
        )
    )


def _rewrite_signed_baseline(
    path: Path,
    mutate,
    *,
    private_key: Ed25519PrivateKey | None = None,
) -> None:
    payload = json.loads(path.read_bytes())
    mutate(payload)
    signer = (
        Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        if private_key is None
        else private_key
    )
    if "signature" in payload:
        payload["signature"] = base64.b64encode(
            signer.sign(
                canonical_json(
                    {key: value for key, value in payload.items() if key != "signature"}
                )
            )
        ).decode("ascii")
    path.write_bytes(canonical_json(payload))
    path.chmod(0o600)


def test_root_replay_is_deterministic_zero_write_and_exact_adapter_parity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)
    captured: dict[str, object] = {}
    static_replay = monthly.static_producer.produce_research_artifacts
    thermostat_replay = monthly.thermostat_producer.produce_snapshot

    def capture_static(value):
        result = static_replay(value)
        captured["static"] = result
        return result

    def capture_thermostat(value):
        result = thermostat_replay(value)
        captured["thermostat"] = result
        return result

    monkeypatch.setattr(
        monthly.static_producer, "produce_research_artifacts", capture_static
    )
    monkeypatch.setattr(
        monthly.thermostat_producer, "produce_snapshot", capture_thermostat
    )
    before = _tree(tmp_path)
    first = monthly.replay_verified_monthly_final_target(**kwargs)
    second = monthly.replay_verified_monthly_final_target(**kwargs)

    assert first == second
    assert _tree(tmp_path) == before
    assert len(first.quantity_vector) == len(frozen.PRODUCTS) == 10
    assert [product for product, _quantity in first.quantity_vector] == list(
        frozen.PRODUCTS
    )
    assert any(quantity != 0 for _product, quantity in first.quantity_vector)
    assert first.quantity_vector_sha256 == monthly._quantity_vector_sha(
        first.quantity_vector
    )
    assert first.monthly_exact_contract_map_sha256 == monthly._contract_map_sha(
        first.monthly_exact_contract_map
    )
    assert sha256(first.final_target_raw) == first.final_target_raw_sha256
    final_payload = json.loads(first.final_target_raw)
    assert sha256(canonical_json(final_payload)) == first.final_target_sha256
    assert first.lineage_hashes == (
        first.static_core_equal_sha256,
        first.position_manager_sha256,
        first.final_target_sha256,
    )
    assert first.authority == false_authority()
    assert set(first.authority.values()) == {False}

    static_result = captured["static"]
    thermostat_result = captured["thermostat"]
    static_sha, static_rows, execution_day = _static_core_equal_outputs(
        producer_projection=static_result.producer_projection,
        freeze_contract=json.loads(static_result.artifacts["freeze_contract"]),
        target_evidence=json.loads(static_result.artifacts["target_evidence"]),
    )
    adapter_projection, _adapter_rows = _position_manager_final_projection(
        snapshot=json.loads(thermostat_result.snapshot_draft),
        expected_sha256=thermostat_result.snapshot_draft_sha256,
        static_rows=static_rows,
        static_execution_day=execution_day,
    )
    assert static_sha == first.static_core_equal_sha256
    assert thermostat_result.snapshot_draft_sha256 == first.position_manager_sha256
    assert canonical_json_line(adapter_projection) == first.final_target_raw

    selector_input = first.to_structural_selector_candidate()
    assert selector_input.final_target_raw == first.final_target_raw
    assert selector_input.static_core_equal_sha256 == first.static_core_equal_sha256
    assert selector_input.position_manager_sha256 == first.position_manager_sha256
    assert selector_input.baseline_batch_raw_sha256 == first.baseline_batch_raw_sha256
    contract_map = dict(first.monthly_exact_contract_map)
    daily_payload = {
        "schema_version": (
            "vnpy_research_commodity_verified_daily_pit_main_roll_source_v2"
        ),
        "artifact_id": "verified-daily-roll-" + "d" * 64,
        "official_day": first.execution_day,
        "execution_day": "2026-07-02",
        "roll_change_detected": False,
        "changed_products": [],
        "input_lineage_status": "VERIFIED_AT_CONSTRUCTION_V2",
        "execution_lane": "simnow_shakedown",
        "mains": [
            {
                "product": product,
                "previous_exact_contract": contract_map[product],
                "exact_contract": contract_map[product],
                "changed": False,
            }
            for product in frozen.PRODUCTS
        ],
        "verified_lineage": {
            "continuity": {
                "mode": "GENESIS_STATIC_CORE_EQUAL",
                "baseline_batch_raw_sha256": first.baseline_batch_raw_sha256,
                "predecessor_exact_contract_map_sha256": (
                    first.monthly_exact_contract_map_sha256
                ),
            }
        },
        "authority": false_authority(),
    }
    daily_raw = canonical_json_line({"verified": daily_payload["artifact_id"]})
    monkeypatch.setattr(
        selector,
        "validate_structural_daily_pit_main_roll_source",
        lambda observed: daily_payload if observed == daily_raw else None,
    )
    selection = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=BuiltVerifiedDailyPitMainRollSource(
            artifact_raw=daily_raw,
            artifact_id=daily_payload["artifact_id"],
            artifact_raw_sha256=sha256(daily_raw),
        ),
        monthly_candidate=selector_input,
    )
    selection_payload = json.loads(selection.selection_raw)
    event_payload = json.loads(selection.event_candidate_raw)
    assert selection_payload["event_ready"] is False
    assert selection_payload["installable"] is False
    assert event_payload["event_ready"] is False
    assert event_payload["installable"] is False
    assert selection_payload["verification_status"] == selector.VERIFICATION_STATUS


def test_catalog_cross_splice_and_locked_root_drift_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, state = _install_root_mocks(monkeypatch, tmp_path)
    foreign = replace(_catalog(state), operator_state_raw_sha256="f" * 64)
    monkeypatch.setattr(monthly, "load_current_catalog_head", lambda _path: foreign)
    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="cross-spliced",
    ):
        monthly.replay_verified_monthly_final_target(**kwargs)

    monkeypatch.setattr(
        monthly, "load_current_catalog_head", lambda _path: _catalog(state)
    )
    monkeypatch.setattr(
        monthly,
        "load_operator_state",
        lambda _path: replace(state, raw_sha256="e" * 64),
    )
    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="operator state root pin changed",
    ):
        monthly.replay_verified_monthly_final_target(**kwargs)


def test_missing_monthly_history_fails_closed_without_fabricated_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)

    def missing(**_kwargs):
        raise PitSourceViewError("historical monthly raw is unavailable")

    monkeypatch.setattr(monthly, "verified_static_baseline_daily_sources", missing)
    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="failed closed",
    ) as captured:
        monthly.replay_verified_monthly_final_target(**kwargs)
    assert isinstance(captured.value.__cause__, PitSourceViewError)


@pytest.mark.parametrize(
    ("attack", "mutate"),
    [
        (
            "forged_resign",
            lambda payload: payload["targets"][0].__setitem__(
                "target_quantity",
                payload["targets"][0]["target_quantity"] + 1,
            ),
        ),
        (
            "cross_source",
            lambda payload: payload.update(
                {"source_month": "2026-05", "execution_day": "2026-06-01"}
            ),
        ),
        (
            "signer_key_id",
            lambda payload: payload.__setitem__(
                "signer_key_id",
                "forged-monthly-business-key-v1",
            ),
        ),
    ],
)
def test_signed_baseline_forgery_cannot_replace_catalog_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    attack: str,
    mutate,
) -> None:
    del attack
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)
    _rewrite_signed_baseline(kwargs["signed_baseline_batch_path"], mutate)

    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="catalog trust anchor",
    ):
        monthly.replay_verified_monthly_final_target(**kwargs)


def test_missing_signature_or_signed_file_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)
    signed_path = kwargs["signed_baseline_batch_path"]
    _rewrite_signed_baseline(
        signed_path,
        lambda payload: payload.pop("signature"),
    )
    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="catalog trust anchor",
    ):
        monthly.replay_verified_monthly_final_target(**kwargs)

    second = tmp_path / "second"
    second.mkdir(mode=0o700)
    kwargs, _state_value = _install_root_mocks(monkeypatch, second)
    signed_path = kwargs["signed_baseline_batch_path"]
    signed_path.unlink()
    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="failed closed",
    ):
        monthly.replay_verified_monthly_final_target(**kwargs)


def test_attacker_key_and_claimed_hash_do_not_override_catalog_signer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)
    attacker = Ed25519PrivateKey.generate()
    attacker_public = attacker.public_key()
    attacker_raw = attacker_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    attacker_path = tmp_path / "attacker-public.b64"
    attacker_path.write_bytes(base64.b64encode(attacker_raw) + b"\n")
    attacker_path.chmod(0o600)
    _rewrite_signed_baseline(
        kwargs["signed_baseline_batch_path"],
        lambda _payload: None,
        private_key=attacker,
    )
    kwargs["business_public_key_path"] = attacker_path
    kwargs["expected_business_public_key_raw_sha256"] = public_key_sha256(
        attacker_public
    )

    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="catalog trust anchor",
    ):
        monthly.replay_verified_monthly_final_target(**kwargs)


def test_public_replay_accepts_no_caller_built_proof_or_claimed_hash() -> None:
    parameters = inspect.signature(
        monthly.replay_verified_monthly_final_target
    ).parameters
    assert "built_baseline" not in parameters
    assert "catalog_head" not in parameters
    assert "monthly_candidate" not in parameters
    assert "static_core_equal_sha256" not in parameters
    assert "position_manager_sha256" not in parameters
    assert "final_target_sha256" not in parameters

    planner_parameters = inspect.signature(
        monthly.replay_verified_monthly_planner_bundle
    ).parameters
    for caller_built in (
        "final_target",
        "static_core_equal_projection",
        "static_core_equal_freeze_contract",
        "static_core_equal_target_evidence",
        "position_manager_snapshot",
        "position_manager_sha256",
    ):
        assert caller_built not in planner_parameters


def test_root_replay_planner_bundle_builds_explicit_v3_plan_without_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)
    before = _tree(tmp_path)

    bundle = monthly.replay_verified_monthly_planner_bundle(**kwargs)
    legacy = monthly.replay_verified_monthly_final_target(**kwargs)

    assert bundle.final_target == legacy
    assert _tree(tmp_path) == before
    assert set(bundle.authority.values()) == {False}
    assert bundle.position_manager_sha256 == legacy.position_manager_sha256
    assert len(bundle.planner_bundle_sha256) == 64

    planner_inputs = {
        "static_core_equal_projection": bundle.static_core_equal_projection,
        "static_core_equal_freeze_contract": (bundle.static_core_equal_freeze_contract),
        "static_core_equal_target_evidence": (bundle.static_core_equal_target_evidence),
        "position_manager_snapshot": bundle.position_manager_snapshot,
        "position_manager_sha256": bundle.position_manager_sha256,
    }
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    event_generated_at = "2030-01-01T00:00:00Z"
    reconciliation = {"state": "RECONCILED", "unknown_outcomes": 0}
    requirements = build_full_portfolio_quote_requests(
        **planner_inputs,
        current_facts=_snapshot({}),
        reconciliation=reconciliation,
        run_id="issue362-monthly-replay-0001",
        event_generated_at=event_generated_at,
        now=now,
        target_plan_version=3,
    )
    quotes = {
        row.exact_contract: _formal_quote(
            row.exact_contract,
            price_side=row.request.price_side,
            price_tick=row.request.price_tick,
            ingest_seq=index,
            received_at_utc=event_generated_at,
        )
        for index, row in enumerate(requirements.requirements, start=1)
    }
    decision = build_static_core_equal_full_portfolio_keyless_decision(
        **planner_inputs,
        current_facts=_snapshot({}),
        reconciliation=reconciliation,
        quote_requirements=requirements,
        formal_quotes_by_exact_contract=quotes,
        run_id="issue362-monthly-replay-0001",
        event_generated_at=event_generated_at,
        expires_at="2099-01-01T00:00:00Z",
        now=now,
        target_plan_version=3,
    )

    assert requirements.phase == "OPEN"
    assert requirements.input_binding.target_plan_version == 3
    assert decision.close_handoff is None
    assert decision.open_handoff is not None
    assert decision.open_handoff.target_plan["schema_version"] == (
        KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    )
    assert (
        decision.open_handoff.target_plan["creation_quote_proof"]["start_authorized"]
        is False
    )


@pytest.mark.parametrize(
    ("raw_field", "sha_field", "mutate"),
    (
        (
            "static_core_equal_projection_raw",
            "static_core_equal_projection_raw_sha256",
            lambda value: value.__setitem__("status", "CROSS_SPLICED"),
        ),
        (
            "static_core_equal_freeze_contract_raw",
            "static_core_equal_freeze_contract_raw_sha256",
            lambda value: value["D_exact_contract"].__setitem__(
                "entry", "CROSS_SPLICED"
            ),
        ),
        (
            "static_core_equal_target_evidence_raw",
            "static_core_equal_target_evidence_raw_sha256",
            lambda value: value.__setitem__("signal_netting", "CROSS_SPLICED"),
        ),
        (
            "position_manager_snapshot_raw",
            "position_manager_snapshot_raw_sha256",
            lambda value: value.__setitem__("raw_scale", 0.999),
        ),
    ),
)
def test_planner_bundle_rejects_every_component_cross_splice_with_full_rehash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw_field: str,
    sha_field: str,
    mutate,
) -> None:
    kwargs, _state_value = _install_root_mocks(monkeypatch, tmp_path)
    bundle = monthly.replay_verified_monthly_planner_bundle(**kwargs)
    spliced = json.loads(getattr(bundle, raw_field))
    mutate(spliced)
    spliced_raw = canonical_json(spliced)

    with pytest.raises(
        monthly.VerifiedMonthlyFinalTargetError,
        match="cross-spliced|final target binding",
    ):
        replace(
            bundle,
            **{
                raw_field: spliced_raw,
                sha_field: sha256(spliced_raw),
            },
        )


def test_runtime_paths_readonly_open_is_byte_stable_and_never_creates(
    tmp_path: Path,
) -> None:
    runtime = RuntimePaths.ensure(tmp_path / "runtime")
    marker = runtime.run_receipts / "marker.json"
    marker.write_bytes(b"root-pinned\n")
    marker.chmod(0o600)
    before = _tree(tmp_path)

    assert RuntimePaths.open(runtime.root) == runtime
    assert _tree(tmp_path) == before

    absent = tmp_path / "absent-runtime"
    with pytest.raises(RegistryError):
        RuntimePaths.open(absent)
    assert absent.exists() is False
