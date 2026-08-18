# ruff: noqa: E402

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import (
    Draft202012Validator,
    FormatChecker,
    validate as validate_json_schema,
)
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_pure_producer_kernel as frozen
import commodity_static_core_equal_pure_producer as static_producer
import research_warehouse.verified_daily_pit_main_roll_source as verified_roll
from research_warehouse.calendar_models import CalendarDay, OfficialCalendar
from research_warehouse.canonical import canonical_json, canonical_json_line, sha256
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_operator_state import OperatorState
from research_warehouse.m2_receipts import RUN_RECEIPT_SCHEMA, run_receipt_id
from research_warehouse.pit_source_view import SourcePins
from research_warehouse.signing import public_key_sha256
import research_warehouse.static_core_baseline as static_baseline
from test_research_warehouse_static_core_baseline import _build, _contract_registry

UTC = timezone.utc
CALENDAR_SHA = "a" * 64
CALENDAR_ANCHOR_SHA = "2" * 64
WAREHOUSE_REGISTRY_SHA = "1" * 64
POLICY_SHA = "d" * 64
RUNTIME_SHA = "e" * 64
GENESIS_SEAL = "5" * 64


def _calendar() -> OfficialCalendar:
    start = date(2026, 1, 1)
    end = date(2027, 3, 31)
    rows = {}
    current = start
    while current <= end:
        rows[current] = CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    return OfficialCalendar.create(
        calendar_id="official-calendar-verified-daily-roll-v1",
        raw_sha256=CALENDAR_SHA,
        valid_from=start,
        valid_to=end,
        issued_at=datetime(2025, 12, 1, tzinfo=UTC),
        exchanges=("SHFE", "INE"),
        days=rows,
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )


class _Anchor:
    raw_sha256 = CALENDAR_ANCHOR_SHA
    available_at = datetime(2025, 12, 1, tzinfo=UTC)


def _raw(official_day: str, exchange: str, *, main_delivery: str = "2610") -> bytes:
    deliveries = (main_delivery, "2611", "2612")
    rows = []
    for product in frozen.PRODUCTS:
        if frozen.PRODUCT_SPECS[product]["exchange"] != exchange:
            continue
        for index, delivery in enumerate(deliveries):
            oi = 5000 - index * 1000
            if product == "ag" and index == 1:
                oi = 5000
            rows.append(
                {
                    "DELIVERYMONTH": delivery,
                    "PRODUCTID": f"{product}_f",
                    "SETTLEMENTPRICE": str(100 + index),
                    "OPENINTEREST": str(oi),
                }
            )
    return canonical_json(
        {"report_date": official_day.replace("-", ""), "o_curinstrument": rows}
    )


def _verified_input(
    official_day: str,
    *,
    head_seal: str,
    head_commit: str,
    parent_seal: str | None,
    parent_commit: str | None,
    expected_genesis_baseline: verified_roll.BuiltBaseline,
) -> verified_roll._VerifiedDailyInput:
    raw = {exchange: _raw(official_day, exchange) for exchange in ("SHFE", "INE")}
    sources = [
        {
            "source_id": f"{exchange.lower()}-daily-market-data-v1",
            "exchange": exchange,
            "object_id": f"object-{official_day}-{exchange.lower()}",
            "observation_id": f"observation-{official_day}-{exchange.lower()}",
            "revision_id": f"revision-{official_day}-{exchange.lower()}",
            "raw_sha256": sha256(raw[exchange]),
            "raw_bytes": len(raw[exchange]),
            "raw_relative_path": f"raw/{official_day}-{exchange.lower()}.json",
        }
        for exchange in ("SHFE", "INE")
    ]
    receipt = {
        "schema_version": RUN_RECEIPT_SCHEMA,
        "receipt_id": "",
        "trade_day": official_day,
        "completed_at": f"{official_day}T10:00:00.000000Z",
        "registry_raw_sha256": WAREHOUSE_REGISTRY_SHA,
        "calendar_raw_sha256": CALENDAR_SHA,
        "calendar_availability_anchor_raw_sha256": CALENDAR_ANCHOR_SHA,
        "sources": sources,
        "authority": false_authority(),
    }
    receipt["receipt_id"] = run_receipt_id(receipt)
    manifest = {
        "trade_day": official_day,
        "batch_id": f"batch-{official_day}-verified-roll",
        "batch_seal_sha256": head_seal,
        "commit_seal_sha256": head_commit,
        "parent_batch_seal_sha256": parent_seal,
        "parent_commit_seal_sha256": parent_commit,
        "revisions": [dict(source) for source in sources],
    }
    return verified_roll._VerifiedDailyInput(
        receipt_raw=canonical_json_line(receipt),
        receipt=receipt,
        daily_source_raw=raw,
        manifest=manifest,
        manifest_raw_sha256="2" * 64,
        commit_receipt_raw_sha256="3" * 64,
        expected_genesis_baseline=expected_genesis_baseline,
        predecessor_entry=None,
    )


def _state(day: str, head: str, commit: str, *, sequence: int) -> OperatorState:
    return OperatorState(
        path=Path("/operator-state"),
        raw_sha256=("4" if sequence == 1 else "5") * 64,
        payload={
            "manifest_sequence": sequence,
            "manifest_genesis_seal_sha256": GENESIS_SEAL,
            "manifest_head_seal_sha256": head,
            "manifest_head_commit_seal_sha256": commit,
            "commit_anchor_ledger_raw_sha256": "8" * 64,
            "last_trade_day": day,
        },
    )


def _context() -> SimpleNamespace:
    return SimpleNamespace(
        runtime_input=SimpleNamespace(raw_sha256=RUNTIME_SHA),
        policy=SimpleNamespace(raw_sha256=POLICY_SHA),
        registry=SimpleNamespace(raw_sha256=WAREHOUSE_REGISTRY_SHA),
        calendar=_calendar(),
        availability=_Anchor(),
    )


def _signed_genesis(
    tmp_path: Path,
) -> tuple[verified_roll.GenesisContinuity, str, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_path = tmp_path / "business-public.b64"
    public_path.write_bytes(base64.b64encode(public_raw) + b"\n")
    built = _build()
    baseline = json.loads(built.unsigned_batch_raw)
    baseline["signature"] = base64.b64encode(
        private.sign(
            canonical_json(
                {key: value for key, value in baseline.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    return (
        verified_roll.GenesisContinuity(
            source_month="2026-06",
            built_baseline=built,
            signed_baseline_batch_raw=canonical_json(baseline),
            business_public_key_path=public_path,
            expected_business_signer_key_id="research-key",
        ),
        public_key_sha256(public),
        private,
    )


def _kwargs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    dict,
    dict[str, verified_roll._VerifiedDailyInput],
    Ed25519PrivateKey,
]:
    head = "6" * 64
    commit = "7" * 64
    genesis, public_sha, private = _signed_genesis(tmp_path)
    inputs = {
        "2026-07-01": _verified_input(
            "2026-07-01",
            head_seal=head,
            head_commit=commit,
            parent_seal=None,
            parent_commit=None,
            expected_genesis_baseline=genesis.built_baseline,
        )
    }
    monkeypatch.setattr(
        verified_roll,
        "_verify_daily_input",
        lambda **values: inputs[values["official_day"].isoformat()],
    )
    registry = _contract_registry()
    return (
        {
            "context": _context(),
            "operator_state": _state("2026-07-01", head, commit, sequence=1),
            "history_receipt_path": Path("/history.json"),
            "pins": SourcePins(
                history_receipt_raw_sha256="3" * 64,
                operator_state_raw_sha256="4" * 64,
                manifest_public_key_raw_sha256="0" * 64,
                baseline_public_key_raw_sha256=public_sha,
            ),
            "manifest_public_key_path": Path("/manifest-public.b64"),
            "official_day": "2026-07-01",
            "contract_registry_raw": registry,
            "expected_contract_registry_raw_sha256": sha256(registry),
            "genesis": genesis,
        },
        inputs,
        private,
    )


def _coherently_forged_baseline(
    built: static_baseline.BuiltBaseline,
    *,
    attack: str,
) -> static_baseline.BuiltBaseline:
    source = json.loads(built.source_view_raw)
    product = source["products"][0]
    if attack == "historical_oi":
        product["daily"][0]["contracts"][0]["open_interest"] += 250.0
    elif attack == "exact_contract":
        for daily in product["daily"]:
            daily["contracts"][0]["exact_contract"] = "SHFE.ag2611"
            daily["contracts"][0]["delivery_yyyymm"] = 202611
        product["execution_reference"]["exact_contract"] = "SHFE.ag2611"
        product["contract_spec"]["exact_contract"] = "SHFE.ag2611"
        product["contract_spec"]["official_last_trading_day"] = "2026-11-16"
    else:  # pragma: no cover - test helper contract
        raise AssertionError(attack)
    replay = static_producer.produce_research_artifacts(canonical_json(source))
    target = json.loads(replay.artifacts["target_evidence"])
    original_unsigned = json.loads(built.unsigned_batch_raw)
    unsigned_raw = canonical_json(
        static_baseline._unsigned_batch(
            target,
            source_month=original_unsigned["source_month"],
            execution_day=date.fromisoformat(original_unsigned["execution_day"]),
            signer_key_id=original_unsigned["signer_key_id"],
            execution_lane=original_unsigned["execution_lane"],
        )
    )
    evidence = json.loads(built.evidence_raw)
    evidence["source_view_raw_sha256"] = sha256(replay.source_view_canonical)
    evidence["source_view_raw_bytes"] = len(replay.source_view_canonical)
    evidence["artifact_digests"] = [
        {
            "role": role,
            "raw_sha256": sha256(replay.artifacts[role]),
            "raw_bytes": len(replay.artifacts[role]),
        }
        for role in static_producer.ARTIFACT_ROLES
    ]
    evidence["unsigned_batch_raw_sha256"] = sha256(unsigned_raw)
    evidence["unsigned_batch_raw_bytes"] = len(unsigned_raw)
    forged = static_baseline.BuiltBaseline(
        source_view_raw=replay.source_view_canonical,
        artifacts=dict(replay.artifacts),
        unsigned_batch_raw=unsigned_raw,
        evidence_raw=canonical_json_line(evidence),
    )
    static_baseline.verify_built_baseline(forged)
    return forged


def test_root_baseline_replay_uses_verified_history_chain_and_current_pins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _build()
    context = _context()
    state = _state("2026-07-01", "6" * 64, "7" * 64, sequence=1)
    history = {"receipt": "root-verified"}
    chain = [{"batch": "root-verified"}]
    registry_raw = _contract_registry()
    pins = SourcePins(
        history_receipt_raw_sha256="3" * 64,
        operator_state_raw_sha256="4" * 64,
        manifest_public_key_raw_sha256="0" * 64,
        baseline_public_key_raw_sha256="9" * 64,
    )
    sources = SimpleNamespace(
        daily_raw={"root": {"SHFE": b"shfe", "INE": b"ine"}},
        supplemental_daily_receipts=({"trade_day": "2026-07-01"},),
    )
    calls = {}

    def fake_sources(**kwargs):
        calls["sources"] = kwargs
        return sources

    def fake_build(**kwargs):
        calls["build"] = kwargs
        return expected

    monkeypatch.setattr(
        verified_roll,
        "verified_static_baseline_daily_sources",
        fake_sources,
    )
    monkeypatch.setattr(verified_roll, "build_historical_baseline", fake_build)

    result = verified_roll._root_replayed_genesis_baseline(
        context=context,
        operator_state=state,
        history=history,
        chain=chain,
        pins=pins,
        contract_registry_raw=registry_raw,
        source_month="2026-06",
        signer_key_id="research-key",
    )

    assert result is expected
    assert calls["sources"] == {
        "context": context,
        "history": history,
        "chain": chain,
        "source_month": "2026-06",
    }
    assert calls["build"] == {
        "calendar": context.calendar,
        "calendar_anchor_raw_sha256": CALENDAR_ANCHOR_SHA,
        "warehouse_registry_raw_sha256": WAREHOUSE_REGISTRY_SHA,
        "history_receipt": history,
        "history_receipt_raw_sha256": "3" * 64,
        "operator_pins": {
            "operator_state_raw_sha256": "4" * 64,
            "manifest_genesis_seal_sha256": "5" * 64,
            "manifest_head_seal_sha256": "6" * 64,
            "manifest_head_commit_seal_sha256": "7" * 64,
            "commit_anchor_ledger_raw_sha256": "8" * 64,
        },
        "daily_source_raw": sources.daily_raw,
        "contract_registry_raw": registry_raw,
        "source_month": "2026-06",
        "signer_key_id": "research-key",
        "execution_lane": verified_roll.EXECUTION_LANE,
        "supplemental_daily_receipts": sources.supplemental_daily_receipts,
    }


@pytest.mark.parametrize("attack", ["historical_oi", "exact_contract"])
def test_coherent_caller_baseline_forgery_cannot_replace_root_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    attack: str,
) -> None:
    kwargs, _inputs, private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    forged = _coherently_forged_baseline(
        genesis.built_baseline,
        attack=attack,
    )
    signed = json.loads(forged.unsigned_batch_raw)
    signed["signature"] = base64.b64encode(
        private.sign(
            canonical_json(
                {key: value for key, value in signed.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=forged,
        signed_baseline_batch_raw=canonical_json(signed),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="does not match independently root-replayed bytes",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_genesis_is_deterministic_schema_valid_tie_broken_and_no_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    first = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    second = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    payload = verified_roll.validate_structural_daily_pit_main_roll_source(
        first.artifact_raw
    )

    assert first == second
    assert payload["official_day"] == "2026-07-01"
    assert payload["execution_day"] == "2026-07-02"
    assert [row["product"] for row in payload["mains"]] == list(frozen.PRODUCTS)
    assert payload["mains"][0]["exact_contract"] == "SHFE.ag2610"
    assert payload["mains"][0]["open_interest"] == 5000.0
    assert payload["mains"][0]["eligible_contract_count"] == 3
    assert payload["verified_lineage"]["continuity"]["mode"] == (
        "GENESIS_STATIC_CORE_EQUAL"
    )
    for field in (
        "installable",
        "event_ready",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "official_forward_claimed",
        "dispatch_authorized",
        "order_authorized",
    ):
        assert payload[field] is False
    assert payload["authority"] == false_authority()
    schema = json.loads(
        (
            ROOT
            / "deployments/research-warehouse/verified-daily-pit-main-roll-source-v2.schema.json"
        ).read_text(encoding="utf-8")
    )
    validate_json_schema(
        payload,
        schema,
        format_checker=FormatChecker(),
    )


@pytest.mark.parametrize(
    ("source_month", "official_day"),
    [
        ("2026-07", "2026-07-01"),
        ("2026-06", "2026-06-30"),
    ],
)
def test_delayed_genesis_requires_monthly_batch_execution_as_artifact_day(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_month: str,
    official_day: str,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    kwargs["genesis"] = replace(kwargs["genesis"], source_month=source_month)
    kwargs["official_day"] = official_day

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="source month does not execute on artifact official day",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_delayed_genesis_source_month_must_be_canonical(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    kwargs["genesis"] = replace(kwargs["genesis"], source_month="2026-6")

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="source month is not canonical",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_signed_monthly_batch_execution_day_must_equal_artifact_day(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    signed = json.loads(genesis.signed_baseline_batch_raw)
    signed["execution_day"] = "2026-07-02"
    signed["signature"] = base64.b64encode(
        private.sign(
            canonical_json(
                {key: value for key, value in signed.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    kwargs["genesis"] = replace(
        genesis,
        signed_baseline_batch_raw=canonical_json(signed),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="baseline frozen-field binding mismatch",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_continuity_mode_must_be_exclusive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    missing = {**kwargs, "genesis": None}
    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="requires exactly one continuity mode",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**missing)

    both = {
        **kwargs,
        "predecessor": verified_roll.PredecessorContinuity(),
    }
    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="requires exactly one continuity mode",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**both)


def test_signed_genesis_must_match_the_exact_replayed_baseline_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    signed = json.loads(genesis.signed_baseline_batch_raw)
    signed["targets"][0]["exact_contract"] = "SHFE.ag2611"
    signed["signature"] = base64.b64encode(
        private.sign(
            canonical_json(
                {key: value for key, value in signed.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    kwargs["genesis"] = replace(
        genesis,
        signed_baseline_batch_raw=canonical_json(signed),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="does not match deterministic replayed target bytes",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_synchronized_unsigned_evidence_and_signature_forgery_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    built = genesis.built_baseline
    tampered_unsigned = json.loads(built.unsigned_batch_raw)
    tampered_unsigned["targets"][0]["exact_contract"] = "SHFE.ag2611"
    tampered_unsigned_raw = canonical_json(tampered_unsigned)
    tampered_evidence = json.loads(built.evidence_raw)
    tampered_evidence["unsigned_batch_raw_sha256"] = sha256(tampered_unsigned_raw)
    tampered_evidence["unsigned_batch_raw_bytes"] = len(tampered_unsigned_raw)
    tampered_built = replace(
        built,
        unsigned_batch_raw=tampered_unsigned_raw,
        evidence_raw=canonical_json_line(tampered_evidence),
    )
    signed = dict(tampered_unsigned)
    signed["signature"] = base64.b64encode(
        private.sign(
            canonical_json(
                {key: value for key, value in signed.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=tampered_built,
        signed_baseline_batch_raw=canonical_json(signed),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="does not match independently root-replayed bytes",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("run_receipt", "raw_bytes"),
        ("contract_registry", "raw_bytes"),
    ],
)
def test_structural_validator_and_schema_reject_invalid_lineage_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    section: str,
    field: str,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    payload = json.loads(built.artifact_raw)
    payload["verified_lineage"][section][field] = -5
    payload["artifact_id"] = verified_roll._artifact_id(payload)
    raw = canonical_json_line(payload)

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="JSON schema validation failed",
    ):
        verified_roll.validate_structural_daily_pit_main_roll_source(raw)

    schema = json.loads(verified_roll.SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload)
    )
    assert errors


def test_structural_validator_and_schema_reject_invalid_source_raw_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    payload = json.loads(built.artifact_raw)
    payload["verified_lineage"]["sources"][0]["raw_bytes"] = -5
    payload["artifact_id"] = verified_roll._artifact_id(payload)
    raw = canonical_json_line(payload)

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="JSON schema validation failed",
    ):
        verified_roll.validate_structural_daily_pit_main_roll_source(raw)

    schema = json.loads(verified_roll.SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload)
    )


def test_structural_validator_rejects_baseline_execution_day_splice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    payload = json.loads(built.artifact_raw)
    payload["verified_lineage"]["continuity"]["baseline_execution_day"] = "2026-07-02"
    payload["artifact_id"] = verified_roll._artifact_id(payload)

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="Genesis continuity binding mismatch",
    ):
        verified_roll.validate_structural_daily_pit_main_roll_source(
            canonical_json_line(payload)
        )


def test_schema_and_structural_validator_reject_invalid_baseline_source_month(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    payload = json.loads(built.artifact_raw)
    payload["verified_lineage"]["continuity"]["baseline_source_month"] = "2026-13"
    payload["artifact_id"] = verified_roll._artifact_id(payload)
    raw = canonical_json_line(payload)

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="JSON schema validation failed",
    ):
        verified_roll.validate_structural_daily_pit_main_roll_source(raw)

    schema = json.loads(verified_roll.SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload)
    )


def test_genesis_evidence_rejects_unknown_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    built = genesis.built_baseline
    evidence = json.loads(built.evidence_raw)
    evidence["unverified_claim"] = "forged"
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=replace(
            built,
            evidence_raw=canonical_json_line(evidence),
        ),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="replay evidence contract mismatch",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_genesis_evidence_must_match_current_root_pins(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    built = genesis.built_baseline
    evidence = json.loads(built.evidence_raw)
    evidence["pins"]["history_receipt_raw_sha256"] = "f" * 64
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=replace(
            built,
            evidence_raw=canonical_json_line(evidence),
        ),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="does not match independently root-replayed bytes",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


@pytest.mark.parametrize(
    ("field", "maximum", "message"),
    [
        (
            "source_view_raw",
            verified_roll.MAX_BASELINE_SOURCE_VIEW_RAW_BYTES,
            "baseline source view resource limit",
        ),
        (
            "evidence_raw",
            verified_roll.MAX_BASELINE_EVIDENCE_RAW_BYTES,
            "baseline evidence resource limit",
        ),
        (
            "unsigned_batch_raw",
            verified_roll.MAX_BASELINE_UNSIGNED_RAW_BYTES,
            "baseline unsigned batch resource limit",
        ),
    ],
)
def test_genesis_baseline_primary_resource_limits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    maximum: int,
    message: str,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=replace(
            genesis.built_baseline,
            **{field: b"x" * (maximum + 1)},
        ),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match=message,
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_genesis_baseline_each_artifact_has_a_resource_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    built = genesis.built_baseline
    artifacts = dict(built.artifacts)
    role = next(iter(artifacts))
    artifacts[role] = b"x" * (verified_roll.MAX_BASELINE_ARTIFACT_RAW_BYTES + 1)
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=replace(built, artifacts=artifacts),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match=f"baseline {role} resource limit",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


def test_genesis_baseline_aggregate_has_a_resource_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    genesis = kwargs["genesis"]
    built = genesis.built_baseline
    artifacts = {
        role: b"x" * verified_roll.MAX_BASELINE_ARTIFACT_RAW_BYTES
        for role in built.artifacts
    }
    kwargs["genesis"] = replace(
        genesis,
        built_baseline=replace(built, artifacts=artifacts),
    )

    with pytest.raises(
        verified_roll.VerifiedDailyPitMainRollSourceError,
        match="baseline aggregate resource limit",
    ):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)


@pytest.mark.parametrize(
    "drift", ["raw", "receipt", "manifest", "calendar", "registry"]
)
def test_verified_inputs_fail_closed_on_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    drift: str,
) -> None:
    kwargs, inputs, _private = _kwargs(monkeypatch, tmp_path)
    value = inputs["2026-07-01"]
    if drift == "raw":
        raw = dict(value.daily_source_raw)
        raw["SHFE"] += b" "
        inputs["2026-07-01"] = replace(value, daily_source_raw=raw)
    elif drift == "receipt":
        receipt = dict(value.receipt)
        receipt["completed_at"] = "2026-07-01T10:00:01.000000Z"
        inputs["2026-07-01"] = replace(value, receipt=receipt)
    elif drift == "manifest":
        manifest = dict(value.manifest)
        manifest["batch_seal_sha256"] = "f" * 64
        inputs["2026-07-01"] = replace(value, manifest=manifest)
    elif drift == "calendar":
        receipt = dict(value.receipt)
        receipt["calendar_raw_sha256"] = "f" * 64
        receipt["receipt_id"] = run_receipt_id(receipt)
        inputs["2026-07-01"] = replace(
            value,
            receipt=receipt,
            receipt_raw=canonical_json_line(receipt),
        )
    else:
        kwargs["expected_contract_registry_raw_sha256"] = "f" * 64
    with pytest.raises(verified_roll.VerifiedDailyPitMainRollSourceError):
        verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
