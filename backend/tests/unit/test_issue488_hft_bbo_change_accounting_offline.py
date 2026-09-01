from __future__ import annotations

import ast
from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from collector_ordered_l1_bbo_change_accounting_v1 import (  # noqa: E402
    AccountingContractError,
    AdmissionCandidate,
    BrokerMarkupBinding,
    DailyCoverageEvidence,
    DailyAggregateRow,
    ExecutionQuote,
    ExecutionScenarioSpec,
    FeeScheduleBinding,
    InstrumentTermsBinding,
    PRIMARY,
    STRESS,
    ScenarioAdmissionLedger,
    TradeLedgerRow,
    aggregate_fixed_20_day_grid,
    attempt_round_trip,
    bootstrap_parameters_gate,
    calculate_fee,
    liquidation_side_mtm,
    make_execution_leg,
    primary_best3_removal,
    require_frozen_scenario,
    resolve_close_offset,
    resolve_fee_schedule,
    resolve_instrument_terms,
)


CONTRACT = "SHFE.rb2701"
OTHER = "DCE.i2701"
D1, D2 = date(2030, 1, 2), date(2030, 1, 3)
HASH = "a" * 64


def terms(
    contract: str = CONTRACT,
    day: date = D1,
    *,
    tick: str = "1",
    multiplier: str = "10",
    version: str = "v1",
) -> InstrumentTermsBinding:
    return InstrumentTermsBinding(
        "terms-" + contract + version,
        contract,
        day,
        0,
        10_000,
        Decimal(tick),
        Decimal(multiplier),
        "exchange",
        "terms.pdf",
        version,
        HASH,
    )


def fee(
    contract: str = CONTRACT,
    day: date = D1,
    offset: str = "OPEN",
    *,
    fixed: str = "1",
    ratio: str = "0",
) -> FeeScheduleBinding:
    return FeeScheduleBinding(
        "fee-" + contract + offset,
        contract,
        day,
        0,
        10_000,
        offset,
        Decimal(fixed),
        Decimal(ratio),
        "exchange",
        "fees.pdf",
        "v1",
        HASH,
    )


def markup(
    contract: str = CONTRACT,
    day: date = D1,
    offset: str = "OPEN",
    *,
    fixed: str = "0.5",
    ratio: str = "0",
) -> BrokerMarkupBinding:
    return BrokerMarkupBinding(
        "markup-" + contract + offset,
        contract,
        day,
        0,
        10_000,
        offset,
        Decimal(fixed),
        Decimal(ratio),
        "broker",
        "markup.pdf",
        "v1",
        HASH,
    )


def bindings(
    contract: str = CONTRACT,
    days: tuple[date, ...] = (D1,),
    *,
    tick: str = "1",
    multiplier: str = "10",
) -> tuple[
    list[InstrumentTermsBinding], list[FeeScheduleBinding], list[BrokerMarkupBinding]
]:
    return (
        [terms(contract, day, tick=tick, multiplier=multiplier) for day in days],
        [
            fee(contract, day, offset)
            for day in days
            for offset in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
        ],
        [
            markup(contract, day, offset)
            for day in days
            for offset in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
        ],
    )


def quote(
    seq: int,
    *,
    contract: str = CONTRACT,
    day: date = D1,
    bid: str = "100",
    ask: str = "101",
    segment: str = "day-1",
    bid_size: str = "1",
    ask_size: str = "1",
    clock: str = "SYNCED",
    source_event_utc_ns: int | None = None,
    provider_update_id: str | None = "AUTO",
) -> ExecutionQuote:
    source = seq * 100 if source_event_utc_ns is None else source_event_utc_ns
    return ExecutionQuote(
        contract,
        f"{seq:064x}",
        "gen-1",
        "epoch-1",
        segment,
        seq,
        f"provider-{seq}" if provider_update_id == "AUTO" else provider_update_id,
        source,
        seq * 100 + 1,
        seq * 100 + 2,
        seq * 100 + 3,
        day,
        Decimal(bid),
        Decimal(bid_size),
        Decimal(ask),
        Decimal(ask_size),
        clock,
        None,
        False,
    )


def candidate(
    trade_id: str, *, seq: int = 1, eligibility: str = "ELIGIBLE"
) -> AdmissionCandidate:
    return AdmissionCandidate(
        "run-1",
        "gen-1",
        "epoch-1",
        "day-1",
        D1,
        CONTRACT,
        "PRIMARY",
        "LONG",
        eligibility,
        seq,
        f"cross-{trade_id}",
        trade_id,
    )


def full_coverage(
    grid: tuple[date, ...],
    attempt_counts: dict[tuple[str, str, date], int] | None = None,
) -> tuple[DailyCoverageEvidence, ...]:
    mapping = (("rb", CONTRACT), ("i", OTHER))
    counts = attempt_counts or {}
    return tuple(
        DailyCoverageEvidence(
            product,
            contract,
            "PRIMARY",
            day,
            True,
            True,
            counts.get((product, contract, day), 0),
        )
        for product, contract in mapping
        for day in grid
    )


def test_frozen_scenario_includes_horizon_lots_size_grace_scope_and_event_order() -> None:
    assert (
        PRIMARY.horizon_ns,
        PRIMARY.lots,
        PRIMARY.min_side_size,
        PRIMARY.exit_grace_ns,
    ) == (30_000_000_000, 1, Decimal(1), 5_000_000_000)
    assert PRIMARY.position_scope == "scenario_id×exact_contract"
    assert PRIMARY.event_order_version == STRESS.event_order_version
    with pytest.raises(AccountingContractError, match="frozen"):
        require_frozen_scenario(
            ExecutionScenarioSpec(
                "PRIMARY",
                1,
                1,
                0,
                30_000_000_000,
                1,
                Decimal(1),
                5_000_000_000,
                "scenario_id×exact_contract",
                PRIMARY.event_order_version,
            )
        )


def test_admission_provenance_eligibility_blocker_and_same_callback_exit_before_signal() -> None:
    ledger = ScenarioAdmissionLedger()
    admitted = ledger.admit(candidate("t1"))
    assert admitted.accepted_trade_id == "t1"
    suppressed = ledger.admit(candidate("t2"))
    assert (
        suppressed.decision == "SUPPRESSED"
        and suppressed.blocking_trade_id == "t1"
        and suppressed.blocker
    )
    ineligible = ledger.admit(candidate("t3", eligibility="INELIGIBLE"))
    assert (
        ineligible.decision == "INELIGIBLE"
        and ineligible.state_after == "ENTRY_PENDING"
        and ineligible.accepted_trade_id is None
    )
    ledger.transition(
        "PRIMARY",
        CONTRACT,
        "IDLE",
        2,
        "t1",
        run_id="run-1",
        collector_generation="gen-1",
        clock_epoch="epoch-1",
        segment_id="day-1",
        official_day=D1,
    )
    assert ledger.admit(candidate("t4", seq=2)).decision == "ADMITTED"


def test_admission_wrong_trade_transition_and_bad_eligibility_fail_closed() -> None:
    ledger = ScenarioAdmissionLedger()
    ledger.admit(candidate("t1"))
    with pytest.raises(AccountingContractError, match="does not own"):
        ledger.transition(
            "PRIMARY",
            CONTRACT,
            "OPEN",
            2,
            "wrong",
            run_id="run-1",
            collector_generation="gen-1",
            clock_epoch="epoch-1",
            segment_id="day-1",
            official_day=D1,
        )
    with pytest.raises(
        AccountingContractError, match="invalid direction or eligibility"
    ):
        candidate("x", eligibility="ACCEPT")


def test_admission_locks_run_generation_and_never_reuses_admitted_id() -> None:
    ledger = ScenarioAdmissionLedger()
    ledger.admit(candidate("t1"))
    ledger.transition(
        "PRIMARY",
        CONTRACT,
        "IDLE",
        2,
        "t1",
        run_id="run-1",
        collector_generation="gen-1",
        clock_epoch="epoch-1",
        segment_id="day-1",
        official_day=D1,
    )
    with pytest.raises(AccountingContractError, match="cannot be reused"):
        ledger.admit(candidate("t1", seq=2))
    with pytest.raises(AccountingContractError, match="threshold_crossing_id"):
        ledger.admit(
            AdmissionCandidate(
                "run-1", "gen-1", "epoch-1", "day-1", D1, CONTRACT,
                "PRIMARY", "LONG", "ELIGIBLE", 2, "cross-t1", "fresh-trade",
            )
        )


def test_same_crossing_is_independently_admitted_by_primary_and_stress() -> None:
    ledger = ScenarioAdmissionLedger()
    primary = candidate("primary")
    stress = AdmissionCandidate(
        primary.run_id,
        primary.collector_generation,
        primary.clock_epoch,
        primary.segment_id,
        primary.official_day,
        primary.exact_contract,
        "STRESS",
        primary.direction,
        primary.eligibility,
        primary.callback_seq,
        primary.threshold_crossing_id,
        "stress",
    )

    assert ledger.admit(primary).decision == "ADMITTED"
    assert ledger.admit(stress).decision == "ADMITTED"
    ledger.transition(
        "PRIMARY",
        CONTRACT,
        "IDLE",
        2,
        "primary",
        run_id="run-1",
        collector_generation="gen-1",
        clock_epoch="epoch-1",
        segment_id="day-1",
        official_day=D1,
    )
    with pytest.raises(AccountingContractError, match="threshold_crossing_id"):
        ledger.admit(
            AdmissionCandidate(
                primary.run_id,
                primary.collector_generation,
                primary.clock_epoch,
                primary.segment_id,
                primary.official_day,
                primary.exact_contract,
                "PRIMARY",
                primary.direction,
                primary.eligibility,
                2,
                primary.threshold_crossing_id,
                "primary-reused-crossing",
            )
        )
    with pytest.raises(AccountingContractError, match="one run/generation"):
        ledger.admit(
            AdmissionCandidate(
                "run-2", "gen-1", "epoch-1", "day-1", D1, CONTRACT,
                "PRIMARY", "LONG", "ELIGIBLE", 3, "cross-new", "new",
            )
        )


def test_pit_binding_authority_source_version_hash_and_exact_one_checks() -> None:
    with pytest.raises(AccountingContractError, match="SHA-256"):
        InstrumentTermsBinding(
            "x", CONTRACT, D1, 0, 1, Decimal(1), Decimal(1), "a", "s", "v", "bad"
        )
    with pytest.raises(AccountingContractError, match="got 0"):
        resolve_fee_schedule([], CONTRACT, D1, 1, "OPEN")
    with pytest.raises(AccountingContractError, match="got 2"):
        resolve_fee_schedule([fee(), fee()], CONTRACT, D1, 1, "OPEN")
    with pytest.raises(AccountingContractError, match="positive"):
        terms(tick="0")


def test_fee_ratio_zero_rounding_and_contract_day_offset_consistency() -> None:
    instrument = terms()
    exchange = fee(fixed="1.005", ratio="0.2")
    broker = markup(fixed="0", ratio="0")
    assert (
        calculate_fee(
            Decimal("101"),
            instrument,
            exchange,
            broker,
            exact_contract=CONTRACT,
            official_day=D1,
            offset="OPEN",
        )
        == (Decimal("1.21"), Decimal("0.00"))
    )
    with pytest.raises(AccountingContractError, match="mismatch"):
        calculate_fee(
            Decimal("101"),
            instrument,
            exchange,
            broker,
            exact_contract=CONTRACT,
            official_day=D1,
            offset="CLOSE_TODAY",
        )


def test_pit_lookup_uses_receive_time_and_public_resolver_validates_inputs() -> None:
    boundary_terms = [
        InstrumentTermsBinding(
            "terms-before", CONTRACT, D1, 0, 201, Decimal("1"), Decimal("10"),
            "exchange", "terms.pdf", "v1", HASH,
        ),
        InstrumentTermsBinding(
            "terms-after", CONTRACT, D1, 201, 10_000, Decimal("1"), Decimal("10"),
            "exchange", "terms.pdf", "v2", HASH,
        ),
    ]
    fee_rows, markup_rows = bindings()[1:]
    result = attempt_round_trip(
        "receive-boundary", CONTRACT, PRIMARY, "LONG", quote(1), quote(2),
        boundary_terms, fee_rows, markup_rows,
    )
    assert result.entry and result.exit
    assert result.entry.instrument_terms_binding_id == "terms-before"
    assert result.exit.instrument_terms_binding_id == "terms-after"
    with pytest.raises(AccountingContractError, match="utc_ns"):
        resolve_instrument_terms(boundary_terms, CONTRACT, D1, 0)


def test_primary_stress_provenance_sides_positions_and_terms_must_match() -> None:
    term_rows, fee_rows, markup_rows = bindings()
    primary = attempt_round_trip(
        "p",
        CONTRACT,
        PRIMARY,
        "LONG",
        quote(1),
        quote(2, bid="105", ask="106"),
        term_rows,
        fee_rows,
        markup_rows,
    )
    stress = attempt_round_trip(
        "s",
        CONTRACT,
        STRESS,
        "SHORT",
        quote(1),
        quote(2, bid="95", ask="96"),
        term_rows,
        fee_rows,
        markup_rows,
    )
    assert primary.status == stress.status == "CLOSED"
    assert (
        primary.entry
        and primary.exit
        and primary.entry.side == "BUY"
        and primary.exit.side == "SELL"
    )
    assert (
        primary.entry.signed_lots,
        primary.entry.abs_lots,
        primary.entry.position_before,
        primary.entry.position_after,
    ) == (1, 1, 0, 1)
    assert primary.entry.quote.raw_record_hash == quote(1).raw_record_hash
    assert (
        stress.entry
        and stress.exit
        and (stress.entry.execution_price, stress.exit.execution_price)
        == (Decimal("99"), Decimal("97"))
    )
    changed = [
        InstrumentTermsBinding(
            "terms-earlier",
            CONTRACT,
            D1,
            0,
            201,
            Decimal("1"),
            Decimal("10"),
            "exchange",
            "terms.pdf",
            "v1",
            HASH,
        ),
        InstrumentTermsBinding(
            "terms-later",
            CONTRACT,
            D1,
            201,
            10_000,
            Decimal("2"),
            Decimal("10"),
            "exchange",
            "terms.pdf",
            "v2",
            HASH,
        ),
    ]
    bad = attempt_round_trip(
        "mismatch", CONTRACT, PRIMARY, "LONG", quote(1), quote(2, bid="106", ask="108"),
        changed, fee_rows, markup_rows,
    )
    assert bad.status == "FAILED" and bad.failure_reason and "equal tick" in bad.failure_reason


def test_same_source_timestamp_is_legal_and_side_size_only_checks_execution_side() -> None:
    rows = bindings()
    same_source = attempt_round_trip(
        "same-source", CONTRACT, PRIMARY, "LONG",
        quote(1, source_event_utc_ns=100, bid_size="0.1", ask_size="1"),
        quote(2, bid="105", ask="106", source_event_utc_ns=100, bid_size="1", ask_size="0.1"),
        *rows,
    )
    assert same_source.status == "CLOSED"
    assert quote(3, provider_update_id=None).qualified()
    failed = attempt_round_trip(
        "actual-side", CONTRACT, PRIMARY, "LONG", quote(1, ask_size="0.1"),
        quote(2, bid="105", ask="106"), *rows,
    )
    assert failed.status == "FAILED" and failed.failure_reason


def test_exit_pricing_failure_preserves_successful_entry_leg() -> None:
    term_rows, _, _ = bindings()
    partial = attempt_round_trip(
        "partial", CONTRACT, PRIMARY, "LONG", quote(1), quote(2, bid="105", ask="106"),
        term_rows, [fee(offset="OPEN")], [markup(offset="OPEN")],
    )
    assert partial.status == "FAILED" and partial.entry is not None and partial.exit is None


def test_failed_partial_trade_revalidates_entry_and_forbids_exit_without_entry() -> None:
    term_rows, fee_rows, markup_rows = bindings()
    entry = make_execution_leg(
        CONTRACT,
        PRIMARY,
        "LONG",
        "OPEN",
        quote(1),
        term_rows,
        fee_rows,
        markup_rows,
    )
    partial = TradeLedgerRow(
        "partial-validated",
        CONTRACT,
        "PRIMARY",
        "LONG",
        "FAILED",
        "no later usable quote",
        entry,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    partial.__post_init__()
    object.__setattr__(entry, "exact_contract", OTHER)
    with pytest.raises(AccountingContractError, match="quote contract mismatch"):
        partial.__post_init__()

    closed = attempt_round_trip(
        "closed-for-exit",
        CONTRACT,
        PRIMARY,
        "LONG",
        quote(1),
        quote(2, bid="105", ask="106"),
        term_rows,
        fee_rows,
        markup_rows,
    )
    assert closed.exit is not None
    with pytest.raises(AccountingContractError, match="requires an entry"):
        TradeLedgerRow(
            "exit-only",
            CONTRACT,
            "PRIMARY",
            "LONG",
            "FAILED",
            "forged",
            None,
            closed.exit,
            None,
            None,
            None,
            None,
            None,
        )


def test_forged_closed_trade_with_unusable_execution_side_is_rejected() -> None:
    term_rows, fee_rows, markup_rows = bindings()
    closed = attempt_round_trip(
        "forged-leg", CONTRACT, PRIMARY, "LONG", quote(1),
        quote(2, bid="105", ask="106"), term_rows, fee_rows, markup_rows,
    )
    assert closed.entry is not None
    object.__setattr__(closed.entry.quote, "ask_size", Decimal("0"))
    with pytest.raises(AccountingContractError, match="quote is not usable"):
        closed.__post_init__()


@pytest.mark.parametrize(
    "mutated,reason",
    [
        (lambda q: quote(2, segment="next"), "one generation"),
        (lambda q: quote(2, day=D2), "official trading day"),
        (lambda q: quote(2, bid_size="0"), "execution-usable"),
    ],
)
def test_current_candidate_rejects_cross_lane_day_and_unusable_quotes(
    mutated, reason: str
) -> None:
    rows = bindings(days=(D1, D2))
    result = attempt_round_trip(
        "bad", CONTRACT, PRIMARY, "LONG", quote(1), mutated(quote(2)), *rows
    )
    assert (
        result.status == "FAILED"
        and result.failure_reason
        and reason in result.failure_reason
    )


def test_close_offset_uses_official_day_not_calendar_date() -> None:
    assert resolve_close_offset(D1, D1) == "CLOSE_TODAY"
    assert resolve_close_offset(D1, D2) == "CLOSE_YESTERDAY"


def test_liquidation_marks_long_bid_short_ask() -> None:
    rows = bindings()
    long = liquidation_side_mtm(
        CONTRACT, PRIMARY, "LONG", "101", D1, 101, "1.5", quote(2, bid="105", ask="106"), *rows
    )
    short = liquidation_side_mtm(
        CONTRACT, PRIMARY, "SHORT", "110", D1, 101, "1.5", quote(2, bid="105", ask="106"), *rows
    )
    assert (long.liquidation_price, long.net_cny) == (Decimal("105"), Decimal("37.00"))
    assert short.liquidation_price == Decimal("106")
    stress_long = liquidation_side_mtm(
        CONTRACT, STRESS, "LONG", "101", D1, 101, "1.5", quote(2, bid="105", ask="106"), *rows
    )
    stress_short = liquidation_side_mtm(
        CONTRACT, STRESS, "SHORT", "110", D1, 101, "1.5", quote(2, bid="105", ask="106"), *rows
    )
    assert stress_long.liquidation_price == Decimal("104")
    assert stress_short.liquidation_price == Decimal("107")


def test_daily_grid_nonprimary_mapping_and_bad_rows_fail_closed() -> None:
    grid = tuple(D1 + timedelta(days=i) for i in range(20))
    trusted_terms = [terms(day=grid[0])]
    trusted_fees = [
        fee(day=grid[0], offset=o)
        for o in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
    ]
    trusted_markups = [
        markup(day=grid[0], offset=o)
        for o in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
    ]
    closed = attempt_round_trip(
        "x",
        CONTRACT,
        PRIMARY,
        "LONG",
        quote(1, day=grid[0]),
        quote(2, day=grid[0], bid="102", ask="103"),
        trusted_terms,
        trusted_fees,
        trusted_markups,
    )
    assert closed.entry is not None and closed.exit is not None
    trusted_quotes = {
        closed.entry.quote.raw_record_hash: closed.entry.quote,
        closed.exit.quote.raw_record_hash: closed.exit.quote,
    }

    def aggregate(
        rows: list[TradeLedgerRow],
        mapping: dict[str, str],
        evidence: tuple[DailyCoverageEvidence, ...],
        scenario: ExecutionScenarioSpec = PRIMARY,
    ) -> tuple[DailyAggregateRow, ...]:
        return aggregate_fixed_20_day_grid(
            rows,
            mapping,
            grid,
            evidence,
            scenario,
            terms_bindings=trusted_terms,
            fees=trusted_fees,
            markups=trusted_markups,
            trusted_quotes_by_raw_record_hash=trusted_quotes,
        )

    coverage = full_coverage(grid, {("rb", CONTRACT, grid[0]): 1})
    with pytest.raises(AccountingContractError, match="one exact"):
        aggregate([closed], {CONTRACT: "rb", OTHER: "rb"}, coverage)
    with pytest.raises(AccountingContractError, match="PRIMARY-only"):
        aggregate(
            [closed],
            {CONTRACT: "rb", OTHER: "i"},
            coverage,
            scenario=STRESS,
        )
    daily = aggregate([closed], {CONTRACT: "rb", OTHER: "i"}, coverage)
    assert len(daily) == 40 and daily[1].trade_count == 0
    with pytest.raises(AccountingContractError, match="attempt_id"):
        aggregate(
            [closed, closed],
            {CONTRACT: "rb", OTHER: "i"},
            full_coverage(grid, {("rb", CONTRACT, grid[0]): 2}),
        )
    with pytest.raises(AccountingContractError, match="attempt_count"):
        aggregate([], {CONTRACT: "rb", OTHER: "i"}, coverage)
    failed = attempt_round_trip(
        "failed-coverage",
        CONTRACT,
        PRIMARY,
        "LONG",
        quote(1, day=grid[0]),
        quote(2, day=grid[0], bid="102", ask="103"),
        [terms(day=grid[0])],
        [fee(day=grid[0], offset="OPEN")],
        [markup(day=grid[0], offset="OPEN")],
    )
    with pytest.raises(AccountingContractError, match="bad or unpriced"):
        aggregate(
            [failed],
            {CONTRACT: "rb", OTHER: "i"},
            full_coverage(grid, {("rb", CONTRACT, grid[0]): 1}),
        )
    with pytest.raises(AccountingContractError, match="complete"):
        aggregate([closed], {CONTRACT: "rb", OTHER: "i"}, coverage[:-1])
    with pytest.raises(AccountingContractError, match="sealed"):
        aggregate(
            [closed], {CONTRACT: "rb", OTHER: "i"},
            coverage[:-1]
            + (DailyCoverageEvidence("i", OTHER, "PRIMARY", grid[-1], False, True, 0),),
        )
    object.__setattr__(closed, "net_cny", Decimal("999"))
    with pytest.raises(AccountingContractError, match="economics"):
        aggregate([closed], {CONTRACT: "rb", OTHER: "i"}, coverage)
    with pytest.raises(AccountingContractError, match="unpriced"):
        primary_best3_removal(
            [
                DailyAggregateRow("rb", "PRIMARY", day, 0, Decimal(0), day != grid[3])
                for day in grid
            ],
            grid,
        )


def test_daily_aggregation_rebuilds_legs_from_trusted_pit_bindings() -> None:
    grid = tuple(D1 + timedelta(days=i) for i in range(20))
    trusted = bindings(days=(D1,))
    closed = attempt_round_trip(
        "forgery",
        CONTRACT,
        PRIMARY,
        "LONG",
        quote(1),
        quote(2, bid="105", ask="106"),
        *trusted,
    )
    assert closed.entry is not None and closed.exit is not None
    forged_entry = replace(
        closed.entry,
        instrument_terms_binding_id="forged-terms",
        fee_schedule_binding_id="forged-fee",
        broker_markup_binding_id="forged-markup",
        exchange_fee_cny=Decimal(0),
        broker_fee_cny=Decimal(0),
    )
    exchange_fee = forged_entry.exchange_fee_cny + closed.exit.exchange_fee_cny
    broker_fee = forged_entry.broker_fee_cny + closed.exit.broker_fee_cny
    forged = replace(
        closed,
        entry=forged_entry,
        exchange_fee_cny=exchange_fee,
        broker_fee_cny=broker_fee,
        net_cny=closed.gross_cny - exchange_fee - broker_fee,
    )

    with pytest.raises(AccountingContractError, match="trusted PIT bindings"):
        aggregate_fixed_20_day_grid(
            [forged],
            {CONTRACT: "rb", OTHER: "i"},
            grid,
            full_coverage(grid, {("rb", CONTRACT, D1): 1}),
            terms_bindings=trusted[0],
            fees=trusted[1],
            markups=trusted[2],
            trusted_quotes_by_raw_record_hash={
                closed.entry.quote.raw_record_hash: closed.entry.quote,
                closed.exit.quote.raw_record_hash: closed.exit.quote,
            },
        )


def test_public_binding_resolution_rejects_structural_impostors() -> None:
    trusted = bindings()
    fake_terms = SimpleNamespace(**vars(trusted[0][0]))

    with pytest.raises(AccountingContractError, match="exact InstrumentTermsBinding"):
        make_execution_leg(
            CONTRACT,
            PRIMARY,
            "LONG",
            "OPEN",
            quote(1),
            [fake_terms],
            trusted[1],
            trusted[2],
        )


def test_daily_aggregation_requires_exact_rows_and_trusted_raw_quotes() -> None:
    grid = tuple(D1 + timedelta(days=i) for i in range(20))
    trusted = bindings(days=(D1,))
    entry_quote = quote(1)
    exit_quote = quote(2, bid="105", ask="106")
    closed = attempt_round_trip(
        "trusted-raw",
        CONTRACT,
        PRIMARY,
        "LONG",
        entry_quote,
        exit_quote,
        *trusted,
    )
    assert closed.entry is not None and closed.exit is not None
    coverage = full_coverage(grid, {("rb", CONTRACT, D1): 1})
    quote_map = {
        entry_quote.raw_record_hash: entry_quote,
        exit_quote.raw_record_hash: exit_quote,
    }

    def aggregate(
        rows: object,
        evidence: object = coverage,
    ) -> tuple[DailyAggregateRow, ...]:
        return aggregate_fixed_20_day_grid(
            rows,  # type: ignore[arg-type]
            {CONTRACT: "rb", OTHER: "i"},
            grid,
            evidence,  # type: ignore[arg-type]
            terms_bindings=trusted[0],
            fees=trusted[1],
            markups=trusted[2],
            trusted_quotes_by_raw_record_hash=quote_map,
        )

    fake_trade = SimpleNamespace(
        __post_init__=lambda: None,
        attempt_id="fake",
        exact_contract=CONTRACT,
        scenario_id="PRIMARY",
        direction="LONG",
        status="CLOSED",
        entry=closed.entry,
        exit=closed.exit,
        net_cny=Decimal("999999"),
    )
    with pytest.raises(AccountingContractError, match="exact TradeLedgerRow"):
        aggregate([fake_trade])

    fake_coverage = tuple(
        SimpleNamespace(
            product=product,
            exact_contract=contract,
            official_day=day,
            sealed="false",
            priced="false",
            attempt_count=0,
        )
        for product, contract in (("rb", CONTRACT), ("i", OTHER))
        for day in grid
    )
    with pytest.raises(AccountingContractError, match="exact DailyCoverageEvidence"):
        aggregate([], fake_coverage)

    forged_entry_quote = replace(
        entry_quote,
        bid=Decimal("49"),
        ask=Decimal("50"),
    )
    forged = attempt_round_trip(
        "forged-raw",
        CONTRACT,
        PRIMARY,
        "LONG",
        forged_entry_quote,
        exit_quote,
        *trusted,
    )
    with pytest.raises(AccountingContractError, match="trusted raw quote"):
        aggregate([forged])


def test_nested_quote_and_best3_rows_are_revalidated() -> None:
    trusted = bindings()
    entry_quote = quote(1)
    closed = attempt_round_trip(
        "nested-mutation",
        CONTRACT,
        PRIMARY,
        "LONG",
        entry_quote,
        quote(2, bid="105", ask="106"),
        *trusted,
    )
    object.__setattr__(entry_quote, "raw_record_hash", "BAD")
    with pytest.raises(AccountingContractError, match="raw_record_hash"):
        closed.__post_init__()

    grid = tuple(D1 + timedelta(days=i) for i in range(20))
    rows = [
        DailyAggregateRow(product, "PRIMARY", day, 0, Decimal(0), True)
        for product in ("rb", "i")
        for day in grid
    ]
    object.__setattr__(rows[0], "net_cny", Decimal("100"))
    with pytest.raises(AccountingContractError, match="zero-trade"):
        primary_best3_removal(rows, grid)


def test_pooled_best3_removes_same_days_for_two_products_with_offset_peaks() -> None:
    grid = tuple(D1 + timedelta(days=i) for i in range(20))
    values = [
        DailyAggregateRow(product, "PRIMARY", day, 0, Decimal("0"), True)
        for product in ("rb", "i")
        for day in grid
    ]
    replacement = {
        ("rb", grid[0]): Decimal("10"),
        ("rb", grid[1]): Decimal("9"),
        ("rb", grid[2]): Decimal("1"),
        ("i", grid[1]): Decimal("1"),
        ("i", grid[2]): Decimal("12"),
        ("i", grid[3]): Decimal("11"),
    }
    values = [
        DailyAggregateRow(
            row.product,
            row.scenario_id,
            row.official_day,
            1 if (row.product, row.official_day) in replacement else 0,
            replacement.get((row.product, row.official_day), Decimal("0")),
            True,
        )
        for row in values
    ]
    results = primary_best3_removal(values, grid)
    assert {result.removed_days for result in results} == {(grid[2], grid[3], grid[0])}
    assert bootstrap_parameters_gate().status == "BLOCKED"
    with pytest.raises(AccountingContractError, match="zero-trade"):
        DailyAggregateRow("rb", "PRIMARY", grid[0], 0, Decimal("1"), True)
    with pytest.raises(AccountingContractError, match="fixed 20-day"):
        primary_best3_removal(values, tuple(reversed(grid)))


def test_accounting_module_has_no_network_vnpy_rpc_or_order_imports() -> None:
    tree = ast.parse(
        (
            ROOT / "scripts" / "collector_ordered_l1_bbo_change_accounting_v1.py"
        ).read_text()
    )
    imports = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ] + [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]
    assert not [
        name
        for name in imports
        if any(
            token in name.lower()
            for token in (
                "requests",
                "http",
                "socket",
                "websocket",
                "vnpy",
                "rpc",
                "order",
                "ctp",
            )
        )
    ]
