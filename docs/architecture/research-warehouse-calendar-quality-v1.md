# Research Warehouse calendar and history quality v1

Issue #170 adds a fail-closed authority layer between immutable daily evidence
and later research features. It does not normalize data, build the catalog,
compute signals, or grant execution authority.

## Layer boundaries

- `official_calendar.py` verifies a canonical Ed25519-signed calendar and the
  exact raw SHFE/INE source evidence named by that calendar.
- `trade_day_mapping.py` maps stored UTC timestamps through the frozen
  `Asia/Shanghai` session rules.
- `clock_quality.py` enforces NTP offset, sample age, and future-skew limits.
- `source_availability.py` classifies HTTP 200/404 responses only after an
  authoritative calendar classification exists.
- `absence_receipts.py` publishes create-only evidence for an authorized 404.
- `daily_evidence.py` independently reads the signed revision's exact raw bytes
  and extracts product coverage.
- `quality_gate.py` coordinates PIT anchors, official days, daily evidence, and
  the exact ten-product 126+60-day contract.

The signed calendar is a separate authority artifact. A missing calendar entry,
HTTP 404, weekday calculation, or derived catalog row can never create an
official-day or holiday classification.

## Calendar authority

The calendar must:

- bind the exact INE and SHFE exchanges, official HTTPS owners, raw source
  paths, byte counts, and SHA-256 hashes;
- explicitly classify every natural date in its validity range as
  `OFFICIAL_DAY` or `CLOSED`;
- retain at least 186 official days and explicitly authorize each preceding
  evening session;
- store timestamps in UTC while declaring `Asia/Shanghai` as the exchange
  timezone;
- match an externally pinned calendar hash and trusted Ed25519 public key.

Source evidence is read from private, non-symlink custody directories both
when the calendar is loaded and immediately before history evaluation. A
missing, changed, linked, or permission-weakened source artifact fails closed.

## Session and availability rules

The frozen local windows are day `08:30–16:00`, evening `20:00–23:59:59`, and
after-midnight `00:00–03:00`. An evening timestamp maps to the next natural
date; an after-midnight timestamp maps to that natural date. The target date
must be an official day whose `previous_evening_session` flag is true.
Timestamps outside the declared session window fail closed.

Calendar-aware acquisition requires a trusted NTP sample. HTTP 200 is accepted
only for an official day. HTTP 404 is accepted only for an explicitly closed
day and produces an append-only absence receipt. An official-day 404, a
closed-day 200, a missing classification, or another status fails closed.

## 186-day PIT quality gate

The gate requires exactly `ag`, `al`, `au`, `bu`, `cu`, `rb`, `ru`, `sc`,
`sp`, and `zn` for 126 trend-history plus 60 volatility-lookback official
days. The as-of date must be official and the execution date must be the next
official date.

Only manifests whose external commit-anchor `available_at` is at or before the
UTC cutoff are eligible. For every required day, the gate verifies the exact
raw revision bytes, authoritative report date, source schema, exchange/product
binding, and all ten products. Missing days, missing products, future-dated
revisions, broken anchors, or changed raw bytes fail closed. A legitimate
revision available before the cutoff replaces the earlier revision for that
source and day.

Daily `OPENPRICE` has evidence class
`OFFICIAL_DAILY_SUMMARY_POST_CLOSE`. It is explicitly ineligible as intraday
observed-open evidence.

## Commands

The CLI exposes `verify-calendar`, `map-trade-day`,
`acquire-calendar-aware`, and `quality-gate`. Each command requires explicit
calendar path, trusted calendar SHA-256, trusted public key, and raw source
evidence root. Acquisition and quality evaluation additionally require an NTP
sample; the quality gate also requires the signed manifest-chain heads and
externally pinned commit-anchor ledger. Run:

```bash
python scripts/research_warehouse_cli.py <command> --help
```

for the complete argument contract.
