# Issue #502: real-source PIT precheck (manual pilot)

This is a focused, offline precheck of two **human-defined** candidate formulas. It is not a Provider round, a scientific acceptance of Stage 2, or a trading run. The public [row-level manifest](issue-502-real-source-pit-precheck.json) records all 31 effective rows, their exact input and target prices, source hashes and times, recomputed values, snapshot hashes, Engine outcomes, and verified ResultStore receipt references. The signed source originals and full Engine/Evidence/Critic/Memory artifacts remain in the authorized private evidence directory.

## Independent time basis and what it proves

The [SHFE trading rules effective 2026-06-12](https://www.shfe.com.cn/regulation/exchangerules/rules/202606/P020260603536202760412.docx), SHA256 `2657195f541a79560b60894f3ca7bbc043f30c6c4cf4388e0a6fd1c5ae585e47`, identify trading-day attribution for night sessions (Art. 81(5)), the day session ending at 15:00 China time (Art. 81(7)), and the settlement price as determined after the trading-day close (Art. 81(26)). The [RB](https://www.shfe.com.cn/regulation/exchangerules/productrules/202512/P020251231387806725796.docx) and [HC](https://www.shfe.com.cn/regulation/exchangerules/productrules/202512/P020251231388355404219.docx) product rules, effective 2026-01-01, also specify the 15:00 day-session close (Art. 7). Their pinned hashes are in the manifest. The rule originals were retrieved on 2026-09-30 03:32–03:37 UTC and retained privately. The applicable pilot window is 2026-08-31 through 2026-09-24.

Accordingly, **15:00 Asia/Shanghai on each trading day is only a conservative not-before bound for determining that day's settlement price**. It is not a claimed exchange publication instant or an acquisition timestamp. The warehouse's signed observation and batch/commit receipts separately establish the exact source version and when this warehouse first saw and committed it. The `update_date` in the raw file, HTTP metadata, file mtime, and today's document retrieval time are never used as historical availability proof. The exchange rule establishes night-session trading-day attribution; the signed official calendar supplies the actual trading-day sequence across holidays. Calendar SHA256 is `b0fddf98c56a68d995edc9be9eb0d1277006d5dcfcc62a26a05b6b61984d4291`. The 2026-09-24 signed original differs from a later website download in its `update_date` metadata; the pilot uses the exact signed original rather than silently replacing its version.

The read-only verifier checks the pinned rule bytes, signer public keys, signed calendar, source registry, all 19 daily signed batch chains and commit receipts, run/observation receipts, original raw hashes, exact `rb_f`/`hc_f` January 2027 rows and settlement prices. It rejects missing official days, mismatch, tampering and acquisition or commit before the market close. The original private provenance SHA256 is `e3d6b6b74d8b6617455bcccf7d6eeed3e4f5fbfe8eca1216f40ad03006725354`; the read-only source bundle archive SHA256 is `f680b3bb6c70a9d440e2ba4f57b0e3848be8aaa0b92ea3c8a41d99e14b1a133b`. A caller's provenance SHA or authority label does not establish source trust.

## Manual candidate results

| Human definition | Formula | Warm-up / target tail | Effective PIT rows | Derived snapshot SHA256 | Engine / Critic | Verified ResultStore receipts |
| --- | --- | --- | ---: | --- | --- | ---: |
| RB2701 momentum, k=1 | `log(settlement[t]/settlement[t-1])` | 1 / 2 trading days | 16 | `c9692245d37d0491de91117897f2518364f857deed5015a567b57b9a5a258d44` | COMPLETED / REJECT | 4 |
| HC2701 reversal, k=2 | `-log(settlement[t]/settlement[t-2])` | 2 / 2 trading days | 15 | `5ab8d5eff48d9b80dbb28687ac7ecc1dbc8b9f6ba7c1b557fa25f508b311197c` | COMPLETED / NEED_MORE_EVIDENCE | 4 |

Both use the unchanged target `log(settlement[t+2]/settlement[t+1])`. All 19 official source days are present; no interior days were dropped. The effective row counts reflect only formula warm-up and the two-day target tail. Before Engine, the script independently recomputes every feature and target from signed prices, verifies the per-row target boundary and compares the Engine-produced CSV hash to the precheck CSV. It then reads each Engine receipt from ResultStore with `verify=True` and confirms one Memory entry per manual hypothesis. Critic decisions retain their original scientific meaning; neither is a promotion.

## Authorized replay and limits

The reviewer with access to the private evidence copy can set `EVIDENCE_ROOT` to the original checkout's `.git/issue502-stage2-real-data` directory and run:

```sh
python scripts/precheck_issue502_real_source_pit.py \
  --provenance "$EVIDENCE_ROOT/snapshot-provenance.json" \
  --bundle-root "$EVIDENCE_ROOT/pit-source-final-20260930" \
  --official-rules-root "$EVIDENCE_ROOT/pit-official-20260930" \
  --output "$EVIDENCE_ROOT/reviewer-replay-unique-name"

ISSUE502_SOURCE_BUNDLE="$EVIDENCE_ROOT/pit-source-final-20260930" \
ISSUE502_OFFICIAL_RULES="$EVIDENCE_ROOT/pit-official-20260930" \
ISSUE502_PROVENANCE="$EVIDENCE_ROOT/snapshot-provenance.json" \
python -m pytest -q tests/research_lab/alpha_discovery/test_real_source_time.py
```

The output directory must not exist; the source bundle and existing private caches are never deleted or rewritten. The original execution artifacts are under `$EVIDENCE_ROOT/pit-pilot-final-20260930/<candidate>/` (`precheck/`, `engine/`, `store/`) and the public manifest names each run receipt. The pilot uses existing Integration → Engine → Evidence → Critic → Memory; it does not call Provider, send orders, or alter M2 custody. This verified path is deliberately limited to the named dates, contracts, source and pinned rules. Other dates/sources remain fail-closed pending their own independent evidence. #502 and Stage 2 scientific acceptance stay **BLOCKED** until the separately authorized two 10-slot Provider rounds and Memory feedback are rebuilt from trusted observations.
