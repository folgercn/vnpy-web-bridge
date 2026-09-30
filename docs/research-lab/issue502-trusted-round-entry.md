# #502 trusted-source round entry

The two existing round runners now import their own checkout, accept explicit
read-only evidence and isolated output roots, and use the installed FastMCP
stdio boundary rather than the historical repository-local Desktop backend.
Before any Provider call, they verify the pinned provenance and all 19 signed
SHFE trading days using the #592 official settlement-time rules. Both candidate
precheck and Engine binding receive the same source bundle and official rules.
Scientific identity, Runner methods, Critic thresholds and the byte-identical
objective are unchanged.

## Offline source check

Use the existing Unix Python environment with `cryptography==48.0.0` and the
reviewed private evidence root. Set `OUTPUT_ROOT` to a new isolated directory,
separate from the evidence directory. The installed MCP argv must be a JSON
array ending in `--transport`, `stdio`; there is no shell expansion or fallback
transport. The offline check neither starts MCP nor writes a ResultStore:

```sh
python scripts/run_stage2_universal_round1_real.py \
  --run-id trusted-unique-name \
  --evidence-root "$EVIDENCE_ROOT" \
  --output-root "$OUTPUT_ROOT" \
  --mcp-command '["/absolute/path/to/agy-mcp", "--transport", "stdio"]' \
  --preflight-only
```

Expected outcome is `SOURCE_PREFLIGHT_PASS`, `verified_source_days=19`,
`provider_submissions=0`, `scientific_memory_writes=0`, and
`stage2_accepted=false`. This check is not a Discovery round.

## Real round gate and recovery

After the actual checkout is registered to the exact `vnpy` project in
Antigravity, run the same command without `--preflight-only`. The existing
Router, quota, ExecutionPreparation and candidate admission remain mandatory.
The entry does not register a project, select another cwd, switch accounts,
cancel shared jobs or alter permissions. An active scheduler or unknown quota
blocks execution. Record the implementation commit and runtime with the run.

The new run root contains `trusted-source-binding.json`; historical roots
without this marker cannot resume or become Round 2 inputs. Submission handles
are saved immediately under `round_1/provider_raw/submission_NN.json`, before
waiting for results. Observation uses bounded `watch` calls for the same job
and cursor; exhaustion raises engineering uncertainty and halts further
submissions. Never restart an incomplete Provider batch to obtain new jobs.
Reconcile the recorded job before further action. Existing `--resume` is only
for a batch whose completed batch-result JSON is already present.

Once Round 1 is persisted and its source, receipts and Memory B are verified,
invoke `scripts/run_stage2_universal_round2_real.py` with the same arguments and
run ID. It retains the existing isolated Round 2 store and unchanged R1 SQLite
check. A scientific decision can be REJECT or NEED_MORE_EVIDENCE. Acceptance
requires the actual two requested=10 funnels, complete per-slot provenance and
an auditable effect of valid R1 Memory on R2; no CLI success message grants it.

## Current verification and limitation

On `main@30f574e4` plus this entry change, the offline source check passed all
19 reviewed days. A new, isolated **human-defined** pilot reproduced RB2701
momentum k=1 with 16 rows / REJECT and HC2701 reversal k=2 with 15 rows /
NEED_MORE_EVIDENCE; all 8 ResultStore receipts were read with `verify=True`.
The private source was protected by a no-network, read-only OS profile.
These are source readiness evidence, not Provider Round 1 or Stage 2 PASS.

Focused Session/Batch/M5/M6/signal-binding regression: 284 passed, 1 skipped.
After the final CLI/lineage additions, entry-point tests: 25 passed; Ruff and
whitespace checks passed. The real installed stdio tools were discovered, but
`projects(cwd)` for the isolated checkout returned `PROJECT_NOT_FOUND`.
No new Provider task was submitted. #502 remains OPEN and Stage 2 acceptance
remains pending; #500, #586 and #587 have not started.

### #593 review corrections

The stdio transport now correlates exact JSON-RPC request IDs and reads complete
frames until the matching response. Notifications update a durable same-job watch
cursor; unrelated responses cannot complete a request. EOF, timeout, malformed
frames and tool errors fail closed. The regression peer uses the actual installed
FastMCP library, emits a notification before its response, and never submits a
model job.

Submission ownership intent is atomically persisted before submit. A lost submit
response, accepted-handle persistence failure or unresolved first result halts the
actual batch: later slots are not attempted, ownership is classified uncertain,
and submit is never retried. Two-slot regressions exercise both runner hooks
through DiscoveryBatchOrchestrator.

Round 2 rebuilds the controlled view from the current round 1 database opened
read-only, checks its persisted view and evidence summary, and verifies each run
receipt. Historical view IDs, hashes, entry counts and fixed missing-dimension
text are no longer prerequisites. Required structured stability/outlier gaps
remain enforced. Contract fixtures exercise this boundary only; they do not count
as either real Provider round or scientific acceptance.

### Complete R1 scientific reference coverage

Before creating the Round 2 Provider, the runner reads **all** original R1
Memory records through the existing read-only domain reader, including records
outside the bounded controlled view. Every evaluation record must occur exactly
once in the integration summary. The summary's hypothesis identity, final plan,
Critic decision and complete task/spec/run/manifest/evidence reference sets must
agree with those records. Each declared run is then re-read with
`ResultStore.query_v2_runs(..., verify=True)`; receipt IDs, hashes, applicable
revisions and run status must resolve all Memory references. Removing a receipt
and also omitting it from the summary cannot hide a remaining Memory reference.
A resumed R2 continues using the original R1 reader rather than its own expanded
Memory database.

This is a consistency check of existing local research artifacts and verified
receipts. It adds no new trust source and does not authenticate a rewritten local
artifact collection as a real Provider round. Real two-round provenance, trusted
PIT sources and measurable Memory feedback remain the #502 acceptance gate.
