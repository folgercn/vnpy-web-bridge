# Windows durable-fence ceremony runner v1

This runner is a verification and orchestration boundary. It does not create
keys, sign artifacts, connect to RPC, submit orders, or infer Windows state.

The safe command is the default dry-run. It reads the exact 22-artifact closure
and public keyring, verifies canonical bytes, signatures, freshness, raw-hash
joins, and the seven-event chain. Missing, unsigned, stale, fixture, or
non-zero evidence fails closed.

The CLI is dry-run only. Programmatic execution requires a separately reviewed
immediate authorization and a query-only host controller. The runner binds the
exact attempt and predecessor evidence returned by each event. It completes
events 1–2, durably reserves event 3 before any SCM call, completes event 4,
dispatches SCM at most once, then collects events 5–7. After event 3 every
exception is query-only against the same attempt; a second blind restart is
forbidden.

No prior approval, merge, dry-run, or successful isolated test authorizes a
real installation, restart, M2 deployment, RPC mutation, or order action.
