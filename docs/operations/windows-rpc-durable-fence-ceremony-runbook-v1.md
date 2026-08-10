# Windows durable-fence ceremony runner v1

This runner is a verification and orchestration boundary. It does not create
keys, sign artifacts, connect to RPC, submit orders, or infer Windows state.

The safe command is the default dry-run. It reads the exact 22-artifact closure
and public keyring, verifies canonical bytes, signatures, freshness, raw-hash
joins, and the seven-event chain. Missing, unsigned, stale, fixture, or
non-zero evidence fails closed.

The checked-in runner has no live mutation path. A future execution command
must be separately reviewed and authorized immediately, then bind its
query-only host controller to the exact attempt and evidence returned by each
event. It must complete events 1–2, durably reserve event 3 before any SCM
call, complete event 4, dispatch SCM at most once, then collect events 5–7.
After event 3 every exception is query-only against the same attempt; a second
blind restart is forbidden.

No prior approval, merge, dry-run, or successful isolated test authorizes a
real installation, restart, M2 deployment, RPC mutation, or order action.
