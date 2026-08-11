# Windows RPC validation-only attach v1

For the existing `C:\quant\run_rpc_server.py`, call this after the legacy
`RpcServiceApp` is built and before `rpc_engine.start(...)`:

```python
from scripts.windows_rpc_durable_fence_v1 import (
    attach_windows_rpc_validation_only_v1,
)

attach_windows_rpc_validation_only_v1(
    rpc_engine=rpc_engine,
    event_engine=event_engine,
    main_engine=main_engine,
)
rpc_engine.start("tcp://*:2014", "tcp://*:4102")
```

The attach has no public gateway, scope, environment, or store-path override:
it always uses `CTP`, `account:windows`, `simnow`, and
`C:\quant\durable\execution-final-admission-v1.json`. It replaces legacy
`send_order` and `cancel_order` with FROZEN deny-only handlers, exposes only
`peek_current_facts_v1`, and rejects a second attach. It starts no gateway and
accepts no credentials or caller-provided handlers. `peek` rejects missing or
foreign-gateway account, position, order, and active-order facts. It does not
perform preflight, outcome classification, or reconciliation.

## Reconciliation-only attach

For a fixed-scope durable observation surface, use the separately named attach
instead:

```python
from scripts.windows_rpc_durable_fence_v1 import (
    attach_windows_rpc_reconciliation_only_v1,
)

attach_windows_rpc_reconciliation_only_v1(
    rpc_engine=rpc_engine,
    event_engine=event_engine,
    main_engine=main_engine,
)
rpc_engine.start("tcp://*:2014", "tcp://*:4102")
```

It has the same fixed `CTP`, `account:windows`, `simnow`, and
`C:\quant\durable\execution-final-admission-v1.json` binding and accepts no
path, scope, environment, credentials, or handler override. The listener must
not have started. Legacy `send_order` and `cancel_order` remain permanent
FROZEN denials; the only readable RPCs are `peek_current_facts_v1` and
`get_execution_snapshot_v1`. Every snapshot allocates its generation through
the existing durable store allocator. A repeated or failed attach is
fail-closed and leaves only the legacy frozen denials after failure.
