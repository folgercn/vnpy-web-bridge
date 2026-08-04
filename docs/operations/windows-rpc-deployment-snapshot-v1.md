# Windows RPC deployment snapshot v1

This runbook describes the code-only A2 extension. It does not authorize a
Windows service change or restart.

## Assembly

Copy `scripts/windows_rpc_deployment_snapshot_v1.py` beside the managed
`run_rpc_server.py`. After `RpcServiceApp` creates `rpc_engine` and before
`rpc_engine.start(...)`, register the extension with vn.py's actual event
constants:

```python
from vnpy.trader.event import (
    EVENT_ACCOUNT,
    EVENT_ORDER,
    EVENT_POSITION,
    EVENT_TRADE,
)
from windows_rpc_deployment_snapshot_v1 import (
    register_windows_rpc_deployment_snapshot_v1,
)

deployment_snapshot_v1 = register_windows_rpc_deployment_snapshot_v1(
    rpc_engine,
    event_engine,
    main_engine,
    order_event_type=EVENT_ORDER,
    trade_event_type=EVENT_TRADE,
    position_event_type=EVENT_POSITION,
    account_event_type=EVENT_ACCOUNT,
)
```

Registration fails if the MainEngine exposes CTA/strategy control methods.
It replaces the RPC registry's final `send_order` and `cancel_order` entries
with admission wrappers, then registers
`get_deployment_safety_snapshot_v1(request_id, challenge)`. Snapshot capture
sends no order, but it deliberately freezes Windows RPC order/cancel admission
before waiting for in-flight mutations and copying facts on the EventEngine
thread. A2 exposes no Windows unfreeze RPC.

## Safety boundary

- Never place CTP credentials, signing keys, tokens, or account IDs in the
  repository or this runbook.
- Back up the managed script before installation.
- A service restart requires explicit operator authorization and a safe
  trading window. A2 merging alone is not restart authorization.
- Until the extension is installed, Linux online snapshot acquisition fails
  closed and `scripts/deploy.sh` remains hard-frozen.
- A2 has no coordinated unfreeze path: once capture installs the Windows
  fence, both the online Linux drain and Windows admission remain frozen until
  a later phase supplies challenge-bound reconciliation. Do not use the legacy
  Linux `release()` path for an online checkpoint.
- After installation, first validate read-only schema, server instance,
  request/challenge echo, freshness, generation, exactly one allowlisted
  account hash, zero pending send outcomes, zero active orders, and zero Linux
  sends. Do not activate receipt consumption or reconciliation in A2.
