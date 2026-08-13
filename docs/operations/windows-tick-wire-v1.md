# Windows tick-only wire v1

This is a validation-only, no-trading runbook.  TCP/4102 remains the mixed vn.py
RPC PUB channel for Execution and must not be changed.  The separate publisher
binds only TCP/4103 and emits `(ASCII eTick.v1.<vt_symbol>, canonical JSON)`.

1. Before change, record hashes of the installed Windows bundle/configuration,
   back up the current bundle, and record the M2 market-worker image and durable
   state volume identity.  Do not restart an active order-bearing controller.
2. Install the reviewed bundle whose frozen inventory includes
   `windows_tick_wire_v1.py` and `windows_position_readiness_v1.py`.  The fixed
   launcher binds readiness and the tick publisher before `main_engine.connect`;
   do not add a second manual hook to `run_rpc_server.py`.
3. On Windows, add only a TCP/4103 inbound firewall rule scoped to source
   `192.168.100.89`.  Do not broaden the existing Windows SSH/RPC firewall and
   do not alter TCP/4102.
4. Deploy the M2 worker image configured for `gateway-tick-wire-proxy:4103`.
   Keep all trading flags false.  Start Windows first, then the fixed tick proxy,
   then market-data worker; verify the proxy listener/readiness and a durable
   verified-tick readback with matching `eTick.v1.<vt_symbol>`/JSON fields.
5. Read `peek_current_facts_v1`: `position_query_complete` must be explicitly
   `true` before any snapshot/target adaptation; `false` is an expected
   fail-closed state, including a verified empty position query.

If any listener, JSON validation, position readiness, or readback check fails,
keep trading disabled; restore the previous Windows bundle and previous M2
worker image while preserving the existing market-data state volume, then
confirm TCP/4102 and the old worker path recover.  Do not delete or rewrite the
durable stream/state as part of rollback.
