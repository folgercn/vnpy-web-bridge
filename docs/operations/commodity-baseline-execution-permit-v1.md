# Commodity baseline Execution Permit v1

This boundary applies only to non-C_FAST CommoditySimNow execution: the frozen
`STATIC_CORE_EQUAL` baseline and the
`MONTHLY_RELATIVE_VOL_THERMOSTAT_V1` position-manager shakedown. It does not
authorize production/live trading, C_FAST, the manual `/orders` route, or
automatic promotion.

One permit authorizes exactly one plan phase (`close` or `open`). The next phase
requires a newly drafted and signed permit. Dynamic L1 repricing is allowed only
inside every signed order's price band and the signed price-policy/risk envelope.
The bridge never holds the private signing key.

`TradeService.send_order()` and capability-free `_send_order()` are permanently
fail-closed. Executable order RPC is reachable only through the mutually
exclusive C_FAST, manual-permit, or baseline-permit private capabilities.

## One-time signer/keyring setup

Generate an Ed25519 PEM on an offline machine and keep it outside the repo and
runtime host. Use a key that is not present in any C_FAST, target-batch, or
manual-order keyring.

```bash
openssl genpkey -algorithm ED25519 -out baseline-permit-offline.pem
python scripts/commodity_baseline_execution_permit.py keyring \
  --private-key baseline-permit-offline.pem \
  --signer-key-id baseline-permit-operator-v1 \
  --output commodity-baseline-permit-keyring-v1.json
```

Record the printed `keyring_raw_sha256`. Install only the public keyring on the
runtime host. Keep its canonical bytes unchanged.

## Draft, review, sign, and preinstall the phase pair

Stop before the signing step if the active plan is not the intended account,
strategy, session, phase, order set, or risk budget. The draft command verifies
the persisted active-plan checksum and immutable execution-core hash.

```bash
python scripts/commodity_baseline_execution_permit.py draft \
  --active-plan logs/commodity-simnow/state.active.json \
  --phase close \
  --signer-key-id baseline-permit-operator-v1 \
  --price-band-percent 3 \
  --output baseline-close.draft.json

python scripts/commodity_baseline_execution_permit.py draft \
  --active-plan logs/commodity-simnow/state.active.json \
  --phase open \
  --signer-key-id baseline-permit-operator-v1 \
  --price-band-percent 3 \
  --output baseline-open.draft.json
```

Review every `minimum_price`, `maximum_price`, order, and risk limit. Transfer
the reviewed draft to the offline signer, then create a new output path:

```bash
python scripts/commodity_baseline_execution_permit.py sign \
  --input baseline-close.draft.json \
  --private-key baseline-permit-offline.pem \
  --output baseline-close.signed.json

python scripts/commodity_baseline_execution_permit.py sign \
  --input baseline-open.draft.json \
  --private-key baseline-permit-offline.pem \
  --output baseline-open.signed.json

python scripts/commodity_baseline_execution_permit.py verify \
  --permit baseline-close.signed.json \
  --keyring commodity-baseline-permit-keyring-v1.json \
  --active-plan logs/commodity-simnow/state.active.json

python scripts/commodity_baseline_execution_permit.py verify \
  --permit baseline-open.signed.json \
  --keyring commodity-baseline-permit-keyring-v1.json \
  --active-plan logs/commodity-simnow/state.active.json
```

Never overwrite a prior signed permit or consumption marker. Before the one-key
start/auto-dispatch action, atomically install both signed files at their fixed
close/open paths. If both phases contain orders, the close preflight validates
the complete pair before its first RPC call. Do not replace a permit while the
plan is running. Open-only plans require only the open permit file to be valid.

## Runtime configuration

The feature is fail-closed and default-off. All paths must be distinct. The
consume directory is create-only, owner-only (`0700`); an existing directory
with broader permissions is rejected and is never chmod-mutated.

```dotenv
COMMODITY_BASELINE_EXECUTION_PERMIT_ENABLED=true
COMMODITY_BASELINE_EXECUTION_PERMIT_CLOSE_PATH=/run/secrets/commodity-baseline/close-permit.json
COMMODITY_BASELINE_EXECUTION_PERMIT_OPEN_PATH=/run/secrets/commodity-baseline/open-permit.json
COMMODITY_BASELINE_EXECUTION_PERMIT_TRUSTED_KEYRING_PATH=/run/secrets/commodity-baseline/trusted-keys.json
COMMODITY_BASELINE_EXECUTION_PERMIT_EXPECTED_KEYRING_RAW_SHA256=<64 lowercase hex>
COMMODITY_BASELINE_EXECUTION_PERMIT_CONSUME_ROOT=/var/lib/vnpy-web-bridge/commodity-baseline-permit-consumed
COMMODITY_BASELINE_EXECUTION_PERMIT_MAX_TTL_SECONDS=600
```

Load/restart the bridge only after installing the public keyring and pin. A
missing/expired/tampered/wrong-phase permit results in zero order RPC calls.
When both preinstalled permits remain inside their signed validity windows, the
existing reconciler may advance close to open without a file swap or restart.
The first child consumes the phase permit inside the shared RPC and dispatch
abort locks. A timeout or unknown outcome burns the permit and halts the phase;
restart recovery must reconcile existing send intents and never replays it.
Even after a successful child ACK, a process restart does not automatically
continue the remaining children of that phase: the active plan enters safe-halt
recovery and requires reconciliation/new authority. This is intentionally more
conservative than in-process continuation after a safe ACK.
