# Issue #362 continuous SimNow night-run gate

This run is a non-countable `simnow_shakedown`. It must not be described as
production, live trading, or official forward performance.

## Frozen bootstrap

The one-time August bootstrap replays the already verified July monthly pair:

- STATIC_CORE_EQUAL: `ac134a0a78e4273df6451ad6106010bdcdeaa801654f4c241fc0782a0d295c51`
- position manager: `eee9517b172ffb665cd1ea3895a5cb123e03ee4ea448dd0f97fe096878a1708e`
- final target: `5e25217e1eb6f1f6cba42890ef5c817e4740fb1b5e58a8aa72ac40912d20bdef`

The frozen target quantity vector is `ag=-2, al=11, au=-2, bu=30, cu=4,
rb=-81, ru=-8, sc=2, sp=-29, zn=12`. STATIC_CORE_EQUAL remains the reviewed
50/50 blend of `C_FAST_CROSS_SECTION_NEUTRAL` and
`D_DONCHIAN20_EXIT10_NEUTRAL`; no separate intraday-HFT strategy is introduced
by this runner.

It is accepted only while the current verified daily official day is in
`2026-08`, the custody head is `NO_EVENT`, the account is a quiescent flat
Genesis, and the replayed monthly target also belongs to `2026-08`. The normal
selector remains unchanged for every non-Genesis event. In September the
bootstrap is rejected; the next monthly event must come from completed August
data.

The target itself is the signal. Starting the service at market open does not
create an order. An order can be admitted only when the selector emits a real
MONTHLY or ROLL event, full-account ownership returns `NEW_TARGET` or
`RESUME_AFTER_CLOSE`, exact formal quotes are fresh, and Execution is ready.

## Prepare the root-managed config

1. As root, copy the adjacent template into a private directory owned by the
   locked host `vnpyresearch` UID/GID used by the container.
2. Replace all Warehouse paths and SHA-256 pins from the current M2 root.
3. Inject the three shared secrets from the root secret store. Never commit the
   materialized file.
4. Keep `simnow_execution_enabled` set to `false` for the dry run.
5. Canonicalize to one UTF-8 JSON line, create the lock file, and enforce the
   exact ownership/modes required by the runner:

```sh
install -d -o "$SIMNOW_CONTINUOUS_UID" -g "$SIMNOW_CONTINUOUS_GID" -m 0700 "$SIMNOW_CONTINUOUS_CONFIG_DIR"
python -c 'import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text()); p.write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n")' "$SIMNOW_CONTINUOUS_CONFIG_DIR/simnow-continuous.json"
install -o "$SIMNOW_CONTINUOUS_UID" -g "$SIMNOW_CONTINUOUS_GID" -m 0600 /dev/null "$SIMNOW_CONTINUOUS_CONFIG_DIR/simnow-continuous.lock"
chown "$SIMNOW_CONTINUOUS_UID:$SIMNOW_CONTINUOUS_GID" "$SIMNOW_CONTINUOUS_CONFIG_DIR/simnow-continuous.json"
chmod 0600 "$SIMNOW_CONTINUOUS_CONFIG_DIR/simnow-continuous.json"
```

Set `SIMNOW_CONTINUOUS_LIBEXEC_ROOT=/usr/local/libexec/vnpyresearch` and
`SIMNOW_CONTINUOUS_WAREHOUSE_ROOT=/Users/Shared/vnpy-research` on the M2 host.
The compose mounts preserve those absolute names because the signed runtime
input and isolation policy bind them. Both mounts are read-only and the root
private signing-key directory is never mounted.

## Dry-run gate

Keep the Execution and custody mutation flags disabled and run exactly one
pass. A new signal returns fail-closed `STOP`; an already installed event may
report a `BLOCKED` lifecycle. Both results must show no event/plan custody,
leader, Execution, or gateway mutation:

```sh
docker compose -f deployments/docker-compose.final.yml \
  --profile simnow-continuous run --rm simnow-continuous-runner
```

Do not enable the run unless all of these are independently observed:

- installed images are the reviewed exact digests;
- `SIMNOW_CONTINUOUS_UID/GID` exactly match the owner of every private M2
  evidence file; do not run the continuous container as root;
- M2 runtime input, catalog head, history receipt, public keys, signed baseline,
  and contract registry match the root-managed config pins;
- account scope and environment are the intended SimNow account;
- Execution is `READY`, `RECONCILED`, has no unknown outcome, no active order,
  no pending intent, and the fresh account is flat for the Genesis run;
- Windows has subscribed the complete exact-contract set required by the
  CLOSE/OPEN phase and the formal journal has one stable generation, ack zero,
  fresh bid/ask events, and correct price ticks for every required contract;
- Phase-C custody head and deterministic CLOSE/OPEN recovery keys have no
  foreign or ambiguous artifact;
- one operator explicitly authorizes this non-countable SimNow mutation.

## Enable one pass

Only after the gate above, set all three explicit SimNow execution switches:

```text
config: simnow_execution_enabled=true
compose: EXECUTION_ALLOW_SIMNOW_EXECUTION=true
compose: SIMNOW_EXECUTION_ENABLED=true
compose: SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED=true
```

Canonicalize the config again, then invoke the same one-shot command. Never
run two instances: the existing service-owned nonblocking lock is the local
process fence. WatchPaths or market-open time may wake a pass, but neither is
authority.

On a timeout, response loss, restart, or `UNKNOWN_OUTCOME`, do not publish a
new event or plan and do not resend an order. Re-run the same command; the
runner must query the same event/phase/command keys, resume existing intents
query-only, and first-send only an actually missing deterministic intent.

## Stop conditions

Leave execution disabled and stop the run on any root drift, stale/missing
quote, price incompatibility, foreign leader/plan, custody version drift,
unresolved active order, unknown broker outcome, non-flat Genesis account, or
failed completion archive. These are evidence failures, not reasons to bypass
the gate.
