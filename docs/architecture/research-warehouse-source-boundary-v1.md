# Research Warehouse source boundary v1

## Scope

Issue #167 freezes only the source registry and Research authority boundary. It
does not download data, write custody objects, create a catalog, normalize data,
schedule a service, export a C_FAST bundle, or grant any runtime authority.
Those responsibilities remain isolated behind #169, #168, #170, #171, #172,
and #173.

The registry is
`deployments/research-warehouse/source-registry-v1.json`. Its exact raw SHA256
is an input to future acquisition manifests; changing any byte creates a new
registry version.

## Frozen official sources

| ID | Owner | Exact endpoint | Documentation / use terms |
| --- | --- | --- | --- |
| `shfe-daily-market-data-v1` | Shanghai Futures Exchange | `https://www.shfe.com.cn/data/tradedata/future/dailydata/kx{yyyymmdd}.dat` | SHFE 日周数据页 |
| `ine-daily-market-data-v1` | Shanghai International Energy Exchange | `https://www.ine.cn/data/tradedata/future/dailydata/kx{yyyymmdd}.dat` | INE 日周数据页 |

Both endpoints were observed as official-host `application/json` endpoints on
2026-07-29. Public reachability is not interpreted as a transfer of ownership
or an unrestricted license. The exchange usage notice continues to apply.
Future collectors must preserve response bytes and HTTP metadata exactly.

Only exact HTTPS hosts `www.shfe.com.cn` and `www.ine.cn` are admitted.
Credentials, fragments, alternate ports, subdomain suffix matching, IP
addresses, cross-host redirects, and URLs supplied by downloaded content are
not admitted. Every redirect target must pass the same exact-host check.

## Authority and dependency boundary

Registry validation is Research Data Custody / Evidence only. It cannot:

- read account, order, trade, position, RPC, Web Bridge API, TradeService,
  execution QuestDB, tick spool, state, logs, keys, or `.env`;
- produce targets, permits, dispatches, orders, positions, or trading actions;
- authorize control, execution, deployment, production, network, or trading;
- treat a missing response or HTTP 404 as proof of a weekend or holiday.

The Research package is layered:

```text
CLI -> registry parser -> immutable models
                    \-> URL/authority policy
CLI -> static authority boundary
```

No acquisition, custody, catalog, normalization, quality-gate, export,
deployment, or migration code belongs in this package change.

## Threat model

The later M2 deployment is intended to prevent accidental cross-service reads,
ordinary local-process privilege mistakes, and lateral access after compromise
of one unprivileged service. It cannot defend against an attacker with M2
`root`/admin or Docker daemon authority. Host-admin compromise is explicitly
outside the same-host isolation guarantee.

Static import checks are defense-in-depth, not the deployment proof. #172 must
run negative checks under the dedicated `vnpyresearch` identity and prove that
execution paths, secrets, Docker socket, APIs, RPC ports, Windows/CTP/SimNow
addresses, and execution networks are unavailable.

## Verification

```bash
python scripts/research_warehouse_cli.py verify-registry \
  --registry deployments/research-warehouse/source-registry-v1.json
python scripts/research_warehouse_cli.py verify-boundary \
  --source-root scripts/research_warehouse
pytest -q backend/tests/unit/test_research_warehouse_source_registry.py
python -m py_compile scripts/research_warehouse/*.py \
  scripts/research_warehouse_cli.py
```
