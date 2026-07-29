# Research Warehouse M2 isolation v1

Issue #172 defines the native macOS service boundary for Research Warehouse.
It does not activate a LaunchDaemon, create a local user, or modify PF by
merging this repository. Those root-level host changes require an explicit
operator action followed by freshly captured, externally SHA-pinned evidence.

## Layering

- `m2_isolation_contracts.py` loads the frozen raw-SHA-pinned deployment
  policy and canonical evidence envelope.
- `m2_deployment_assets.py` verifies the two raw-pinned LaunchDaemon assets
  and PF anchor.
- `m2_isolation_audit.py` verifies dedicated identity, exact environment,
  filesystem denials, process separation, egress results, and monitor result.
- `m2_monitor.py` is a pure evaluator for last success, missing official day,
  unreviewed revision, hash mismatch, disk capacity, and backup freshness.
- `m2_isolation_cli.py` is argument and output plumbing.

These modules import no Web Bridge app, vn.py, RPC, QuestDB, Docker,
SQLAlchemy, account, order, position, trade, or execution service.

## Identity and filesystem

The service identity is exactly `vnpyresearch:vnpyresearch`. Its HOME,
custody, runtime, backup and temporary directories are under
`/Users/Shared/vnpy-research`, owned by that identity and mode `0700`.
Launchd applies umask `077` and an exact five-variable environment:

```text
HOME=/Users/Shared/vnpy-research/home
LANG=C.UTF-8
PATH=/usr/bin:/bin:/usr/sbin:/sbin
PYTHONNOUSERSITE=1
TMPDIR=/Users/Shared/vnpy-research/runtime/tmp
```

Proxy, Docker, Web Bridge, RPC and trading environment variables are absent,
not blank. The service must not inherit an ACL that traverses `/Users/fujun`.
Negative probes run as the dedicated identity and record `false` for every
frozen forbidden path, including `.netrc`, Keychain, Web Bridge `.env`, logs,
tick spool, state, keys and `/var/run/docker.sock`.

The Research process has a distinct uid/gid, credential scope and process
identity. It does not join the Web Bridge Docker network or share a writable
mount. The evidence field `shared_network_namespace=false` means the native
Research process is not a member of the Web Bridge container namespace; it
does not claim that macOS provides Linux-style per-user network namespaces.
PF supplies the host-native per-uid network policy boundary.

## Egress

`pf.vnpyresearch.conf` permits three exact table/port classes first and then
applies a final quick block to all other outbound traffic for `vnpyresearch`:

- TCP/UDP 53 to an administrator-populated literal DNS table;
- UDP 123 to an administrator-populated literal NTP table;
- TCP 443 to an administrator-populated literal registry table.

PF config never contains hostnames because PF resolves names at load time.
Before each activation, the operator resolves the two frozen registry hosts
through the approved resolver, reviews literal addresses, populates the PF
table, loads the anchor, and captures the table contents. Application URL
policy still requires exact HTTPS hosts `www.shfe.com.cn` and
`www.ine.cn`; an allowed IP alone grants no HTTP authority.

Negative connectivity evidence is required for localhost/M2 Web Bridge API,
Windows RPC request/publish ports, Docker socket and unexpected egress.
The service must not possess `sudo`, PF, launchctl, Docker or admin authority.

## LaunchDaemons

The two raw-SHA-pinned plist files run as `vnpyresearch`, use only the exact
minimal environment, and invoke raw-pinned wrappers beneath the root-owned
`/usr/local/libexec/vnpyresearch` tree:

- `com.vnpy.research-warehouse`: scheduled warehouse acquisition/sealing;
- `com.vnpy.research-warehouse-monitor`: 15-minute health evaluation.

The wrapper files, their complete parent chain and the release tree are
root-owned and non-writable by the service; neither entrypoint is beneath a
service-owned runtime directory. The service writes only its private
custody/runtime/backup roots. Activating the plists before PF default-block
and negative preflight pass is forbidden.

## Monitoring

The monitor fails degraded on any of:

- stale last successful run;
- missing/latest official-day gap;
- unreviewed revision;
- raw/hash mismatch;
- less than 50 GiB free;
- backup older than 26 hours or not read-back verified.

Monitor success grants no Control, Deployment, Execution, network expansion,
permit, RPC, account, order, position, trading or production authority.

## Evidence and verification

Evidence is canonical JSON line, private, externally retained by its exact raw
SHA-256. It binds the host identity, frozen policy/registry, uid/gid and
supplementary groups, loaded plist hashes, exact environment, root
ownership/modes/devices, every negative read/connectivity result, PF state,
process separation and monitor inputs. A copied or edited evidence file is
rejected before semantic verification.

Policy, PF and LaunchDaemon activation times are bound to their exact hashes.
Every identity, launchd, environment, filesystem, network and process probe
has an observation time and result hash and must occur after all activation
steps. The create-only success receipt binds host, uid/gid, policy, plist, PF,
externally pinned release-tree hash, output hash and completion time. Its
completion must equal the monitor's last-success time; backup verification
must also be newer than activation. This prevents replaying pre-activation
probe or success artifacts.

```bash
PYTHONPATH=scripts python scripts/research_warehouse_m2_isolation_cli.py \
  --policy deployments/research-warehouse/m2/isolation-policy-v1.json \
  --deployment-dir deployments/research-warehouse/m2 \
  --evidence /secure/external/m2-isolation-evidence.json \
  --expected-evidence-sha256 <independently-retained-sha256> \
  --expected-release-tree-sha256 <independently-retained-release-sha256> \
  --now <trusted-canonical-UTC-Z>
```

Success is only `M2_RESEARCH_ISOLATION_VERIFIED`. Root/admin or host-kernel
compromise remains outside the same-host threat model.
