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
- `m2_probe_binding.py` recomputes domain-separated canonical hashes for each
  normalized post-activation probe class.
- `m2_release_artifacts.py` rescans the root-owned release tree and successful
  output against independently retained raw-pinned artifacts.
- `m2_release_tree_custody.py` performs the fd-relative recursive scan, keeps
  every directory descriptor held, then reopens each bounded-lifetime file
  descriptor from its held parent and rechecks identity, content and directory
  membership before release verification completes.
- `m2_release_lock.py` supplies the root-owned deployment lock: verification
  and job execution take a shared lock; every supported release update must
  take the exclusive lock.
- `m2_wheelhouse.py`, `m2_python_runtime_archive.py`,
  `m2_python_runtime.py`, `m2_release_contracts.py`, `m2_release_builder.py`
  and `m2_release_install.py` build an offline,
  exact-byte tree from a raw-pinned self-contained Python 3.12.13 archive,
  wheelhouse and committed Git blobs, then switch it only under that exclusive
  lock. The complete private interpreter, standard library, dependencies and
  release remain independently manifested.
- `m2_success_binding.py` binds those verified artifacts to one exact
  post-activation success receipt and monitor completion.
- `m2_verifier.py` is the only public layer that can issue final
  `M2_RESEARCH_ISOLATION_VERIFIED`; it always loads raw-pinned files, takes
  the deployment lock and performs artifact I/O before semantic checks.
- `m2_monitor.py` is a pure evaluator for last success, missing official day,
  unreviewed revision, hash mismatch, disk capacity, and backup freshness.
- `m2_isolation_cli.py` is argument and output plumbing.

These modules import no Web Bridge app, vn.py, RPC, QuestDB, Docker,
SQLAlchemy, account, order, position, trade, or execution service.

## Identity and filesystem

The service identity is exactly `vnpyresearch:vnpyresearch` with the
raw-pinned M2 UID/GID `503:503`. Its HOME,
custody, runtime, backup and temporary directories are under
`/Users/Shared/vnpy-research`, owned by that identity and mode `0700`.
macOS automatically adds every local account to the non-admin system groups
`everyone` (12), `localaccounts` (61), and `_lpoperator` (100). The policy
freezes exactly those unavoidable groups plus the fixed primary GID; evidence
normalizes the effective GID set in ascending order and rejects any additional
group or substituted primary group such as `admin`, `wheel`, or a
Docker/operator group.
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

Both raw-pinned wrappers enter the root-owned `release-lock-runner`. The
runner validates `/usr/local/libexec/vnpyresearch/release.lock` as a
root-owned, single-link `0444` regular file, takes a shared lock and keeps its
descriptor inherited for the entire warehouse/monitor process lifetime.
The selected release launcher then executes only
`release/runtime/bin/python3.12 -B -I`; no Homebrew, user-site or workspace
Python pathname participates in the warehouse/monitor runtime.
The verifier holds the same shared lock from tree scan through final result.
All supported root release installation or switching must use
`hold_release_update_lock()` for the entire mutation; the exclusive lock
serializes it against verification and running jobs. Direct in-place changes
that ignore this contract are unsupported root compromise, not a deployment
path.

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
has an observation time and a domain-separated canonical result hash. The
verifier recomputes that hash from probe class, host identity, observation
time and the exact normalized result, so a digest cannot be copied across
classes or paired with edited safe claims. Every probe must occur after all
activation steps.

A separately retained canonical release-tree manifest binds every relative
path, type, byte count, raw SHA-256, owner/mode/link fact, device/inode and
the release-root identity. Verification rescans the installed root-owned tree
and requires exact manifest equality while the shared deployment lock is
held. The successful output is also read
through stable non-symlink custody and checked against an independent raw
SHA-256 plus device/inode/owner/mode/link facts. The create-only success
receipt binds those verified artifacts together with host, uid/gid, policy,
plist, PF, exact deployment-lock identity and completion time. Its completion
must equal the monitor's
last-success time; backup verification must also be newer than activation.
This prevents pre-activation replay and hash-only artifact claims.

```bash
PYTHONPATH=scripts python scripts/research_warehouse_m2_isolation_cli.py \
  --policy deployments/research-warehouse/m2/isolation-policy-v1.json \
  --deployment-dir deployments/research-warehouse/m2 \
  --evidence /secure/external/m2-isolation-evidence.json \
  --expected-evidence-sha256 <independently-retained-sha256> \
  --release-root /usr/local/libexec/vnpyresearch/release \
  --release-tree-manifest /secure/external/release-tree-manifest.json \
  --expected-release-tree-manifest-sha256 <retained-manifest-sha256> \
  --success-output /Users/Shared/vnpy-research/runtime/success-output.json \
  --expected-success-output-sha256 <retained-output-sha256> \
  --now <trusted-canonical-UTC-Z>
```

Success is only `M2_RESEARCH_ISOLATION_VERIFIED`. Root/admin or host-kernel
compromise remains outside the same-host threat model.
