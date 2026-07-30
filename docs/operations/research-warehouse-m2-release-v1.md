# Research Warehouse M2 release bundle v1

Issue #197 supplies the deterministic runtime bundle required before Issue
#172 can activate its LaunchDaemons. It does not schedule an official day,
collect data, modify PF, load launchd jobs, or grant deployment, signing,
Control, Execution, RPC, account, order, position, trading, or production
authority.

## Layers

- `m2_wheelhouse.py` verifies the raw-SHA-pinned offline dependency set.
- `m2_python_runtime_archive.py` extracts the one raw-SHA-pinned standalone
  Python archive into a normalized, symlink-free private runtime.
- `m2_python_runtime.py` owns its exact version, manifest, content and
  self-contained execution contracts.
- `m2_release_contracts.py` owns bundle content, private-runtime launcher and
  manifest contracts.
- `m2_release_builder.py` reads exact blobs from a clean Git HEAD and builds
  the frozen source/dependency tree.
- `m2_release_install.py` copies without symlinks or inherited xattrs, verifies
  the candidate, and atomically exchanges it with current only while holding
  the exclusive root-owned deployment lock. A failed post-switch verification
  or catchable process interruption restores the old tree.
- `m2_release_cli.py` is argument and canonical output plumbing.
- `m2_monitor_cli.py` exposes the existing pure monitor evaluator as a real
  command-line entrypoint.
- `research-warehouse-job` exposes the layered Research Warehouse CLI from the
  frozen bundle. `research-warehouse-monitor` exposes the pure M2 monitor CLI.

The two entrypoints are real import-checked CLIs. They intentionally require
explicit arguments in this foundation release. Issue #198 will add the
root-owned, signed-calendar-aware no-argument daily scheduler and derive
monitor inputs from actual custody and backup facts before either LaunchDaemon
is activated.

## Offline wheelhouse

Download only the exact versions in
`deployments/research-warehouse/m2/runtime-requirements-v1.txt` into a private
temporary directory on the target architecture. No online package resolution
occurs during bundle construction.

Create a canonical manifest and retain its printed SHA-256 outside both the
wheelhouse and manifest:

```bash
PYTHONPATH=scripts python scripts/research_warehouse_m2_release_cli.py \
  manifest-wheelhouse \
  --wheelhouse /private/build/wheels \
  --output /private/evidence/wheelhouse-manifest.json
```

The manifest requires an exact, unique, sorted wheel filename set and binds
every wheel's exact bytes. Adding, removing, replacing, hard-linking or
symlinking a wheel fails closed.

## Private Python runtime

The approved runtime input is
`cpython-3.12.13+20260728-x86_64-apple-darwin-install_only_stripped.tar.gz`
from the Astral `python-build-standalone` `20260728` release. Its required
raw SHA-256 is
`e654c21d0ba53e2c671868d4112fac5874deca4c35226d36c5cfe53bc5c9cd71`.
Retain the archive privately as mode `0600`; any other bytes fail closed.

Prepare and manifest it in the same pinned-archive operation before building:

```bash
PYTHONPATH=scripts python3.12 scripts/research_warehouse_m2_release_cli.py \
  prepare-python-runtime \
  --source-archive /private/build/python-runtime.tar.gz \
  --output-root /private/build/python-runtime \
  --manifest-output /private/evidence/python-runtime-manifest.json
```

Preparation reads the verified archive directly, rejects unsafe paths and
special entries, omits archive links, writes fresh single-link files, applies
fixed modes, and proves that Python 3.12.13 resolves both `sys.prefix` and its
standard library inside the prepared tree with user site disabled. The
resulting exact tree-content SHA and canonical runtime-manifest SHA are frozen
in the contract; no command can issue provenance for an arbitrary runtime
directory.

## Build

Build only from an exact clean Git HEAD. The source commit, frozen requirements
raw hash, externally retained wheelhouse/runtime-manifest hashes, every private
Python runtime, source and dependency byte, mode and relative path are bound
into a canonical bundle manifest.

```bash
PYTHONPATH=scripts python scripts/research_warehouse_m2_release_cli.py build \
  --source-root /private/build/vnpy-web-bridge \
  --source-commit-sha <exact-40-hex-head> \
  --requirements deployments/research-warehouse/m2/runtime-requirements-v1.txt \
  --wheelhouse /private/build/wheels \
  --wheelhouse-manifest /private/evidence/wheelhouse-manifest.json \
  --expected-wheelhouse-manifest-sha256 <retained-sha256> \
  --python-runtime /private/build/python-runtime \
  --python-runtime-manifest \
    /private/evidence/python-runtime-manifest.json \
  --expected-python-runtime-manifest-sha256 <retained-runtime-sha256> \
  --output-root /private/build/release \
  --bundle-manifest-output /private/evidence/release-bundle-manifest.json
```

`pip` runs with `--no-index --no-deps --no-compile`; the wheelhouse is the only
dependency source. It and both import checks execute only the copied private
runtime under `-B -I`. Both launchers bind the fixed
`release/runtime/bin/python3.12` path. The generated bundle is symlink-free,
directory mode `0755`, executable mode `0555`, and other file mode `0444`.

Verify it again with the independently retained bundle-manifest SHA:

```bash
PYTHONPATH=scripts python scripts/research_warehouse_m2_release_cli.py verify \
  --root /private/build/release \
  --manifest /private/evidence/release-bundle-manifest.json \
  --expected-manifest-sha256 <retained-sha256>
```

## Install

Installation requires root, the fixed
`/usr/local/libexec/vnpyresearch/release.lock`, and the frozen target
`/usr/local/libexec/vnpyresearch/release`. It performs no network access.

```bash
sudo env PYTHONPATH=scripts python \
  scripts/research_warehouse_m2_release_cli.py install \
  --staged-root /private/build/release \
  --manifest /private/evidence/release-bundle-manifest.json \
  --expected-manifest-sha256 <retained-sha256> \
  --installed-tree-manifest-output \
    /private/evidence/installed-release-tree-manifest.json
```

The installer never executes staged or installed bundle code. It:

1. verifies staged content, the embedded runtime manifest and all private
   Python/runtime bytes;
2. takes the exclusive deployment lock;
3. creates `release.candidate` using exact-byte writes without carrying source
   ACLs, xattrs or symlinks;
4. verifies root ownership and the complete candidate manifest;
5. atomically exchanges an existing tree with `release.candidate`, so current
   is never absent even if the process is killed or the host loses power;
6. retains the exchanged old tree as `release.previous` and fsyncs the parent;
7. verifies the installed tree again;
8. publishes the create-only physical installed-tree manifest needed by the
   #172 verifier and prints its independently retainable raw SHA-256;
9. atomically restores the previous tree on every `BaseException` after the
   exchange, including `KeyboardInterrupt` and parent-directory fsync failure.

At the start of the next root update, a legacy/interrupted state with
`release` missing and `release.previous` present is restored before staging;
an orphan `release.candidate` is removed under the exclusive lock. A retained
`release.previous` from a completed update still requires explicit archival
before another update.

The installed-tree verifier holds the release-root descriptor while it walks.
Traversal descriptors are bounded by path depth; every reopened component uses
`O_NOFOLLOW` and must retain its recorded identity. Each regular file is read
twice through one fd-relative descriptor and reopened for final identity/hash
verification. This preserves root-relative pathname and exact-byte binding
without holding every runtime directory or dependency file open
simultaneously; the full runtime tree remains verifiable under the M2
LaunchDaemon soft limit of 256 file descriptors.
