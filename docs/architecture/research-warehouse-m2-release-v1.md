# Research Warehouse M2 deterministic release v1

Issue #197 defines the build, verification, installation and rollback contract
for the two M2 Research entrypoints required by Issue #172. Merging this code
does not install a release, activate PF or load either LaunchDaemon. It grants
no schedule, network, deployment, RPC or trading authority. Official-day
scheduling and real acquisition/monitor results remain in Issue #198.

## Frozen inputs

The committed
`deployments/research-warehouse/m2/release-dependency-lock-v1.json` is bound
by its raw SHA-256 in code. It freezes:

- CPython `3.12.13` at `/usr/local/bin/python3.12`;
- the `macosx_11_0_arm64` platform;
- exact wheel filenames, byte counts and raw SHA-256 values for `cffi`,
  `cryptography`, `duckdb` and `pycparser`;
- an explicitly all-false authority object.

The builder also requires an exact 40-character source commit and refuses a
dirty checkout through the public CLI. Every copied
`scripts/research_warehouse/*.py` file is statically checked by the existing
Research source-boundary guard and recorded by repository path, release path
and raw SHA-256.

Wheels are build inputs, not repository assets. The operator acquires the
exact locked files into a private wheelhouse through an approved build-host
workflow, then verifies the committed lock before building:

```bash
PYTHONPATH=scripts /usr/local/bin/python3.12 \
  scripts/research_warehouse_m2_release_cli.py verify-dependency-lock \
  --dependency-lock \
  deployments/research-warehouse/m2/release-dependency-lock-v1.json
```

The builder rejects missing or changed wheels before extraction. It also
rejects absolute/traversal paths, duplicate zip members, symlinks, `.pth`,
`sitecustomize`, `usercustomize`, unsupported `.data` relocation, path
collisions and execution-side import roots.

## Bundle layout and entrypoints

The create-only package root is private to the builder. Its
`bundle-manifest.json` binds every generated directory and regular file by
relative path, type, mode, size and raw SHA-256, as well as the complete tree
content hash, dependency lock, source commit and all-false authority.

```text
<private-package>/
  bundle-manifest.json
  release/
    bin/
      research-warehouse-job
      research-warehouse-monitor
    lib/
      research_warehouse/
      python3.12/site-packages/
    libexec/m2_release_entry.py
    meta/release-runtime.json
```

Both shell entrypoints unset Python path overrides and invoke the frozen
interpreter with `-I -s -E`. The runtime entry verifies the installed tree,
exact dependency distributions, interpreter identity and isolation flags,
rejects Web Bridge/RPC/trading environment variables, and imports the frozen
role-specific Research modules. In v1 its only command is `self-check`, which
returns `RELEASE_SELF_CHECK_PASSED_NO_SCHEDULE_AUTHORITY`; Issue #198 owns the
calendar-aware work command.

The release root is root-owned mode `0755`, its internal directories are
`0555`, data/source files are `0444`, and executable entry files are `0555`.
No path may be a symlink or group/world writable. Consequently
`vnpyresearch` can execute and read the release but cannot change it.

## Build and verify

The installable bundle must be built as root from a root-owned clean build
checkout and private wheelhouse; a user-owned package is intentionally
rejected by the root installer. The checkout `HEAD` must equal the supplied
commit:

```bash
commit="$(git rev-parse HEAD)"
release_id="m2-release-$(date -u +%Y%m%dT%H%M%SZ)"

sudo env PYTHONPATH=scripts /usr/local/bin/python3.12 \
  scripts/research_warehouse_m2_release_cli.py build \
  --source-root "$PWD" \
  --wheelhouse /secure/private/m2-wheelhouse \
  --dependency-lock \
  deployments/research-warehouse/m2/release-dependency-lock-v1.json \
  --release-id "$release_id" \
  --source-commit-sha "$commit" \
  --output "/secure/private/releases/$release_id"

PYTHONPATH=scripts /usr/local/bin/python3.12 \
  scripts/research_warehouse_m2_release_cli.py verify-package \
  --package-root "/secure/private/releases/$release_id"
```

Identical frozen inputs and release ID produce an identical canonical
manifest and tree content hash.

## Install and rollback

The root-only installer requires the literal confirmation
`INSTALL_M2_RESEARCH_RELEASE_NOT_ACTIVATE`. It verifies the private package,
takes the existing root-owned `release.lock` exclusively, copies into a
same-parent private stage, reapplies root ownership and frozen modes, rescans
the complete stage and runs the non-importing runtime self-check. Only then
does it atomically exchange the stage and current directory. The previous
release moves into the private rollback root.

```bash
sudo env PYTHONPATH=scripts /usr/local/bin/python3.12 \
  scripts/research_warehouse_m2_release_cli.py install \
  --package-root "/secure/private/releases/$release_id" \
  --installed-manifest \
  "/secure/external/manifests/$release_id.release-tree.json" \
  --confirm INSTALL_M2_RESEARCH_RELEASE_NOT_ACTIVATE
```

The installed tree manifest is create-only and is generated from the verified
stage before switching. A failure before the switch removes the partial stage
and manifest. A failure during or after the atomic exchange restores the prior
current release before returning failure.

Explicit rollback exchanges the current release with one verified rollback
candidate while holding the same exclusive lock:

```bash
sudo env PYTHONPATH=scripts /usr/local/bin/python3.12 \
  scripts/research_warehouse_m2_release_cli.py rollback \
  --candidate \
  /usr/local/libexec/vnpyresearch/release-rollbacks/<release-id> \
  --confirm ROLLBACK_M2_RESEARCH_RELEASE_NOT_ACTIVATE
```

Installation and rollback deliberately do not load PF, bootstrap a
LaunchDaemon, schedule work, call a registry, access Web Bridge, or submit a
trade. Issue #172 activation remains blocked until Issue #198 supplies the
official-day work contract and both issues have passed review.
