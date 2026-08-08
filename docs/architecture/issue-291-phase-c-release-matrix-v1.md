# Issue #291 Phase C build-only release matrix

Phase C consumes both reviewed dependency classifiers and runs only their
selected closure.  Phase A keeps the execution proxy closure; Phase B keeps
its per-consumer dependency selection.  A Phase C planner/receipt contract
change deliberately selects all A and B units, because the matrix itself is a
shared release control.

The plan is non-authorizing.  Unknown paths, equally specific rules, unknown
baselines, missing Containerfiles, and invalid classifier dependencies block
the whole plan.  A successful plan contains no create, deploy, restart,
production, live-trading, or countable-forward action.

Each selected matrix entry builds one Containerfile in its own CI job and runs
its profile-specific offline smoke.  The job then requires Buildx's
`containerimage.digest` and writes an image receipt with a digest-pinned OCI
reference.  The mutable CI tag is only a local build handle and is not a
release identity.

The receipt's rollback identity is the same pinned build artifact and its
rollback receipt is `build_only_hold`: it records no observed runtime target,
permits no rollback action, and cannot be mistaken for a production rollback
authorization.  This follows the useful Issue #267 evidence pattern (exact
identity and explicit non-authorization) without importing blue/green,
rolling replacement, legacy-runtime compatibility, or live deployment logic.

For every selected entry CI also validates the applicable Phase A or Phase B
Compose configuration using CI-only placeholders.  The image smoke remains in
the same matrix job so a service that was not selected cannot be built or
implicitly smoke-tested through a broad Compose invocation.
