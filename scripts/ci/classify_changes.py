"""Classify changed paths for CI without broad, unauditable shell globs."""

from __future__ import annotations

import argparse
import fnmatch
import json
from pathlib import PurePosixPath

WORKFLOW_PREFIX = ".github/workflows/"
WINDOWS_FENCE_GLOBS = (
    "scripts/windows_rpc_*",
    "docs/schemas/windows-rpc-durable-fence-*.schema.json",
    "docs/schemas/windows-fence-release-build-audit-v1.schema.json",
    "docs/schemas/windows-fence-release-input-v1.schema.json",
    "docs/operations/windows-rpc-durable-fence-*.md",
    "docs/architecture/windows-rpc-durable-fence-foundation-*.json",
    "backend/tests/unit/test_issue267_windows_fence_foundation_*.py",
    "backend/tests/unit/test_windows_rpc_deployment_snapshot_*.py",
    "backend/tests/unit/test_windows_rpc_durable_fence_*.py",
    "backend/tests/unit/test_windows_fence_*.py",
    "backend/tests/unit/test_windows_fence_foundation_*.py",
    "backend/tests/unit/windows_fence_*_fixture_v1.py",
    "backend/tests/integration/test_windows_rpc_durable_fence_*.py",
    "backend/tests/integration/test_windows_fence_foundation_*.py",
)
WINDOWS_FENCE_PREFIXES = ("scripts/windows_fence_foundation/",)
QUERY_CLOSURE_FILES = {
    ".dockerignore",
    "scripts/c_fast_t1/Containerfile.query-v3",
    "scripts/c_fast_t1/Containerfile.query-v4",
    "scripts/c_fast_t1/Containerfile.query-v5",
    "scripts/c_fast_t1/ci_query_v5_real_oci_attestation.py",
    "scripts/c_fast_t1/create_query_v3_source_bundle.py",
    "scripts/c_fast_t1/create_query_v4_source_bundle.py",
    "scripts/c_fast_t1/create_query_v5_source_bundle.py",
    "scripts/c_fast_t1/validate_query_v3_runtime.py",
    "scripts/c_fast_t1/validate_query_v4_runtime.py",
    "scripts/c_fast_t1/validate_query_v5_runtime.py",
    "scripts/c_fast_t1/verify_image_attestation.py",
    "scripts/c_fast_t1/verify_query_v3_image_attestation.py",
    "scripts/c_fast_t1/verify_query_v4_image_attestation.py",
    "scripts/c_fast_t1/verify_query_v5_image_attestation.py",
    "scripts/commodity_c_fast_t1_query_v4.py",
    "scripts/commodity_c_fast_t1_query_child_v4.py",
    "scripts/commodity_c_fast_t1_one_shot.py",
    "scripts/commodity_c_fast_t1_readiness_v3.py",
    "scripts/commodity_c_fast_readonly_deployment_outcome.py",
    "scripts/commodity_c_fast_readonly_deployment_release.py",
    "scripts/commodity_c_fast_t1_build_registry_provenance_v2.py",
    "scripts/commodity_c_fast_l1_l5_audit_v4.py",
    "scripts/commodity_c_fast_l1_l5_audit.py",
    "scripts/commodity_c_fast_t1_query_v3.py",
    "scripts/commodity_c_fast_t1_query_child_v3.py",
    "scripts/commodity_c_fast_t1_readiness_v2.py",
    "scripts/commodity_c_fast_t1_release_v2_foundation.py",
    "scripts/commodity_c_fast_t1_build_registry_provenance.py",
    "scripts/commodity_c_fast_t1_query_v5_launcher.py",
    "scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py",
    "docs/operations/c-fast-t1-query-v4-runtime.template.yml",
    "docs/operations/c-fast-t1-query-v5-image-attestation-pin-set.template.json",
    "docs/operations/c-fast-t1-query-v5-image-attestation-bootstrap-pin.template",
    "backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py",
    "backend/tests/unit/test_c_fast_t1_query_v4_image_attestation.py",
    "backend/tests/unit/test_c_fast_t1_query_v4_runtime_packaging.py",
    "backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py",
    "backend/tests/unit/test_c_fast_t1_query_v5_runtime_packaging.py",
    "scripts/ci/requirements-query-v5.txt",
}
QUERY_SCHEMA_NAMES = {
    "commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "commodity-c-fast-l1-l5-audit-v1.schema.json",
    "commodity-c-fast-l1-l5-audit-v2.schema.json",
    "commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "commodity-c-fast-t1-one-shot-query-release-v4.schema.json",
    "commodity-c-fast-t1-one-shot-query-release-v3.schema.json",
    "commodity-c-fast-t1-query-consume-v3.schema.json",
    "commodity-c-fast-t1-query-child-started-v3.schema.json",
    "commodity-c-fast-t1-query-terminal-v3.schema.json",
    "commodity-c-fast-t1-query-v3-trusted-keys-v1.schema.json",
    "commodity-c-fast-t1-query-consume-v4.schema.json",
    "commodity-c-fast-t1-query-child-started-v4.schema.json",
    "commodity-c-fast-t1-query-terminal-v4.schema.json",
    "commodity-c-fast-t1-query-v4-trusted-keys-v1.schema.json",
    "commodity-c-fast-t1-readiness-v3.schema.json",
    "commodity-c-fast-t1-readiness-v2.schema.json",
    "commodity-c-fast-t1-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-v1.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-receipt-v1.schema.json",
    "commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json",
    "commodity-c-fast-t1-query-v3-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-query-v3-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-query-v4-source-manifest-v1.schema.json",
    "commodity-c-fast-t1-query-v4-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-query-v4-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-v2.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-receipt-v2.schema.json",
    "commodity-c-fast-readonly-deployment-release-v1.schema.json",
    "commodity-c-fast-readonly-deployment-consume-v1.schema.json",
    "commodity-c-fast-readonly-deployment-receipt-v1.schema.json",
    "commodity-c-fast-readonly-deployment-outcome-v1.schema.json",
    "commodity-c-fast-readonly-deployment-execution-v1.schema.json",
    "commodity-c-fast-readonly-deployment-writer-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-health-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-backlog-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-principal-secret-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-network-post-v1.schema.json",
    "commodity-c-fast-t1-query-v5-source-manifest-v1.schema.json",
    "commodity-c-fast-t1-query-v5-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-query-v5-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-query-v5-image-attestation-pin-set-v1.schema.json",
    "commodity-c-fast-t1-query-v5-build-registry-provenance-v1.schema.json",
}

# Issue #291 Phase A is deliberately classified independently from the legacy
# ``backend_changed``/``image_changed`` flags below.  Those flags pre-date the
# runtime split and intentionally remain broad for the existing backend
# shards.  A release consumer must use ``classify_phase_a`` instead: each
# service has an explicit owner and a shared contract is expanded only to the
# images that actually consume it.
PHASE_A_UNITS = (
    "frontend-edge",
    "control-api",
    "execution-orchestrator",
)

# The proxy sidecars are not independently selectable Phase A services.  They
# are fixed dependencies of the execution image and are added only to the
# release/build closure when Execution is selected.
PHASE_A_EXECUTION_DEPENDENCIES = (
    "gateway-rpc-request-proxy",
    "gateway-rpc-publish-proxy",
)
PHASE_A_EXTERNAL_ARTIFACTS = ("windows-ctp-gateway",)
PHASE_A_ALL_UNITS = PHASE_A_UNITS + PHASE_A_EXECUTION_DEPENDENCIES

PHASE_A_UNIT_METADATA = {
    "frontend-edge": {
        "build_file": "frontend/Containerfile",
        "entrypoint": "nginx -c /etc/nginx/nginx.conf -g 'daemon off;'",
        "verification_units": ["frontend_check", "frontend_health_version"],
    },
    "control-api": {
        "build_file": "deployments/phase-a/Containerfile.control-api",
        "entrypoint": "uvicorn app.control_api:app --host 0.0.0.0 --port 8081 --app-dir backend",
        "verification_units": ["control_api_tests", "control_api_health_version"],
    },
    "execution-orchestrator": {
        "build_file": "deployments/phase-a/Containerfile.execution-orchestrator",
        "entrypoint": "python -m app.execution_orchestrator",
        "verification_units": [
            "execution_typed_tests",
            "execution_health_version",
            "execution_safety_review",
        ],
    },
    "gateway-rpc-request-proxy": {
        "build_file": "deployments/phase-a/Containerfile.gateway-proxy",
        "entrypoint": "python /usr/local/bin/gateway_proxy.py",
        "command": "request",
        "verification_units": [
            "gateway_proxy_contract",
            "gateway_proxy_request_target_required",
        ],
    },
    "gateway-rpc-publish-proxy": {
        "build_file": "deployments/phase-a/Containerfile.gateway-proxy",
        "entrypoint": "python /usr/local/bin/gateway_proxy.py",
        "command": "publish",
        "verification_units": [
            "gateway_proxy_contract",
            "gateway_proxy_publish_target_required",
        ],
    },
}

# Phase B is an offline, non-deploying validation graph.  Its CI boundary is
# intentionally narrower than the historical backend/image flags: ordinary
# backend or documentation work must not make the expensive seven-image gate
# mandatory, but every owned Phase B input and its CI contract must do so.
PHASE_B_UNITS = (
    "artifact-custody",
    "c-fast-producer",
    "execution-quality-worker",
    "map-producer",
    "market-data-worker",
    "monitor-worker",
    "signing-authority",
)


def _phase_b_rule(
    rule_id: str,
    *,
    units: tuple[str, ...] = (),
    exact: tuple[str, ...] = (),
    prefix: tuple[str, ...] = (),
    shared: bool = False,
) -> dict[str, object]:
    return {
        "id": rule_id,
        "units": units,
        "match": {"exact": exact, "glob": (), "prefix": prefix},
        "shared": shared,
    }


# Every shared contract selects its full Phase B consumer closure.  The CI job
# builds all seven images rather than attempting an unreviewed per-image
# optimisation, so the classifier's unit list is an auditable dependency
# declaration rather than a release selector.
PHASE_B_RULES = (
    _phase_b_rule(
        "phase-b-ci-contract",
        units=PHASE_B_UNITS,
        exact=(
            ".github/workflows/ci.yml",
            "scripts/ci/classify_changes.py",
            "scripts/ci/phase_b_projection_compose_smoke.sh",
            "scripts/ci/validate_json_schemas.py",
        ),
        prefix=("backend/tests/unit/test_issue291_phase_b_ci",),
        shared=True,
    ),
    _phase_b_rule(
        "phase-b-compose",
        units=PHASE_B_UNITS,
        exact=("deployments/docker-compose.phase-b.yml",),
        shared=True,
    ),
    _phase_b_rule(
        "phase-b-artifact-custody-image",
        units=("artifact-custody",),
        exact=("deployments/phase-b/Containerfile.artifact-custody",),
    ),
    _phase_b_rule(
        "phase-b-c-fast-image",
        units=("c-fast-producer",),
        exact=("deployments/phase-b/Containerfile.c-fast-producer",),
    ),
    _phase_b_rule(
        "phase-b-simnow-runner-packaging",
        units=PHASE_B_UNITS,
        exact=(
            "deployments/phase-b/Containerfile.simnow-runner",
            "deployments/phase-b/requirements-simnow-runner.txt",
            "scripts/simnow_keyless_pilot.py",
        ),
        shared=True,
    ),
    _phase_b_rule(
        "phase-b-execution-quality-image",
        units=("execution-quality-worker",),
        exact=("deployments/phase-b/Containerfile.execution-quality-worker",),
    ),
    _phase_b_rule(
        "phase-b-map-image",
        units=("map-producer",),
        exact=("deployments/phase-b/Containerfile.map-producer",),
    ),
    _phase_b_rule(
        "phase-b-market-data-image",
        units=("market-data-worker",),
        exact=("deployments/phase-b/Containerfile.market-data-worker",),
    ),
    _phase_b_rule(
        "phase-b-monitor-image",
        units=("monitor-worker",),
        exact=("deployments/phase-b/Containerfile.monitor-worker",),
    ),
    _phase_b_rule(
        "phase-b-signing-image",
        units=("signing-authority",),
        exact=("deployments/phase-b/Containerfile.signing-authority",),
    ),
    _phase_b_rule(
        "phase-b-artifact-dependencies",
        units=("artifact-custody", "signing-authority"),
        exact=("deployments/phase-b/requirements-artifact.txt",),
    ),
    _phase_b_rule(
        "phase-b-artifact-runtime",
        units=("artifact-custody",),
        exact=("scripts/phase_b_artifact_custody.py",),
    ),
    _phase_b_rule(
        "phase-b-execution-control-custody-tests",
        units=("artifact-custody",),
        exact=("backend/tests/unit/test_issue362_execution_control_plumbing.py",),
    ),
    _phase_b_rule(
        "phase-b-signing-runtime",
        units=("signing-authority",),
        exact=("scripts/phase_b_offline_signer.py",),
    ),
    _phase_b_rule(
        "phase-b-worker-runtime",
        units=("execution-quality-worker", "market-data-worker", "monitor-worker"),
        prefix=("scripts/phase_b_workers/",),
    ),
    _phase_b_rule(
        "phase-b-map-runtime",
        units=("map-producer",),
        prefix=("scripts/map/",),
    ),
    _phase_b_rule(
        "phase-b-c-fast-runtime",
        units=("c-fast-producer",),
        prefix=("scripts/c_fast_producer/",),
    ),
    _phase_b_rule(
        "phase-b-producer-kernel",
        units=("c-fast-producer", "map-producer"),
        exact=("scripts/commodity_c_fast_pure_producer_kernel.py",),
    ),
    _phase_b_rule(
        "phase-b-shared-contracts",
        units=PHASE_B_UNITS,
        prefix=(
            "shared/artifact_contracts/",
            "shared/artifact_custody/",
            "shared/trust_contracts/",
            "shared/artifact-contracts/",
        ),
        shared=True,
    ),
    _phase_b_rule(
        "phase-b-contracts-and-tests",
        units=PHASE_B_UNITS,
        exact=("backend/requirements.phase-b-verifier.txt",),
        prefix=(
            "backend/tests/unit/test_issue_291_phase_b_",
            "backend/tests/unit/test_phase_b_producers.py",
            "docs/architecture/issue-291-phase-b-",
            "docs/operations/phase-b-",
            "docs/schemas/issue-291-phase-b-",
            "docs/schemas/web-bridge-artifact-",
        ),
        shared=True,
    ),
)

PHASE_B_SCOPE_PREFIXES = (
    "deployments/phase-b/",
    "scripts/phase_b_workers/",
    "scripts/map/",
    "scripts/c_fast_producer/",
    "shared/artifact_contracts/",
    "shared/artifact_custody/",
    "shared/trust_contracts/",
    "shared/artifact-contracts/",
    "docs/architecture/issue-291-phase-b-",
    "docs/operations/phase-b-",
    "docs/schemas/issue-291-phase-b-",
    "docs/schemas/web-bridge-artifact-",
    "backend/tests/unit/test_issue_291_phase_b_",
    "backend/tests/unit/test_phase_b_producers",
    "backend/tests/unit/test_issue291_phase_b_ci",
)
PHASE_B_SCOPE_EXACT = {
    ".github/workflows/ci.yml",
    "backend/requirements.phase-b-verifier.txt",
    "backend/tests/unit/test_issue362_execution_control_plumbing.py",
    "deployments/docker-compose.phase-b.yml",
    "scripts/ci/classify_changes.py",
    "scripts/ci/phase_b_projection_compose_smoke.sh",
    "scripts/ci/validate_json_schemas.py",
    "scripts/commodity_c_fast_pure_producer_kernel.py",
    "scripts/phase_b_artifact_custody.py",
    "scripts/phase_b_offline_signer.py",
}

# Phase A consumes this explicit Phase B ownership boundary when creating its
# non-deploying release plan.  These files are preserved as Phase-B-owned: they
# cannot select a Phase A image or turn an otherwise valid Phase A plan into an
# unknown-path block.  The shared workflow and CI classifiers remain governed
# by their existing Phase A rules so that cross-phase CI changes retain Phase A
# verification coverage.
PHASE_A_PHASE_B_PRESERVED_EXACT = (
    "backend/requirements.phase-b-verifier.txt",
    "deployments/docker-compose.phase-b.yml",
    "scripts/commodity_c_fast_pure_producer_kernel.py",
    "scripts/phase_b_artifact_custody.py",
    "scripts/phase_b_offline_signer.py",
)
PHASE_A_PHASE_B_PRESERVED_PREFIXES = PHASE_B_SCOPE_PREFIXES

# Phase C owns its small workflow/fault contract surface.  These paths are
# deliberately listed rather than opening broad backend, shared or scripts
# prefixes: Phase C's combined planner expands them to the full A+B matrix,
# while the legacy Phase A-only planner preserves them without selecting an
# accidental Phase A runtime action.
PHASE_A_PHASE_C_PRESERVED_EXACT = (
    "backend/app/phase_c_custody.py",
    "backend/app/phase_c_execution.py",
    "deployments/phase-c/Containerfile.custody",
    "deployments/phase-c/Containerfile.execution",
    "deployments/phase-c/docker-compose.offline-e2e.yml",
    "backend/app/execution/final_runtime.py",
    "deployments/final/questdb-market-ticks.sql",
    "scripts/ci/final_runtime_compose_smoke.sh",
    "backend/tests/unit/test_issue291_final_execution.py",
    "backend/tests/unit/test_issue291_final_runtime_integration.py",
    "deployments/final/docker-compose.runtime-smoke.yml",
    "deployments/final/Containerfile.questdb-schema",
    "deployments/final/Containerfile.artifact-bootstrap",
    "deployments/final/artifact_bootstrap.py",
    "deployments/final/market_source.py",
    "deployments/phase-b/Containerfile.simnow-runner",
    "deployments/phase-b/requirements-simnow-runner.txt",
    "scripts/simnow_keyless_pilot.py",
    "scripts/simnow_run_once.py",
)
PHASE_A_PHASE_C_PRESERVED_PREFIXES = (
    "backend/app/api/routes_phase_c_",
    "backend/app/phase_c/",
    "backend/tests/unit/test_issue291_phase_c_",
    "docs/architecture/issue-291-phase-c-",
    "docs/schemas/issue-291-phase-c-",
    "scripts/ci/phase_c_",
    "scripts/phase_c_faults/",
    "shared/phase_c_workflow/",
    "shared/commodity_execution/",
)

# Issue #362's daily PIT-main detectors are no-authority Research foundations.
# These exact paths neither enter a Phase A image nor authorize a runtime
# consumer.  Keep the list narrow until a separately reviewed installer exists.
PHASE_A_ISSUE362_RESEARCH_FOUNDATION_EXACT = (
    "backend/tests/unit/test_research_warehouse_daily_roll_predecessor_catalog.py",
    "backend/tests/unit/test_research_warehouse_continuous_event_selector.py",
    "backend/tests/unit/test_research_warehouse_verified_daily_pit_main_roll_source.py",
    "deployments/research-warehouse/daily-pit-main-roll-source-v1.schema.json",
    "deployments/research-warehouse/daily-roll-predecessor-catalog-receipt-v1.schema.json",
    "deployments/research-warehouse/verified-daily-pit-main-roll-source-v2.schema.json",
    "scripts/research_warehouse/continuous_event_selector.py",
    "scripts/research_warehouse/daily_pit_main_roll_source.py",
    "scripts/research_warehouse/daily_roll_predecessor_catalog.py",
    "scripts/research_warehouse/verified_daily_pit_main_roll_source.py",
)


def _phase_a_dependency_closure(selected_units: set[str]) -> set[str]:
    """Expand selected primary services to their reviewed image closure."""

    closure = set(selected_units)
    if "execution-orchestrator" in selected_units:
        closure.update(PHASE_A_EXECUTION_DEPENDENCIES)
    return closure


def _phase_a_rule(
    rule_id: str,
    *,
    units: tuple[str, ...] = (),
    verification: tuple[str, ...] = (),
    exact: tuple[str, ...] = (),
    glob: tuple[str, ...] = (),
    prefix: tuple[str, ...] = (),
    kind: str = "source",
    shared: bool = False,
    safety: bool = False,
    external_artifacts: tuple[str, ...] = (),
) -> dict[str, object]:
    """Create one reviewed Phase A path rule.

    Rules intentionally use the same exact/glob/prefix specificity ordering as
    the legacy release guard.  Keeping this table in Python makes the
    classifier usable by local release tooling without depending on shell
    globs, while the companion manifest mirrors the reviewed ownership.
    """

    return {
        "id": rule_id,
        "units": units,
        "verification": verification,
        "match": {"exact": exact, "glob": glob, "prefix": prefix},
        "kind": kind,
        "shared": shared,
        "safety": safety,
        "external_artifacts": external_artifacts,
    }


PHASE_A_RULES = (
    _phase_a_rule(
        "phase-a-workflow",
        units=PHASE_A_UNITS,
        verification=("phase_a_workflow_contract",),
        prefix=(WORKFLOW_PREFIX,),
        kind="infra",
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-compose",
        units=PHASE_A_UNITS,
        verification=("phase_a_compose_config",),
        exact=(
            "deployments/docker-compose.phase-a.yml",
            "deployments/docker-compose.prod.yml",
            "deployments/docker-compose.final.yml",
        ),
        kind="infra",
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-frontend-build",
        units=("frontend-edge",),
        verification=("frontend_check", "frontend_health_version"),
        exact=(
            "frontend/Containerfile",
            "frontend/nginx.conf",
            "frontend/package.json",
            "frontend/package-lock.json",
            "frontend/index.html",
            "frontend/vite.config.ts",
        ),
        prefix=("frontend/src/", "frontend/public/"),
    ),
    _phase_a_rule(
        "phase-a-control-build",
        units=("control-api",),
        verification=("control_api_tests", "control_api_health_version"),
        exact=(
            "deployments/phase-a/Containerfile.control-api",
            "backend/app/control_api.py",
            "backend/app/control_execution_client.py",
            "backend/app/control_execution_projection.py",
            "backend/app/control_ws_ticket.py",
            "backend/app/api/control_execution.py",
            "backend/app/api/routes_control_execution.py",
            "backend/app/api/routes_control_safe.py",
            "backend/app/api/routes_auth.py",
            "backend/app/core/config.py",
            "backend/app/core/errors.py",
            "backend/app/core/logging.py",
            "backend/app/core/security.py",
            "backend/app/schemas/auth.py",
            "backend/app/services/audit_service.py",
            "backend/app/services/control_execution_client.py",
            "backend/app/services/execution_projection.py",
            "backend/app/services/calendar_service.py",
            "backend/app/services/watchlist_service.py",
            "backend/app/main.py",
        ),
        prefix=(
            "backend/app/core/",
            "backend/app/api/routes_control_",
            "backend/tests/unit/test_issue291_control_api",
        ),
    ),
    _phase_a_rule(
        "phase-a-root-dockerfile",
        units=("control-api",),
        verification=("control_api_tests", "phase_a_root_dockerfile_contract"),
        exact=("Dockerfile",),
        kind="infra",
    ),
    _phase_a_rule(
        "phase-a-execution-build",
        units=("execution-orchestrator",),
        verification=(
            "execution_typed_tests",
            "execution_health_version",
            "execution_safety_review",
        ),
        exact=(
            "deployments/phase-a/Containerfile.execution-orchestrator",
            "backend/app/execution_orchestrator.py",
            "backend/app/services/commodity_c_fast_execution_quality_artifact_revalidation.py",
            "scripts/commodity_c_fast_executable_target_adapter.py",
        ),
        prefix=(
            "backend/app/execution/",
            "backend/tests/unit/test_issue291_phase_a_durable_execution",
            "backend/tests/unit/test_issue291_phase_a_leader_fencing",
            "backend/tests/unit/test_issue291_phase_a_commands",
        ),
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-gateway-proxy-build",
        units=("execution-orchestrator",),
        verification=(
            "gateway_proxy_contract",
            "gateway_proxy_target_required",
            "execution_safety_review",
        ),
        exact=(
            "deployments/phase-a/Containerfile.gateway-proxy",
            "deployments/phase-a/gateway-allowlist.json",
            "deployments/phase-a/gateway_proxy.py",
        ),
        kind="infra",
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-postgres-init",
        units=("control-api", "execution-orchestrator"),
        verification=("phase_a_postgres_role_contract", "execution_safety_review"),
        exact=("deployments/phase-a/postgres-init.sh",),
        kind="infra",
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-windows-fence-external-artifact",
        units=("execution-orchestrator",),
        verification=(
            "windows_fence_contract",
            "windows_fence_external_artifact",
            "execution_safety_review",
        ),
        exact=(
            "scripts/windows_rpc_durable_fence_v1.py",
            "scripts/windows_position_readiness_v1.py",
            "scripts/windows_tick_wire_v1.py",
            "scripts/windows_fence_foundation/__init__.py",
            "scripts/windows_fence_foundation/assembly.py",
            "scripts/windows_fence_foundation/final_admission_v1.py",
            "scripts/windows_fence_foundation/credential_config_v1.py",
            "scripts/windows_fence_foundation/installer_windows_v1.py",
            "scripts/windows_fence_foundation/native_windows_installer_host_v1.py",
            "scripts/windows_rpc_service_wrapper_v1.py",
        ),
        glob=("scripts/windows_rpc_*.py",),
        prefix=("scripts/windows_fence_foundation/",),
        kind="infra",
        safety=True,
        external_artifacts=PHASE_A_EXTERNAL_ARTIFACTS,
    ),
    _phase_a_rule(
        "phase-a-shared-control-execution-schema",
        units=("control-api", "execution-orchestrator"),
        verification=("typed_command_schema", "execution_status_schema"),
        exact=(
            "backend/app/execution/models.py",
            "backend/app/execution/errors.py",
            "backend/app/schemas/control_execution.py",
            "docs/schemas/web-bridge-control-execution-command-v1.schema.json",
            "docs/schemas/web-bridge-execution-status-v1.schema.json",
        ),
        prefix=("backend/tests/unit/test_issue362_execution_control_",),
        shared=True,
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-shared-profile",
        units=PHASE_A_UNITS,
        verification=("shared_contract_dependency_resolution",),
        exact=("shared/trading_session_profiles.json",),
        shared=True,
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-backend-dependencies",
        units=("control-api", "execution-orchestrator"),
        verification=("python_dependency_compatibility",),
        exact=("backend/requirements.txt",),
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-contract-documents",
        verification=("phase_a_contract",),
        exact=(
            "docs/architecture/issue-291-phase-a-contract-v1.md",
            "docs/architecture/issue-291-phase-a-ownership-v1.json",
            "docs/architecture/issue-291-phase-a-release-dependencies-v1.json",
            "backend/tests/unit/test_issue291_phase_a_contract.py",
            "backend/tests/unit/test_issue291_phase_a_compose.py",
            "backend/tests/unit/test_issue291_frontend_edge.py",
        ),
        kind="contract",
    ),
    _phase_a_rule(
        "phase-a-ci-tests",
        verification=("ci_contract",),
        prefix=("scripts/ci/", "backend/tests/unit/test_ci_"),
        kind="infra",
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-preserved-phase-b",
        exact=PHASE_A_PHASE_B_PRESERVED_EXACT,
        prefix=PHASE_A_PHASE_B_PRESERVED_PREFIXES,
        kind="preserved",
    ),
    _phase_a_rule(
        "phase-a-preserved-phase-c",
        exact=PHASE_A_PHASE_C_PRESERVED_EXACT,
        prefix=PHASE_A_PHASE_C_PRESERVED_PREFIXES,
        kind="preserved",
    ),
    _phase_a_rule(
        "phase-a-preserved-issue362-research-foundation",
        exact=PHASE_A_ISSUE362_RESEARCH_FOUNDATION_EXACT,
        kind="preserved",
    ),
    _phase_a_rule(
        "phase-a-legacy-root",
        verification=("legacy_monolith_absence",),
        exact=("test_rpc_readonly.py", "test_rpc_trade_flow.py"),
        kind="forbidden",
        safety=True,
    ),
    _phase_a_rule(
        "phase-a-unrelated-docs",
        verification=("markdown_links",),
        exact=("README.md",),
        prefix=("docs/",),
        kind="contract",
    ),
    _phase_a_rule(
        "phase-a-unrelated-tests",
        verification=("backend_tests",),
        prefix=("backend/tests/",),
        kind="contract",
    ),
)


def _phase_a_specificity(rule: dict[str, object], path: str) -> tuple[int, int] | None:
    match = rule["match"]
    candidates: list[tuple[int, int]] = []
    if path in match["exact"]:
        candidates.append((3, len(path)))
    candidates.extend(
        (2, len(pattern.replace("*", "")))
        for pattern in match["glob"]
        if fnmatch.fnmatchcase(path, pattern)
    )
    candidates.extend(
        (1, len(prefix)) for prefix in match["prefix"] if path.startswith(prefix)
    )
    return max(candidates, default=None)


def _normalise_change_path(raw_path: str) -> str:
    # PurePosixPath turns accidental ``./`` and repeated separators into the
    # same repository-relative spelling used by git, while rejecting absolute
    # paths and parent traversal keeps release evidence canonical.
    raw = raw_path.strip().replace("\\", "/")
    if not raw:
        return ""
    normalised = PurePosixPath(raw).as_posix()
    if normalised.startswith(("/", "../")) or normalised == "..":
        raise ValueError(f"path must be repository-relative: {raw_path!r}")
    return normalised


def _phase_a_selected_rules(path: str) -> list[dict[str, object]]:
    scored = [
        (score, rule)
        for rule in PHASE_A_RULES
        if (score := _phase_a_specificity(rule, path)) is not None
    ]
    if not scored:
        return []
    highest = max(score for score, _ in scored)
    return [rule for score, rule in scored if score == highest]


def classify_phase_a(paths: list[str], *, force_all: bool = False) -> dict[str, object]:
    """Classify Phase A services and fail closed on unknown/ambiguous paths.

    This result is intentionally separate from the historical classifier.  In
    particular, a frontend or control-only change never receives an execution
    safety flag; only an execution-owned, shared, infrastructure, or forbidden
    change does.  Shared rules list all actual image consumers, giving release
    plans a dependency closure instead of selecting the whole backend.
    """

    if force_all:
        selected_rule_ids = ["<force-all>"]
        selected_units = set(PHASE_A_UNITS)
        dependency_closure = _phase_a_dependency_closure(selected_units)
        verification = {
            "phase_a_contract",
            "phase_a_compose_config",
            "phase_a_workflow_contract",
            "typed_command_schema",
            "execution_status_schema",
            "frontend_check",
            "frontend_health_version",
            "control_api_tests",
            "control_api_health_version",
            "execution_typed_tests",
            "execution_health_version",
            "execution_safety_review",
            "windows_fence_contract",
            "windows_fence_external_artifact",
        }
        return {
            "phase_a_changed": True,
            "frontend_edge_changed": True,
            "control_api_changed": True,
            "execution_orchestrator_changed": True,
            "execution_changed": True,
            "execution_safety_required": True,
            "shared_contract_changed": True,
            "unknown_changed": False,
            "ambiguous_changed": False,
            "release_blocked": False,
            "selected_rule_ids": selected_rule_ids,
            "candidate_rule_ids": selected_rule_ids,
            "selected_units": sorted(selected_units),
            "dependency_closure": sorted(dependency_closure),
            "external_artifacts": list(PHASE_A_EXTERNAL_ARTIFACTS),
            "verification_units": sorted(verification),
            "blocked_reasons": [],
        }

    changed_paths = sorted({_normalise_change_path(path) for path in paths})
    changed_paths = [path for path in changed_paths if path]
    selected_rule_ids: set[str] = set()
    candidate_rule_ids: set[str] = set()
    selected_units: set[str] = set()
    verification_units: set[str] = set()
    blocked_reasons: list[dict[str, object]] = []
    shared_contract_changed = False
    execution_safety_required = False
    external_artifacts: set[str] = set()

    for path in changed_paths:
        selected = _phase_a_selected_rules(path)
        candidate_rule_ids.update(str(rule["id"]) for rule in selected)
        if not selected:
            blocked_reasons.append(
                {"path": path, "code": "unknown_path", "rule_ids": []}
            )
            continue
        if len(selected) != 1:
            ids = sorted(str(rule["id"]) for rule in selected)
            blocked_reasons.append(
                {"path": path, "code": "ambiguous_rule", "rule_ids": ids}
            )
            continue
        rule = selected[0]
        rule_id = str(rule["id"])
        selected_rule_ids.add(rule_id)
        kind = str(rule["kind"])
        if kind == "forbidden":
            blocked_reasons.append(
                {
                    "path": path,
                    "code": "legacy_monolith_forbidden",
                    "rule_ids": [rule_id],
                }
            )
        selected_units.update(str(unit) for unit in rule["units"])
        verification_units.update(str(unit) for unit in rule["verification"])
        shared_contract_changed = shared_contract_changed or bool(rule["shared"])
        execution_safety_required = execution_safety_required or bool(rule["safety"])
        external_artifacts.update(str(item) for item in rule["external_artifacts"])

    # Rules are reviewed against the primary Phase A images and their fixed
    # execution dependencies.  A corrupted rule table must not silently emit a
    # release plan for an unknown unit.
    invalid_units = sorted(selected_units - set(PHASE_A_ALL_UNITS))
    if invalid_units:
        blocked_reasons.append(
            {
                "path": "<classifier>",
                "code": "unknown_dependency",
                "rule_ids": [],
                "units": invalid_units,
            }
        )
        selected_units.difference_update(invalid_units)

    if "execution-orchestrator" in selected_units:
        execution_safety_required = True
    if "execution-orchestrator" in selected_units:
        verification_units.add("execution_safety_review")

    dependency_closure = _phase_a_dependency_closure(selected_units)

    unknown_changed = any(item["code"] == "unknown_path" for item in blocked_reasons)
    ambiguous_changed = any(
        item["code"] == "ambiguous_rule" for item in blocked_reasons
    )
    release_blocked = bool(blocked_reasons)
    return {
        "phase_a_changed": bool(changed_paths),
        "frontend_edge_changed": "frontend-edge" in selected_units,
        "control_api_changed": "control-api" in selected_units,
        "execution_orchestrator_changed": "execution-orchestrator" in selected_units,
        "execution_changed": "execution-orchestrator" in selected_units,
        "execution_safety_required": execution_safety_required,
        "shared_contract_changed": shared_contract_changed,
        "unknown_changed": unknown_changed,
        "ambiguous_changed": ambiguous_changed,
        "release_blocked": release_blocked,
        "selected_rule_ids": sorted(selected_rule_ids),
        "candidate_rule_ids": sorted(candidate_rule_ids),
        "selected_units": sorted(selected_units),
        "dependency_closure": sorted(dependency_closure),
        "external_artifacts": sorted(external_artifacts),
        "verification_units": sorted(verification_units),
        "blocked_reasons": blocked_reasons,
        "changed_paths": changed_paths,
    }


def _phase_b_selected_rules(path: str) -> list[dict[str, object]]:
    scored = [
        (score, rule)
        for rule in PHASE_B_RULES
        if (score := _phase_a_specificity(rule, path)) is not None
    ]
    if not scored:
        return []
    highest = max(score for score, _ in scored)
    return [rule for score, rule in scored if score == highest]


def _is_phase_b_scope(path: str) -> bool:
    return path in PHASE_B_SCOPE_EXACT or path.startswith(PHASE_B_SCOPE_PREFIXES)


def classify_phase_b(paths: list[str], *, force_all: bool = False) -> dict[str, object]:
    """Classify the offline Phase B CI boundary without selecting deployment.

    Unknown or equally-specific Phase B rules are blocking rather than silently
    skipped.  Paths outside the Phase B boundary deliberately remain unrelated
    so that the expensive image matrix runs only when its contracts can change.
    """

    if force_all:
        return {
            "phase_b_changed": True,
            "phase_b_shared_contract_changed": True,
            "phase_b_unknown_changed": False,
            "phase_b_ambiguous_changed": False,
            "phase_b_gate_blocked": False,
            "selected_rule_ids": ["<force-all>"],
            "candidate_rule_ids": ["<force-all>"],
            "selected_units": list(PHASE_B_UNITS),
            "blocked_reasons": [],
            "changed_paths": [],
        }

    changed_paths = sorted({_normalise_change_path(path) for path in paths})
    changed_paths = [path for path in changed_paths if path]
    phase_b_paths = [path for path in changed_paths if _is_phase_b_scope(path)]
    selected_rule_ids: set[str] = set()
    candidate_rule_ids: set[str] = set()
    selected_units: set[str] = set()
    blocked_reasons: list[dict[str, object]] = []
    shared_contract_changed = False

    for path in phase_b_paths:
        selected = _phase_b_selected_rules(path)
        candidate_rule_ids.update(str(rule["id"]) for rule in selected)
        if not selected:
            blocked_reasons.append(
                {"path": path, "code": "unknown_phase_b_path", "rule_ids": []}
            )
            continue
        if len(selected) != 1:
            blocked_reasons.append(
                {
                    "path": path,
                    "code": "ambiguous_phase_b_rule",
                    "rule_ids": sorted(str(rule["id"]) for rule in selected),
                }
            )
            continue
        rule = selected[0]
        selected_rule_ids.add(str(rule["id"]))
        selected_units.update(str(unit) for unit in rule["units"])
        shared_contract_changed = shared_contract_changed or bool(rule["shared"])

    invalid_units = sorted(selected_units - set(PHASE_B_UNITS))
    if invalid_units:
        blocked_reasons.append(
            {
                "path": "<classifier>",
                "code": "unknown_phase_b_consumer",
                "rule_ids": [],
                "units": invalid_units,
            }
        )
        selected_units.difference_update(invalid_units)

    return {
        "phase_b_changed": bool(phase_b_paths),
        "phase_b_shared_contract_changed": shared_contract_changed,
        "phase_b_unknown_changed": any(
            item["code"] == "unknown_phase_b_path" for item in blocked_reasons
        ),
        "phase_b_ambiguous_changed": any(
            item["code"] == "ambiguous_phase_b_rule" for item in blocked_reasons
        ),
        "phase_b_gate_blocked": bool(blocked_reasons),
        "selected_rule_ids": sorted(selected_rule_ids),
        "candidate_rule_ids": sorted(candidate_rule_ids),
        "selected_units": sorted(selected_units),
        "blocked_reasons": blocked_reasons,
        "changed_paths": phase_b_paths,
    }


def _is_under(path: str, prefix: str) -> bool:
    return path == prefix.rstrip("/") or path.startswith(prefix)


def _is_windows_fence_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in WINDOWS_FENCE_PREFIXES) or any(
        fnmatch.fnmatchcase(path, pattern) for pattern in WINDOWS_FENCE_GLOBS
    )


def classify(paths: list[str], *, force_all: bool = False) -> dict[str, bool]:
    result = {
        "backend_changed": force_all,
        "frontend_changed": force_all,
        "image_changed": force_all,
        "query_v5_changed": force_all,
        "windows_fence_changed": force_all,
    }
    for raw_path in paths:
        path = PurePosixPath(raw_path.strip()).as_posix()
        if not path or path == ".":
            continue
        if path.startswith(WORKFLOW_PREFIX):
            return {key: True for key in result}
        if _is_windows_fence_path(path):
            result["backend_changed"] = True
            result["windows_fence_changed"] = True
            # The Windows foundation has a dedicated offline gate.  Its exact
            # paths must not select the unrelated Linux production image.
            continue
        if (
            _is_under(path, "backend/")
            or _is_under(path, "shared/")
            or _is_under(path, "scripts/")
            or _is_under(path, "docs/schemas/")
            or _is_under(path, "docs/operations/")
            or path in {"requirements.txt", "backend/requirements.txt"}
            or path.startswith("scripts/tick_")
        ):
            result["backend_changed"] = True
        if _is_under(path, "frontend/") or _is_under(path, "shared/"):
            result["frontend_changed"] = True
        if (
            path
            in {
                "Dockerfile",
                ".dockerignore",
                "test_rpc_readonly.py",
                "test_rpc_trade_flow.py",
            }
            or _is_under(path, "backend/")
            or _is_under(path, "frontend/")
            or _is_under(path, "shared/")
            or _is_under(path, "scripts/")
            or _is_under(path, "docs/schemas/")
            or _is_under(path, "deployments/")
            or path
            in {
                "scripts/deploy.sh",
                "scripts/install-watchdog.sh",
                "scripts/watchdog.py",
            }
        ):
            result["image_changed"] = True
        if path in QUERY_CLOSURE_FILES or (
            path.startswith("docs/schemas/")
            and PurePosixPath(path).name in QUERY_SCHEMA_NAMES
        ):
            result["query_v5_changed"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--paths-file")
    parser.add_argument("--force-all", action="store_true")
    parser.add_argument("--github-output", action="store_true")
    parser.add_argument(
        "--phase-a",
        action="store_true",
        help="emit the independent Issue #291 Phase A service classifier",
    )
    parser.add_argument(
        "--phase-b",
        action="store_true",
        help="emit the independent Issue #291 Phase B CI classifier",
    )
    args = parser.parse_args()
    paths = list(args.paths)
    if args.paths_file:
        with open(args.paths_file, encoding="utf-8") as source:
            paths.extend(line.rstrip("\n") for line in source)
    if args.phase_a and args.phase_b:
        parser.error("--phase-a and --phase-b are mutually exclusive")
    if args.phase_a:
        result = classify_phase_a(paths, force_all=args.force_all)
        if args.github_output:
            for key, value in result.items():
                if isinstance(value, bool):
                    print(f"{key}={'true' if value else 'false'}")
            # The list fields are useful in local output but are intentionally
            # not written to GITHUB_OUTPUT; callers can re-run the release-plan
            # command to obtain canonical JSON evidence.
        else:
            print(json.dumps(result, sort_keys=True))
        return 1 if result["release_blocked"] else 0
    if args.phase_b:
        result = classify_phase_b(paths, force_all=args.force_all)
        if args.github_output:
            for key, value in result.items():
                if isinstance(value, bool):
                    print(f"{key}={'true' if value else 'false'}")
        else:
            print(json.dumps(result, sort_keys=True))
        return 1 if result["phase_b_gate_blocked"] else 0
    result = classify(paths, force_all=args.force_all)
    if args.github_output:
        for key, value in result.items():
            print(f"{key}={'true' if value else 'false'}")
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
