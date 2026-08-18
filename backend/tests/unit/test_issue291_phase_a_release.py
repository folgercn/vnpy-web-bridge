from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.ci.classify_changes import (
    PHASE_A_RULES,
    PHASE_A_UNIT_METADATA,
    classify_phase_a,
)
from scripts.ci.plan_phase_a_release import create_plan

ROOT = Path(__file__).resolve().parents[3]
PLAN_SCHEMA = json.loads(
    (ROOT / "docs/schemas/issue-291-phase-a-release-plan-v1.schema.json").read_text(
        encoding="utf-8"
    )
)
SHA = "a" * 40

# Phase B paths in the PR that introduced its offline validation graph.  This
# is intentionally an explicit contract rather than a broad "everything under
# backend" exception: a new unowned path must still fail closed in Phase A.
CURRENT_PHASE_B_CHANGED_PATHS = (
    ".github/workflows/ci.yml",
    "backend/requirements.phase-b-verifier.txt",
    "backend/tests/unit/test_ci_workflow_contract.py",
    "backend/tests/unit/test_issue291_phase_b_ci.py",
    "backend/tests/unit/test_issue_291_phase_b_custody.py",
    "backend/tests/unit/test_issue_291_phase_b_trust.py",
    "backend/tests/unit/test_phase_b_producers.py",
    "deployments/docker-compose.phase-b.yml",
    "deployments/phase-b/Containerfile.artifact-custody",
    "deployments/phase-b/Containerfile.c-fast-producer",
    "deployments/phase-b/Containerfile.execution-quality-worker",
    "deployments/phase-b/Containerfile.map-producer",
    "deployments/phase-b/Containerfile.market-data-worker",
    "deployments/phase-b/Containerfile.monitor-worker",
    "deployments/phase-b/Containerfile.signing-authority",
    "deployments/phase-b/requirements-artifact.txt",
    "docs/architecture/issue-291-phase-b-trust-custody-v1.md",
    "docs/operations/phase-b-producer-contract-v1.md",
    "docs/schemas/issue-291-phase-b-custody-record-v1.schema.json",
    "docs/schemas/issue-291-phase-b-signed-artifact-v1.schema.json",
    "docs/schemas/issue-291-phase-b-signing-request-v1.schema.json",
    "docs/schemas/issue-291-phase-b-trust-keyring-v1.schema.json",
    "docs/schemas/web-bridge-artifact-consume-receipt-v1.schema.json",
    "docs/schemas/web-bridge-artifact-envelope-v1.schema.json",
    "docs/schemas/web-bridge-artifact-install-receipt-v1.schema.json",
    "docs/schemas/web-bridge-artifact-publish-receipt-v1.schema.json",
    "docs/schemas/web-bridge-artifact-publish-request-v1.schema.json",
    "docs/schemas/web-bridge-artifact-receipt-v1.schema.json",
    "docs/schemas/web-bridge-artifact-revoke-receipt-v1.schema.json",
    "scripts/c_fast_producer/__init__.py",
    "scripts/c_fast_producer/producer.py",
    "scripts/ci/classify_changes.py",
    "scripts/ci/phase_b_projection_compose_smoke.sh",
    "scripts/ci/validate_json_schemas.py",
    "scripts/map/__init__.py",
    "scripts/map/producer.py",
    "scripts/phase_b_artifact_custody.py",
    "scripts/phase_b_offline_signer.py",
    "scripts/phase_b_workers/README.md",
    "scripts/phase_b_workers/__init__.py",
    "scripts/phase_b_workers/contracts.py",
    "scripts/phase_b_workers/durable.py",
    "scripts/phase_b_workers/execution_quality_worker.py",
    "scripts/phase_b_workers/market_data_worker.py",
    "scripts/phase_b_workers/monitor_worker.py",
    "scripts/phase_b_workers/projections.py",
    "scripts/phase_b_workers/schemas/execution-quality-evidence-v1.schema.json",
    "scripts/phase_b_workers/schemas/monitor-incident-v1.schema.json",
    "scripts/phase_b_workers/schemas/verified-tick-v1.schema.json",
    "scripts/phase_b_workers/schemas/worker-health-v1.schema.json",
    "scripts/phase_b_workers/schemas/worker-metrics-v1.schema.json",
    "scripts/phase_b_workers/schemas/worker-readiness-v1.schema.json",
    "scripts/phase_b_workers/tests/__init__.py",
    "scripts/phase_b_workers/tests/test_phase_b_workers.py",
    "shared/artifact-contracts/c-fast/commodity-approved-research-source-v1.schema.json",
    "shared/artifact-contracts/c-fast/commodity-c-fast-target-candidate-v1.schema.json",
    "shared/artifact-contracts/map/commodity-approved-research-source-v1.schema.json",
    "shared/artifact-contracts/map/commodity-map-signal-candidate-v1.schema.json",
    "shared/artifact_contracts/__init__.py",
    "shared/artifact_contracts/v1.py",
    "shared/artifact_custody/__init__.py",
    "shared/artifact_custody/v1.py",
    "shared/trust_contracts/__init__.py",
    "shared/trust_contracts/v1.py",
)
PHASE_B_SHARED_CI_PATHS = {
    ".github/workflows/ci.yml",
    "backend/tests/unit/test_ci_workflow_contract.py",
    "scripts/ci/classify_changes.py",
    "scripts/ci/phase_b_projection_compose_smoke.sh",
    "scripts/ci/validate_json_schemas.py",
}


def test_frontend_and_control_changes_are_independent_from_execution() -> None:
    frontend = classify_phase_a(["frontend/src/App.tsx"])
    assert frontend["selected_units"] == ["frontend-edge"]
    assert frontend["dependency_closure"] == ["frontend-edge"]
    assert frontend["execution_changed"] is False
    assert frontend["execution_safety_required"] is False

    control = classify_phase_a(["backend/app/control_api.py"])
    assert control["selected_units"] == ["control-api"]
    assert control["dependency_closure"] == ["control-api"]
    assert control["execution_changed"] is False
    assert control["execution_safety_required"] is False


def test_issue362_execution_control_tests_select_both_runtime_contract_owners() -> None:
    result = classify_phase_a(
        ["backend/tests/unit/test_issue362_execution_control_plumbing.py"]
    )
    assert result["release_blocked"] is False
    assert result["selected_rule_ids"] == ["phase-a-shared-control-execution-schema"]
    assert result["selected_units"] == ["control-api", "execution-orchestrator"]
    assert result["execution_safety_required"] is True


def test_execution_changes_select_only_execution_and_raise_safety_flag() -> None:
    for path in (
        "backend/app/execution/orchestrator.py",
        "backend/app/execution_orchestrator.py",
    ):
        result = classify_phase_a([path])
        assert result["selected_units"] == ["execution-orchestrator"]
        assert set(result["dependency_closure"]) == {
            "execution-orchestrator",
            "gateway-rpc-request-proxy",
            "gateway-rpc-publish-proxy",
        }
        assert result["execution_changed"] is True
        assert result["execution_safety_required"] is True


@pytest.mark.parametrize(
    "path",
    (
        "deployments/phase-a/Containerfile.gateway-proxy",
        "deployments/phase-a/gateway-allowlist.json",
        "deployments/phase-a/gateway_proxy.py",
    ),
)
def test_gateway_proxy_asset_selects_exact_execution_closure_only(path: str) -> None:
    result = classify_phase_a([path])
    assert result["selected_units"] == ["execution-orchestrator"]
    assert set(result["dependency_closure"]) == {
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }
    assert result["frontend_edge_changed"] is False
    assert result["control_api_changed"] is False
    assert result["execution_safety_required"] is True
    assert result["selected_rule_ids"] == ["phase-a-gateway-proxy-build"]
    assert result["release_blocked"] is False


@pytest.mark.parametrize(
    ("path", "selected_units", "closure"),
    (
        (
            "frontend/Containerfile",
            ["frontend-edge"],
            {"frontend-edge"},
        ),
        (
            "deployments/phase-a/Containerfile.control-api",
            ["control-api"],
            {"control-api"},
        ),
        (
            "deployments/phase-a/Containerfile.execution-orchestrator",
            ["execution-orchestrator"],
            {
                "execution-orchestrator",
                "gateway-rpc-request-proxy",
                "gateway-rpc-publish-proxy",
            },
        ),
    ),
)
def test_containerfile_classifier_matrix_is_unit_exact(
    path: str, selected_units: list[str], closure: set[str]
) -> None:
    result = classify_phase_a([path])
    assert result["release_blocked"] is False
    assert result["selected_units"] == selected_units
    assert set(result["dependency_closure"]) == closure


@pytest.mark.parametrize(
    "path",
    (
        "deployments/docker-compose.phase-a.yml",
        "deployments/docker-compose.prod.yml",
        "deployments/docker-compose.final.yml",
    ),
)
def test_compose_paths_select_all_primary_units_and_execution_proxy_closure(
    path: str,
) -> None:
    result = classify_phase_a([path])
    assert result["selected_rule_ids"] == ["phase-a-compose"]
    assert result["selected_units"] == [
        "control-api",
        "execution-orchestrator",
        "frontend-edge",
    ]
    assert set(result["dependency_closure"]) == {
        "control-api",
        "execution-orchestrator",
        "frontend-edge",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }


def test_final_compose_path_produces_phase_a_full_build_plan() -> None:
    plan = create_plan(["deployments/docker-compose.final.yml"], source_commit_sha=SHA)
    assert plan["decision"] == "BUILD_ONLY"
    assert plan["selected_rule_ids"] == ["phase-a-compose"]
    assert {unit["unit"] for unit in plan["build_units"]} == {
        "control-api",
        "execution-orchestrator",
        "frontend-edge",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }


def test_postgres_init_selects_only_database_consumers_and_execution_closure() -> None:
    result = classify_phase_a(["deployments/phase-a/postgres-init.sh"])
    assert result["selected_rule_ids"] == ["phase-a-postgres-init"]
    assert result["selected_units"] == ["control-api", "execution-orchestrator"]
    assert "frontend-edge" not in result["dependency_closure"]
    assert {
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    } <= set(result["dependency_closure"])


def test_unknown_phase_a_deployment_asset_fails_closed() -> None:
    result = classify_phase_a(["deployments/phase-a/unreviewed-entrypoint.sh"])
    assert result["release_blocked"] is True
    assert result["unknown_changed"] is True
    assert result["selected_units"] == []


@pytest.mark.parametrize(
    "path",
    [
        "backend/tests/unit/test_research_warehouse_daily_roll_predecessor_catalog.py",
        "backend/tests/unit/test_research_warehouse_verified_daily_pit_main_roll_source.py",
        "deployments/research-warehouse/daily-pit-main-roll-source-v1.schema.json",
        "deployments/research-warehouse/daily-roll-predecessor-catalog-receipt-v1.schema.json",
        "deployments/research-warehouse/verified-daily-pit-main-roll-source-v2.schema.json",
        "scripts/research_warehouse/daily_pit_main_roll_source.py",
        "scripts/research_warehouse/daily_roll_predecessor_catalog.py",
        "scripts/research_warehouse/verified_daily_pit_main_roll_source.py",
    ],
)
def test_issue362_research_foundations_are_preserved_exactly(
    path: str,
) -> None:
    result = classify_phase_a([path])

    assert result["release_blocked"] is False
    assert result["selected_rule_ids"] == [
        "phase-a-preserved-issue362-research-foundation"
    ]
    assert result["selected_units"] == []
    assert result["dependency_closure"] == []


@pytest.mark.parametrize("path", CURRENT_PHASE_B_CHANGED_PATHS)
def test_current_phase_b_paths_are_preserved_without_phase_a_units(path: str) -> None:
    result = classify_phase_a([path])
    assert result["release_blocked"] is False

    if path in PHASE_B_SHARED_CI_PATHS:
        # Workflow and CI changes retain their existing Phase A verification
        # behavior because their contracts are intentionally cross-phase.
        assert "phase-a-preserved-phase-b" not in result["selected_rule_ids"]
    else:
        assert result["selected_rule_ids"] == ["phase-a-preserved-phase-b"]
    if path == ".github/workflows/ci.yml":
        assert result["selected_units"] == [
            "control-api",
            "execution-orchestrator",
            "frontend-edge",
        ]
    else:
        assert result["selected_units"] == []
        assert result["dependency_closure"] == []


def test_phase_b_only_paths_produce_no_phase_a_build_or_deploy_plan() -> None:
    paths = [
        path
        for path in CURRENT_PHASE_B_CHANGED_PATHS
        if path not in PHASE_B_SHARED_CI_PATHS
    ]
    plan = create_plan(paths, source_commit_sha=SHA)
    assert plan["decision"] == "CONTRACT_ONLY"
    assert plan["selected_units"] == []
    assert plan["build_units"] == []
    assert plan["deploy_units"] == []


def test_unknown_non_phase_b_path_remains_blocked() -> None:
    result = classify_phase_a(["scripts/phase_b_workers_new/unreviewed.py"])
    assert result["release_blocked"] is True
    assert result["unknown_changed"] is True
    assert result["selected_units"] == []


def test_windows_fence_change_selects_execution_proxy_closure_and_external_artifact() -> (
    None
):
    result = classify_phase_a(
        ["scripts/windows_fence_foundation/final_admission_v1.py"]
    )
    assert result["selected_units"] == ["execution-orchestrator"]
    assert set(result["dependency_closure"]) == {
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }
    assert result["external_artifacts"] == ["windows-ctp-gateway"]
    assert result["frontend_edge_changed"] is False
    assert result["control_api_changed"] is False


def test_shared_typed_contract_unions_actual_consumers() -> None:
    result = classify_phase_a(
        ["docs/schemas/web-bridge-control-execution-command-v1.schema.json"]
    )
    assert result["selected_units"] == ["control-api", "execution-orchestrator"]
    assert set(result["dependency_closure"]) == {
        "control-api",
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }
    assert result["shared_contract_changed"] is True
    assert result["execution_safety_required"] is True

    status_projection = classify_phase_a(["backend/app/schemas/control_execution.py"])
    assert status_projection["release_blocked"] is False
    assert status_projection["selected_units"] == [
        "control-api",
        "execution-orchestrator",
    ]

    profile = classify_phase_a(["shared/trading_session_profiles.json"])
    assert profile["selected_units"] == [
        "control-api",
        "execution-orchestrator",
        "frontend-edge",
    ]
    assert set(profile["dependency_closure"]) == {
        "control-api",
        "execution-orchestrator",
        "frontend-edge",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }

    frontend_only = classify_phase_a(["frontend/src/router/index.ts"])
    control_only = classify_phase_a(["backend/app/control_api.py"])
    for isolated in (frontend_only, control_only):
        assert "gateway-rpc-request-proxy" not in isolated["dependency_closure"]
        assert "gateway-rpc-publish-proxy" not in isolated["dependency_closure"]


def test_unknown_ambiguous_and_legacy_monolith_paths_are_classified() -> None:
    unknown = classify_phase_a(["new/unowned/file.txt"])
    assert unknown["release_blocked"] is True
    assert unknown["unknown_changed"] is True
    assert unknown["selected_units"] == []

    ambiguous = classify_phase_a(["backend/app/execution/models.py"])
    # Exact shared rule outranks the execution prefix, so this path is not
    # ambiguous and proves that specificity is deterministic.
    assert ambiguous["release_blocked"] is False
    assert ambiguous["selected_units"] == ["control-api", "execution-orchestrator"]

    root_image = classify_phase_a(["Dockerfile"])
    assert root_image["release_blocked"] is False
    assert root_image["selected_units"] == ["control-api"]
    assert root_image["selected_rule_ids"] == ["phase-a-root-dockerfile"]

    forbidden = classify_phase_a(["test_rpc_trade_flow.py"])
    assert forbidden["release_blocked"] is True
    assert forbidden["blocked_reasons"][0]["code"] == "legacy_monolith_forbidden"
    assert forbidden["selected_units"] == []


def test_equal_specificity_overlap_is_ambiguous_and_blocks(monkeypatch) -> None:
    from scripts.ci import classify_changes

    original = classify_changes.PHASE_A_RULES
    duplicate = dict(original[2])
    duplicate["id"] = "duplicate-frontend-rule"
    classify_changes.PHASE_A_RULES = (*original, duplicate)
    try:
        result = classify_phase_a(["frontend/src/App.tsx"])
    finally:
        classify_changes.PHASE_A_RULES = original
    assert result["release_blocked"] is True
    assert result["ambiguous_changed"] is True


@pytest.mark.parametrize(
    "paths",
    [
        ["frontend/src/App.tsx"],
        ["backend/app/control_api.py"],
        ["backend/app/execution/orchestrator.py"],
        ["docs/schemas/web-bridge-control-execution-command-v1.schema.json"],
        ["new/unowned/file.txt"],
    ],
)
def test_phase_a_plan_is_schema_valid_and_never_claims_deployment(
    paths: list[str],
) -> None:
    plan = create_plan(paths, source_commit_sha=SHA)
    Draft202012Validator(PLAN_SCHEMA).validate(plan)
    assert plan["deploy_units"] == []
    assert plan["restart_units"] == []
    assert plan["automatic_deploy_allowed"] is False
    assert plan["manual_deploy_allowed"] is False
    assert plan["production_allowed"] is False
    assert plan["live_trading_authorized"] is False
    assert plan["countable_forward"] is False
    assert plan["deployed"] is False
    assert plan["accepted"] is False


def test_unknown_baseline_and_missing_build_file_block_plan() -> None:
    plan = create_plan(
        ["frontend/src/App.tsx"], source_commit_sha=SHA, baseline_known=False
    )
    assert plan["decision"] == "BLOCKED"
    assert plan["blocked_reasons"][0]["code"] == "unknown_baseline"


def test_root_dockerfile_static_contract_blocks_monolith_reintroduction() -> None:
    current = create_plan(["Dockerfile"], source_commit_sha=SHA)
    assert current["decision"] == "BUILD_ONLY"
    assert current["selected_units"] == ["control-api"]
    assert current["blocked_reasons"] == []

    regressed = create_plan(
        ["Dockerfile"],
        source_commit_sha=SHA,
        static_contents={
            "Dockerfile": "FROM node:22 AS frontend-build\nCOPY frontend/dist /app/frontend/dist\n"
        },
    )
    assert regressed["decision"] == "BLOCKED"
    assert regressed["blocked_reasons"][0]["code"] == "static_contract_violation"


def test_classifier_manifest_rules_are_one_to_one() -> None:
    manifest = json.loads(
        (
            ROOT / "docs/architecture/issue-291-phase-a-release-dependencies-v1.json"
        ).read_text(encoding="utf-8")
    )
    manifest_rules = {str(rule["id"]): rule for rule in manifest["path_rules"]}
    classifier_rules = {str(rule["id"]): rule for rule in PHASE_A_RULES}
    assert set(manifest_rules) == set(classifier_rules)
    for rule_id, classifier_rule in classifier_rules.items():
        manifest_rule = manifest_rules[rule_id]
        assert manifest_rule["match"] == {
            key: list(value) for key, value in classifier_rule["match"].items()
        }
        assert manifest_rule["units"] == list(classifier_rule["units"])
        assert manifest_rule["verification"] == list(classifier_rule["verification"])
        assert manifest_rule["kind"] == classifier_rule["kind"]
        assert manifest_rule["shared"] is classifier_rule["shared"]
        assert manifest_rule["safety"] is classifier_rule["safety"]
        assert manifest_rule["external_artifacts"] == list(
            classifier_rule["external_artifacts"]
        )


def test_static_changed_paths_produce_allowed_dependency_closure() -> None:
    paths = [
        "frontend/src/App.tsx",
        "backend/app/control_api.py",
        "backend/app/execution/orchestrator.py",
        "backend/app/services/commodity_c_fast_execution_quality_artifact_revalidation.py",
        "scripts/windows_fence_foundation/assembly.py",
    ]
    plan = create_plan(paths, source_commit_sha=SHA)
    assert plan["decision"] == "BUILD_ONLY"
    assert plan["blocked_reasons"] == []
    assert plan["selected_units"] == [
        "control-api",
        "execution-orchestrator",
        "frontend-edge",
    ]
    assert {unit["unit"] for unit in plan["build_units"]} == {
        "frontend-edge",
        "control-api",
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }
    assert plan["external_artifacts"] == ["windows-ctp-gateway"]
    assert plan["dependency_closure"]["external_artifacts"] == ["windows-ctp-gateway"]
    assert "phase-a-windows-fence-external-artifact" in plan["selected_rule_ids"]


@pytest.mark.parametrize("working_directory", ("repo-root", "external"))
def test_cli_entrypoint_resolves_repo_root_without_pythonpath(
    tmp_path: Path, working_directory: str
) -> None:
    paths_file = tmp_path / "paths.txt"
    output = tmp_path / f"plan-{working_directory}.json"
    paths_file.write_text("frontend/src/App.tsx\n", encoding="utf-8")
    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/ci/plan_phase_a_release.py"),
            "--paths-file",
            str(paths_file),
            "--source-commit-sha",
            SHA,
            "--output",
            str(output),
        ],
        cwd=ROOT if working_directory == "repo-root" else tmp_path,
        env=clean_env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    plan = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(PLAN_SCHEMA).validate(plan)
    assert plan["decision"] == "BUILD_ONLY"
    assert plan["changed_paths"] == ["frontend/src/App.tsx"]


def test_phase_a_release_manifest_records_real_build_files_without_deploy_claim() -> (
    None
):
    manifest = json.loads(
        (
            ROOT / "docs/architecture/issue-291-phase-a-release-dependencies-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["status"] == "build_contract_implemented_not_deployed_or_accepted"
    units = {item["id"]: item for item in manifest["build_units"]}
    assert set(units) == {
        "frontend-edge",
        "control-api",
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }
    assert units["frontend-edge"]["build_file"] == "frontend/Containerfile"
    assert units["control-api"]["build_file"] == (
        "deployments/phase-a/Containerfile.control-api"
    )
    assert units["execution-orchestrator"]["build_file"] == (
        "deployments/phase-a/Containerfile.execution-orchestrator"
    )
    assert units["gateway-rpc-request-proxy"]["build_file"] == (
        "deployments/phase-a/Containerfile.gateway-proxy"
    )
    assert units["gateway-rpc-request-proxy"]["required_target_env"] == (
        "WINDOWS_RPC_REQ_ADDRESS"
    )
    assert units["gateway-rpc-publish-proxy"]["required_target_env"] == (
        "WINDOWS_RPC_PUB_ADDRESS"
    )
    assert units["control-api"]["runtime_user"] == "65532:65532"
    assert units["execution-orchestrator"]["runtime_user"] == "65532:65532"
    for proxy_id, command in (
        ("gateway-rpc-request-proxy", "request"),
        ("gateway-rpc-publish-proxy", "publish"),
    ):
        assert units[proxy_id]["entrypoint"] == (
            "python /usr/local/bin/gateway_proxy.py"
        )
        assert units[proxy_id]["command"] == command
        assert (
            PHASE_A_UNIT_METADATA[proxy_id]["entrypoint"]
            == units[proxy_id]["entrypoint"]
        )
        assert PHASE_A_UNIT_METADATA[proxy_id]["command"] == command
        assert units[proxy_id]["runtime_user"] == "65532:65532"
        assert units[proxy_id]["health"] == "/health/live,/health/ready"
        assert units[proxy_id]["version"] == "/version"
    assert manifest["dependency_closure"][
        "frontend_control_only_never_selects_gateway_proxies"
    ]
    assert manifest["dependency_closure"]["execution_never_joins_gateway_egress"]
    assert manifest["dependency_closure"][
        "execution_readiness_requires_both_gateway_proxies_healthy"
    ]
    assert all(item["deploy_units"] == [] for item in units.values())
    assert manifest["safety"]["deployed"] is False
    assert manifest["safety"]["accepted"] is False
    assert manifest["safety"]["production_allowed"] is False


def test_proxy_release_plan_records_fixed_python_entrypoint_and_role_commands() -> None:
    plan = create_plan(["deployments/phase-a/gateway_proxy.py"], source_commit_sha=SHA)
    assert plan["decision"] == "BUILD_ONLY"
    assert plan["selected_units"] == ["execution-orchestrator"]
    units = {item["unit"]: item for item in plan["build_units"]}
    assert set(units) == {
        "execution-orchestrator",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    }
    for proxy_id, command in (
        ("gateway-rpc-request-proxy", "request"),
        ("gateway-rpc-publish-proxy", "publish"),
    ):
        assert units[proxy_id]["entrypoint"] == (
            "python /usr/local/bin/gateway_proxy.py"
        )
        assert units[proxy_id]["command"] == command
    assert all(unit not in units for unit in ("frontend-edge", "control-api"))
    Draft202012Validator(PLAN_SCHEMA).validate(plan)
