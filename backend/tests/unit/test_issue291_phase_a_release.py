from __future__ import annotations

import json
import subprocess
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
    ("deployments/docker-compose.phase-a.yml", "deployments/docker-compose.prod.yml"),
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


def test_full_current_changed_paths_produce_allowed_dependency_closure() -> None:
    tracked = subprocess.check_output(
        ["git", "diff", "--name-only", "origin/main"],
        cwd=ROOT,
        text=True,
    ).splitlines()
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
    ).splitlines()
    paths = sorted({path for path in (*tracked, *untracked) if path})
    assert paths, "the Phase A fixture must exercise a non-empty changed-path set"
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
