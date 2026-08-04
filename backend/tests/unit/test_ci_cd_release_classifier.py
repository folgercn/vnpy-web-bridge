import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.ci.plan_legacy_cd_guard import create_plan

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = json.loads(
    (ROOT / "docs/architecture/web-bridge-release-dependencies-v1.json").read_text(
        encoding="utf-8"
    )
)
SCHEMA = json.loads(
    (ROOT / "docs/schemas/web-bridge-legacy-cd-guard-plan-v1.schema.json").read_text(
        encoding="utf-8"
    )
)
SOURCE_SHA = "a" * 40


def _plan(paths: list[str]) -> dict[str, object]:
    plan = create_plan(paths, source_commit_sha=SOURCE_SHA, manifest=MANIFEST)
    Draft202012Validator(SCHEMA).validate(plan)
    return plan


@pytest.mark.parametrize(
    ("paths", "decision", "build_units"),
    [
        (["README.md"], "NO_DEPLOY", []),
        (["frontend/src/App.vue"], "BUILD_ONLY", ["legacy-web-bridge-app"]),
        (
            ["backend/app/api/routes_status.py"],
            "BUILD_ONLY",
            ["legacy-web-bridge-app"],
        ),
        (
            ["backend/app/main.py"],
            "BLOCKED",
            ["legacy-web-bridge-app"],
        ),
        (["deployments/docker-compose.prod.yml"], "BLOCKED", []),
        ([".github/workflows/cd.yml"], "BLOCKED", []),
        (
            ["scripts/windows_rpc_deployment_snapshot_v1.py"],
            "BLOCKED",
            ["legacy-web-bridge-app"],
        ),
        (
            ["scripts/windows_fence_foundation/install_attempt.py"],
            "BLOCKED",
            ["legacy-web-bridge-app"],
        ),
        (
            ["docs/schemas/windows-rpc-durable-fence-state-v1.schema.json"],
            "BLOCKED",
            ["legacy-web-bridge-app"],
        ),
        (
            ["docs/operations/windows-rpc-durable-fence-foundation-v1.md"],
            "BLOCKED",
            ["legacy-web-bridge-app"],
        ),
        (
            ["docs/architecture/windows-rpc-durable-fence-foundation-chain-v1.json"],
            "BLOCKED",
            ["legacy-web-bridge-app"],
        ),
        (["future-unowned-path.txt"], "BLOCKED", []),
        ([], "BLOCKED", []),
    ],
)
def test_guard_plan_is_fail_closed(
    paths: list[str], decision: str, build_units: list[str]
) -> None:
    plan = _plan(paths)
    assert plan["decision"] == decision
    assert plan["build_units"] == build_units
    assert plan["restart_units"] == []
    assert plan["preserve_units"] == ["postgres", "questdb", "web-bridge"]
    assert plan["automatic_deploy_allowed"] is False
    assert plan["manual_deploy_allowed"] is False
    assert plan["merge_gate_blocked"] is (
        not paths or "future-unowned-path.txt" in paths
    )


def test_mixed_docs_and_frontend_is_build_only_without_restart() -> None:
    plan = _plan(["README.md", "frontend/src/App.vue"])
    assert plan["decision"] == "BUILD_ONLY"
    assert plan["build_units"] == ["legacy-web-bridge-app"]
    assert plan["restart_units"] == []


def test_unknown_or_infrastructure_path_has_explicit_blocker() -> None:
    unknown = _plan(["unowned/new.txt"])
    assert unknown["blocked_reasons"] == [
        {"path": "unowned/new.txt", "code": "unknown_path", "rule_id": None}
    ]
    unknown["merge_gate_blocked"] = False
    assert list(Draft202012Validator(SCHEMA).iter_errors(unknown))

    infrastructure = _plan([".github/workflows/cd.yml"])
    assert infrastructure["blocked_reasons"] == [
        {
            "path": ".github/workflows/cd.yml",
            "code": "infra_manual",
            "rule_id": "release-workflows",
        }
    ]
    assert infrastructure["merge_gate_blocked"] is False

    windows = _plan(["scripts/windows_rpc_deployment_snapshot_v1.py"])
    assert windows["blocked_reasons"] == [
        {
            "path": "scripts/windows_rpc_deployment_snapshot_v1.py",
            "code": "infra_manual",
            "rule_id": "windows-fence-foundation-sources",
        }
    ]
    assert windows["restart_units"] == []
    assert windows["automatic_deploy_allowed"] is False
    assert windows["manual_deploy_allowed"] is False


def test_known_plus_unknown_and_ambiguous_rules_block_merge() -> None:
    mixed = _plan(["frontend/src/App.vue", "unowned/new.txt"])
    assert mixed["decision"] == "BLOCKED"
    assert mixed["build_units"] == ["legacy-web-bridge-app"]
    assert mixed["merge_gate_blocked"] is True

    ambiguous_manifest = deepcopy(MANIFEST)
    duplicate = deepcopy(
        next(rule for rule in MANIFEST["path_rules"] if rule["id"] == "root-readme")
    )
    duplicate["id"] = "duplicate-root-readme"
    ambiguous_manifest["path_rules"].append(duplicate)
    ambiguous = create_plan(
        ["README.md"],
        source_commit_sha=SOURCE_SHA,
        manifest=ambiguous_manifest,
    )
    assert ambiguous["merge_gate_blocked"] is True
    assert ambiguous["blocked_reasons"][0]["code"] == "ambiguous_rule"


def test_source_sha_must_be_complete_and_nonzero() -> None:
    for invalid in ("a" * 12, "0" * 40, "g" * 40):
        with pytest.raises(ValueError, match="source_commit_sha"):
            create_plan(["README.md"], source_commit_sha=invalid, manifest=MANIFEST)


def test_unknown_diff_baseline_blocks_merge_even_when_all_paths_are_known() -> None:
    plan = create_plan(
        ["README.md"],
        source_commit_sha=SOURCE_SHA,
        manifest=MANIFEST,
        baseline_known=False,
    )
    Draft202012Validator(SCHEMA).validate(plan)
    assert plan["decision"] == "BLOCKED"
    assert plan["merge_gate_blocked"] is True
    assert plan["blocked_reasons"][0] == {
        "path": "<baseline>",
        "code": "unknown_baseline",
        "rule_id": None,
    }


def test_cli_writes_schema_valid_evidence_before_failing_unknown_path(
    tmp_path: Path,
) -> None:
    paths_file = tmp_path / "paths.txt"
    output = tmp_path / "plan.json"
    paths_file.write_text("unowned/new.txt\n", encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/ci/plan_legacy_cd_guard.py"),
            "--paths-file",
            str(paths_file),
            "--source-commit-sha",
            SOURCE_SHA,
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    plan = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(SCHEMA).validate(plan)
    assert plan["merge_gate_blocked"] is True
