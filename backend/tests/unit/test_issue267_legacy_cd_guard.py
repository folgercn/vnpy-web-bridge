from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
ISSUE79_WORKFLOW = (
    ROOT / ".github/workflows/issue79-production-validation.yml"
).read_text(encoding="utf-8")


def test_legacy_cd_workflow_is_removed() -> None:
    assert not (ROOT / ".github/workflows/cd.yml").exists()


def test_no_registered_workflow_contains_legacy_deploy_commands() -> None:
    workflows = [
        *(ROOT / ".github/workflows").glob("*.yml"),
        *(ROOT / ".github/workflows").glob("*.yaml"),
    ]
    assert workflows
    for workflow in workflows:
        content = workflow.read_text(encoding="utf-8")
        for forbidden in (
            "Deploy via docker compose",
            "Build and deploy on Macmini",
            "scripts/deploy.sh",
            "docker compose up",
            "rsync -az --delete",
        ):
            assert forbidden not in content, (workflow, forbidden)


def test_issue79_is_a_separate_main_owner_guarded_workflow() -> None:
    trigger = ISSUE79_WORKFLOW.split("jobs:\n", maxsplit=1)[0]
    job = ISSUE79_WORKFLOW.split(
        "  issue79-production-validation:\n", maxsplit=1
    )[1]
    assert "workflow_dispatch:" in trigger
    assert "push:" not in trigger
    assert "pull_request" not in trigger
    assert "github.ref == 'refs/heads/main'" in job
    assert "github.repository == 'folgercn/vnpy-web-bridge'" in job
    assert "github.repository_owner == 'folgercn'" in job
    assert "github.actor == 'folgercn'" in job


def test_issue79_validation_retains_separate_confirmation() -> None:
    assert 'test "$CONFIRMATION" = "ISSUE79_PRODUCTION"' in ISSUE79_WORKFLOW
    assert "inputs.confirmation" in ISSUE79_WORKFLOW


def test_ci_always_publishes_guard_plan_before_ci_gate() -> None:
    plan_job = CI_WORKFLOW.split(
        "  legacy-cd-guard-plan:\n", maxsplit=1
    )[1].split("  backend:\n", maxsplit=1)[0]
    ci_gate = CI_WORKFLOW.split("  ci-gate:\n", maxsplit=1)[1]
    assert "python scripts/ci/plan_legacy_cd_guard.py" in plan_job
    assert "actions/upload-artifact@v4" in plan_job
    assert "if: always()" in plan_job
    assert "git diff --name-only --no-renames" in plan_job
    assert "baseline_status=unknown" in plan_job
    assert '--baseline-status "${{ steps.changed-files.outputs.baseline_status }}"' in plan_job
    assert "- legacy-cd-guard-plan" in ci_gate
    assert 'needs["legacy-cd-guard-plan"]["result"] != "success"' in ci_gate
