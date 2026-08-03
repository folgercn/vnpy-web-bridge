from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[3] / ".github/workflows/ci.yml"
).read_text(encoding="utf-8")


def test_concurrency_is_scoped_per_pr_and_preserves_main_runs() -> None:
    assert (
        "group: ci-${{ github.workflow }}-${{ "
        "github.event.pull_request.number || github.ref }}" in WORKFLOW
    )
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in WORKFLOW


def test_ci_gate_is_stable_and_always_created() -> None:
    gate = WORKFLOW.split("  ci-gate:\n", maxsplit=1)[1]

    assert "name: CI Gate" in gate
    assert "if: always()" in gate
    assert 'not in {"success", "skipped"}' in gate


def test_fork_pull_requests_cannot_write_build_caches() -> None:
    same_repository_guard = (
        "github.event.pull_request.head.repo.full_name == github.repository"
    )

    assert WORKFLOW.count(same_repository_guard) >= 3


def test_quick_checks_only_run_dependency_free_ci_contract_tests() -> None:
    quick_checks = WORKFLOW.split("  quick-checks:\n", maxsplit=1)[1].split(
        "  backend:\n", maxsplit=1
    )[0]

    assert "focused_tests.py" not in quick_checks
    assert "backend/tests/unit/test_ci_backend_test_shards.py" in quick_checks
    assert "backend/tests/unit/test_ci_change_classifier.py" in quick_checks
    assert "backend/tests/unit/test_ci_workflow_contract.py" in quick_checks
