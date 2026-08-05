from pathlib import Path

WORKFLOW = (Path(__file__).resolve().parents[3] / ".github/workflows/ci.yml").read_text(
    encoding="utf-8"
)


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


def test_windows_fence_gate_is_read_only_cross_platform_and_non_deploying() -> None:
    assert (
        "windows_fence_changed: ${{ steps.filter.outputs.windows_fence_changed }}"
        in WORKFLOW
    )
    job = WORKFLOW.split("  windows-fence-core:\n", maxsplit=1)[1].split(
        "  docker:\n", maxsplit=1
    )[0]

    assert "if: needs.changes.outputs.windows_fence_changed == 'true'" in job
    assert "permissions:\n      contents: read" in job
    assert "os: [ubuntu-latest, windows-latest]" in job
    assert "backend/tests/unit/test_windows_rpc_deployment_snapshot_v1.py" in job
    assert "backend/tests/unit/test_windows_rpc_durable_fence_store_v1.py" in job
    assert "backend/tests/unit/test_windows_rpc_durable_fence_admission_v1.py" in job
    assert "backend/tests/unit/test_windows_rpc_durable_fence_bootstrap_v1.py" in job
    assert "backend/tests/unit/test_windows_rpc_durable_fence_bundle_v1.py" in job
    assert "backend/tests/unit/test_windows_rpc_durable_fence_manifest_v1.py" in job
    assert (
        "backend/tests/unit/test_windows_rpc_durable_fence_target_contract_v1.py" in job
    )
    assert "cryptography==48.0.0" in (
        Path(__file__).resolve().parents[3] / "scripts/ci/requirements-quick.txt"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "secrets.",
        "id-token:",
        "packages: write",
        "docker build",
        "docker/build-push-action",
        "actions/upload-artifact",
        "cache:",
        "ssh ",
        "scp ",
        "scripts/deploy.sh",
        "docker compose",
        "kubectl ",
        "Restart-Service",
        "Start-Service",
        "Stop-Service",
        "sc.exe",
    ):
        assert forbidden.lower() not in job.lower()

    gate = WORKFLOW.split("  ci-gate:\n", maxsplit=1)[1]
    assert "- windows-fence-core" in gate
