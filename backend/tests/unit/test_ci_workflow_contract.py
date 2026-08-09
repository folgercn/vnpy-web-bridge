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
    assert "- phase-b-projection-smoke" in gate


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
    assert "installer_entry_v1 --native-host-preflight" in job
    assert "if: runner.os == 'Windows'" in job
    assert job.count("pip install pywin32==306") == 1
    assert job.index("pip install pywin32==306") < job.index(
        "Run Windows fence offline tests"
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


def test_issue291_phase_a_gate_builds_primary_images_and_execution_proxy_closure() -> (
    None
):
    assert "--phase-a --github-output" in WORKFLOW
    assert "phase_a_changed" in WORKFLOW
    assert "execution_safety_required" in WORKFLOW
    release = WORKFLOW.split("  phase-a-release-plan:\n", maxsplit=1)[1]
    assert "plan_phase_a_release.py" in release
    assert "issue-291-phase-a-release-plan" in release
    assert (
        "if: always() && hashFiles('artifacts/issue-291-phase-a-release-plan.json') != ''"
        in release
    )
    build = WORKFLOW.split("  phase-a-build-check:\n", maxsplit=1)[1].split(
        "  backend:\n", maxsplit=1
    )[0]
    assert "uses: actions/checkout@v7\n        with:\n          fetch-depth: 0" in build
    assert "cache-dependency-path: backend/requirements.txt" in build
    assert "pip install -r backend/requirements.txt" in build
    assert "pip install -r scripts/ci/requirements-quick.txt" not in build
    for token in (
        "frontend/Containerfile",
        "deployments/phase-a/Containerfile.control-api",
        "deployments/phase-a/Containerfile.execution-orchestrator",
        "deployments/phase-a/Containerfile.gateway-proxy",
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
        "GATEWAY_RPC_REQ_PROXY_PORT",
        "GATEWAY_RPC_PUB_PROXY_PORT",
        "WINDOWS_RPC_REQ_ADDRESS",
        "WINDOWS_RPC_PUB_ADDRESS",
        "vnpy-web-bridge-gateway-proxy:phase-a-${{ github.sha }}",
        "docker compose -f deployments/docker-compose.phase-a.yml config --quiet",
        "CONTROL_EXECUTION_SHARED_SECRET",
        "CONTROL_DB_PASSWORD",
        "WINDOWS_RPC_REQ_ADDRESS",
        "--entrypoint python",
        "--entrypoint nginx",
        "--add-host control-api:127.0.0.1",
        "['python','/usr/local/bin/gateway_proxy.py']",
        "c['Cmd'] == ['request']",
        "c['User'] == '65532:65532'",
        "value['service'] == 'gateway-rpc-proxy'",
        "health/live",
        "version",
        "test_issue291_phase_a_release.py",
        "test_issue291_phase_a_contract.py",
    ):
        assert token in build, token
    assert (
        "docker run --rm --add-host control-api:127.0.0.1 --entrypoint nginx" in build
    )
    assert "socat -V" not in build
    changes = WORKFLOW.split("  changes:\n", maxsplit=1)[1].split(
        "  quick-checks:\n", maxsplit=1
    )[0]
    assert (
        'git ls-tree -r --name-only "$CURRENT_SHA" > /tmp/changed-files.txt' in changes
    )
    assert (
        'if [ "$EVENT_NAME" = "workflow_dispatch" ]; then extra+=(--force-all); fi'
        in changes
    )
    gate = WORKFLOW.split("  ci-gate:\n", maxsplit=1)[1]
    assert "- phase-a-release-plan" in gate
    assert "- phase-a-build-check" in gate


def test_phase_a_ci_has_no_legacy_monolith_deploy_or_runtime_mutation() -> None:
    section = WORKFLOW.split("  phase-a-build-check:\n", maxsplit=1)[1].split(
        "  backend:\n", maxsplit=1
    )[0]
    for forbidden in (
        "scripts/deploy.sh",
        "ssh ",
        "scp ",
        "Restart-Service",
        "docker compose up",
        "production_allowed: true",
        "live_trading_authorized: true",
    ):
        assert forbidden.lower() not in section.lower()


def test_issue291_final_runtime_job_pins_pytest_before_invocation() -> None:
    job = WORKFLOW.split("  final-runtime-compose-smoke:\n", maxsplit=1)[1].split(
        "  backend:\n", maxsplit=1
    )[0]
    assert "pytest==8.3.4" in job
    assert "fastapi==0.115.6" in job
    assert "httpx==0.28.1" in job
    assert "jsonschema==4.26.0" in job
    assert "referencing==0.37.0" in job
    assert (
        "PYTHONPATH=backend:scripts:. pytest -q backend/tests/unit/test_issue291_final_runtime_integration.py"
        in job
    )
