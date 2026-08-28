from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
CD_WORKFLOW = (ROOT / ".github/workflows/m2-simnow-lab-cd.yml").read_text(encoding="utf-8")


def _job(name: str, next_name: str | None = None) -> str:
    section = WORKFLOW.split(f"  {name}:\n", maxsplit=1)[1]
    if next_name:
        section = section.split(f"  {next_name}:\n", maxsplit=1)[0]
    return section


def test_only_minimal_simnow_lab_jobs_remain() -> None:
    jobs = re.findall(
        r"^  ([a-z][a-z0-9-]+):$",
        WORKFLOW.split("jobs:\n", maxsplit=1)[1],
        flags=re.MULTILINE,
    )

    assert jobs == [
        "quick-checks",
        "simnow-lab-linux",
        "simnow-lab-windows",
        "simnow-lab-dashboard",
        "ci-gate",
    ]
    for retired in (
        "legacy-cd-guard-plan",
        "phase-a-release-plan",
        "phase-a-build-check",
        "phase-b-ci",
        "phase-b-projection-smoke",
        "phase-c-release-plan",
        "phase-c-build-and-smoke",
        "phase-c-phase-b-projection-smoke",
        "phase-c-offline-e2e",
        "final-runtime-compose-smoke",
        "backend",
        "frontend",
        "windows-fence-core",
        "docker",
        "query-v5-real-oci",
        "simnow-experimental",
    ):
        assert f"  {retired}:\n" not in WORKFLOW


def test_quick_checks_are_changed_file_only() -> None:
    job = _job("quick-checks", "simnow-lab-linux")

    assert 'git diff --check "$PULL_REQUEST_BASE_SHA" "$PULL_REQUEST_HEAD_SHA"' in job
    assert 'ruff check "${python_files[@]}"' in job
    assert 'python -m py_compile "${python_files[@]}"' in job
    assert "backend/tests/unit/test_ci_workflow_contract.py" in job
    assert "compileall" not in job
    assert "validate_json_schemas.py" not in job
    assert "backend_test_shards.py" not in job


def test_linux_lane_covers_only_m2_producer_and_lab() -> None:
    job = _job("simnow-lab-linux", "simnow-lab-windows")

    for required in (
        "test_commodity_static_core_equal_pure_producer.py",
        "test_late_receipt_stops_without_route_output",
        "test_future_shfe_main_uses_pinned_exact_expiry_outside_calendar_coverage",
        "test_service_identity_is_required_before_private_runtime_access",
        "test_stdout_route_mode_keeps_stop_payload_off_stdout",
        "test_issue462_simnow_lab_cli.py",
        "test_issue462_simnow_lab_m1.py",
        "test_windows_rpc_simnow_e2e_v1.py",
    ):
        assert required in job
    for forbidden in (
        "docker build",
        "Containerfile",
        "test_simnow_experimental_target.py",
        "test_issue291",
        "test_issue267",
    ):
        assert forbidden not in job


def test_windows_lane_is_focused_and_non_mutating() -> None:
    job = _job("simnow-lab-windows", "simnow-lab-dashboard")

    assert "runs-on: windows-latest" in job
    assert "pywin32==306 pyzmq==27.1.0 vnpy==4.4.0 --no-deps" in job
    assert "test_issue462_simnow_lab_cli.py" in job
    assert "test_issue462_simnow_lab_m1.py" in job
    assert "test_windows_rpc_simnow_e2e_v1.py" in job
    for forbidden in (
        "secrets.",
        "ssh ",
        "scp ",
        "Restart-Service",
        "Start-Service",
        "Stop-Service",
        "docker",
        "actions/upload-artifact",
    ):
        assert forbidden.lower() not in job.lower()


def test_dashboard_lane_is_read_only_and_focused() -> None:
    job = _job("simnow-lab-dashboard", "ci-gate")

    assert "test_issue466_windows_dashboard.py" in job
    assert "test_issue466_simnow_lab_dashboard_api.py" in job
    assert "test_issue466_simnow_lab_one_shot.py" in job
    assert "npm run check" in job
    for forbidden in ("docker", "ssh ", "scp ", "apply_target", "send_order", "cancel_order"):
        assert forbidden not in job.lower()


def test_ci_gate_keeps_the_required_context_stable() -> None:
    gate = _job("ci-gate")

    assert "name: CI Gate" in gate
    assert "if: always()" in gate
    assert "- quick-checks" in gate
    assert "- simnow-lab-linux" in gate
    assert "- simnow-lab-windows" in gate
    assert "- simnow-lab-dashboard" in gate
    assert 'details["result"] != "success"' in gate


def test_old_production_validation_workflows_are_removed() -> None:
    assert not (ROOT / ".github/workflows/issue45-production-validation.yml").exists()
    assert not (ROOT / ".github/workflows/issue79-production-validation.yml").exists()


def test_workflow_has_no_build_deploy_or_artifact_lane() -> None:
    assert "permissions:\n  contents: read" in WORKFLOW
    assert "DOCKER_BUILD_RECORD_UPLOAD" not in WORKFLOW
    for forbidden in (
        "docker/",
        "docker ",
        "actions/upload-artifact",
        "packages: write",
        "id-token:",
        "scripts/deploy.sh",
        "phase_c_",
        "Custody",
        "TargetPlan",
        "Execution",
    ):
        assert forbidden not in WORKFLOW


def test_m2_cd_uses_successful_main_exact_sha_and_one_release_entrypoint() -> None:
    assert "workflow_run:" in CD_WORKFLOW
    assert "github.event.workflow_run.conclusion == 'success'" in CD_WORKFLOW
    assert "github.event.workflow_run.head_branch == 'main'" in CD_WORKFLOW
    assert "EXPECTED_SHA: ${{ github.event.workflow_run.head_sha }}" in CD_WORKFLOW
    assert 'test "$actual_sha" = "$EXPECTED_SHA"' in CD_WORKFLOW
    assert "deployments/simnow-lab/release_v1.py" in CD_WORKFLOW
    assert "--channel main" in CD_WORKFLOW
    for forbidden in ("secrets.", "ssh ", "scp ", "upload-artifact", "Custody", "Execution"):
        assert forbidden.lower() not in CD_WORKFLOW.lower()
