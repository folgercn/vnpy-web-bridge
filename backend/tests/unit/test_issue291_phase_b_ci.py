from __future__ import annotations

from pathlib import Path

from scripts.ci import classify_changes
from scripts.ci.classify_changes import PHASE_B_UNITS, classify_phase_b

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
PHASE_B_COMPOSE = (ROOT / "deployments/docker-compose.phase-b.yml").read_text(encoding="utf-8")


def _phase_b_job() -> str:
    return WORKFLOW.split("  phase-b-ci:\n", maxsplit=1)[1].split(
        "  backend:\n", maxsplit=1
    )[0]


def test_phase_b_containerfiles_select_their_exact_consumer() -> None:
    expected = {
        "artifact-custody": "artifact-custody",
        "c-fast-producer": "c-fast-producer",
        "execution-quality-worker": "execution-quality-worker",
        "map-producer": "map-producer",
        "market-data-worker": "market-data-worker",
        "monitor-worker": "monitor-worker",
        "signing-authority": "signing-authority",
    }
    for image, unit in expected.items():
        result = classify_phase_b([f"deployments/phase-b/Containerfile.{image}"])
        assert result["phase_b_changed"] is True
        assert result["phase_b_gate_blocked"] is False
        assert result["selected_units"] == [unit]


def test_phase_b_shared_contracts_select_every_consumer() -> None:
    for path in (
        "shared/trust_contracts/v1.py",
        "docs/schemas/issue-291-phase-b-trust-keyring-v1.schema.json",
        "docs/schemas/web-bridge-artifact-envelope-v1.schema.json",
        "deployments/docker-compose.phase-b.yml",
    ):
        result = classify_phase_b([path])
        assert result["phase_b_changed"] is True
        assert result["phase_b_shared_contract_changed"] is True
        assert result["selected_units"] == list(PHASE_B_UNITS)
        assert result["phase_b_gate_blocked"] is False


def test_phase_b_artifact_image_dependency_selects_its_consumers() -> None:
    result = classify_phase_b(["deployments/phase-b/requirements-artifact.txt"])
    assert result["phase_b_changed"] is True
    assert result["selected_units"] == ["artifact-custody", "signing-authority"]
    assert result["phase_b_gate_blocked"] is False


def test_phase_b_unknown_and_ambiguous_owned_paths_fail_closed() -> None:
    unknown = classify_phase_b(["deployments/phase-b/unreviewed-entrypoint.sh"])
    assert unknown["phase_b_changed"] is True
    assert unknown["phase_b_unknown_changed"] is True
    assert unknown["phase_b_gate_blocked"] is True

    original = classify_changes.PHASE_B_RULES
    duplicate = dict(original[2])
    duplicate["id"] = "duplicate-artifact-custody"
    classify_changes.PHASE_B_RULES = (*original, duplicate)
    try:
        ambiguous = classify_phase_b(
            ["deployments/phase-b/Containerfile.artifact-custody"]
        )
    finally:
        classify_changes.PHASE_B_RULES = original
    assert ambiguous["phase_b_changed"] is True
    assert ambiguous["phase_b_ambiguous_changed"] is True
    assert ambiguous["phase_b_gate_blocked"] is True


def test_phase_b_gate_is_not_selected_for_unrelated_paths() -> None:
    result = classify_phase_b(["backend/app/main.py", "docs/README.md"])
    assert result["phase_b_changed"] is False
    assert result["phase_b_gate_blocked"] is False
    assert result["selected_units"] == []


def test_phase_b_workflow_builds_all_images_and_smokes_offline_only() -> None:
    job = _phase_b_job()
    assert "if: needs.changes.outputs.phase_b_changed == 'true'" in job
    assert "--phase-b" in job
    assert "scripts/phase_b_workers/tests" in job
    assert "PYTHONPATH=backend:scripts:. pytest -q" in job
    assert "scripts/ci/validate_json_schemas.py" in job
    assert "docker compose -f deployments/docker-compose.phase-b.yml config --quiet" in job
    assert "MAP_ACCEPTANCE_KEYRING_SHA256" in job
    assert "--network none" in job
    assert "--read-only" in job
    assert "--cap-drop ALL" in job
    assert "LIVE_TRADING_AUTHORIZED=false" in job
    assert "COUNTABLE_FORWARD=false" in job
    assert "docker volume create" in job
    assert 'docker volume create "$volume"' in job
    assert 'state=(-v "$volume:/state")' in job
    assert "--tmpfs /state:" not in job
    for unit in PHASE_B_UNITS:
        assert f"Containerfile.{unit}" in job
    for forbidden in (
        "docker compose up",
        "scripts/deploy.sh",
        "ssh ",
        "scp ",
        "--key-fd",
        "--request-sha256",
        "WEB_TRADE_ENABLED=true",
    ):
        assert forbidden.lower() not in job.lower()


def test_phase_b_compose_keeps_durable_state_and_projections_out_of_tmpfs() -> None:
    for durable in (
        "artifact_custody_state:", "market_data_state:", "execution_quality_state:",
        "monitor_state:", "artifact_custody_projection_state:",
        "market_data_projection_state:", "execution_quality_projection_state:",
    ):
        assert f"{durable}\n    driver_opts" not in PHASE_B_COMPOSE
        assert f"{durable}\n      type: tmpfs" not in PHASE_B_COMPOSE
    assert "${CUSTODY_WRITER_EPOCH:?CUSTODY_WRITER_EPOCH required}" in PHASE_B_COMPOSE
    assert "artifact_custody_projection_state:/var/lib/phase-b/projections/artifact-custody:ro" in PHASE_B_COMPOSE
    assert "market_data_projection_state:/var/lib/phase-b/projections/market-data-worker:ro" in PHASE_B_COMPOSE
    assert "execution_quality_projection_state:/var/lib/phase-b/projections/execution-quality-worker:ro" in PHASE_B_COMPOSE
    assert "PHASE_B_MONITOR_NOTIFIER_ENABLED: \"false\"" in PHASE_B_COMPOSE


def test_ci_gate_requires_phase_b_job_but_allows_it_to_skip_when_irrelevant() -> None:
    changes = WORKFLOW.split("  changes:\n", maxsplit=1)[1].split(
        "  quick-checks:\n", maxsplit=1
    )[0]
    gate = WORKFLOW.split("  ci-gate:\n", maxsplit=1)[1]
    assert "phase_b_changed: ${{ steps.phase_b_filter.outputs.phase_b_changed }}" in changes
    assert "phase_b_gate_blocked: ${{ steps.phase_b_filter.outputs.phase_b_gate_blocked }}" in changes
    assert "- phase-b-ci" in gate
    assert 'not in {"success", "skipped"}' in gate
