from pathlib import Path

import yaml


def test_phase_c_offline_e2e_compose_is_private_and_has_no_fake_runtime_switch() -> (
    None
):
    root = Path(__file__).resolve().parents[3]
    compose = (root / "deployments/phase-c/docker-compose.offline-e2e.yml").read_text()
    document = yaml.safe_load(compose)
    client = (root / "backend/app/phase_c/client.py").read_text()
    assert (
        "artifact-custody" in compose
        and "execution-orchestrator" in compose
        and "control-api" in compose
    )
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert "PHASE_C_OFFLINE_FAKE_ADAPTER_ENABLED" not in client
    assert (
        "publish-install"
        in (root / "backend/app/phase_c/custody_service.py").read_text()
    )
    assert "deployments/phase-c/Containerfile" not in compose
    assert document["services"]["artifact-custody"]["entrypoint"] == [
        "python",
        "-m",
        "uvicorn",
    ]
    assert document["services"]["artifact-custody"]["command"] == [
        "app.phase_c_custody:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8091",
    ]
    custody_image = (
        root / "deployments/phase-b/Containerfile.artifact-custody"
    ).read_text()
    control_image = (root / "deployments/phase-a/Containerfile.control-api").read_text()
    execution_image = (
        root / "deployments/phase-a/Containerfile.execution-orchestrator"
    ).read_text()
    assert (
        "/var/lib/phase-c-custody" in custody_image
        and "chown 65532:65532" in custody_image
    )
    assert "PYTHONPATH=/app/backend:/app" in control_image
    assert (
        "/var/lib/vnpy-control" in control_image
        and "chown -R 65532:65532" in control_image
    )
    assert (
        "/var/lib/vnpy-execution" in execution_image
        and "chown -R 65532:65532" in execution_image
    )
