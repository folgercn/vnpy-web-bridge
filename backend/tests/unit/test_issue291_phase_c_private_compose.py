from pathlib import Path


def test_phase_c_offline_e2e_compose_is_private_and_has_no_fake_runtime_switch() -> None:
    root = Path(__file__).resolve().parents[3]
    compose = (root / "deployments/phase-c/docker-compose.offline-e2e.yml").read_text()
    client = (root / "backend/app/phase_c/client.py").read_text()
    assert "artifact-custody" in compose and "execution-orchestrator" in compose and "control-api" in compose
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert "PHASE_C_OFFLINE_FAKE_ADAPTER_ENABLED" not in client
    assert "publish-install" in (root / "backend/app/phase_c/custody_service.py").read_text()
    assert "deployments/phase-c/Containerfile" not in compose
