from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import yaml
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
    create_app,
)
from fastapi.testclient import TestClient

from scripts.ci.phase_c_release_matrix import UNIT_METADATA, create_plan

ROOT = Path(__file__).resolve().parents[3]


def _service(tmp_path: Path) -> ArtifactCustodyService:
    policy = CustodyPolicy(str(tmp_path / "keyring.json"), "0" * 64, "unused")
    return ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            "control-secret",
            frozenset({"control-api"}),
            {name: policy for name in ("map_acceptance", "c_fast_acceptance", "runtime_authorization")},
            "execution-read-secret",
        )
    )


def test_custody_separates_control_from_execution_target_plan_read(tmp_path: Path) -> None:
    service = _service(tmp_path)
    app = create_app(
        ArtifactCustodyService(
            replace(service.settings, projection_dir=tmp_path / "projection")
        )
    )
    with TestClient(app) as client:
        control = client.get(
            "/internal/v1/artifacts/target-plan-0001",
            headers={
                "X-Phase-C-Principal": "control-api",
                "X-Phase-C-Custody-Secret": "control-secret",
            },
        )
        assert control.status_code == 401
        execution = client.get(
            "/internal/v1/artifacts/target-plan-0001",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": "execution-read-secret",
            },
        )
        assert execution.status_code == 404
        assert client.get("/health/live").json()["status"] == "live"
        assert client.get("/health/ready").json()["status"] == "ready"
    assert (tmp_path / "projection" / "artifact-custody.json").is_file()


def test_final_compose_keeps_custody_single_writer_and_data_plane_isolated() -> None:
    raw = (ROOT / "deployments/docker-compose.final.yml").read_text(encoding="utf-8")
    document = yaml.safe_load(raw)
    services = document["services"]
    assert "artifact-custody" in services and "phase-c-execution" not in services
    assert services["artifact-custody"]["command"][0] == "app.phase_c_custody:app"
    assert "artifact_custody_projection:/var/lib/phase-b/projection" in raw
    assert services["execution-orchestrator"]["environment"]["FINAL_EXECUTION_RUNTIME_REQUIRED"] == "true"
    assert services["execution-orchestrator"]["environment"]["EXECUTION_ALLOW_SIMNOW_EXECUTION"] == "false"
    assert "gateway-egress" not in services["execution-orchestrator"]["networks"]
    assert services["market-data-worker"]["networks"] == ["market-ingress", "questdb-data"]
    assert services["gateway-rpc-publish-proxy"]["networks"] == ["gateway-proxy", "gateway-egress", "market-ingress"]
    assert services["map-producer"]["profiles"] == ["batch"]
    assert services["c-fast-producer"]["profiles"] == ["batch"]
    assert services["signing-authority"]["profiles"] == ["offline-signing"]
    assert "WAL DEDUP UPSERT KEYS(ts, ingest_id)" in (ROOT / "deployments/final/questdb-market-ticks.sql").read_text(encoding="utf-8")


def test_final_runtime_paths_expand_the_a_b_build_closure() -> None:
    plan = create_plan(
        [
            "deployments/docker-compose.final.yml",
            "deployments/phase-b/Containerfile.artifact-custody",
            "shared/commodity_execution/v1.py",
            "scripts/phase_b_workers/market_data_worker.py",
        ],
        source_commit_sha="863c8fe5a7b86e66c5cf996e4e9425229aa54e29",
    )
    assert plan["decision"] == "BUILD_ONLY"
    assert {(item["phase"], item["unit"]) for item in plan["build_units"]} == set(
        UNIT_METADATA
    )
