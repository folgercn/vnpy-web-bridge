from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
    create_app,
)
from fastapi.testclient import TestClient
from phase_b_workers.projections import validate_projection

from scripts.ci.phase_c_release_matrix import UNIT_METADATA, create_plan
from shared.artifact_custody.v1 import CustodyError
from shared.commodity_execution import TARGET_PLAN_SCHEMA_VERSION

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
        legacy_execution = client.get(
            "/internal/v1/artifacts/target-plan-0001",
            headers={
                "X-Phase-C-Principal": "phase-c-execution",
                "X-Phase-C-Custody-Secret": "control-secret",
            },
        )
        assert legacy_execution.status_code == 401
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
    projection_path = tmp_path / "projection" / "artifact-custody.json"
    assert projection_path.is_file()
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    assert validate_projection(
        projection, expected_service_id="artifact-custody"
    )["service_id"] == "artifact-custody"


def test_custody_rejects_reused_control_and_execution_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = {
        name: {
            "keyring_path": str(tmp_path / f"{name}.json"),
            "keyring_raw_sha256": "0" * 64,
            "key_purpose": "public-only",
        }
        for name in ("map_acceptance", "c_fast_acceptance", "runtime_authorization")
    }
    monkeypatch.setenv("PHASE_C_CUSTODY_ROOT", str(tmp_path / "custody"))
    monkeypatch.setenv("PHASE_C_CUSTODY_SHARED_SECRET", "same-secret")
    monkeypatch.setenv("PHASE_C_CUSTODY_EXECUTION_READ_SECRET", "same-secret")
    monkeypatch.setenv("PHASE_C_CUSTODY_WRITER_EPOCH", "1")
    monkeypatch.setenv("PHASE_C_CUSTODY_POLICIES_JSON", json.dumps(policy))
    with pytest.raises(RuntimeError, match="configuration"):
        CustodySettings.from_env()


def test_custody_target_plan_schema_is_readable_but_fails_closed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with service._custody() as custody:
        assert TARGET_PLAN_SCHEMA_VERSION in custody.schema_registry
        with pytest.raises(CustodyError, match="CUSTODY_SCHEMA_UNKNOWN"):
            custody._validate_schema({"schema_ref": "unreviewed-schema", "payload": {}})
        with pytest.raises(CustodyError, match="CUSTODY_SCHEMA_VALIDATION_FAILED"):
            custody._validate_schema(
                {"schema_ref": TARGET_PLAN_SCHEMA_VERSION, "payload": {}}
            )


def test_custody_image_includes_only_the_target_plan_contract_closure() -> None:
    containerfile = (
        ROOT / "deployments/phase-b/Containerfile.artifact-custody"
    ).read_text(encoding="utf-8")
    assert "COPY shared/commodity_execution /app/shared/commodity_execution" in containerfile
    assert "COPY backend/app/execution " not in containerfile
    assert "COPY deployments/phase-a/" not in containerfile


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
    assert "docker-compose.runtime-smoke.yml" in (
        ROOT / "scripts/ci/final_runtime_compose_smoke.sh"
    ).read_text(encoding="utf-8")
    smoke_source = (ROOT / "deployments/final/market_source.py").read_text(
        encoding="utf-8"
    )
    smoke = (ROOT / "scripts/ci/final_runtime_compose_smoke.sh").read_text(
        encoding="utf-8"
    )
    assert "datetime(2026, 8, 8, 1, 2, 3, tzinfo=timezone.utc)" in smoke_source
    assert smoke.index('assert int(fence["last_source_seq"]) >= 2') < smoke.index(
        "SELECT count(*)"
    )
    assert 'event_time.isoformat() == "2026-08-08T01:02:03+00:00"' in smoke


def test_runtime_smoke_bootstraps_only_a_signed_target_plan_before_http_custody() -> None:
    smoke_compose = yaml.safe_load(
        (ROOT / "deployments/final/docker-compose.runtime-smoke.yml").read_text(
            encoding="utf-8"
        )
    )
    bootstrap = smoke_compose["services"]["artifact-bootstrap"]
    assert bootstrap["profiles"] == ["bootstrap"]
    assert bootstrap["network_mode"] == "none"
    assert "custody_state:/var/lib/phase-c-custody" in bootstrap["volumes"]
    assert "bootstrap_handoff:/handoff" in bootstrap["volumes"]
    smoke = (ROOT / "scripts/ci/final_runtime_compose_smoke.sh").read_text(
        encoding="utf-8"
    )
    assert "Ed25519PrivateKey.generate()" in smoke
    assert "docker cp \"$workdir/keyring.json\"" in smoke
    assert "docker cp \"$workdir/signed.json\"" in smoke
    assert "docker wait \"$bootstrap_container\"" in smoke
    assert "SMOKE_ARTIFACT_RAW_SHA256" in smoke
    assert '"X-Phase-C-Principal": "phase-c-execution"' in smoke
    assert (
        "custody_projection:/var/lib/phase-b/projections/artifact-custody:ro"
        in smoke_compose["services"]["monitor-worker"]["volumes"]
    )
    assert "docker exec -i \"$monitor_container\" python - <<'PY'" in smoke
    assert "artifact-custody projection invalid at {path}" in smoke


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
