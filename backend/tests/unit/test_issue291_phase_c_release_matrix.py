from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.ci.phase_c_build_receipt import create_receipt
from scripts.ci.classify_changes import classify_phase_a
from scripts.ci.phase_c_release_matrix import UNIT_METADATA, create_plan

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
MATRIX_SCHEMA = json.loads(
    (ROOT / "docs/schemas/issue-291-phase-c-release-matrix-v1.schema.json").read_text(
        encoding="utf-8"
    )
)
RECEIPT_SCHEMA = json.loads(
    (ROOT / "docs/schemas/issue-291-phase-c-image-receipt-v1.schema.json").read_text(
        encoding="utf-8"
    )
)
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
COMPOSE_SMOKE = (ROOT / "scripts/ci/phase_c_compose_smoke.sh").read_text(
    encoding="utf-8"
)
OFFLINE_E2E = (ROOT / "scripts/ci/phase_c_offline_e2e.sh").read_text(encoding="utf-8")
OFFLINE_E2E_COMPOSE = (
    ROOT / "deployments/phase-c/docker-compose.offline-e2e.yml"
).read_text(encoding="utf-8")


def _units(plan: dict[str, object]) -> set[tuple[str, str]]:
    return {(item["phase"], item["unit"]) for item in plan["build_units"]}  # type: ignore[index]


def test_frontend_only_change_builds_only_its_exact_phase_a_unit() -> None:
    plan = create_plan(["frontend/src/App.tsx"], source_commit_sha=SHA)
    Draft202012Validator(MATRIX_SCHEMA).validate(plan)
    assert plan["decision"] == "BUILD_ONLY"
    assert _units(plan) == {("A", "frontend-edge")}
    assert plan["phase_b"]["selected_units"] == []


def test_phase_a_shared_contract_expands_only_its_real_consumer_closure() -> None:
    plan = create_plan(
        ["docs/schemas/web-bridge-control-execution-command-v1.schema.json"],
        source_commit_sha=SHA,
    )
    assert _units(plan) == {
        ("A", "control-api"),
        ("A", "execution-orchestrator"),
        ("A", "gateway-rpc-request-proxy"),
        ("A", "gateway-rpc-publish-proxy"),
    }


def test_phase_b_image_change_selects_one_independent_unit() -> None:
    plan = create_plan(
        ["deployments/phase-b/Containerfile.market-data-worker"], source_commit_sha=SHA
    )
    assert plan["decision"] == "BUILD_ONLY"
    assert _units(plan) == {("B", "market-data-worker")}
    assert plan["phase_a"]["selected_units"] == []
    assert plan["phase_b_projection_required"] is True


def test_phase_b_batch_only_change_does_not_run_projection_dependency_group() -> None:
    plan = create_plan(
        ["deployments/phase-b/Containerfile.map-producer"], source_commit_sha=SHA
    )
    assert _units(plan) == {("B", "map-producer")}
    assert plan["phase_b_projection_required"] is False


def test_unknown_or_ambiguous_phase_inputs_block_whole_matrix(monkeypatch) -> None:
    unknown = create_plan(["deployments/phase-b/unreviewed.sh"], source_commit_sha=SHA)
    assert unknown["decision"] == "BLOCKED"
    assert unknown["blocked_reasons"][0]["phase"] == "B"
    assert unknown["blocked_reasons"][0]["code"] == "unknown_phase_b_path"

    from scripts.ci import classify_changes, phase_c_release_matrix

    original = classify_changes.PHASE_A_RULES
    duplicate = dict(original[2])
    duplicate["id"] = "phase-c-test-ambiguous-frontend"
    classify_changes.PHASE_A_RULES = (*original, duplicate)
    phase_c_release_matrix._classifier.PHASE_A_RULES = classify_changes.PHASE_A_RULES
    try:
        ambiguous = create_plan(["frontend/src/App.tsx"], source_commit_sha=SHA)
    finally:
        classify_changes.PHASE_A_RULES = original
        phase_c_release_matrix._classifier.PHASE_A_RULES = original
    assert ambiguous["decision"] == "BLOCKED"
    assert ambiguous["blocked_reasons"][0]["code"] == "ambiguous_rule"


def test_phase_c_shared_contract_change_exercises_all_a_and_b_units() -> None:
    for path in (
        "docs/schemas/issue-291-phase-c-release-matrix-v1.schema.json",
        "docs/schemas/issue-291-phase-c-image-receipt-v1.schema.json",
    ):
        plan = create_plan([path], source_commit_sha=SHA)
        assert plan["decision"] == "BUILD_ONLY"
        assert _units(plan) == set(UNIT_METADATA)
        assert plan["phase_b_projection_required"] is True
        assert plan["offline_e2e_required"] is True


def test_phase_c_offline_e2e_assets_are_explicitly_preserved_and_shared() -> None:
    paths = (
        "backend/app/phase_c_custody.py",
        "backend/app/phase_c_execution.py",
        "deployments/phase-c/Containerfile.custody",
        "deployments/phase-c/Containerfile.execution",
        "deployments/phase-c/docker-compose.offline-e2e.yml",
    )
    for path in paths:
        phase_a = classify_phase_a([path])
        assert phase_a["release_blocked"] is False
        assert phase_a["selected_rule_ids"] == ["phase-a-preserved-phase-c"]
        plan = create_plan([path], source_commit_sha=SHA)
        assert plan["decision"] == "BUILD_ONLY"
        assert _units(plan) == {
            ("A", "control-api"),
            ("A", "execution-orchestrator"),
            ("A", "gateway-rpc-request-proxy"),
            ("A", "gateway-rpc-publish-proxy"),
            ("B", "artifact-custody"),
        }
        assert plan["offline_e2e_required"] is True


def test_phase_c_workflow_path_selects_only_canonical_service_owners() -> None:
    plan = create_plan(
        ["backend/app/api/routes_phase_c_workflow.py"], source_commit_sha=SHA
    )
    assert _units(plan) == {
        ("A", "control-api"),
        ("A", "execution-orchestrator"),
        ("A", "gateway-rpc-request-proxy"),
        ("A", "gateway-rpc-publish-proxy"),
        ("B", "artifact-custody"),
    }
    assert plan["offline_e2e_required"] is True


def test_plan_is_unconditionally_non_deploying_and_requires_receipts() -> None:
    plan = create_plan(["frontend/src/App.tsx"], source_commit_sha=SHA)
    for field in (
        "automatic_deploy_allowed",
        "manual_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "deployed",
        "accepted",
    ):
        assert plan[field] is False
    unit = plan["build_units"][0]
    assert unit["immutable_oci_digest_required"] is True
    assert unit["build_receipt_required"] is True
    assert unit["rollback_receipt_required"] is True
    assert unit["deploy_allowed"] is False


def test_receipt_is_digest_pinned_and_rollback_is_explicit_build_only_hold() -> None:
    receipt = create_receipt(
        phase="A",
        unit="frontend-edge",
        source_commit_sha=SHA,
        image_repository="vnpy-web-bridge-frontend",
        image_tag="issue-291-phase-c-test",
        image_digest=IMAGE_DIGEST,
        containerfile="frontend/Containerfile",
        metadata_sha256="c" * 64,
    )
    Draft202012Validator(RECEIPT_SCHEMA).validate(receipt)
    assert receipt["immutable_image_ref"] == f"vnpy-web-bridge-frontend@{IMAGE_DIGEST}"
    assert receipt["rollback_identity"] == receipt["immutable_image_ref"]
    assert receipt["rollback_receipt"]["status"] == "build_only_hold"
    assert receipt["rollback_receipt"]["automatic_rollback_allowed"] is False
    assert receipt["production_allowed"] is False
    assert receipt["live_trading_authorized"] is False
    assert receipt["countable_forward"] is False


def test_ci_consumes_one_dynamic_matrix_and_keeps_compose_smoke_in_matrix_job() -> None:
    assert "phase-c-release-plan:" in WORKFLOW
    assert "phase-c-build-and-smoke:" in WORKFLOW
    assert "fromJSON(needs.phase-c-release-plan.outputs.build_matrix)" in WORKFLOW
    assert "scripts/ci/phase_c_build_and_smoke.sh" in WORKFLOW
    assert "scripts/ci/phase_c_compose_smoke.sh" in WORKFLOW
    assert "phase-c-phase-b-projection-smoke:" in WORKFLOW
    assert "phase-c-offline-e2e:" in WORKFLOW
    assert "scripts/ci/phase_c_offline_e2e.sh" in WORKFLOW
    assert "timeout-minutes: 25" in WORKFLOW
    assert "phase_b_projection_required" in WORKFLOW
    gate = WORKFLOW.split("  ci-gate:\n", maxsplit=1)[1]
    assert "- phase-c-phase-b-projection-smoke" in gate
    assert "- phase-c-offline-e2e" in gate
    assert "Superseded by the dependency-aware Phase C A+B matrix plan" in WORKFLOW


def test_compose_smoke_pins_selected_image_to_exact_service_or_gateway_pair() -> None:
    assert 'unit="${2:?selected unit required}"' in COMPOSE_SMOKE
    assert 'FRONTEND_IMAGE="$image"' in COMPOSE_SMOKE
    assert 'CONTROL_API_IMAGE="$image"' in COMPOSE_SMOKE
    assert 'EXECUTION_IMAGE="$image"' in COMPOSE_SMOKE
    assert 'GATEWAY_PROXY_IMAGE="$image"' in COMPOSE_SMOKE
    assert "JWT_SECRET_KEY='phase-c-ci-not-a-runtime-secret-x'" in COMPOSE_SMOKE
    for assignment in (
        'ARTIFACT_CUSTODY_IMAGE="$image"',
        'C_FAST_PRODUCER_IMAGE="$image"',
        'EXECUTION_QUALITY_WORKER_IMAGE="$image"',
        'MAP_PRODUCER_IMAGE="$image"',
        'MARKET_DATA_WORKER_IMAGE="$image"',
        'MONITOR_WORKER_IMAGE="$image"',
        'SIGNING_AUTHORITY_IMAGE="$image"',
    ):
        assert assignment in COMPOSE_SMOKE
    assert (
        '"gateway-rpc-request-proxy",\n        "gateway-rpc-publish-proxy",'
        in COMPOSE_SMOKE
    )
    assert 'config --format json > "$rendered"' in COMPOSE_SMOKE
    assert 'compose_profile=batch' in COMPOSE_SMOKE
    assert 'compose_profile=offline-signing' in COMPOSE_SMOKE
    assert 'compose_args=(--profile "$compose_profile"' in COMPOSE_SMOKE
    assert 'map-producer) MAP_PRODUCER_IMAGE="$image"; export MAP_PRODUCER_IMAGE; compose_profile=batch' in COMPOSE_SMOKE
    assert '"gateway-rpc-request-proxy": ["request"]' in COMPOSE_SMOKE
    assert '"gateway-rpc-publish-proxy": ["publish"]' in COMPOSE_SMOKE
    assert "if actual != image:" in COMPOSE_SMOKE


def test_gateway_publish_smoke_uses_explicit_runtime_mode_not_baked_cmd() -> None:
    build_smoke = (ROOT / "scripts/ci/phase_c_build_and_smoke.sh").read_text(
        encoding="utf-8"
    )
    assert "assert c['User'] == '65532:65532'" in build_smoke
    assert "assert c['Cmd'] == ['$expected']" not in build_smoke
    assert '"$image" version' in build_smoke


def test_offline_e2e_uses_canonical_images_and_receipts_not_phase_c_duplicates() -> (
    None
):
    assert "deployments/phase-a/Containerfile.control-api" in OFFLINE_E2E
    assert "deployments/phase-b/Containerfile.artifact-custody" in OFFLINE_E2E
    assert "deployments/phase-a/Containerfile.execution-orchestrator" in OFFLINE_E2E
    assert "deployments/phase-c/Containerfile" not in OFFLINE_E2E
    assert "PHASE_C_CUSTODY_POLICIES_JSON" in OFFLINE_E2E
    assert "Ed25519PrivateKey.generate" in OFFLINE_E2E
    assert "secrets.token_urlsafe(48)" in OFFLINE_E2E
    assert "failed to generate a compliant ephemeral Control JWT secret" in OFFLINE_E2E
    assert "phase-c-e2e-jwt-secret" not in OFFLINE_E2E
    assert "APP_ENV: phase-c-offline" in OFFLINE_E2E_COMPOSE
    assert "JWT_SECRET_KEY: ${JWT_SECRET_KEY:?required}" in OFFLINE_E2E_COMPOSE
    assert "immutable_image_ref" in OFFLINE_E2E
    assert "receipt_image_tag()" in OFFLINE_E2E
    assert "receipt['image_repository']}:{receipt['image_tag']}" in OFFLINE_E2E
    assert "receipt_image_tag artifacts/issue-291-phase-c-e2e-control-api-receipt.json" in OFFLINE_E2E
    assert "receipt_image_tag artifacts/issue-291-phase-c-e2e-artifact-custody-receipt.json" in OFFLINE_E2E
    assert "receipt_image_tag artifacts/issue-291-phase-c-e2e-execution-orchestrator-receipt.json" in OFFLINE_E2E
    assert '))["immutable_image_ref"])' not in OFFLINE_E2E
    for image_env in ("CONTROL_API_IMAGE", "ARTIFACT_CUSTODY_IMAGE", "EXECUTION_IMAGE"):
        assert image_env in OFFLINE_E2E
    assert "/api/phase-c/artifacts/upload-install" in OFFLINE_E2E
    assert "/api/phase-c/authorization/commands" in OFFLINE_E2E
    assert (
        "compose restart control-api artifact-custody execution-orchestrator"
        in OFFLINE_E2E
    )
    assert "wait_for_control" in OFFLINE_E2E
    assert "compose down --volumes --remove-orphans" in OFFLINE_E2E
    for unit in ("control-api", "artifact-custody", "execution-orchestrator"):
        assert f"issue-291-phase-c-e2e-{unit}-receipt.json" in OFFLINE_E2E
