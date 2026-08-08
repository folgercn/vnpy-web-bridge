from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.ci.phase_c_build_receipt import create_receipt
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
    plan = create_plan(
        ["docs/schemas/issue-291-phase-c-release-matrix-v1.schema.json"],
        source_commit_sha=SHA,
    )
    assert plan["decision"] == "BUILD_ONLY"
    assert _units(plan) == set(UNIT_METADATA)


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
    assert "Superseded by the dependency-aware Phase C A+B matrix plan" in WORKFLOW
