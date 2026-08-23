from pathlib import Path

from scripts.ci.classify_changes import (
    PHASE_B_UNITS,
    classify,
    classify_phase_a,
    classify_phase_b,
)
from scripts.ci.validate_json_schemas import SCHEMA_DIRECTORIES


def test_workflow_change_conservatively_triggers_every_area() -> None:
    assert all(classify([".github/workflows/ci.yml"]).values())


def test_query_containerfiles_and_copy_closure_trigger_real_oci() -> None:
    positives = [
        "scripts/c_fast_t1/Containerfile.query-v4",
        "scripts/c_fast_t1/Containerfile.query-v5",
        "scripts/commodity_c_fast_t1_query_v4.py",
        "scripts/commodity_c_fast_t1_query_v5_launcher.py",
        "scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py",
        "docs/schemas/commodity-c-fast-t1-query-v5-image-attestation-v1.schema.json",
        "docs/operations/c-fast-t1-query-v4-runtime.template.yml",
        "docs/operations/c-fast-t1-query-v5-image-attestation-pin-set.template.json",
        "scripts/c_fast_t1/create_query_v4_source_bundle.py",
        "scripts/c_fast_t1/verify_image_attestation.py",
        "scripts/c_fast_t1/ci_query_v5_real_oci_attestation.py",
        "backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py",
        "scripts/ci/requirements-query-v5.txt",
    ]

    for path in positives:
        assert classify([path])["query_v5_changed"], path


def test_every_query_v4_v5_containerfile_copy_source_triggers_real_oci() -> None:
    root = Path(__file__).resolve().parents[3]
    containerfiles = (
        root / "scripts/c_fast_t1/Containerfile.query-v3",
        root / "scripts/c_fast_t1/Containerfile.query-v4",
        root / "scripts/c_fast_t1/Containerfile.query-v5",
    )

    copy_sources = []
    for containerfile in containerfiles:
        for line in containerfile.read_text(encoding="utf-8").splitlines():
            if line.startswith("COPY "):
                copy_sources.append(line.split()[1])

    assert copy_sources
    for path in copy_sources:
        assert classify([path])["query_v5_changed"], path


def test_non_closure_commodity_changes_do_not_trigger_real_oci() -> None:
    negatives = [
        "scripts/commodity_c_fast_fee_statement.py",
        "scripts/commodity_c_fast_pnl_reconcile.py",
        "scripts/commodity_simnow_shakedown.py",
        "docs/schemas/commodity-c-fast-fee-statement-v1.schema.json",
        "scripts/research_warehouse/acquire.py",
        "docs/operations/unrelated.md",
    ]

    for path in negatives:
        assert not classify([path])["query_v5_changed"], path
        if path.startswith(("scripts/", "docs/schemas/")):
            assert classify([path])["backend_changed"], path


def test_area_classification_examples() -> None:
    assert classify(["backend/app/main.py"])["backend_changed"]
    assert classify(["scripts/ci/backend_test_shards.py"])["backend_changed"]
    assert classify(["frontend/src/App.tsx"])["frontend_changed"]
    assert not any(classify(["docs/README.md"]).values())
    assert all(classify([], force_all=True).values())


def test_simnow_runner_packaging_fastlane_skips_unrelated_heavy_ci() -> None:
    fastlane = [
        "deployments/phase-b/Containerfile.simnow-runner",
        "deployments/phase-b/requirements-simnow-runner.txt",
        "backend/tests/unit/test_issue325_keyless_simnow.py",
        "backend/tests/unit/test_issue362_simnow_continuous_run_once.py",
    ]
    for path in fastlane:
        assert not any(classify([path]).values()), path

    for path in fastlane[:2] + fastlane[3:]:
        phase_b = classify_phase_b([path])
        assert phase_b["phase_b_changed"] is True
        assert phase_b["phase_b_shared_contract_changed"] is False
        assert phase_b["selected_units"] == []
        assert phase_b["phase_b_gate_blocked"] is False

    test_only = classify_phase_b([fastlane[2]])
    assert test_only["phase_b_changed"] is False
    assert test_only["selected_units"] == []


def test_simnow_runner_logic_and_shared_execution_still_take_heavy_paths() -> None:
    runner_logic = classify(["scripts/simnow_continuous_run_once.py"])
    assert runner_logic["backend_changed"] is True
    assert runner_logic["image_changed"] is True

    shared_execution = classify(["backend/app/execution/formal_tick_reader.py"])
    assert shared_execution["backend_changed"] is True
    assert shared_execution["image_changed"] is True

    for path in (
        "scripts/simnow_continuous_run_once.py",
        "backend/app/execution/formal_tick_reader.py",
    ):
        phase_b = classify_phase_b([path])
        assert phase_b["phase_b_changed"] is True
        assert phase_b["phase_b_shared_contract_changed"] is True
        assert phase_b["selected_units"] == list(PHASE_B_UNITS)
        assert phase_b["phase_b_gate_blocked"] is False


def test_issue412_experimental_glue_stays_on_the_contract_only_fast_lane() -> None:
    glue_only = [
        "deployments/com.vnpy-web-bridge.simnow-experimental.plist",
        "deployments/docker-compose.simnow-experimental.yml",
        "deployments/simnow-experimental-run-once.sh",
        "scripts/simnow_experimental_materialize_target.py",
        "scripts/simnow_experimental_monthly_once.py",
        "scripts/simnow_experimental_run_once.py",
        "backend/tests/unit/test_simnow_experimental_target.py",
        "docs/schemas/simnow-experimental-target-v1.schema.json",
        "deployments/phase-b/Containerfile.simnow-experimental-runner",
        "deployments/phase-b/requirements-simnow-experimental-runner.txt",
    ]

    for path in glue_only:
        result = classify([path])
        assert result["simnow_experimental_changed"] is True, path
        assert not any(
            value
            for key, value in result.items()
            if key != "simnow_experimental_changed"
        ), path

        phase_a = classify_phase_a([path])
        assert phase_a["release_blocked"] is False, path
        assert phase_a["selected_rule_ids"] == [
            "phase-a-preserved-issue412-simnow-experimental"
        ], path
        assert phase_a["selected_units"] == [], path

        phase_b = classify_phase_b([path])
        assert phase_b["phase_b_gate_blocked"] is False, path
        assert phase_b["selected_units"] == [], path


def test_issue412_fast_lane_does_not_cover_execution_or_quote_core() -> None:
    core_paths = (
        "backend/app/execution/formal_tick_reader.py",
        "backend/app/execution/final_runtime.py",
        "shared/commodity_execution/target_plan.py",
    )

    for path in core_paths:
        result = classify([path])
        assert result["backend_changed"] is True, path
        assert result["image_changed"] is True, path
        assert result["simnow_experimental_changed"] is False, path

    formal_tick = classify_phase_b([core_paths[0]])
    assert formal_tick["phase_b_shared_contract_changed"] is True
    assert formal_tick["selected_units"] == list(PHASE_B_UNITS)


def test_experimental_fast_lane_requires_explicit_glue_registration() -> None:
    for path in (
        "deployments/com.vnpy-web-bridge.simnow-experimental.plist",
        "deployments/docker-compose.simnow-experimental.yml",
        "deployments/simnow-experimental-run-once.sh",
        "scripts/simnow_experimental_materialize_target.py",
        "scripts/simnow_experimental_monthly_once.py",
        "scripts/simnow_experimental_run_once.py",
    ):
        assert classify([path])["simnow_experimental_changed"] is True

    unregistered = classify(["scripts/simnow_experimental_future_helper.py"])
    assert unregistered["backend_changed"] is True
    assert unregistered["simnow_experimental_changed"] is False
    assert classify(["backend/tests/unit/test_simnow_experimental_target.py"])[
        "simnow_experimental_changed"
    ] is True


def test_global_schema_gate_includes_research_warehouse_contracts() -> None:
    root = Path(__file__).resolve().parents[3]
    research_schema_directory = root / "deployments/research-warehouse"

    assert research_schema_directory in SCHEMA_DIRECTORIES
    assert (
        research_schema_directory / "verified-daily-pit-main-roll-source-v2.schema.json"
    ).is_file()


def test_windows_fence_exact_paths_use_the_dedicated_gate_without_generic_image() -> (
    None
):
    paths = [
        "scripts/windows_rpc_deployment_snapshot_v1.py",
        "scripts/windows_rpc_durable_fence_v1.py",
        "scripts/windows_fence_foundation/store.py",
        "scripts/windows_fence_foundation/bootstrap_v1.py",
        "scripts/windows_fence_foundation/bundle_v1.py",
        "scripts/windows_fence_foundation/manifest_v1.py",
        "scripts/windows_fence_foundation/target_contract_v1.py",
        "scripts/windows_fence_foundation/trust_pins_v1.py",
        "scripts/windows_fence_foundation/build_manifest_draft_v1.py",
        "scripts/windows_fence_foundation/offline_signing_v1.py",
        "scripts/windows_fence_foundation/release_bundle_v1.py",
        "scripts/windows_fence_foundation/release_input_builder_v1.py",
        "scripts/windows_fence_foundation/release_input_builder_cli_v1.py",
        "docs/schemas/windows-fence-release-build-audit-v1.schema.json",
        "docs/schemas/windows-fence-release-input-v1.schema.json",
        "docs/schemas/windows-rpc-durable-fence-signing-closure-bundle-v1.schema.json",
        "docs/operations/windows-rpc-durable-fence-offline-signing-closure-v1.md",
        "docs/schemas/windows-rpc-durable-fence-state-v1.schema.json",
        "docs/operations/windows-rpc-durable-fence-foundation-v1.md",
        "docs/architecture/windows-rpc-durable-fence-foundation-chain-v1.json",
        "backend/tests/unit/test_windows_rpc_durable_fence_store_v1.py",
        "backend/tests/unit/test_windows_rpc_durable_fence_admission_v1.py",
        "backend/tests/unit/test_windows_rpc_durable_fence_bootstrap_v1.py",
        "backend/tests/unit/test_windows_rpc_durable_fence_bundle_v1.py",
        "backend/tests/unit/test_windows_rpc_durable_fence_manifest_v1.py",
        "backend/tests/unit/test_windows_rpc_durable_fence_target_contract_v1.py",
        "backend/tests/unit/test_windows_fence_offline_signing_v1.py",
        "backend/tests/unit/test_windows_fence_signing_closure_e2e_v1.py",
        "backend/tests/unit/windows_fence_public_fixture_v1.py",
        "backend/tests/integration/test_windows_fence_foundation_windows.py",
    ]

    for path in paths:
        result = classify([path])
        assert result["windows_fence_changed"], path
        assert result["backend_changed"], path
        assert not result["image_changed"], path
        assert not result["frontend_changed"], path
        assert not result["query_v5_changed"], path


def test_mixed_windows_fence_and_backend_runtime_still_builds_generic_image() -> None:
    result = classify(
        [
            "scripts/windows_rpc_durable_fence_v1.py",
            "backend/app/main.py",
        ]
    )

    assert result["windows_fence_changed"]
    assert result["backend_changed"]
    assert result["image_changed"]
