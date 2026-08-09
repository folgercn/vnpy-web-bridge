from pathlib import Path

from scripts.ci.classify_changes import classify


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
