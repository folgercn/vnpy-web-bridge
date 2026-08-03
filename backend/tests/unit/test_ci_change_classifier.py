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
