from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_lineage_verify as verifier  # noqa: E402


BUNDLE = ROOT / "docs/research/commodity-c-fast-lineage-v1"


def _copy_bundle(tmp_path: Path) -> Path:
    copied = tmp_path / "bundle"
    shutil.copytree(BUNDLE, copied)
    return copied


def _manifest(bundle: Path) -> dict:
    return json.loads(
        (bundle / "bundle_manifest.json").read_text(encoding="utf-8")
    )


def _write_manifest(bundle: Path, manifest: dict) -> None:
    (bundle / "bundle_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_committed_lineage_bundle_verifies() -> None:
    assert verifier.verify_bundle(BUNDLE) == {
        "status": "PASS",
        "archive_files": 15,
        "consumer_source_hashes": 4,
        "source_lineage_hashes": 5,
        "sector_map_products": 10,
        "authority_fields_false": 10,
    }


def test_tampered_archive_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    target = bundle / "sources/commodity_fast_tsmom_family_dev_v1.py"
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")

    with pytest.raises(
        verifier.LineageVerificationError,
        match="archive byte size mismatch",
    ):
        verifier.verify_bundle(bundle)


def test_missing_archive_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    (
        bundle
        / "freeze/forward_collection_TEMPLATE.json"
    ).unlink()

    with pytest.raises(
        verifier.LineageVerificationError,
        match="archive file missing",
    ):
        verifier.verify_bundle(bundle)


def test_authority_escalation_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["authority"]["dispatch_authorized"] = True
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="authority must be explicitly all false",
    ):
        verifier.verify_bundle(bundle)


def test_path_traversal_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["archive_bindings"][0]["path"] = "../outside.py"
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="unsafe archive path",
    ):
        verifier.verify_bundle(bundle)


def test_consumer_lineage_drift_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["consumer"]["lineage"][
        "fast_tsmom_signal_source_sha256"
    ] = "0" * 64
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="consumer lineage mismatch",
    ):
        verifier.verify_bundle(bundle)


def test_consumer_identity_drift_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["consumer"]["path"] = "scripts/unrelated.py"
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="consumer path mismatch",
    ):
        verifier.verify_bundle(bundle)


def test_consumer_audited_commit_drift_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["consumer"]["audited_main_commit"] = "0" * 40
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="consumer audited commit mismatch",
    ):
        verifier.verify_bundle(bundle)


def test_manifest_consumer_source_hash_drift_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["consumer"]["source_sha256"] = "0" * 64
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="manifest consumer source sha256 mismatch",
    ):
        verifier.verify_bundle(bundle)


def test_manifest_related_consumer_source_hash_drift_fails_closed(
    tmp_path: Path,
) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["consumer"]["related_source_sha256"][
        "scripts/commodity_static_core_equal_pure_producer.py"
    ] = "0" * 64
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="manifest related consumer source hashes mismatch",
    ):
        verifier.verify_bundle(bundle)


def test_live_consumer_source_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_root = tmp_path / "root"
    consumer = fake_root / verifier.CONSUMER_PATH
    consumer.parent.mkdir(parents=True)
    shutil.copy2(ROOT / verifier.CONSUMER_PATH, consumer)
    consumer.write_bytes(consumer.read_bytes() + b"\n# drift\n")
    monkeypatch.setattr(verifier, "ROOT", fake_root)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="live consumer source sha256 mismatch",
    ):
        verifier.verify_bundle(BUNDLE)


def test_related_consumer_source_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_root = tmp_path / "root"
    primary = fake_root / verifier.CONSUMER_PATH
    primary.parent.mkdir(parents=True)
    shutil.copy2(ROOT / verifier.CONSUMER_PATH, primary)
    for related_path in verifier.RELATED_CONSUMER_SOURCE_SHA256:
        target = fake_root / related_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / related_path, target)
    drifted = (
        fake_root
        / "scripts/commodity_static_core_equal_pure_producer.py"
    )
    drifted.write_bytes(drifted.read_bytes() + b"\n# drift\n")
    monkeypatch.setattr(verifier, "ROOT", fake_root)

    with pytest.raises(
        verifier.LineageVerificationError,
        match=(
            "related consumer source sha256 mismatch: "
            "scripts/commodity_static_core_equal_pure_producer.py"
        ),
    ):
        verifier.verify_bundle(BUNDLE)


def test_missing_related_consumer_source_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_root = tmp_path / "root"
    primary = fake_root / verifier.CONSUMER_PATH
    primary.parent.mkdir(parents=True)
    shutil.copy2(ROOT / verifier.CONSUMER_PATH, primary)
    monkeypatch.setattr(verifier, "ROOT", fake_root)

    with pytest.raises(
        verifier.LineageVerificationError,
        match=(
            "related consumer source is missing or unsafe: "
            "scripts/commodity_static_core_equal_formula_v1.py"
        ),
    ):
        verifier.verify_bundle(BUNDLE)


def test_symlinked_related_consumer_source_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_root = tmp_path / "root"
    primary = fake_root / verifier.CONSUMER_PATH
    primary.parent.mkdir(parents=True)
    shutil.copy2(ROOT / verifier.CONSUMER_PATH, primary)
    for related_path in verifier.RELATED_CONSUMER_SOURCE_SHA256:
        target = fake_root / related_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if related_path.endswith("formula_v1.py"):
            target.symlink_to(ROOT / related_path)
        else:
            shutil.copy2(ROOT / related_path, target)
    monkeypatch.setattr(verifier, "ROOT", fake_root)

    with pytest.raises(
        verifier.LineageVerificationError,
        match=(
            "related consumer source is missing or unsafe: "
            "scripts/commodity_static_core_equal_formula_v1.py"
        ),
    ):
        verifier.verify_bundle(BUNDLE)


def test_missing_live_consumer_source_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(verifier, "ROOT", tmp_path / "missing-root")

    with pytest.raises(
        verifier.LineageVerificationError,
        match="live consumer source is missing or unsafe",
    ):
        verifier.verify_bundle(BUNDLE)


def test_symlinked_live_consumer_source_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_root = tmp_path / "root"
    consumer = fake_root / verifier.CONSUMER_PATH
    consumer.parent.mkdir(parents=True)
    consumer.symlink_to(ROOT / verifier.CONSUMER_PATH)
    monkeypatch.setattr(verifier, "ROOT", fake_root)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="live consumer source is missing or unsafe",
    ):
        verifier.verify_bundle(BUNDLE)


def test_consumer_sector_map_identity_drift_fails_closed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest = _manifest(bundle)
    manifest["consumer"]["sector_map_id"] = "UNRELATED_MAP"
    _write_manifest(bundle, manifest)

    with pytest.raises(
        verifier.LineageVerificationError,
        match="manifest consumer sector map id mismatch",
    ):
        verifier.verify_bundle(bundle)
