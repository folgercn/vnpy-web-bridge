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
        "source_lineage_hashes": 5,
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
