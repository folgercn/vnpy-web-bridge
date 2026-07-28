from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.core.config import Settings
from app.schemas.commodity_c_fast_research import (
    CommodityCFastSimNowResearchBundleDTO,
)
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO
from app.services.commodity_c_fast_research import (
    CFastResearchBundleInvalidError,
    load_research_bundle,
    produce_unsigned_snapshot,
    research_bundle_checksum,
    verify_evidence_files,
)
from app.services.commodity_c_fast_shadow import (
    CommodityCFastShadowService,
)
from test_commodity_c_fast_shadow import (
    contract_loader,
    public_key_json,
    sign_payload,
    unsigned_payload,
)
from test_commodity_simnow import make_key


NOW = datetime(2026, 9, 1, 3, tzinfo=timezone.utc)


def make_bundle(tmp_path: Path) -> tuple[Path, Path, dict]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence_rows = []
    contents = {
        "research_manifest": b"real research manifest bytes\n",
        "allocation_evidence": b"real allocation evidence bytes\n",
        "daily_roll_evidence": b"real daily roll evidence bytes\n",
        "reference_price_source": b"real official-open evidence bytes\n",
    }
    for purpose, content in contents.items():
        relative_path = f"{purpose}.json"
        (evidence_root / relative_path).write_bytes(content)
        evidence_rows.append(
            {
                "purpose": purpose,
                "relative_path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    source = unsigned_payload()
    reference_hash = next(
        row["sha256"]
        for row in evidence_rows
        if row["purpose"] == "reference_price_source"
    )
    for target in source["targets"]:
        target["reference_price_source_sha256"] = reference_hash
    payload = {
        "schema_version": "commodity_c_fast_simnow_research_bundle_v1",
        "bundle_id": "c-fast-research-bundle-20260901",
        "snapshot_id": "c-fast-simnow-20260901",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "frozen_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "frozen_rule_sha256": (
            "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
        ),
        "purpose": "SIMNOW_SHAKEDOWN_NON_COUNTABLE_ONLY",
        "production_allowed": False,
        "countable_forward": False,
        "human_confirmation": (
            "HUMAN_CONFIRMED_RESEARCH_INPUT_FOR_SIMNOW_SHAKEDOWN_ONLY"
        ),
        "confirmed_by": "research-owner",
        "confirmed_at_utc": "2026-08-31T07:30:00Z",
        "source_month": "2026-08",
        "source_official_day": "2026-08-31",
        "execution_day": "2026-09-01",
        "input_cutoff_at_utc": "2026-08-31T07:00:00Z",
        "snapshot_created_at_utc": "2026-09-01T02:00:00Z",
        "expires_at_utc": "2026-09-01T14:00:00Z",
        "previous_snapshot_hash": None,
        "evidence_files": evidence_rows,
        "targets": source["targets"],
        "signer_key_id": "c-fast-research-1",
    }
    payload["bundle_checksum"] = research_bundle_checksum(payload)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")
    return bundle_path, evidence_root, payload


def produce(tmp_path: Path) -> tuple[
    CommodityCFastSimNowResearchBundleDTO,
    CommodityCFastShadowDTO,
]:
    bundle_path, evidence_root, _ = make_bundle(tmp_path)
    bundle = load_research_bundle(bundle_path)
    manifest_hash = verify_evidence_files(bundle, evidence_root)
    return bundle, produce_unsigned_snapshot(
        bundle,
        evidence_manifest_sha256=manifest_hash,
    )


def test_producer_binds_human_bundle_and_evidence(tmp_path: Path) -> None:
    bundle, snapshot = produce(tmp_path)

    assert snapshot.execution_lane == "simnow_shakedown"
    assert snapshot.countable_forward is False
    assert snapshot.production_allowed is False
    assert snapshot.research_bindings.research_input_bundle_sha256 == (
        bundle.bundle_checksum
    )
    assert snapshot.research_bindings.snapshot_producer_status == (
        "IMPLEMENTED_HUMAN_CONFIRMED_SIMNOW_RESEARCH_BUNDLE_V1"
    )


def test_bundle_checksum_tamper_fails_closed(tmp_path: Path) -> None:
    bundle_path, _, payload = make_bundle(tmp_path)
    payload["targets"][0]["target_quantity"] += 1
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        CFastResearchBundleInvalidError,
        match="BUNDLE_CHECKSUM_MISMATCH",
    ):
        load_research_bundle(bundle_path)


def test_unknown_bundle_field_fails_closed(tmp_path: Path) -> None:
    bundle_path, _, payload = make_bundle(tmp_path)
    payload["unreviewed_override"] = True
    payload["bundle_checksum"] = research_bundle_checksum(payload)
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        CFastResearchBundleInvalidError,
        match="BUNDLE_SCHEMA_INVALID",
    ):
        load_research_bundle(bundle_path)


def test_evidence_hash_tamper_fails_closed(tmp_path: Path) -> None:
    bundle_path, evidence_root, _ = make_bundle(tmp_path)
    bundle = load_research_bundle(bundle_path)
    (evidence_root / "allocation_evidence.json").write_bytes(b"tampered")

    with pytest.raises(
        CFastResearchBundleInvalidError,
        match="EVIDENCE_FILE_HASH_MISMATCH",
    ):
        verify_evidence_files(bundle, evidence_root)


def test_reference_price_must_bind_evidence_file(tmp_path: Path) -> None:
    bundle_path, evidence_root, payload = make_bundle(tmp_path)
    payload["targets"][0]["reference_price_source_sha256"] = "f" * 64
    payload["bundle_checksum"] = research_bundle_checksum(payload)
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_research_bundle(bundle_path)

    with pytest.raises(
        CFastResearchBundleInvalidError,
        match="REFERENCE_PRICE_EVIDENCE_UNBOUND",
    ):
        verify_evidence_files(bundle, evidence_root)


def test_signed_shakedown_snapshot_accepts_and_persists_lane(
    tmp_path: Path,
) -> None:
    _, snapshot = produce(tmp_path)
    private_key = make_key()
    signed, _ = sign_payload(
        snapshot.model_dump(mode="json", exclude={"signature"}),
        private_key,
    )
    snapshot_path = tmp_path / "signed.json"
    snapshot_path.write_text(json.dumps(signed), encoding="utf-8")
    service = CommodityCFastShadowService(
        settings=Settings(
            commodity_c_fast_shadow_enabled=True,
            commodity_c_fast_shadow_snapshot_path=str(snapshot_path),
            commodity_c_fast_shadow_state_path=str(tmp_path / "state.json"),
            commodity_c_fast_shadow_evidence_path=str(
                tmp_path / "reload.jsonl"
            ),
            commodity_c_fast_shadow_trusted_public_keys_json=public_key_json(
                private_key
            ),
        ),
        contract_loader=contract_loader,
        clock=lambda: NOW,
    )

    status = service.reload(
        operator="admin", role="admin", source_ip=None
    )

    assert status["valid"] is True
    assert status["execution_lane"] == "simnow_shakedown"
    assert status["countable_forward"] is False
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["schema_version"] == "commodity_c_fast_shakedown_state_v1"
    assert state["execution_lane"] == "simnow_shakedown"


def test_expired_shakedown_snapshot_fails_closed(tmp_path: Path) -> None:
    _, snapshot = produce(tmp_path)
    private_key = make_key()
    signed, _ = sign_payload(
        snapshot.model_dump(mode="json", exclude={"signature"}),
        private_key,
    )
    snapshot_path = tmp_path / "signed.json"
    snapshot_path.write_text(json.dumps(signed), encoding="utf-8")
    service = CommodityCFastShadowService(
        settings=Settings(
            commodity_c_fast_shadow_enabled=False,
            commodity_c_fast_shadow_snapshot_path=str(snapshot_path),
            commodity_c_fast_shadow_trusted_public_keys_json=public_key_json(
                private_key
            ),
        ),
        contract_loader=contract_loader,
        clock=lambda: datetime(2026, 9, 1, 14, tzinfo=timezone.utc),
    )

    status = service.reload(
        operator="admin", role="admin", source_ip=None
    )

    assert status["valid"] is False
    assert status["error_code"] == "SHAKEDOWN_SNAPSHOT_EXPIRED"


def test_bundle_target_tamper_with_recomputed_checksum_hits_formula_gate(
    tmp_path: Path,
) -> None:
    bundle_path, evidence_root, payload = make_bundle(tmp_path)
    payload["targets"][0]["raw_risk_score"] += 0.01
    payload["bundle_checksum"] = research_bundle_checksum(payload)
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_research_bundle(bundle_path)
    manifest_hash = verify_evidence_files(bundle, evidence_root)

    with pytest.raises(
        CFastResearchBundleInvalidError,
        match="RAW_RISK_SCORE_MISMATCH",
    ):
        produce_unsigned_snapshot(
            bundle,
            evidence_manifest_sha256=manifest_hash,
        )
