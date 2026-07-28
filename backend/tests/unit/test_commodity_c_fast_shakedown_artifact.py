from __future__ import annotations

import base64
import copy
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.core.config import Settings
from app.services.commodity_c_fast_shadow import (
    CFastShadowInvalidError,
    CommodityCFastShadowService,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_commodity_c_fast_shadow import contract_loader, unsigned_payload

SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "scripts"
    / "commodity_c_fast_shakedown_artifact.py"
)
SPEC = importlib.util.spec_from_file_location("cfast_shakedown_artifact", SCRIPT)
assert SPEC and SPEC.loader
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)

NOW = datetime(2026, 9, 1, 2, tzinfo=timezone.utc)
ACCOUNT_HASH = "9" * 64


def key_entry(key: Ed25519PrivateKey, purpose: str) -> dict[str, str]:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "public_key_base64": base64.b64encode(raw).decode(),
        "purpose": purpose,
    }


def research_bundle() -> dict:
    # Synthetic test fixture only; producer assertion tests must never be
    # reused as runtime Research evidence.
    snapshot = unsigned_payload(
        snapshot_id="c-fast-shakedown-20260901",
        source_month="2026-09",
        source_day="2026-09-01",
        execution_day="2026-09-01",
        input_cutoff="2026-09-01T00:30:00Z",
    )
    snapshot["snapshot_created_at_utc"] = "2026-09-01T01:02:00Z"
    snapshot["research_observed_at_utc"] = "2026-09-01T01:01:30Z"
    for key in ARTIFACT.PROTECTED_SNAPSHOT_KEYS:
        snapshot.pop(key, None)
    for key in (
        "snapshot_producer_status",
        "producer_sha256",
        "input_bundle_sha256",
    ):
        snapshot["research_bindings"].pop(key, None)
    return {
        "schema_version": "commodity_c_fast_simnow_research_input_v1",
        "human_confirmed": True,
        "reviewer_assertion":
        "REAL_RESEARCH_INPUT_NOT_FIXTURE_NOT_EXECUTION_DERIVED",
        "evidence": [
            {
                "name": "research-manifest.json",
                "kind": "research_manifest",
                "sha256": "1" * 64,
            },
            {
                "name": "allocation.json",
                "kind": "allocation",
                "sha256": "2" * 64,
            },
            {
                "name": "daily-roll.json",
                "kind": "daily_roll",
                "sha256": "3" * 64,
            },
            {
                "name": "official-open.json",
                "kind": "reference_price",
                "sha256": "4" * 64,
            },
        ],
        "snapshot": snapshot,
    }


def signed_artifact(
    research_key: Ed25519PrivateKey,
    control_key: Ed25519PrivateKey,
) -> dict:
    core = ARTIFACT.produce(research_bundle())
    research = ARTIFACT.sign_research(core, research_key)
    return ARTIFACT.issue_permit(
        research,
        research_public_key=research_key.public_key(),
        control_private_key=control_key,
        acceptance_id="cfast-accept-20260901a",
        permit_id="cfast-permit-20260901a",
        account_sha256=ACCOUNT_HASH,
        accepted_at="2026-09-01T01:03:00Z",
        expires_at="2026-09-01T03:00:00Z",
        max_selected_products=1,
        control_signer_key_id="c-fast-control-1",
    )


def service(
    tmp_path: Path,
    payload: dict,
    research_key: Ed25519PrivateKey,
    control_key: Ed25519PrivateKey,
    *,
    now: datetime = NOW,
) -> CommodityCFastShadowService:
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps(payload), encoding="utf-8")
    settings = Settings(
        commodity_simnow_enabled=True,
        commodity_c_fast_shadow_enabled=True,
        commodity_c_fast_shadow_snapshot_path=str(snapshot),
        commodity_c_fast_shadow_state_path=str(tmp_path / "state.json"),
        commodity_c_fast_shadow_evidence_path=str(tmp_path / "evidence.jsonl"),
        commodity_c_fast_simnow_shakedown_enabled=True,
        commodity_c_fast_simnow_account_hashes=ACCOUNT_HASH,
        commodity_c_fast_shadow_trusted_public_keys_json=json.dumps(
            {
                "c-fast-research-1": key_entry(
                    research_key, "research_snapshot_signer"
                ),
                "c-fast-control-1": key_entry(
                    control_key, "simnow_shakedown_control_signer"
                ),
            }
        ),
    )
    return CommodityCFastShadowService(
        settings=settings,
        contract_loader=contract_loader,
        clock=lambda: now,
    )


def test_produce_sign_permit_reload_and_runtime_read(
    tmp_path: Path,
) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = signed_artifact(research_key, control_key)
    instance = service(tmp_path, payload, research_key, control_key)

    result = instance.reload(operator="admin", role="admin", source_ip=None)
    snapshot, snapshot_hash = instance.accepted_snapshot_for_control()

    assert result["valid"] is True
    assert result["execution_lane"] == "simnow_shakedown"
    assert snapshot.account_sha256 == ACCOUNT_HASH
    assert snapshot.max_selected_products == 1
    assert snapshot_hash == result["snapshot_hash"]


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda value: value["targets"][0].update(
                {"target_quantity": value["targets"][0]["target_quantity"] + 1}
            ),
            "SHAKEDOWN_SIGNATURE_INVALID",
        ),
        (
            lambda value: value.update({"account_sha256": "8" * 64}),
            "SHAKEDOWN_SIGNATURE_INVALID",
        ),
        (
            lambda value: value.update({"signature": base64.b64encode(bytes(64)).decode()}),
            "SHAKEDOWN_SIGNATURE_INVALID",
        ),
    ],
)
def test_tamper_fails_closed(tmp_path: Path, mutator, error: str) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = copy.deepcopy(signed_artifact(research_key, control_key))
    mutator(payload)
    result = service(tmp_path, payload, research_key, control_key).reload(
        operator="admin", role="admin", source_ip=None
    )
    assert result["valid"] is False
    assert result["error_code"] == error


def test_expired_permit_and_wrong_allowlist_fail_closed(tmp_path: Path) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = signed_artifact(research_key, control_key)
    expired = service(
        tmp_path,
        payload,
        research_key,
        control_key,
        now=datetime(2026, 9, 1, 4, tzinfo=timezone.utc),
    ).reload(operator="admin", role="admin", source_ip=None)
    assert expired["error_code"] == "EXECUTION_PERMIT_EXPIRED"


def test_same_day_successor_is_replay_rejected(tmp_path: Path) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    first = signed_artifact(research_key, control_key)
    instance = service(tmp_path, first, research_key, control_key)
    accepted = instance.reload(operator="admin", role="admin", source_ip=None)
    assert accepted["valid"] is True

    bundle = research_bundle()
    bundle["snapshot"]["snapshot_id"] = "c-fast-shakedown-20260901-replay"
    bundle["snapshot"]["previous_snapshot_hash"] = accepted["snapshot_hash"]
    for row in bundle["snapshot"]["targets"]:
        row["previous_exact_contract"] = row["exact_contract"]
        row["previous_target_quantity"] = row["target_quantity"]
    core = ARTIFACT.produce(bundle)
    research = ARTIFACT.sign_research(core, research_key)
    replay = ARTIFACT.issue_permit(
        research,
        research_public_key=research_key.public_key(),
        control_private_key=control_key,
        acceptance_id="cfast-accept-20260901b",
        permit_id="cfast-permit-20260901b",
        account_sha256=ACCOUNT_HASH,
        accepted_at="2026-09-01T01:04:00Z",
        expires_at="2026-09-01T03:00:00Z",
        max_selected_products=1,
        control_signer_key_id="c-fast-control-1",
    )
    snapshot_path = Path(
        instance.settings.commodity_c_fast_shadow_snapshot_path
    )
    snapshot_path.write_text(json.dumps(replay), encoding="utf-8")
    rejected = instance.reload(operator="admin", role="admin", source_ip=None)

    assert rejected["error_code"] == "SNAPSHOT_STALE_OR_REPLAYED"


def test_producer_rejects_missing_evidence_and_owned_fields() -> None:
    missing = research_bundle()
    missing["evidence"] = []
    with pytest.raises(ValueError, match="evidence"):
        ARTIFACT.produce(missing)
    controlled = research_bundle()
    controlled["snapshot"]["account_sha256"] = ACCOUNT_HASH
    with pytest.raises(ValueError, match="producer/control-owned"):
        ARTIFACT.produce(controlled)


def test_installer_is_create_only(tmp_path: Path) -> None:
    target = tmp_path / "installed.json"
    ARTIFACT.write_private_create(target, b"first")
    with pytest.raises(FileExistsError):
        ARTIFACT.write_private_create(target, b"replacement")
    assert target.read_bytes() == b"first"
    assert target.stat().st_mode & 0o077 == 0
