from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.commodity_strategy_identity import (
    commodity_c_fast_allocation_policy_projection,
    commodity_c_fast_allocation_policy_projection_sha256,
    commodity_executable_target_projection_sha256,
    commodity_map_output_contract_sha256,
    commodity_map_strategy_version_projection,
    commodity_map_strategy_version_projection_sha256,
)
from app.core.config import Settings
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastRuntimeExecutableSnapshotDTO,
)
from app.services.commodity_c_fast_runtime_authorization import (
    CommodityCFastRuntimeAuthorizationError,
    CommodityCFastRuntimeAuthorizationService,
    canonical_json,
    sha256_bytes,
)
from app.services.commodity_c_fast_shadow_common import unsigned_snapshot_payload
from app.services.commodity_c_fast_shadow import (
    CFastShadowInvalidError,
    CommodityCFastShadowService,
)
from test_commodity_c_fast_simnow import sign_payload as sign_legacy_snapshot
from test_commodity_c_fast_shadow import sign_payload as sign_shadow_snapshot
from test_commodity_c_fast_shadow import unsigned_payload


NOW = datetime(2026, 9, 1, 2, tzinfo=timezone.utc)
ACCOUNT_SHA256 = "9" * 64
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
ROOT = Path(__file__).resolve().parents[3]


def _public_key(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


def _identity(prefix: str, payload: dict[str, Any], field: str) -> str:
    core = {
        key: value
        for key, value in payload.items()
        if key not in {field, "signature"}
    }
    return prefix + sha256_bytes(canonical_json(core))


def _signed_artifact(
    payload: dict[str, Any],
    *,
    identity_field: str,
    identity_prefix: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result[identity_field] = _identity(identity_prefix, result, identity_field)
    result["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(
                {key: value for key, value in result.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    return result


def _write(path: Path, payload: dict[str, Any]) -> bytes:
    raw = canonical_json(payload) + b"\n"
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _runtime_snapshot_draft() -> CommodityCFastRuntimeExecutableSnapshotDTO:
    payload = unsigned_payload()
    payload.update(
        {
            "schema_version": (
                "commodity_map_c_fast_simnow_executable_target_snapshot_v1"
            ),
            "mode": "simnow_runtime",
            "execution_lane": "simnow_shakedown",
            "countable_forward": False,
            "live_allowed": False,
            "research_observed_at_utc": payload["snapshot_created_at_utc"],
            "map_acceptance_id": f"commodity-map-accept-v1-{'0' * 64}",
            "map_acceptance_raw_sha256": "0" * 64,
            "map_strategy_projection_sha256": "0" * 64,
            "map_signal_artifact_sha256": "3" * 64,
            "c_fast_allocation_acceptance_id": (
                f"commodity-c-fast-allocation-accept-v1-{'0' * 64}"
            ),
            "c_fast_allocation_acceptance_raw_sha256": "0" * 64,
            "c_fast_allocation_projection_sha256": "0" * 64,
            "runtime_selected_products": ["ag"],
            "executable_target_binding_sha256": "0" * 64,
            "signature": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )
    payload["research_bindings"].update(
        {
            "snapshot_producer_status": (
                "IMPLEMENTED_SIGNED_MAP_C_FAST_RUNTIME_V1"
            ),
            "producer_sha256": "1" * 64,
            "input_bundle_sha256": "2" * 64,
        }
    )
    return CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(payload)


def _authority_fixture(
    tmp_path: Path,
    *,
    valid_until: datetime | None = None,
) -> tuple[
    CommodityCFastRuntimeAuthorizationService,
    CommodityCFastRuntimeExecutableSnapshotDTO,
    str,
]:
    map_key = Ed25519PrivateKey.generate()
    allocation_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    snapshot_key = Ed25519PrivateKey.generate()
    keyring = {
        "schema_version": "commodity_c_fast_runtime_authority_trusted_keys_v1",
        "purpose": "commodity_c_fast_runtime_authority_verification",
        "trusted_keys": [
            {
                "key_id": "map-authority-key-v1",
                "public_key_base64": _public_key(map_key),
                "signer_role": "map_strategy_acceptance",
                "reviewer_role": "strategy-reviewer",
            },
            {
                "key_id": "allocation-authority-key-v1",
                "public_key_base64": _public_key(allocation_key),
                "signer_role": "c_fast_allocation_acceptance",
                "reviewer_role": "allocation-reviewer",
            },
            {
                "key_id": "runtime-authority-key-v1",
                "public_key_base64": _public_key(runtime_key),
                "signer_role": "simnow_runtime_authorization",
                "reviewer_role": "runtime-admin",
            },
        ],
    }
    keyring_path = tmp_path / "keyring.json"
    keyring_raw = _write(keyring_path, keyring)

    draft = _runtime_snapshot_draft()
    map_projection = commodity_map_strategy_version_projection(draft)
    allocation_projection = commodity_c_fast_allocation_policy_projection(draft)
    map_acceptance = _signed_artifact(
        {
            "schema_version": "commodity_map_strategy_acceptance_v1",
            "purpose": "commodity_map_strategy_version_acceptance",
            "issued_at": (NOW - timedelta(days=1)).isoformat(),
            "not_before": (NOW - timedelta(hours=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=365)).isoformat(),
            "accepted_by": "strategy-reviewer",
            "reviewer_role": "strategy-reviewer",
            "projection": map_projection,
            "projection_sha256": sha256_bytes(canonical_json(map_projection)),
            "output_to_c_fast_only": True,
            "production_allowed": False,
            "live_allowed": False,
            "countable_forward": False,
            "signer_key_id": "map-authority-key-v1",
        },
        identity_field="acceptance_id",
        identity_prefix="commodity-map-accept-v1-",
        private_key=map_key,
    )
    map_path = tmp_path / "map-acceptance.json"
    map_raw = _write(map_path, map_acceptance)
    allocation_acceptance = _signed_artifact(
        {
            "schema_version": "commodity_c_fast_allocation_acceptance_v1",
            "purpose": "commodity_c_fast_allocation_policy_acceptance",
            "issued_at": (NOW - timedelta(days=1)).isoformat(),
            "not_before": (NOW - timedelta(hours=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=365)).isoformat(),
            "accepted_by": "allocation-reviewer",
            "reviewer_role": "allocation-reviewer",
            "map_strategy_identity": "commodity_fast_tsmom_forward_freeze_v1",
            "map_output_contract_sha256": commodity_map_output_contract_sha256(),
            "projection": allocation_projection,
            "projection_sha256": sha256_bytes(
                canonical_json(allocation_projection)
            ),
            "snapshot_production_allowed": False,
            "live_allowed": False,
            "countable_forward": False,
            "signer_key_id": "allocation-authority-key-v1",
        },
        identity_field="acceptance_id",
        identity_prefix="commodity-c-fast-allocation-accept-v1-",
        private_key=allocation_key,
    )
    allocation_path = tmp_path / "allocation-acceptance.json"
    allocation_raw = _write(allocation_path, allocation_acceptance)
    runtime = _signed_artifact(
        {
            "schema_version": "commodity_c_fast_simnow_runtime_authorization_v1",
            "purpose": "commodity_c_fast_simnow_continuous_runtime_authorization",
            "issued_at": (NOW - timedelta(hours=2)).isoformat(),
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": valid_until.isoformat() if valid_until else None,
            "until_revoked": valid_until is None,
            "authorized_by": "runtime-admin",
            "reviewer_role": "runtime-admin",
            "map_acceptance_id": map_acceptance["acceptance_id"],
            "map_acceptance_raw_sha256": hashlib.sha256(map_raw).hexdigest(),
            "map_strategy_projection_sha256": map_acceptance[
                "projection_sha256"
            ],
            "c_fast_allocation_acceptance_id": allocation_acceptance[
                "acceptance_id"
            ],
            "c_fast_allocation_acceptance_raw_sha256": hashlib.sha256(
                allocation_raw
            ).hexdigest(),
            "c_fast_allocation_projection_sha256": allocation_acceptance[
                "projection_sha256"
            ],
            "expected_simnow_account_sha256": ACCOUNT_SHA256,
            "allowed_products": ["ag", "cu"],
            "max_selected_products": 2,
            "max_child_order_lots": 1,
            "risk_limits": {
                "max_product_abs_weight": 0.15,
                "max_sector_gross_weight": 0.35,
                "max_portfolio_gross_weight": 1.0,
                "max_portfolio_abs_net_weight": 0.1,
            },
            "allowed_execution_lane": "simnow_shakedown",
            "signed_snapshots_only": True,
            "continuous": True,
            "production_allowed": False,
            "live_allowed": False,
            "countable_forward": False,
            "automatic_promotion_allowed": False,
            "signer_key_id": "runtime-authority-key-v1",
        },
        identity_field="authorization_id",
        identity_prefix="commodity-c-fast-runtime-auth-v1-",
        private_key=runtime_key,
    )
    runtime_path = tmp_path / "runtime-authorization.json"
    _write(runtime_path, runtime)
    snapshot_payload = draft.model_dump(mode="json")
    snapshot_payload.update(
        {
            "map_acceptance_id": map_acceptance["acceptance_id"],
            "map_acceptance_raw_sha256": hashlib.sha256(map_raw).hexdigest(),
            "map_strategy_projection_sha256": map_acceptance[
                "projection_sha256"
            ],
            "c_fast_allocation_acceptance_id": allocation_acceptance[
                "acceptance_id"
            ],
            "c_fast_allocation_acceptance_raw_sha256": hashlib.sha256(
                allocation_raw
            ).hexdigest(),
            "c_fast_allocation_projection_sha256": allocation_acceptance[
                "projection_sha256"
            ],
        }
    )
    snapshot = CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(
        snapshot_payload
    )
    snapshot_payload["executable_target_binding_sha256"] = (
        commodity_executable_target_projection_sha256(snapshot)
    )
    snapshot = CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(
        snapshot_payload
    )
    signature = snapshot_key.sign(canonical_json(unsigned_snapshot_payload(snapshot)))
    snapshot = snapshot.model_copy(
        update={"signature": base64.b64encode(signature).decode("ascii")}
    )
    snapshot_sha256 = hashlib.sha256(
        canonical_json(unsigned_snapshot_payload(snapshot))
    ).hexdigest()
    service = CommodityCFastRuntimeAuthorizationService(
        enabled=True,
        clock=lambda: NOW,
        map_acceptance_path=map_path,
        allocation_acceptance_path=allocation_path,
        authorization_path=runtime_path,
        trusted_keyring_path=keyring_path,
        expected_keyring_raw_sha256=hashlib.sha256(keyring_raw).hexdigest(),
        state_dir=tmp_path / "state",
    )
    return service, snapshot, snapshot_sha256


def test_version_projection_excludes_period_outputs() -> None:
    first = _runtime_snapshot_draft()
    payload = first.model_dump(mode="json")
    payload["execution_day"] = "2026-10-01"
    payload["source_month"] = "2026-09"
    payload["targets"][0]["exact_contract"] = "SHFE.ag2702"
    payload["targets"][0]["target_quantity"] += 1
    payload["targets"][0]["previous_target_quantity"] += 1
    second = CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(payload)
    assert commodity_map_strategy_version_projection_sha256(first) == (
        commodity_map_strategy_version_projection_sha256(second)
    )
    assert commodity_c_fast_allocation_policy_projection_sha256(first) == (
        commodity_c_fast_allocation_policy_projection_sha256(second)
    )


def test_projection_changes_for_map_or_allocator_version() -> None:
    snapshot = _runtime_snapshot_draft()
    changed_map = snapshot.model_copy(
        update={
            "research_bindings": snapshot.research_bindings.model_copy(
                update={"producer_sha256": "a" * 64}
            )
        }
    )
    changed_allocation = snapshot.model_copy(
        update={
            "research_bindings": snapshot.research_bindings.model_copy(
                update={"allocator_runner_sha256": "b" * 64}
            )
        }
    )
    assert commodity_map_strategy_version_projection_sha256(snapshot) != (
        commodity_map_strategy_version_projection_sha256(changed_map)
    )
    assert commodity_c_fast_allocation_policy_projection_sha256(snapshot) != (
        commodity_c_fast_allocation_policy_projection_sha256(changed_allocation)
    )


def test_enable_verify_restart_and_revoke_are_persistent(tmp_path: Path) -> None:
    service, snapshot, snapshot_sha256 = _authority_fixture(tmp_path)
    assert service.enable(
        authorized_by="admin", reason="approved continuous SimNow runtime"
    )["state"] == "ACTIVE"
    verified = service.verify_snapshot(
        snapshot=snapshot,
        snapshot_sha256=snapshot_sha256,
        actual_account_sha256=ACCOUNT_SHA256,
        selected_products=["ag"],
        snapshot_signature_verified=True,
    )
    assert verified.authorization.production_allowed is False
    restarted = CommodityCFastRuntimeAuthorizationService(
        enabled=True,
        clock=lambda: NOW,
        map_acceptance_path=service.map_acceptance_path,
        allocation_acceptance_path=service.allocation_acceptance_path,
        authorization_path=service.authorization_path,
        trusted_keyring_path=service.trusted_keyring_path,
        expected_keyring_raw_sha256=service.expected_keyring_raw_sha256,
        state_dir=service.state_dir,
    )
    assert restarted.status()["state"] == "ACTIVE"
    assert restarted.revoke(
        revoked_by="admin", reason="operator revoked runtime"
    )["state"] == "REVOKED"
    assert restarted.status()["state"] == "REVOKED"
    assert len(list(service.state_dir.glob("*.json"))) == 2


def test_snapshot_binding_drift_revokes_before_execution(tmp_path: Path) -> None:
    service, snapshot, snapshot_sha256 = _authority_fixture(tmp_path)
    service.enable(
        authorized_by="admin", reason="approved continuous SimNow runtime"
    )
    tampered = snapshot.model_copy(
        update={"map_signal_artifact_sha256": "f" * 64}
    )
    with pytest.raises(CommodityCFastRuntimeAuthorizationError) as caught:
        service.verify_snapshot(
            snapshot=tampered,
            snapshot_sha256=snapshot_sha256,
            actual_account_sha256=ACCOUNT_SHA256,
            selected_products=["ag"],
            snapshot_signature_verified=True,
        )
    assert caught.value.code == "SNAPSHOT_EXECUTABLE_TARGET_BINDING_INVALID"
    assert service.status()["state"] == "HARD_DRIFT_REVOKED"


def test_missing_artifact_still_persists_hard_revoke(tmp_path: Path) -> None:
    service, _snapshot, _snapshot_sha256 = _authority_fixture(tmp_path)
    service.enable(
        authorized_by="admin", reason="approved continuous SimNow runtime"
    )
    service.map_acceptance_path.unlink()
    status = service.status()
    assert status["state"] == "HARD_DRIFT_REVOKED"
    assert status["reason"] == "MAP_ACCEPTANCE_READ_INVALID"
    assert len(list(service.state_dir.glob("*.json"))) == 2


def test_expiry_auto_revokes_and_survives_restart(tmp_path: Path) -> None:
    service, _snapshot, _snapshot_sha256 = _authority_fixture(
        tmp_path, valid_until=NOW + timedelta(minutes=1)
    )
    service.enable(
        authorized_by="admin", reason="approved bounded SimNow runtime"
    )
    service.clock = lambda: NOW + timedelta(minutes=2)
    assert service.status()["state"] == "EXPIRED"
    assert service.status()["state"] == "EXPIRED"
    assert len(list(service.state_dir.glob("*.json"))) == 2


def test_keyring_pin_mismatch_is_fail_closed(tmp_path: Path) -> None:
    service, _snapshot, _snapshot_sha256 = _authority_fixture(tmp_path)
    service.expected_keyring_raw_sha256 = "0" * 64
    with pytest.raises(CommodityCFastRuntimeAuthorizationError) as caught:
        service.enable(
            authorized_by="admin", reason="approved continuous SimNow runtime"
        )
    assert caught.value.code == "RUNTIME_AUTHORIZATION_KEYRING_PIN_MISMATCH"
    assert not service.state_dir.exists()


def test_runtime_authority_key_cannot_reuse_research_domain(tmp_path: Path) -> None:
    service, _snapshot, _snapshot_sha256 = _authority_fixture(tmp_path)
    keyring = json.loads(service.trusted_keyring_path.read_text(encoding="utf-8"))
    encoded = keyring["trusted_keys"][0]["public_key_base64"]
    service.settings.commodity_c_fast_shadow_trusted_public_keys_json = json.dumps(
        {
            "research-snapshot-key": {
                "public_key_base64": encoded,
                "purpose": "research_snapshot_signer",
            }
        }
    )
    with pytest.raises(CommodityCFastRuntimeAuthorizationError) as caught:
        service.enable(
            authorized_by="admin", reason="approved continuous SimNow runtime"
        )
    assert caught.value.code == "RUNTIME_AUTHORIZATION_KEY_DOMAIN_COLLISION"


@pytest.mark.parametrize(
    ("account", "products", "expected_code"),
    [
        ("8" * 64, ["ag"], "RUNTIME_AUTHORIZATION_ACCOUNT_DRIFT"),
        (ACCOUNT_SHA256, ["rb"], "RUNTIME_AUTHORIZATION_PRODUCT_SCOPE_DRIFT"),
    ],
)
def test_account_or_product_drift_durably_revokes(
    tmp_path: Path,
    account: str,
    products: list[str],
    expected_code: str,
) -> None:
    service, snapshot, snapshot_sha256 = _authority_fixture(tmp_path)
    service.enable(
        authorized_by="admin", reason="approved continuous SimNow runtime"
    )
    with pytest.raises(CommodityCFastRuntimeAuthorizationError) as caught:
        service.verify_snapshot(
            snapshot=snapshot,
            snapshot_sha256=snapshot_sha256,
            actual_account_sha256=account,
            selected_products=products,
            snapshot_signature_verified=True,
        )
    assert caught.value.code == expected_code
    assert service.status()["state"] == "HARD_DRIFT_REVOKED"


def test_owner_only_state_directory_is_required(tmp_path: Path) -> None:
    service, _snapshot, _snapshot_sha256 = _authority_fixture(tmp_path)
    service.state_dir.mkdir()
    service.state_dir.chmod(0o777)
    with pytest.raises(CommodityCFastRuntimeAuthorizationError) as caught:
        service.enable(
            authorized_by="admin", reason="approved continuous SimNow runtime"
        )
    assert caught.value.code == "RUNTIME_AUTHORIZATION_STATE_DIR_INVALID"


def test_runtime_snapshot_uses_single_research_signature_and_loader(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    snapshot = _runtime_snapshot_draft()
    signature = private.sign(canonical_json(unsigned_snapshot_payload(snapshot)))
    snapshot = snapshot.model_copy(
        update={"signature": base64.b64encode(signature).decode("ascii")}
    )
    path = tmp_path / "runtime-snapshot.json"
    path.write_text(json.dumps(snapshot.model_dump(mode="json")), encoding="utf-8")
    loaded = CommodityCFastShadowService._load_snapshot(path)
    assert isinstance(loaded, CommodityCFastRuntimeExecutableSnapshotDTO)
    service = object.__new__(CommodityCFastShadowService)
    service.settings = Settings.model_construct(
        commodity_c_fast_shadow_trusted_public_keys_json=json.dumps(
            {
                snapshot.signer_key_id: {
                    "public_key_base64": _public_key(private),
                    "purpose": "research_snapshot_signer",
                }
            }
        )
    )
    service._verify_signature(loaded)
    with pytest.raises(CFastShadowInvalidError) as caught:
        service._verify_signature(
            loaded.model_copy(update={"signature": PLACEHOLDER_SIGNATURE})
        )
    assert caught.value.code == "SIGNATURE_INVALID"


def test_legacy_snapshot_is_not_runtime_authority_input(tmp_path: Path) -> None:
    service, _snapshot, snapshot_sha256 = _authority_fixture(tmp_path)
    service.enable(
        authorized_by="admin", reason="approved continuous SimNow runtime"
    )
    private = Ed25519PrivateKey.generate()
    legacy_payload, _legacy_hash = sign_legacy_snapshot(
        unsigned_payload(), private
    )
    from app.schemas.commodity_c_fast_shadow import (
        CommodityCFastShakedownSnapshotDTO,
    )

    legacy = CommodityCFastShakedownSnapshotDTO.model_validate(legacy_payload)
    with pytest.raises(CommodityCFastRuntimeAuthorizationError) as caught:
        service.verify_snapshot(
            snapshot=legacy,  # type: ignore[arg-type]
            snapshot_sha256=snapshot_sha256,
            actual_account_sha256=ACCOUNT_SHA256,
            selected_products=["ag"],
            snapshot_signature_verified=True,
        )
    assert caught.value.code == "RUNTIME_SNAPSHOT_SCHEMA_REQUIRED"
    assert service.status()["state"] == "HARD_DRIFT_REVOKED"


def test_explicit_binding_tool_does_not_enable_authority(tmp_path: Path) -> None:
    service, _snapshot, _snapshot_sha256 = _authority_fixture(tmp_path)
    source_key = Ed25519PrivateKey.generate()
    source_payload, _ = sign_shadow_snapshot(unsigned_payload(), source_key)
    source_raw = canonical_json(source_payload) + b"\n"
    spec = importlib.util.spec_from_file_location(
        "commodity_c_fast_runtime_snapshot_test",
        ROOT / "scripts" / "commodity_c_fast_runtime_snapshot.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    runtime = module.build_runtime_snapshot(
        source_payload=source_payload,
        source_raw=source_raw,
        private_key=source_key,
        signer_key_id="c-fast-research-1",
        producer_sha256="1" * 64,
        map_signal_artifact_sha256="3" * 64,
        selected_products=["ag"],
        authority=service,
    )
    assert runtime.schema_version == (
        "commodity_map_c_fast_simnow_executable_target_snapshot_v1"
    )
    assert runtime.production_allowed is False
    assert runtime.live_allowed is False
    assert service.status()["state"] == "NOT_ENABLED"


def _migration_module():
    spec = importlib.util.spec_from_file_location(
        "commodity_c_fast_runtime_migration_preflight_test",
        ROOT / "scripts" / "commodity_c_fast_runtime_migration_preflight.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _terminal_session(module) -> dict[str, Any]:
    execution_core = {
        "schema_version": "commodity_c_fast_execution_v1",
        "available": True,
        "orders": [],
        "reconciliation": {
            "matched": True,
            "active_order_ids": [],
            "expected_positions": {"SHFE.ag2612": 1},
            "observed_positions": {"SHFE.ag2612": 1},
        },
    }
    execution = {
        **execution_core,
        "state_checksum": module.sha256_json(execution_core),
    }
    session = {
        "schema_version": "commodity_c_fast_shakedown_session_v1",
        "session_id": "cfast-shakedown-0123456789abcdef0123456789abcdef",
        "status": "COMPLETE",
        "completed_at_utc": NOW.isoformat(),
        "execution": execution,
        "previous_terminal_checksum": None,
        "account_hash": ACCOUNT_SHA256,
        "source_snapshot_hash": "7" * 64,
    }
    plan_core = {
        key: value
        for key, value in session.items()
        if key
        not in {
            "schema_version",
            "plan_hash",
            "status",
            "started_by",
            "previewed_at_utc",
            "completed_at_utc",
            "execution",
            "terminal_checksum",
            "continuous_authorized",
        }
    }
    session["plan_hash"] = module.sha256_json(plan_core)
    session["terminal_checksum"] = module.sha256_json(
        {
            "session_id": session["session_id"],
            "plan_hash": session["plan_hash"],
            "status": session["status"],
            "completed_at_utc": session["completed_at_utc"],
            "execution_state_checksum": execution["state_checksum"],
        }
    )
    return session


def test_migration_preflight_is_eligible_but_never_enables(tmp_path: Path) -> None:
    module = _migration_module()
    session = _terminal_session(module)
    archive_dir = tmp_path / "sessions"
    archive_dir.mkdir()
    (archive_dir / f"{session['session_id']}.json").write_text(
        json.dumps(session), encoding="utf-8"
    )
    report = module.migration_preflight(
        terminal_pointer=copy.deepcopy(session),
        archive_dir=archive_dir,
        live_facts={
            "account_sha256": ACCOUNT_SHA256,
            "active_orders": [],
            "positions": {"SHFE.ag2612": 1},
        },
        expected_account_sha256=ACCOUNT_SHA256,
    )
    assert report["eligible"] is True
    assert report["automatic_enable"] is False
    assert report["archive_chain_length"] == 1


def test_migration_preflight_blocks_position_or_order_drift(tmp_path: Path) -> None:
    module = _migration_module()
    session = _terminal_session(module)
    archive_dir = tmp_path / "sessions"
    archive_dir.mkdir()
    (archive_dir / f"{session['session_id']}.json").write_text(
        json.dumps(session), encoding="utf-8"
    )
    report = module.migration_preflight(
        terminal_pointer=session,
        archive_dir=archive_dir,
        live_facts={
            "account_sha256": ACCOUNT_SHA256,
            "active_orders": [{"vt_orderid": "CTP.external"}],
            "positions": {},
        },
        expected_account_sha256=ACCOUNT_SHA256,
    )
    assert report["eligible"] is False
    assert "ACTIVE_ORDERS_NOT_ZERO" in report["blockers"]
    assert "POSITION_RECONCILIATION_MISMATCH" in report["blockers"]
