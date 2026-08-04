from dataclasses import replace

import pytest
from app.core.errors import CommoditySimNowSafetyError
from app.services.commodity_c_fast_continuous_runtime import (
    ContinuousDecision,
    completed_snapshot_outcome,
    resolve_continuous_authority,
    restart_outcome,
)
from test_commodity_c_fast_runtime_authorization import (
    ACCOUNT_SHA256,
    _authority_fixture,
)
from test_commodity_c_fast_simnow import prepare_c_fast_shakedown


def complete_session() -> dict[str, str]:
    return {
        "status": "COMPLETE",
        "source_snapshot_id": "snapshot-2026-08",
        "source_snapshot_hash": "a" * 64,
    }


def test_completed_snapshot_is_recognised_without_authority_artifacts() -> None:
    result = completed_snapshot_outcome(
        complete_session(),
        snapshot_id="snapshot-2026-08",
        snapshot_sha256="a" * 64,
    )

    assert result.decision == ContinuousDecision.ALREADY_COMPLETED
    assert result.reason == "snapshot_already_completed"


def test_partial_snapshot_identity_match_is_hard_drift() -> None:
    result = completed_snapshot_outcome(
        complete_session(),
        snapshot_id="snapshot-2026-08",
        snapshot_sha256="b" * 64,
    )

    assert result.decision == ContinuousDecision.HARD_REVOKE
    assert result.reason == "snapshot_identity_hash_inconsistent"


def test_new_snapshot_requires_full_verification() -> None:
    result = completed_snapshot_outcome(
        complete_session(),
        snapshot_id="snapshot-2026-09",
        snapshot_sha256="b" * 64,
    )

    assert result.decision == ContinuousDecision.VERIFY_NEW_SNAPSHOT


def test_crash_with_active_plan_never_creates_a_new_plan() -> None:
    result = restart_outcome(
        active_plan_status="OPEN_SUBMITTED",
        runtime_authorization_state="ACTIVE",
        planned_shutdown_marker=False,
    )

    assert result.decision == ContinuousDecision.RECOVERY_REQUIRED


def test_planned_restart_restores_only_after_full_preflight() -> None:
    result = restart_outcome(
        active_plan_status=None,
        runtime_authorization_state="ACTIVE",
        planned_shutdown_marker=True,
    )

    assert result.decision == ContinuousDecision.RESTORE_AFTER_PREFLIGHT
    assert result.reason == "planned_restart_requires_full_preflight"


def test_revoked_authorization_does_not_restore_on_restart() -> None:
    result = restart_outcome(
        active_plan_status=None,
        runtime_authorization_state="REVOKED",
        planned_shutdown_marker=True,
    )

    assert result.decision == ContinuousDecision.WAITING


def test_runtime_snapshot_never_loads_or_consumes_legacy_permit(
    tmp_path,
) -> None:
    service, snapshot, snapshot_sha256 = _authority_fixture(tmp_path)
    service.enable(
        authorized_by="admin",
        reason="approved continuous SimNow runtime",
    )
    permit_calls = 0

    def forbidden_permit(*_args):
        nonlocal permit_calls
        permit_calls += 1
        raise AssertionError("runtime snapshot must not load legacy permit")

    resolved = resolve_continuous_authority(
        snapshot=snapshot,
        snapshot_sha256=snapshot_sha256,
        actual_account_sha256=ACCOUNT_SHA256,
        selected_products=["ag"],
        runtime_authorization=service,
        legacy_permit_provider=forbidden_permit,
    )

    assert resolved.mode == "RUNTIME_AUTHORIZATION"
    assert resolved.legacy_permit is None
    assert permit_calls == 0


def test_runtime_preview_start_persists_three_ids_without_permit(
    tmp_path,
    monkeypatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    authority_root = tmp_path / "runtime-authority"
    authority_root.mkdir(mode=0o700)
    core, snapshot, snapshot_sha256 = _authority_fixture(authority_root)
    core.enable(
        authorized_by="admin",
        reason="approved continuous SimNow runtime",
    )
    verified = core.verify_snapshot(
        snapshot=snapshot,
        snapshot_sha256=snapshot_sha256,
        actual_account_sha256=ACCOUNT_SHA256,
        selected_products=["ag"],
        snapshot_signature_verified=True,
    )

    class BoundRuntimeAuthority:
        def verify_snapshot(self, **_kwargs):
            return verified

        def status(self):
            return {"state": "ACTIVE", "max_child_order_lots": 100}

    service.c_fast_runtime_authorization = BoundRuntimeAuthority()
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_sha256)
    )
    service._c_fast_execution_permit_provider = None
    monkeypatch.setattr(
        service,
        "_consume_c_fast_execution_permit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("runtime path consumed legacy permit")
        ),
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert preview["execution_authority_mode"] == "RUNTIME_AUTHORIZATION"
    assert service.current_plan is not None
    assert service.current_plan["runtime_authorization_id"] == (
        verified.authorization.authorization_id
    )
    assert service.current_plan["map_acceptance_id"] == (
        verified.map_acceptance.acceptance_id
    )
    assert service.current_plan["c_fast_allocation_acceptance_id"] == (
        verified.allocation_acceptance.acceptance_id
    )
    assert service.current_plan["execution_permit_id"] is None


def test_runtime_start_rejects_authorization_changed_after_preview(
    tmp_path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    authority_root = tmp_path / "runtime-authority-change"
    authority_root.mkdir(mode=0o700)
    core, snapshot, snapshot_sha256 = _authority_fixture(authority_root)
    core.enable(
        authorized_by="admin",
        reason="approved continuous SimNow runtime",
    )
    verified = core.verify_snapshot(
        snapshot=snapshot,
        snapshot_sha256=snapshot_sha256,
        actual_account_sha256=ACCOUNT_SHA256,
        selected_products=["ag"],
        snapshot_signature_verified=True,
    )
    changed = replace(
        verified,
        authorization=verified.authorization.model_copy(
            update={
                "authorization_id": (
                    "commodity-c-fast-runtime-auth-v1-" + "f" * 64
                )
            }
        ),
    )

    class ChangingRuntimeAuthority:
        calls = 0

        def verify_snapshot(self, **_kwargs):
            self.calls += 1
            return verified if self.calls == 1 else changed

        def status(self):
            return {"state": "ACTIVE", "max_child_order_lots": 100}

    service.c_fast_runtime_authorization = ChangingRuntimeAuthority()
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_sha256)
    )
    service._c_fast_execution_permit_provider = None
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]

    with pytest.raises(CommoditySimNowSafetyError, match="preview 后发生变化"):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    assert service.current_plan is None
