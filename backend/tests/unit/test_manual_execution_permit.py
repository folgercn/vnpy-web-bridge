from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, RLock
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import (
    ManualExecutionPermitError,
    ManualExecutionPermitReplayError,
)
from app.schemas.manual_execution_permit import (
    ManualExecutionPermitDTO,
    ManualOrderSubmissionDTO,
    canonical_json,
    derived_manual_permit_id,
    unsigned_manual_permit_payload,
)
from app.services.audit_service import AuditService
from app.services.manual_execution_permit import ManualExecutionPermitService
from app.services.trade_service import TradeService, _ManualExecutionCapability


NOW = datetime(2026, 8, 2, 1, 0, tzinfo=timezone.utc)
ACCOUNT_ID = "synthetic-manual-simnow-account"
ACCOUNT_SHA256 = hashlib.sha256(ACCOUNT_ID.encode()).hexdigest()


class FakeRpc:
    def __init__(self) -> None:
        self._call_lock = RLock()
        self.accounts = [
            {
                "accountid": ACCOUNT_ID,
                "gateway_name": "CTP",
            }
        ]
        self.send_attempts = 0
        self.guard_calls = 0
        self.fail_unknown = False
        self.before_guard: Any = None

    def get_accounts(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.accounts]

    def send_order_guarded(
        self,
        order_request: object,
        gateway_name: str,
        guard: Any,
        *,
        linearization_lock: object | None = None,
    ) -> str:
        assert linearization_lock is None
        with self._call_lock:
            if self.before_guard is not None:
                self.before_guard()
            self.guard_calls += 1
            guard()
            self.send_attempts += 1
            if self.fail_unknown:
                raise TimeoutError("outcome unknown")
            return "CTP.manual-1"


class FakeRisk:
    def __init__(self) -> None:
        self.calls = 0
        self.mutate: Any = None

    def check_order(self, payload: Any) -> None:
        self.calls += 1
        if self.mutate is not None:
            self.mutate(payload)


def public_material(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def build_service(
    tmp_path: Path,
    *,
    now: datetime = NOW,
    private: Ed25519PrivateKey | None = None,
) -> tuple[
    ManualExecutionPermitService,
    FakeRpc,
    FakeRisk,
    Ed25519PrivateKey,
]:
    signing_key = private or Ed25519PrivateKey.generate()
    encoded = base64.b64encode(public_material(signing_key)).decode("ascii")
    settings = Settings(
        web_trade_enabled=True,
        order_confirm_required=True,
        default_gateway_name="CTP",
        vnpy_gateway_name="CTP",
        manual_execution_permit_enabled=True,
        manual_execution_permit_trusted_public_keys_json=(
            '{"manual-human-v1":{"public_key_base64":"'
            + encoded
            + '","purpose":"manual_execution_permit_signer"}}'
        ),
        manual_execution_permit_account_hashes=ACCOUNT_SHA256,
        manual_execution_permit_consume_root=str(tmp_path / "consumed"),
    )
    rpc = FakeRpc()
    risk = FakeRisk()
    owner = object.__new__(ManualExecutionPermitService)
    trade = TradeService(
        settings=settings,
        audit=AuditService(tmp_path / "audit.log"),
        risk=risk,  # type: ignore[arg-type]
        rpc=rpc,  # type: ignore[arg-type]
        _manual_execution_capability_issuers=(owner,),
    )
    ManualExecutionPermitService.__init__(
        owner,
        settings=settings,
        trade=trade,
        rpc=rpc,  # type: ignore[arg-type]
        clock=lambda: now,
    )
    return owner, rpc, risk, signing_key


def signed_submission(
    private: Ed25519PrivateKey,
    *,
    operator: str = "alice",
    account_sha256: str = ACCOUNT_SHA256,
    gateway_name: str | None = "CTP",
    resolved_gateway_name: str = "CTP",
    price: float = 3000,
    volume: int = 1,
    nonce: str = "nonce-manual-0001",
    expires_at: datetime | None = None,
) -> ManualOrderSubmissionDTO:
    order = {
        "symbol": "rb2610",
        "exchange": "SHFE",
        "direction": "long",
        "offset": "open",
        "type": "limit",
        "price": price,
        "volume": volume,
        "gateway_name": gateway_name,
        "reference": "manual:alice:rb2610:0001",
        "confirm": True,
    }
    payload: dict[str, Any] = {
        "schema_version": "manual_execution_permit_v1",
        "purpose": "manual_order_one_shot_execution_permit",
        "permit_id": "manual-execution-permit-v1-" + "0" * 64,
        "nonce": nonce,
        "issued_at_utc": NOW.isoformat().replace("+00:00", "Z"),
        "not_before_utc": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (
            expires_at or NOW + timedelta(minutes=2)
        ).isoformat().replace("+00:00", "Z"),
        "execution_environment": "SIMNOW",
        "account_sha256": account_sha256,
        "operator": operator,
        "order": order,
        "resolved_gateway_name": resolved_gateway_name,
        "signer_key_id": "manual-human-v1",
        "human_issued": True,
        "manual_order_authorized": True,
        "one_shot": True,
        "replay_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "automatic_dispatch_authorized": False,
        "c_fast_authority_reused": False,
        "signature": base64.b64encode(b"0" * 64).decode("ascii"),
    }
    unsigned = ManualExecutionPermitDTO.model_validate(payload)
    payload = unsigned.model_dump(mode="json")
    payload["permit_id"] = derived_manual_permit_id(unsigned)
    unsigned = ManualExecutionPermitDTO.model_validate(payload)
    payload["signature"] = base64.b64encode(
        private.sign(canonical_json(unsigned_manual_permit_payload(unsigned)))
    ).decode("ascii")
    permit = ManualExecutionPermitDTO.model_validate(payload)
    return ManualOrderSubmissionDTO.model_validate(
        {"order": order, "execution_permit": permit}
    )


def test_valid_manual_permit_is_consumed_and_sent_once(tmp_path: Path) -> None:
    service, rpc, risk, private = build_service(tmp_path)
    submission = signed_submission(private)

    result = service.submit(submission, operator="alice")

    assert result == {"vt_orderid": "CTP.manual-1", "accepted": True}
    assert risk.calls == 1
    assert rpc.guard_calls == 1
    assert rpc.send_attempts == 1
    markers = list((tmp_path / "consumed").glob("*.consumed.json"))
    assert len(markers) == 1
    assert markers[0].stat().st_mode & 0o777 == 0o600
    assert b'"automatic_dispatch_authorized":false' in markers[0].read_bytes()


@pytest.mark.parametrize(
    "mutation",
    (
        lambda body: setattr(body.execution_permit, "operator", "mallory"),
        lambda body: setattr(body.execution_permit.order, "price", 3001),
    ),
)
def test_frozen_schema_prevents_in_memory_permit_tamper(
    tmp_path: Path,
    mutation: Any,
) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)

    with pytest.raises(ValidationError):
        mutation(submission)

    assert rpc.send_attempts == 0


def test_signature_and_request_tamper_fail_before_consume(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)
    raw = submission.model_dump(mode="python")
    raw["order"]["price"] = 3001
    tampered = ManualOrderSubmissionDTO.model_validate(raw)

    with pytest.raises(ManualExecutionPermitError):
        service.submit(tampered, operator="alice")

    assert rpc.send_attempts == 0
    assert list((tmp_path / "consumed").glob("*")) == []


def test_signature_tamper_fails_before_consume(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    raw = signed_submission(private).model_dump(mode="python")
    raw["execution_permit"]["signature"] = base64.b64encode(
        b"1" * 64
    ).decode("ascii")
    tampered = ManualOrderSubmissionDTO.model_validate(raw)

    with pytest.raises(ManualExecutionPermitError) as caught:
        service.submit(tampered, operator="alice")

    assert caught.value.detail["reason"] == "MANUAL_EXECUTION_SIGNATURE_INVALID"
    assert rpc.send_attempts == 0
    assert list((tmp_path / "consumed").glob("*")) == []


@pytest.mark.parametrize(
    "case",
    ("operator", "account", "gateway", "expired"),
)
def test_scope_expiry_account_operator_and_gateway_fail_closed(
    tmp_path: Path,
    case: str,
) -> None:
    service, rpc, _, private = build_service(tmp_path)
    kwargs: dict[str, Any] = {}
    submit_operator = "alice"
    if case == "operator":
        submit_operator = "bob"
    elif case == "account":
        kwargs["account_sha256"] = "f" * 64
    elif case == "gateway":
        kwargs["resolved_gateway_name"] = "SIMNOW2"
    elif case == "expired":
        kwargs["expires_at"] = NOW + timedelta(minutes=1)
        service.clock = lambda: NOW + timedelta(minutes=2)
    submission = signed_submission(private, **kwargs)

    with pytest.raises(ManualExecutionPermitError):
        service.submit(submission, operator=submit_operator)

    assert rpc.send_attempts == 0


def test_default_gateway_is_bound_separately_from_raw_order(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private, gateway_name=None)
    service.trade.settings.default_gateway_name = "SIMNOW2"

    with pytest.raises(ManualExecutionPermitError):
        service.submit(submission, operator="alice")

    assert rpc.send_attempts == 0


def test_create_only_marker_rejects_sequential_replay(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)
    service.submit(submission, operator="alice")

    with pytest.raises(ManualExecutionPermitReplayError):
        service.submit(submission, operator="alice")

    assert rpc.send_attempts == 1


def test_concurrent_replay_allows_one_send_attempt(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)
    barrier = Barrier(2)

    def submit() -> str:
        barrier.wait()
        try:
            service.submit(submission, operator="alice")
        except ManualExecutionPermitReplayError:
            return "replay"
        return "sent"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: submit(), range(2)))

    assert sorted(results) == ["replay", "sent"]
    assert rpc.send_attempts == 1


def test_timeout_unknown_consumes_permit_and_cannot_retry(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)
    rpc.fail_unknown = True

    with pytest.raises(TimeoutError, match="outcome unknown"):
        service.submit(submission, operator="alice")
    with pytest.raises(ManualExecutionPermitReplayError):
        service.submit(submission, operator="alice")

    assert rpc.send_attempts == 1


def test_final_guard_revalidates_account_inside_rpc_lock(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)
    rpc.before_guard = lambda: setattr(
        rpc,
        "accounts",
        [{"accountid": "changed", "gateway_name": "CTP"}],
    )

    with pytest.raises(ManualExecutionPermitError):
        service.submit(submission, operator="alice")

    assert rpc.guard_calls == 1
    assert rpc.send_attempts == 0


def test_final_guard_detects_risk_payload_mutation(tmp_path: Path) -> None:
    service, rpc, risk, private = build_service(tmp_path)
    submission = signed_submission(private)
    risk.mutate = lambda payload: setattr(payload, "price", 3001)

    with pytest.raises(ManualExecutionPermitError):
        service.submit(submission, operator="alice")

    assert rpc.guard_calls == 1
    assert rpc.send_attempts == 0


def test_final_guard_detects_consume_root_replacement(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    submission = signed_submission(private)
    root = tmp_path / "consumed"

    def replace_root() -> None:
        root.rename(tmp_path / "consumed-replaced")
        root.mkdir(mode=0o700)

    rpc.before_guard = replace_root

    with pytest.raises(ManualExecutionPermitError):
        service.submit(submission, operator="alice")

    assert rpc.guard_calls == 1
    assert rpc.send_attempts == 0


@pytest.mark.parametrize("drift", ("default_gateway", "vnpy_gateway"))
def test_final_rpc_guard_rejects_gateway_drift_after_consume(
    tmp_path: Path,
    drift: str,
) -> None:
    service, rpc, risk, private = build_service(tmp_path)
    submission = signed_submission(private, gateway_name=None)
    if drift == "default_gateway":
        risk.mutate = lambda _payload: setattr(
            service.trade.settings,
            "default_gateway_name",
            "SIMNOW2",
        )
    else:
        rpc.before_guard = lambda: setattr(
            service.settings,
            "vnpy_gateway_name",
            "SIMNOW2",
        )

    with pytest.raises(ManualExecutionPermitError):
        service.submit(submission, operator="alice")

    assert rpc.guard_calls == 1
    assert rpc.send_attempts == 0


def test_existing_unsafe_consume_root_is_not_chmodded(tmp_path: Path) -> None:
    root = tmp_path / "consumed"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    service, rpc, _, private = build_service(tmp_path)

    with pytest.raises(ManualExecutionPermitError) as caught:
        service.submit(signed_submission(private), operator="alice")

    assert caught.value.detail["reason"] == (
        "MANUAL_EXECUTION_CONSUME_ROOT_INVALID"
    )
    assert root.stat().st_mode & 0o777 == 0o755
    assert rpc.send_attempts == 0


def test_manual_key_domain_cannot_reuse_c_fast_key(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    service, rpc, _, _ = build_service(tmp_path, private=private)
    encoded = base64.b64encode(public_material(private)).decode("ascii")
    service.settings.commodity_c_fast_shadow_trusted_public_keys_json = (
        '{"cfast-control":{"public_key_base64":"'
        + encoded
        + '","purpose":"simnow_shakedown_control_signer"}}'
    )

    with pytest.raises(ManualExecutionPermitError) as caught:
        service.submit(signed_submission(private), operator="alice")

    assert caught.value.detail["reason"] == "MANUAL_EXECUTION_KEY_DOMAIN_REUSE"
    assert rpc.send_attempts == 0


def test_foreign_key_domain_enumeration_covers_all_commodity_key_sources(
    tmp_path: Path,
) -> None:
    service, _, _, _ = build_service(tmp_path)
    enumerated = {
        field
        for field in type(service.settings).model_fields
        if field.startswith("commodity_")
        and (
            field.endswith("trusted_public_keys_json")
            or field.endswith("keyring_path")
        )
    }

    assert enumerated == {
        "commodity_simnow_trusted_public_keys_json",
        "commodity_baseline_execution_permit_trusted_keyring_path",
        "commodity_c_fast_shadow_trusted_public_keys_json",
        "commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path",
        "commodity_c_fast_simnow_execution_permit_trusted_keyring_path",
        "commodity_c_fast_simnow_research_acceptance_trusted_keyring_path",
        "commodity_c_fast_simnow_research_keyring_path",
    }


@pytest.mark.parametrize(
    "keyring_field",
    (
        "commodity_baseline_execution_permit_trusted_keyring_path",
        "commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path",
        "commodity_c_fast_simnow_execution_permit_trusted_keyring_path",
        "commodity_c_fast_simnow_research_acceptance_trusted_keyring_path",
        "commodity_c_fast_simnow_research_keyring_path",
    ),
)
def test_manual_key_domain_cannot_reuse_any_external_c_fast_keyring(
    tmp_path: Path,
    keyring_field: str,
) -> None:
    private = Ed25519PrivateKey.generate()
    service, rpc, _, _ = build_service(tmp_path, private=private)
    encoded = base64.b64encode(public_material(private)).decode("ascii")
    keyring_path = tmp_path / f"{keyring_field}.json"
    keyring_path.write_text(
        '{"trusted_keys":[{"key_id":"foreign-v1",'
        '"public_key_base64":"'
        + encoded
        + '"}]}',
        encoding="utf-8",
    )
    setattr(service.settings, keyring_field, str(keyring_path))

    with pytest.raises(ManualExecutionPermitError) as caught:
        service.submit(signed_submission(private), operator="alice")

    assert caught.value.detail["reason"] == "MANUAL_EXECUTION_KEY_DOMAIN_REUSE"
    assert rpc.send_attempts == 0


def test_unreadable_configured_c_fast_keyring_fails_closed(
    tmp_path: Path,
) -> None:
    service, rpc, _, private = build_service(tmp_path)
    service.settings.commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path = str(
        tmp_path / "missing-keyring.json"
    )

    with pytest.raises(ManualExecutionPermitError) as caught:
        service.submit(signed_submission(private), operator="alice")

    assert caught.value.detail["reason"] == (
        "MANUAL_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED"
    )
    assert rpc.send_attempts == 0


def test_disabled_manual_boundary_sends_nothing(tmp_path: Path) -> None:
    service, rpc, _, private = build_service(tmp_path)
    service.settings.manual_execution_permit_enabled = False

    with pytest.raises(ManualExecutionPermitError):
        service.submit(signed_submission(private), operator="alice")

    assert rpc.send_attempts == 0


def test_manual_execution_capability_cannot_be_forged_or_cross_bound(
    tmp_path: Path,
) -> None:
    service, rpc, _, private = build_service(tmp_path)

    with pytest.raises(TypeError, match="cannot be constructed"):
        _ManualExecutionCapability(object(), construction_key=object())

    with pytest.raises(RuntimeError, match="capability is invalid"):
        service.trade._send_manual_permitted_order(
            signed_submission(private).order.to_order_request(),
            manual_execution_owner=object(),
            manual_execution_capability=object(),
            pre_rpc_guard=lambda _fingerprint: None,
        )

    assert rpc.send_attempts == 0
