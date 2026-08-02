#!/usr/bin/env python3
"""Offline draft/sign/verify tooling for CommoditySimNow baseline permits."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.schemas.commodity_baseline_execution_permit import (  # noqa: E402
    CommodityBaselineExecutionPermitDTO,
    CommodityBaselinePermitTrustedKeysDTO,
    baseline_execution_plan_core_payload,
    baseline_order_set_sha256,
    baseline_price_policy_sha256,
    canonical_json,
    derived_baseline_permit_id,
    sha256_bytes,
    unsigned_baseline_permit_payload,
)


PENDING_SIGNATURE = "PENDING_OFFLINE_ED25519_SIGNATURE"


def _read_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload


def _write_canonical(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        raw = canonical_json(payload) + b"\n"
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519 PEM")
    return key


def _active_plan(path: Path) -> dict[str, Any]:
    wrapper = _read_object(path)
    plan = wrapper.get("plan") if "plan" in wrapper else wrapper
    if not isinstance(plan, dict):
        raise ValueError("active plan payload is invalid")
    if "plan_checksum" in wrapper and wrapper["plan_checksum"] != sha256_bytes(
        canonical_json(plan)
    ):
        raise ValueError("active plan checksum mismatch")
    observed = sha256_bytes(canonical_json(baseline_execution_plan_core_payload(plan)))
    if observed != plan.get("execution_plan_core_sha256"):
        raise ValueError("active plan immutable core hash mismatch")
    if plan.get("c_fast_shakedown_session_id"):
        raise ValueError("C_FAST plans cannot receive baseline permits")
    return plan


def _identity(plan: dict[str, Any]) -> tuple[str, str, str]:
    if plan.get("position_manager_shakedown_session_id"):
        return (
            "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
            "commodity_relative_vol_position_manager_shakedown_v1",
            str(plan["position_manager_shakedown_session_id"]),
        )
    return (
        "STATIC_CORE_EQUAL",
        "commodity_static_core_equal_target_batch_v2",
        str(plan["baseline_execution_session_id"]),
    )


def draft(args: argparse.Namespace) -> None:
    plan = _active_plan(args.active_plan)
    strategy_id, strategy_version, session_id = _identity(plan)
    orders = list(plan[f"{args.phase}_orders"])
    if not orders:
        raise ValueError("selected phase has no orders")
    factor = args.price_band_percent / 100.0
    scoped_orders: list[dict[str, Any]] = []
    for order in orders:
        decision = float(order["price"])
        scoped_orders.append(
            {
                "symbol": str(order["symbol"]),
                "exchange": str(order["exchange"]),
                "direction": str(order["direction"]),
                "offset": str(order["offset"]),
                "type": "limit",
                "volume": int(order["volume"]),
                "reference": str(order["reference"]),
                "minimum_price": round(decision * (1.0 - factor), 10),
                "maximum_price": round(decision * (1.0 + factor), 10),
            }
        )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    policy_id = (
        "COMMODITY_SIMNOW_ACCEPTANCE_PASSIVE_TOUCH_V1"
        if args.acceptance_passive
        else "COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1"
    )
    risk = {
        "max_child_order_lots": args.max_child_order_lots,
        "max_orders_per_phase": args.max_orders_per_phase,
        "max_total_phase_lots": sum(row["volume"] for row in scoped_orders),
        "max_symbol_position_lots": float(args.max_symbol_position_lots),
        "max_product_weight": 0.15,
        "max_gross_weight": 1.0,
        "max_abs_net_weight": 0.10,
        "max_sector_weight": 0.35,
        "max_quote_age_seconds": args.max_quote_age_seconds,
        "max_spread_ticks": float(args.max_spread_ticks),
    }
    payload: dict[str, Any] = {
        "schema_version": "commodity_baseline_execution_permit_v1",
        "purpose": "commodity_baseline_phase_one_shot_execution_permit",
        "permit_id": "PENDING_DERIVED_PERMIT_ID",
        "nonce": f"baseline-{uuid.uuid4().hex}",
        "issued_at_utc": now.isoformat().replace("+00:00", "Z"),
        "not_before_utc": now.isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (now + timedelta(seconds=args.ttl_seconds))
        .isoformat()
        .replace("+00:00", "Z"),
        "execution_environment": "SIMNOW",
        "strategy_id": strategy_id,
        "strategy_version": strategy_version,
        "plan_hash": str(plan["plan_hash"]),
        "execution_plan_core_sha256": str(plan["execution_plan_core_sha256"]),
        "execution_session_id": session_id,
        "phase": args.phase,
        "account_sha256": str(plan["account_hash"]),
        "resolved_gateway_name": args.gateway_name,
        "price_policy_id": policy_id,
        "price_policy_sha256": baseline_price_policy_sha256(
            price_policy_id=policy_id,
            max_quote_age_seconds=args.max_quote_age_seconds,
            max_spread_ticks=float(args.max_spread_ticks),
        ),
        "order_set_sha256": baseline_order_set_sha256(scoped_orders),
        "orders": scoped_orders,
        "risk_envelope": risk,
        "signer_key_id": args.signer_key_id,
        "phase_dispatch_authorized": True,
        "one_shot": True,
        "replay_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "automatic_promotion_authorized": False,
        "c_fast_authority_reused": False,
        "manual_authority_reused": False,
        "signature": PENDING_SIGNATURE,
    }
    _write_canonical(args.output, payload)
    print(f"draft={args.output}")
    print(f"execution_plan_core_sha256={plan['execution_plan_core_sha256']}")
    print("Review every price band and risk limit before offline signing.")


def sign(args: argparse.Namespace) -> None:
    payload = _read_object(args.input)
    if payload.get("signature") != PENDING_SIGNATURE:
        raise ValueError("input is not an unsigned draft")
    private = _load_private_key(args.private_key)
    payload["permit_id"] = derived_baseline_permit_id(payload)
    payload["signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
    unsigned = CommodityBaselineExecutionPermitDTO.model_validate(payload)
    payload["signature"] = base64.b64encode(
        private.sign(canonical_json(unsigned_baseline_permit_payload(unsigned)))
    ).decode("ascii")
    permit = CommodityBaselineExecutionPermitDTO.model_validate(payload)
    _write_canonical(args.output, permit.model_dump(mode="json"))
    print(f"signed={args.output}")
    print(f"permit_id={permit.permit_id}")


def keyring(args: argparse.Namespace) -> None:
    private = _load_private_key(args.private_key)
    material = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    payload = {
        "schema_version": ("commodity_baseline_execution_permit_trusted_keys_v1"),
        "purpose": "commodity_baseline_execution_permit_verification",
        "trusted_keys": [
            {
                "key_id": args.signer_key_id,
                "public_key_base64": base64.b64encode(material).decode("ascii"),
                "purpose": "commodity_baseline_execution_permit_signer",
            }
        ],
    }
    validated = CommodityBaselinePermitTrustedKeysDTO.model_validate(payload)
    _write_canonical(args.output, validated.model_dump(mode="json"), mode=0o644)
    raw = args.output.read_bytes()
    print(f"keyring={args.output}")
    print(f"keyring_raw_sha256={hashlib.sha256(raw).hexdigest()}")


def verify(args: argparse.Namespace) -> None:
    permit_payload = _read_object(args.permit)
    keyring_payload = _read_object(args.keyring)
    permit = CommodityBaselineExecutionPermitDTO.model_validate(permit_payload)
    keyring = CommodityBaselinePermitTrustedKeysDTO.model_validate(keyring_payload)
    if permit.permit_id != derived_baseline_permit_id(permit):
        raise ValueError("permit id mismatch")
    trusted = {row.key_id: row for row in keyring.trusted_keys}.get(
        permit.signer_key_id
    )
    if trusted is None:
        raise ValueError("signer is not in keyring")
    material = base64.b64decode(trusted.public_key_base64, validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(material).verify(
            base64.b64decode(permit.signature, validate=True),
            canonical_json(unsigned_baseline_permit_payload(permit)),
        )
    except InvalidSignature as exc:
        raise ValueError("signature invalid") from exc
    if args.active_plan:
        plan = _active_plan(args.active_plan)
        strategy_id, strategy_version, session_id = _identity(plan)
        if (
            permit.plan_hash != plan["plan_hash"]
            or permit.execution_plan_core_sha256 != plan["execution_plan_core_sha256"]
            or permit.execution_session_id != session_id
            or permit.strategy_id != strategy_id
            or permit.strategy_version != strategy_version
        ):
            raise ValueError("permit does not match active plan")
        planned = list(plan[f"{permit.phase}_orders"])
        authorized_shape = [
            {
                "symbol": row.symbol,
                "exchange": row.exchange,
                "direction": row.direction,
                "offset": row.offset,
                "type": row.type,
                "volume": row.volume,
                "reference": row.reference,
            }
            for row in permit.orders
        ]
        planned_shape = [
            {
                "symbol": str(row["symbol"]),
                "exchange": str(row["exchange"]),
                "direction": str(row["direction"]),
                "offset": str(row["offset"]),
                "type": "limit",
                "volume": int(row["volume"]),
                "reference": str(row["reference"]),
            }
            for row in planned
        ]
        if authorized_shape != planned_shape:
            raise ValueError("permit order set does not match active plan")
    print("verification=PASS")
    print(f"permit_id={permit.permit_id}")
    print(f"keyring_raw_sha256={hashlib.sha256(args.keyring.read_bytes()).hexdigest()}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    draft_parser = commands.add_parser("draft")
    draft_parser.add_argument("--active-plan", type=Path, required=True)
    draft_parser.add_argument("--phase", choices=("close", "open"), required=True)
    draft_parser.add_argument("--output", type=Path, required=True)
    draft_parser.add_argument("--signer-key-id", required=True)
    draft_parser.add_argument("--gateway-name", default="CTP")
    draft_parser.add_argument("--ttl-seconds", type=int, default=300)
    draft_parser.add_argument("--price-band-percent", type=float, required=True)
    draft_parser.add_argument("--max-child-order-lots", type=int, default=10)
    draft_parser.add_argument("--max-orders-per-phase", type=int, default=128)
    draft_parser.add_argument("--max-symbol-position-lots", type=float, default=5)
    draft_parser.add_argument("--max-quote-age-seconds", type=int, default=5)
    draft_parser.add_argument("--max-spread-ticks", type=float, default=4)
    draft_parser.add_argument("--acceptance-passive", action="store_true")
    draft_parser.set_defaults(handler=draft)

    sign_parser = commands.add_parser("sign")
    sign_parser.add_argument("--input", type=Path, required=True)
    sign_parser.add_argument("--private-key", type=Path, required=True)
    sign_parser.add_argument("--output", type=Path, required=True)
    sign_parser.set_defaults(handler=sign)

    keyring_parser = commands.add_parser("keyring")
    keyring_parser.add_argument("--private-key", type=Path, required=True)
    keyring_parser.add_argument("--signer-key-id", required=True)
    keyring_parser.add_argument("--output", type=Path, required=True)
    keyring_parser.set_defaults(handler=keyring)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--permit", type=Path, required=True)
    verify_parser.add_argument("--keyring", type=Path, required=True)
    verify_parser.add_argument("--active-plan", type=Path)
    verify_parser.set_defaults(handler=verify)
    return result


def main() -> int:
    args = parser().parse_args()
    args.handler(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
