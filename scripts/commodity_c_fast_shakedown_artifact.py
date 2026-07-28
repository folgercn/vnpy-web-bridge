#!/usr/bin/env python3
"""Produce, sign, verify, and create-only install one C_FAST SimNow artifact.

The producer consumes only a human-confirmed Research bundle.  It has no
account, RPC, order, position, or gateway dependency.  Control authority is
added later with a distinct Ed25519 key.
"""

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
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.schemas.commodity_c_fast_shadow import (  # noqa: E402
    CommodityCFastShakedownSnapshotDTO,
)
from app.core.config import Settings  # noqa: E402
from app.services.commodity_c_fast_shadow import (  # noqa: E402
    CommodityCFastShadowService,
)
from app.services.commodity_c_fast_shadow_common import (  # noqa: E402
    canonical_json,
    formula_target_binding_sha256,
    shakedown_research_payload,
    unsigned_snapshot_payload,
)
from commodity_c_fast_shadow_sign import (  # noqa: E402
    PLACEHOLDER_SIGNATURE,
    load_private_key,
)

INPUT_KEYS = {
    "schema_version",
    "human_confirmed",
    "reviewer_assertion",
    "evidence",
    "snapshot",
}
EVIDENCE_KEYS = {"name", "kind", "sha256"}
REQUIRED_EVIDENCE_KINDS = {
    "research_manifest",
    "allocation",
    "daily_roll",
    "reference_price",
}
PROTECTED_SNAPSHOT_KEYS = {
    "schema_version",
    "mode",
    "execution_lane",
    "frequency",
    "source_is_month_last_official_day",
    "execution_is_next_cross_month_official_day",
    "input_cutoff_after_source_close",
    "calendar_alignment",
    "allocator_output_validation",
    "daily_roll_alignment",
    "formula_target_binding_sha256",
    "research_signature",
    "control_acceptance_id",
    "execution_permit_id",
    "accepted_at_utc",
    "expires_at_utc",
    "account_sha256",
    "max_selected_products",
    "max_child_order_lots",
    "countable_forward",
    "control_signer_key_id",
    "signature",
}


def read_object(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("input must contain one JSON object")
    return raw


def write_private_create(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except Exception:
        raise
    finally:
        temporary.unlink(missing_ok=True)


def dummy_control(core: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        **core,
        "research_signature": PLACEHOLDER_SIGNATURE,
        "control_acceptance_id": "cfast-accept-placeholder1",
        "execution_permit_id": "cfast-permit-placeholder1",
        "accepted_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
        "account_sha256": "0" * 64,
        "max_selected_products": 1,
        "max_child_order_lots": 0,
        "countable_forward": False,
        "control_signer_key_id": "placeholder-control",
        "signature": PLACEHOLDER_SIGNATURE,
    }


def produce(bundle: dict[str, Any]) -> dict[str, Any]:
    if set(bundle) != INPUT_KEYS:
        raise ValueError("research input bundle fields are not exact")
    if (
        bundle["schema_version"]
        != "commodity_c_fast_simnow_research_input_v1"
        or bundle["human_confirmed"] is not True
        or bundle["reviewer_assertion"]
        != "REAL_RESEARCH_INPUT_NOT_FIXTURE_NOT_EXECUTION_DERIVED"
    ):
        raise ValueError("research input authority assertion is invalid")
    evidence = bundle["evidence"]
    if (
        not isinstance(evidence, list)
        or not evidence
        or any(
            not isinstance(row, dict)
            or set(row) != EVIDENCE_KEYS
            or not isinstance(row["name"], str)
            or not row["name"]
            or row["kind"] not in REQUIRED_EVIDENCE_KINDS
            or not isinstance(row["sha256"], str)
            or len(row["sha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in row["sha256"])
            for row in evidence
        )
    ):
        raise ValueError("research evidence list is invalid")
    if len({row["name"] for row in evidence}) != len(evidence):
        raise ValueError("research evidence names must be unique")
    evidence_by_kind = {row["kind"]: row for row in evidence}
    if (
        len(evidence_by_kind) != len(evidence)
        or set(evidence_by_kind) != REQUIRED_EVIDENCE_KINDS
    ):
        raise ValueError("research evidence kinds must be exact and unique")
    snapshot = bundle["snapshot"]
    if not isinstance(snapshot, dict) or set(snapshot) & PROTECTED_SNAPSHOT_KEYS:
        raise ValueError("snapshot contains producer/control-owned fields")
    bindings = snapshot.get("research_bindings")
    if not isinstance(bindings, dict):
        raise ValueError("research_bindings is required")
    bindings = dict(bindings)
    for key in (
        "snapshot_producer_status",
        "producer_sha256",
        "input_bundle_sha256",
    ):
        if key in bindings:
            raise ValueError(f"research input may not set {key}")
    expected_evidence_hashes = {
        "research_manifest": bindings.get("research_manifest_sha256"),
        "allocation": bindings.get("allocation_evidence_sha256"),
        "daily_roll": bindings.get("daily_roll_evidence_sha256"),
    }
    if any(
        evidence_by_kind[kind]["sha256"] != expected
        for kind, expected in expected_evidence_hashes.items()
    ):
        raise ValueError("research evidence hash does not match bindings")
    targets = snapshot.get("targets")
    reference_hashes = {
        row.get("reference_price_source_sha256")
        for row in targets
        if isinstance(row, dict)
    } if isinstance(targets, list) else set()
    if (
        len(reference_hashes) != 1
        or evidence_by_kind["reference_price"]["sha256"]
        not in reference_hashes
    ):
        raise ValueError(
            "reference-price evidence does not bind every target"
        )
    input_hash = hashlib.sha256(canonical_json(bundle)).hexdigest()
    core = {
        **snapshot,
        "schema_version": "commodity_c_fast_simnow_shakedown_snapshot_v1",
        "mode": "simnow_shakedown",
        "execution_lane": "simnow_shakedown",
        "frequency": "ONE_SHOT",
        "source_is_month_last_official_day": False,
        "execution_is_next_cross_month_official_day": False,
        "input_cutoff_after_source_close": False,
        "calendar_alignment": "HUMAN_CONFIRMED_RESEARCH_BUNDLE",
        "allocator_output_validation":
        "PRODUCER_RECOMPUTED_AND_SIGNER_CONFIRMED",
        "daily_roll_alignment": "HUMAN_CONFIRMED_PIT_EXACT_CONTRACT",
        "research_bindings": {
            **bindings,
            "snapshot_producer_status":
            "IMPLEMENTED_HUMAN_CONFIRMED_BUNDLE_V1",
            "producer_sha256": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "input_bundle_sha256": input_hash,
        },
        "formula_target_binding_sha256": "0" * 64,
    }
    draft = CommodityCFastShakedownSnapshotDTO.model_validate(
        dummy_control(core)
    )
    CommodityCFastShadowService(
        settings=Settings()
    )._verify_targets(draft)
    core["formula_target_binding_sha256"] = (
        formula_target_binding_sha256(draft)
    )
    CommodityCFastShakedownSnapshotDTO.model_validate(dummy_control(core))
    return core


def load_public_key(path: Path) -> Ed25519PublicKey:
    raw = path.read_bytes().strip()
    if raw.startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        return key
    decoded = base64.b64decode(raw, validate=True)
    if len(decoded) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(decoded)


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def sign_research(
    core: dict[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    draft = CommodityCFastShakedownSnapshotDTO.model_validate(
        dummy_control(core)
    )
    CommodityCFastShadowService(
        settings=Settings()
    )._verify_targets(draft)
    if formula_target_binding_sha256(draft) != draft.formula_target_binding_sha256:
        raise ValueError("formula/target binding mismatch")
    signature = private_key.sign(canonical_json(shakedown_research_payload(draft)))
    return {**core, "research_signature": base64.b64encode(signature).decode()}


def issue_permit(
    research: dict[str, Any],
    *,
    research_public_key: Ed25519PublicKey,
    control_private_key: Ed25519PrivateKey,
    acceptance_id: str,
    permit_id: str,
    account_sha256: str,
    accepted_at: str,
    expires_at: str,
    max_selected_products: int,
    control_signer_key_id: str,
) -> dict[str, Any]:
    control_public_key = control_private_key.public_key()
    if public_key_bytes(research_public_key) == public_key_bytes(
        control_public_key
    ):
        raise ValueError("Research and Control keys must be distinct")
    payload = {
        **research,
        "control_acceptance_id": acceptance_id,
        "execution_permit_id": permit_id,
        "accepted_at_utc": accepted_at,
        "expires_at_utc": expires_at,
        "account_sha256": account_sha256,
        "max_selected_products": max_selected_products,
        "max_child_order_lots": 0,
        "countable_forward": False,
        "control_signer_key_id": control_signer_key_id,
        "signature": PLACEHOLDER_SIGNATURE,
    }
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(payload)
    research_public_key.verify(
        base64.b64decode(snapshot.research_signature, validate=True),
        canonical_json(shakedown_research_payload(snapshot)),
    )
    payload["signature"] = base64.b64encode(
        control_private_key.sign(
            canonical_json(unsigned_snapshot_payload(snapshot))
        )
    ).decode()
    return CommodityCFastShakedownSnapshotDTO.model_validate(payload).model_dump(
        mode="json"
    )


def verify(
    payload: dict[str, Any],
    research_key: Ed25519PublicKey,
    control_key: Ed25519PublicKey,
) -> CommodityCFastShakedownSnapshotDTO:
    if public_key_bytes(research_key) == public_key_bytes(control_key):
        raise ValueError("Research and Control keys must be distinct")
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(payload)
    if formula_target_binding_sha256(snapshot) != snapshot.formula_target_binding_sha256:
        raise ValueError("formula/target binding mismatch")
    research_key.verify(
        base64.b64decode(snapshot.research_signature, validate=True),
        canonical_json(shakedown_research_payload(snapshot)),
    )
    control_key.verify(
        base64.b64decode(snapshot.signature, validate=True),
        canonical_json(unsigned_snapshot_payload(snapshot)),
    )
    now = datetime.now(timezone.utc)
    checker = CommodityCFastShadowService(
        settings=Settings(
            commodity_c_fast_simnow_account_hashes=snapshot.account_sha256
        ),
        clock=lambda: now,
    )
    checker._verify_shakedown_timing(snapshot)
    checker._verify_targets(snapshot)
    if snapshot.execution_day != now.astimezone(
        ZoneInfo("Asia/Shanghai")
    ).date():
        raise ValueError("execution day is not today")
    return snapshot


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("produce", "sign-research", "issue-permit", "verify", "install"):
        command = commands.add_parser(name)
        command.add_argument("--input", required=True, type=Path)
        if name in {"produce", "sign-research", "issue-permit"}:
            command.add_argument("--output", required=True, type=Path)
        if name == "sign-research":
            command.add_argument("--research-private-key-file", required=True, type=Path)
        if name == "issue-permit":
            command.add_argument("--research-public-key-file", required=True, type=Path)
            command.add_argument("--control-private-key-file", required=True, type=Path)
            command.add_argument("--acceptance-id", required=True)
            command.add_argument("--permit-id", required=True)
            command.add_argument("--account-sha256", required=True)
            command.add_argument("--accepted-at-utc", required=True)
            command.add_argument("--expires-at-utc", required=True)
            command.add_argument("--max-selected-products", type=int, default=1)
            command.add_argument("--control-signer-key-id", required=True)
        if name in {"verify", "install"}:
            command.add_argument("--research-public-key-file", required=True, type=Path)
            command.add_argument("--control-public-key-file", required=True, type=Path)
        if name == "install":
            command.add_argument("--destination", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        payload = read_object(args.input)
        if args.command == "produce":
            output = produce(payload)
        elif args.command == "sign-research":
            output = sign_research(
                payload, load_private_key(args.research_private_key_file)
            )
        elif args.command == "issue-permit":
            output = issue_permit(
                payload,
                research_public_key=load_public_key(args.research_public_key_file),
                control_private_key=load_private_key(args.control_private_key_file),
                acceptance_id=args.acceptance_id,
                permit_id=args.permit_id,
                account_sha256=args.account_sha256,
                accepted_at=args.accepted_at_utc,
                expires_at=args.expires_at_utc,
                max_selected_products=args.max_selected_products,
                control_signer_key_id=args.control_signer_key_id,
            )
        else:
            snapshot = verify(
                payload,
                load_public_key(args.research_public_key_file),
                load_public_key(args.control_public_key_file),
            )
            canonical = canonical_json(snapshot.model_dump(mode="json"))
            if args.command == "install":
                write_private_create(args.destination, canonical + b"\n")
                checksum = hashlib.sha256(canonical).hexdigest().encode() + b"\n"
                write_private_create(
                    args.destination.with_suffix(args.destination.suffix + ".sha256"),
                    checksum,
                )
            print(hashlib.sha256(canonical).hexdigest())
            return 0
        write_private_create(
            args.output,
            json.dumps(output, ensure_ascii=False, indent=2).encode() + b"\n",
        )
        return 0
    except Exception as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
