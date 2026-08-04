#!/usr/bin/env python3
"""Explicitly bind and sign one MAP→C_FAST Runtime Snapshot.

This tool never enables Runtime Authorization.  It verifies the three installed
authority artifacts, verifies the source Research snapshot with the supplied
Research key, emits the independent runtime snapshot schema, and publishes it
create-only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.core.commodity_strategy_identity import (  # noqa: E402
    commodity_c_fast_allocation_policy_projection_sha256,
    commodity_executable_target_projection_sha256,
    commodity_map_strategy_version_projection_sha256,
)
from app.schemas.commodity_c_fast_shadow import (  # noqa: E402
    CommodityCFastRuntimeExecutableSnapshotDTO,
    CommodityCFastShadowDTO,
)
from app.services.commodity_c_fast_runtime_authorization import (  # noqa: E402
    CommodityCFastRuntimeAuthorizationService,
    canonical_json,
)
from app.services.commodity_c_fast_shadow_common import (  # noqa: E402
    formula_target_binding_sha256,
    unsigned_snapshot_payload,
)
from commodity_c_fast_shadow_sign import load_private_key  # noqa: E402


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _read_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload, raw


def build_runtime_snapshot(
    *,
    source_payload: dict[str, Any],
    source_raw: bytes,
    private_key,
    signer_key_id: str,
    producer_sha256: str,
    map_signal_artifact_sha256: str,
    selected_products: list[str],
    authority: CommodityCFastRuntimeAuthorizationService,
) -> CommodityCFastRuntimeExecutableSnapshotDTO:
    source = CommodityCFastShadowDTO.model_validate(source_payload)
    if source.signer_key_id != signer_key_id:
        raise ValueError("source signer_key_id does not match runtime signer")
    if formula_target_binding_sha256(source) != source.formula_target_binding_sha256:
        raise ValueError("source formula/target binding is invalid")
    try:
        private_key.public_key().verify(
            base64.b64decode(source.signature, validate=True),
            canonical_json(unsigned_snapshot_payload(source)),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("source Research signature is invalid") from exc
    artifacts = authority.verified_artifacts()
    products = sorted(selected_products)
    if (
        not products
        or len(products) != len(set(products))
        or len(products) > artifacts.authorization.max_selected_products
        or not set(products).issubset(artifacts.authorization.allowed_products)
    ):
        raise ValueError("selected products exceed Runtime Authorization")
    payload = source.model_dump(mode="json")
    payload.update(
        {
            "schema_version": (
                "commodity_map_c_fast_simnow_executable_target_snapshot_v1"
            ),
            "mode": "simnow_runtime",
            "execution_lane": "simnow_shakedown",
            "countable_forward": False,
            "live_allowed": False,
            "research_observed_at_utc": source.snapshot_created_at_utc.isoformat(),
            "map_acceptance_id": artifacts.map_acceptance.acceptance_id,
            "map_acceptance_raw_sha256": artifacts.map_acceptance_raw_sha256,
            "map_strategy_projection_sha256": (
                artifacts.map_acceptance.projection_sha256
            ),
            "map_signal_artifact_sha256": map_signal_artifact_sha256,
            "c_fast_allocation_acceptance_id": (
                artifacts.allocation_acceptance.acceptance_id
            ),
            "c_fast_allocation_acceptance_raw_sha256": (
                artifacts.allocation_acceptance_raw_sha256
            ),
            "c_fast_allocation_projection_sha256": (
                artifacts.allocation_acceptance.projection_sha256
            ),
            "runtime_selected_products": products,
            "executable_target_binding_sha256": "0" * 64,
            "signature": PLACEHOLDER_SIGNATURE,
        }
    )
    payload["research_bindings"].update(
        {
            "snapshot_producer_status": (
                "IMPLEMENTED_SIGNED_MAP_C_FAST_RUNTIME_V1"
            ),
            "producer_sha256": producer_sha256,
            "input_bundle_sha256": hashlib.sha256(source_raw).hexdigest(),
        }
    )
    draft = CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(payload)
    payload["formula_target_binding_sha256"] = formula_target_binding_sha256(draft)
    draft = CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(payload)
    if (
        commodity_map_strategy_version_projection_sha256(draft)
        != artifacts.map_acceptance.projection_sha256
    ):
        raise ValueError("source MAP version is not covered by Acceptance")
    if (
        commodity_c_fast_allocation_policy_projection_sha256(draft)
        != artifacts.allocation_acceptance.projection_sha256
    ):
        raise ValueError("source C_FAST policy is not covered by Acceptance")
    payload["executable_target_binding_sha256"] = (
        commodity_executable_target_projection_sha256(draft)
    )
    draft = CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(payload)
    payload["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_snapshot_payload(draft)))
    ).decode("ascii")
    return CommodityCFastRuntimeExecutableSnapshotDTO.model_validate(payload)


def _publish_create_only(path: Path, snapshot: CommodityCFastRuntimeExecutableSnapshotDTO) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        raw = canonical_json(snapshot.model_dump(mode="json")) + b"\n"
        if os.write(descriptor, raw) != len(raw):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-snapshot", type=Path, required=True)
    result.add_argument("--map-acceptance", type=Path, required=True)
    result.add_argument("--allocation-acceptance", type=Path, required=True)
    result.add_argument("--runtime-authorization", type=Path, required=True)
    result.add_argument("--trusted-keyring", type=Path, required=True)
    result.add_argument("--keyring-raw-sha256", required=True)
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--signer-key-id", required=True)
    result.add_argument("--producer-sha256", required=True)
    result.add_argument("--map-signal-artifact-sha256", required=True)
    result.add_argument("--selected-product", action="append", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    source_payload, source_raw = _read_object(args.source_snapshot)
    authority = CommodityCFastRuntimeAuthorizationService(
        enabled=True,
        map_acceptance_path=args.map_acceptance,
        allocation_acceptance_path=args.allocation_acceptance,
        authorization_path=args.runtime_authorization,
        trusted_keyring_path=args.trusted_keyring,
        expected_keyring_raw_sha256=args.keyring_raw_sha256,
        state_dir=args.output.parent / ".runtime-authorization-state-unused",
    )
    snapshot = build_runtime_snapshot(
        source_payload=source_payload,
        source_raw=source_raw,
        private_key=load_private_key(args.private_key),
        signer_key_id=args.signer_key_id,
        producer_sha256=args.producer_sha256,
        map_signal_artifact_sha256=args.map_signal_artifact_sha256,
        selected_products=args.selected_product,
        authority=authority,
    )
    _publish_create_only(args.output, snapshot)
    print(f"runtime snapshot written create-only: {args.output}")
    print("Runtime Authorization remains disabled until the admin enable API is called.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
