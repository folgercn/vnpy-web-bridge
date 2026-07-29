#!/usr/bin/env python3
"""Sign one independently verified C_FAST SimNow execution permit.

All public #165 evidence, the existing create-only receipt, the legacy target
snapshot and the configured Execution keyring are verified before the private
key is read.  The signer performs no RPC, account query, order or deployment.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_permit import (
    CommodityCFastExecutionPermitTrustedKeysDTO,
)
from app.services.commodity_c_fast_execution_permit import canonical_json
from app.services.commodity_c_fast_research_acceptance_evidence import (
    CommodityCFastResearchAcceptanceEvidenceService,
)
from app.services.commodity_c_fast_shadow_common import (
    sha256_json,
    unsigned_snapshot_payload,
)
from commodity_c_fast_shadow_sign import load_private_key
from commodity_c_fast_shakedown_artifact import (
    load_public_key,
    read_object,
    verify as verify_legacy_snapshot,
)
from commodity_c_fast_simnow_execution_permit import (
    prepare_unsigned_execution_permit,
    sign_execution_permit,
)
from commodity_c_fast_simnow_research_acceptance import (
    CONSUME_SCHEMA_PATH,
    RECEIPT_SCHEMA_PATH,
    validate_json_schema,
    verify_signed_acceptance,
)
from commodity_c_fast_simnow_research_bundle import (
    write_json_create_only_verified,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsigned", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--snapshot-research-public-key", type=Path, required=True)
    parser.add_argument("--snapshot-control-public-key", type=Path, required=True)
    parser.add_argument("--execution-private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _exact_json(path: Path, label: str) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or raw != canonical_json(payload) + b"\n":
        raise ValueError(f"{label} must be exact canonical JSON")
    return payload, raw


def main() -> int:
    args = parse_args()
    try:
        settings = Settings()
        evidence_service = CommodityCFastResearchAcceptanceEvidenceService(
            settings=settings
        )
        evidence_service.bind_full_acceptance_verifier(
            verify_signed_acceptance,
            contract_schema_validator=validate_json_schema,
            consume_schema_path=CONSUME_SCHEMA_PATH,
            receipt_schema_path=RECEIPT_SCHEMA_PATH,
        )
        evidence = evidence_service.verify_existing_receipt()
        snapshot_payload = read_object(args.snapshot)
        snapshot = verify_legacy_snapshot(
            snapshot_payload,
            load_public_key(args.snapshot_research_public_key),
            load_public_key(args.snapshot_control_public_key),
        )
        snapshot_sha256 = sha256_json(unsigned_snapshot_payload(snapshot))
        unsigned, _unsigned_raw = _exact_json(
            args.unsigned, "unsigned execution permit"
        )
        expected = prepare_unsigned_execution_permit(
            evidence,
            snapshot,
            snapshot_sha256,
            execution_signer_key_id=str(unsigned["signer_key_id"]),
            reviewer_role=str(unsigned["reviewer_role"]),
            human_signature=str(unsigned["human_signature"]),
            issued_at=datetime.fromisoformat(
                str(unsigned["issued_at"]).replace("Z", "+00:00")
            ),
            not_before=datetime.fromisoformat(
                str(unsigned["not_before"]).replace("Z", "+00:00")
            ),
            expires_at=datetime.fromisoformat(
                str(unsigned["expires_at"]).replace("Z", "+00:00")
            ),
        )
        if expected != unsigned:
            raise ValueError(
                "unsigned permit differs from freshly derived public evidence"
            )
        keyring, keyring_raw = _exact_json(
            Path(
                settings.commodity_c_fast_simnow_execution_permit_trusted_keyring_path
            ).expanduser(),
            "Execution permit trusted keyring",
        )
        if hashlib.sha256(keyring_raw).hexdigest() != (
            settings.commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256
        ):
            raise ValueError("Execution permit keyring pin mismatch")
        trusted = CommodityCFastExecutionPermitTrustedKeysDTO.model_validate(keyring)
        selected = {row.key_id: row for row in trusted.trusted_keys}.get(
            str(unsigned["signer_key_id"])
        )
        if selected is None or selected.reviewer_role != unsigned["reviewer_role"]:
            raise ValueError("Execution signer is not trusted")

        # Private material is intentionally read only after every public check.
        private_key = load_private_key(args.execution_private_key)
        public_base64 = base64.b64encode(
            private_key.public_key().public_bytes_raw()
        ).decode("ascii")
        if public_base64 != selected.public_key_base64:
            raise ValueError("private key does not match trusted Execution signer")
        if evidence_service.verify_existing_receipt() != evidence:
            raise ValueError("#165 evidence changed after private key access")
        signed = sign_execution_permit(
            unsigned, private_key=private_key, evidence=evidence
        )
        write_json_create_only_verified(
            args.output,
            signed,
            label="signed C_FAST SimNow execution permit",
        )
    except Exception as exc:
        print(f"execution permit signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"execution_permit_id: {signed['permit_id']}")
    print("execution_environment: SIMNOW")
    print("production_allowed: false")
    print("live_trading_authorized: false")
    print("automatic_promotion_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
