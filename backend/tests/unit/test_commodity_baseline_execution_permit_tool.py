from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.schemas.commodity_baseline_execution_permit import (
    baseline_execution_plan_core_payload,
    canonical_json,
    sha256_bytes,
)


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "scripts" / "commodity_baseline_execution_permit.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def test_offline_draft_sign_keyring_and_verify_round_trip(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "offline.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    plan = {
        "schema_version": "commodity_simnow_active_plan_v1",
        "baseline_execution_session_id": ("baseline-session-v1-0123456789abcdef"),
        "strategy_id": "STATIC_CORE_EQUAL",
        "strategy_version": "commodity_static_core_equal_target_batch_v2",
        "plan_hash": "a" * 64,
        "batch_hash": "b" * 64,
        "batch_id": "baseline-batch-v1",
        "execution_lane": "official_forward",
        "countable_forward": True,
        "account_hash": "c" * 64,
        "execution_day": "2026-08-03",
        "previous_positions": {},
        "expected_after_close": {},
        "expected_final_positions": {"SHFE.ag2610": 1},
        "close_orders": [
            {
                "product": "cu",
                "vt_symbol": "cu2610.SHFE",
                "symbol": "cu2610",
                "exchange": "SHFE",
                "direction": "short",
                "offset": "close",
                "volume": 1,
                "price": 75000.0,
                "reference": "commodity_static_core:close:cu:1",
            }
        ],
        "open_orders": [
            {
                "product": "ag",
                "vt_symbol": "SHFE.ag2610",
                "symbol": "ag2610",
                "exchange": "SHFE",
                "direction": "long",
                "offset": "open",
                "volume": 1,
                "price": 1000.0,
                "reference": "commodity_static_core:open:ag:1",
            }
        ],
        "targets": [],
        "quote_snapshot_hash": "d" * 64,
        "roll_products": [],
    }
    plan["execution_plan_core_sha256"] = sha256_bytes(
        canonical_json(baseline_execution_plan_core_payload(plan))
    )
    active = {
        "schema_version": "commodity_simnow_active_plan_v1",
        "plan_checksum": sha256_bytes(canonical_json(plan)),
        "plan": plan,
    }
    active_path = tmp_path / "state.active.json"
    active_path.write_text(json.dumps(active), encoding="utf-8")
    draft_path = tmp_path / "draft.json"
    signed_path = tmp_path / "signed.json"
    close_draft_path = tmp_path / "close-draft.json"
    close_signed_path = tmp_path / "close-signed.json"
    keyring_path = tmp_path / "keyring.json"

    run(
        "draft",
        "--active-plan",
        str(active_path),
        "--phase",
        "open",
        "--signer-key-id",
        "baseline-signer-v1",
        "--price-band-percent",
        "3",
        "--output",
        str(draft_path),
    )
    run(
        "draft",
        "--active-plan",
        str(active_path),
        "--phase",
        "close",
        "--signer-key-id",
        "baseline-signer-v1",
        "--price-band-percent",
        "3",
        "--output",
        str(close_draft_path),
    )
    keyring_result = run(
        "keyring",
        "--private-key",
        str(private_path),
        "--signer-key-id",
        "baseline-signer-v1",
        "--output",
        str(keyring_path),
    )
    run(
        "sign",
        "--input",
        str(draft_path),
        "--private-key",
        str(private_path),
        "--output",
        str(signed_path),
    )
    run(
        "sign",
        "--input",
        str(close_draft_path),
        "--private-key",
        str(private_path),
        "--output",
        str(close_signed_path),
    )
    verify_result = run(
        "verify",
        "--permit",
        str(signed_path),
        "--keyring",
        str(keyring_path),
        "--active-plan",
        str(active_path),
    )
    close_verify_result = run(
        "verify",
        "--permit",
        str(close_signed_path),
        "--keyring",
        str(keyring_path),
        "--active-plan",
        str(active_path),
    )

    assert "keyring_raw_sha256=" in keyring_result.stdout
    assert "verification=PASS" in verify_result.stdout
    assert "verification=PASS" in close_verify_result.stdout
