from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_simnow_research_acceptance as acceptance  # noqa: E402
import commodity_c_fast_simnow_research_bundle as bundle  # noqa: E402
import commodity_c_fast_simnow_sign_research_acceptance as signer  # noqa: E402


RESEARCH_NOW = datetime(2026, 7, 29, 2, 1, tzinfo=timezone.utc)
ACCEPTANCE_NOW = datetime(2026, 7, 29, 2, 3, tzinfo=timezone.utc)
EXECUTION_DAY = date(2026, 7, 29)
FOLLOWING_DAY = date(2026, 7, 30)
LAST_TRADING_DAY = date(2026, 12, 15)
RESEARCH_KEY_ID = "c-fast-research-key-a01"
ACCEPTANCE_KEY_ID = "c-fast-acceptance-key-a01"
ZERO_SHA256 = "0" * 64
ACCOUNT_SHA256 = hashlib.sha256(b"synthetic-simnow-account").hexdigest()
PRICES = {
    "ag": 8000.0,
    "al": 20000.0,
    "au": 500.0,
    "bu": 3800.0,
    "cu": 80000.0,
    "rb": 3600.0,
    "ru": 15000.0,
    "sc": 600.0,
    "sp": 6200.0,
    "zn": 24000.0,
}
DIRECTION = {
    "ag": 1,
    "al": 1,
    "au": -1,
    "bu": -1,
    "cu": 1,
    "rb": 1,
    "ru": -1,
    "sc": -1,
    "sp": 1,
    "zn": -1,
}


def write_bytes(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(path: Path, payload: dict, *, mode: int = 0o600) -> Path:
    return write_bytes(
        path,
        bundle.canonical_json(payload) + b"\n",
        mode=mode,
    )


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def private_key_base64(private_key: Ed25519PrivateKey) -> bytes:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw) + b"\n"


def target_rows() -> list[dict]:
    dte = (LAST_TRADING_DAY - EXECUTION_DAY).days
    following_dte = (LAST_TRADING_DAY - FOLLOWING_DAY).days
    rows: list[dict] = []
    for index, product in enumerate(bundle.PRODUCTS):
        direction = DIRECTION[product]
        volatility = 0.10 + index * 0.01
        spec = bundle.PRODUCT_SPECS[product]
        exact_contract = f"{spec['exchange']}.{product}2612"
        rows.append(
            {
                "product": product,
                "sector": bundle.SECTOR_MAP[product],
                "trend_21_sign": direction,
                "trend_63_sign": direction,
                "trend_126_sign": direction,
                "source_score": float(direction),
                "vol60_annualized": volatility,
                "raw_risk_score": direction / max(volatility, 0.05),
                "source_target_weight": 0.10 * direction,
                "buffered_target_weight": 0.08 * direction,
                "previous_exact_contract": None,
                "exact_contract": exact_contract,
                "previous_target_quantity": 0,
                "target_quantity": direction,
                "reference_open_price": PRICES[product],
                "reference_price_field": "official_open",
                "reference_price_observed_at": (
                    "2026-07-29T01:30:00+00:00"
                ),
                "reference_price_source_sha256": "a" * 64,
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "pit_main_exact_contract": exact_contract,
                "pit_main_dte": dte,
                "pit_main_official_last_trading_day": (
                    LAST_TRADING_DAY.isoformat()
                ),
                "pit_main_following_official_day": (
                    FOLLOWING_DAY.isoformat()
                ),
                "pit_main_following_dte": following_dte,
                "pit_main_target_position_allowed": True,
                "pit_main_roll": False,
            }
        )
    return rows


def research_draft() -> dict:
    payload = {
        "schema_version": bundle.SCHEMA_VERSION,
        "purpose": bundle.PURPOSE,
        "candidate_id": bundle.CANDIDATE_ID,
        "parent_issue_number": 114,
        "issue_number": 157,
        "bundle_id": "PENDING_DERIVED_BY_SIGNER",
        "generated_at": "2026-07-29T02:00:00+00:00",
        "not_before": "2026-07-29T01:55:00+00:00",
        "expires_at": "2026-07-29T10:00:00+00:00",
        "execution_day": EXECUTION_DAY.isoformat(),
        "research_as_of_official_day": "2026-07-09",
        "research_source_class": "SEALED_EXTERNAL_C_FAST_EVIDENCE",
        "target_derivation": "FROZEN_RULE_EXTERNAL_RESEARCH_PRODUCER",
        "initialization_policy": "COLD_START_ZERO_ACCOUNT",
        "frozen_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "frozen_rule_sha256": bundle.FROZEN_RULE_SHA256,
        "frequency": "ONE_SHOT_SIMNOW_EXERCISE",
        "pit_main_definition": "DAILY_PIT_OI_MAIN",
        "trend_horizons_official_days": [21, 63, 126],
        "volatility_lookback_official_days": 60,
        "volatility_floor": 0.05,
        "virtual_nav_cny": 20_000_000,
        "artifact_bindings": {
            role: {"bytes": 1, "raw_sha256": ZERO_SHA256}
            for role in bundle.ARTIFACT_ROLES
        },
        "artifact_index_sha256": ZERO_SHA256,
        "formula_target_binding_sha256": ZERO_SHA256,
        "verifier_sha256": ZERO_SHA256,
        "signer_sha256": ZERO_SHA256,
        "bundle_schema_sha256": ZERO_SHA256,
        "trusted_keyring_schema_sha256": ZERO_SHA256,
        "install_receipt_schema_sha256": ZERO_SHA256,
        "trusted_keyring_raw_sha256": ZERO_SHA256,
        "custody_root_path_sha256": ZERO_SHA256,
        "custody_identity_sha256": ZERO_SHA256,
        "source_artifacts_exact_raw_required": True,
        "research_bundle_fact_frozen": True,
        "orders_sent": 0,
        "positions_modified": 0,
        "targets": target_rows(),
        "signer_key_id": RESEARCH_KEY_ID,
    }
    for field in bundle.FALSE_AUTHORITY_FIELDS:
        payload[field] = False
    return payload


def acceptance_draft(bundle_id: str) -> dict:
    template = json.loads(
        (
            ROOT
            / "docs/operations/"
            "c-fast-simnow-research-acceptance-v1.template.json"
        ).read_text(encoding="utf-8")
    )
    template.pop("template_state")
    template.update(
        {
            "accepted_at": "2026-07-29T02:02:00+00:00",
            "not_before": "2026-07-29T02:00:00+00:00",
            "expires_at": "2026-07-29T02:10:00+00:00",
            "execution_day": EXECUTION_DAY.isoformat(),
            "reviewer_role": "C_FAST Control reviewer",
            "human_signature": "human-reviewed-issue-162-synthetic",
            "signer_key_id": ACCEPTANCE_KEY_ID,
            "research_bundle_id": bundle_id,
            "expected_simnow_account_sha256": ACCOUNT_SHA256,
            "selected_products": ["ag", "au"],
        }
    )
    return template


@pytest.fixture
def acceptance_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    # Synthetic cryptographic/market fixtures only. They are not a real
    # Research bundle, account assertion, execution permit or trading authority.
    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    custody_dir = tmp_path / "custody"
    custody_dir.mkdir(mode=0o700)
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    monkeypatch.setattr(bundle, "CUSTODY_OWNER_UID", os.geteuid())

    research_private_key = Ed25519PrivateKey.generate()
    research_keyring = {
        "schema_version": bundle.KEYRING_VERSION,
        "purpose": bundle.KEY_PURPOSE,
        "keys": [
            {
                "key_id": RESEARCH_KEY_ID,
                "purpose": bundle.KEY_PURPOSE,
                "public_key_base64": public_key_base64(
                    research_private_key
                ),
            }
        ],
    }
    research_keyring_path = write_json(
        private_dir / "research-keyring.json",
        research_keyring,
    )
    research_keyring_sha256 = hashlib.sha256(
        research_keyring_path.read_bytes()
    ).hexdigest()
    artifacts = {
        role: write_bytes(
            artifacts_dir / f"{role}.raw",
            f"synthetic-{role}\n".encode(),
            mode=0o644,
        )
        for role in bundle.ARTIFACT_ROLES
    }
    research_signer_sha256 = hashlib.sha256(
        (
            ROOT
            / "scripts/commodity_c_fast_simnow_sign_research_bundle.py"
        ).read_bytes()
    ).hexdigest()
    custody = bundle.custody_facts(custody_dir)
    research_candidate, research_public_key, _artifact_raw = (
        bundle.prepare_unsigned_bundle(
            research_draft(),
            research_keyring_path,
            artifacts,
            expected_keyring_raw_sha256=research_keyring_sha256,
            expected_signer_sha256=research_signer_sha256,
            expected_custody_root_path_sha256=custody.root_path_sha256,
            expected_custody_identity_sha256=custody.identity_sha256,
            now=RESEARCH_NOW,
        )
    )
    signed_research = bundle.complete_signature(
        research_candidate,
        research_public_key,
        research_private_key,
    )
    research_source = bundle.write_json_create_only_verified(
        private_dir / "signed-research-bundle.json",
        signed_research,
        label="synthetic signed Research bundle",
    )
    verified_research = bundle.verify_signed_bundle(
        research_source,
        research_keyring_path,
        artifacts,
        expected_keyring_raw_sha256=research_keyring_sha256,
        expected_signer_sha256=research_signer_sha256,
        now=RESEARCH_NOW,
    )
    bundle.install_verified_bundle(
        verified_research,
        source_bundle_path=research_source,
        keyring_path=research_keyring_path,
        artifact_paths=artifacts,
        custody_root=custody_dir,
        expected_keyring_raw_sha256=research_keyring_sha256,
        expected_signer_sha256=research_signer_sha256,
        now=RESEARCH_NOW,
    )

    acceptance_private_key = Ed25519PrivateKey.generate()
    acceptance_private_key_path = write_bytes(
        private_dir / "acceptance-private-key",
        private_key_base64(acceptance_private_key),
    )
    acceptance_keyring = {
        "schema_version": acceptance.KEYRING_VERSION,
        "purpose": acceptance.KEY_PURPOSE,
        "keys": [
            {
                "key_id": ACCEPTANCE_KEY_ID,
                "purpose": acceptance.KEY_PURPOSE,
                "public_key_base64": public_key_base64(
                    acceptance_private_key
                ),
            }
        ],
    }
    acceptance_keyring_path = write_json(
        private_dir / "acceptance-keyring.json",
        acceptance_keyring,
    )
    acceptance_keyring_sha256 = hashlib.sha256(
        acceptance_keyring_path.read_bytes()
    ).hexdigest()
    acceptance_signer_sha256 = hashlib.sha256(
        (
            ROOT
            / "scripts/commodity_c_fast_simnow_sign_research_acceptance.py"
        ).read_bytes()
    ).hexdigest()
    return {
        "private_dir": private_dir,
        "custody_dir": custody_dir,
        "artifacts": artifacts,
        "research_private_key": research_private_key,
        "research_keyring": research_keyring,
        "research_keyring_path": research_keyring_path,
        "research_keyring_sha256": research_keyring_sha256,
        "research_signer_sha256": research_signer_sha256,
        "verified_research": verified_research,
        "bundle_id": verified_research.payload["bundle_id"],
        "acceptance_private_key": acceptance_private_key,
        "acceptance_private_key_path": acceptance_private_key_path,
        "acceptance_keyring": acceptance_keyring,
        "acceptance_keyring_path": acceptance_keyring_path,
        "acceptance_keyring_sha256": acceptance_keyring_sha256,
        "acceptance_signer_sha256": acceptance_signer_sha256,
    }


def verification_kwargs(
    inputs: dict,
    *,
    now: datetime = ACCEPTANCE_NOW,
) -> dict:
    return {
        "custody_root": inputs["custody_dir"],
        "research_keyring_path": inputs["research_keyring_path"],
        "acceptance_keyring_path": inputs["acceptance_keyring_path"],
        "artifact_paths": inputs["artifacts"],
        "expected_research_keyring_raw_sha256": inputs[
            "research_keyring_sha256"
        ],
        "expected_research_signer_sha256": inputs[
            "research_signer_sha256"
        ],
        "expected_acceptance_keyring_raw_sha256": inputs[
            "acceptance_keyring_sha256"
        ],
        "expected_acceptance_signer_sha256": inputs[
            "acceptance_signer_sha256"
        ],
        "expected_simnow_account_sha256": ACCOUNT_SHA256,
        "now": now,
    }


def consume_kwargs(
    inputs: dict,
    *,
    clock=None,
) -> dict:
    kwargs = verification_kwargs(inputs)
    kwargs.pop("now")
    kwargs["clock"] = clock or (lambda: ACCEPTANCE_NOW)
    return kwargs


def prepare_acceptance(
    inputs: dict,
    draft: dict | None = None,
    *,
    now: datetime = ACCEPTANCE_NOW,
) -> tuple[dict, object, acceptance.InstalledResearchBundle]:
    return acceptance.prepare_unsigned_acceptance(
        copy.deepcopy(draft or acceptance_draft(inputs["bundle_id"])),
        **verification_kwargs(inputs, now=now),
    )


def signed_acceptance(
    inputs: dict,
    draft: dict | None = None,
) -> tuple[Path, acceptance.VerifiedResearchAcceptance]:
    candidate, public_key, _installed = prepare_acceptance(inputs, draft)
    signed = acceptance.complete_signature(
        candidate,
        public_key,
        inputs["acceptance_private_key"],
    )
    path = bundle.write_json_create_only_verified(
        inputs["private_dir"] / "signed-acceptance.json",
        signed,
        label="synthetic signed Research Acceptance",
    )
    verified = acceptance.verify_signed_acceptance(
        path,
        **verification_kwargs(inputs),
    )
    return path, verified


def test_sign_verify_consume_is_one_shot_and_acceptance_only(
    acceptance_inputs: dict,
) -> None:
    signed_path, verified = signed_acceptance(acceptance_inputs)

    assert verified.payload["selected_products"] == ["ag", "au"]
    assert all(
        row["signed_target_delta"] != 0
        for row in verified.payload["selected_targets"]
    )
    assert verified.payload["acceptance_state"] == acceptance.ACCEPTANCE_STATE
    for field in acceptance.FALSE_AUTHORITY_FIELDS:
        assert verified.payload[field] is False

    consume_path, receipt_path = acceptance.consume_signed_acceptance(
        signed_path,
        **consume_kwargs(acceptance_inputs),
    )
    consume = json.loads(consume_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    acceptance.validate_json_schema(
        consume,
        acceptance.CONSUME_SCHEMA_PATH,
        "synthetic consume marker",
    )
    acceptance.validate_json_schema(
        receipt,
        acceptance.RECEIPT_SCHEMA_PATH,
        "synthetic acceptance receipt",
    )
    assert receipt["acceptance_state"] == acceptance.ACCEPTANCE_STATE
    for field in acceptance.FALSE_AUTHORITY_FIELDS:
        assert consume[field] is False
        assert receipt[field] is False

    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="consume marker already exists",
    ):
        acceptance.consume_signed_acceptance(
            signed_path,
            **consume_kwargs(acceptance_inputs),
        )


@pytest.mark.parametrize("missing_role", ["claim", "bundle", "receipt"])
def test_partial_installed_chain_is_rejected(
    acceptance_inputs: dict,
    missing_role: str,
) -> None:
    bundle_id = acceptance_inputs["bundle_id"]
    names = {
        "claim": f"{bundle_id}.install-claim.json",
        "bundle": f"{bundle_id}.bundle.json",
        "receipt": f"{bundle_id}.install-receipt.json",
    }
    (
        acceptance_inputs["custody_dir"] / names[missing_role]
    ).unlink()
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="unavailable",
    ):
        prepare_acceptance(acceptance_inputs)


@pytest.mark.parametrize("role", ["claim", "receipt"])
def test_install_claim_or_receipt_tampering_is_rejected(
    acceptance_inputs: dict,
    role: str,
) -> None:
    bundle_id = acceptance_inputs["bundle_id"]
    suffix = (
        "install-claim.json"
        if role == "claim"
        else "install-receipt.json"
    )
    path = acceptance_inputs["custody_dir"] / f"{bundle_id}.{suffix}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if role == "claim":
        payload["artifact_index_sha256"] = "f" * 64
    else:
        payload["bundle_raw_sha256"] = "f" * 64
    write_json(path, payload)
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="binding is invalid",
    ):
        prepare_acceptance(acceptance_inputs)


def test_installed_custody_file_mode_is_exact(
    acceptance_inputs: dict,
) -> None:
    bundle_id = acceptance_inputs["bundle_id"]
    claim = (
        acceptance_inputs["custody_dir"]
        / f"{bundle_id}.install-claim.json"
    )
    claim.chmod(0o640)
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="identity or mode is invalid",
    ):
        prepare_acceptance(acceptance_inputs)


def test_raw_artifact_tampering_and_aliases_are_rejected(
    acceptance_inputs: dict,
) -> None:
    signal = acceptance_inputs["artifacts"]["signal_evidence"]
    signal.write_bytes(signal.read_bytes() + b"tampered\n")
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="raw research artifact binding",
    ):
        prepare_acceptance(acceptance_inputs)


def test_extra_missing_and_hardlinked_artifact_roles_are_rejected(
    acceptance_inputs: dict,
) -> None:
    missing = dict(acceptance_inputs["artifacts"])
    missing.pop("signal_evidence")
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="artifact role set is incomplete",
    ):
        acceptance._verify_install_chain(
            bundle_id=acceptance_inputs["bundle_id"],
            custody_root=acceptance_inputs["custody_dir"],
            research_keyring_path=acceptance_inputs[
                "research_keyring_path"
            ],
            artifact_paths=missing,
            expected_research_keyring_raw_sha256=acceptance_inputs[
                "research_keyring_sha256"
            ],
            expected_research_signer_sha256=acceptance_inputs[
                "research_signer_sha256"
            ],
            now=ACCEPTANCE_NOW,
        )

    extra = dict(acceptance_inputs["artifacts"])
    extra["unexpected"] = next(iter(extra.values()))
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="artifact role set is incomplete",
    ):
        acceptance._verify_install_chain(
            bundle_id=acceptance_inputs["bundle_id"],
            custody_root=acceptance_inputs["custody_dir"],
            research_keyring_path=acceptance_inputs[
                "research_keyring_path"
            ],
            artifact_paths=extra,
            expected_research_keyring_raw_sha256=acceptance_inputs[
                "research_keyring_sha256"
            ],
            expected_research_signer_sha256=acceptance_inputs[
                "research_signer_sha256"
            ],
            now=ACCEPTANCE_NOW,
        )

    hardlink_path = (
        next(iter(acceptance_inputs["artifacts"].values())).parent
        / "hardlinked.raw"
    )
    os.link(
        acceptance_inputs["artifacts"]["freeze_contract"],
        hardlink_path,
    )
    hardlinked = dict(acceptance_inputs["artifacts"])
    hardlinked["signal_evidence"] = hardlink_path
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="hardlinks",
    ):
        acceptance._verify_install_chain(
            bundle_id=acceptance_inputs["bundle_id"],
            custody_root=acceptance_inputs["custody_dir"],
            research_keyring_path=acceptance_inputs[
                "research_keyring_path"
            ],
            artifact_paths=hardlinked,
            expected_research_keyring_raw_sha256=acceptance_inputs[
                "research_keyring_sha256"
            ],
            expected_research_signer_sha256=acceptance_inputs[
                "research_signer_sha256"
            ],
            now=ACCEPTANCE_NOW,
        )


@pytest.mark.parametrize(
    "selected",
    [
        [],
        ["ag", "ag"],
        ["ag", "au", "cu"],
        ["not-a-product"],
        ["au", "ag"],
    ],
)
def test_selected_product_scope_is_strict(
    acceptance_inputs: dict,
    selected: list[str],
) -> None:
    draft = acceptance_draft(acceptance_inputs["bundle_id"])
    draft["selected_products"] = selected
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="selected product",
    ):
        prepare_acceptance(acceptance_inputs, draft)


def test_zero_signed_target_delta_is_rejected(
    acceptance_inputs: dict,
) -> None:
    draft = acceptance_draft(acceptance_inputs["bundle_id"])
    bundle_payload = copy.deepcopy(
        acceptance_inputs["verified_research"].payload
    )
    bundle_payload["targets"][0]["target_quantity"] = 0
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="nonzero signed target delta",
    ):
        acceptance._selected_target_bindings(draft, bundle_payload)


def test_account_pin_ttl_execution_day_and_expiry_fail_closed(
    acceptance_inputs: dict,
) -> None:
    mismatched_draft = acceptance_draft(acceptance_inputs["bundle_id"])
    mismatched_draft["expected_simnow_account_sha256"] = "f" * 64
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="account binding mismatch",
    ):
        prepare_acceptance(acceptance_inputs, mismatched_draft)

    signed_path, _verified = signed_acceptance(acceptance_inputs)
    wrong_account = verification_kwargs(acceptance_inputs)
    wrong_account["expected_simnow_account_sha256"] = "f" * 64
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="SimNow account binding mismatch",
    ):
        acceptance.verify_signed_acceptance(
            signed_path,
            **wrong_account,
        )

    ttl_draft = acceptance_draft(acceptance_inputs["bundle_id"])
    ttl_draft["expires_at"] = "2026-07-29T02:16:00+00:00"
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="at most 15 minutes",
    ):
        prepare_acceptance(acceptance_inputs, ttl_draft)

    day_draft = acceptance_draft(acceptance_inputs["bundle_id"])
    day_draft["execution_day"] = "2026-07-30"
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="execution day does not match",
    ):
        prepare_acceptance(acceptance_inputs, day_draft)

    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="not currently valid",
    ):
        acceptance.verify_signed_acceptance(
            signed_path,
            **verification_kwargs(
                acceptance_inputs,
                now=ACCEPTANCE_NOW + timedelta(minutes=8),
            ),
        )
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="not currently valid",
    ):
        acceptance.verify_signed_acceptance(
            signed_path,
            **verification_kwargs(
                acceptance_inputs,
                now=datetime(
                    2026,
                    7,
                    29,
                    2,
                    10,
                    tzinfo=timezone.utc,
                ),
            ),
        )


def test_control_and_research_key_material_must_be_disjoint(
    acceptance_inputs: dict,
) -> None:
    reused = {
        "schema_version": acceptance.KEYRING_VERSION,
        "purpose": acceptance.KEY_PURPOSE,
        "keys": [
            {
                "key_id": ACCEPTANCE_KEY_ID,
                "purpose": acceptance.KEY_PURPOSE,
                "public_key_base64": acceptance_inputs[
                    "research_keyring"
                ]["keys"][0]["public_key_base64"],
            }
        ],
    }
    reused_path = write_json(
        acceptance_inputs["private_dir"] / "reused-keyring.json",
        reused,
    )
    kwargs = verification_kwargs(acceptance_inputs)
    kwargs["acceptance_keyring_path"] = reused_path
    kwargs["expected_acceptance_keyring_raw_sha256"] = hashlib.sha256(
        reused_path.read_bytes()
    ).hexdigest()
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="reuses Research key material",
    ):
        acceptance.prepare_unsigned_acceptance(
            acceptance_draft(acceptance_inputs["bundle_id"]),
            **kwargs,
        )


def test_control_keyring_pin_purpose_and_signature_fail_closed(
    acceptance_inputs: dict,
) -> None:
    kwargs = verification_kwargs(acceptance_inputs)
    kwargs["expected_acceptance_keyring_raw_sha256"] = "f" * 64
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="raw pin binding mismatch",
    ):
        acceptance.prepare_unsigned_acceptance(
            acceptance_draft(acceptance_inputs["bundle_id"]),
            **kwargs,
        )

    wrong_purpose = copy.deepcopy(acceptance_inputs["acceptance_keyring"])
    wrong_purpose["purpose"] = "wrong-purpose"
    wrong_path = write_json(
        acceptance_inputs["private_dir"] / "wrong-purpose-keyring.json",
        wrong_purpose,
    )
    kwargs = verification_kwargs(acceptance_inputs)
    kwargs["acceptance_keyring_path"] = wrong_path
    kwargs["expected_acceptance_keyring_raw_sha256"] = hashlib.sha256(
        wrong_path.read_bytes()
    ).hexdigest()
    with pytest.raises(
        acceptance.OneShotError,
        match="schema validation failed",
    ):
        acceptance.prepare_unsigned_acceptance(
            acceptance_draft(acceptance_inputs["bundle_id"]),
            **kwargs,
        )

    signed_path, _verified = signed_acceptance(acceptance_inputs)
    tampered = json.loads(signed_path.read_text(encoding="utf-8"))
    signature_text = tampered["signature"]
    tampered["signature"] = (
        ("A" if signature_text[0] != "A" else "B")
        + signature_text[1:]
    )
    tampered_path = write_json(
        acceptance_inputs["private_dir"] / "tampered-acceptance.json",
        tampered,
    )
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="signature is invalid",
    ):
        acceptance.verify_signed_acceptance(
            tampered_path,
            **verification_kwargs(acceptance_inputs),
        )


def test_any_execution_authority_fails_before_signing(
    acceptance_inputs: dict,
) -> None:
    for field in acceptance.FALSE_AUTHORITY_FIELDS:
        draft = acceptance_draft(acceptance_inputs["bundle_id"])
        draft[field] = True
        with pytest.raises(
            (
                acceptance.ResearchAcceptanceError,
                acceptance.OneShotError,
            ),
            match="must remain false|schema validation failed",
        ):
            prepare_acceptance(acceptance_inputs, draft)


def test_concurrent_double_consume_has_one_winner(
    acceptance_inputs: dict,
) -> None:
    signed_path, _verified = signed_acceptance(acceptance_inputs)

    def attempt() -> str:
        try:
            acceptance.consume_signed_acceptance(
                signed_path,
                **consume_kwargs(acceptance_inputs),
            )
        except acceptance.ResearchAcceptanceError:
            return "rejected"
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: attempt(), range(2)))
    assert sorted(outcomes) == ["consumed", "rejected"]


def test_same_research_bundle_cannot_use_a_second_acceptance(
    acceptance_inputs: dict,
) -> None:
    first_path, first = signed_acceptance(acceptance_inputs)
    acceptance.consume_signed_acceptance(
        first_path,
        **consume_kwargs(acceptance_inputs),
    )

    second_draft = acceptance_draft(acceptance_inputs["bundle_id"])
    second_draft["human_signature"] = (
        "different-human-review-same-research-bundle"
    )
    candidate, public_key, _installed = prepare_acceptance(
        acceptance_inputs,
        second_draft,
    )
    second_signed = acceptance.complete_signature(
        candidate,
        public_key,
        acceptance_inputs["acceptance_private_key"],
    )
    second_path = bundle.write_json_create_only_verified(
        acceptance_inputs["private_dir"] / "second-acceptance.json",
        second_signed,
        label="second synthetic Research Acceptance",
    )
    assert candidate["acceptance_id"] != first.payload["acceptance_id"]
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="consume marker already exists",
    ):
        acceptance.consume_signed_acceptance(
            second_path,
            **consume_kwargs(acceptance_inputs),
        )


def test_marker_without_receipt_is_irreversible_fail_closed(
    acceptance_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed_path, verified = signed_acceptance(acceptance_inputs)
    real_write = bundle._custody_write_create_only
    writes = 0

    def fail_receipt(*args, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise bundle.ResearchBundleError(
                "synthetic receipt write failure"
            )
        return real_write(*args, **kwargs)

    monkeypatch.setattr(bundle, "_custody_write_create_only", fail_receipt)
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="synthetic receipt write failure",
    ):
        acceptance.consume_signed_acceptance(
            signed_path,
            **consume_kwargs(acceptance_inputs),
        )
    consume_name, receipt_name = acceptance._consume_filenames(
        verified.payload["research_bundle_id"]
    )
    assert (acceptance_inputs["custody_dir"] / consume_name).is_file()
    assert not (acceptance_inputs["custody_dir"] / receipt_name).exists()

    monkeypatch.setattr(
        bundle,
        "_custody_write_create_only",
        real_write,
    )
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="consume marker already exists",
    ):
        acceptance.consume_signed_acceptance(
            signed_path,
            **consume_kwargs(acceptance_inputs),
        )


def test_ttl_crossed_after_marker_leaves_no_receipt(
    acceptance_inputs: dict,
) -> None:
    signed_path, verified = signed_acceptance(acceptance_inputs)
    times = iter(
        [
            datetime(2026, 7, 29, 2, 9, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 9, 30, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 9, 40, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 9, 50, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 10, tzinfo=timezone.utc),
        ]
    )
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="not currently valid",
    ):
        acceptance.consume_signed_acceptance(
            signed_path,
            **consume_kwargs(acceptance_inputs, clock=lambda: next(times)),
        )
    consume_name, receipt_name = acceptance._consume_filenames(
        verified.payload["research_bundle_id"]
    )
    assert (acceptance_inputs["custody_dir"] / consume_name).is_file()
    assert not (acceptance_inputs["custody_dir"] / receipt_name).exists()


def test_same_length_artifact_drift_at_final_snapshot_leaves_no_receipt(
    acceptance_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed_path, verified = signed_acceptance(acceptance_inputs)
    real_final_check = acceptance._assert_exact_snapshot_current
    artifact = acceptance_inputs["artifacts"]["signal_evidence"]

    def mutate_then_check(*args, **kwargs):
        raw = artifact.read_bytes()
        replacement = (b"X" if raw[:1] != b"X" else b"Y") + raw[1:]
        assert len(replacement) == len(raw)
        artifact.write_bytes(replacement)
        return real_final_check(*args, **kwargs)

    monkeypatch.setattr(
        acceptance,
        "_assert_exact_snapshot_current",
        mutate_then_check,
    )
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="Research artifacts changed",
    ):
        acceptance.consume_signed_acceptance(
            signed_path,
            **consume_kwargs(acceptance_inputs),
        )
    consume_name, receipt_name = acceptance._consume_filenames(
        verified.payload["research_bundle_id"]
    )
    assert (acceptance_inputs["custody_dir"] / consume_name).is_file()
    assert not (acceptance_inputs["custody_dir"] / receipt_name).exists()


def test_receipt_without_marker_fails_closed(
    acceptance_inputs: dict,
) -> None:
    signed_path, verified = signed_acceptance(acceptance_inputs)
    _consume_name, receipt_name = acceptance._consume_filenames(
        verified.payload["research_bundle_id"]
    )
    write_bytes(
        acceptance_inputs["custody_dir"] / receipt_name,
        b"irreversible-orphan-receipt\n",
    )
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="receipt exists without a consume marker",
    ):
        acceptance.consume_signed_acceptance(
            signed_path,
            **consume_kwargs(acceptance_inputs),
        )


def test_signer_does_not_read_private_key_after_public_failure(
    acceptance_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = acceptance_draft(acceptance_inputs["bundle_id"])
    invalid["order_submission_authorized"] = True
    draft_path = write_json(
        acceptance_inputs["private_dir"] / "invalid-acceptance-draft.json",
        invalid,
    )
    args = argparse.Namespace(
        input=draft_path,
        output=acceptance_inputs["private_dir"] / "must-not-exist.json",
        private_key_file=acceptance_inputs["acceptance_private_key_path"],
        custody_root=acceptance_inputs["custody_dir"],
        research_trusted_keyring=acceptance_inputs[
            "research_keyring_path"
        ],
        expected_research_keyring_raw_sha256=acceptance_inputs[
            "research_keyring_sha256"
        ],
        expected_research_signer_sha256=acceptance_inputs[
            "research_signer_sha256"
        ],
        acceptance_trusted_keyring=acceptance_inputs[
            "acceptance_keyring_path"
        ],
        expected_acceptance_keyring_raw_sha256=acceptance_inputs[
            "acceptance_keyring_sha256"
        ],
        expected_acceptance_signer_sha256=acceptance_inputs[
            "acceptance_signer_sha256"
        ],
        expected_simnow_account_sha256=ACCOUNT_SHA256,
        **acceptance_inputs["artifacts"],
    )
    private_key_read = False

    def forbidden_private_key_read(_path: Path):
        nonlocal private_key_read
        private_key_read = True
        raise AssertionError("private key was read before public validation")

    monkeypatch.setattr(signer, "parse_args", lambda: args)
    monkeypatch.setattr(signer, "utc_now", lambda: ACCEPTANCE_NOW)
    monkeypatch.setattr(
        signer,
        "load_private_key",
        forbidden_private_key_read,
    )
    assert signer.main() == 2
    assert private_key_read is False
    assert not args.output.exists()


def test_signer_self_pin_fails_before_private_key_read(
    acceptance_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft_path = write_json(
        acceptance_inputs["private_dir"] / "valid-acceptance-draft.json",
        acceptance_draft(acceptance_inputs["bundle_id"]),
    )
    args = argparse.Namespace(
        input=draft_path,
        output=acceptance_inputs["private_dir"] / "must-not-exist-pin.json",
        private_key_file=acceptance_inputs["acceptance_private_key_path"],
        custody_root=acceptance_inputs["custody_dir"],
        research_trusted_keyring=acceptance_inputs[
            "research_keyring_path"
        ],
        expected_research_keyring_raw_sha256=acceptance_inputs[
            "research_keyring_sha256"
        ],
        expected_research_signer_sha256=acceptance_inputs[
            "research_signer_sha256"
        ],
        acceptance_trusted_keyring=acceptance_inputs[
            "acceptance_keyring_path"
        ],
        expected_acceptance_keyring_raw_sha256=acceptance_inputs[
            "acceptance_keyring_sha256"
        ],
        expected_acceptance_signer_sha256="f" * 64,
        expected_simnow_account_sha256=ACCOUNT_SHA256,
        **acceptance_inputs["artifacts"],
    )
    private_key_read = False

    def forbidden_private_key_read(_path: Path):
        nonlocal private_key_read
        private_key_read = True
        raise AssertionError("private key was read after signer-pin failure")

    monkeypatch.setattr(signer, "parse_args", lambda: args)
    monkeypatch.setattr(signer, "utc_now", lambda: ACCEPTANCE_NOW)
    monkeypatch.setattr(
        signer,
        "load_private_key",
        forbidden_private_key_read,
    )
    assert signer.main() == 2
    assert private_key_read is False
    assert not args.output.exists()


def test_signer_crossing_expiry_never_reads_private_key(
    acceptance_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft_path = write_json(
        acceptance_inputs["private_dir"] / "cross-ttl-draft.json",
        acceptance_draft(acceptance_inputs["bundle_id"]),
    )
    args = argparse.Namespace(
        input=draft_path,
        output=acceptance_inputs["private_dir"] / "cross-ttl-output.json",
        private_key_file=acceptance_inputs["acceptance_private_key_path"],
        custody_root=acceptance_inputs["custody_dir"],
        research_trusted_keyring=acceptance_inputs[
            "research_keyring_path"
        ],
        expected_research_keyring_raw_sha256=acceptance_inputs[
            "research_keyring_sha256"
        ],
        expected_research_signer_sha256=acceptance_inputs[
            "research_signer_sha256"
        ],
        acceptance_trusted_keyring=acceptance_inputs[
            "acceptance_keyring_path"
        ],
        expected_acceptance_keyring_raw_sha256=acceptance_inputs[
            "acceptance_keyring_sha256"
        ],
        expected_acceptance_signer_sha256=acceptance_inputs[
            "acceptance_signer_sha256"
        ],
        expected_simnow_account_sha256=ACCOUNT_SHA256,
        **acceptance_inputs["artifacts"],
    )
    times = iter(
        [
            datetime(2026, 7, 29, 2, 9, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 10, tzinfo=timezone.utc),
        ]
    )
    private_key_read = False

    def forbidden_private_key_read(_path: Path):
        nonlocal private_key_read
        private_key_read = True
        raise AssertionError("private key was read after TTL expiry")

    monkeypatch.setattr(signer, "parse_args", lambda: args)
    monkeypatch.setattr(signer, "utc_now", lambda: next(times))
    monkeypatch.setattr(
        signer,
        "load_private_key",
        forbidden_private_key_read,
    )
    assert signer.main() == 2
    assert private_key_read is False
    assert not args.output.exists()


def test_signer_rechecks_expiry_immediately_before_signature(
    acceptance_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft_path = write_json(
        acceptance_inputs["private_dir"] / "pre-sign-ttl-draft.json",
        acceptance_draft(acceptance_inputs["bundle_id"]),
    )
    args = argparse.Namespace(
        input=draft_path,
        output=acceptance_inputs["private_dir"] / "pre-sign-output.json",
        private_key_file=acceptance_inputs["acceptance_private_key_path"],
        custody_root=acceptance_inputs["custody_dir"],
        research_trusted_keyring=acceptance_inputs[
            "research_keyring_path"
        ],
        expected_research_keyring_raw_sha256=acceptance_inputs[
            "research_keyring_sha256"
        ],
        expected_research_signer_sha256=acceptance_inputs[
            "research_signer_sha256"
        ],
        acceptance_trusted_keyring=acceptance_inputs[
            "acceptance_keyring_path"
        ],
        expected_acceptance_keyring_raw_sha256=acceptance_inputs[
            "acceptance_keyring_sha256"
        ],
        expected_acceptance_signer_sha256=acceptance_inputs[
            "acceptance_signer_sha256"
        ],
        expected_simnow_account_sha256=ACCOUNT_SHA256,
        **acceptance_inputs["artifacts"],
    )
    times = iter(
        [
            datetime(2026, 7, 29, 2, 9, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 9, 30, tzinfo=timezone.utc),
            datetime(2026, 7, 29, 2, 10, tzinfo=timezone.utc),
        ]
    )
    signature_attempted = False

    def forbidden_signature(*_args, **_kwargs):
        nonlocal signature_attempted
        signature_attempted = True
        raise AssertionError("signature attempted after TTL expiry")

    monkeypatch.setattr(signer, "parse_args", lambda: args)
    monkeypatch.setattr(signer, "utc_now", lambda: next(times))
    monkeypatch.setattr(
        signer,
        "load_private_key",
        lambda _path: acceptance_inputs["acceptance_private_key"],
    )
    monkeypatch.setattr(signer, "complete_signature", forbidden_signature)
    assert signer.main() == 2
    assert signature_attempted is False
    assert not args.output.exists()


def test_pending_template_and_official_forward_shape_are_rejected(
    acceptance_inputs: dict,
) -> None:
    template_path = (
        ROOT
        / "docs/operations/"
        "c-fast-simnow-research-acceptance-v1.template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    with pytest.raises(
        acceptance.ResearchAcceptanceError,
        match="INVALID/PENDING",
    ):
        acceptance.prepare_unsigned_acceptance(
            template,
            **verification_kwargs(acceptance_inputs),
        )
    with pytest.raises(
        acceptance.OneShotError,
        match="schema validation failed",
    ):
        acceptance.validate_json_schema(
            template,
            acceptance.ACCEPTANCE_SCHEMA_PATH,
            "INVALID Research Acceptance template",
        )

    official_forward = {
        "schema_version": (
            "commodity_c_fast_cross_section_neutral_shadow_v1"
        ),
        "execution_lane": "official_forward",
        "snapshot_id": "official-forward-snapshot",
    }
    path = write_json(
        acceptance_inputs["private_dir"] / "official-forward.json",
        official_forward,
    )
    with pytest.raises(
        (
            acceptance.ResearchAcceptanceError,
            acceptance.OneShotError,
        ),
        match="schema validation failed|identity is invalid",
    ):
        acceptance.verify_signed_acceptance(
            path,
            **verification_kwargs(acceptance_inputs),
        )


def test_acceptance_tools_have_no_execution_runtime_imports() -> None:
    verifier_source = (
        ROOT
        / "scripts/commodity_c_fast_simnow_research_acceptance.py"
    ).read_text(encoding="utf-8")
    signer_source = (
        ROOT
        / "scripts/commodity_c_fast_simnow_sign_research_acceptance.py"
    ).read_text(encoding="utf-8")
    assert (
        "commodity_c_fast_simnow_sign_research_acceptance"
        not in verifier_source
    )
    assert "SIGNER_PATH" not in verifier_source
    for source in (verifier_source, signer_source):
        for forbidden in (
            "backend.app.core.config",
            "backend.app.api",
            "TradeService",
            "RpcServer",
            "commodity_simnow",
            "commodity_c_fast_shadow",
            "send_order",
            "cancel_order",
        ):
            assert forbidden not in source


def test_all_acceptance_schemas_are_strict_draft_2020_12() -> None:
    for schema_path in (
        acceptance.ACCEPTANCE_SCHEMA_PATH,
        acceptance.KEYRING_SCHEMA_PATH,
        acceptance.CONSUME_SCHEMA_PATH,
        acceptance.RECEIPT_SCHEMA_PATH,
    ):
        payload = json.loads(schema_path.read_text(encoding="utf-8"))
        assert payload["$schema"].endswith("/draft/2020-12/schema")
        assert payload["additionalProperties"] is False
        Draft202012Validator.check_schema(payload)
