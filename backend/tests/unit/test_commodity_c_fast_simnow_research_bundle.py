from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import date, datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
import pytest

from app.core.commodity_strategy_identity import (
    COMMODITY_FROZEN_SECTOR_MAP_V1,
    COMMODITY_FROZEN_SECTOR_MAP_V1_ID,
)

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_simnow_research_bundle as bundle  # noqa: E402
import commodity_c_fast_simnow_sign_research_bundle as signer  # noqa: E402


NOW = datetime(2026, 7, 29, 2, 1, tzinfo=timezone.utc)
EXECUTION_DAY = date(2026, 7, 29)
FOLLOWING_DAY = date(2026, 7, 30)
LAST_TRADING_DAY = date(2026, 12, 15)
KEY_ID = "c-fast-research-key-a01"
ZERO_SHA256 = "0" * 64
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


def test_bundle_verifier_uses_frozen_cross_plane_sector_map_identity() -> None:
    assert bundle.SECTOR_MAP_ID == COMMODITY_FROZEN_SECTOR_MAP_V1_ID
    assert bundle.SECTOR_MAP == dict(COMMODITY_FROZEN_SECTOR_MAP_V1)


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


def draft_payload() -> dict:
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
        "signer_key_id": KEY_ID,
    }
    for field in bundle.FALSE_AUTHORITY_FIELDS:
        payload[field] = False
    return payload


@pytest.fixture
def research_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    # These are synthetic cryptographic and market fixtures only. They do not
    # represent a real C_FAST bundle, current PIT-main assertion or authority.
    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    installed_dir = tmp_path / "installed"
    installed_dir.mkdir(mode=0o700)
    monkeypatch.setattr(bundle, "CUSTODY_OWNER_UID", os.geteuid())
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()

    private_key = Ed25519PrivateKey.generate()
    private_key_path = write_bytes(
        private_dir / "signing-key",
        private_key_base64(private_key),
    )
    keyring = {
        "schema_version": bundle.KEYRING_VERSION,
        "purpose": bundle.KEY_PURPOSE,
        "keys": [
            {
                "key_id": KEY_ID,
                "purpose": bundle.KEY_PURPOSE,
                "public_key_base64": public_key_base64(private_key),
            }
        ],
    }
    keyring_path = write_json(private_dir / "keyring.json", keyring)
    keyring_raw_sha256 = hashlib.sha256(keyring_path.read_bytes()).hexdigest()
    artifacts = {
        role: write_bytes(
            artifacts_dir / f"{role}.raw",
            f"synthetic-{role}\n".encode(),
            mode=0o644,
        )
        for role in bundle.ARTIFACT_ROLES
    }
    signer_sha256 = hashlib.sha256(
        (
            ROOT
            / "scripts/commodity_c_fast_simnow_sign_research_bundle.py"
        ).read_bytes()
    ).hexdigest()
    custody = bundle.custody_facts(installed_dir)
    return {
        "private_dir": private_dir,
        "installed_dir": installed_dir,
        "private_key": private_key,
        "private_key_path": private_key_path,
        "keyring": keyring,
        "keyring_path": keyring_path,
        "keyring_raw_sha256": keyring_raw_sha256,
        "signer_sha256": signer_sha256,
        "custody_root_path_sha256": custody.root_path_sha256,
        "custody_identity_sha256": custody.identity_sha256,
        "artifacts": artifacts,
    }


def prepare(
    inputs: dict,
    draft: dict | None = None,
    *,
    now: datetime = NOW,
) -> tuple[dict, object, dict[str, bytes]]:
    return bundle.prepare_unsigned_bundle(
        copy.deepcopy(draft or draft_payload()),
        inputs["keyring_path"],
        inputs["artifacts"],
        expected_keyring_raw_sha256=inputs["keyring_raw_sha256"],
        expected_signer_sha256=inputs["signer_sha256"],
        expected_custody_root_path_sha256=inputs[
            "custody_root_path_sha256"
        ],
        expected_custody_identity_sha256=inputs[
            "custody_identity_sha256"
        ],
        now=now,
    )


def signed_bundle(inputs: dict) -> tuple[Path, bundle.VerifiedResearchBundle]:
    candidate, public_key, _ = prepare(inputs)
    signed = bundle.complete_signature(
        candidate,
        public_key,
        inputs["private_key"],
    )
    path = bundle.write_json_create_only_verified(
        inputs["private_dir"] / "signed.json",
        signed,
        label="synthetic signed research bundle",
    )
    verified = bundle.verify_signed_bundle(
        path,
        inputs["keyring_path"],
        inputs["artifacts"],
        expected_keyring_raw_sha256=inputs["keyring_raw_sha256"],
        expected_signer_sha256=inputs["signer_sha256"],
        now=NOW,
    )
    return path, verified


def test_sign_verify_install_is_exact_create_only_and_non_authoritative(
    research_inputs: dict,
) -> None:
    source_path, verified = signed_bundle(research_inputs)

    installed, receipt = bundle.install_verified_bundle(
        verified,
        source_bundle_path=source_path,
        keyring_path=research_inputs["keyring_path"],
        artifact_paths=research_inputs["artifacts"],
        custody_root=research_inputs["installed_dir"],
        expected_keyring_raw_sha256=(
            research_inputs["keyring_raw_sha256"]
        ),
        expected_signer_sha256=research_inputs["signer_sha256"],
        now=NOW,
    )

    assert installed.read_bytes() == source_path.read_bytes()
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    bundle.validate_json_schema(
        receipt_payload,
        bundle.RECEIPT_SCHEMA_PATH,
        "synthetic install receipt",
    )
    assert receipt_payload["countable_forward"] is False
    assert receipt_payload["simnow_execution_authorized"] is False
    assert receipt_payload["runtime_activation_authorized"] is False
    assert receipt_payload["order_submission_authorized"] is False
    bundle_id = verified.payload["bundle_id"]
    assert installed.name == f"{bundle_id}.bundle.json"
    assert receipt.name == f"{bundle_id}.install-receipt.json"
    assert (
        research_inputs["installed_dir"]
        / f"{bundle_id}.install-claim.json"
    ).is_file()

    with pytest.raises(bundle.ResearchBundleError, match="already exists"):
        bundle.install_verified_bundle(
            verified,
            source_bundle_path=source_path,
            keyring_path=research_inputs["keyring_path"],
            artifact_paths=research_inputs["artifacts"],
            custody_root=research_inputs["installed_dir"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )


def test_artifact_roles_reject_same_path_and_hardlink_alias(
    research_inputs: dict,
) -> None:
    same_path = dict(research_inputs["artifacts"])
    same_path["signal_evidence"] = same_path["freeze_contract"]
    with pytest.raises(
        bundle.ResearchBundleError,
        match="distinct paths and inodes",
    ):
        bundle._read_artifacts(same_path)

    hardlink_path = (
        research_inputs["artifacts"]["signal_evidence"].parent
        / "signal-hardlink.raw"
    )
    os.link(research_inputs["artifacts"]["freeze_contract"], hardlink_path)
    hardlink = dict(research_inputs["artifacts"])
    hardlink["signal_evidence"] = hardlink_path
    with pytest.raises(
        bundle.ResearchBundleError,
        match="distinct paths and inodes",
    ):
        bundle._read_artifacts(hardlink)


def test_artifact_set_identity_is_stable_across_complete_read(
    research_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_read = bundle.read_regular_file_strict
    calls = 0
    first = research_inputs["artifacts"]["freeze_contract"]

    def mutating_read(*args, **kwargs):
        nonlocal calls
        raw = real_read(*args, **kwargs)
        calls += 1
        if calls == 2:
            first.write_bytes(first.read_bytes())
        return raw

    monkeypatch.setattr(bundle, "read_regular_file_strict", mutating_read)
    with pytest.raises(
        bundle.ResearchBundleError,
        match="changed while being read",
    ):
        bundle._read_artifacts(research_inputs["artifacts"])


def test_same_signed_bundle_cannot_install_to_different_custody(
    research_inputs: dict,
    tmp_path: Path,
) -> None:
    source_path, verified = signed_bundle(research_inputs)
    other = tmp_path / "other-custody"
    other.mkdir(mode=0o700)

    with pytest.raises(
        bundle.ResearchBundleError,
        match="signed custody root path binding mismatch",
    ):
        bundle.install_verified_bundle(
            verified,
            source_bundle_path=source_path,
            keyring_path=research_inputs["keyring_path"],
            artifact_paths=research_inputs["artifacts"],
            custody_root=other,
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )


def test_concurrent_double_install_has_exactly_one_claim_winner(
    research_inputs: dict,
) -> None:
    source_path, verified = signed_bundle(research_inputs)

    def attempt() -> str:
        try:
            bundle.install_verified_bundle(
                verified,
                source_bundle_path=source_path,
                keyring_path=research_inputs["keyring_path"],
                artifact_paths=research_inputs["artifacts"],
                custody_root=research_inputs["installed_dir"],
                expected_keyring_raw_sha256=(
                    research_inputs["keyring_raw_sha256"]
                ),
                expected_signer_sha256=research_inputs["signer_sha256"],
                now=NOW,
            )
        except bundle.ResearchBundleError:
            return "rejected"
        return "installed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: attempt(), range(2)))
    assert sorted(outcomes) == ["installed", "rejected"]


def test_custody_directory_replacement_after_claim_fails_closed(
    research_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path, verified = signed_bundle(research_inputs)
    real_write = bundle._custody_write_create_only
    replaced = False

    def replacing_write(*args, **kwargs):
        nonlocal replaced
        output = real_write(*args, **kwargs)
        if kwargs["label"].endswith("install claim") and not replaced:
            replaced = True
            root = research_inputs["installed_dir"]
            moved = root.with_name(root.name + "-replaced")
            root.rename(moved)
            root.mkdir(mode=0o700)
        return output

    monkeypatch.setattr(bundle, "_custody_write_create_only", replacing_write)
    with pytest.raises(
        bundle.ResearchBundleError,
        match="identity changed during installation",
    ):
        bundle.install_verified_bundle(
            verified,
            source_bundle_path=source_path,
            keyring_path=research_inputs["keyring_path"],
            artifact_paths=research_inputs["artifacts"],
            custody_root=research_inputs["installed_dir"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )
    assert replaced is True


def test_verifier_succeeds_when_signer_file_is_not_present(
    research_inputs: dict,
    tmp_path: Path,
) -> None:
    source_path, _ = signed_bundle(research_inputs)
    isolated_root = tmp_path / "isolated-verifier"
    isolated_scripts = isolated_root / "scripts"
    isolated_schemas = isolated_root / "docs/schemas"
    isolated_scripts.mkdir(parents=True)
    isolated_schemas.mkdir(parents=True)

    verifier_copy = (
        isolated_scripts / "commodity_c_fast_simnow_research_bundle.py"
    )
    shutil.copyfile(
        ROOT / "scripts/commodity_c_fast_simnow_research_bundle.py",
        verifier_copy,
    )
    for schema_path in (
        bundle.BUNDLE_SCHEMA_PATH,
        bundle.KEYRING_SCHEMA_PATH,
        bundle.RECEIPT_SCHEMA_PATH,
    ):
        shutil.copyfile(schema_path, isolated_schemas / schema_path.name)
    assert not (
        isolated_scripts
        / "commodity_c_fast_simnow_sign_research_bundle.py"
    ).exists()

    module_name = "isolated_c_fast_simnow_research_bundle"
    spec = importlib.util.spec_from_file_location(module_name, verifier_copy)
    assert spec is not None and spec.loader is not None
    isolated = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = isolated
    try:
        spec.loader.exec_module(isolated)
        verified = isolated.verify_signed_bundle(
            source_path,
            research_inputs["keyring_path"],
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )
    finally:
        sys.modules.pop(module_name, None)

    assert verified.payload["signer_sha256"] == research_inputs["signer_sha256"]


def test_verifier_rejects_wrong_independent_signer_pin(
    research_inputs: dict,
) -> None:
    source_path, _ = signed_bundle(research_inputs)
    with pytest.raises(
        bundle.ResearchBundleError,
        match="signer source binding mismatch",
    ):
        bundle.verify_signed_bundle(
            source_path,
            research_inputs["keyring_path"],
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256="f" * 64,
            now=NOW,
        )


def test_verify_and_install_cli_require_independent_signer_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for command in ("verify", "install"):
        argv = [
            "commodity_c_fast_simnow_research_bundle.py",
            command,
            "--bundle",
            "/private/bundle.json",
            "--trusted-keyring",
            "/private/keyring.json",
            "--expected-trusted-keyring-raw-sha256",
            "a" * 64,
        ]
        for role in bundle.ARTIFACT_ROLES:
            argv.extend(
                [
                    f"--{role.replace('_', '-')}",
                    f"/sealed/{role}.raw",
                ]
            )
        if command == "install":
            argv.extend(
                [
                    "--custody-root",
                    "/private/installed",
                ]
            )
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as exc_info:
            bundle.parse_args()
        assert exc_info.value.code == 2

        argv.extend(["--expected-signer-sha256", "b" * 64])
        parsed = bundle.parse_args()
        assert parsed.expected_signer_sha256 == "b" * 64


def test_invalid_pending_template_cannot_be_signed(
    research_inputs: dict,
) -> None:
    template_path = (
        ROOT
        / "docs/operations/c-fast-simnow-research-bundle-v1.template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    with pytest.raises(
        bundle.ResearchBundleError,
        match="INVALID/PENDING template",
    ):
        prepare(research_inputs, template)
    with pytest.raises(bundle.OneShotError):
        bundle.validate_json_schema(
            template,
            bundle.BUNDLE_SCHEMA_PATH,
            "INVALID research-bundle template",
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda draft: draft.__setitem__("trading_authorized", True),
            "schema validation failed",
        ),
        (
            lambda draft: draft["targets"][0].__setitem__(
                "unexpected_field",
                "forbidden",
            ),
            "schema validation failed",
        ),
        (
            lambda draft: draft["targets"].__setitem__(
                9,
                copy.deepcopy(draft["targets"][0]),
            ),
            "target universe",
        ),
        (
            lambda draft: draft["targets"][0].__setitem__(
                "raw_risk_score",
                123.0,
            ),
            "raw risk score formula",
        ),
        (
            lambda draft: draft["targets"][0].__setitem__(
                "pit_main_dte",
                draft["targets"][0]["pit_main_dte"] + 1,
            ),
            "DTE arithmetic",
        ),
    ],
)
def test_public_validation_rejects_schema_formula_and_target_drift(
    research_inputs: dict,
    mutate,
    message: str,
) -> None:
    draft = draft_payload()
    mutate(draft)
    with pytest.raises(
        (bundle.ResearchBundleError, bundle.OneShotError),
        match=message,
    ):
        prepare(research_inputs, draft)


def test_raw_artifact_and_signature_tampering_fail_closed(
    research_inputs: dict,
) -> None:
    source_path, _ = signed_bundle(research_inputs)
    source_payload = json.loads(source_path.read_text(encoding="utf-8"))
    reformatted_path = research_inputs["private_dir"] / "reformatted.json"
    reformatted_path.write_text(
        json.dumps(source_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    reformatted_path.chmod(0o600)
    with pytest.raises(
        bundle.ResearchBundleError,
        match="exact canonical JSON bytes",
    ):
        bundle.verify_signed_bundle(
            reformatted_path,
            research_inputs["keyring_path"],
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )

    artifact = research_inputs["artifacts"]["signal_evidence"]
    artifact.write_bytes(artifact.read_bytes() + b"tampered\n")
    with pytest.raises(
        bundle.ResearchBundleError,
        match="raw research artifact binding",
    ):
        bundle.verify_signed_bundle(
            source_path,
            research_inputs["keyring_path"],
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )

    artifact.write_bytes(b"synthetic-signal_evidence\n")
    tampered = json.loads(source_path.read_text(encoding="utf-8"))
    tampered["signature"] = bundle.PLACEHOLDER_SIGNATURE
    tampered_path = write_json(
        research_inputs["private_dir"] / "tampered-signature.json",
        tampered,
    )
    with pytest.raises(
        bundle.ResearchBundleError,
        match="signature is invalid",
    ):
        bundle.verify_signed_bundle(
            tampered_path,
            research_inputs["keyring_path"],
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=(
                research_inputs["keyring_raw_sha256"]
            ),
            expected_signer_sha256=research_inputs["signer_sha256"],
            now=NOW,
        )


def test_keyring_raw_pin_purpose_and_duplicate_material_fail_closed(
    research_inputs: dict,
) -> None:
    with pytest.raises(
        bundle.ResearchBundleError,
        match="raw pin",
    ):
        bundle.prepare_unsigned_bundle(
            draft_payload(),
            research_inputs["keyring_path"],
            research_inputs["artifacts"],
            expected_keyring_raw_sha256="f" * 64,
            expected_signer_sha256=research_inputs["signer_sha256"],
            expected_custody_root_path_sha256=research_inputs[
                "custody_root_path_sha256"
            ],
            expected_custody_identity_sha256=research_inputs[
                "custody_identity_sha256"
            ],
            now=NOW,
        )

    wrong_purpose = copy.deepcopy(research_inputs["keyring"])
    wrong_purpose["purpose"] = "wrong"
    wrong_path = write_json(
        research_inputs["private_dir"] / "wrong-purpose.json",
        wrong_purpose,
    )
    with pytest.raises(bundle.OneShotError, match="schema validation failed"):
        bundle.prepare_unsigned_bundle(
            draft_payload(),
            wrong_path,
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=hashlib.sha256(
                wrong_path.read_bytes()
            ).hexdigest(),
            expected_signer_sha256=research_inputs["signer_sha256"],
            expected_custody_root_path_sha256=research_inputs[
                "custody_root_path_sha256"
            ],
            expected_custody_identity_sha256=research_inputs[
                "custody_identity_sha256"
            ],
            now=NOW,
        )

    duplicate = copy.deepcopy(research_inputs["keyring"])
    duplicate["keys"].append(
        {
            **copy.deepcopy(duplicate["keys"][0]),
            "key_id": "c-fast-research-key-a02",
        }
    )
    duplicate_path = write_json(
        research_inputs["private_dir"] / "duplicate-key.json",
        duplicate,
    )
    with pytest.raises(
        bundle.ResearchBundleError,
        match="reuses public-key material",
    ):
        bundle.prepare_unsigned_bundle(
            draft_payload(),
            duplicate_path,
            research_inputs["artifacts"],
            expected_keyring_raw_sha256=hashlib.sha256(
                duplicate_path.read_bytes()
            ).hexdigest(),
            expected_signer_sha256=research_inputs["signer_sha256"],
            expected_custody_root_path_sha256=research_inputs[
                "custody_root_path_sha256"
            ],
            expected_custody_identity_sha256=research_inputs[
                "custody_identity_sha256"
            ],
            now=NOW,
        )


@pytest.mark.parametrize(
    "now",
    [
        NOW + timedelta(days=1),
        NOW - timedelta(hours=2),
    ],
)
def test_expired_or_not_yet_valid_bundle_is_rejected(
    research_inputs: dict,
    now: datetime,
) -> None:
    with pytest.raises(
        bundle.ResearchBundleError,
        match="not currently valid",
    ):
        prepare(research_inputs, now=now)


def test_signer_never_reads_private_key_after_public_failure(
    research_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = draft_payload()
    invalid["order_submission_authorized"] = True
    draft_path = write_json(
        research_inputs["private_dir"] / "invalid-draft.json",
        invalid,
    )
    args = argparse.Namespace(
        input=draft_path,
        output=research_inputs["private_dir"] / "must-not-exist.json",
        private_key_file=research_inputs["private_key_path"],
        trusted_keyring=research_inputs["keyring_path"],
        expected_trusted_keyring_raw_sha256=(
            research_inputs["keyring_raw_sha256"]
        ),
        expected_signer_sha256=research_inputs["signer_sha256"],
        expected_custody_root_path_sha256=research_inputs[
            "custody_root_path_sha256"
        ],
        expected_custody_identity_sha256=research_inputs[
            "custody_identity_sha256"
        ],
        **research_inputs["artifacts"],
    )
    private_key_read = False

    def forbidden_private_key_read(_path: Path):
        nonlocal private_key_read
        private_key_read = True
        raise AssertionError("private key was read before public validation")

    monkeypatch.setattr(signer, "parse_args", lambda: args)
    monkeypatch.setattr(signer, "load_private_key", forbidden_private_key_read)

    assert signer.main() == 2
    assert private_key_read is False
    assert not args.output.exists()


def test_signer_rejects_wrong_self_pin_before_private_key_read(
    research_inputs: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft_path = write_json(
        research_inputs["private_dir"] / "valid-draft-wrong-pin.json",
        draft_payload(),
    )
    args = argparse.Namespace(
        input=draft_path,
        output=research_inputs["private_dir"] / "wrong-pin-output.json",
        private_key_file=research_inputs["private_key_path"],
        trusted_keyring=research_inputs["keyring_path"],
        expected_trusted_keyring_raw_sha256=(
            research_inputs["keyring_raw_sha256"]
        ),
        expected_signer_sha256="f" * 64,
        expected_custody_root_path_sha256=research_inputs[
            "custody_root_path_sha256"
        ],
        expected_custody_identity_sha256=research_inputs[
            "custody_identity_sha256"
        ],
        **research_inputs["artifacts"],
    )
    private_key_read = False

    def forbidden_private_key_read(_path: Path):
        nonlocal private_key_read
        private_key_read = True
        raise AssertionError("private key was read after signer-pin failure")

    monkeypatch.setattr(signer, "parse_args", lambda: args)
    monkeypatch.setattr(signer, "load_private_key", forbidden_private_key_read)

    assert signer.main() == 2
    assert private_key_read is False
    assert not args.output.exists()


def test_create_only_output_rejects_public_parent_and_symlink_parent(
    research_inputs: dict,
    tmp_path: Path,
) -> None:
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    with pytest.raises(
        bundle.ResearchBundleError,
        match="private owned directory",
    ):
        bundle.write_bytes_create_only_verified(
            public_parent / "output.json",
            b"{}\n",
            label="unsafe synthetic output",
        )

    link_parent = tmp_path / "private-link"
    link_parent.symlink_to(research_inputs["private_dir"], target_is_directory=True)
    with pytest.raises(
        bundle.ResearchBundleError,
        match="must not traverse a symlink",
    ):
        bundle.write_bytes_create_only_verified(
            link_parent / "output.json",
            b"{}\n",
            label="symlinked synthetic output",
        )


def test_all_research_bundle_schemas_are_strict_draft_2020_12() -> None:
    for schema_path in (
        bundle.BUNDLE_SCHEMA_PATH,
        bundle.KEYRING_SCHEMA_PATH,
        bundle.RECEIPT_SCHEMA_PATH,
    ):
        payload = json.loads(schema_path.read_text(encoding="utf-8"))
        assert payload["$schema"].endswith("/draft/2020-12/schema")
        assert payload["additionalProperties"] is False
        Draft202012Validator.check_schema(payload)
