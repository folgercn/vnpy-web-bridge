"""Public, temporary-key custody regressions using the actual signature verifiers.

Only in-memory trust roots are replaced for these generated test originals.
No private witness, production key or successful-verification mock is used.
"""

from __future__ import annotations

import base64
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research_lab.alpha_discovery import real_source_time as real
from scripts.research_warehouse.canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from scripts.research_warehouse.m2_isolation_contracts import false_authority
from scripts.research_warehouse.m2_receipts import RUN_RECEIPT_SCHEMA, run_receipt_id
from scripts.research_warehouse.manifest_commits import COMMIT_AUTHORITY, COMMIT_SCHEMA
from scripts.research_warehouse.manifest_contracts import MANIFEST_AUTHORITY, MANIFEST_SCHEMA, input_fingerprint, seal_base
from scripts.research_warehouse.observation_contracts import observation_id, raw_object_id, revision_occurrence_id
from scripts.research_warehouse.official_calendar import CALENDAR_AUTHORITY, CALENDAR_SCHEMA, SOURCE_CONTRACTS, SOURCE_TYPE
from scripts.research_warehouse.registry import load_registry
from scripts.research_warehouse.signing import public_key_raw, public_key_sha256, sign_payload

ROOT = Path(__file__).resolve().parents[3]
DAY = "2026-08-31"


def _write(path: Path, raw: bytes) -> Path:
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


@pytest.fixture
def local_custody(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    bundle, rules = tmp_path / "bundle", tmp_path / "rules"
    custody = bundle / "warehouse/custody"
    private = Ed25519PrivateKey.generate()
    calendar_private = Ed25519PrivateKey.generate()
    for label, key in (("MANIFEST", private), ("CALENDAR", calendar_private)):
        key_bytes = base64.b64encode(public_key_raw(key.public_key())) + b"\n"
        _write(bundle / f"libexec/{label.lower()}-public-key.b64", key_bytes)
        monkeypatch.setattr(real, f"{label}_KEY_SHA256", public_key_sha256(key.public_key()))
        monkeypatch.setattr(real, f"{label}_KEY_FILE_SHA256", sha256(key_bytes))
    rule_bytes = b"temporary test rule root"
    _write(rules / "shfe-trading-rules-202606.docx", rule_bytes)
    monkeypatch.setattr(real, "SHFE_RULE_SHA256", sha256(rule_bytes))
    products = {}
    for product, (filename, _) in real.PRODUCT_RULES.items():
        raw = f"temporary {product} test rule root".encode()
        _write(rules / filename, raw)
        products[product] = filename, sha256(raw)
    monkeypatch.setattr(real, "PRODUCT_RULES", products)

    registry_path = bundle / "libexec/source-registry-v1.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "deployments/research-warehouse/source-registry-v1.json", registry_path)
    registry = load_registry(registry_path)
    source = registry.source(real.SOURCE_ID)

    evidence = []
    for exchange, (owner, host) in SOURCE_CONTRACTS.items():
        raw = f"temporary {exchange} calendar evidence".encode()
        relative = f"calendar-sources/{exchange.lower()}/{sha256(raw)}.raw"
        _write(custody / "calendar-evidence" / relative, raw)
        evidence.append({
            "exchange": exchange, "owner": owner, "source_url": f"https://{host}/test-calendar",
            "source_type": SOURCE_TYPE, "observed_at": "2025-12-01T08:00:00.000000Z",
            "raw_sha256": sha256(raw), "raw_bytes": len(raw), "raw_relative_path": relative,
        })
    calendar_days = []
    current = date(2026, 1, 1)
    while current <= date(2026, 12, 31):
        calendar_days.append({
            "date": current.isoformat(), "status": "OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            "evening_session_natural_date": None,
        })
        current += timedelta(days=1)
    calendar = {
        "schema_version": CALENDAR_SCHEMA, "timezone": "Asia/Shanghai", "timestamp_storage": "UTC",
        "valid_from": "2026-01-01", "valid_to": "2026-12-31", "issued_at": "2025-12-01T09:00:00.000000Z",
        "exchanges": ["INE", "SHFE"], "source_evidence": evidence, "days": calendar_days,
        "authority": CALENDAR_AUTHORITY, "signer_key_id": "calendar-test-key",
        "signer_public_key_sha256": public_key_sha256(calendar_private.public_key()),
    }
    calendar["calendar_id"] = "calendar-" + sha256(canonical_json(calendar))
    calendar_raw = canonical_json_line(sign_payload(calendar, calendar_private))
    calendar_sha = sha256(calendar_raw)
    _write(bundle / f"warehouse/runtime/inputs/official-calendar-{calendar_sha}.json", calendar_raw)
    monkeypatch.setattr(real, "CALENDAR_SHA256", calendar_sha)

    rows = []
    for product, price in (("rb_f", 3186), ("hc_f", 3350)):
        rows.append({**dict.fromkeys(source.required_row_fields, 1),
                     "PRODUCTID": product, "DELIVERYMONTH": "2701", "SETTLEMENTPRICE": price})
    raw = canonical_json_line({"report_date": "20260831", "o_curinstrument": rows})
    relative = f"raw/shfe/{DAY}/{real.SOURCE_ID}/{sha256(raw)}.raw"
    raw_path = _write(custody / relative, raw)
    object_id = raw_object_id(source, DAY, sha256(raw))
    revision_id = revision_occurrence_id(source_id=source.source_id, trade_day=DAY, observation_sequence=1,
                                         object_id=object_id, supersedes_revision_id=None)
    observation = {
        "source_url": source.endpoint_template.replace("{yyyymmdd}", "20260831"), "http_status": 200,
        "trade_day": DAY, "revision_id": revision_id, "raw_sha256": sha256(raw),
        "first_seen_at": f"{DAY}T08:00:00.000000Z", "observed_at": f"{DAY}T08:00:00.000000Z",
        "registry_raw_sha256": registry.raw_sha256,
    }
    obs_id = observation_id(observation)
    observation["observation_id"] = obs_id
    observation_path = _write(custody / f"observations/shfe/{DAY}/{real.SOURCE_ID}/{obs_id}.json",
                              canonical_json_line(observation))
    revision = {
        "revision_id": revision_id, "revision_sequence": 1, "object_id": object_id,
        "source_id": source.source_id, "exchange": "SHFE", "trade_day": DAY,
        "raw_sha256": sha256(raw), "raw_bytes": len(raw), "raw_relative_path": relative,
        "first_seen_at": observation["first_seen_at"], "last_seen_at": observation["first_seen_at"],
        "supersedes_revision_id": None, "supersedes_object_id": None, "observation_ids": [obs_id],
    }
    manifest = {
        "schema_version": MANIFEST_SCHEMA, "trade_day": DAY, "sealed_at": f"{DAY}T08:02:00.000000Z",
        "registry_raw_sha256": registry.raw_sha256, "input_fingerprint_sha256": input_fingerprint(registry.raw_sha256, [obs_id]),
        "parent_batch_seal_sha256": None, "parent_commit_seal_sha256": None,
        "revisions": [revision], "observation_ids": [obs_id], "revision_count": 1,
        "unique_raw_object_count": 1, "observation_count": 1, "total_unique_raw_bytes": len(raw),
        "signer_key_id": "manifest-test-key", "signer_public_key_sha256": public_key_sha256(private.public_key()),
        "authority": MANIFEST_AUTHORITY, "ready": False,
    }
    manifest["batch_seal_sha256"] = sha256(canonical_json(seal_base(manifest)))
    manifest["batch_id"] = f"batch-{DAY}-{manifest['batch_seal_sha256'][:24]}"
    manifest = sign_payload(manifest, private)
    manifest_path = _write(custody / f"manifests/{DAY}/{manifest['batch_id']}.json", canonical_json_line(manifest))
    commit = sign_payload({
        "schema_version": COMMIT_SCHEMA, "batch_id": manifest["batch_id"], "batch_seal_sha256": manifest["batch_seal_sha256"],
        "registry_raw_sha256": registry.raw_sha256, "committed_at": f"{DAY}T08:03:00.000000Z",
        "signer_key_id": manifest["signer_key_id"], "signer_public_key_sha256": manifest["signer_public_key_sha256"],
        "authority": COMMIT_AUTHORITY, "ready": True,
    }, private)
    commit_path = _write(manifest_path.parent / f"commit-{manifest['batch_id']}.json", canonical_json_line(commit))
    receipt_source = {key: revision[key] for key in (
        "source_id", "exchange", "object_id", "revision_id", "raw_sha256", "raw_bytes", "raw_relative_path")}
    receipt_source["observation_id"] = obs_id
    receipt = {
        "schema_version": RUN_RECEIPT_SCHEMA, "receipt_id": "", "trade_day": DAY, "completed_at": f"{DAY}T08:01:00.000000Z",
        "registry_raw_sha256": registry.raw_sha256, "calendar_raw_sha256": calendar_sha,
        "calendar_availability_anchor_raw_sha256": "a" * 64, "authority": false_authority(),
        "sources": [receipt_source, {**receipt_source, "source_id": "ine-daily-market-data-v1", "exchange": "INE"}],
    }
    receipt["receipt_id"] = run_receipt_id(receipt)
    receipt_path = _write(bundle / f"warehouse/runtime/run-receipts/{DAY}.json", canonical_json_line(receipt))
    record = {
        "day": DAY, "first_seen_at": revision["first_seen_at"], "committed_at": commit["committed_at"],
        "raw_sha256": sha256(raw), "raw_bytes": len(raw), "raw_relative_path": relative,
        "batch_seal_sha256": manifest["batch_seal_sha256"], "settlement": {"rb_f": 3186, "hc_f": 3350},
    }
    return {"bundle": bundle, "rules": rules, "days": [record], "raw_path": raw_path,
            "observation_path": observation_path, "manifest_path": manifest_path,
            "commit_path": commit_path, "receipt_path": receipt_path}


def _verify(fixture: dict) -> dict:
    return real.verify_shfe_settlement_days(fixture["days"], bundle_root=fixture["bundle"], official_rules_root=fixture["rules"])


def test_local_signed_originals_pass(local_custody: dict) -> None:
    verified = _verify(local_custody)[DAY]
    assert verified.settlement == {"rb_f": 3186.0, "hc_f": 3350.0}
    assert verified.raw_sha256 == sha256(local_custody["raw_path"].read_bytes())
    assert verified.settlement_not_before == f"{DAY}T07:00:00Z"


@pytest.mark.parametrize("price", [3187, 31860])
@pytest.mark.parametrize("after_verification", [False, True])
def test_raw_replacement_rejected(local_custody: dict, monkeypatch: pytest.MonkeyPatch,
                                  price: int, after_verification: bool) -> None:
    _verify(local_custody)  # Each negative starts with actually verified signed originals.
    raw_path = local_custody["raw_path"]
    original = raw_path.read_bytes()
    replacement = original.replace(b'"SETTLEMENTPRICE":3186', f'"SETTLEMENTPRICE":{price}'.encode())
    assert replacement != original
    assert (len(replacement) == len(original)) == (price == 3187)
    local_custody["days"][0]["settlement"]["rb_f"] = price
    verified_calls = []
    if after_verification:
        validate = real.validate_manifest_envelope

        def validate_then_replace(*args, **kwargs):
            manifest = validate(*args, **kwargs)
            verified_calls.append(manifest["batch_seal_sha256"])
            raw_path.write_bytes(replacement)
            return manifest

        monkeypatch.setattr(real, "validate_manifest_envelope", validate_then_replace)
    else:
        raw_path.write_bytes(replacement)
    with pytest.raises(real.RealSourceEvidenceError) as raised:
        _verify(local_custody)
    assert raised.value.reason == ("SOURCE_EVIDENCE_MISMATCH" if after_verification else "SOURCE_EVIDENCE_INVALID")
    assert bool(verified_calls) == after_verification


@pytest.mark.parametrize("rehash", [False, True])
def test_observation_body_replacement_rejected(local_custody: dict, rehash: bool) -> None:
    _verify(local_custody)
    path = local_custody["observation_path"]
    observation = parse_json_strict(path.read_bytes(), "test observation")
    observation["observed_at"] = f"{DAY}T08:00:30.000000Z"  # Still inside the permitted time interval.
    if rehash:
        observation["observation_id"] = observation_id(observation)
        assert observation["observation_id"] != path.stem
    path.write_bytes(canonical_json_line(observation))
    with pytest.raises(real.RealSourceEvidenceError) as raised:
        _verify(local_custody)
    assert raised.value.reason == "OBSERVATION_RECEIPT_MISMATCH"


def test_rehashed_body_receipt_and_path_outside_signed_revision_rejected(local_custody: dict) -> None:
    _verify(local_custody)
    observation = parse_json_strict(local_custody["observation_path"].read_bytes(), "test observation")
    observation["observed_at"] = f"{DAY}T08:00:30.000000Z"
    observation["observation_id"] = observation_id(observation)
    _write(local_custody["observation_path"].with_name(observation["observation_id"] + ".json"), canonical_json_line(observation))
    receipt_path = local_custody["receipt_path"]
    receipt = parse_json_strict(receipt_path.read_bytes(), "test receipt")
    receipt["sources"][0]["observation_id"] = observation["observation_id"]
    receipt["receipt_id"] = run_receipt_id(receipt)
    receipt_path.write_bytes(canonical_json_line(receipt))
    with pytest.raises(real.RealSourceEvidenceError) as raised:
        _verify(local_custody)
    assert raised.value.reason == "RUN_RECEIPT_MISMATCH"


@pytest.mark.parametrize("file_key", ["manifest_path", "commit_path"])
def test_local_invalid_signature_rejected(local_custody: dict, file_key: str) -> None:
    _verify(local_custody)
    path = local_custody[file_key]
    payload = parse_json_strict(path.read_bytes(), "test signed payload")
    payload["signature"] = base64.b64encode(b"\0" * 64).decode()
    path.write_bytes(canonical_json_line(payload))
    with pytest.raises(real.RealSourceEvidenceError, match="signature is invalid"):
        _verify(local_custody)
