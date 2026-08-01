from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_query_v5_release as query_v5  # noqa: E402
import commodity_c_fast_t1_query_v6_authority as subject  # noqa: E402
import commodity_c_fast_t1_query_v6_sign as signer  # noqa: E402
from commodity_c_fast_t1_one_shot import OneShotError  # noqa: E402


NOW = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
H = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
IMAGE_DIGEST = "sha256:" + "4" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _artifact(payload: dict[str, Any], seed: str) -> subject.JsonArtifact:
    return subject.JsonArtifact(
        payload=payload,
        raw_sha256=_sha(f"raw:{seed}".encode()),
        canonical_sha256=_sha(f"canonical:{seed}".encode()),
    )


def _provenance() -> query_v5.VerifiedProvenance:
    return query_v5.VerifiedProvenance(
        payload={
            "issued_at": (NOW - timedelta(minutes=2)).isoformat(),
            "runtime_source_commit_sha": "a" * 40,
            "image_reference": f"registry.invalid/c-fast-query-v5@{IMAGE_DIGEST}",
            "image_digest": IMAGE_DIGEST,
            "image_id": "sha256:" + "5" * 64,
            "trusted_keyring_sha256": H,
        },
        raw_sha256=H,
        canonical_sha256=H2,
        signer_public_key_sha256=H3,
        composition_raw_sha256="4" * 64,
        composition_canonical_sha256="5" * 64,
    )


def _dsn_identity() -> dict[str, Any]:
    payload = {
        "schema_version": subject.DSN_IDENTITY_VERSION,
        "attestation_id": "dsn-identity-test-0001",
        "observed_at": (NOW - timedelta(minutes=1)).isoformat(),
        "dsn_file_absolute_path_sha256": "6" * 64,
        "device": 42,
        "inode": 99,
        "owner_uid": 1000,
        "owner_gid": 1000,
        "mode": 0o600,
        "link_count": 1,
        "size_bytes": 120,
        "expected_readonly_principal_sha256": "7" * 64,
        "expected_endpoint_identity_sha256": "8" * 64,
        "dsn_secret_included": False,
        "dsn_content_hash_included": False,
        "dsn_secret_read": False,
        "network_accessed": False,
        "authority_granted": False,
    }
    payload["dsn_file_identity_sha256"] = subject.dsn_identity_sha256(payload)
    return payload


def _evidence(
    custody_path: str = "/var/lib/c-fast-t1-query-v6-custody",
    *,
    verified_domain_public_key_hashes: frozenset[str] = frozenset(),
) -> subject.AuthorityEvidence:
    dsn = _dsn_identity()
    l3 = _artifact(
        {"questdb_target_identity_sha256": dsn["expected_endpoint_identity_sha256"]},
        "l3",
    )
    readiness = _artifact(
        {
            "generated_at": (NOW - timedelta(minutes=3)).isoformat(),
            "expires_at": (NOW + timedelta(minutes=20)).isoformat(),
            "packet_custody_path_sha256": _sha(custody_path.encode()),
            "packet_custody_id": "query-v6-custody-test-0001",
            "packet_custody_identity_sha256": "9" * 64,
            "packet_custody_directory_identity_sha256": "a" * 64,
            "readonly_deployment_outcome": {
                "signed_outcome_raw_sha256": l3.raw_sha256,
                "signed_outcome_canonical_sha256": l3.canonical_sha256,
            },
        },
        "readiness",
    )
    return subject.AuthorityEvidence(
        readiness=readiness,
        l3_outcome=l3,
        query_manifest=_artifact({"snapshot_id": "snapshot-test-0001"}, "manifest"),
        runtime_pin_manifest=_artifact(
            {
                "generation_id": "runtime-pin-generation-test-0001",
                "runtime_image_digest": IMAGE_DIGEST,
                "code_only_blocked": True,
                "authority_granted": False,
            },
            "runtime-pins",
        ),
        dsn_identity_attestation=_artifact(dsn, "dsn"),
        verified_domain_public_key_hashes=verified_domain_public_key_hashes,
    )


def _keyring(private_key: Ed25519PrivateKey) -> dict[str, Any]:
    return {
        "schema_version": subject.KEYRING_VERSION,
        "keys": [
            {
                "key_id": "query-v6-test-key-0001",
                "purpose": subject.KEY_PURPOSE,
                "public_key_base64": base64.b64encode(
                    private_key.public_key().public_bytes_raw()
                ).decode("ascii"),
            }
        ],
    }


def _draft(custody_path: str = "/var/lib/c-fast-t1-query-v6-custody") -> dict[str, Any]:
    payload = json.loads(
        (
            ROOT
            / "docs/operations/c-fast-t1-query-v6-authority-foundation.template.json"
        ).read_text(encoding="utf-8")
    )
    payload.update(
        {
            "release_id": "query-v6-release-test-0001",
            "issued_at": (NOW - timedelta(seconds=20)).isoformat(),
            "not_before": (NOW - timedelta(seconds=10)).isoformat(),
            "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
            "signer_key_id": "query-v6-test-key-0001",
            "reviewer_role": "human-risk-reviewer",
            "human_signature": "approved no-query foundation for test only",
            "custody_absolute_path": custody_path,
        }
    )
    return payload


def _signed() -> tuple[
    dict[str, Any],
    dict[str, Any],
    Ed25519PrivateKey,
    query_v5.VerifiedProvenance,
    subject.AuthorityEvidence,
]:
    private_key = Ed25519PrivateKey.generate()
    keyring = _keyring(private_key)
    provenance = _provenance()
    evidence = _evidence()
    keyring_hash = _sha(subject.canonical_json(keyring))
    signed = signer.sign_release(
        _draft(),
        keyring,
        provenance,
        frozenset({_sha(b"different-provenance-key")}),
        evidence,
        private_key,
        expected_keyring_sha256=keyring_hash,
        now=NOW,
    )
    return signed, keyring, private_key, provenance, evidence


def _write_private(path: Path, payload: dict[str, Any]) -> Path:
    path.write_bytes(subject.canonical_json(payload) + b"\n")
    path.chmod(0o600)
    return path


def _manifest() -> dict[str, Any]:
    products = sorted(subject.EXPECTED_PRODUCTS)
    targets = []
    windows = []
    for index, product in enumerate(products):
        current = f"SHFE.{product}{2701 + index}"
        previous = f"SHFE.{product}{2601 + index}" if index == 0 else None
        targets.append(
            {
                "product": product,
                "exact_contract": current,
                "previous_exact_contract": previous,
                "roll_expected": previous is not None,
            }
        )
        for suffix, contract in (("current", current), ("previous", previous)):
            if contract is not None:
                windows.append(
                    {
                        "window_id": f"window-{product}-{suffix}-0001",
                        "product": product,
                        "exact_contract": contract,
                        "execution_time": "2026-08-02T13:01:00+00:00",
                        "window_seconds": 60,
                    }
                )
    return {
        "schema_version": "commodity_c_fast_l1_l5_audit_manifest_v2",
        "candidate_id": subject.CANDIDATE_ID,
        "snapshot_id": "snapshot-query-v6-test-0001",
        "audit_window": {
            "start": "2026-08-02T13:00:00+00:00",
            "end_exclusive": "2026-08-03T01:21:00+00:00",
            "trading_day": "20260803",
        },
        "session_windows": {
            "night_open": {
                "start": "2026-08-02T13:00:00+00:00",
                "end_exclusive": "2026-08-02T13:02:05+00:00",
            },
            "night_session": {
                "start": "2026-08-02T13:10:00+00:00",
                "end_exclusive": "2026-08-02T13:20:00+00:00",
            },
            "day_open": {
                "start": "2026-08-03T01:00:00+00:00",
                "end_exclusive": "2026-08-03T01:02:05+00:00",
            },
            "day_session": {
                "start": "2026-08-03T01:10:00+00:00",
                "end_exclusive": "2026-08-03T01:20:00+00:00",
            },
        },
        "targets": targets,
        "execution_windows": windows,
    }


def test_sign_and_offline_verify_freezes_complete_no_query_foundation(
    tmp_path: Path,
) -> None:
    signed, keyring, _private_key, provenance, evidence = _signed()
    release_path = _write_private(tmp_path / "release.json", signed)
    keyring_path = _write_private(tmp_path / "keyring.json", keyring)
    verified = subject.verify_release(
        release_path,
        keyring_path,
        provenance,
        frozenset({_sha(b"different-provenance-key")}),
        evidence,
        expected_release_keyring_sha256=_sha(subject.canonical_json(keyring)),
        now=NOW,
    )

    assert verified.payload["attempt_id"] == subject.release_attempt_id(
        verified.payload["release_id"]
    )
    assert verified.payload["maximum_uses"] == 1
    assert verified.payload["replay_allowed"] is False
    assert all(verified.payload[field] is False for field in subject.FALSE_AUTHORITY_FIELDS)
    assert all(verified.payload[field] is False for field in subject.FALSE_FACT_FIELDS)
    assert all(verified.payload[field] == 0 for field in subject.ZERO_FACT_FIELDS)


@pytest.mark.parametrize(
    "field",
    [
        "readiness_v4_raw_sha256",
        "readiness_v4_canonical_sha256",
        "l3_outcome_raw_sha256",
        "l3_outcome_canonical_sha256",
        "query_manifest_raw_sha256",
        "query_manifest_canonical_sha256",
        "runtime_pin_generation_id",
        "runtime_pin_manifest_sha256",
        "runtime_identity_sha256",
        "custody_path_sha256",
        "custody_id",
        "custody_identity_sha256",
        "custody_directory_identity_sha256",
        "dsn_file_identity_attestation_raw_sha256",
        "dsn_file_identity_attestation_canonical_sha256",
        "dsn_file_identity_attestation_schema_sha256",
        "expected_readonly_principal_sha256",
        "expected_endpoint_identity_sha256",
        "query_manifest_schema_sha256",
        "runtime_runner_sha256",
        "query_child_sha256",
        "audit_script_sha256",
        "consume_schema_sha256",
        "child_started_schema_sha256",
        "terminal_schema_sha256",
        "readonly_proof_schema_sha256",
        "provenance_raw_sha256",
        "composition_attestation_raw_sha256",
    ],
)
def test_each_runtime_blocker_tamper_fails_closed(field: str) -> None:
    signed, _keyring_payload, _private_key, provenance, evidence = _signed()
    signed[field] = "tampered-runtime-binding"
    with pytest.raises(subject.QueryV6AuthorityError, match=field):
        subject.validate_release_semantics(signed, provenance, evidence, now=NOW)


def test_cross_domain_key_reuse_fails_before_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    keyring = _keyring(private_key)
    material_hash = _sha(private_key.public_key().public_bytes_raw())
    with pytest.raises(subject.QueryV6AuthorityError, match="domains overlap"):
        signer.prepare_release(
            _draft(),
            keyring,
            _provenance(),
            frozenset({material_hash}),
            _evidence(),
            expected_keyring_sha256=_sha(subject.canonical_json(keyring)),
            now=NOW,
        )


def test_readiness_signer_key_reuse_also_fails_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    keyring = _keyring(private_key)
    material_hash = _sha(private_key.public_key().public_bytes_raw())
    evidence = _evidence(
        verified_domain_public_key_hashes=frozenset({material_hash})
    )
    with pytest.raises(subject.QueryV6AuthorityError, match="domains overlap"):
        signer.prepare_release(
            _draft(),
            keyring,
            _provenance(),
            frozenset({_sha(b"different-provenance-key")}),
            evidence,
            expected_keyring_sha256=_sha(subject.canonical_json(keyring)),
            now=NOW,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"attempt_id": f"attempt-{'0' * 64}"}, "attempt_id"),
        (
            {"expires_at": (NOW + timedelta(minutes=11)).isoformat()},
            "TTL",
        ),
        ({"network_query_authorized": True}, "schema"),
        ({"maximum_uses": 2}, "schema"),
    ],
)
def test_one_shot_ttl_and_authority_are_strict(
    mutation: dict[str, Any], message: str
) -> None:
    signed, _keyring_payload, _private_key, provenance, evidence = _signed()
    signed.update(mutation)
    with pytest.raises((subject.QueryV6AuthorityError, OneShotError), match=message):
        subject.validate_release_semantics(signed, provenance, evidence, now=NOW)


def test_secret_free_dsn_identity_is_self_bound_and_strict() -> None:
    payload = _dsn_identity()
    subject.validate_json_schema(
        payload, subject.DSN_IDENTITY_SCHEMA_PATH, "DSN identity"
    )
    subject._validate_dsn_identity(payload)

    tampered = dict(payload)
    tampered["inode"] += 1
    with pytest.raises(subject.QueryV6AuthorityError, match="identity"):
        subject._validate_dsn_identity(tampered)

    forbidden = dict(payload)
    forbidden["dsn_content_sha256"] = H
    with pytest.raises(OneShotError, match="schema"):
        subject.validate_json_schema(
            forbidden, subject.DSN_IDENTITY_SCHEMA_PATH, "DSN identity"
        )


def test_exact_ten_product_manifest_and_roll_windows_fail_closed() -> None:
    manifest = _manifest()
    subject.validate_json_schema(
        manifest, subject.QUERY_MANIFEST_SCHEMA_PATH, "query manifest"
    )
    subject._validate_query_manifest(manifest)

    missing_product = copy.deepcopy(manifest)
    missing_product["targets"].pop()
    with pytest.raises(subject.QueryV6AuthorityError, match="each frozen product"):
        subject._validate_query_manifest(missing_product)

    missing_roll_window = copy.deepcopy(manifest)
    previous = missing_roll_window["targets"][0]["previous_exact_contract"]
    missing_roll_window["execution_windows"] = [
        row
        for row in missing_roll_window["execution_windows"]
        if row["exact_contract"] != previous
    ]
    with pytest.raises(subject.QueryV6AuthorityError, match="lacks an execution"):
        subject._validate_query_manifest(missing_roll_window)

    duplicated_previous = copy.deepcopy(manifest)
    duplicated_previous["targets"][0]["previous_exact_contract"] = (
        duplicated_previous["targets"][1]["exact_contract"]
    )
    with pytest.raises(subject.QueryV6AuthorityError, match="duplicated"):
        subject._validate_query_manifest(duplicated_previous)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("inverted", "later than start"),
        ("outside_audit", "outside signed audit window"),
        ("overlap", "session windows overlap"),
        ("wrong_trading_day", "signed trading_day"),
    ],
)
def test_session_windows_fail_closed_on_invalid_causality(
    case: str,
    message: str,
) -> None:
    manifest = _manifest()
    if case == "inverted":
        window = manifest["session_windows"]["night_open"]
        window["start"], window["end_exclusive"] = (
            window["end_exclusive"],
            window["start"],
        )
    elif case == "outside_audit":
        manifest["session_windows"]["night_open"]["start"] = (
            "2026-08-02T12:59:59+00:00"
        )
    elif case == "overlap":
        manifest["session_windows"]["night_session"]["start"] = (
            "2026-08-02T13:01:00+00:00"
        )
    else:
        manifest["session_windows"]["day_open"] = {
            "start": "2026-08-02T01:00:00+00:00",
            "end_exclusive": "2026-08-02T01:02:05+00:00",
        }
        manifest["audit_window"]["start"] = "2026-08-02T01:00:00+00:00"

    with pytest.raises(subject.QueryV6AuthorityError, match=message):
        subject._validate_query_manifest(manifest)


def _readiness_replay_stub(l3_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        outcome=l3_path,
        outcome_keyring=Path("outcome-keyring.json"),
        t1_keyring=Path("t1-keyring.json"),
        outcome_source=SimpleNamespace(
            release_keyring=Path("l3-release-keyring.json")
        ),
        post_evidence=object(),
        outcome_contract_source_commit_assertion="a" * 40,
        l3_contract_source_commit_sha="b" * 40,
        questdb_image_digest=IMAGE_DIGEST,
    )


@pytest.mark.parametrize(
    "failure",
    [
        "existing readiness-v4 packet is not the exact re-derived object",
        "existing readiness-v4 packet changed during verification",
    ],
)
def test_schema_valid_forged_or_tampered_readiness_cannot_skip_official_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    l3_path = tmp_path / "l3.json"
    l3_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(subject.readiness_v4, "_read_production_pins", lambda: object())
    monkeypatch.setattr(
        subject,
        "_readiness_runtime_identity_candidate",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        subject.readiness_v4,
        "verify_existing_readiness_packet",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subject.readiness_v4.ReadinessV4Error(failure)
        ),
    )

    with pytest.raises(subject.QueryV6AuthorityError, match="full replay failed"):
        subject.load_authority_evidence(
            tmp_path / "readiness.json",
            l3_path,
            tmp_path / "manifest.json",
            tmp_path / "runtime-pins.json",
            tmp_path / "dsn.json",
            readiness_inputs=_readiness_replay_stub(l3_path),
            now=NOW,
            require_root_owned_parent=False,
        )


def test_forged_l3_signature_cannot_skip_official_outcome_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    l3_path = tmp_path / "l3.json"
    l3_path.write_text("{}", encoding="utf-8")
    pins = SimpleNamespace(
        outcome_keyring_sha256=H,
        l3_authority_keyring_sha256=H2,
        t1_authority_keyring_sha256=H3,
    )
    monkeypatch.setattr(subject.readiness_v4, "_read_production_pins", lambda: pins)
    monkeypatch.setattr(
        subject,
        "_readiness_runtime_identity_candidate",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        subject.readiness_v4,
        "verify_existing_readiness_packet",
        lambda *_args, **_kwargs: SimpleNamespace(
            payload={}, raw_sha256=H, canonical_sha256=H2
        ),
    )
    monkeypatch.setattr(
        subject,
        "verify_signed_outcome",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subject.DeploymentOutcomeError("deployment outcome signature is invalid")
        ),
    )

    with pytest.raises(subject.QueryV6AuthorityError, match="signature is invalid"):
        subject.load_authority_evidence(
            tmp_path / "readiness.json",
            l3_path,
            tmp_path / "manifest.json",
            tmp_path / "runtime-pins.json",
            tmp_path / "dsn.json",
            readiness_inputs=_readiness_replay_stub(l3_path),
            now=NOW,
            require_root_owned_parent=False,
        )


def test_active_readiness_pin_rotation_after_replay_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    l3_path = tmp_path / "l3.json"
    l3_path.write_text("{}", encoding="utf-8")
    pins = SimpleNamespace(
        outcome_keyring_sha256=H,
        l3_authority_keyring_sha256=H2,
        t1_authority_keyring_sha256=H3,
    )
    monkeypatch.setattr(subject.readiness_v4, "_read_production_pins", lambda: pins)
    monkeypatch.setattr(
        subject,
        "_readiness_runtime_identity_candidate",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        subject.readiness_v4,
        "verify_existing_readiness_packet",
        lambda *_args, **_kwargs: SimpleNamespace(
            payload={}, raw_sha256=H, canonical_sha256=H2
        ),
    )
    monkeypatch.setattr(
        subject,
        "verify_signed_outcome",
        lambda *_args, **_kwargs: SimpleNamespace(
            payload={}, raw_sha256=H2, canonical_sha256=H3
        ),
    )
    monkeypatch.setattr(
        subject,
        "_verified_readiness_key_materials",
        lambda *_args: frozenset({H}),
    )
    monkeypatch.setattr(
        subject.readiness_v4,
        "verify_active_readiness_pins",
        lambda _pins: (_ for _ in ()).throw(
            subject.readiness_v4.ReadinessV4Error(
                "active readiness-v4 pins changed"
            )
        ),
    )

    with pytest.raises(subject.QueryV6AuthorityError, match="pins changed"):
        subject.load_authority_evidence(
            tmp_path / "readiness.json",
            l3_path,
            tmp_path / "manifest.json",
            tmp_path / "runtime-pins.json",
            tmp_path / "dsn.json",
            readiness_inputs=_readiness_replay_stub(l3_path),
            now=NOW,
            require_root_owned_parent=False,
        )


def test_verifier_has_no_dsn_network_consume_or_launch_capability() -> None:
    source = subject.VERIFIER_PATH.read_text(encoding="utf-8")
    forbidden_tokens = (
        "psycopg",
        "import socket",
        "subprocess",
        "os.exec",
        "Popen",
        "write_json_create_only",
        "connect_server_enforced_readonly",
    )
    assert all(token not in source for token in forbidden_tokens)
    assert 'parser.add_argument("--dsn-file"' not in source
    assert "def consume" not in source
    assert "def launch" not in source


def test_signer_does_not_require_verifier_only_signed_release(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["query-v6-sign", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        signer.parse_args()
    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--signed-release" not in help_text

    monkeypatch.setattr(sys, "argv", ["query-v6-verify", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        subject.parse_args()
    assert exc_info.value.code == 0
    assert "--signed-release" in capsys.readouterr().out


def test_pending_templates_are_not_signed_contracts() -> None:
    release_template = json.loads(
        (
            ROOT
            / "docs/operations/c-fast-t1-query-v6-authority-foundation.template.json"
        ).read_text(encoding="utf-8")
    )
    keyring_template = json.loads(
        (
            ROOT
            / "docs/operations/c-fast-t1-query-v6-trusted-keys-v1.template.json"
        ).read_text(encoding="utf-8")
    )
    assert subject._contains_pending(release_template)
    assert subject._contains_pending(keyring_template)
    with pytest.raises((OneShotError, subject.QueryV6AuthorityError)):
        subject.validate_json_schema(
            release_template, subject.RELEASE_SCHEMA_PATH, "release template"
        )
