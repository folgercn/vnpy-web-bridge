from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_readonly_deployment_release as release_module  # noqa: E402
import commodity_c_fast_readonly_deployment_sign_release as signer_module  # noqa: E402
import commodity_c_fast_t1_one_shot as t1_module  # noqa: E402


NOW = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
SOURCE_COMMIT_SHA = "a" * 40
QUESTDB_IMAGE_DIGEST = "sha256:" + "b" * 64


def write_bytes(
    path: Path,
    raw: bytes,
    *,
    mode: int = 0o600,
) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(
    path: Path,
    payload: dict,
    *,
    mode: int = 0o600,
) -> Path:
    return write_bytes(
        path,
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        mode=mode,
    )


def public_key_base64(
    private_key: Ed25519PrivateKey,
) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


@dataclass
class Fixture:
    private_key: Ed25519PrivateKey
    keyring_path: Path
    keyring_sha256: str
    evidence_paths: release_module.DeploymentEvidencePaths
    custody_dir: Path
    custody_identity_sha256: str
    draft: dict


def build_fixture(tmp_path: Path) -> Fixture:
    private_key = Ed25519PrivateKey.generate()
    keyring = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_trusted_keys_v1"
        ),
        "keys": [
            {
                "key_id": "c-fast-readonly-deployment-key-a01",
                "purpose": "readonly_deployment_release_signer",
                "public_key_base64": public_key_base64(private_key),
            }
        ],
    }
    keyring_path = write_json(tmp_path / "trusted-keyring.json", keyring)
    keyring_sha256 = hashlib.sha256(
        release_module.canonical_json(keyring)
    ).hexdigest()

    evidence_values: dict[str, dict] = {
        name: {
            "schema_version": f"test_{name}_v1",
            "artifact_id": f"{name}-a01",
            "secret_value_included": False,
        }
        for name, _field in release_module.EVIDENCE_FILE_FIELDS
    }
    principal_identity_sha256 = "e" * 64
    secret_file_path_sha256 = hashlib.sha256(
        b"/run/secrets/c-fast-t1-questdb-readonly-password"
    ).hexdigest()
    evidence_values["questdb_image_attestation"] = {
        "schema_version": (
            "commodity_c_fast_questdb_image_attestation_v1"
        ),
        "attestation_id": "questdb-image-attestation-a01",
        "source_commit_sha": SOURCE_COMMIT_SHA,
        "questdb_image_digest": QUESTDB_IMAGE_DIGEST,
        "questdb_target_identity_sha256": "c" * 64,
        "questdb_build_sha256": "d" * 64,
        "external_verification_asserted": True,
    }
    evidence_values[
        "readonly_principal_identity_attestation"
    ] = {
        "schema_version": (
            "commodity_c_fast_readonly_principal_identity_attestation_v1"
        ),
        "attestation_id": "readonly-principal-attestation-a01",
        "readonly_principal_identity_sha256": (
            principal_identity_sha256
        ),
        "principal_differs_from_admin": True,
        "principal_name_included": False,
        "secret_included": False,
    }
    evidence_values["secret_file_identity_attestation"] = {
        "schema_version": (
            "commodity_c_fast_readonly_secret_file_identity_attestation_v1"
        ),
        "attestation_id": "readonly-secret-file-attestation-a01",
        "secret_file_path_sha256": secret_file_path_sha256,
        "owner_uid": 65532,
        "owner_gid": 65532,
        "mode": "0600",
        "regular_file": True,
        "symlink": False,
        "secret_content_included": False,
    }
    evidence_files = {
        name: write_json(tmp_path / f"{name}.json", payload)
        for name, payload in evidence_values.items()
    }
    evidence_paths = release_module.DeploymentEvidencePaths(
        **evidence_files
    )
    evidence_hashes = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in evidence_files.items()
    }
    evidence_bundle_index = hashlib.sha256(
        release_module.canonical_json(evidence_hashes)
    ).hexdigest()

    custody_dir = tmp_path / "custody"
    custody_dir.mkdir(mode=0o700)
    custody_identity = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_custody_identity_v1"
        ),
        "custody_id": "c-fast-readonly-deployment-custody-a01",
    }
    write_json(
        custody_dir
        / release_module.CUSTODY_IDENTITY_FILENAME,
        custody_identity,
    )
    custody_identity_sha256 = hashlib.sha256(
        release_module.canonical_json(custody_identity)
    ).hexdigest()

    release_id = "c-fast-readonly-deployment-release-a01"
    draft = {
        "schema_version": (
            "commodity_c_fast_readonly_deployment_release_v1"
        ),
        "purpose": "c_fast_questdb_readonly_principal_deployment",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "issue_number": 114,
        "release_id": release_id,
        "issued_at": (NOW - timedelta(minutes=5)).isoformat(),
        "not_before": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=30)).isoformat(),
        "signer_key_id": "c-fast-readonly-deployment-key-a01",
        "signer_type": "human",
        "reviewer_role": "human_l3_readonly_deployment_reviewer",
        "human_signature": (
            "Approved exact one-shot readonly principal deployment."
        ),
        "trusted_keyring_sha256": keyring_sha256,
        "pin_root_path_sha256": (
            release_module.pin_root_path_sha256()
        ),
        "custody_identity_sha256": custody_identity_sha256,
        "custody_path_sha256": t1_module.custody_path_sha256(
            custody_dir
        ),
        "source_commit_sha": SOURCE_COMMIT_SHA,
        "verifier_sha256": hashlib.sha256(
            release_module.VERIFIER_PATH.read_bytes()
        ).hexdigest(),
        "release_schema_sha256": hashlib.sha256(
            release_module.RELEASE_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "consume_schema_sha256": hashlib.sha256(
            release_module.CONSUME_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "receipt_schema_sha256": hashlib.sha256(
            release_module.RECEIPT_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "questdb_image_digest": QUESTDB_IMAGE_DIGEST,
        "questdb_target_identity_sha256": "c" * 64,
        "questdb_build_sha256": "d" * 64,
        "readonly_principal_identity_sha256": (
            principal_identity_sha256
        ),
        "secret_file_path_sha256": secret_file_path_sha256,
        "secret_file_expected_owner_uid": 65532,
        "secret_file_expected_owner_gid": 65532,
        "secret_file_expected_mode": "0600",
        "secret_file_regular_file_required": True,
        "secret_file_symlink_allowed": False,
        "secret_content_read_authorized": False,
        "evidence_bundle_index_sha256": evidence_bundle_index,
        "max_deployment_seconds": 1800,
        "allowed_restart_count": 1,
        "rollback_deadline_seconds": 900,
        "principal_must_differ_from_admin": True,
        "readonly_password_value_source_required": "file",
        "global_pgwire_readonly_allowed": False,
        "instance_readonly_allowed": False,
        "writer_continuity_required": True,
        "post_restart_health_required": True,
        "backlog_drain_required": True,
        "rollback_required": True,
        "isolated_network_required": True,
        "readonly_principal_deployment_authorized": True,
        "readonly_secret_file_installation_authorized": True,
        "questdb_restart_authorized": True,
        "questdb_recreate_authorized": False,
        "questdb_image_change_authorized": False,
        "writer_identity_mutation_authorized": False,
        "writer_secret_mutation_authorized": False,
        "network_mutation_authorized": False,
        "unscoped_deployment_mutation_authorized": False,
        "production_query_authorized": False,
        "readonly_query_authorized": False,
        "collection_authorized": False,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "strategy_activation_authorized": False,
        "automatic_promotion_authorized": False,
        "web_bridge_deployment_authorized": False,
        "replay_allowed": False,
        "receipt_is_authority": False,
    }
    for name, release_field in release_module.EVIDENCE_FILE_FIELDS:
        draft[release_field] = evidence_hashes[name]
    return Fixture(
        private_key=private_key,
        keyring_path=keyring_path,
        keyring_sha256=keyring_sha256,
        evidence_paths=evidence_paths,
        custody_dir=custody_dir,
        custody_identity_sha256=custody_identity_sha256,
        draft=draft,
    )


def sign_fixture(
    fixture: Fixture,
) -> dict:
    return signer_module.sign_release(
        fixture.draft,
        fixture.private_key,
        fixture.evidence_paths,
        fixture.keyring_path,
        expected_keyring_sha256=fixture.keyring_sha256,
        source_commit_sha=SOURCE_COMMIT_SHA,
        questdb_image_digest=QUESTDB_IMAGE_DIGEST,
        now=NOW,
    )


def execution_args(
    fixture: Fixture,
    release_path: Path,
) -> argparse.Namespace:
    values = {
        "release": release_path,
        "trusted_keyring": fixture.keyring_path,
        "custody_dir": fixture.custody_dir,
        "source_commit_sha": SOURCE_COMMIT_SHA,
        "questdb_image_digest": QUESTDB_IMAGE_DIGEST,
    }
    values.update(fixture.evidence_paths.as_dict())
    return argparse.Namespace(**values)


def test_signed_release_consumes_once_and_receipt_has_no_authority(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    signed = sign_fixture(fixture)
    release_path = write_json(tmp_path / "signed-release.json", signed)
    args = execution_args(fixture, release_path)

    verified = release_module.verify_release(
        release_path,
        fixture.keyring_path,
        fixture.evidence_paths,
        source_commit_sha=SOURCE_COMMIT_SHA,
        questdb_image_digest=QUESTDB_IMAGE_DIGEST,
        pinned_keyring_sha256=fixture.keyring_sha256,
        now=NOW,
    )
    assert verified.payload["attempt_id"] == (
        release_module.release_attempt_id(signed["release_id"])
    )
    assert verified.evidence_bundle_index_sha256 == (
        signed["evidence_bundle_index_sha256"]
    )

    receipt = release_module.consume_release(
        args,
        now=NOW,
        pinned_keyring_sha256=fixture.keyring_sha256,
        pinned_custody_path=fixture.custody_dir,
    )

    assert receipt["signature_verified"] is True
    assert receipt["deployment_executed"] is False
    assert receipt["receipt_authority_state"] == (
        "NON_AUTHORITATIVE_OFFLINE_VERIFICATION_RECEIPT"
    )
    for field in (
        "receipt_is_authority",
        "authority_granted",
        "replay_allowed",
        "readonly_principal_deployment_authorized",
        "readonly_secret_file_installation_authorized",
        "questdb_restart_authorized",
        "questdb_recreate_authorized",
        "network_mutation_authorized",
        "unscoped_deployment_mutation_authorized",
        "production_query_authorized",
        "readonly_query_authorized",
        "collection_authorized",
        "write_probe_authorized",
        "database_mutation_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "trading_authorized",
        "strategy_activation_authorized",
        "automatic_promotion_authorized",
        "web_bridge_deployment_authorized",
    ):
        assert receipt[field] is False

    consume_path = fixture.custody_dir / (
        f"{signed['attempt_id']}.deployment-consumed.json"
    )
    receipt_path = fixture.custody_dir / (
        f"{signed['attempt_id']}.deployment-receipt.json"
    )
    assert consume_path.exists()
    assert receipt_path.exists()
    assert consume_path.stat().st_mode & 0o777 == 0o600
    assert receipt_path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="RELEASE_ALREADY_CONSUMED_REPLAY_FORBIDDEN",
    ):
        release_module.consume_release(
            args,
            now=NOW,
            pinned_keyring_sha256=fixture.keyring_sha256,
            pinned_custody_path=fixture.custody_dir,
        )


def test_wrong_key_purpose_and_keyring_permissions_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    keyring = json.loads(
        fixture.keyring_path.read_text(encoding="utf-8")
    )
    keyring["keys"][0]["purpose"] = "t1_audit_release_signer"
    write_json(fixture.keyring_path, keyring)
    wrong_pin = hashlib.sha256(
        release_module.canonical_json(keyring)
    ).hexdigest()
    draft = {
        **fixture.draft,
        "trusted_keyring_sha256": wrong_pin,
    }
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="wrong-purpose",
    ):
        signer_module.sign_release(
            draft,
            fixture.private_key,
            fixture.evidence_paths,
            fixture.keyring_path,
            expected_keyring_sha256=wrong_pin,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            now=NOW,
        )

    write_json(fixture.keyring_path, keyring, mode=0o644)
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="permissions",
    ):
        release_module._load_json(
            fixture.keyring_path,
            "keyring",
            private=True,
        )


def test_duplicate_nan_symlink_and_wrong_evidence_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    signed = sign_fixture(fixture)
    valid_raw = json.dumps(
        signed,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    duplicate = valid_raw.replace(
        b'{"allowed_restart_count":',
        b'{"release_id":"duplicate-release","allowed_restart_count":',
        1,
    )
    duplicate_path = write_bytes(
        tmp_path / "duplicate-release.json",
        duplicate,
    )
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="duplicate JSON key",
    ):
        release_module.verify_release(
            duplicate_path,
            fixture.keyring_path,
            fixture.evidence_paths,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            pinned_keyring_sha256=fixture.keyring_sha256,
            now=NOW,
        )

    nonfinite = valid_raw.replace(
        b'"max_deployment_seconds":1800',
        b'"max_deployment_seconds":NaN',
    )
    nonfinite_path = write_bytes(
        tmp_path / "nan-release.json",
        nonfinite,
    )
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="non-finite",
    ):
        release_module.verify_release(
            nonfinite_path,
            fixture.keyring_path,
            fixture.evidence_paths,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            pinned_keyring_sha256=fixture.keyring_sha256,
            now=NOW,
        )

    original = fixture.evidence_paths.health_evidence
    symlink = tmp_path / "health-link.json"
    symlink.symlink_to(original)
    symlinked = release_module.DeploymentEvidencePaths(
        **{
            **fixture.evidence_paths.as_dict(),
            "health_evidence": symlink,
        }
    )
    release_path = write_json(tmp_path / "signed-release.json", signed)
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="must not be a symlink",
    ):
        release_module.verify_release(
            release_path,
            fixture.keyring_path,
            symlinked,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            pinned_keyring_sha256=fixture.keyring_sha256,
            now=NOW,
        )

    original.write_bytes(original.read_bytes() + b" ")
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="does not match exact evidence bytes",
    ):
        release_module.verify_release(
            release_path,
            fixture.keyring_path,
            fixture.evidence_paths,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            pinned_keyring_sha256=fixture.keyring_sha256,
            now=NOW,
        )


def test_same_fd_content_change_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = write_bytes(tmp_path / "evidence.json", b"same-length-one")
    calls = 0

    def inconsistent_read(
        _descriptor: int,
        _label: str,
        _limit: int,
    ) -> bytes:
        nonlocal calls
        calls += 1
        return b"same-length-one" if calls == 1 else b"same-length-two"

    monkeypatch.setattr(
        t1_module,
        "_read_fd_bounded",
        inconsistent_read,
    )
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="changed while it was being read",
    ):
        release_module._sha256_file(target, "evidence")


def test_attestation_content_must_match_signed_expectations(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    secret_path = (
        fixture.evidence_paths.secret_file_identity_attestation
    )
    secret_attestation = json.loads(
        secret_path.read_text(encoding="utf-8")
    )
    secret_attestation["mode"] = "0644"
    write_json(secret_path, secret_attestation)
    evidence_hashes = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in fixture.evidence_paths.as_dict().items()
    }
    draft = {
        **fixture.draft,
        "secret_file_identity_attestation_raw_sha256": (
            evidence_hashes["secret_file_identity_attestation"]
        ),
        "evidence_bundle_index_sha256": hashlib.sha256(
            release_module.canonical_json(evidence_hashes)
        ).hexdigest(),
    }

    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="secret file identity attestation bindings",
    ):
        signer_module.sign_release(
            draft,
            fixture.private_key,
            fixture.evidence_paths,
            fixture.keyring_path,
            expected_keyring_sha256=fixture.keyring_sha256,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            now=NOW,
        )


def test_expired_release_and_forbidden_capability_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    expired = {
        **fixture.draft,
        "issued_at": (NOW - timedelta(hours=3)).isoformat(),
        "not_before": (NOW - timedelta(hours=2)).isoformat(),
        "expires_at": (NOW - timedelta(hours=1)).isoformat(),
    }
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="expired|TTL",
    ):
        signer_module.sign_release(
            expired,
            fixture.private_key,
            fixture.evidence_paths,
            fixture.keyring_path,
            expected_keyring_sha256=fixture.keyring_sha256,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            now=NOW,
        )

    forbidden = {
        **fixture.draft,
        "production_query_authorized": True,
    }
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="schema validation|forbidden authority",
    ):
        signer_module.sign_release(
            forbidden,
            fixture.private_key,
            fixture.evidence_paths,
            fixture.keyring_path,
            expected_keyring_sha256=fixture.keyring_sha256,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            now=NOW,
        )

    coercive_integer = {
        **fixture.draft,
        "max_deployment_seconds": 1800.0,
    }
    with pytest.raises(
        release_module.DeploymentReleaseError,
        match="integer JSON literal",
    ):
        signer_module.sign_release(
            coercive_integer,
            fixture.private_key,
            fixture.evidence_paths,
            fixture.keyring_path,
            expected_keyring_sha256=fixture.keyring_sha256,
            source_commit_sha=SOURCE_COMMIT_SHA,
            questdb_image_digest=QUESTDB_IMAGE_DIGEST,
            now=NOW,
        )
