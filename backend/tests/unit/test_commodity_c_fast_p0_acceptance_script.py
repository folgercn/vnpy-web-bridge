from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_l1_l5_audit as audit_module  # noqa: E402
import commodity_c_fast_p0_acceptance as acceptance_module  # noqa: E402
import commodity_c_fast_p0_sign_acceptance as signer_module  # noqa: E402
import commodity_c_fast_t1_one_shot as t1_module  # noqa: E402


RELEASE_NOW = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
ENDPOINT_SHA256 = "c" * 64
SOURCE_COMMIT_SHA = "a" * 40
RUNTIME_IMAGE_DIGEST = "sha256:" + "b" * 64
QUESTDB_BUILD = "Build Information: QuestDB 9.4.3"
PRODUCTS = audit_module.FROZEN_PRODUCTS
EXCHANGES = audit_module.PRODUCT_EXCHANGES
AUDIT_START = datetime(2026, 8, 31, 12, tzinfo=timezone.utc)
AUDIT_END = datetime(2026, 9, 1, 8, tzinfo=timezone.utc)
SESSION_BOUNDS = {
    "night_open": (
        datetime(2026, 8, 31, 13, 0, tzinfo=timezone.utc),
        datetime(2026, 8, 31, 13, 2, 5, tzinfo=timezone.utc),
    ),
    "night_session": (
        datetime(2026, 8, 31, 13, 10, tzinfo=timezone.utc),
        datetime(2026, 8, 31, 13, 20, tzinfo=timezone.utc),
    ),
    "day_open": (
        datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 1, 2, 5, tzinfo=timezone.utc),
    ),
    "day_session": (
        datetime(2026, 9, 1, 1, 10, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 1, 20, tzinfo=timezone.utc),
    ),
}


def write_bytes(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(
    path: Path,
    payload: dict,
    *,
    indent: int | None = None,
    mode: int = 0o600,
) -> Path:
    return write_bytes(
        path,
        (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                indent=indent,
            )
            + "\n"
        ).encode("utf-8"),
        mode=mode,
    )


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def canonical_sha256(payload: dict) -> str:
    return hashlib.sha256(
        t1_module.canonical_json(payload)
    ).hexdigest()


def manifest_payload() -> dict:
    execution_time = datetime(2026, 9, 1, 1, 1, tzinfo=timezone.utc)
    return {
        "schema_version": (
            "commodity_c_fast_l1_l5_audit_manifest_v2"
        ),
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_id": "c-fast-p0-acceptance-a01",
        "audit_window": {
            "start": AUDIT_START.isoformat(),
            "end_exclusive": AUDIT_END.isoformat(),
            "trading_day": "20260901",
        },
        "session_windows": {
            name: {
                "start": start.isoformat(),
                "end_exclusive": end.isoformat(),
            }
            for name, (start, end) in SESSION_BOUNDS.items()
        },
        "targets": [
            {
                "product": product,
                "exact_contract": f"{EXCHANGES[product]}.{product}2609",
                "previous_exact_contract": None,
                "roll_expected": False,
            }
            for product in PRODUCTS
        ],
        "execution_windows": [
            {
                "window_id": f"{product}-window-a01",
                "product": product,
                "exact_contract": f"{EXCHANGES[product]}.{product}2609",
                "execution_time": execution_time.isoformat(),
                "window_seconds": 60,
            }
            for product in PRODUCTS
        ],
    }


def tick_row(
    timestamp: datetime,
    *,
    index: int,
) -> dict:
    row = {
        "ts": timestamp,
        "received_at": timestamp + timedelta(milliseconds=100),
        "ingest_id": f"tick-{index}",
        "ingest_seq": index + 1,
        "trading_day": "20260901",
        "last_price": 100,
        "last_volume": 0 if index == 0 else 1,
        "volume": 10 + index,
    }
    for level in range(1, 6):
        row[f"bid_price_{level}"] = 100 - level
        row[f"ask_price_{level}"] = 100 + level
        row[f"bid_volume_{level}"] = 10
        row[f"ask_volume_{level}"] = 11
    return row


def complete_rows() -> list[dict]:
    timestamps = [
        timestamp
        for start, end in SESSION_BOUNDS.values()
        for timestamp in (
            start + timedelta(seconds=offset)
            for offset in range(
                0,
                int((end - start).total_seconds()),
                5,
            )
        )
    ]
    return [
        tick_row(timestamp, index=index)
        for index, timestamp in enumerate(timestamps)
    ]


class FakeCursor:
    def __init__(self, rows: list[tuple]) -> None:
        self.rows = rows
        self.offset = 0

    def fetchmany(self, size: int) -> list[tuple]:
        result = self.rows[self.offset : self.offset + size]
        self.offset += len(result)
        return result


class FakeConnection:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows

    def execute(self, _sql: str, _params: tuple) -> FakeCursor:
        return FakeCursor(
            [
                tuple(row.get(column) for column in audit_module.QUERY_COLUMNS)
                for row in self.rows
            ]
        )


@dataclass
class Fixture:
    paths: acceptance_module.P0BundlePaths
    t1_keyring_sha256: str
    acceptance_keyring_path: Path
    acceptance_keyring_sha256: str
    acceptance_private_key: Ed25519PrivateKey
    t1_private_key: Ed25519PrivateKey
    release: dict
    consume: dict
    terminal: dict


def build_fixture(
    tmp_path: Path,
    *,
    reserved_t1_authority_key: Ed25519PrivateKey | None = None,
    acceptance_private_key: Ed25519PrivateKey | None = None,
) -> Fixture:
    manifest_path = write_json(
        tmp_path / "manifest.json",
        manifest_payload(),
        indent=2,
    )
    manifest, contracts, sessions, windows = audit_module.load_manifest(
        manifest_path
    )
    evidence = audit_module.audit(
        FakeConnection(complete_rows()),
        manifest,
        contracts,
        sessions,
        windows,
        AUDIT_START,
        AUDIT_END,
    )
    evidence["generated_at"] = (
        RELEASE_NOW + timedelta(minutes=1, seconds=2)
    ).isoformat()
    assert evidence["summary"]["p0_pass"] is True
    audit_json_path = write_json(
        tmp_path / "audit.json",
        evidence,
        indent=2,
    )
    audit_json_sha256 = hashlib.sha256(
        audit_json_path.read_bytes()
    ).hexdigest()
    proof_snapshot = audit_module.ReadonlyProofSnapshot(
        principal="c_fast_audit_reader",
        readonly_user="c_fast_audit_reader",
        admin_user="bridge_writer",
        questdb_build=QUESTDB_BUILD,
        readonly_user_enabled_source="env",
        readonly_user_source="env",
        readonly_password_source="file",
        admin_user_source="env",
        global_pgwire_readonly_source="default",
        instance_readonly_source="default",
    )
    proof = audit_module.build_readonly_proof(
        evidence,
        audit_json_sha256,
        proof_snapshot,
        proof_snapshot,
        ENDPOINT_SHA256,
    )
    proof["generated_at"] = (
        RELEASE_NOW + timedelta(minutes=1, seconds=3)
    ).isoformat()
    proof_path = write_json(
        tmp_path / "readonly-proof.json",
        proof,
        indent=2,
    )
    frozen_manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )
    audit_csv_path = write_bytes(
        tmp_path / "audit.csv",
        b"product,classification\nall,L5_USABLE\n",
    )
    audit_markdown_path = write_bytes(
        tmp_path / "audit.md",
        b"# C_FAST P0 PASS\n",
    )

    t1_private_key = Ed25519PrivateKey.generate()
    t1_keyring = {
        "schema_version": "commodity_c_fast_t1_trusted_keys_v1",
        "keys": [
            {
                "key_id": "c-fast-t1-release-key-a01",
                "purpose": "t1_audit_release_signer",
                "public_key_base64": public_key_base64(t1_private_key),
            }
        ],
    }
    if reserved_t1_authority_key is not None:
        t1_keyring["keys"].append(
            {
                "key_id": "c-fast-t1-release-key-reserved",
                "purpose": "t1_audit_release_signer",
                "public_key_base64": public_key_base64(
                    reserved_t1_authority_key
                ),
            }
        )
    t1_keyring_path = write_json(
        tmp_path / "t1-keyring.json",
        t1_keyring,
    )
    t1_keyring_sha256 = canonical_sha256(t1_keyring)
    release_id = "c-fast-t1-p0-acceptance-a01"
    release = {
        "schema_version": "commodity_c_fast_t1_one_shot_release_v1",
        "purpose": "c_fast_l1_l5_t1_readonly_audit",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "issue_number": 114,
        "release_id": release_id,
        "attempt_id": t1_module.release_attempt_id(release_id),
        "issued_at": (
            RELEASE_NOW - timedelta(minutes=2)
        ).isoformat(),
        "not_before": (
            RELEASE_NOW - timedelta(minutes=1)
        ).isoformat(),
        "expires_at": (
            RELEASE_NOW + timedelta(hours=1)
        ).isoformat(),
        "signer_key_id": "c-fast-t1-release-key-a01",
        "signer_type": "human",
        "reviewer_role": "T1 release reviewer",
        "human_signature": "Approved one read-only T1 audit.",
        "trusted_keyring_sha256": t1_keyring_sha256,
        "custody_identity_sha256": "d" * 64,
        "custody_path_sha256": "e" * 64,
        "source_commit_sha": SOURCE_COMMIT_SHA,
        "runtime_image_digest": RUNTIME_IMAGE_DIGEST,
        "runner_sha256": t1_module.sha256_regular_file(
            t1_module.RUNNER_PATH,
            "runner",
        ),
        "audit_script_sha256": t1_module.sha256_regular_file(
            t1_module.AUDIT_SCRIPT_PATH,
            "audit script",
        ),
        "manifest_schema_sha256": t1_module.sha256_regular_file(
            t1_module.MANIFEST_SCHEMA_PATH,
            "manifest schema",
        ),
        "evidence_schema_sha256": t1_module.sha256_regular_file(
            t1_module.EVIDENCE_SCHEMA_PATH,
            "evidence schema",
        ),
        "legacy_evidence_schema_sha256": t1_module.sha256_regular_file(
            t1_module.LEGACY_EVIDENCE_SCHEMA_PATH,
            "legacy evidence schema",
        ),
        "readonly_proof_schema_sha256": t1_module.sha256_regular_file(
            t1_module.READONLY_PROOF_SCHEMA_PATH,
            "readonly proof schema",
        ),
        "snapshot_id": frozen_manifest["snapshot_id"],
        "manifest_sha256": canonical_sha256(frozen_manifest),
        "audit_window": frozen_manifest["audit_window"],
        "endpoint_identity_sha256": ENDPOINT_SHA256,
        "questdb_build_sha256": hashlib.sha256(
            QUESTDB_BUILD.encode("utf-8")
        ).hexdigest(),
        "connect_timeout_seconds": 10,
        "statement_timeout_ms": 60_000,
        "max_rows_per_contract": 500_000,
        "max_runtime_seconds": 300,
        "network_authorized": True,
        "readonly_production_query_authorized": True,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "deployment_mutation_authorized": False,
    }
    release["signature"] = base64.b64encode(
        t1_private_key.sign(
            t1_module.canonical_json(release)
        )
    ).decode("ascii")
    release_path = write_json(
        tmp_path / "t1-release.json",
        release,
        indent=2,
    )
    release_canonical_sha256 = canonical_sha256(release)
    consumed_at = RELEASE_NOW + timedelta(minutes=1)
    consume = {
        "schema_version": "commodity_c_fast_t1_consume_v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "release_id": release_id,
        "attempt_id": release["attempt_id"],
        "release_sha256": release_canonical_sha256,
        "consumed_at": consumed_at.isoformat(),
        "manifest_sha256": release["manifest_sha256"],
        "endpoint_identity_sha256": ENDPOINT_SHA256,
        "source_commit_sha": SOURCE_COMMIT_SHA,
        "runtime_image_digest": RUNTIME_IMAGE_DIGEST,
        "runner_sha256": release["runner_sha256"],
        "audit_script_sha256": release["audit_script_sha256"],
        "trusted_keyring_sha256": t1_keyring_sha256,
        "custody_identity_sha256": release["custody_identity_sha256"],
        "custody_path_sha256": release["custody_path_sha256"],
        "replay_allowed": False,
    }
    consume_path = write_json(
        tmp_path / "consume.json",
        consume,
        indent=2,
    )
    artifact_sha256 = {
        "audit_json": hashlib.sha256(
            audit_json_path.read_bytes()
        ).hexdigest(),
        "audit_csv": hashlib.sha256(
            audit_csv_path.read_bytes()
        ).hexdigest(),
        "audit_markdown": hashlib.sha256(
            audit_markdown_path.read_bytes()
        ).hexdigest(),
        "readonly_proof": hashlib.sha256(
            proof_path.read_bytes()
        ).hexdigest(),
    }
    started_at = consumed_at
    attempt_dir = tmp_path / release["attempt_id"]
    bundle_root = attempt_dir / "verified-bundle"
    invocation_artifacts = t1_module.ArtifactPaths(
        audit_json=attempt_dir / "artifacts/audit.json",
        audit_csv=attempt_dir / "artifacts/audit.csv",
        audit_markdown=attempt_dir / "artifacts/audit.md",
        readonly_proof=attempt_dir / "artifacts/readonly-proof.json",
    )
    dsn_path = write_bytes(
        tmp_path / "readonly.dsn",
        b"postgresql://readonly@example.invalid:8812/qdb",
    )
    child_invocation = t1_module.build_child_invocation(
        release,
        bundle_root / "scripts/commodity_c_fast_l1_l5_audit.py",
        bundle_root / "release/manifest.json",
        dsn_path,
        invocation_artifacts,
    )
    child_invocation_path = write_bytes(
        tmp_path / "child-invocation.json",
        t1_module.canonical_json(child_invocation),
    )
    terminal = {
        "schema_version": "commodity_c_fast_t1_terminal_seal_v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "release_id": release_id,
        "attempt_id": release["attempt_id"],
        "terminal_state": "SUCCEEDED_P0_PASS",
        "error_code": None,
        "release_sha256": release_canonical_sha256,
        "consume_marker_sha256": hashlib.sha256(
            consume_path.read_bytes()
        ).hexdigest(),
        "child_invocation_sha256": hashlib.sha256(
            child_invocation_path.read_bytes()
        ).hexdigest(),
        "child_exit_code": 0,
        "started_at": started_at.isoformat(),
        "ended_at": (started_at + timedelta(seconds=30)).isoformat(),
        "artifact_sha256": artifact_sha256,
        "manifest_sha256": release["manifest_sha256"],
        "endpoint_identity_sha256": ENDPOINT_SHA256,
        "p0_pass": True,
        "proof_verified": True,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "replay_allowed": False,
        "p0_acceptance_authorized": False,
        "terminal_integrity_scope": (
            "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
        ),
    }
    terminal_path = write_json(
        tmp_path / "terminal.json",
        terminal,
        indent=2,
    )
    external_identity = {
        "schema_version": (
            "commodity_c_fast_p0_external_custody_identity_v1"
        ),
        "custody_id": "c-fast-p0-external-custody-a01",
        "asserted_archive_type": "ASSERTED_WORM",
        "archive_locator_sha256": "1" * 64,
        "independent_from_t1_runner": True,
        "immutability_asserted": True,
    }
    external_identity_path = write_json(
        tmp_path / "external-custody-identity.json",
        external_identity,
    )
    if acceptance_private_key is None:
        acceptance_private_key = Ed25519PrivateKey.generate()
    acceptance_keyring = {
        "schema_version": (
            "commodity_c_fast_p0_acceptance_trusted_keys_v1"
        ),
        "keys": [
            {
                "key_id": "c-fast-p0-acceptance-key-a01",
                "purpose": "c_fast_p0_acceptance_signer",
                "public_key_base64": public_key_base64(
                    acceptance_private_key
                ),
            }
        ],
    }
    acceptance_keyring_path = write_json(
        tmp_path / "acceptance-keyring.json",
        acceptance_keyring,
    )
    return Fixture(
        paths=acceptance_module.P0BundlePaths(
            t1_release=release_path,
            t1_trusted_keyring=t1_keyring_path,
            manifest=manifest_path,
            consume_marker=consume_path,
            terminal_seal=terminal_path,
            child_invocation=child_invocation_path,
            audit_json=audit_json_path,
            audit_csv=audit_csv_path,
            audit_markdown=audit_markdown_path,
            readonly_proof=proof_path,
            external_custody_identity=external_identity_path,
        ),
        t1_keyring_sha256=t1_keyring_sha256,
        acceptance_keyring_path=acceptance_keyring_path,
        acceptance_keyring_sha256=canonical_sha256(
            acceptance_keyring
        ),
        acceptance_private_key=acceptance_private_key,
        t1_private_key=t1_private_key,
        release=release,
        consume=consume,
        terminal=terminal,
    )


def acceptance_draft(
    fixture: Fixture,
    verified: acceptance_module.VerifiedP0Bundle,
) -> dict:
    terminal = verified.terminal
    archived_at = (
        t1_module.parse_datetime(terminal["ended_at"], "ended_at")
        + timedelta(minutes=10)
    )
    return {
        "schema_version": "commodity_c_fast_p0_acceptance_v1",
        "purpose": "c_fast_p0_terminal_acceptance",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "issue_number": 114,
        "acceptance_id": acceptance_module.acceptance_id_for_terminal(
            verified.raw_sha256["terminal_seal"]
        ),
        "accepted_at": (
            archived_at + timedelta(days=30)
        ).isoformat(),
        "signer_key_id": "c-fast-p0-acceptance-key-a01",
        "signer_type": "human",
        "reviewer_role": "independent P0 terminal reviewer",
        "human_signature": "Accepted exact archived P0 evidence bundle.",
        "acceptance_keyring_sha256": (
            fixture.acceptance_keyring_sha256
        ),
        "release_id": verified.release["release_id"],
        "attempt_id": verified.release["attempt_id"],
        "source_commit_sha": verified.release["source_commit_sha"],
        "runtime_image_digest": verified.release["runtime_image_digest"],
        "t1_trusted_keyring_sha256": verified.t1_keyring_sha256,
        "t1_release_raw_sha256": verified.raw_sha256["t1_release"],
        "t1_release_canonical_sha256": (
            verified.canonical_sha256["t1_release"]
        ),
        "manifest_raw_sha256": verified.raw_sha256["manifest"],
        "manifest_canonical_sha256": (
            verified.canonical_sha256["manifest"]
        ),
        "consume_marker_raw_sha256": (
            verified.raw_sha256["consume_marker"]
        ),
        "terminal_seal_raw_sha256": (
            verified.raw_sha256["terminal_seal"]
        ),
        "terminal_seal_canonical_sha256": (
            verified.canonical_sha256["terminal_seal"]
        ),
        "child_invocation_raw_sha256": (
            verified.raw_sha256["child_invocation"]
        ),
        "artifact_sha256": verified.artifact_sha256,
        "bundle_index_sha256": verified.bundle_index_sha256,
        "snapshot_id": verified.release["snapshot_id"],
        "audit_window": verified.release["audit_window"],
        "endpoint_identity_sha256": (
            verified.release["endpoint_identity_sha256"]
        ),
        "questdb_build_sha256": (
            verified.release["questdb_build_sha256"]
        ),
        "consumed_at": verified.consume["consumed_at"],
        "started_at": terminal["started_at"],
        "ended_at": terminal["ended_at"],
        "external_archive": {
            "custody_id": (
                verified.external_custody_identity["custody_id"]
            ),
            "asserted_archive_type": (
                verified.external_custody_identity[
                    "asserted_archive_type"
                ]
            ),
            "archive_locator_sha256": (
                verified.external_custody_identity[
                    "archive_locator_sha256"
                ]
            ),
            "custody_identity_raw_sha256": (
                verified.external_custody_identity_raw_sha256
            ),
            "custody_identity_canonical_sha256": (
                verified.external_custody_identity_canonical_sha256
            ),
            "archived_bundle_index_sha256": (
                verified.bundle_index_sha256
            ),
            "archived_at": archived_at.isoformat(),
            "independent_custody_asserted": True,
            "immutability_asserted": True,
        },
        "external_archive_verification_state": (
            "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED"
        ),
        "terminal_state": "SUCCEEDED_P0_PASS",
        "p0_pass": True,
        "proof_verified": True,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "p0_accepted": True,
        "p0_acceptance_scope": "INDEPENDENT_SIGNED_HUMAN_ACCEPTANCE",
        "source_terminal_integrity_scope": (
            "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
        ),
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "replacement_authorized": False,
        "production_authorized": False,
        "automatic_promotion_authorized": False,
        "dynamic_selection_allowed": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
    }


def sign_fixture(
    fixture: Fixture,
) -> tuple[dict, acceptance_module.VerifiedP0Bundle]:
    verified = acceptance_module.verify_t1_bundle(
        fixture.paths,
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )
    signed = signer_module.sign_acceptance(
        acceptance_draft(fixture, verified),
        fixture.acceptance_private_key,
        fixture.acceptance_keyring_path,
        fixture.paths,
        expected_acceptance_keyring_sha256=(
            fixture.acceptance_keyring_sha256
        ),
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )
    return signed, verified


def test_historical_expired_release_can_receive_offline_p0_acceptance(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    signed, verified = sign_fixture(fixture)
    acceptance_path = write_json(
        tmp_path / "signed-acceptance.json",
        signed,
        indent=2,
    )

    accepted, digest = acceptance_module.verify_signed_acceptance(
        acceptance_path,
        fixture.acceptance_keyring_path,
        fixture.paths,
        expected_acceptance_keyring_sha256=(
            fixture.acceptance_keyring_sha256
        ),
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )

    release_expires = t1_module.parse_datetime(
        fixture.release["expires_at"],
        "expires_at",
    )
    accepted_at = t1_module.parse_datetime(
        accepted["accepted_at"],
        "accepted_at",
    )
    assert accepted_at > release_expires
    assert accepted["p0_accepted"] is True
    assert accepted["collection_authorized"] is False
    assert accepted["runtime_activation_authorized"] is False
    assert accepted["dispatch_authorized"] is False
    assert accepted["production_authorized"] is False
    assert accepted["dynamic_selection_allowed"] is False
    assert accepted["database_mutation_authorized"] is False
    assert accepted["deployment_mutation_authorized"] is False
    assert digest == acceptance_module.acceptance_sha256(accepted)
    assert (
        accepted["bundle_index_sha256"]
        == verified.bundle_index_sha256
    )


def test_consume_must_be_inside_original_release_window(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    consume = dict(fixture.consume)
    consume["consumed_at"] = (
        t1_module.parse_datetime(
            fixture.release["expires_at"],
            "expires_at",
        )
        + timedelta(seconds=1)
    ).isoformat()
    write_json(fixture.paths.consume_marker, consume, indent=2)
    terminal = dict(fixture.terminal)
    terminal["consume_marker_sha256"] = hashlib.sha256(
        fixture.paths.consume_marker.read_bytes()
    ).hexdigest()
    terminal["started_at"] = consume["consumed_at"]
    terminal["ended_at"] = (
        t1_module.parse_datetime(terminal["started_at"], "started_at")
        + timedelta(seconds=30)
    ).isoformat()
    write_json(fixture.paths.terminal_seal, terminal, indent=2)

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="original release window",
    ):
        acceptance_module.verify_t1_bundle(
            fixture.paths,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_terminal_start_must_equal_consume_time(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    terminal = dict(fixture.terminal)
    terminal["started_at"] = (
        t1_module.parse_datetime(
            fixture.consume["consumed_at"],
            "consumed_at",
        )
        + timedelta(milliseconds=1)
    ).isoformat()
    write_json(fixture.paths.terminal_seal, terminal, indent=2)

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="must equal",
    ):
        acceptance_module.verify_t1_bundle(
            fixture.paths,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_blocked_terminal_is_never_acceptable(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    terminal = dict(fixture.terminal)
    terminal.update(
        {
            "terminal_state": "COMPLETED_P0_BLOCKED",
            "child_exit_code": 1,
            "p0_pass": False,
        }
    )
    write_json(fixture.paths.terminal_seal, terminal, indent=2)

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="SUCCEEDED_P0_PASS",
    ):
        acceptance_module.verify_t1_bundle(
            fixture.paths,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_exact_artifact_bytes_are_bound_by_terminal(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    fixture.paths.audit_csv.write_bytes(
        fixture.paths.audit_csv.read_bytes() + b"tampered\n"
    )

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="artifact hashes",
    ):
        acceptance_module.verify_t1_bundle(
            fixture.paths,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_child_invocation_exact_bytes_and_fixed_argv_are_required(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    invocation = json.loads(
        fixture.paths.child_invocation.read_text(encoding="utf-8")
    )
    invocation.extend(["--unexpected-option", "forbidden"])
    write_bytes(
        fixture.paths.child_invocation,
        t1_module.canonical_json(invocation),
    )
    terminal = dict(fixture.terminal)
    terminal["child_invocation_sha256"] = hashlib.sha256(
        fixture.paths.child_invocation.read_bytes()
    ).hexdigest()
    write_json(fixture.paths.terminal_seal, terminal, indent=2)

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="unexpected or missing arguments",
    ):
        acceptance_module.verify_t1_bundle(
            fixture.paths,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


@pytest.mark.parametrize(
    "authority_field",
    [
        "collection_authorized",
        "runtime_activation_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "replacement_authorized",
        "production_authorized",
        "automatic_promotion_authorized",
        "dynamic_selection_allowed",
        "database_mutation_authorized",
        "deployment_mutation_authorized",
    ],
)
def test_acceptance_authority_literals_cannot_be_enabled(
    tmp_path: Path,
    authority_field: str,
) -> None:
    fixture = build_fixture(tmp_path)
    signed, _verified = sign_fixture(fixture)
    signed[authority_field] = True
    acceptance_path = write_json(
        tmp_path / "tampered-acceptance.json",
        signed,
    )

    with pytest.raises(t1_module.OneShotError, match="schema validation"):
        acceptance_module.verify_signed_acceptance(
            acceptance_path,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=(
                fixture.acceptance_keyring_sha256
            ),
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_acceptance_signer_key_purpose_isolated(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    keyring = json.loads(
        fixture.acceptance_keyring_path.read_text(encoding="utf-8")
    )
    keyring["keys"][0]["purpose"] = "t1_audit_release_signer"
    write_json(fixture.acceptance_keyring_path, keyring)
    wrong_hash = canonical_sha256(keyring)
    verified = acceptance_module.verify_t1_bundle(
        fixture.paths,
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )
    draft = acceptance_draft(fixture, verified)
    draft["acceptance_keyring_sha256"] = wrong_hash

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="purpose",
    ):
        signer_module.sign_acceptance(
            draft,
            fixture.acceptance_private_key,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=wrong_hash,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_same_key_material_is_rejected_across_distinct_ids_purposes_and_pins(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    acceptance_keyring = {
        "schema_version": (
            "commodity_c_fast_p0_acceptance_trusted_keys_v1"
        ),
        "keys": [
            {
                "key_id": "independent-looking-acceptance-key",
                "purpose": "c_fast_p0_acceptance_signer",
                "public_key_base64": public_key_base64(
                    fixture.t1_private_key
                ),
            }
        ],
    }
    write_json(fixture.acceptance_keyring_path, acceptance_keyring)
    acceptance_pin = canonical_sha256(acceptance_keyring)
    assert acceptance_pin != fixture.t1_keyring_sha256
    verified = acceptance_module.verify_t1_bundle(
        fixture.paths,
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )
    draft = acceptance_draft(fixture, verified)
    draft["signer_key_id"] = "independent-looking-acceptance-key"
    draft["acceptance_keyring_sha256"] = acceptance_pin

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="cryptographically distinct",
    ):
        signer_module.sign_acceptance(
            draft,
            fixture.t1_private_key,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=acceptance_pin,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )

    signed = {
        **draft,
        "signature": base64.b64encode(
            fixture.t1_private_key.sign(
                t1_module.canonical_json(draft)
            )
        ).decode("ascii"),
    }
    acceptance_path = write_json(
        tmp_path / "same-key-acceptance.json",
        signed,
    )
    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="cryptographically distinct",
    ):
        acceptance_module.verify_signed_acceptance(
            acceptance_path,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=acceptance_pin,
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_acceptance_key_cannot_match_unused_t1_authority(
    tmp_path: Path,
) -> None:
    shared_key = Ed25519PrivateKey.generate()
    fixture = build_fixture(
        tmp_path,
        reserved_t1_authority_key=shared_key,
        acceptance_private_key=shared_key,
    )
    verified = acceptance_module.verify_t1_bundle(
        fixture.paths,
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )
    draft = acceptance_draft(fixture, verified)

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="every T1 audit release authority",
    ):
        signer_module.sign_acceptance(
            draft,
            shared_key,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=(
                fixture.acceptance_keyring_sha256
            ),
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )

    signed = {
        **draft,
        "signature": base64.b64encode(
            shared_key.sign(t1_module.canonical_json(draft))
        ).decode("ascii"),
    }
    acceptance_path = write_json(
        tmp_path / "reserved-key-acceptance.json",
        signed,
    )
    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="every T1 audit release authority",
    ):
        acceptance_module.verify_signed_acceptance(
            acceptance_path,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=(
                fixture.acceptance_keyring_sha256
            ),
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_external_archive_bundle_binding_cannot_be_rewritten(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    verified = acceptance_module.verify_t1_bundle(
        fixture.paths,
        expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
    )
    draft = acceptance_draft(fixture, verified)
    draft["external_archive"]["archived_bundle_index_sha256"] = "9" * 64

    with pytest.raises(
        acceptance_module.P0AcceptanceError,
        match="archived_bundle_index_sha256",
    ):
        signer_module.sign_acceptance(
            draft,
            fixture.acceptance_private_key,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=(
                fixture.acceptance_keyring_sha256
            ),
            expected_t1_keyring_sha256=fixture.t1_keyring_sha256,
        )


def test_acceptance_output_is_create_only_and_private(
    tmp_path: Path,
) -> None:
    fixture = build_fixture(tmp_path)
    signed, _verified = sign_fixture(fixture)
    output = tmp_path / "signed-output.json"

    signer_module.write_private_json_create_only(output, signed)

    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        signer_module.write_private_json_create_only(output, signed)
