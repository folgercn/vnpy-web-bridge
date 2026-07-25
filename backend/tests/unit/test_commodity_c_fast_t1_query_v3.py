from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_l1_l5_audit as audit_module  # noqa: E402
import commodity_c_fast_t1_query_child_v3 as child_module  # noqa: E402
import commodity_c_fast_t1_query_v3 as query_module  # noqa: E402
import commodity_c_fast_t1_query_v3_sign_release as sign_module  # noqa: E402
from commodity_c_fast_t1_one_shot import (  # noqa: E402
    OneShotError,
    VerifiedRelease,
    canonical_json,
    release_attempt_id,
)
from commodity_c_fast_t1_readiness_v2 import (  # noqa: E402
    ReadinessPins,
    ReadinessV2Error,
    VerifiedReadinessPacket,
)


NOW = datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc)
H = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64


def readiness() -> VerifiedReadinessPacket:
    payload = {
        "packet_id": f"readiness-v2-{H}",
        "generated_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=9)).isoformat(),
        "pin_root_path_sha256": H2,
        "source_namespaces": {
            "t1_runtime_source_commit_sha": "1" * 40,
            "l3_contract_source_commit_sha": "2" * 40,
            "outcome_contract_source_commit_assertion": "3" * 40,
        },
        "digest_namespaces": {
            "t1_runtime_image_digest": f"sha256:{H3}",
            "questdb_image_digest": f"sha256:{H4}",
        },
        "t1_runtime": {
            "content_attestation_raw_sha256": H,
            "content_attestation_canonical_sha256": H2,
        },
        "build_registry_provenance": {
            "signed_provenance_raw_sha256": H2,
            "signed_provenance_canonical_sha256": H3,
            "signer_public_key_sha256": H4,
        },
        "readonly_deployment_outcome": {
            "signed_outcome_raw_sha256": H3,
            "signed_outcome_canonical_sha256": H4,
            "signer_public_key_sha256": H5,
            "questdb_target_identity_sha256": H4,
        },
    }
    raw = canonical_json(payload)
    return VerifiedReadinessPacket(
        payload=payload,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_sha256=hashlib.sha256(raw).hexdigest(),
    )


def manifest() -> dict:
    audit_start = datetime(2026, 7, 24, 12, tzinfo=timezone.utc)
    audit_end = datetime(2026, 7, 25, 8, tzinfo=timezone.utc)
    session_bounds = {
        "night_open": (
            datetime(2026, 7, 24, 13, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 24, 13, 2, 5, tzinfo=timezone.utc),
        ),
        "night_session": (
            datetime(2026, 7, 24, 13, 10, tzinfo=timezone.utc),
            datetime(2026, 7, 24, 13, 20, tzinfo=timezone.utc),
        ),
        "day_open": (
            datetime(2026, 7, 25, 1, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 25, 1, 2, 5, tzinfo=timezone.utc),
        ),
        "day_session": (
            datetime(2026, 7, 25, 1, 10, tzinfo=timezone.utc),
            datetime(2026, 7, 25, 1, 20, tzinfo=timezone.utc),
        ),
    }
    return {
        "schema_version": "commodity_c_fast_l1_l5_audit_manifest_v2",
        "candidate_id": query_module.CANDIDATE_ID,
        "snapshot_id": "snapshot-query-v3-test",
        "audit_window": {
            "start": audit_start.isoformat(),
            "end_exclusive": audit_end.isoformat(),
            "trading_day": "20260725",
        },
        "session_windows": {
            name: {
                "start": start.isoformat(),
                "end_exclusive": end.isoformat(),
            }
            for name, (start, end) in session_bounds.items()
        },
        "targets": [
            {
                "product": product,
                "exact_contract": (
                    f"INE.{product}2609"
                    if product == "sc"
                    else f"SHFE.{product}2609"
                ),
                "previous_exact_contract": None,
                "roll_expected": False,
            }
            for product in ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
        ],
        "execution_windows": [],
    }


def release_payload(current_readiness: VerifiedReadinessPacket) -> dict:
    release_id = "query-v3-test-release-0001"
    manifest_payload = manifest()
    payload = {
        "schema_version": query_module.RELEASE_SCHEMA_VERSION,
        "purpose": query_module.RELEASE_PURPOSE,
        "candidate_id": query_module.CANDIDATE_ID,
        "parent_issue_number": 114,
        "issue_number": 135,
        "release_id": release_id,
        "attempt_id": release_attempt_id(release_id),
        "issued_at": (NOW - timedelta(seconds=30)).isoformat(),
        "not_before": (NOW - timedelta(seconds=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "signer_key_id": "query-v3-signer-key",
        "signer_type": "human",
        "reviewer_role": "human-query-risk-reviewer",
        "human_signature": "approve one exact readonly T1 query",
        "trusted_keyring_sha256": H2,
        "pin_root_path_sha256": H2,
        "custody_identity_sha256": H3,
        "custody_path_sha256": H4,
        "parent_runner_sha256": H,
        "query_child_sha256": H,
        "release_schema_sha256": H,
        "consume_schema_sha256": H,
        "terminal_schema_sha256": H,
        "readiness_verifier_sha256": H,
        "readiness_schema_sha256": H,
        "query_keyring_schema_sha256": H,
        "audit_script_sha256": H,
        "manifest_schema_sha256": H,
        "evidence_schema_sha256": H,
        "legacy_evidence_schema_sha256": H,
        "readonly_proof_schema_sha256": H,
        "readiness": query_module._readiness_binding(current_readiness),
        "namespaces": {
            **current_readiness.payload["source_namespaces"],
            **current_readiness.payload["digest_namespaces"],
        },
        "readiness_source_bundle_index_sha256": H,
        "manifest_raw_sha256": H,
        "manifest_canonical_sha256": hashlib.sha256(
            canonical_json(manifest_payload)
        ).hexdigest(),
        "snapshot_id": manifest_payload["snapshot_id"],
        "audit_window": manifest_payload["audit_window"],
        "endpoint_identity_sha256": H4,
        "questdb_build_sha256": H5,
        "connect_timeout_seconds": 10,
        "statement_timeout_ms": 60000,
        "max_rows_per_contract": 500000,
        "max_runtime_seconds": 600,
        "minimum_launch_margin_seconds": 30,
        "query_plan_scope": "EXACT_SIGNED_MANIFEST_ONE_SHOT_READONLY_ONLY",
        "signature": base64.b64encode(bytes(64)).decode("ascii"),
    }
    payload.update(
        {field: True for field in query_module.TRUE_AUTHORITY_FIELDS}
    )
    payload.update(
        {field: False for field in query_module.FALSE_AUTHORITY_FIELDS}
    )
    return payload


def verified(tmp_path: Path) -> tuple[
    query_module.VerifiedQueryRelease,
    ReadinessPins,
    Path,
]:
    current_readiness = readiness()
    payload = release_payload(current_readiness)
    manifest_payload = manifest()
    bundle_files = {
        "scripts/commodity_c_fast_t1_query_child_v3.py": (
            query_module.QUERY_CHILD_PATH.read_bytes()
        ),
        "scripts/commodity_c_fast_l1_l5_audit.py": (
            query_module.AUDIT_SCRIPT_PATH.read_bytes()
        ),
        "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json": (
            query_module.MANIFEST_SCHEMA_PATH.read_bytes()
        ),
        "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json": (
            query_module.EVIDENCE_SCHEMA_PATH.read_bytes()
        ),
        "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json": (
            query_module.LEGACY_EVIDENCE_SCHEMA_PATH.read_bytes()
        ),
        "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json": (
            query_module.READONLY_PROOF_SCHEMA_PATH.read_bytes()
        ),
    }
    legacy_payload = dict(payload)
    legacy_payload["manifest_sha256"] = payload["manifest_canonical_sha256"]
    legacy = VerifiedRelease(
        payload=legacy_payload,
        release_sha256=H,
        keyring_sha256=H2,
        manifest=manifest_payload,
        bundle_files=bundle_files,
    )
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    pins = ReadinessPins(H, H2, H3, H5, custody)
    dsn = tmp_path / "readonly.dsn"
    dsn.write_text("postgresql://readonly:secret@invalid/qdb", encoding="utf-8")
    dsn.chmod(0o600)
    release_bytes = canonical_json(payload)
    readiness_bytes = canonical_json(current_readiness.payload)
    manifest_bytes = canonical_json(manifest_payload)
    return (
        query_module.VerifiedQueryRelease(
            payload=payload,
            raw_sha256=hashlib.sha256(release_bytes).hexdigest(),
            canonical_sha256=hashlib.sha256(release_bytes).hexdigest(),
            keyring_sha256=H2,
            readiness=current_readiness,
            legacy=legacy,
            release_bytes=release_bytes,
            readiness_bytes=readiness_bytes,
            manifest_bytes=manifest_bytes,
        ),
        pins,
        dsn,
    )


def signed_release_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    reuse_query_material_in_upstream_unused: bool = False,
) -> tuple[
    Path,
    Path,
    Path,
    Path,
    SimpleNamespace,
    ReadinessPins,
    dict,
]:
    current_readiness = readiness()
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    identity = {
        "schema_version": "commodity_c_fast_t1_custody_identity_v1",
        "custody_id": "query-v3-test-custody",
    }
    identity_path = custody / "custody-identity.json"
    identity_path.write_bytes(canonical_json(identity))
    identity_path.chmod(0o600)

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "schema_version": "commodity_c_fast_t1_query_v3_trusted_keys_v1",
        "keys": [
            {
                "key_id": "query-v3-signer-key",
                "purpose": query_module.TRUSTED_KEY_PURPOSE,
                "public_key_base64": base64.b64encode(public_raw).decode(
                    "ascii"
                ),
            }
        ],
    }
    keyring_path = tmp_path / "query-keyring.json"
    keyring_path.write_bytes(canonical_json(keyring))
    keyring_path.chmod(0o600)
    keyring_sha256 = hashlib.sha256(canonical_json(keyring)).hexdigest()
    upstream_entries = [
        {
            "key_id": "upstream-t1-primary-key",
            "purpose": "t1_audit_release_signer",
            "public_key_base64": base64.b64encode(bytes(range(32))).decode(
                "ascii"
            ),
        }
    ]
    if reuse_query_material_in_upstream_unused:
        upstream_entries.append(
            {
                "key_id": "upstream-t1-unused-key",
                "purpose": "t1_audit_release_signer",
                "public_key_base64": base64.b64encode(public_raw).decode(
                    "ascii"
                ),
            }
        )
    upstream_t1_keyring = {
        "schema_version": "commodity_c_fast_t1_trusted_keys_v1",
        "keys": upstream_entries,
    }
    upstream_t1_keyring_path = tmp_path / "upstream-t1-keyring.json"
    upstream_t1_keyring_path.write_bytes(canonical_json(upstream_t1_keyring))
    upstream_t1_keyring_path.chmod(0o600)
    upstream_t1_keyring_sha256 = hashlib.sha256(
        canonical_json(upstream_t1_keyring)
    ).hexdigest()
    pins = ReadinessPins(H, upstream_t1_keyring_sha256, H3, H5, custody)

    readiness_path = custody / "readiness-v2.json"
    readiness_path.write_bytes(canonical_json(current_readiness.payload))
    readiness_path.chmod(0o600)
    manifest_payload = manifest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest_payload))
    manifest_path.chmod(0o600)
    l3_release_path = tmp_path / "l3-release.json"
    l3_release_path.write_bytes(
        canonical_json(
            {
                "questdb_target_identity_sha256": H4,
                "questdb_build_sha256": H5,
            }
        )
    )
    l3_release_path.chmod(0o600)
    readiness_inputs = SimpleNamespace(
        outcome_source=SimpleNamespace(release=l3_release_path),
        t1_keyring=upstream_t1_keyring_path,
    )

    draft = release_payload(current_readiness)
    draft.pop("signature")
    draft.update(
        {
            "trusted_keyring_sha256": keyring_sha256,
            "custody_identity_sha256": hashlib.sha256(
                canonical_json(identity)
            ).hexdigest(),
            "custody_path_sha256": query_module.custody_path_sha256(custody),
            "readiness_source_bundle_index_sha256": (
                query_module.readiness_source_bundle_index(current_readiness)
            ),
            "manifest_raw_sha256": hashlib.sha256(
                manifest_path.read_bytes()
            ).hexdigest(),
            "manifest_canonical_sha256": hashlib.sha256(
                canonical_json(manifest_payload)
            ).hexdigest(),
        }
    )
    runtime_paths = {
        "parent_runner_sha256": query_module.PARENT_RUNNER_PATH,
        "query_child_sha256": query_module.QUERY_CHILD_PATH,
        "release_schema_sha256": query_module.RELEASE_SCHEMA_PATH,
        "consume_schema_sha256": query_module.CONSUME_SCHEMA_PATH,
        "terminal_schema_sha256": query_module.TERMINAL_SCHEMA_PATH,
        "readiness_verifier_sha256": query_module.READINESS_VERIFIER_PATH,
        "readiness_schema_sha256": query_module.READINESS_SCHEMA_PATH,
        "query_keyring_schema_sha256": query_module.QUERY_KEYRING_SCHEMA_PATH,
        "audit_script_sha256": query_module.AUDIT_SCRIPT_PATH,
        "manifest_schema_sha256": query_module.MANIFEST_SCHEMA_PATH,
        "evidence_schema_sha256": query_module.EVIDENCE_SCHEMA_PATH,
        "legacy_evidence_schema_sha256": (
            query_module.LEGACY_EVIDENCE_SCHEMA_PATH
        ),
        "readonly_proof_schema_sha256": (
            query_module.READONLY_PROOF_SCHEMA_PATH
        ),
    }
    draft.update(
        {
            field: hashlib.sha256(path.read_bytes()).hexdigest()
            for field, path in runtime_paths.items()
        }
    )
    signed = sign_module.sign_release(
        draft,
        current_readiness,
        private_key,
        now=NOW,
    )
    release_path = custody / "query-v3-signed.json"
    release_path.write_bytes(canonical_json(signed))
    release_path.chmod(0o600)
    monkeypatch.setattr(
        query_module,
        "verify_existing_readiness_packet",
        lambda *_args, **_kwargs: current_readiness,
    )
    monkeypatch.setattr(
        query_module,
        "read_root_owned_deployment_pin",
        lambda *_args, **_kwargs: keyring_sha256,
    )
    return (
        release_path,
        keyring_path,
        manifest_path,
        readiness_path,
        readiness_inputs,
        pins,
        signed,
    )


def audit_gate_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, list[str], str, str]:
    current_readiness = readiness()
    readiness_path = tmp_path / "gate-readiness.json"
    readiness_path.write_bytes(canonical_json(current_readiness.payload))
    readiness_path.chmod(0o400)
    manifest_payload = manifest()
    manifest_path = tmp_path / "gate-manifest.json"
    manifest_path.write_bytes(canonical_json(manifest_payload))
    manifest_path.chmod(0o400)
    manifest_canonical_sha256 = hashlib.sha256(
        canonical_json(manifest_payload)
    ).hexdigest()
    release = release_payload(current_readiness)
    release["audit_script_sha256"] = hashlib.sha256(
        Path(audit_module.__file__).read_bytes()
    ).hexdigest()
    release["manifest_raw_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    release["manifest_canonical_sha256"] = manifest_canonical_sha256
    release_path = tmp_path / "gate-release.json"
    release_path.write_bytes(canonical_json(release))
    release_path.chmod(0o400)
    gate_path = tmp_path / "gate.json"
    invocation_path = tmp_path / "gate-invocation.json"
    values = {
        "--manifest": str(manifest_path),
        "--start": release["audit_window"]["start"],
        "--end": release["audit_window"]["end_exclusive"],
        "--dsn-file": str(tmp_path / "must-not-read.dsn"),
        "--expected-endpoint-identity-sha256": H4,
        "--expected-manifest-sha256": manifest_canonical_sha256,
        "--json-output": str(tmp_path / "audit.json"),
        "--csv-output": str(tmp_path / "audit.csv"),
        "--markdown-output": str(tmp_path / "audit.md"),
        "--readonly-proof-output": str(tmp_path / "proof.json"),
        "--pre-connect-query-gate": str(gate_path),
    }
    invocation_core = [
        str(Path(sys.executable).resolve()),
        "-I",
        str(Path(audit_module.__file__).resolve()),
    ]
    for flag in child_module.AUDIT_FLAGS[:-2]:
        invocation_core.extend([flag, values[flag]])
    invocation_core_raw = canonical_json(invocation_core)
    gate = {
        "schema_version": "commodity_c_fast_t1_pre_connect_gate_v3",
        "purpose": "c_fast_t1_last_active_pin_gate_before_dsn",
        "audit_script_raw_sha256": release["audit_script_sha256"],
        "audit_invocation_path": str(invocation_path),
        "audit_invocation_core_raw_sha256": hashlib.sha256(
            invocation_core_raw
        ).hexdigest(),
        "audit_invocation_core_canonical_sha256": hashlib.sha256(
            canonical_json(invocation_core)
        ).hexdigest(),
        "release_path": str(release_path),
        "release_raw_sha256": hashlib.sha256(
            release_path.read_bytes()
        ).hexdigest(),
        "release_canonical_sha256": hashlib.sha256(
            canonical_json(release)
        ).hexdigest(),
        "readiness_path": str(readiness_path),
        "readiness_raw_sha256": hashlib.sha256(
            readiness_path.read_bytes()
        ).hexdigest(),
        "readiness_canonical_sha256": hashlib.sha256(
            canonical_json(current_readiness.payload)
        ).hexdigest(),
        "manifest_source_path": str(manifest_path),
        "manifest_raw_sha256": release["manifest_raw_sha256"],
        "manifest_canonical_sha256": manifest_canonical_sha256,
        "provenance_keyring_sha256": H,
        "t1_authority_keyring_sha256": H2,
        "query_v3_authority_keyring_sha256": H2,
        "l3_authority_keyring_sha256": H3,
        "outcome_keyring_sha256": H5,
        "packet_custody_path": str(tmp_path),
    }
    gate_path.write_bytes(canonical_json(gate))
    gate_path.chmod(0o400)
    gate_raw_sha256 = hashlib.sha256(gate_path.read_bytes()).hexdigest()
    gate_canonical_sha256 = hashlib.sha256(canonical_json(gate)).hexdigest()
    invocation = [
        *invocation_core,
        "--expected-pre-connect-gate-raw-sha256",
        gate_raw_sha256,
        "--expected-pre-connect-gate-canonical-sha256",
        gate_canonical_sha256,
    ]
    invocation_path.write_bytes(canonical_json(invocation))
    invocation_path.chmod(0o400)
    return (
        gate_path,
        invocation_path,
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    )


class Clock:
    def __init__(self, values: list[datetime]) -> None:
        self.values = iter(values)

    def __call__(self) -> datetime:
        return next(self.values)


def times(*offsets: int) -> Clock:
    return Clock([NOW + timedelta(seconds=value) for value in offsets])


def execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    child_executor,
    output_validator=lambda *_args: (True, {
        "audit_json": H,
        "audit_csv": H2,
        "audit_markdown": H3,
        "readonly_proof": H4,
    }),
    clock: Clock | None = None,
    revalidator=None,
):
    current, pins, dsn = verified(tmp_path)
    monkeypatch.setattr(
        query_module,
        "verify_active_readiness_pins",
        lambda _pins: None,
    )
    return query_module.execute_verified_query(
        current,
        pins,
        dsn,
        revalidator or (lambda _at: current),
        clock=clock or times(0, 1, 2, 3),
        child_executor=child_executor,
        output_validator=output_validator,
        require_root_owned_parent=False,
    )


def test_release_schema_allows_only_narrow_readonly_authority() -> None:
    current = readiness()
    payload = release_payload(current)
    query_module.validate_release_semantics(payload, current, now=NOW)
    payload["dispatch_authorized"] = True
    with pytest.raises((OneShotError, query_module.QueryV3Error)):
        query_module.validate_release_semantics(payload, current, now=NOW)


@pytest.mark.parametrize(
    "field",
    ("human_signature", "reviewer_role"),
)
def test_human_review_fields_reject_leading_space_pending(
    field: str,
) -> None:
    current = readiness()
    payload = release_payload(current)
    payload[field] = "  PENDING_human_review"
    with pytest.raises(query_module.QueryV3Error, match="human review"):
        query_module.validate_release_semantics(payload, current, now=NOW)


def test_offline_signed_release_passes_complete_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        release_path,
        keyring_path,
        manifest_path,
        readiness_path,
        readiness_inputs,
        pins,
        signed,
    ) = signed_release_inputs(tmp_path, monkeypatch)
    result = query_module.verify_query_release(
        release_path,
        keyring_path,
        manifest_path,
        readiness_path,
        readiness_inputs,
        pins,
        now=NOW,
        require_root_owned_parent=False,
    )
    assert result.payload == signed
    assert result.raw_sha256 == hashlib.sha256(
        release_path.read_bytes()
    ).hexdigest()


def test_complete_verifier_rejects_wrong_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _release_path,
        keyring_path,
        manifest_path,
        readiness_path,
        readiness_inputs,
        pins,
        signed,
    ) = signed_release_inputs(tmp_path, monkeypatch)
    tampered = dict(signed)
    tampered["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    tampered_path = pins.packet_custody_path / "query-v3-tampered.json"
    tampered_path.write_bytes(canonical_json(tampered))
    tampered_path.chmod(0o600)
    with pytest.raises(query_module.QueryV3Error, match="signature is invalid"):
        query_module.verify_query_release(
            tampered_path,
            keyring_path,
            manifest_path,
            readiness_path,
            readiness_inputs,
            pins,
            now=NOW,
            require_root_owned_parent=False,
        )


def test_complete_verifier_rejects_wrong_query_v3_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        release_path,
        keyring_path,
        manifest_path,
        readiness_path,
        readiness_inputs,
        pins,
        _signed,
    ) = signed_release_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        query_module,
        "read_root_owned_deployment_pin",
        lambda *_args, **_kwargs: H,
    )
    with pytest.raises(query_module.QueryV3Error, match="active query-v3 pin"):
        query_module.verify_query_release(
            release_path,
            keyring_path,
            manifest_path,
            readiness_path,
            readiness_inputs,
            pins,
            now=NOW,
            require_root_owned_parent=False,
        )


def test_complete_verifier_rejects_unused_upstream_t1_key_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        release_path,
        keyring_path,
        manifest_path,
        readiness_path,
        readiness_inputs,
        pins,
        _signed,
    ) = signed_release_inputs(
        tmp_path,
        monkeypatch,
        reuse_query_material_in_upstream_unused=True,
    )
    with pytest.raises(
        query_module.QueryV3Error,
        match="reuses upstream T1 authority",
    ):
        query_module.verify_query_release(
            release_path,
            keyring_path,
            manifest_path,
            readiness_path,
            readiness_inputs,
            pins,
            now=NOW,
            require_root_owned_parent=False,
        )


def test_active_pin_rotation_before_consume_does_not_burn_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current, pins, dsn = verified(tmp_path)
    monkeypatch.setattr(
        query_module,
        "verify_active_readiness_pins",
        lambda _pins: (_ for _ in ()).throw(
            ReadinessV2Error("rotated")
        ),
    )
    with pytest.raises(ReadinessV2Error):
        query_module.execute_verified_query(
            current,
            pins,
            dsn,
            lambda _at: current,
            clock=times(0, 1),
            child_executor=lambda *_args, **_kwargs: pytest.fail(
                "child must not launch"
            ),
            require_root_owned_parent=False,
        )
    assert not list(pins.packet_custody_path.glob("*.query-consumed-v3.json"))


def test_final_revalidation_failure_burns_attempt_without_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    current, _, _ = verified(seed)
    calls = 0

    def revalidator(_at):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise query_module.QueryV3Error("changed")
        return current

    code, terminal = execute(
        tmp_path,
        monkeypatch,
        child_executor=lambda *_args, **_kwargs: pytest.fail(
            "child must not launch"
        ),
        revalidator=revalidator,
    )
    assert code == 2
    assert terminal["terminal_state"] == "BLOCKED_FINAL_REVALIDATION_PRE_CHILD"
    assert terminal["production_query_attempted"] is False


@pytest.mark.parametrize(
    ("executor", "expected"),
    [
        (
            lambda *_args, **_kwargs: subprocess.CompletedProcess([], 78),
            "FAILED_CHILD_LAUNCH_PRE_QUERY",
        ),
        (
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(["child"], 1)
            ),
            "TIMED_OUT_OUTCOME_UNKNOWN",
        ),
        (
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                KeyboardInterrupt()
            ),
            "INTERRUPTED_OUTCOME_UNKNOWN",
        ),
    ],
)
def test_prequery_and_unknown_terminal_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    executor,
    expected: str,
) -> None:
    code, terminal = execute(
        tmp_path,
        monkeypatch,
        child_executor=executor,
    )
    assert code == 2
    assert terminal["terminal_state"] == expected
    if "OUTCOME_UNKNOWN" in expected:
        assert terminal["query_execution_state"] == "OUTCOME_UNKNOWN"
        assert terminal["production_query_completed"] is None
        assert terminal["database_mutations_observed"] is None
        assert terminal["p0_pass"] is None
    else:
        assert terminal["query_execution_state"] == "NOT_STARTED"
        assert terminal["production_query_attempted"] is False


def test_clock_rollback_cannot_emit_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, terminal = execute(
        tmp_path,
        monkeypatch,
        child_executor=lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
        ),
        clock=times(0, 1, 2, 1),
    )
    assert code == 2
    assert terminal["terminal_state"] == "FAILED_OUTPUT_VALIDATION"
    assert terminal["error_code"] == "NON_MONOTONIC_CLOCK_OUTCOME_UNKNOWN"
    assert terminal["p0_pass"] is None
    assert terminal["proof_verified"] is False


def test_success_binds_gate_and_both_invocations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, terminal = execute(
        tmp_path,
        monkeypatch,
        child_executor=lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
        ),
    )
    assert code == 0
    assert terminal["terminal_state"] == "COMPLETED_EVIDENCE_P0_PASS"
    for field in (
        "pre_connect_gate_raw_sha256",
        "pre_connect_gate_canonical_sha256",
        "audit_child_invocation_raw_sha256",
        "audit_child_invocation_canonical_sha256",
        "query_child_invocation_raw_sha256",
        "query_child_invocation_canonical_sha256",
    ):
        assert terminal[field] is not None
    invalid = dict(terminal)
    invalid["pre_connect_gate_raw_sha256"] = None
    with pytest.raises(OneShotError):
        query_module.validate_json_schema(
            invalid,
            query_module.TERMINAL_SCHEMA_PATH,
            "invalid completed terminal",
        )


def test_query_gate_tamper_is_blocked_before_active_pin_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = tmp_path / "release.json"
    readiness_path = tmp_path / "readiness.json"
    manifest_path = tmp_path / "manifest.json"
    for path in (release, readiness_path, manifest_path):
        path.write_text('{"value":1}', encoding="utf-8")
        path.chmod(0o400)
    invocation_path = tmp_path / "invocation.json"
    gate_path = tmp_path / "gate.json"
    invocation = [
        str(Path(sys.executable).resolve()),
        "-I",
        str(Path(audit_module.__file__).resolve()),
        "--pre-connect-query-gate",
        str(gate_path),
    ]
    invocation_core_raw = canonical_json(invocation)
    exact_raw = release.read_bytes()
    gate = {
        "schema_version": "commodity_c_fast_t1_pre_connect_gate_v3",
        "purpose": "c_fast_t1_last_active_pin_gate_before_dsn",
        "audit_script_raw_sha256": hashlib.sha256(
            Path(audit_module.__file__).read_bytes()
        ).hexdigest(),
        "audit_invocation_path": str(invocation_path),
        "audit_invocation_core_raw_sha256": hashlib.sha256(
            invocation_core_raw
        ).hexdigest(),
        "audit_invocation_core_canonical_sha256": hashlib.sha256(
            canonical_json(invocation)
        ).hexdigest(),
        "release_path": str(release),
        "release_raw_sha256": hashlib.sha256(exact_raw).hexdigest(),
        "release_canonical_sha256": hashlib.sha256(
            canonical_json({"value": 1})
        ).hexdigest(),
        "readiness_path": str(readiness_path),
        "readiness_raw_sha256": hashlib.sha256(
            readiness_path.read_bytes()
        ).hexdigest(),
        "readiness_canonical_sha256": hashlib.sha256(
            canonical_json({"value": 1})
        ).hexdigest(),
        "manifest_source_path": str(manifest_path),
        "manifest_raw_sha256": hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest(),
        "manifest_canonical_sha256": hashlib.sha256(
            canonical_json({"value": 1})
        ).hexdigest(),
        "provenance_keyring_sha256": H,
        "t1_authority_keyring_sha256": H2,
        "query_v3_authority_keyring_sha256": H2,
        "l3_authority_keyring_sha256": H3,
        "outcome_keyring_sha256": H4,
        "packet_custody_path": str(tmp_path),
    }
    gate_path.write_bytes(canonical_json(gate))
    gate_path.chmod(0o400)
    gate_raw_sha256 = hashlib.sha256(gate_path.read_bytes()).hexdigest()
    gate_canonical_sha256 = hashlib.sha256(canonical_json(gate)).hexdigest()
    invocation.extend(
        [
            "--expected-pre-connect-gate-raw-sha256",
            gate_raw_sha256,
            "--expected-pre-connect-gate-canonical-sha256",
            gate_canonical_sha256,
        ]
    )
    invocation_path.write_bytes(canonical_json(invocation))
    invocation_path.chmod(0o400)
    release.chmod(0o600)
    release.write_text('{"value":2}', encoding="utf-8")
    release.chmod(0o400)
    monkeypatch.setattr(
        audit_module,
        "QUERY_V3_PIN_ROOT",
        SimpleNamespace(
            lstat=lambda: pytest.fail("active pins must not be read")
        ),
    )
    with pytest.raises(audit_module.AuditError, match="exact binding changed"):
        audit_module.verify_pre_connect_query_gate(
            gate_path,
            expected_gate_raw_sha256=gate_raw_sha256,
            expected_gate_canonical_sha256=gate_canonical_sha256,
            actual_invocation=invocation,
        )


def test_invalid_pending_template_remains_unsignable() -> None:
    template = json.loads(
        (
            ROOT / "docs/operations/c-fast-t1-query-v3.template.json"
        ).read_text(encoding="utf-8")
    )
    schema = json.loads(query_module.RELEASE_SCHEMA_PATH.read_text())
    from jsonschema import Draft202012Validator, FormatChecker

    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(template)
    )
    assert errors


def test_child_rejects_late_gate_replacement(tmp_path: Path) -> None:
    gate = tmp_path / "gate.json"
    invocation = [
        str(Path(sys.executable).resolve()),
        "-I",
        str(Path(audit_module.__file__).resolve()),
        *sum(
            (
                [
                    flag,
                    str(gate) if flag == "--pre-connect-query-gate" else "x",
                ]
                for flag in child_module.AUDIT_FLAGS[:-2]
            ),
            [],
        ),
    ]
    invocation_core_raw = canonical_json(invocation)
    gate.write_bytes(
        canonical_json(
            {
                "audit_invocation_core_raw_sha256": hashlib.sha256(
                    invocation_core_raw
                ).hexdigest(),
                "audit_invocation_core_canonical_sha256": hashlib.sha256(
                    canonical_json(invocation)
                ).hexdigest(),
            }
        )
    )
    expected_raw = hashlib.sha256(gate.read_bytes()).hexdigest()
    expected_canonical = hashlib.sha256(
        canonical_json(json.loads(gate.read_text()))
    ).hexdigest()
    invocation.extend(
        [
            "--expected-pre-connect-gate-raw-sha256",
            expected_raw,
            "--expected-pre-connect-gate-canonical-sha256",
            expected_canonical,
        ]
    )
    gate.write_bytes(canonical_json({"version": 2}))
    with pytest.raises(
        child_module.QueryChildError,
        match="binding changed",
    ):
        child_module.verify_gate_binding(
            invocation,
            expected_raw,
            expected_canonical,
        )


def test_gate_replacement_after_bootstrap_is_blocked_before_active_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        gate_path,
        _invocation_path,
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    ) = audit_gate_fixture(tmp_path)
    child_module.verify_gate_binding(
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    )
    gate_path.chmod(0o600)
    gate_path.write_bytes(canonical_json({"replaced": True}))
    gate_path.chmod(0o400)
    monkeypatch.setattr(
        audit_module,
        "QUERY_V3_PIN_ROOT",
        SimpleNamespace(
            lstat=lambda: pytest.fail("active pins must not be read")
        ),
    )
    with pytest.raises(audit_module.AuditError, match="raw binding changed"):
        audit_module.verify_pre_connect_query_gate(
            gate_path,
            expected_gate_raw_sha256=gate_raw_sha256,
            expected_gate_canonical_sha256=gate_canonical_sha256,
            actual_invocation=invocation,
            now=NOW,
        )


def test_non_gate_invocation_tamper_is_bootstrap_blocked(
    tmp_path: Path,
) -> None:
    (
        _gate_path,
        _invocation_path,
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    ) = audit_gate_fixture(tmp_path)
    tampered = list(invocation)
    tampered[tampered.index("--dsn-file") + 1] = str(
        tmp_path / "attacker.dsn"
    )
    with pytest.raises(child_module.QueryChildError, match="core binding"):
        child_module.verify_gate_binding(
            tampered,
            gate_raw_sha256,
            gate_canonical_sha256,
        )


def test_invocation_rewrite_after_bootstrap_is_audit_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        gate_path,
        invocation_path,
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    ) = audit_gate_fixture(tmp_path)
    child_module.verify_gate_binding(
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    )
    rewritten = list(invocation)
    rewritten[rewritten.index("--dsn-file") + 1] = str(
        tmp_path / "attacker.dsn"
    )
    invocation_path.chmod(0o600)
    invocation_path.write_bytes(canonical_json(rewritten))
    invocation_path.chmod(0o400)
    monkeypatch.setattr(
        audit_module,
        "QUERY_V3_PIN_ROOT",
        SimpleNamespace(
            lstat=lambda: pytest.fail("active pins must not be read")
        ),
    )
    with pytest.raises(
        audit_module.AuditError,
        match="frozen audit invocation changed",
    ):
        audit_module.verify_pre_connect_query_gate(
            gate_path,
            expected_gate_raw_sha256=gate_raw_sha256,
            expected_gate_canonical_sha256=gate_canonical_sha256,
            actual_invocation=invocation,
            now=NOW,
        )


def test_expired_release_is_blocked_before_active_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        gate_path,
        _invocation_path,
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    ) = audit_gate_fixture(tmp_path)
    child_module.verify_gate_binding(
        invocation,
        gate_raw_sha256,
        gate_canonical_sha256,
    )
    monkeypatch.setattr(
        audit_module,
        "QUERY_V3_PIN_ROOT",
        SimpleNamespace(
            lstat=lambda: pytest.fail("active pins must not be read")
        ),
    )
    with pytest.raises(audit_module.AuditError, match="not active"):
        audit_module.verify_pre_connect_query_gate(
            gate_path,
            expected_gate_raw_sha256=gate_raw_sha256,
            expected_gate_canonical_sha256=gate_canonical_sha256,
            actual_invocation=invocation,
            now=NOW + timedelta(minutes=6),
        )


def test_audit_calls_gate_immediately_before_dsn_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    args = SimpleNamespace(
        manifest=tmp_path / "manifest.json",
        dsn_file=tmp_path / "dsn",
        expected_manifest_sha256=H,
        expected_endpoint_identity_sha256=H2,
        start=None,
        end=None,
        json_output=tmp_path / "audit.json",
        csv_output=tmp_path / "audit.csv",
        markdown_output=tmp_path / "audit.md",
        readonly_proof_output=tmp_path / "proof.json",
        pre_connect_query_gate=tmp_path / "gate.json",
        expected_pre_connect_gate_raw_sha256=H3,
        expected_pre_connect_gate_canonical_sha256=H4,
    )
    monkeypatch.setattr(audit_module, "parse_args", lambda: args)
    monkeypatch.setattr(audit_module, "validate_artifact_paths", lambda _args: None)
    monkeypatch.setattr(
        audit_module,
        "load_manifest",
        lambda _path: ({}, [], {}, []),
    )
    monkeypatch.setattr(
        audit_module,
        "canonical_manifest_sha256",
        lambda _manifest: H,
    )
    def gate(
        _path,
        *,
        expected_gate_raw_sha256,
        expected_gate_canonical_sha256,
        actual_invocation,
    ):
        assert expected_gate_raw_sha256 == H3
        assert expected_gate_canonical_sha256 == H4
        assert actual_invocation[1] == "-I"
        order.append("gate")

    monkeypatch.setattr(
        audit_module,
        "verify_pre_connect_query_gate",
        gate,
    )

    def no_network(_path):
        order.append("dsn")
        raise audit_module.AuditError("blocked test connection")

    monkeypatch.setattr(
        audit_module,
        "connect_server_enforced_readonly",
        no_network,
    )
    assert audit_module.main() == 2
    assert order == ["gate", "dsn"]


def test_real_isolated_audit_invocation_preserves_dash_i_binding(
    tmp_path: Path,
) -> None:
    common_git = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=ROOT,
            text=True,
        ).strip()
    )
    if not common_git.is_absolute():
        common_git = (ROOT / common_git).resolve()
    interpreter = common_git.parent / ".venv/bin/python"
    if not interpreter.exists():
        interpreter = Path(sys.executable)
    dependency_probe = subprocess.run(
        [
            str(interpreter),
            "-I",
            "-c",
            "import jsonschema, referencing",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if dependency_probe.returncode != 0:
        pytest.skip("no isolated Python with audit dependencies")
    wall_now = datetime.now(timezone.utc)
    readiness_payload = json.loads(json.dumps(readiness().payload))
    readiness_payload["generated_at"] = (
        wall_now - timedelta(minutes=2)
    ).isoformat()
    readiness_payload["expires_at"] = (
        wall_now + timedelta(minutes=10)
    ).isoformat()
    readiness_raw = canonical_json(readiness_payload)
    current_readiness = VerifiedReadinessPacket(
        payload=readiness_payload,
        raw_sha256=hashlib.sha256(readiness_raw).hexdigest(),
        canonical_sha256=hashlib.sha256(readiness_raw).hexdigest(),
    )
    manifest_payload = manifest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest_payload))
    manifest_path.chmod(0o400)
    readiness_path = tmp_path / "readiness.json"
    readiness_path.write_bytes(canonical_json(current_readiness.payload))
    readiness_path.chmod(0o400)
    release = release_payload(current_readiness)
    release["issued_at"] = (wall_now - timedelta(minutes=1)).isoformat()
    release["not_before"] = (wall_now - timedelta(seconds=30)).isoformat()
    release["expires_at"] = (wall_now + timedelta(minutes=5)).isoformat()
    release["audit_script_sha256"] = hashlib.sha256(
        Path(audit_module.__file__).read_bytes()
    ).hexdigest()
    release["manifest_raw_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    release["manifest_canonical_sha256"] = (
        audit_module.canonical_manifest_sha256(manifest_payload)
    )
    release["readiness"]["packet_raw_sha256"] = hashlib.sha256(
        readiness_path.read_bytes()
    ).hexdigest()
    release["readiness"]["packet_canonical_sha256"] = hashlib.sha256(
        canonical_json(current_readiness.payload)
    ).hexdigest()
    release_path = tmp_path / "release.json"
    release_path.write_bytes(canonical_json(release))
    release_path.chmod(0o400)
    dsn = tmp_path / "dsn"
    dsn.write_text("must-not-be-read", encoding="utf-8")
    dsn.chmod(0o600)
    gate_path = tmp_path / "gate.json"
    invocation_path = tmp_path / "invocation.json"
    invocation = [
        str(interpreter.absolute()),
        "-I",
        str(Path(audit_module.__file__).resolve()),
        "--manifest",
        str(manifest_path),
        "--start",
        release["audit_window"]["start"],
        "--end",
        release["audit_window"]["end_exclusive"],
        "--dsn-file",
        str(dsn),
        "--expected-endpoint-identity-sha256",
        H4,
        "--expected-manifest-sha256",
        release["manifest_canonical_sha256"],
        "--json-output",
        str(tmp_path / "audit.json"),
        "--csv-output",
        str(tmp_path / "audit.csv"),
        "--markdown-output",
        str(tmp_path / "audit.md"),
        "--readonly-proof-output",
        str(tmp_path / "proof.json"),
        "--pre-connect-query-gate",
        str(gate_path),
    ]
    gate = {
        "schema_version": "commodity_c_fast_t1_pre_connect_gate_v3",
        "purpose": "c_fast_t1_last_active_pin_gate_before_dsn",
        "audit_script_raw_sha256": release["audit_script_sha256"],
        "audit_invocation_path": str(invocation_path),
        "audit_invocation_core_raw_sha256": hashlib.sha256(
            canonical_json(invocation)
        ).hexdigest(),
        "audit_invocation_core_canonical_sha256": hashlib.sha256(
            canonical_json(invocation)
        ).hexdigest(),
        "release_path": str(release_path),
        "release_raw_sha256": hashlib.sha256(
            release_path.read_bytes()
        ).hexdigest(),
        "release_canonical_sha256": hashlib.sha256(
            canonical_json(release)
        ).hexdigest(),
        "readiness_path": str(readiness_path),
        "readiness_raw_sha256": hashlib.sha256(
            readiness_path.read_bytes()
        ).hexdigest(),
        "readiness_canonical_sha256": hashlib.sha256(
            canonical_json(current_readiness.payload)
        ).hexdigest(),
        "manifest_source_path": str(manifest_path),
        "manifest_raw_sha256": release["manifest_raw_sha256"],
        "manifest_canonical_sha256": release["manifest_canonical_sha256"],
        "provenance_keyring_sha256": H,
        "t1_authority_keyring_sha256": H2,
        "query_v3_authority_keyring_sha256": H2,
        "l3_authority_keyring_sha256": H3,
        "outcome_keyring_sha256": H5,
        "packet_custody_path": str(tmp_path),
    }
    gate_path.write_bytes(canonical_json(gate))
    gate_path.chmod(0o400)
    gate_raw_sha256 = hashlib.sha256(gate_path.read_bytes()).hexdigest()
    gate_canonical_sha256 = hashlib.sha256(canonical_json(gate)).hexdigest()
    invocation.extend(
        [
            "--expected-pre-connect-gate-raw-sha256",
            gate_raw_sha256,
            "--expected-pre-connect-gate-canonical-sha256",
            gate_canonical_sha256,
        ]
    )
    invocation_path.write_bytes(canonical_json(invocation))
    invocation_path.chmod(0o400)
    result = subprocess.run(
        invocation,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
    )
    assert result.returncode == 2
    assert "frozen audit invocation changed" not in result.stderr
    assert "active pin root" in result.stderr


def test_query_key_requires_dedicated_signer_purpose() -> None:
    keyring = {
        "schema_version": "commodity_c_fast_t1_query_v3_trusted_keys_v1",
        "keys": [
            {
                "key_id": "query-v3-key",
                "purpose": "t1_audit_release_signer",
                "public_key_base64": base64.b64encode(bytes(32)).decode(
                    "ascii"
                ),
            }
        ],
    }
    with pytest.raises(query_module.QueryV3Error, match="purpose"):
        query_module._load_query_public_key(keyring, "query-v3-key")


def test_query_keyring_rejects_legacy_t1_schema() -> None:
    keyring = {
        "schema_version": "commodity_c_fast_t1_trusted_keys_v1",
        "keys": [
            {
                "key_id": "query-v3-key",
                "purpose": "t1_audit_release_signer",
                "public_key_base64": base64.b64encode(bytes(32)).decode(
                    "ascii"
                ),
            }
        ],
    }
    with pytest.raises(query_module.QueryV3Error, match="schema version"):
        query_module._load_query_public_key(keyring, "query-v3-key")


def test_query_keyring_rejects_reused_public_material() -> None:
    material = base64.b64encode(bytes(32)).decode("ascii")
    keyring = {
        "schema_version": "commodity_c_fast_t1_query_v3_trusted_keys_v1",
        "keys": [
            {
                "key_id": "query-v3-key-one",
                "purpose": query_module.TRUSTED_KEY_PURPOSE,
                "public_key_base64": material,
            },
            {
                "key_id": "query-v3-key-two",
                "purpose": "another-purpose",
                "public_key_base64": material,
            },
        ],
    }
    with pytest.raises(query_module.QueryV3Error, match="reuses public-key"):
        query_module._load_query_public_key(keyring, "query-v3-key-one")


def test_query_bootstrap_invocation_is_isolated(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    custody.mkdir()
    pins = ReadinessPins(H, H2, H3, H4, custody)
    staged_child = tmp_path / "scripts/query-child.py"
    invocation = query_module.build_query_child_invocation(
        pins,
        H5,
        staged_child,
        tmp_path / "audit-invocation.json",
        H,
        H2,
    )
    assert invocation[:3] == [
        str(Path(sys.executable).resolve(strict=True)),
        "-I",
        str(staged_child.resolve(strict=False)),
    ]


def test_run_query_child_cleans_up_on_generic_communicate_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        returncode = None

        def communicate(self, *, timeout):
            assert timeout == 9
            raise RuntimeError("communicate failed")

    process = Process()
    monkeypatch.setattr(
        query_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    cleaned: list[object] = []
    monkeypatch.setattr(
        query_module,
        "_terminate_query_process_group",
        lambda current: cleaned.append(current),
    )
    with pytest.raises(RuntimeError, match="communicate failed"):
        query_module.run_query_child(["child"], cwd=tmp_path, timeout=9)
    assert cleaned == [process]


def test_run_query_child_sigterm_cleans_up_and_restores_handlers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_handlers = {
        query_module.signal.SIGTERM: object(),
        query_module.signal.SIGHUP: object(),
    }
    handlers = dict(old_handlers)

    def set_handler(current, handler):
        previous = handlers[current]
        handlers[current] = handler
        return previous

    monkeypatch.setattr(
        query_module.signal,
        "getsignal",
        lambda current: handlers[current],
    )
    monkeypatch.setattr(query_module.signal, "signal", set_handler)

    class Process:
        returncode = None

        def communicate(self, *, timeout):
            assert timeout == 7
            handlers[query_module.signal.SIGTERM](
                query_module.signal.SIGTERM,
                None,
            )
            pytest.fail("signal handler must interrupt communicate")

    process = Process()
    monkeypatch.setattr(
        query_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    cleaned: list[object] = []
    monkeypatch.setattr(
        query_module,
        "_terminate_query_process_group",
        lambda current: cleaned.append(current),
    )
    with pytest.raises(KeyboardInterrupt, match="received signal"):
        query_module.run_query_child(["child"], cwd=tmp_path, timeout=7)
    assert cleaned == [process]
    assert handlers == old_handlers


def test_terminate_process_group_escalates_to_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 123
        waits = 0

        def poll(self):
            return None

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired(["child"], timeout)
            return 0

    signals: list[int] = []
    monkeypatch.setattr(
        query_module.os,
        "killpg",
        lambda _pid, sig: signals.append(sig),
    )
    query_module._terminate_query_process_group(Process())
    assert signals == [query_module.signal.SIGTERM, query_module.signal.SIGKILL]


def test_terminate_process_group_reaps_after_interrupted_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 456
        alive = True
        waits = 0

        def poll(self):
            return None if self.alive else 0

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                raise KeyboardInterrupt()
            self.alive = False
            return 0

    signals: list[int] = []
    monkeypatch.setattr(
        query_module.os,
        "killpg",
        lambda _pid, current: signals.append(current),
    )
    process = Process()
    query_module._terminate_query_process_group(process)
    assert signals == [
        query_module.signal.SIGTERM,
        query_module.signal.SIGKILL,
    ]
    assert process.waits == 2
    assert process.alive is False
