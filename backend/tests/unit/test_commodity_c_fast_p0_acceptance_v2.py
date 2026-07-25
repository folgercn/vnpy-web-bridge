from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_p0_acceptance_v2 as acceptance_module  # noqa: E402
import commodity_c_fast_p0_sign_acceptance_v2 as signer_module  # noqa: E402
import commodity_c_fast_t1_query_v3 as query_module  # noqa: E402
import commodity_c_fast_t1_readiness_v2 as readiness_module  # noqa: E402
from commodity_c_fast_t1_one_shot import (  # noqa: E402
    ArtifactPaths,
    OneShotError,
    canonical_json,
    release_attempt_id,
)


def load_helper(name: str, filename: str):
    path = ROOT / "backend/tests/unit" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


provenance_helpers = load_helper(
    "acceptance_v2_provenance_helpers",
    "test_c_fast_t1_build_registry_provenance.py",
)
outcome_helpers = load_helper(
    "acceptance_v2_outcome_helpers",
    "test_commodity_c_fast_readonly_deployment_outcome_script.py",
)
query_helpers = load_helper(
    "acceptance_v2_query_helpers",
    "test_commodity_c_fast_t1_query_v3.py",
)
p0_v1_helpers = load_helper(
    "acceptance_v2_p0_v1_helpers",
    "test_commodity_c_fast_p0_acceptance_script.py",
)


QUERY_NOW = datetime(2026, 9, 1, 0, 10, tzinfo=timezone.utc)


def write_bytes(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(
    path: Path,
    payload,
    *,
    indent: int | None = None,
    mode: int = 0o600,
) -> Path:
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=indent is None,
            separators=(",", ":") if indent is None else None,
            indent=indent,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    return write_bytes(path, raw, mode=mode)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_raw(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def keyring(
    private_key: Ed25519PrivateKey,
    *,
    version: str,
    purpose: str,
    key_id: str,
    unused: Ed25519PrivateKey | None = None,
) -> dict:
    entries = [
        {
            "key_id": key_id,
            "purpose": purpose,
            "public_key_base64": base64.b64encode(
                public_raw(private_key)
            ).decode("ascii"),
        }
    ]
    if unused is not None:
        entries.append(
            {
                "key_id": f"{key_id}-unused",
                "purpose": purpose,
                "public_key_base64": base64.b64encode(
                    public_raw(unused)
                ).decode("ascii"),
            }
        )
    return {"schema_version": version, "keys": entries}


class Fixture:
    def __init__(
        self,
        *,
        paths: acceptance_module.P0BundleV2Paths,
        pins: dict[str, str],
        acceptance_keyring_path: Path,
        acceptance_pin: str,
        acceptance_private: Ed25519PrivateKey,
    ) -> None:
        self.paths = paths
        self.pins = pins
        self.acceptance_keyring_path = acceptance_keyring_path
        self.acceptance_pin = acceptance_pin
        self.acceptance_private = acceptance_private


def build_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    acceptance_private: Ed25519PrivateKey | None = None,
    acceptance_unused: Ed25519PrivateKey | None = None,
) -> Fixture:
    t1_private = Ed25519PrivateKey.generate()
    outcome_values = outcome_helpers.build_all(
        tmp_path / "deployment",
        t1_private=t1_private,
    )
    signed_outcome = outcome_helpers.sign(outcome_values)
    verified_outcome = outcome_helpers.verify(
        outcome_values,
        signed_outcome,
    )
    outcome_path = (
        outcome_values["source"].consume_marker.parent
        / f"{signed_outcome['attempt_id']}.deployment-outcome.json"
    )
    l3_private = outcome_values["fixture"].private_key
    l3_keyring_path = outcome_values["fixture"].keyring_path
    l3_pin = outcome_values["fixture"].keyring_sha256
    t1_keyring_path = outcome_values["t1_keyring"]
    t1_pin = outcome_values["t1_pin"]
    outcome_keyring_path = outcome_values["outcome_keyring"]
    outcome_pin = outcome_values["outcome_pin"]

    external_path = write_bytes(tmp_path / "runtime-external.json", b"external")
    oci_path = write_bytes(tmp_path / "runtime.oci.tar", b"oci")
    content = provenance_helpers.valid_content_attestation()
    content["external_evidence_sha256"] = sha256(external_path.read_bytes())
    content["oci_layout_archive_sha256"] = sha256(oci_path.read_bytes())
    content_path = write_json(tmp_path / "content.json", content)
    content_raw = content_path.read_bytes()
    provenance_private = Ed25519PrivateKey.generate()
    provenance_keyring = provenance_helpers.keyring_for(provenance_private)
    provenance_keyring_path = write_json(
        tmp_path / "provenance-keyring.json",
        provenance_keyring,
    )
    provenance_pin = sha256(canonical_json(provenance_keyring))
    excluded_hashes = sorted(
        [sha256(public_raw(t1_private)), sha256(public_raw(l3_private))]
    )
    excluded_keyrings = {
        "t1_release_keyring_sha256": t1_pin,
        "l3_release_keyring_sha256": l3_pin,
    }
    provenance_draft = provenance_helpers.valid_draft(
        content_raw,
        content,
        provenance_pin,
        excluded_hashes,
        excluded_keyrings,
    )
    signed_provenance = (
        provenance_helpers.signer.sign_provenance(
            provenance_draft,
            provenance_private,
            provenance_keyring,
            content_raw,
            content,
            expected_trusted_keyring_sha256=provenance_pin,
            expected_runtime_source_commit_sha=(
                provenance_helpers.RUNTIME_SOURCE_COMMIT_SHA
            ),
            expected_image_digest=provenance_helpers.IMAGE_DIGEST,
            excluded_authority_key_hashes=excluded_hashes,
            excluded_authority_keyring_sha256s=excluded_keyrings,
            now=provenance_helpers.NOW,
        )
    )
    provenance_path = write_json(
        tmp_path / "provenance.signed.json",
        signed_provenance,
    )

    custody = tmp_path / "readiness-custody"
    custody.mkdir(mode=0o700)
    pins = readiness_module.ReadinessPins(
        provenance_pin,
        t1_pin,
        l3_pin,
        outcome_pin,
        custody,
    )
    readiness_inputs = readiness_module.ReadinessInputs(
        external_image_evidence=external_path,
        oci_layout_archive=oci_path,
        source_root=tmp_path,
        content_attestation=content_path,
        provenance=provenance_path,
        provenance_keyring=provenance_keyring_path,
        t1_keyring=t1_keyring_path,
        outcome=outcome_path,
        outcome_keyring=outcome_keyring_path,
        outcome_source=outcome_values["source"],
        post_evidence=outcome_values["post"],
        t1_runtime_source_commit_sha=(
            provenance_helpers.RUNTIME_SOURCE_COMMIT_SHA
        ),
        t1_runtime_image_digest=provenance_helpers.IMAGE_DIGEST,
        l3_contract_source_commit_sha=outcome_helpers.SOURCE_COMMIT_SHA,
        outcome_contract_source_commit_assertion=(
            outcome_helpers.OUTCOME_SOURCE_COMMIT_SHA
        ),
        questdb_image_digest=outcome_helpers.QUESTDB_IMAGE_DIGEST,
    )
    monkeypatch.setattr(
        readiness_module,
        "verify_image_evidence",
        lambda *_args, **_kwargs: dict(content),
    )
    packet = readiness_module.derive_readiness_packet(
        readiness_inputs,
        pins,
        now=QUERY_NOW - timedelta(minutes=1),
    )
    readiness_path = write_json(tmp_path / "readiness-v2.json", packet, indent=2)
    readiness_raw = readiness_path.read_bytes()
    verified_readiness = readiness_module.VerifiedReadinessPacket(
        payload=packet,
        raw_sha256=sha256(readiness_raw),
        canonical_sha256=sha256(canonical_json(packet)),
    )

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence_fixture = p0_v1_helpers.build_fixture(evidence_root)
    evidence = json.loads(
        evidence_fixture.paths.audit_json.read_text(encoding="utf-8")
    )
    evidence["generated_at"] = (QUERY_NOW + timedelta(seconds=2)).isoformat()
    write_json(evidence_fixture.paths.audit_json, evidence, indent=2)
    proof = json.loads(
        evidence_fixture.paths.readonly_proof.read_text(encoding="utf-8")
    )
    proof["generated_at"] = (QUERY_NOW + timedelta(seconds=3)).isoformat()
    proof["audit_evidence_sha256"] = sha256(
        evidence_fixture.paths.audit_json.read_bytes()
    )
    write_json(evidence_fixture.paths.readonly_proof, proof, indent=2)
    manifest_path = evidence_fixture.paths.manifest
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    query_private = Ed25519PrivateKey.generate()
    query_keyring = keyring(
        query_private,
        version=acceptance_module.QUERY_KEYRING_VERSION,
        purpose=acceptance_module.QUERY_KEY_PURPOSE,
        key_id="query-v3-acceptance-fixture-key",
    )
    query_keyring_path = write_json(
        tmp_path / "query-keyring.json",
        query_keyring,
    )
    query_pin = sha256(canonical_json(query_keyring))
    release = query_helpers.release_payload(verified_readiness)
    release_id = "query-v3-p0-acceptance-v2-a01"
    release.update(
        {
            "release_id": release_id,
            "attempt_id": release_attempt_id(release_id),
            "issued_at": (QUERY_NOW - timedelta(seconds=30)).isoformat(),
            "not_before": (QUERY_NOW - timedelta(seconds=5)).isoformat(),
            "expires_at": (QUERY_NOW + timedelta(minutes=5)).isoformat(),
            "signer_key_id": "query-v3-acceptance-fixture-key",
            "trusted_keyring_sha256": query_pin,
            "pin_root_path_sha256": packet["pin_root_path_sha256"],
            "custody_identity_sha256": "a" * 64,
            "custody_path_sha256": "b" * 64,
            "readiness": query_module._readiness_binding(
                verified_readiness
            ),
            "namespaces": {
                **packet["source_namespaces"],
                **packet["digest_namespaces"],
            },
            "readiness_source_bundle_index_sha256": (
                query_module.readiness_source_bundle_index(
                    verified_readiness
                )
            ),
            "manifest_raw_sha256": sha256(manifest_path.read_bytes()),
            "manifest_canonical_sha256": sha256(canonical_json(manifest)),
            "snapshot_id": manifest["snapshot_id"],
            "audit_window": manifest["audit_window"],
            "endpoint_identity_sha256": (
                verified_outcome.payload["questdb_target_identity_sha256"]
            ),
            "questdb_build_sha256": hashlib.sha256(
                p0_v1_helpers.QUESTDB_BUILD.encode("utf-8")
            ).hexdigest(),
        }
    )
    runtime_paths = {
        "parent_runner_sha256": query_module.PARENT_RUNNER_PATH,
        "query_child_sha256": query_module.QUERY_CHILD_PATH,
        "release_schema_sha256": query_module.RELEASE_SCHEMA_PATH,
        "consume_schema_sha256": query_module.CONSUME_SCHEMA_PATH,
        "child_started_schema_sha256": query_module.CHILD_STARTED_SCHEMA_PATH,
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
    release.update(
        {
            field: sha256(path.read_bytes())
            for field, path in runtime_paths.items()
        }
    )
    release["signature"] = base64.b64encode(
        query_private.sign(
            canonical_json(query_module.unsigned_release_payload(release))
        )
    ).decode("ascii")
    release_path = write_json(tmp_path / "query-release.json", release, indent=2)
    release_raw_sha256 = sha256(release_path.read_bytes())
    release_canonical_sha256 = sha256(canonical_json(release))
    verified_query = SimpleNamespace(
        payload=release,
        raw_sha256=release_raw_sha256,
        canonical_sha256=release_canonical_sha256,
        keyring_sha256=query_pin,
        readiness=verified_readiness,
    )
    consume = query_module._consume_payload(verified_query, QUERY_NOW)
    consume_path = write_json(tmp_path / "consume.json", consume, indent=2)
    consume_raw_sha256 = sha256(consume_path.read_bytes())
    consume_canonical_sha256 = sha256(canonical_json(consume))

    attempt_root = tmp_path / release["attempt_id"]
    bundle_root = attempt_root / "verified-bundle"
    staged_audit = bundle_root / "scripts/commodity_c_fast_l1_l5_audit.py"
    staged_manifest = bundle_root / "release/manifest.json"
    gate_path = bundle_root / "release/pre-connect-query-gate-v3.json"
    audit_invocation_path = (
        bundle_root / "release/audit-child-invocation.json"
    )
    query_invocation_path = (
        bundle_root / "release/query-child-invocation-v3.json"
    )
    legacy_release = dict(release)
    legacy_release["manifest_sha256"] = release["manifest_canonical_sha256"]
    artifact_paths = ArtifactPaths(
        audit_json=evidence_fixture.paths.audit_json,
        audit_csv=evidence_fixture.paths.audit_csv,
        audit_markdown=evidence_fixture.paths.audit_markdown,
        readonly_proof=evidence_fixture.paths.readonly_proof,
    )
    dsn_path = write_bytes(
        tmp_path / "must-not-read.dsn",
        b"postgresql://readonly:unused@invalid/qdb\n",
    )
    audit_core = query_module.build_child_invocation(
        legacy_release,
        staged_audit,
        staged_manifest,
        dsn_path,
        artifact_paths,
    )
    audit_core[0] = os.path.abspath(sys.executable)
    audit_core.extend(["--pre-connect-query-gate", str(gate_path)])
    gate = query_module.build_pre_connect_gate(
        verified_query,
        pins,
        audit_invocation_core=audit_core,
        audit_invocation_path=audit_invocation_path,
        release_path=release_path,
        readiness_path=readiness_path,
        manifest_source_path=manifest_path,
        consume_raw_sha256=consume_raw_sha256,
        consume_canonical_sha256=consume_canonical_sha256,
    )
    gate_path = write_json(gate_path, gate)
    gate_raw_sha256 = sha256(gate_path.read_bytes())
    gate_canonical_sha256 = sha256(canonical_json(gate))
    audit_invocation = [
        *audit_core,
        "--expected-pre-connect-gate-raw-sha256",
        gate_raw_sha256,
        "--expected-pre-connect-gate-canonical-sha256",
        gate_canonical_sha256,
    ]
    audit_invocation_path = write_bytes(
        audit_invocation_path,
        canonical_json(audit_invocation),
    )
    query_invocation = query_module.build_query_child_invocation(
        pins,
        query_pin,
        bundle_root / "scripts/commodity_c_fast_t1_query_child_v3.py",
        audit_invocation_path,
        gate_raw_sha256,
        gate_canonical_sha256,
        release_id=release["release_id"],
        attempt_id=release["attempt_id"],
        release_raw_sha256=release_raw_sha256,
        release_canonical_sha256=release_canonical_sha256,
        consume_raw_sha256=consume_raw_sha256,
        consume_canonical_sha256=consume_canonical_sha256,
    )
    query_invocation_path = write_bytes(
        query_invocation_path,
        canonical_json(query_invocation),
    )
    child_launch = query_module._expected_child_launch_payload(
        consume,
        consume_raw_sha256=consume_raw_sha256,
        consume_canonical_sha256=consume_canonical_sha256,
        launch_capability_sha256="d" * 64,
    )
    child_launch_path = write_json(
        tmp_path / "child-launch.json",
        child_launch,
        indent=2,
    )
    artifact_hashes = {
        "audit_json": sha256(evidence_fixture.paths.audit_json.read_bytes()),
        "audit_csv": sha256(evidence_fixture.paths.audit_csv.read_bytes()),
        "audit_markdown": sha256(
            evidence_fixture.paths.audit_markdown.read_bytes()
        ),
        "readonly_proof": sha256(
            evidence_fixture.paths.readonly_proof.read_bytes()
        ),
    }
    terminal = query_module._terminal(
        verified_query,
        consume_raw_sha256=consume_raw_sha256,
        consume_canonical_sha256=consume_canonical_sha256,
        child_launch_raw_sha256=sha256(child_launch_path.read_bytes()),
        child_launch_canonical_sha256=sha256(canonical_json(child_launch)),
        audit_invocation_raw_sha256=sha256(
            audit_invocation_path.read_bytes()
        ),
        audit_invocation_canonical_sha256=sha256(
            canonical_json(audit_invocation)
        ),
        pre_connect_gate_raw_sha256=gate_raw_sha256,
        pre_connect_gate_canonical_sha256=gate_canonical_sha256,
        query_invocation_raw_sha256=sha256(
            query_invocation_path.read_bytes()
        ),
        query_invocation_canonical_sha256=sha256(
            canonical_json(query_invocation)
        ),
        started_at=QUERY_NOW,
        final_revalidation_at=QUERY_NOW + timedelta(seconds=1),
        ended_at=QUERY_NOW + timedelta(seconds=4),
        terminal_state=acceptance_module.TERMINAL_PASS_STATE,
        error_code=None,
        child_exit_code=0,
        hashes=artifact_hashes,
        p0_pass=True,
        proof_verified=True,
    )
    terminal_path = write_json(tmp_path / "terminal.json", terminal, indent=2)
    external_identity = {
        "schema_version": (
            acceptance_module.EXTERNAL_CUSTODY_IDENTITY_VERSION
        ),
        "custody_id": "c-fast-query-v3-archive-a01",
        "asserted_archive_type": "ASSERTED_APPEND_ONLY",
        "archive_locator_sha256": "e" * 64,
        "independent_from_t1_runner": True,
        "immutability_asserted": True,
    }
    external_identity_path = write_json(
        tmp_path / "external-custody.json",
        external_identity,
    )

    if acceptance_private is None:
        acceptance_private = Ed25519PrivateKey.generate()
    acceptance_keyring = keyring(
        acceptance_private,
        version=acceptance_module.ACCEPTANCE_KEYRING_VERSION,
        purpose=acceptance_module.ACCEPTANCE_KEY_PURPOSE,
        key_id="p0-acceptance-v2-fixture-key",
        unused=acceptance_unused,
    )
    acceptance_keyring_path = write_json(
        tmp_path / "acceptance-keyring.json",
        acceptance_keyring,
    )
    paths = acceptance_module.P0BundleV2Paths(
        query_release=release_path,
        query_trusted_keyring=query_keyring_path,
        readiness_packet=readiness_path,
        content_attestation=content_path,
        provenance=provenance_path,
        provenance_trusted_keyring=provenance_keyring_path,
        t1_trusted_keyring=t1_keyring_path,
        l3_trusted_keyring=l3_keyring_path,
        l3_release=outcome_values["source"].release,
        outcome=outcome_path,
        outcome_trusted_keyring=outcome_keyring_path,
        manifest=manifest_path,
        consume_marker=consume_path,
        child_launch_marker=child_launch_path,
        audit_child_invocation=audit_invocation_path,
        pre_connect_gate=gate_path,
        query_child_invocation=query_invocation_path,
        terminal_seal=terminal_path,
        audit_json=evidence_fixture.paths.audit_json,
        audit_csv=evidence_fixture.paths.audit_csv,
        audit_markdown=evidence_fixture.paths.audit_markdown,
        readonly_proof=evidence_fixture.paths.readonly_proof,
        external_custody_identity=external_identity_path,
    )
    return Fixture(
        paths=paths,
        pins={
            "query": query_pin,
            "provenance": provenance_pin,
            "t1": t1_pin,
            "l3": l3_pin,
            "outcome": outcome_pin,
        },
        acceptance_keyring_path=acceptance_keyring_path,
        acceptance_pin=sha256(canonical_json(acceptance_keyring)),
        acceptance_private=acceptance_private,
    )


def acceptance_draft(
    verified: acceptance_module.VerifiedP0BundleV2,
    fixture: Fixture,
) -> dict:
    release = verified.payloads["query_release"]
    consume = verified.payloads["consume_marker"]
    terminal = verified.payloads["terminal_seal"]
    identity = verified.external_custody_identity
    draft = {
        "schema_version": acceptance_module.ACCEPTANCE_SCHEMA_VERSION,
        "purpose": acceptance_module.ACCEPTANCE_PURPOSE,
        "candidate_id": acceptance_module.CANDIDATE_ID,
        "parent_issue_number": 114,
        "issue_number": 136,
        "acceptance_id": acceptance_module.acceptance_id_for_terminal(
            verified.raw_sha256["terminal_seal"]
        ),
        "accepted_at": (QUERY_NOW + timedelta(minutes=2)).isoformat(),
        "signer_key_id": "p0-acceptance-v2-fixture-key",
        "signer_type": "human",
        "reviewer_role": "independent P0 acceptance reviewer",
        "human_signature": "Accepted exact archived query-v3 P0 evidence.",
        "acceptance_keyring_sha256": fixture.acceptance_pin,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "readiness_packet_id": verified.payloads["readiness_packet"][
            "packet_id"
        ],
        "snapshot_id": release["snapshot_id"],
        "audit_window": release["audit_window"],
        "consumed_at": consume["consumed_at"],
        "started_at": terminal["started_at"],
        "final_revalidation_at": terminal["final_revalidation_at"],
        "ended_at": terminal["ended_at"],
        "keyring_sha256": verified.keyring_sha256,
        "bundle_raw_sha256": verified.raw_sha256,
        "bundle_canonical_sha256": verified.canonical_sha256,
        "artifact_sha256": verified.artifact_sha256,
        "bundle_index_sha256": verified.bundle_index_sha256,
        "external_archive": {
            "custody_id": identity["custody_id"],
            "asserted_archive_type": identity["asserted_archive_type"],
            "archive_locator_sha256": identity["archive_locator_sha256"],
            "custody_identity_raw_sha256": (
                verified.external_custody_identity_raw_sha256
            ),
            "custody_identity_canonical_sha256": (
                verified.external_custody_identity_canonical_sha256
            ),
            "archived_bundle_index_sha256": (
                verified.bundle_index_sha256
            ),
            "archived_at": (QUERY_NOW + timedelta(minutes=1)).isoformat(),
            "independent_custody_asserted": True,
            "immutability_asserted": True,
        },
        "external_archive_verification_state": (
            "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED"
        ),
        "terminal_state": acceptance_module.TERMINAL_PASS_STATE,
        "query_execution_state": "COMPLETED",
        "child_exit_code": 0,
        "production_query_attempted": True,
        "production_query_completed": True,
        "p0_pass": True,
        "proof_verified": True,
        "write_probe_attempted": False,
        "database_mutations_observed": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "p0_accepted": True,
        "p0_acceptance_scope": (
            "HISTORICAL_QUERY_V3_EXACT_EVIDENCE_ONLY"
        ),
        "source_terminal_integrity_scope": (
            "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
        ),
    }
    draft.update(
        {
            field: False
            for field in acceptance_module.ACCEPTANCE_FALSE_AUTHORITY_FIELDS
        }
    )
    return draft


def test_query_v3_exact_bundle_and_signed_acceptance_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    verified = acceptance_module.verify_query_v3_bundle(
        fixture.paths,
        expected_keyring_sha256=fixture.pins,
    )
    draft = acceptance_draft(verified, fixture)
    signed = signer_module.sign_acceptance(
        draft,
        fixture.acceptance_private,
        fixture.acceptance_keyring_path,
        fixture.paths,
        expected_acceptance_keyring_sha256=fixture.acceptance_pin,
        expected_keyring_sha256=fixture.pins,
    )
    acceptance_path = write_json(
        tmp_path / "signed-acceptance.json",
        signed,
    )
    observed, digest = acceptance_module.verify_signed_acceptance(
        acceptance_path,
        fixture.acceptance_keyring_path,
        fixture.paths,
        expected_acceptance_keyring_sha256=fixture.acceptance_pin,
        expected_keyring_sha256=fixture.pins,
    )
    assert observed == signed
    assert digest == acceptance_module.acceptance_sha256(signed)


@pytest.mark.parametrize(
    "terminal_state",
    [
        "COMPLETED_EVIDENCE_P0_BLOCKED",
        "BLOCKED_FINAL_REVALIDATION_PRE_CHILD",
        "FAILED_CHILD_LAUNCH_PRE_QUERY",
        "FAILED_CHILD",
        "FAILED_OUTPUT_VALIDATION",
        "TIMED_OUT_OUTCOME_UNKNOWN",
        "INTERRUPTED_OUTCOME_UNKNOWN",
    ],
)
def test_every_non_pass_terminal_state_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_state: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    terminal = json.loads(fixture.paths.terminal_seal.read_text())
    terminal["terminal_state"] = terminal_state
    write_json(fixture.paths.terminal_seal, terminal, indent=2)
    with pytest.raises(
        (acceptance_module.P0AcceptanceV2Error, OneShotError),
    ):
        acceptance_module.verify_query_v3_bundle(
            fixture.paths,
            expected_keyring_sha256=fixture.pins,
        )


@pytest.mark.parametrize(
    ("role", "field", "value"),
    [
        (
            "query_release",
            "schema_version",
            "commodity_c_fast_t1_one_shot_release_v2",
        ),
        (
            "consume_marker",
            "schema_version",
            "commodity_c_fast_t1_consume_v2",
        ),
        (
            "terminal_seal",
            "schema_version",
            "commodity_c_fast_t1_harness_terminal_v2",
        ),
        (
            "terminal_seal",
            "purpose",
            "c_fast_t1_harness_v2_terminal",
        ),
    ],
)
def test_v1_v2_harness_identity_fallback_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    field: str,
    value: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    path = getattr(fixture.paths, role)
    payload = json.loads(path.read_text())
    payload[field] = value
    write_json(path, payload)
    with pytest.raises(acceptance_module.P0AcceptanceV2Error):
        acceptance_module.verify_query_v3_bundle(
            fixture.paths,
            expected_keyring_sha256=fixture.pins,
        )


def test_raw_reorder_cross_attempt_and_artifact_tamper_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_fixture = build_fixture(tmp_path / "raw", monkeypatch)
    packet = json.loads(raw_fixture.paths.readiness_packet.read_text())
    write_json(raw_fixture.paths.readiness_packet, packet, indent=None)
    with pytest.raises(acceptance_module.P0AcceptanceV2Error):
        acceptance_module.verify_query_v3_bundle(
            raw_fixture.paths,
            expected_keyring_sha256=raw_fixture.pins,
        )

    splice_fixture = build_fixture(tmp_path / "splice", monkeypatch)
    consume = json.loads(splice_fixture.paths.consume_marker.read_text())
    consume["attempt_id"] = "attempt-" + "f" * 64
    write_json(splice_fixture.paths.consume_marker, consume, indent=2)
    with pytest.raises(
        (acceptance_module.P0AcceptanceV2Error, OneShotError),
    ):
        acceptance_module.verify_query_v3_bundle(
            splice_fixture.paths,
            expected_keyring_sha256=splice_fixture.pins,
        )

    tamper_fixture = build_fixture(tmp_path / "tamper", monkeypatch)
    tamper_fixture.paths.audit_csv.write_bytes(b"partial\n")
    with pytest.raises(acceptance_module.P0AcceptanceV2Error):
        acceptance_module.verify_query_v3_bundle(
            tamper_fixture.paths,
            expected_keyring_sha256=tamper_fixture.pins,
        )


@pytest.mark.parametrize(
    "domain",
    ["query", "provenance", "t1", "l3", "outcome"],
)
def test_acceptance_unused_key_cannot_reuse_any_upstream_domain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    domain: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    upstream_name = {
        "query": "query_trusted_keyring",
        "provenance": "provenance_trusted_keyring",
        "t1": "t1_trusted_keyring",
        "l3": "l3_trusted_keyring",
        "outcome": "outcome_trusted_keyring",
    }[domain]
    upstream = json.loads(getattr(fixture.paths, upstream_name).read_text())
    reused_raw = base64.b64decode(
        upstream["keys"][0]["public_key_base64"],
        validate=True,
    )
    reused_private = None
    acceptance_keyring = json.loads(
        fixture.acceptance_keyring_path.read_text()
    )
    acceptance_keyring["keys"].append(
        {
            "key_id": f"acceptance-reused-{domain}-unused",
            "purpose": acceptance_module.ACCEPTANCE_KEY_PURPOSE,
            "public_key_base64": base64.b64encode(reused_raw).decode("ascii"),
        }
    )
    write_json(fixture.acceptance_keyring_path, acceptance_keyring)
    fixture.acceptance_pin = sha256(canonical_json(acceptance_keyring))
    verified = acceptance_module.verify_query_v3_bundle(
        fixture.paths,
        expected_keyring_sha256=fixture.pins,
    )
    draft = acceptance_draft(verified, fixture)
    assert reused_private is None
    with pytest.raises(
        acceptance_module.P0AcceptanceV2Error,
        match="active or unused upstream",
    ):
        signer_module.prepare_acceptance(
            draft,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=fixture.acceptance_pin,
            expected_keyring_sha256=fixture.pins,
        )


def test_acceptance_signer_rejects_purpose_pin_private_and_signature_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    verified = acceptance_module.verify_query_v3_bundle(
        fixture.paths,
        expected_keyring_sha256=fixture.pins,
    )
    draft = acceptance_draft(verified, fixture)
    with pytest.raises(
        acceptance_module.P0AcceptanceV2Error,
        match="pinned acceptance-v2 keyring",
    ):
        signer_module.prepare_acceptance(
            draft,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256="0" * 64,
            expected_keyring_sha256=fixture.pins,
        )
    original_keyring = fixture.acceptance_keyring_path.read_bytes()
    wrong_purpose = json.loads(original_keyring)
    wrong_purpose["keys"][0]["purpose"] = "t1_audit_release_signer"
    write_json(fixture.acceptance_keyring_path, wrong_purpose)
    wrong_purpose_pin = sha256(canonical_json(wrong_purpose))
    wrong_purpose_draft = dict(draft)
    wrong_purpose_draft["acceptance_keyring_sha256"] = wrong_purpose_pin
    with pytest.raises(
        acceptance_module.P0AcceptanceV2Error,
        match="purpose",
    ):
        signer_module.prepare_acceptance(
            wrong_purpose_draft,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=wrong_purpose_pin,
            expected_keyring_sha256=fixture.pins,
        )
    write_bytes(fixture.acceptance_keyring_path, original_keyring)
    with pytest.raises(
        acceptance_module.P0AcceptanceV2Error,
        match="private key",
    ):
        signer_module.sign_acceptance(
            draft,
            Ed25519PrivateKey.generate(),
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=fixture.acceptance_pin,
            expected_keyring_sha256=fixture.pins,
        )
    signed = signer_module.sign_acceptance(
        draft,
        fixture.acceptance_private,
        fixture.acceptance_keyring_path,
        fixture.paths,
        expected_acceptance_keyring_sha256=fixture.acceptance_pin,
        expected_keyring_sha256=fixture.pins,
    )
    signed["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    signed_path = write_json(tmp_path / "tampered-signature.json", signed)
    with pytest.raises(
        acceptance_module.P0AcceptanceV2Error,
        match="signature",
    ):
        acceptance_module.verify_signed_acceptance(
            signed_path,
            fixture.acceptance_keyring_path,
            fixture.paths,
            expected_acceptance_keyring_sha256=fixture.acceptance_pin,
            expected_keyring_sha256=fixture.pins,
        )


@pytest.mark.parametrize(
    "field",
    acceptance_module.ACCEPTANCE_FALSE_AUTHORITY_FIELDS,
)
def test_acceptance_complete_authority_deny_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    verified = acceptance_module.verify_query_v3_bundle(
        fixture.paths,
        expected_keyring_sha256=fixture.pins,
    )
    candidate = {
        **acceptance_draft(verified, fixture),
        "signature": acceptance_module.PLACEHOLDER_SIGNATURE,
    }
    candidate[field] = True
    with pytest.raises(
        (acceptance_module.P0AcceptanceV2Error, OneShotError)
    ):
        acceptance_module.validate_acceptance_bindings(candidate, verified)


def test_signed_output_is_private_create_only_and_template_shape_cannot_sign(
    tmp_path: Path,
) -> None:
    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    output = private_dir / "signed.json"
    payload = {"signed": True}
    signer_module.write_private_json_create_only_verified(output, payload)
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        signer_module.write_private_json_create_only_verified(output, payload)

    with pytest.raises(acceptance_module.P0AcceptanceV2Error):
        signer_module.prepare_acceptance(
            {"human_signature": "PENDING_REVIEW", "signature": "INVALID"},
            private_dir / "missing-keyring.json",
            SimpleNamespace(),
            expected_acceptance_keyring_sha256="0" * 64,
            expected_keyring_sha256={
                domain: "0" * 64
                for domain in acceptance_module.UPSTREAM_PIN_FIELDS
            },
        )
    template = json.loads(
        (
            ROOT
            / "docs/operations/c-fast-p0-acceptance-v2.template.json"
        ).read_text(encoding="utf-8")
    )
    template["signature"] = acceptance_module.PLACEHOLDER_SIGNATURE
    with pytest.raises(OneShotError):
        acceptance_module.validate_json_schema(
            template,
            acceptance_module.ACCEPTANCE_SCHEMA_PATH,
            "invalid pending template",
        )


def test_verifier_has_no_query_network_or_child_execution_entrypoint() -> None:
    source = acceptance_module.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import psycopg",
        "run_query_child(",
        "verify_query_release(",
    ):
        assert forbidden not in text
