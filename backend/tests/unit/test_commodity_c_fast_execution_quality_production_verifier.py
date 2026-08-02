from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_production_artifacts import (
    CFastExecutionQualityCollectionAdmissionV2DTO,
    CFastExecutionQualityP0AcceptanceV6DTO,
    CFastExecutionQualityRoleTrustedKeysDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
)
from app.services.commodity_c_fast_execution_quality import compile_virtual_intent_plan
from app.services.commodity_c_fast_execution_quality_artifact_revalidation import (
    ARTIFACT_ROLES,
    CommodityCFastExecutionQualityArtifactRevalidator,
)
from app.services.commodity_c_fast_execution_quality_production_verifier import (
    CFastExecutionQualityProductionVerifierError,
    CommodityCFastExecutionQualityProductionArtifactVerifier,
    P0_QUERY_V6_BUNDLE_FILE_ORDER,
    runtime_artifact_signature_message,
)
from app.services import (
    commodity_c_fast_execution_quality_production_assembly as assembly_module,
)
from app.services.commodity_c_fast_execution_quality_runtime import (
    CommodityCFastExecutionQualityRuntime,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (
    canonical_json,
)
from app.services.commodity_c_fast_l1_l5_audit_semantic_replay import (
    replay_audit_evidence_semantics,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 9, 1, 2, 0, tzinfo=timezone.utc)
FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}
PURPOSES = {
    "signed_p0_acceptance": ("c_fast_execution_quality_query_v6_p0_acceptance_signer"),
    "collection_admission": (
        "c_fast_execution_quality_query_v6_collection_admission_signer"
    ),
    "execution_policy": "execution_quality_policy_freeze_signer",
    "signed_snapshot": "research_snapshot_signer",
    "virtual_intent_plan": "c_fast_execution_quality_virtual_plan_signer",
    "contract_spec_set": "c_fast_execution_quality_contract_spec_signer",
    "custody_binding": "c_fast_execution_quality_custody_binding_signer",
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


POLICY = _load(
    "production_verifier_policy_helpers",
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py",
)
SHADOW = _load(
    "production_verifier_shadow_helpers",
    ROOT / "backend/tests/unit/test_commodity_c_fast_shadow.py",
)
AUDIT = _load(
    "production_verifier_audit_helpers",
    ROOT / "backend/tests/unit/test_commodity_c_fast_l1_l5_audit_script.py",
)
ONE_SHOT = _load(
    "production_verifier_query_v6_writer",
    ROOT / "scripts/commodity_c_fast_t1_one_shot.py",
)
SIGNER = _load(
    "production_verifier_runtime_artifact_signer",
    ROOT / "scripts/commodity_c_fast_execution_quality_sign_runtime_artifact.py",
)
AUDIT_V4 = _load(
    "production_verifier_frozen_audit_v4",
    ROOT / "scripts/commodity_c_fast_l1_l5_audit_v4.py",
)


def _raw(payload: object) -> bytes:
    return canonical_json(payload) + b"\n"


def _write(path: Path, payload: object) -> bytes:
    raw = _raw(payload)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _write_real_query_v6_evidence(
    path: Path,
    payload: dict,
    *,
    schema_path: Path,
) -> bytes:
    ONE_SHOT.write_json_create_only(
        path,
        payload,
        schema_path,
        "production verifier query-v6 fixture",
    )
    return path.read_bytes()


def _public(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


def _signed(
    payload: dict,
    private: Ed25519PrivateKey,
    role: str,
) -> dict:
    keyring = CFastExecutionQualityRoleTrustedKeysDTO.model_validate(
        {
            "schema_version": (
                "commodity_c_fast_execution_quality_role_trusted_keys_v1"
            ),
            "artifact_role": role,
            "trusted_keys": [
                {
                    "key_id": payload["signer_key_id"],
                    "purpose": PURPOSES[role],
                    "public_key_base64": _public(private),
                }
            ],
        }
    )
    return SIGNER.sign_runtime_artifact(
        payload,
        private_key=private,
        keyring=keyring,
    )


def _signed_without_official_semantic_preflight(
    payload: dict,
    private: Ed25519PrivateKey,
    role: str,
) -> dict:
    signature = private.sign(runtime_artifact_signature_message(role, payload))
    return {
        **payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def _spec(exact: str, multiplier: int, price_tick: object):
    core = {
        "schema_version": "commodity_c_fast_execution_quality_contract_spec_v1",
        "exact_contract": exact,
        "price_tick": str(price_tick),
        "multiplier": multiplier,
        "volume_lots_per_raw_unit": "1",
        "binding_state": ("CALLER_MUST_BIND_TO_ACCEPTED_SIGNED_SNAPSHOT_CONTRACT_SPEC"),
    }
    return CFastExecutionQualityContractSpecDTO.model_validate(
        {**core, "contract_spec_hash": sha256_json(core)}
    )


def _proof(snapshot_id: str, manifest_sha256: str, audit_sha256: str) -> dict:
    snapshot = {
        "questdb_build": "test-build",
        "readonly_user_enabled": True,
        "principal_matches_readonly_user": True,
        "principal_differs_admin": True,
        "global_pgwire_readonly": False,
        "instance_readonly": False,
        "configuration_sources": {
            "pg.readonly.user.enabled": "env",
            "pg.readonly.user": "env",
            "pg.readonly.password": "env",
            "pg.user": "env",
            "pg.security.readonly": "default",
            "readonly": "default",
        },
    }
    return {
        "schema_version": "commodity_c_fast_questdb_readonly_proof_v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_id": snapshot_id,
        "manifest_sha256": manifest_sha256,
        "audit_evidence_sha256": audit_sha256,
        "endpoint_identity_sha256": "3" * 64,
        "endpoint_binding_verified": True,
        "generated_at": (NOW - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "proof_method": "questdb_builtin_pgwire_readonly_user_configuration",
        "same_connection": True,
        "observable_readonly_metadata_stable": True,
        "requested_statement_timeout_ms": 60_000,
        "connect_timeout_seconds": 10,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "preflight": snapshot,
        "postflight": snapshot,
        "limitations": ["l1", "l2", "l3"],
    }


def _terminal(proof_raw: bytes, proof: dict, audit_sha256: str) -> dict:
    pre_hash = hashlib.sha256(canonical_json(proof["preflight"])).hexdigest()
    post_hash = hashlib.sha256(canonical_json(proof["postflight"])).hexdigest()
    return {
        "schema_version": "commodity_c_fast_t1_query_terminal_v6",
        "purpose": "c_fast_t1_query_v6_readonly_terminal",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "release_id": "query-v6-test-release",
        "attempt_id": "attempt-" + "a" * 64,
        "terminal_state": "COMPLETED_PASS",
        "error_code": None,
        "started_at": (NOW - timedelta(minutes=4)).isoformat(),
        "final_revalidation_at": (NOW - timedelta(minutes=3)).isoformat(),
        "ended_at": (NOW - timedelta(minutes=2)).isoformat(),
        "executable_release_raw_sha256": "4" * 64,
        "executable_release_canonical_sha256": "5" * 64,
        "foundation_raw_sha256": "6" * 64,
        "foundation_canonical_sha256": "7" * 64,
        "consume_marker_raw_sha256": "8" * 64,
        "consume_marker_canonical_sha256": "9" * 64,
        "execution_adapter_sha256": "a" * 64,
        "adapter_launch_attempted": True,
        "child_exit_code": 0,
        "child_signal": None,
        "production_query_attempted": True,
        "production_query_completed": True,
        "readonly_proof_verified": True,
        "readonly_principal_verified": True,
        "endpoint_verified": True,
        "readonly_preflight_canonical_sha256": pre_hash,
        "readonly_postflight_canonical_sha256": post_hash,
        "artifact_sha256": {
            "audit_json": audit_sha256,
            "audit_csv": "c" * 64,
            "audit_markdown": "d" * 64,
            "readonly_proof": hashlib.sha256(proof_raw).hexdigest(),
        },
        "p0_pass": True,
        "write_probe_attempted": False,
        "database_mutations_observed": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "terminal_is_authority": False,
        "p0_acceptance_authorized": False,
        "database_mutation_authorized": False,
        "collection_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "replay_allowed": False,
    }


def _root_identity(root: Path) -> tuple[str, str]:
    info = root.stat()
    path_hash = hashlib.sha256(str(root).encode()).hexdigest()
    identity = hashlib.sha256(
        canonical_json(
            {
                "path_sha256": path_hash,
                "device": info.st_dev,
                "inode": info.st_ino,
                "owner_uid": info.st_uid,
                "owner_gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
            }
        )
    ).hexdigest()
    return path_hash, identity


def generation(
    tmp_path: Path,
    *,
    overlap_domains: bool = False,
    audit_scope_splice: bool = False,
    audit_vt_symbol_splice: bool = False,
    audit_detail_summary_splice: bool = False,
    audit_segment_classification_splice: bool = False,
    readonly_proof_drift: bool = False,
    hidden_contract_spec: bool = False,
    bypass_p0_signer_semantic_preflight: bool = False,
):
    root = tmp_path / "runtime-artifacts"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    keys = {role: Ed25519PrivateKey.generate() for role in ARTIFACT_ROLES}
    if overlap_domains:
        keys["custody_binding"] = keys["contract_spec_set"]

    keyring_paths = {}
    keyring_pins = {}
    for role in ARTIFACT_ROLES:
        path = tmp_path / f"{role}.keyring.json"
        key_id = "c-fast-research-1" if role == "signed_snapshot" else f"{role}-signer"
        payload = {
            "schema_version": (
                "commodity_c_fast_execution_quality_role_trusted_keys_v1"
            ),
            "artifact_role": role,
            "trusted_keys": [
                {
                    "key_id": key_id,
                    "purpose": PURPOSES[role],
                    "public_key_base64": _public(keys[role]),
                }
            ],
        }
        raw = _write(path, payload)
        keyring_paths[role] = str(path)
        keyring_pins[role] = hashlib.sha256(raw).hexdigest()

    policy_private, policy_v1, _unused = POLICY._signed_chain()
    keys["execution_policy"] = policy_private
    # Rewrite the policy role keyring after choosing the official signer.
    policy_keyring = {
        "schema_version": "commodity_c_fast_execution_quality_role_trusted_keys_v1",
        "artifact_role": "execution_policy",
        "trusted_keys": [
            {
                "key_id": "c-fast-policy-freeze-signer-1",
                "purpose": PURPOSES["execution_policy"],
                "public_key_base64": _public(policy_private),
            }
        ],
    }
    policy_keyring_raw = _write(Path(keyring_paths["execution_policy"]), policy_keyring)
    keyring_pins["execution_policy"] = hashlib.sha256(policy_keyring_raw).hexdigest()

    policy_v1_raw = _raw(policy_v1.model_dump(mode="json"))
    policy_v2 = POLICY._sign_v2(
        POLICY._unsigned_v2_payload(policy_v1, parent_raw=policy_v1_raw),
        policy_private,
    )
    policy_v1_path = tmp_path / "policy-v1.json"
    policy_v1_path.write_bytes(policy_v1_raw)
    policy_v1_path.chmod(0o600)

    snapshot_private = keys["signed_snapshot"]
    snapshot_payload, snapshot_receipt = SHADOW.sign_payload(
        SHADOW.unsigned_payload(), snapshot_private
    )
    snapshot = SHADOW.CommodityCFastShadowDTO.model_validate(snapshot_payload)
    plan = compile_virtual_intent_plan(
        snapshot=snapshot,
        snapshot_hash=snapshot_receipt,
        policy=policy_v1.policy,
    )
    exact_contracts = tuple(sorted({intent.exact_contract for intent in plan.intents}))
    specs = tuple(
        _spec(row.exact_contract, row.multiplier, row.price_tick)
        for row in sorted(snapshot.targets, key=lambda item: item.exact_contract)
    )
    if hidden_contract_spec:
        specs = (*specs, _spec("SHFE.ag9999", 15, 1))
    common = {
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "generation_id": "c-fast-runtime-generation-test-v1",
        "snapshot_id": snapshot.snapshot_id,
        "issued_at_utc": (NOW - timedelta(minutes=1)).isoformat(),
        "valid_until_utc": (NOW + timedelta(minutes=5)).isoformat(),
        "exact_contracts": list(exact_contracts),
        **FALSE_AUTHORITY,
    }
    audit_manifest = AUDIT.manifest_payload()
    audit_manifest["snapshot_id"] = snapshot.snapshot_id
    exact_by_product = {
        target.product: target.exact_contract for target in snapshot.targets
    }
    audit_manifest["targets"] = [
        {
            "product": product,
            "exact_contract": exact_by_product[product],
            "previous_exact_contract": None,
            "roll_expected": False,
        }
        for product in AUDIT.PRODUCTS
    ]
    execution_time = datetime(2026, 9, 1, 1, 1, tzinfo=timezone.utc)
    audit_manifest["execution_windows"] = [
        {
            "window_id": f"{product}-window-a01",
            "product": product,
            "exact_contract": exact_by_product[product],
            "execution_time": execution_time.isoformat(),
            "window_seconds": 60,
        }
        for product in AUDIT.PRODUCTS
    ]
    manifest_path = AUDIT.write_manifest(tmp_path, audit_manifest)
    manifest_exact_raw = canonical_json(audit_manifest) + b"\n"
    manifest, contracts, session_windows, windows = AUDIT_V4.load_manifest(
        manifest_path
    )
    audit = AUDIT_V4.audit(
        AUDIT.FakeConnection(AUDIT.complete_session_rows(execution_time)),
        manifest,
        contracts,
        session_windows,
        windows,
        AUDIT.AUDIT_START,
        AUDIT.AUDIT_END,
    )
    audit["generated_at"] = (NOW - timedelta(minutes=2, seconds=30)).isoformat()
    if audit_scope_splice:
        audit["contracts"][0]["exact_contract"] = "SHFE.ag9999"
    if audit_vt_symbol_splice:
        audit["contracts"][0]["vt_symbol"] = "cu9999.SHFE"
    if audit_detail_summary_splice:
        audit["contracts"][0]["all"]["rows"] = 0
        audit["contracts"][0]["all"]["classification"] = "UNUSABLE"
    if audit_segment_classification_splice:
        audit["contracts"][0]["sessions"]["night_open"][
            "classification"
        ] = "UNUSABLE"
    audit_raw = _write_real_query_v6_evidence(
        tmp_path / "adapter-audit.json",
        audit,
        schema_path=(
            ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
        ),
    )
    audit_sha256 = hashlib.sha256(audit_raw).hexdigest()
    proof = _proof(snapshot.snapshot_id, audit["manifest_sha256"], audit_sha256)
    if readonly_proof_drift:
        proof["postflight"] = {
            **proof["postflight"],
            "questdb_build": "drifted-build",
        }
    proof_raw = _write_real_query_v6_evidence(
        tmp_path / "adapter-readonly-proof.json",
        proof,
        schema_path=(
            ROOT
            / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
        ),
    )
    terminal = _terminal(proof_raw, proof, audit_sha256)
    terminal_raw = _write_real_query_v6_evidence(
        tmp_path / "query-v6-terminal.json",
        terminal,
        schema_path=(
            ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json"
        ),
    )
    bundle_raw_sha256 = {name: hashlib.sha256(f"raw:{name}".encode()).hexdigest() for name in P0_QUERY_V6_BUNDLE_FILE_ORDER}
    bundle_canonical_sha256 = {
        name: (
            None
            if name in {"audit_csv", "audit_markdown"}
            else hashlib.sha256(f"canonical:{name}".encode()).hexdigest()
        )
        for name in P0_QUERY_V6_BUNDLE_FILE_ORDER
    }
    bundle_raw_sha256.update(
        {
            "foundation_release": terminal["foundation_raw_sha256"],
            "executable_release": terminal["executable_release_raw_sha256"],
            "terminal": hashlib.sha256(terminal_raw).hexdigest(),
            "audit_json": audit_sha256,
            "audit_csv": terminal["artifact_sha256"]["audit_csv"],
            "audit_markdown": terminal["artifact_sha256"]["audit_markdown"],
            "readonly_proof": hashlib.sha256(proof_raw).hexdigest(),
            "manifest": hashlib.sha256(manifest_exact_raw).hexdigest(),
        }
    )
    bundle_canonical_sha256.update(
        {
            "foundation_release": terminal["foundation_canonical_sha256"],
            "executable_release": terminal["executable_release_canonical_sha256"],
            "terminal": hashlib.sha256(canonical_json(terminal)).hexdigest(),
            "audit_json": hashlib.sha256(canonical_json(audit)).hexdigest(),
            "readonly_proof": hashlib.sha256(canonical_json(proof)).hexdigest(),
            "manifest": hashlib.sha256(canonical_json(audit_manifest)).hexdigest(),
        }
    )
    bundle_size_bytes = {name: 1 for name in P0_QUERY_V6_BUNDLE_FILE_ORDER}
    bundle_size_bytes.update(
        {
            "terminal": len(terminal_raw),
            "audit_json": len(audit_raw),
            "readonly_proof": len(proof_raw),
            "manifest": len(manifest_exact_raw),
        }
    )
    bundle_index = {
        "schema_version": "commodity_c_fast_execution_quality_p0_bundle_index_v6_v1",
        "files": [
            {
                "name": name,
                "size_bytes": bundle_size_bytes[name],
                "raw_sha256": bundle_raw_sha256[name],
                "canonical_sha256": bundle_canonical_sha256[name],
            }
            for name in P0_QUERY_V6_BUNDLE_FILE_ORDER
        ],
    }
    bundle_index_sha256 = hashlib.sha256(canonical_json(bundle_index)).hexdigest()
    archived_at = NOW - timedelta(minutes=1, seconds=30)
    p0_unsigned = {
            **common,
            "schema_version": "commodity_c_fast_execution_quality_p0_acceptance_v6_v1",
            "artifact_role": "signed_p0_acceptance",
            "purpose": "c_fast_query_v6_exact_terminal_p0_acceptance",
            "terminal_exact_json_base64": base64.b64encode(terminal_raw).decode(),
            "terminal_raw_sha256": hashlib.sha256(terminal_raw).hexdigest(),
            "terminal_canonical_sha256": hashlib.sha256(
                canonical_json(terminal)
            ).hexdigest(),
            "readonly_proof_exact_json_base64": base64.b64encode(proof_raw).decode(),
            "readonly_proof_raw_sha256": hashlib.sha256(proof_raw).hexdigest(),
            "readonly_proof_canonical_sha256": hashlib.sha256(
                canonical_json(proof)
            ).hexdigest(),
            "audit_exact_json_base64": base64.b64encode(audit_raw).decode(),
            "audit_raw_sha256": audit_sha256,
            "audit_canonical_sha256": hashlib.sha256(canonical_json(audit)).hexdigest(),
            "manifest_exact_json_base64": base64.b64encode(
                manifest_exact_raw
            ).decode(),
            "executable_release_raw_sha256": terminal["executable_release_raw_sha256"],
            "executable_release_canonical_sha256": terminal[
                "executable_release_canonical_sha256"
            ],
            "foundation_raw_sha256": terminal["foundation_raw_sha256"],
            "foundation_canonical_sha256": terminal["foundation_canonical_sha256"],
            "execution_adapter_sha256": terminal["execution_adapter_sha256"],
            "bundle_raw_sha256": bundle_raw_sha256,
            "bundle_canonical_sha256": bundle_canonical_sha256,
            "bundle_size_bytes": bundle_size_bytes,
            "bundle_index_sha256": bundle_index_sha256,
            "external_archive": {
                "custody_id": "external-custody-test-v1",
                "asserted_archive_type": "ASSERTED_APPEND_ONLY",
                "archive_locator_sha256": "b" * 64,
                "custody_identity_raw_sha256": bundle_raw_sha256[
                    "external_custody_identity"
                ],
                "custody_identity_canonical_sha256": bundle_canonical_sha256[
                    "external_custody_identity"
                ],
                "archived_bundle_index_sha256": bundle_index_sha256,
                "archived_at_utc": archived_at.isoformat(),
                "independent_custody_asserted": True,
                "immutability_asserted": True,
                "verification_state": "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED",
            },
            "consumed_at_utc": terminal["started_at"],
            "launch_claimed_at_utc": (NOW - timedelta(minutes=2, seconds=45)).isoformat(),
            "started_at_utc": terminal["started_at"],
            "final_revalidation_at_utc": terminal["final_revalidation_at"],
            "ended_at_utc": terminal["ended_at"],
            "archived_at_utc": archived_at.isoformat(),
            "p0_accepted": True,
            "exact_terminal_replayed": True,
            "exact_readonly_proof_replayed": True,
            "exact_audit_replayed": True,
            "signer_type": "human",
            "reviewer_role": "independent query-v6 P0 reviewer",
            "human_signature": "Reviewed exact terminal and readonly proof",
            "signer_key_id": "signed_p0_acceptance-signer",
        }
    p0 = (
        _signed_without_official_semantic_preflight(
            p0_unsigned,
            keys["signed_p0_acceptance"],
            "signed_p0_acceptance",
        )
        if bypass_p0_signer_semantic_preflight
        else _signed(
            p0_unsigned,
            keys["signed_p0_acceptance"],
            "signed_p0_acceptance",
        )
    )
    raw_by_role = {"signed_p0_acceptance": _raw(p0)}
    policy_v2_payload = policy_v2.model_dump(mode="json")
    raw_by_role["execution_policy"] = _raw(policy_v2_payload)
    raw_by_role["signed_snapshot"] = _raw(snapshot_payload)
    spec_payload = _signed(
        {
            **common,
            "schema_version": "commodity_c_fast_execution_quality_signed_contract_spec_set_v1",
            "artifact_role": "contract_spec_set",
            "purpose": "c_fast_execution_quality_exact_contract_spec_freeze",
            "specs": [item.model_dump(mode="json") for item in specs],
            "signer_key_id": "contract_spec_set-signer",
        },
        keys["contract_spec_set"],
        "contract_spec_set",
    )
    raw_by_role["contract_spec_set"] = _raw(spec_payload)
    plan_payload = _signed(
        {
            **common,
            "schema_version": "commodity_c_fast_execution_quality_signed_plan_v1",
            "artifact_role": "virtual_intent_plan",
            "purpose": "c_fast_execution_quality_virtual_plan_freeze",
            "execution_policy_raw_sha256": hashlib.sha256(
                raw_by_role["execution_policy"]
            ).hexdigest(),
            "signed_snapshot_raw_sha256": hashlib.sha256(
                raw_by_role["signed_snapshot"]
            ).hexdigest(),
            "contract_spec_set_raw_sha256": hashlib.sha256(
                raw_by_role["contract_spec_set"]
            ).hexdigest(),
            "plan": plan.model_dump(mode="json"),
            "signer_key_id": "virtual_intent_plan-signer",
        },
        keys["virtual_intent_plan"],
        "virtual_intent_plan",
    )
    raw_by_role["virtual_intent_plan"] = _raw(plan_payload)
    admission_payload = _signed(
        {
            **common,
            "schema_version": "commodity_c_fast_execution_quality_collection_admission_v2",
            "artifact_role": "collection_admission",
            "purpose": "c_fast_execution_quality_query_v6_collection_admission",
            "signed_p0_acceptance_raw_sha256": hashlib.sha256(
                raw_by_role["signed_p0_acceptance"]
            ).hexdigest(),
            "execution_policy_raw_sha256": hashlib.sha256(
                raw_by_role["execution_policy"]
            ).hexdigest(),
            "p0_accepted": True,
            "policy_rules_complete": True,
            "admission_fact_frozen": True,
            "signer_type": "human",
            "reviewer_role": "independent collection admission reviewer",
            "human_signature": "Reviewed P0 and policy bindings",
            "signer_key_id": "collection_admission-signer",
        },
        keys["collection_admission"],
        "collection_admission",
    )
    raw_by_role["collection_admission"] = _raw(admission_payload)

    path_hash, identity = _root_identity(root)
    custody_payload = _signed(
        {
            **common,
            "schema_version": "commodity_c_fast_execution_quality_signed_custody_binding_v1",
            "artifact_role": "custody_binding",
            "purpose": "c_fast_execution_quality_exact_generation_custody",
            "custody_root_path_sha256": path_hash,
            "custody_identity_sha256": identity,
            "artifact_raw_sha256": {
                role: hashlib.sha256(raw_by_role[role]).hexdigest()
                for role in ARTIFACT_ROLES[:-1]
            },
            "signer_key_id": "custody_binding-signer",
        },
        keys["custody_binding"],
        "custody_binding",
    )
    raw_by_role["custody_binding"] = _raw(custody_payload)

    artifact_paths = {}
    for role in ARTIFACT_ROLES:
        path = root / f"{role}.json"
        path.write_bytes(raw_by_role[role])
        path.chmod(0o600)
        artifact_paths[role] = path

    settings = Settings(
        commodity_c_fast_execution_quality_artifact_custody_root=str(root),
        commodity_c_fast_execution_quality_artifact_paths_json=json.dumps(
            {role: str(path) for role, path in artifact_paths.items()}
        ),
        commodity_c_fast_execution_quality_artifact_expected_root_path_sha256=path_hash,
        commodity_c_fast_execution_quality_artifact_expected_identity_sha256=identity,
        commodity_c_fast_execution_quality_artifact_expected_owner_uid=os.geteuid(),
        commodity_c_fast_execution_quality_role_keyring_paths_json=json.dumps(
            keyring_paths
        ),
        commodity_c_fast_execution_quality_role_keyring_raw_sha256_json=json.dumps(
            keyring_pins
        ),
        commodity_c_fast_execution_quality_policy_v1_path=str(policy_v1_path),
        commodity_c_fast_execution_quality_policy_v1_expected_raw_sha256=hashlib.sha256(
            policy_v1_raw
        ).hexdigest(),
    )
    revalidator = CommodityCFastExecutionQualityArtifactRevalidator(
        artifact_paths=artifact_paths,
        artifact_bundle_verifier=(
            CommodityCFastExecutionQualityProductionArtifactVerifier(settings=settings)
        ),
        custody_root=root,
        expected_custody_root_path_sha256=path_hash,
        expected_custody_identity_sha256=identity,
        expected_owner_uid=os.geteuid(),
    )
    return revalidator, artifact_paths, settings


def test_complete_signed_generation_returns_same_typed_inputs(
    secure_tmp_path: Path,
) -> None:
    revalidator, paths, _ = generation(secure_tmp_path)
    p0_payload = json.loads(paths["signed_p0_acceptance"].read_text())
    for field in (
        "terminal_exact_json_base64",
        "readonly_proof_exact_json_base64",
        "audit_exact_json_base64",
    ):
        exact_raw = base64.b64decode(p0_payload[field], validate=True)
        assert exact_raw.startswith(b'{\n  "')
        assert exact_raw.endswith(b"\n")
        assert exact_raw != canonical_json(json.loads(exact_raw)) + b"\n"

    identities = []
    for trigger in ("startup", "reload", "recovery"):
        bundle = revalidator(trigger, NOW)
        identities.append(
            (
                bundle.preverified_plan.plan_hash,
                bundle.source_snapshot_receipt_sha256,
                bundle.score_policy_hash,
                tuple(spec.contract_spec_hash for spec in bundle.contract_specs),
            )
        )
        assert bundle.revalidation_receipt.exact_contracts
        assert (
            bundle.source_snapshot_receipt_sha256
            == bundle.preverified_plan.snapshot_hash
        )
        assert tuple(spec.exact_contract for spec in bundle.contract_specs) == (
            bundle.revalidation_receipt.exact_contracts
        )
        assert (
            bundle.score_policy.foundation_policy_hash
            == bundle.preverified_plan.policy_hash
        )
        assert bundle.revalidation_receipt.production_allowed is False
    assert len(set(identities)) == 1


def test_frozen_audit_v4_complete_evidence_replays_in_shared_core(
    secure_tmp_path: Path,
) -> None:
    _, paths, _ = generation(secure_tmp_path)
    p0 = json.loads(paths["signed_p0_acceptance"].read_text())
    audit = json.loads(base64.b64decode(p0["audit_exact_json_base64"], validate=True))
    manifest = json.loads(
        base64.b64decode(p0["manifest_exact_json_base64"], validate=True)
    )

    assert replay_audit_evidence_semantics(audit, manifest) == tuple(
        sorted(p0["exact_contracts"])
    )


def test_embedded_exact_json_rejects_duplicate_keys_and_nonfinite_constants() -> None:
    for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n'):
        with pytest.raises(
            CFastExecutionQualityProductionVerifierError,
            match="EXACT_JSON_INVALID",
        ):
            CommodityCFastExecutionQualityProductionArtifactVerifier._decode_exact_json(
                base64.b64encode(raw).decode("ascii"),
                "UNSAFE_EMBEDDED",
            )


def test_cross_role_key_material_overlap_fails_closed(secure_tmp_path: Path) -> None:
    revalidator, _, _ = generation(secure_tmp_path, overlap_domains=True)

    with pytest.raises(
        CFastExecutionQualityProductionVerifierError,
        match="PRODUCTION_ARTIFACT_KEY_DOMAIN_OVERLAP",
    ):
        revalidator("startup", NOW)


def test_role_signature_domain_rejects_cross_role_replay() -> None:
    private = Ed25519PrivateKey.generate()
    unsigned = {
        "artifact_role": "signed_p0_acceptance",
        "signer_key_id": "cross-role-replay-key",
    }
    signature = private.sign(
        CommodityCFastExecutionQualityProductionArtifactVerifier._custom_signature_message(
            "signed_p0_acceptance",
            unsigned,
        )
    )
    payload = {
        **unsigned,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    wrong_role_keyring = CFastExecutionQualityRoleTrustedKeysDTO.model_validate(
        {
            "schema_version": (
                "commodity_c_fast_execution_quality_role_trusted_keys_v1"
            ),
            "artifact_role": "collection_admission",
            "trusted_keys": [
                {
                    "key_id": "cross-role-replay-key",
                    "purpose": PURPOSES["collection_admission"],
                    "public_key_base64": _public(private),
                }
            ],
        }
    )

    with pytest.raises(
        CFastExecutionQualityProductionVerifierError,
        match="COLLECTION_ADMISSION_SIGNATURE_INVALID",
    ):
        CommodityCFastExecutionQualityProductionArtifactVerifier._verify_custom_signature(
            "collection_admission",
            payload,
            wrong_role_keyring,
        )


def test_signed_audit_contract_splice_cannot_supply_runtime_scope(
    secure_tmp_path: Path,
) -> None:
    revalidator, _, _ = generation(
        secure_tmp_path,
        audit_scope_splice=True,
        bypass_p0_signer_semantic_preflight=True,
    )

    with pytest.raises(
        CFastExecutionQualityProductionVerifierError,
        match="QUERY_V6_P0_AUDIT_SEMANTIC_REPLAY_INVALID",
    ):
        revalidator("startup", NOW)


@pytest.mark.parametrize(
    "tamper",
    (
        "audit_vt_symbol_splice",
        "audit_detail_summary_splice",
        "audit_segment_classification_splice",
    ),
)
def test_signed_audit_derived_semantic_tamper_fails_closed(
    secure_tmp_path: Path,
    tamper: str,
) -> None:
    revalidator, _, _ = generation(
        secure_tmp_path,
        bypass_p0_signer_semantic_preflight=True,
        **{tamper: True},
    )

    with pytest.raises(
        CFastExecutionQualityProductionVerifierError,
        match="QUERY_V6_P0_AUDIT_SEMANTIC_REPLAY_INVALID",
    ):
        revalidator("startup", NOW)


def test_official_signer_replays_self_contained_p0_before_signing(
    secure_tmp_path: Path,
) -> None:
    with pytest.raises(
        SIGNER.RuntimeArtifactSigningError,
        match="P0 evidence semantic replay failed before signing",
    ):
        generation(secure_tmp_path, audit_scope_splice=True)


def test_readonly_proof_claimed_stable_but_drifted_payload_fails_closed(
    secure_tmp_path: Path,
) -> None:
    revalidator, _, _ = generation(
        secure_tmp_path,
        readonly_proof_drift=True,
        bypass_p0_signer_semantic_preflight=True,
    )

    with pytest.raises(
        CFastExecutionQualityProductionVerifierError,
        match="QUERY_V6_P0_READONLY_PROOF_STABILITY_INVALID",
    ):
        revalidator("startup", NOW)


def test_contract_spec_envelope_cannot_hide_extra_contract(
    secure_tmp_path: Path,
) -> None:
    revalidator, _, _ = generation(secure_tmp_path, hidden_contract_spec=True)

    with pytest.raises(
        CFastExecutionQualityProductionVerifierError,
        match="CONTRACT_SPEC_EXACT_GENERATION_SET_INVALID",
    ):
        revalidator("startup", NOW)


def test_human_review_fields_reject_whitespace_and_indented_pending(
    secure_tmp_path: Path,
) -> None:
    _, paths, _ = generation(secure_tmp_path)
    cases = (
        (
            CFastExecutionQualityP0AcceptanceV6DTO,
            json.loads(paths["signed_p0_acceptance"].read_text()),
        ),
        (
            CFastExecutionQualityCollectionAdmissionV2DTO,
            json.loads(paths["collection_admission"].read_text()),
        ),
    )

    for model, source in cases:
        for field in ("reviewer_role", "human_signature"):
            for invalid in (" \t ", "  PENDING_unsigned"):
                payload = dict(source)
                payload[field] = invalid
                with pytest.raises(ValueError, match="human review is pending"):
                    model.model_validate(payload)


def test_official_runtime_signer_writes_verifier_exact_canonical_newline(
    secure_tmp_path: Path,
) -> None:
    _, paths, _ = generation(secure_tmp_path)
    signed = json.loads(paths["signed_p0_acceptance"].read_text())
    output_root = secure_tmp_path / "signer-output"
    output_root.mkdir(mode=0o700)
    output = output_root / "signed-p0.json"

    raw = SIGNER.write_private_json_create_only(output, signed)

    assert raw == canonical_json(signed) + b"\n"
    assert output.read_bytes() == paths["signed_p0_acceptance"].read_bytes()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        SIGNER.write_private_json_create_only(output, signed)


def test_exact_artifact_tamper_fails_before_semantic_release(
    secure_tmp_path: Path,
) -> None:
    revalidator, paths, _ = generation(secure_tmp_path)
    payload = json.loads(paths["collection_admission"].read_text())
    payload["p0_accepted"] = False
    paths["collection_admission"].write_bytes(_raw(payload))

    with pytest.raises(Exception):
        revalidator("recovery", NOW)


def test_global_factory_binds_concrete_revalidator_when_config_complete(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _revalidator, _paths, base = generation(secure_tmp_path)
    journal = secure_tmp_path / "journal"
    exports = secure_tmp_path / "exports"
    journal.mkdir(mode=0o700)
    exports.mkdir(mode=0o700)
    payload = base.model_dump()
    payload.update(
        {
            "commodity_c_fast_execution_quality_runtime_enabled": True,
            "commodity_c_fast_execution_quality_journal_root": str(journal),
            "commodity_c_fast_execution_quality_evidence_export_root": str(exports),
        }
    )
    settings = Settings(**payload)
    runtime = CommodityCFastExecutionQualityRuntime(
        settings=settings,
        clock=lambda: NOW,
    )
    monkeypatch.setattr(
        assembly_module,
        "commodity_c_fast_execution_quality_runtime",
        runtime,
    )

    assembly = assembly_module._build_production_assembly()
    status = assembly.status()

    assert status["capabilities"]["full_revalidation_verifier_bound"] is True
    assert status["capabilities"]["durable_sidecar_runtime_bound"] is True
    assert status["capabilities"]["horizon_worker_built"] is False
    assert status["capabilities"]["questdb_evidence_adapter_bound"] is False
