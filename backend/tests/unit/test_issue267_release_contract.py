from __future__ import annotations

import fnmatch
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = ROOT / "docs/architecture/web-bridge-release-dependencies-v1.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
EVIDENCE_SHA256 = "a" * 64
SOURCE_COMMIT = "b" * 40
IMAGE_DIGEST = f"sha256:{EVIDENCE_SHA256}"


def _matching_rule_ids(path: str) -> list[str]:
    matches: list[str] = []
    for rule in MANIFEST["path_rules"]:
        match = rule["match"]
        if (
            path in match.get("exact", [])
            or any(path.startswith(prefix) for prefix in match.get("prefix", []))
            or any(
                fnmatch.fnmatchcase(path, pattern) for pattern in match.get("glob", [])
            )
        ):
            matches.append(rule["id"])
    return matches


def _rule_specificity(rule: dict[str, object], path: str) -> tuple[int, int] | None:
    match = rule["match"]
    candidates: list[tuple[int, int]] = []
    if path in match.get("exact", []):
        candidates.append((3, len(path)))
    candidates.extend(
        (2, len(pattern.replace("*", "")))
        for pattern in match.get("glob", [])
        if fnmatch.fnmatchcase(path, pattern)
    )
    candidates.extend(
        (1, len(prefix))
        for prefix in match.get("prefix", [])
        if path.startswith(prefix)
    )
    return max(candidates, default=None)


def _selected_rules(path: str) -> list[dict[str, object]]:
    scored = [
        (score, rule)
        for rule in MANIFEST["path_rules"]
        if (score := _rule_specificity(rule, path)) is not None
    ]
    if not scored:
        return []
    highest = max(score for score, _ in scored)
    return [rule for score, rule in scored if score == highest]


def test_release_dependency_contract_is_inert_and_fail_closed() -> None:
    assert MANIFEST["schema_version"] == "web_bridge_release_dependencies_v1"
    assert MANIFEST["issue"] == 267
    assert MANIFEST["status"] == (
        "phase_1_pre_c_c2b_served_proof_v2_activation_deploy_frozen"
    )

    safety = MANIFEST["safety"]
    assert safety["classifier_consumption_allowed"] is False
    assert safety["production_cd_changed"] is True
    assert safety["automatic_deploy_allowed"] is False
    assert safety["production_allowed"] is False
    assert safety["live_trading_authorized"] is False
    assert safety["countable_forward"] is False
    assert safety["unknown_path"] == "block"
    assert safety["unknown_dependency"] == "block"
    assert safety["ambiguous_match"] == "block"
    bootstrap = MANIFEST["pr_update_comment_gate_bootstrap"]
    assert bootstrap["trusted_event"] == "pull_request_target"
    assert bootstrap["trusted_checkout"] == "github.event.pull_request.base.sha"
    assert "No subsequent issue-267 PR may merge" in bootstrap["activation_blocker"]


def test_legacy_restart_remaining_stages_are_ordered_and_non_authorizing() -> None:
    contract = MANIFEST["legacy_restart_migration_contract"]
    assert contract["current_code_stage"] == "phase_1_pre_c_c2b_served_proof_v2"
    assert contract["current_runtime_stage"] == (
        "not_deployed_or_activated_by_this_contract"
    )
    assert contract["scripts_deploy_status"] == (
        "hard_frozen_except_exact_receipt_bound_frozen_bootstrap_activation_until_d4"
    )
    assert contract["manual_approval_substitutes_for_missing_evidence"] is False
    assert contract["c2b"] == {
        "implementation_status": (
            "implemented_non_authorizing_owner_capture_with_owner_bound_linux_rpc_"
            "adapter_served_proof_v2_activation_custody"
        ),
        "commit_point": (
            "create_only_activation_head_v2_bound_to_actual_fd_pinned_custody_"
            "unique_commodity_owner_captures_and_owner_bound_linux_rpc_adapter_"
            "served_proof"
        ),
        "external_high_water_verified": False,
        "target_runtime_verified": False,
        "reconciliation_completed": False,
        "windows_fence_released": False,
        "authority_restore_allowed": False,
    }

    stages = contract["ordered_remaining_stages"]
    assert [stage["id"] for stage in stages] == [
        "phase_1_pre_c_c2b_windows_durable_fence_foundation",
        "phase_1_pre_c_c2b_frozen_bootstrap_activation",
        "phase_1_pre_c_c2c_external_high_water",
        "phase_1_pre_d_d1_target_runtime_identity",
        "phase_1_pre_d_d2_windows_durable_token_transfer",
        "phase_1_pre_d_d3_atomic_capability_commit",
        "phase_1_pre_d_d4_deployment_gate_restore",
    ]
    assert [stage["may_set_true"] for stage in stages] == [
        [],
        [],
        ["external_high_water_verified"],
        ["target_runtime_verified"],
        [],
        [
            "reconciliation_completed",
            "windows_fence_released",
        ],
        ["deployment_authorized"],
    ]
    by_id = {stage["id"]: stage for stage in stages}
    windows_foundation = by_id["phase_1_pre_c_c2b_windows_durable_fence_foundation"]
    bootstrap = by_id["phase_1_pre_c_c2b_frozen_bootstrap_activation"]
    c2c = by_id["phase_1_pre_c_c2c_external_high_water"]
    d1 = by_id["phase_1_pre_d_d1_target_runtime_identity"]
    d2 = by_id["phase_1_pre_d_d2_windows_durable_token_transfer"]
    d3 = by_id["phase_1_pre_d_d3_atomic_capability_commit"]
    d4 = by_id["phase_1_pre_d_d4_deployment_gate_restore"]
    assert bootstrap["predecessor_artifact"] == (
        "verified_windows_durable_fence_foundation_and_c2b_activation_head_v2_"
        "with_served_proof_closure_and_signed_immutable_bootstrap_manifest"
    )
    assert (
        "activation_head_v2_binds_privacy_safe_exact_served_proof_bytes_facts_"
        "hash_and_transport_observed_at" in bootstrap["requires"]
    )
    assert (
        "activation_head_v1_is_historical_non_eligible_and_cannot_be_backfilled"
        in bootstrap["requires"]
    )
    assert (
        "host_observed_old_runtime_owner_frozen_trading_disabled_and_authority_revoked"
        in windows_foundation["requires"]
    )
    assert (
        "fresh_windows_preflight_pending_send_outcomes_empty_and_active_orders_zero"
        in windows_foundation["requires"]
    )
    assert (
        "signed_exact_extension_hash_version_config_install_attempt_and_zero_order_preflight_receipt"
        in windows_foundation["requires"]
    )
    assert "general_deploy_script_or_unbound_compose_recreate" in bootstrap["forbidden"]
    assert "self_seed_empty_witness_as_verified" in c2c["forbidden"]
    assert "independent_host_observer_not_target_self_report" in d1["requires"]
    assert "staged_token_rejected_by_final_send_cancel" in d2["requires"]
    assert "reconciliation_completed" in d2["forbidden"]
    assert "windows_fence_released" in d2["forbidden"]
    assert (
        "windows_atomic_old_token_revoke_and_staged_target_token_activation"
        in d3["requires"]
    )
    assert (
        "every_final_send_cancel_requires_active_token_and_exact_bound_d3_grant_receipt_hash"
        in d3["requires"]
    )
    assert (
        "initial_baseline_and_legacy_migration_keep_authority_revoked" in d3["requires"]
    )
    assert (
        "activation_receipt_and_post_proofs_compare_and_swap_advance_external_high_water"
        in d3["requires"]
    )
    assert (
        "external_high_water_exact_readback_before_any_boolean_projection"
        in d3["requires"]
    )
    assert d3["conditional_may_set_true"] == {
        "authority_restore_allowed": (
            "mode_is_planned_restart_and_exact_pre_drain_authority_is_unexpired_"
            "unrevoked_and_byte_bound"
        )
    }
    assert d3["mode_projection"] == {
        "PLANNED_RESTART": (
            "may_restore_only_exact_pre_drain_authority_after_capability_commit"
        ),
        "INITIAL_BASELINE": (
            "authority_remains_revoked_requires_new_signed_authorization"
        ),
        "LEGACY_MIGRATION_BASELINE": (
            "authority_remains_revoked_requires_new_signed_authorization"
        ),
    }
    assert "deployment_authorized" in d3["forbidden"]
    assert "deploy_action_must_preserve_d1_bound_runtime_identity" in d4["requires"]
    for stage in stages:
        assert stage["predecessor_artifact"]
        assert stage["commit_point"]
        assert stage["recovery_query"]
        assert stage["retry_identity"]
        assert stage["crash_states"]
        assert stage["requires"]
        assert stage["forbidden"]
        assert stage["forbidden"][-3:] == [
            "production_allowed",
            "live_trading_authorized",
            "countable_forward",
        ]


def test_legacy_restart_stage_commit_and_recovery_semantics_are_exact() -> None:
    stages = {
        stage["id"]: stage
        for stage in MANIFEST["legacy_restart_migration_contract"][
            "ordered_remaining_stages"
        ]
    }
    expected = {
        "phase_1_pre_c_c2b_windows_durable_fence_foundation": {
            "predecessor_artifact": "merged_windows_durable_fence_extension_and_signed_install_manifest",
            "commit_point": "windows_restart_attestation_proves_durable_fail_closed_fence_held_and_final_order_admission_blocked",
            "recovery_query": "query_exact_windows_install_attempt_and_durable_fence_state",
            "retry_identity": "deterministic_windows_fence_install_attempt_id",
            "crash_states": {
                "before_service_restart": "remain_old_extension_frozen_and_require_fresh_authorization",
                "after_restart_before_attestation": "query_same_install_attempt_and_keep_fence_held",
                "partial_install_or_unknown_version": "do_not_restart_again_keep_orders_blocked_and_require_operator_recovery",
                "durable_store_unreadable": "windows_startup_and_final_order_admission_fail_closed",
            },
        },
        "phase_1_pre_c_c2b_frozen_bootstrap_activation": {
            "predecessor_artifact": "verified_windows_durable_fence_foundation_and_c2b_activation_head_v2_with_served_proof_closure_and_signed_immutable_bootstrap_manifest",
            "commit_point": "host_observer_receipt_for_exact_single_frozen_runtime_and_c2b_activation_head",
            "recovery_query": "query_exact_bootstrap_attempt_and_host_identity_without_replacement_retry",
            "retry_identity": "deterministic_bootstrap_attempt_id",
            "crash_states": {
                "before_old_runtime_stop": "remain_old_runtime_frozen",
                "after_stop_before_target_start": "remain_no_runtime_frozen_and_resume_same_attempt",
                "after_start_before_receipt": "query_exact_host_identity_and_resume_same_attempt",
                "identity_mismatch_or_second_replica": "stop_progress_and_keep_both_authorities_false",
            },
        },
        "phase_1_pre_c_c2c_external_high_water": {
            "predecessor_artifact": "verified_c2b_frozen_bootstrap_activation_head_v2_with_served_proof_closure",
            "commit_point": "external_append_compare_and_swap_readback_bound_to_exact_c2b_head_v2",
            "recovery_query": "query_deterministic_activation_head_idempotency_key_then_compare_local_equal_behind_or_fork",
            "retry_identity": "activation_head_derived_idempotency_key",
            "crash_states": {
                "remote_absent_local_pending": "retry_same_idempotency_key",
                "remote_equal_local_uncommitted": "readback_then_commit_local_projection",
                "remote_ahead": "whole_volume_rollback_fail_closed",
                "remote_fork_or_local_ahead": "integrity_failure_fail_closed",
                "external_unavailable": "remain_frozen",
            },
        },
        "phase_1_pre_d_d1_target_runtime_identity": {
            "predecessor_artifact": "verified_c2c_external_high_water_record",
            "commit_point": "host_observer_compare_and_swap_lease_receipt",
            "recovery_query": "host_observer_query_exact_lease_generation_and_target_identity",
            "retry_identity": "target_runtime_identity_and_lease_generation",
            "crash_states": {
                "lease_created_local_receipt_absent": "query_exact_lease_generation",
                "container_replaced_or_dual_replica": "invalidate_lease_and_fail_closed",
                "lease_expired_or_renew_failed": "restart_d1_with_fresh_attestation",
            },
        },
        "phase_1_pre_d_d2_windows_durable_token_transfer": {
            "predecessor_artifact": "verified_d1_target_lease_receipt",
            "commit_point": "windows_create_only_staged_token_receipt_with_final_admission_still_rejecting_token",
            "recovery_query": "query_same_staging_id_and_external_record_after_unknown_response",
            "retry_identity": "deterministic_staging_id",
            "crash_states": {
                "before_windows_staging_commit": "retry_same_staging_id_while_lease_valid",
                "after_windows_staging_commit_before_linux_or_external_record": "query_same_staging_id_and_resume_evidence_only",
                "lease_expired_or_container_changed": "staged_token_remains_rejected_and_restart_d1",
                "windows_restart": "durable_staged_token_remains_rejected",
            },
        },
        "phase_1_pre_d_d3_atomic_capability_commit": {
            "predecessor_artifact": "verified_d2_staged_token_and_external_high_water_record",
            "commit_point": "single_windows_compare_and_swap_permanently_revokes_old_token_and_activates_staged_target_token_bound_to_exact_durable_conditional_authority_grant_receipt",
            "recovery_query": "query_exact_activation_id_then_derive_local_projection_from_windows_commit_receipt",
            "retry_identity": "deterministic_activation_id",
            "crash_states": {
                "conditional_grant_durable_before_windows_commit": "grant_inert_and_staged_token_rejected",
                "windows_commit_unknown": "query_same_activation_id_no_new_token_or_grant",
                "windows_committed_external_absent": "append_same_activation_record_then_exact_readback_before_local_projection",
                "windows_committed_external_equal_local_projection_absent": "readback_then_rebuild_projection_from_exact_receipt_and_post_proofs",
                "windows_committed_external_ahead_or_fork": "fail_closed_and_require_operator_integrity_recovery",
                "post_commit_identity_mismatch": "halt_new_orders_and_require_new_reconciliation",
            },
        },
        "phase_1_pre_d_d4_deployment_gate_restore": {
            "predecessor_artifact": "verified_d3_capability_commit_or_non_restoring_mode_closure",
            "commit_point": "durable_deployment_gate_receipt_after_fresh_read_only_acceptance",
            "recovery_query": "query_exact_deployment_gate_receipt",
            "retry_identity": "deterministic_deployment_gate_receipt_id",
            "crash_states": {
                "before_gate_receipt": "deploy_remains_blocked",
                "after_gate_receipt_before_local_projection": "readback_exact_receipt_then_project",
                "identity_or_evidence_changed": "invalidate_gate_and_restart_frozen_cycle",
            },
        },
    }
    for stage_id, exact in expected.items():
        assert {field: stages[stage_id][field] for field in exact} == exact


def test_legacy_restart_cross_contract_ownership_and_leases_are_explicit() -> None:
    ownership = json.loads(
        (ROOT / "docs/architecture/web-bridge-deployment-ownership-v1.json").read_text(
            encoding="utf-8"
        )
    )
    migration = ownership["legacy_restart_migration_ownership"]
    assert set(migration) == {
        "status",
        "external_high_water",
        "host_target_observer",
        "frozen_bootstrap_coordinator",
        "baseline_target_manifest",
        "windows_fencing_token_store",
        "conditional_authority_grant",
    }
    for owner_id, contract in migration.items():
        if owner_id == "status":
            continue
        assert set(contract) == {
            "unique_writer",
            "credential_domain",
            "durable_store",
            "network_capability",
            "release_responsibility",
            "rollback_responsibility",
        }
        assert all(contract.values())

    stages = {
        stage["id"]: stage
        for stage in MANIFEST["legacy_restart_migration_contract"][
            "ordered_remaining_stages"
        ]
    }
    d1 = stages["phase_1_pre_d_d1_target_runtime_identity"]
    d2 = stages["phase_1_pre_d_d2_windows_durable_token_transfer"]
    d3 = stages["phase_1_pre_d_d3_atomic_capability_commit"]
    assert d1["lease_must_be_valid_through"]
    assert d2["lease_must_be_valid_through"]
    assert d3["lease_must_be_valid_through"]
    assert (
        "compare_and_swap_consume_or_renew_same_unexpired_target_lease"
        in d2["requires"]
    )
    assert (
        "compare_and_swap_consume_or_renew_same_unexpired_target_lease"
        in d3["requires"]
    )
    assert migration["external_high_water"]["release_responsibility"] == (
        "phase_1_pre_web-bridge-unique-commodity-owner-submits_then_phase_2_"
        "execution-orchestrator-after-explicit-owner-migration_external-witness-commits"
    )
    assert migration["frozen_bootstrap_coordinator"]["unique_writer"] == (
        "m2-bootstrap-coordinator"
    )


def test_every_tracked_path_has_a_reviewed_rule() -> None:
    tracked = (
        subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        .stdout.decode("utf-8")
        .split("\0")
    )
    uncovered = sorted(
        path for path in tracked if path and not _matching_rule_ids(path)
    )
    assert uncovered == []


def test_every_tracked_path_has_one_deterministic_effective_rule() -> None:
    tracked = (
        subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        .stdout.decode("utf-8")
        .split("\0")
    )
    ambiguous = {
        path: [rule["id"] for rule in selected]
        for path in tracked
        if path and len(selected := _selected_rules(path)) != 1
    }
    assert ambiguous == {}


def test_rule_references_and_future_units_cannot_authorize_deployment() -> None:
    classifications = set(MANIFEST["classifications"])
    build_units = {unit["id"]: unit for unit in MANIFEST["build_units"]}
    deploy_units = {unit["id"]: unit for unit in MANIFEST["deploy_units"]}

    for rule in MANIFEST["path_rules"]:
        assert rule["classification"] in classifications
        assert rule["deploy_units"] == []
        for unit_id in rule["build_units"]:
            if unit_id.startswith("closure_derived_"):
                continue
            assert unit_id in build_units

    assert deploy_units
    assert all(not unit["automatic_deploy_allowed"] for unit in deploy_units.values())
    assert all(not unit["automatic_deploy_allowed"] for unit in build_units.values())
    assert all(
        unit["implementation_status"].startswith("planned_")
        for unit in build_units.values()
        if unit["build_file"].startswith("future:")
    )


def test_high_risk_paths_resolve_to_conservative_rules() -> None:
    assert "release-workflows" in _matching_rule_ids(".github/workflows/cd.yml")
    assert "deployment-topology" in _matching_rule_ids(
        "deployments/docker-compose.prod.yml"
    )
    assert "execution-source" in _matching_rule_ids(
        "backend/app/services/trade_service.py"
    )
    assert "runtime-json-schemas" in _matching_rule_ids(
        "docs/schemas/web-bridge-release-plan-v1.schema.json"
    )
    assert "scripts-runtime" in _matching_rule_ids(
        "scripts/commodity_simnow_shakedown.py"
    )
    expected = {
        ".github/workflows/cd.yml": ("release-workflows", "infra_manual"),
        ".dockerignore": ("root-dockerignore-contract", "infra_manual"),
        "frontend/src/App.tsx": ("frontend-source", "build_only"),
        "backend/app/services/trade_service.py": (
            "execution-source",
            "infra_manual",
        ),
        "backend/app/services/deployment_reconciliation_activation.py": (
            "execution-source",
            "infra_manual",
        ),
        "backend/app/services/commodity_c_fast_runtime_authorization.py": (
            "execution-source",
            "infra_manual",
        ),
        "scripts/c_fast_t1/Containerfile.query-v5": (
            "c-fast-containerfiles",
            "build_only",
        ),
        "docs/schemas/web-bridge-release-plan-v1.schema.json": (
            "runtime-json-schemas",
            "build_only",
        ),
    }
    for path, result in expected.items():
        selected = _selected_rules(path)
        assert [(selected[0]["id"], selected[0]["classification"])] == [result]


def test_joint_dependency_references_and_rule_ids_are_valid() -> None:
    rule_ids = [rule["id"] for rule in MANIFEST["path_rules"]]
    joint_ids = {item["id"] for item in MANIFEST["joint_dependencies"]}
    build_ids = {item["id"] for item in MANIFEST["build_units"]}
    resolver_tokens = set(MANIFEST["classification_contract"]["resolver_tokens"])

    assert len(rule_ids) == len(set(rule_ids))
    for rule in MANIFEST["path_rules"]:
        if reference := rule.get("joint_dependency"):
            assert reference in joint_ids
        for field in ("build_units", "pre_activation_build_units"):
            for unit in rule.get(field, []):
                assert unit in build_ids or unit in resolver_tokens


def _identity(*, container_hex: str, started_at: str, pid: int) -> dict[str, object]:
    return {
        "present": True,
        "version": "v1",
        "image_digest": IMAGE_DIGEST,
        "config_sha256": EVIDENCE_SHA256,
        "container_id": container_hex * 64,
        "pid": pid,
        "started_at": started_at,
        "restart_count": 0,
        "runtime_generation": 1,
        "state_sha256": EVIDENCE_SHA256,
    }


def _deployment_evidence() -> dict[str, object]:
    return {
        "schema_version": "web_bridge_deployment_evidence_v1",
        "purpose": "deployment_identity_and_safety_evidence",
        "issue_number": 267,
        "evidence_id": f"deployment-evidence-{EVIDENCE_SHA256}",
        "captured_at": "2026-08-04T00:00:00Z",
        "source_commit_sha": SOURCE_COMMIT,
        "release_plan_raw_sha256": EVIDENCE_SHA256,
        "release_plan_canonical_sha256": EVIDENCE_SHA256,
        "release_plan_schema_sha256": EVIDENCE_SHA256,
        "evidence_schema_sha256": EVIDENCE_SHA256,
        "schema_compatibility_verified": False,
        "release_plan_units_sha256": EVIDENCE_SHA256,
        "evidenced_units_sha256": EVIDENCE_SHA256,
        "unit_set_match_verified": False,
        "services": [
            {
                "unit": "frontend",
                "planned_action": "restart",
                "plan_action_sha256": EVIDENCE_SHA256,
                "before": _identity(
                    container_hex="c",
                    started_at="2026-08-04T00:00:00Z",
                    pid=1,
                ),
                "after": _identity(
                    container_hex="d",
                    started_at="2026-08-04T00:01:00Z",
                    pid=2,
                ),
                "identity_unchanged": False,
                "identity_transition_verified": False,
                "restart_observed": True,
                "health_verified": False,
                "readiness_verified": False,
                "version_verified": False,
                "config_verified": False,
                "schema_compatibility_verified": False,
                "safe_restart_receipt_sha256": None,
                "evidence_sha256": EVIDENCE_SHA256,
            }
        ],
        "safe_restart_receipt_sha256": [],
        "outcome": "FAILED",
        "orders_sent": 0,
        "positions_modified": 0,
        "production_allowed": False,
        "live_trading_authorized": False,
        "blockers": [
            {
                "unit": "frontend",
                "code": "health_failed",
                "reason": "health verification failed",
                "evidence_sha256": EVIDENCE_SHA256,
                "manual_override_allowed": False,
            }
        ],
        "redaction": {
            "sanitized": True,
            "redaction_verified": True,
            "contains_private_key": False,
            "contains_secret": False,
            "contains_token": False,
            "contains_account_id": False,
            "contains_private_path": False,
            "redaction_policy_sha256": EVIDENCE_SHA256,
        },
    }


def test_successful_deployment_requires_every_verification() -> None:
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    evidence = _deployment_evidence()
    assert not list(validator.iter_errors(evidence))

    evidence["outcome"] = "SUCCEEDED"
    evidence["blockers"] = []
    assert list(validator.iter_errors(evidence))

    evidence["schema_compatibility_verified"] = True
    evidence["unit_set_match_verified"] = True
    service = evidence["services"][0]
    service["identity_transition_verified"] = True

    for field in (
        "health_verified",
        "readiness_verified",
        "version_verified",
        "config_verified",
        "schema_compatibility_verified",
    ):
        service[field] = True
    assert not list(validator.iter_errors(evidence))


def test_blocked_deployment_can_record_pre_action_failure() -> None:
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    evidence = _deployment_evidence()
    evidence.update(outcome="BLOCKED", services=[])
    assert not list(validator.iter_errors(evidence))

    evidence["evidence_id"] = f"deployment-evidence-{'0' * 64}"
    assert list(validator.iter_errors(evidence))


def test_failed_deployment_can_record_disappeared_runtime() -> None:
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    evidence = _deployment_evidence()
    evidence["services"][0]["after"] = {
        "present": False,
        "observed_at": "2026-08-04T00:01:00Z",
        "reason": "crashed",
        "evidence_sha256": EVIDENCE_SHA256,
    }
    assert not list(validator.iter_errors(evidence))

    evidence["outcome"] = "SUCCEEDED"
    evidence["blockers"] = []
    evidence["schema_compatibility_verified"] = True
    evidence["unit_set_match_verified"] = True
    service = evidence["services"][0]
    for field in (
        "identity_transition_verified",
        "health_verified",
        "readiness_verified",
        "version_verified",
        "config_verified",
        "schema_compatibility_verified",
    ):
        service[field] = True
    assert list(validator.iter_errors(evidence))


def test_successful_create_records_absent_before_and_present_after() -> None:
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    evidence = _deployment_evidence()
    evidence.update(
        outcome="SUCCEEDED",
        blockers=[],
        schema_compatibility_verified=True,
        unit_set_match_verified=True,
    )
    service = evidence["services"][0]
    service.update(
        planned_action="create",
        before={
            "present": False,
            "observed_at": "2026-08-04T00:00:00Z",
            "reason": "not_created",
            "evidence_sha256": EVIDENCE_SHA256,
        },
        restart_observed=False,
        identity_transition_verified=True,
        health_verified=True,
        readiness_verified=True,
        version_verified=True,
        config_verified=True,
        schema_compatibility_verified=True,
    )
    assert not list(validator.iter_errors(evidence))

    service["unit"] = "execution-orchestrator"
    assert list(validator.iter_errors(evidence))


def _release_plan() -> dict[str, object]:
    return {
        "schema_version": "web_bridge_release_plan_v1",
        "purpose": "dependency_aware_release_plan",
        "issue_number": 267,
        "plan_id": f"release-plan-{EVIDENCE_SHA256}",
        "generated_at": "2026-08-04T00:00:00Z",
        "source_commit_sha": SOURCE_COMMIT,
        "planner_version": "v1",
        "planner_image_digest": IMAGE_DIGEST,
        "planner_config_sha256": EVIDENCE_SHA256,
        "ownership_manifest_sha256": EVIDENCE_SHA256,
        "changed_files_sha256": EVIDENCE_SHA256,
        "schema_compatibility": [
            {
                "contract_id": "api-v1",
                "producer_version": "v2",
                "consumer_version": "v1",
                "schema_sha256": EVIDENCE_SHA256,
                "result": "incompatible",
                "evidence_sha256": EVIDENCE_SHA256,
            }
        ],
        "build": [],
        "create": [],
        "restart": [],
        "preserve": [],
        "block": [
            {
                "unit": "control-api",
                "code": "schema_incompatible",
                "reason": "consumer is incompatible",
                "evidence_sha256": EVIDENCE_SHA256,
                "manual_override_allowed": False,
            }
        ],
        "decision": "BLOCKED",
        "production_allowed": False,
        "live_trading_authorized": False,
    }


def test_ready_release_requires_compatible_schemas_and_matching_execution_receipt() -> (
    None
):
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-release-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    plan = _release_plan()
    assert not list(validator.iter_errors(plan))

    plan.update(decision="READY", block=[])
    assert list(validator.iter_errors(plan))
    plan["schema_compatibility"][0]["result"] = "compatible"
    assert not list(validator.iter_errors(plan))

    plan["restart"] = [
        {
            "unit": "execution-orchestrator",
            "from_version": "v1",
            "to_version": "v2",
            "from_image_digest": IMAGE_DIGEST,
            "to_image_digest": IMAGE_DIGEST,
            "from_config_sha256": EVIDENCE_SHA256,
            "to_config_sha256": EVIDENCE_SHA256,
            "safety_gate": "required_verified",
            "receipt_plan_binding_verified": True,
            "receipt_source_binding_verified": True,
            "receipt_freshness_verified": True,
            "pre_restart_recheck_verified": True,
            "receipt_verification_evidence_sha256": EVIDENCE_SHA256,
            "safe_restart_receipt": {
                "schema_version": "web_bridge_safe_restart_receipt_v1",
                "purpose": "authorize_one_bound_web_bridge_restart_attempt",
                "receipt_id": f"safe-restart-{EVIDENCE_SHA256}",
                "receipt_core_sha256": EVIDENCE_SHA256,
                "request_id": "request_00000001",
                "deployment_attempt_id": "deployment_00000001",
                "release_plan_id": f"release-plan-{EVIDENCE_SHA256}",
                "release_plan_core_sha256": EVIDENCE_SHA256,
                "restart_action_sha256": EVIDENCE_SHA256,
                "unit": "web-bridge",
                "issued_at": "2026-08-04T00:00:00Z",
                "expires_at": "2026-08-04T00:01:00Z",
                "ttl_seconds": 60,
                "drain_epoch": 1,
                "execution_epoch": 1,
                "issuer_source_commit_sha": SOURCE_COMMIT,
                "issuer_image_digest": IMAGE_DIGEST,
                "issuer_config_sha256": EVIDENCE_SHA256,
                "issuer_runtime_instance_id": "runtime_00000001",
                "target_source_commit_sha": SOURCE_COMMIT,
                "target_image_digest": IMAGE_DIGEST,
                "target_config_sha256": EVIDENCE_SHA256,
                "rollback_image_digest": IMAGE_DIGEST,
                "rollback_config_sha256": EVIDENCE_SHA256,
                "nonce": "receipt_nonce_001",
                "snapshot": {
                    "schema_version": "web_bridge_deployment_safety_snapshot_v1",
                    "captured_at": "2026-08-04T00:00:00Z",
                    "execution_plan_status": "IDLE",
                    "execution_plan_hash": None,
                    "plan_version": 1,
                    "state_version": "v1",
                    "state_sha256": EVIDENCE_SHA256,
                    "active_orders_snapshot_sha256": EVIDENCE_SHA256,
                    "positions_snapshot_sha256": EVIDENCE_SHA256,
                    "checkpoint_sha256": EVIDENCE_SHA256,
                    "rpc_generation": 1,
                    "web_trade_enabled": False,
                    "execution_authority_revoked": True,
                    "auto_dispatch_stopped": True,
                    "active_orders": 0,
                    "unknown_outcome": False,
                    "reconcile_required": False,
                    "checkpoint_durable": True,
                },
                "safe_to_restart": True,
                "one_shot": True,
                "automatic_deploy_allowed": False,
                "production_allowed": False,
                "live_trading_authorized": False,
            },
            "reason": "version update",
        }
    ]
    assert list(validator.iter_errors(plan))
    plan["restart"][0]["unit"] = "web-bridge"
    assert not list(validator.iter_errors(plan))

    plan["create"] = [
        {
            "unit": "frontend",
            "version": "v1",
            "image_digest": IMAGE_DIGEST,
            "config_sha256": EVIDENCE_SHA256,
            "before_absence_evidence_sha256": EVIDENCE_SHA256,
            "reason": "first split deployment",
        }
    ]
    assert not list(validator.iter_errors(plan))
    plan["create"][0]["unit"] = "execution-orchestrator"
    assert list(validator.iter_errors(plan))
    plan["create"] = []

    plan["source_commit_sha"] = "0" * 40
    plan["planner_config_sha256"] = "0" * 64
    assert list(validator.iter_errors(plan))


def test_safe_restart_standalone_and_embedded_contracts_stay_in_sync() -> None:
    def normalized(value: object) -> object:
        if isinstance(value, dict):
            if value == {"$ref": "#/$defs/identifier"}:
                return {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$",
                }
            value = {key: normalized(item) for key, item in value.items()}
        elif isinstance(value, list):
            value = [normalized(item) for item in value]
        encoded = json.dumps(value, sort_keys=True)
        encoded = encoded.replace("safeRestartSnapshot", "safeSnapshot")
        encoded = encoded.replace("safeRestartUtcDateTime", "dateTime")
        return json.loads(encoded)

    release = json.loads(
        (ROOT / "docs/schemas/web-bridge-release-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    receipt = json.loads(
        (
            ROOT / "docs/schemas/web-bridge-safe-restart-receipt-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    recheck = json.loads(
        (
            ROOT / "docs/schemas/web-bridge-safe-restart-recheck-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    embedded = release["$defs"]["safeRestartReceipt"]

    assert set(receipt["required"]) == set(embedded["required"])
    assert normalized(receipt["properties"]) == normalized(embedded["properties"])

    standalone_snapshot = receipt["$defs"]["safeSnapshot"]
    embedded_snapshot = release["$defs"]["safeRestartSnapshot"]
    recheck_snapshot = recheck["$defs"]["safeSnapshot"]
    assert normalized(standalone_snapshot) == normalized(embedded_snapshot)
    assert standalone_snapshot == recheck_snapshot


def _rollback_manifest() -> dict[str, object]:
    return {
        "schema_version": "web_bridge_rollback_manifest_v1",
        "purpose": "state_compatible_rollback_manifest",
        "issue_number": 267,
        "rollback_id": f"rollback-{EVIDENCE_SHA256}",
        "created_at": "2026-08-04T00:00:00Z",
        "source_commit_sha": SOURCE_COMMIT,
        "release_plan_raw_sha256": EVIDENCE_SHA256,
        "deployment_evidence_raw_sha256": EVIDENCE_SHA256,
        "rollback_schema_sha256": EVIDENCE_SHA256,
        "operator_approval_required": True,
        "automatic_rollback_allowed": False,
        "state_high_water": {
            "captured_at": "2026-08-04T00:00:00Z",
            "state_schema_version": "v1",
            "state_schema_sha256": EVIDENCE_SHA256,
            "state_snapshot_sha256": EVIDENCE_SHA256,
            "journal_sequence": 1,
            "leader_epoch": 1,
            "fencing_token": 1,
            "archive_high_water_sha256": EVIDENCE_SHA256,
            "unknown_outcome": True,
            "reconcile_required": True,
            "active_orders": 1,
        },
        "units": [
            {
                "unit": "control-api",
                "from_version": "v2",
                "to_version": "v1",
                "from_image_digest": IMAGE_DIGEST,
                "to_image_digest": IMAGE_DIGEST,
                "from_config_sha256": EVIDENCE_SHA256,
                "to_config_sha256": EVIDENCE_SHA256,
                "state_schema_version": "v2",
                "target_readable_state_versions": ["v1"],
                "state_version_readable_verified": False,
                "compatibility": "unknown",
                "compatibility_evidence_sha256": EVIDENCE_SHA256,
                "safe_restart_receipt_sha256": None,
                "safe_restart_receipt_freshness_verified": False,
                "safe_restart_receipt_state_binding_verified": False,
                "fencing_verified": False,
                "action": "hold",
            }
        ],
        "compatibility_verified": False,
        "safe_to_rollback": False,
        "decision": "BLOCKED",
        "blockers": [
            {
                "unit": "control-api",
                "code": "active_orders",
                "reason": "unsafe high-water state",
                "evidence_sha256": EVIDENCE_SHA256,
                "manual_override_allowed": False,
            }
        ],
        "production_allowed": False,
        "live_trading_authorized": False,
    }


def test_rollback_records_unsafe_state_but_ready_requires_safe_compatibility() -> None:
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-rollback-manifest-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    manifest = _rollback_manifest()
    assert not list(validator.iter_errors(manifest))

    manifest["rollback_id"] = f"rollback-{'0' * 64}"
    assert list(validator.iter_errors(manifest))
    manifest["rollback_id"] = f"rollback-{EVIDENCE_SHA256}"

    manifest.update(
        compatibility_verified=True,
        safe_to_rollback=True,
        decision="READY",
        blockers=[],
    )
    assert list(validator.iter_errors(manifest))

    manifest["state_high_water"].update(
        unknown_outcome=False,
        reconcile_required=False,
        active_orders=0,
    )
    manifest["units"][0].update(
        compatibility="compatible",
        action="rollback",
        state_version_readable_verified=True,
        fencing_verified=True,
    )
    assert not list(validator.iter_errors(manifest))
