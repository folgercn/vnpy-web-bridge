from __future__ import annotations

import fnmatch
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = (
    ROOT / "docs/architecture/web-bridge-release-dependencies-v1.json"
)
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
                fnmatch.fnmatchcase(path, pattern)
                for pattern in match.get("glob", [])
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
        "phase_1_pre_c_c1c_clean_legacy_migration_baseline_contract_deploy_frozen"
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


def test_every_tracked_path_has_a_reviewed_rule() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8").split("\0")
    uncovered = sorted(path for path in tracked if path and not _matching_rule_ids(path))
    assert uncovered == []


def test_every_tracked_path_has_one_deterministic_effective_rule() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8").split("\0")
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
    resolver_tokens = set(
        MANIFEST["classification_contract"]["resolver_tokens"]
    )

    assert len(rule_ids) == len(set(rule_ids))
    for rule in MANIFEST["path_rules"]:
        if reference := rule.get("joint_dependency"):
            assert reference in joint_ids
        for field in ("build_units", "pre_activation_build_units"):
            for unit in rule.get(field, []):
                assert unit in build_ids or unit in resolver_tokens


def _identity(
    *, container_hex: str, started_at: str, pid: int
) -> dict[str, object]:
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
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json")
        .read_text(encoding="utf-8")
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
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    evidence = _deployment_evidence()
    evidence.update(outcome="BLOCKED", services=[])
    assert not list(validator.iter_errors(evidence))

    evidence["evidence_id"] = f"deployment-evidence-{'0' * 64}"
    assert list(validator.iter_errors(evidence))


def test_failed_deployment_can_record_disappeared_runtime() -> None:
    schema = json.loads(
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json")
        .read_text(encoding="utf-8")
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
        (ROOT / "docs/schemas/web-bridge-deployment-evidence-v1.schema.json")
        .read_text(encoding="utf-8")
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


def test_ready_release_requires_compatible_schemas_and_matching_execution_receipt() -> None:
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
            ROOT
            / "docs/schemas/web-bridge-safe-restart-receipt-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    recheck = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-safe-restart-recheck-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    embedded = release["$defs"]["safeRestartReceipt"]

    assert set(receipt["required"]) == set(embedded["required"])
    assert normalized(receipt["properties"]) == normalized(
        embedded["properties"]
    )

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
        (ROOT / "docs/schemas/web-bridge-rollback-manifest-v1.schema.json")
        .read_text(encoding="utf-8")
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
