"""Actual Engine/Critic/Memory/ResultStore structures, zero live Provider."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

from research_lab.agent_control.alpha_generator import admit_alpha_generation_output
from scripts.issue502_feedback_lineage import verify_r1_scientific_lineage

spec = importlib.util.spec_from_file_location("recovery_helpers", Path(__file__).with_name("test_trusted_round_recovery.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
h = recovery.helper


@pytest.fixture
def chain(tmp_path, request):
    context = h.discovery_context.__wrapped__(tmp_path / "store")
    scope = h.authorized_scope.__wrapped__()
    view = h._build_test_memory_view(context["memory"], scope)
    session = h.DiscoverySession.create(objective="Offline lineage contract, never scientific acceptance",
        memory_view=view, authorized_scope=scope, candidate_budget=2, allowed_universe=("RB2405",),
        allowed_frequency="1d", project_binding=h.STANDARD_PROJECT_BINDING)
    slots = h.plan_candidate_slots(session, view)
    auto_supplemental, count = getattr(request, "param", (False, 1))
    integrations = []
    for index, slot in enumerate(slots[:count]):
        envelope = h._build_candidate_envelope(signal_definition=f"positive rolling return over {5 + index} bars on RB2405")
        envelope["hypothesis"]["proposed_screening_methods"] = ["coverage", "simple_correlation", "direction_consistency", "leakage_audit"]
        candidate = admit_alpha_generation_output(json.dumps(envelope), request=slot.request, memory_view=view,
            task_id=slot.task.task_id, provider="contract_test_provider", actual_model="fixture", created_at=h.NOW)
        result = context["orchestrator"].integrate_candidate(candidate, snapshot_path=context["clean_csv"],
            dataset_binding=context["clean_binding"], project_binding=h.STANDARD_PROJECT_BINDING,
            expected_binding=h.STANDARD_PROJECT_BINDING, auto_supplemental=auto_supplemental)
        assert result.engineering_status == "COMPLETED"
        integrations.append(recovery.integration_payload(result))
    return context, {"integrations": integrations}


@pytest.mark.parametrize("chain", [(False, 2), (True, 2)], indirect=True)
def test_real_structures_verify_all_memory_and_receipts_readonly(chain):
    context, evidence = chain
    database = context["memory"].db_path
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    verify_r1_scientific_lineage(evidence, context["memory"].as_readonly_reader(), context["store"])
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    assert len(context["memory"].get_all_records()) >= 2


@pytest.mark.parametrize("field", ["hypothesis_id", "hypothesis_content_hash", "scientific_identity_hash",
                                    "plan_id", "plan_content_hash", "memory_record_id", "scientific_decision"])
def test_summary_identity_cannot_replace_memory_identity(chain, field):
    context, evidence = chain
    changed = deepcopy(evidence)
    changed["integrations"][0][field] = "unrelated"
    with pytest.raises(ValueError, match="mismatch"):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])


@pytest.mark.parametrize("kind", ["task", "spec", "run", "manifest", "evidence"])
def test_summary_cannot_omit_or_change_reference_hash(chain, kind):
    context, evidence = chain
    changed = deepcopy(evidence)
    changed["integrations"][0][f"{kind}_refs"][0]["content_hash"] = "0" * 64
    with pytest.raises(ValueError, match="mismatched integration"):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])


def test_receipt_deleted_and_omitted_from_summary_still_rejected(chain):
    context, evidence = chain
    changed = deepcopy(evidence)
    missing = changed["integrations"][0]["run_refs"].pop()
    with sqlite3.connect(context["memory"].db_path) as db:
        db.execute("DELETE FROM v2_result_runs WHERE run_id = ?", (missing["run_id"],))
    with pytest.raises(ValueError, match="incomplete/mismatched"):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])


@pytest.mark.parametrize("chain", [(False, 2)], indirect=True)
def test_omitted_entire_integration_detected_from_all_memory(chain):
    context, evidence = chain
    changed = deepcopy(evidence)
    changed["integrations"].pop()
    with pytest.raises(ValueError, match="omitted"):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])


def test_memory_run_hash_tamper_detected_against_real_verified_receipt(chain):
    context, evidence = chain
    changed = deepcopy(evidence)
    record = changed["integrations"][0]["memory_records"][0]
    record["run_refs"][0]["content_hash"] = "0" * 64
    changed["integrations"][0]["run_refs"][0]["content_hash"] = "0" * 64
    with sqlite3.connect(context["memory"].db_path) as db:
        db.execute("UPDATE research_memory_records SET run_refs_json = ? WHERE record_id = ?",
                   (json.dumps(record["run_refs"]), record["record_id"]))
    with pytest.raises(ValueError, match="receipt run identity/hash mismatch"):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])


def test_missing_receipt_for_declared_memory_ref_rejected(chain):
    context, evidence = chain
    run_id = evidence["integrations"][0]["run_refs"][0]["run_id"]
    with sqlite3.connect(context["memory"].db_path) as db:
        db.execute("DELETE FROM v2_result_runs WHERE run_id = ?", (run_id,))
    with pytest.raises(ValueError, match="receipt missing"):
        verify_r1_scientific_lineage(evidence, context["memory"].as_readonly_reader(), context["store"])


def persist_memory_copies(context, evidence):
    """Change only disposable fixture Memory; original sealed receipts stay intact."""
    with sqlite3.connect(context["memory"].db_path) as db:
        for integration in evidence["integrations"]:
            for record in integration["memory_records"]:
                fields = {"plan_payload": record["plan_payload"],
                          "critic_decision_payload": record["critic_decision_payload"],
                          "critic_ref_json": record["critic_ref"]}
                fields.update({f"{kind}_refs_json": record[f"{kind}_refs"] for kind in ("task", "spec", "run", "manifest", "evidence")})
                for column, value in fields.items():
                    db.execute(f"UPDATE research_memory_records SET {column} = ? WHERE record_id = ?",
                               (json.dumps(value), record["record_id"]))


@pytest.mark.parametrize("chain", [(True, 1)], indirect=True)
@pytest.mark.parametrize("record_index", [0, 1])
@pytest.mark.parametrize("tamper", ["plan_body", "critic_body", "critic_ref"])
def test_existing_seals_and_critic_ref_checked_for_each_cycle_record(chain, record_index, tamper):
    context, evidence = chain
    changed = deepcopy(evidence)
    integration = changed["integrations"][0]
    assert len(integration["memory_records"]) == 2  # actual baseline + supplemental
    record = integration["memory_records"][record_index]
    if tamper == "plan_body":
        record["plan_payload"]["methods"][0]["parameters"]["changed_without_reseal"] = True
        expected = "plan_content_hash mismatch"
    elif tamper == "critic_body":
        record["critic_decision_payload"]["criteria"]["min_coverage"] = "0.7"
        if record_index == 1:
            integration["critic_decision"] = deepcopy(record["critic_decision_payload"])
        expected = "review_content_hash mismatch"
    else:
        record["critic_ref"]["decision_id"] = "different-decision"
        expected = "critic_ref mismatch"
    persist_memory_copies(context, changed)
    with pytest.raises(ValueError, match=expected):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])


@pytest.mark.parametrize("chain", [(False, 2)], indirect=True)
def test_valid_receipts_cannot_be_cross_wired_between_candidates(chain):
    context, evidence = chain
    changed = deepcopy(evidence)
    first, second = changed["integrations"]
    for kind in ("task", "spec", "run", "manifest", "evidence"):
        key = f"{kind}_refs"
        first[key], second[key] = second[key], first[key]
        first["memory_records"][0][key], second["memory_records"][0][key] = (
            second["memory_records"][0][key], first["memory_records"][0][key])
    persist_memory_copies(context, changed)
    with pytest.raises(ValueError, match="Evidence ID mismatch"):
        verify_r1_scientific_lineage(changed, context["memory"].as_readonly_reader(), context["store"])
