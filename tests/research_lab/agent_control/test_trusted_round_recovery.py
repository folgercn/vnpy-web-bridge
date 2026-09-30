"""Execute both actual runner hooks through the real two-slot batch path."""
import ast
import importlib.util
import json
from pathlib import Path
import time
from typing import Any

import pytest

from research_lab.agent_control.contracts import AgentExecutionHandle, AgentResult
from research_lab.agent_control.errors import ProviderError, ProviderErrorCode
from research_lab.alpha_discovery import ResearchMemory
from research_lab.config import ResearchLabConfig
from research_lab.database import ResultStore
from scripts.issue502_trusted_runtime import verify_r1_feedback_view

spec = importlib.util.spec_from_file_location("batch_helpers", Path(__file__).with_name("test_agent_control_batch_discovery.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


@pytest.mark.parametrize("round_no", [1, 2])
@pytest.mark.parametrize("failure", ["submit_uncertain", "handle_disk_full", "result_uncertain"])
def test_exact_hooks_stop_second_slot_on_ambiguous_outcome(tmp_path, round_no, failure):
    memory = ResearchMemory(ResultStore(ResearchLabConfig(tmp_path / "store")))
    provider = helper.test_provider.__wrapped__()
    registry = helper.provider_registry.__wrapped__(provider)
    scope = helper.authorized_scope.__wrapped__()
    policy = helper.routing_policy.__wrapped__()
    helper.configure_provider_output(provider, "intentionally invalid candidate")
    view = helper._build_test_memory_view(memory, scope)
    session = helper.DiscoverySession.create(objective="Recovery regression, zero real Provider",
        memory_view=view, authorized_scope=scope, candidate_budget=2, allowed_universe=("RB2405",),
        allowed_frequency="1d", project_binding=helper.STANDARD_PROJECT_BINDING)
    slots = helper.plan_candidate_slots(session, view)
    calls = []
    halted = {"halted": False, "reason": None}
    original = provider.submit

    def submit(task, route, preparation, request_id=None):
        calls.append(task.task_id)
        if failure == "submit_uncertain":
            raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN, "accepted remotely, reply lost")
        return original(task, route, preparation, request_id=request_id)

    def dump(path, data):
        if failure == "handle_disk_full" and data.get("state") == "HANDLE_RECEIVED":
            raise OSError("ENOSPC after accepted submission")
        path.write_text(json.dumps(data))

    def result_call(op, args):
        assert op == "result"
        raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN, "first result reply lost")

    runner = Path(__file__).parents[3] / "scripts" / f"run_stage2_universal_round{round_no}_real.py"
    tree = ast.parse(runner.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    hooks = [node for node in main.body if isinstance(node, ast.FunctionDef) and node.name in {"hooked_submit", "hooked_result"}]
    env = {"Any": Any, "AgentExecutionHandle": AgentExecutionHandle, "AgentResult": AgentResult,
           "uncertain_halt_state": halted, "ProviderError": ProviderError, "ProviderErrorCode": ProviderErrorCode,
           "slot_by_task_id": {s.task.task_id: s for s in slots}, "time": time, "orig_submit": submit,
           "captured_by_task_id": {}, "get_realtime_utc": lambda: helper.NOW, "_dump_json": dump,
           "provider_raw_dir": tmp_path, "tool_caller": result_call}
    exec(compile(ast.Module(body=hooks, type_ignores=[]), str(runner), "exec"), env)
    provider.submit = env["hooked_submit"]
    if failure == "result_uncertain":
        provider.result = env["hooked_result"]
    batch = helper.DiscoveryBatchOrchestrator(registry=registry, routing_policy=policy, memory_store=memory)
    result = batch.execute_session(session, view, created_at=helper.NOW, stop_on_quota=True)
    assert halted["halted"]
    assert len(calls) == 1
    assert result.slots[0].engineering_status == "PROVIDER_UNCERTAIN"
    assert result.slots[1].engineering_status == "NOT_ATTEMPTED"
    assert result.slots[1].error_code == "BATCH_PROVIDER_UNCERTAIN"
    assert not memory.get_all_records()
    ownership = json.loads((tmp_path / "submission_01.json").read_text())
    assert ownership["request_id"] == slots[0].request.request_id
    if failure == "handle_disk_full":
        assert result.slots[0].provider_job_ref
        assert env["captured_by_task_id"][calls[0]]["handle"]


def test_feedback_view_is_this_r1_snapshot_and_receipts(tmp_path):
    memory = ResearchMemory(ResultStore(ResearchLabConfig(tmp_path / "store")))
    scope = helper.authorized_scope.__wrapped__()
    view = helper._build_test_memory_view(memory, scope)
    snapshot = view.to_dict()
    evidence = {"round": 1, "funnel": {"requested": 10}, "slots": [{"ordinal": i} for i in range(1, 11)], "post_r1_memory_view": {"view_id": view.view_id, "content_hash": view.view_content_hash,
                                       "total_entries": view.total_entries},
                "integrations": [{"engineering_status": "COMPLETED", "run_refs": [{"run_id": "fixture-run"}]}]}
    class ReceiptStore:
        def query_v2_runs(self, *, run_id, verify):
            assert run_id == "fixture-run" and verify is True
            return [{"fixture": True}]
    verify_r1_feedback_view(view, snapshot, evidence, ReceiptStore())
    with pytest.raises(ValueError, match="snapshot"):
        verify_r1_feedback_view(view, {**snapshot, "view_id": "historical-view"}, evidence, ReceiptStore())
    with pytest.raises(ValueError, match="disagree"):
        verify_r1_feedback_view(view, snapshot, {**evidence, "post_r1_memory_view": {"total_entries": 23}}, ReceiptStore())
    class MissingStore:
        def query_v2_runs(self, **kwargs):
            return []
    with pytest.raises(ValueError, match="receipt"):
        verify_r1_feedback_view(view, snapshot, evidence, MissingStore())


def test_round2_actual_main_binds_fresh_r1_view_before_provider(tmp_path, monkeypatch):
    """A local contract fixture reaches the Provider boundary; never real acceptance."""
    import hashlib
    import sys
    from scripts import run_stage2_universal_round2_real as runner
    from scripts.issue502_trusted_runtime import bind_run_root
    from research_lab.agent_control.alpha_generator import admit_alpha_generation_output
    from research_lab.agent_control.contracts import ProjectBinding
    from research_lab.agent_control.memory_view import ResearchMemoryCategory, ResearchMemoryQuery, build_research_memory_view
    from research_lab.agent_control.router import authorize

    run_root = tmp_path / "runs" / "fixture-r1"
    r1 = run_root / "round_1"
    r1.mkdir(parents=True)
    context = helper.discovery_context.__wrapped__(r1 / "store")
    pb = ProjectBinding(project_id=runner.EXPECTED_PROJECT_ID, workspace_identity=str(runner.REPO), binding_mode="strict")
    scope = authorize("alpha_generator", ["read_research_memory", "create_hypothesis"], pb)
    categories = (ResearchMemoryCategory.RESEARCH_GAPS.value, ResearchMemoryCategory.NME_BACKLOG.value,
                  ResearchMemoryCategory.FAILED_APPROACHES.value, ResearchMemoryCategory.RECENT_REJECTS.value,
                  ResearchMemoryCategory.PROMOTED_SUMMARIES.value, ResearchMemoryCategory.DUPLICATE_IDENTITIES.value)
    query = ResearchMemoryQuery(role="alpha_generator", project_binding=pb, categories=categories,
                               limit_per_category=10, total_limit=50)
    view_a = build_research_memory_view(query=query, authorized_scope=scope, project_binding=pb,
                                      memory_store=context["memory"], current_time=helper.NOW)
    objective = runner.build_universal_stage2_objective()
    session = helper.DiscoverySession.create(objective=objective, memory_view=view_a, authorized_scope=scope,
        candidate_budget=10, allowed_universe=("RB2405",), allowed_frequency="1d", project_binding=pb)
    slot = helper.plan_candidate_slots(session, view_a)[0]
    envelope = helper._build_candidate_envelope()
    envelope["hypothesis"]["proposed_screening_methods"] = ["coverage", "simple_correlation", "direction_consistency", "leakage_audit"]
    candidate = admit_alpha_generation_output(json.dumps(envelope), request=slot.request, memory_view=view_a,
        task_id=slot.task.task_id, provider="contract_test_provider", actual_model="fixture", created_at=helper.NOW)
    result = context["orchestrator"].integrate_candidate(candidate, snapshot_path=context["clean_csv"],
        dataset_binding=context["clean_binding"], project_binding=pb, expected_binding=pb, auto_supplemental=False)
    assert result.engineering_status == "COMPLETED"
    view_b = build_research_memory_view(query=query, authorized_scope=scope, project_binding=pb,
        memory_store=context["memory"], current_time=runner.get_realtime_utc())
    runner.verify_memory_b_gaps_fail_closed(view_b)
    runner._dump_json(r1 / "memory_view_after_round_1.json", {"view": view_b.to_dict()})
    runner._dump_json(r1 / "ROUND1_FULL_EVIDENCE.json", {
        "round": 1, "objective": objective, "objective_sha256": hashlib.sha256(objective.encode()).hexdigest(),
        "funnel": {"requested": 10}, "slots": [{"ordinal": i} for i in range(1, 11)],
        "post_r1_memory_view": {"view_id": view_b.view_id, "content_hash": view_b.view_content_hash, "total_entries": view_b.total_entries},
        "integrations": [{"engineering_status": result.engineering_status, "run_refs": list(result.run_refs)}]})
    source = tmp_path / "source"
    source.mkdir()
    provenance = source / "snapshot-provenance.json"
    provenance.write_text(json.dumps({"source_days": [{}] * 19}))
    csv = source / "unused-source.csv"
    csv.write_text("fixture; never real-source acceptance")
    inputs = {"provenance": provenance, "base_csv": csv, "output": tmp_path / "runs", "binding": {"fixture": True}}
    bind_run_root(run_root, inputs, runner.REPO, create=True)
    monkeypatch.setattr(runner, "trusted_inputs", lambda *args: inputs)
    monkeypatch.setattr(runner, "EXPECTED_PROVENANCE_SHA256", hashlib.sha256(provenance.read_bytes()).hexdigest())
    calls = []
    def provider_boundary(*args):
        calls.append("provider boundary")
        raise RuntimeError("provider boundary reached; no submission authorized by test")
    monkeypatch.setattr(runner, "make_transport", provider_boundary)
    monkeypatch.setattr(sys, "argv", ["r2", "--run-id", "fixture-r1", "--evidence-root", str(source),
        "--output-root", str(tmp_path / "runs"), "--mcp-command", '["DO-NOT-EXECUTE", "--transport", "stdio"]'])
    original_sha = hashlib.sha256((r1 / "store/research_lab.sqlite3").read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="provider boundary reached"):
        runner.main()
    assert calls == ["provider boundary"]
    assert hashlib.sha256((r1 / "store/research_lab.sqlite3").read_bytes()).hexdigest() == original_sha


def test_atomic_ownership_write_preserves_intent_on_fsync_failure(tmp_path, monkeypatch):
    from scripts import issue502_trusted_runtime as runtime
    path = tmp_path / "submission.json"
    runtime.write_json_atomic(path, {"state": "SUBMIT_INTENT", "request_id": "owned"})
    original = path.read_bytes()
    def disk_full(fd):
        raise OSError("ENOSPC")
    monkeypatch.setattr(runtime.os, "fsync", disk_full)
    with pytest.raises(OSError, match="ENOSPC"):
        runtime.write_json_atomic(path, {"state": "HANDLE_RECEIVED", "job_id": "accepted"})
    assert path.read_bytes() == original
    assert not path.with_suffix(".json.tmp").exists()
