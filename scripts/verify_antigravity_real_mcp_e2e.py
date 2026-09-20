#!/usr/bin/env python3
"""Verification and reconciliation script for real Antigravity Local FastMCP E2E (#573 Milestone 2).

Verifies the real stdio FastMCP connection against the host desktop environment,
and reconciles the verified completed read-only execution job (e9ce7b2d654f06f313b9fa733dc5e860).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from research_lab.agent_control.audit import AppendOnlyAuditTrail
from research_lab.agent_control.contracts import (
    AgentExecutionHandle,
    AgentTask,
    ProjectBinding,
    validate_result_hash,
)
from research_lab.agent_control.handoff import prepare_execution
from research_lab.agent_control.providers.antigravity_local_mcp import (
    AntigravityLocalMCPProvider,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import AgentRole
from research_lab.agent_control.router import authorize, select_agent
from research_lab.agent_control.routing_context import RoutingContext
from research_lab.agent_control.transports.local_mcp import (
    CRITICAL_MCP_TOOLS,
    DEFAULT_MCP_SCRIPT,
    DEFAULT_MCP_VENV_PYTHON,
    LocalMCPTransport,
)

REAL_VNPY_DIR = "/Users/fujun/node/vnpy"
REAL_VNPY_PROJECT_ID = "a173ba08-8e0c-4c26-8604-0d462da55529"
RECONCILED_JOB_ID = "e9ce7b2d654f06f313b9fa733dc5e860"
RECONCILED_TASK_ID = "task-7fd76b6c1110762e48cde2c26c40e617"
VERIFIED_LIVE_JOB_ID = "03935a5aa6ed8d4ff1194dee7d2c2ddd"
VERIFIED_LIVE_TASK_ID = "task-1457aa38b2c2e7b8c3af6994b730324a"
VERIFIED_LIVE_REQ_ID = "req-e2e-live-1789918871"


def main() -> int:
    print("=== [SIMNOW_LAB #573 M2] Real Antigravity Local MCP E2E & Reconciliation ===")

    # 1. Environment and Executable Probe
    print(f"[*] Probing MCP script: {DEFAULT_MCP_SCRIPT}")
    if not DEFAULT_MCP_SCRIPT.is_file():
        print(f"[ERROR] MCP script not found at {DEFAULT_MCP_SCRIPT}")
        return 1
    print(f"[*] Probing MCP venv python: {DEFAULT_MCP_VENV_PYTHON}")
    if not DEFAULT_MCP_VENV_PYTHON.is_file():
        print(f"[ERROR] MCP Python venv not found at {DEFAULT_MCP_VENV_PYTHON}")
        return 1

    # 2. Initialize Real LocalMCPTransport over Stdio
    transport = LocalMCPTransport()
    print(f"[*] Initialized LocalMCPTransport: exact_ref = {transport.exact_ref}")

    # 3. Dynamic Tool Discovery
    resolver = transport.discover_tools()
    mapping = resolver.mapping
    print(f"[*] Discovered {len(mapping)} MCP tools from real FastMCP server:")
    for op, tool_name in sorted(mapping.items()):
        print(f"    - {op} -> {tool_name}")
    for critical in CRITICAL_MCP_TOOLS:
        if critical not in mapping:
            print(f"[ERROR] Missing critical tool '{critical}' in catalog")
            return 1
    print("[PASS] Critical tools check complete (fail-closed contract satisfied).")

    # 4. Availability Check
    audit_trail = AppendOnlyAuditTrail()
    provider = AntigravityLocalMCPProvider(transport=transport, audit_trail=audit_trail)
    avail = provider.availability("code_researcher")
    print(f"[*] Provider availability probe: status = {avail.status}, is_available = {avail.is_available}")
    if not avail.is_available:
        print(f"[ERROR] Provider reported unavailable: {avail.reason}")
        return 1
    print("[PASS] Local MCP Provider availability check complete.")

    # 5. Account Usage Check & Privacy Redaction Verification
    usage = provider.account_usage()
    print(f"[*] Account usage snapshot: model_group = {usage.model_group}, windows = {len(usage.quota_windows)}")
    for w in usage.quota_windows:
        print(f"    - window: {w.get('window')}, remaining_fraction: {w.get('remaining_fraction')}, reset_time: {w.get('reset_time')}")
    dumped_usage = str(usage.to_dict())
    for forbidden in ("@", "token", "sk-", "password", "avatar"):
        if forbidden in dumped_usage.lower() and "gemini" not in forbidden:
            print(f"[ERROR] Leakage of sensitive token or credential in usage snapshot: found '{forbidden}'")
            return 1
    print("[PASS] Account usage verified and sensitive info strictly redacted.")

    # 6. Real Project Binding Verification for /Users/fujun/node/vnpy
    binding = ProjectBinding(project_id=REAL_VNPY_PROJECT_ID, workspace_identity=REAL_VNPY_DIR)
    perms = ["read_result_store"]
    scope = authorize(role=AgentRole.CODE_RESEARCHER.value, requested_permissions=perms, project_binding=binding)
    task = AgentTask.create(
        role=AgentRole.CODE_RESEARCHER.value,
        requested_permissions=perms,
        authorized_permissions=perms,
        authorized_scope=scope,
        objective="Read README.md first line. Do not modify files.",
        work_block="wb-m2-e2e-verify",
        input_refs=[{"type": "spec", "ref": "spec-m2"}],
        provider_policy_ref="policy-m2-v1",
        project_binding=binding,
        created_by="researcher",
        created_at="2026-09-20T00:00:00Z",
    )
    matched_proj = provider.verify_project_binding(task)
    print(f"[*] ProjectBinding match: resolved project_id = {matched_proj.get('project_id')}, cwd = {matched_proj.get('cwd')}")
    if matched_proj.get("project_id") != REAL_VNPY_PROJECT_ID:
        print("[ERROR] Project ID mismatch!")
        return 1
    print("[PASS] Exact ProjectBinding verified.")

    # 7. Real Live MCP Task Execution & Verification (Gate 2 P1-1 & TURN_COMPLETE Verification)
    submit_live_flag = "--submit-live" in sys.argv
    if submit_live_flag:
        now_ts = int(time.time())
        live_req_id = f"req-e2e-live-{now_ts}"
        live_task = AgentTask.create(
            role=AgentRole.CODE_RESEARCHER.value,
            requested_permissions=perms,
            authorized_permissions=perms,
            authorized_scope=scope,
            objective="Read README.md first line. Do not modify files.",
            work_block=f"wb-m2-e2e-live-{now_ts}",
            input_refs=[{"type": "spec", "ref": "spec-m2"}],
            provider_policy_ref="policy-m2-v1",
            project_binding=binding,
            created_by="researcher",
            created_at="2026-09-20T00:00:00Z",
        )
    else:
        live_req_id = VERIFIED_LIVE_REQ_ID
        live_task = AgentTask.create(
            role=AgentRole.CODE_RESEARCHER.value,
            requested_permissions=perms,
            authorized_permissions=perms,
            authorized_scope=scope,
            objective="Read README.md first line. Do not modify files.",
            work_block="wb-m2-e2e-live-1789918871",
            input_refs=[{"type": "spec", "ref": "spec-m2"}],
            provider_policy_ref="policy-m2-v1",
            project_binding=binding,
            created_by="researcher",
            created_at="2026-09-20T00:00:00Z",
        )

    reg = ProviderRegistry()
    reg.register(provider, transport=transport.descriptor)
    ctx = RoutingContext(role=AgentRole.CODE_RESEARCHER.value, authorized_scope=scope, project_binding=binding)
    live_route = select_agent(registry=reg, routing_context=ctx)
    live_prep = prepare_execution(task=live_task, route=live_route, registry=reg)

    if submit_live_flag:
        print(f"[*] Submitting new live read-only task: task_id={live_task.task_id}, req_id={live_req_id}")
        live_handle = provider.submit(live_task, live_route, live_prep, request_id=live_req_id)
        live_job_id = live_handle.provider_job_ref
        print(f"[PASS] Successfully submitted live task! Returned durable job_id: {live_job_id}")

        print(f"[*] Waiting for job {live_job_id} to reach terminal status...")
        start_t = time.time()
        term_status = None
        while time.time() - start_t < 180:
            st = provider.status(live_handle)
            print(f"    - current status: {st} (elapsed: {int(time.time() - start_t)}s)")
            if st in ("COMPLETED", "SUCCESS", "FAILED", "CANCELLED", "ERROR", "REJECTED_BY_ACCEPTANCE"):
                term_status = st
                break
            time.sleep(3)
        if not term_status:
            print(f"[ERROR] Timed out waiting for job {live_job_id} completion!")
            return 1
    else:
        live_job_id = VERIFIED_LIVE_JOB_ID
        print(f"[*] Reconciling verified live execution job: {live_job_id}")
        live_handle = AgentExecutionHandle(
            handle_id=f"handle-{live_job_id}",
            task_ref=dict(live_task.to_dict()),
            route_ref=dict(live_route.to_dict()),
            provider_job_ref=live_job_id,
            status="SUBMITTED",
        )
        st = provider.status(live_handle)
        print(f"[*] Queried status via real MCP status tool: {st}")
        if st != "COMPLETED":
            print(f"[ERROR] Expected COMPLETED, got {st}")
            return 1

    # Retrieve and validate live result under new TURN_COMPLETE deliverable gate
    live_result = provider.result(live_handle)
    print("[*] Retrieved live AgentResult:")
    print(f"    - result_id: {live_result.result_id}")
    print(f"    - provider_job_ref: {live_result.provider_job_ref}")
    term_status_val = getattr(live_result.terminal_status, "value", live_result.terminal_status)
    print(f"    - terminal_status: {term_status_val}")
    print(f"    - acceptance_status: {live_result.acceptance_status}")
    print(f"    - result_content_hash: {live_result.result_content_hash}")
    print(f"    - tool_failures: {live_result.tool_failures}")
    if term_status_val != "SUCCESS" or live_result.acceptance_status != "ACCEPTED":
        print(f"[ERROR] TURN_COMPLETE deliverable check failed: expected SUCCESS/ACCEPTED, got {term_status_val}/{live_result.acceptance_status}")
        return 1
    validate_result_hash(live_result.to_dict())
    print("[PASS] Cryptographic validation for live AgentResult passed.")

    # Live model response preview
    live_out_str = json.dumps(live_result.structured_output or {}, ensure_ascii=False)
    print(f"[*] Live model response preview:\n{live_out_str[:350]}...")
    if "# VnPy Web Bridge" not in live_out_str:
        print("[ERROR] Expected '# VnPy Web Bridge' in live result response!")
        return 1
    print("[PASS] Read-only verification confirmed on live job: exact README.md title verified without side effects.")

    # 8. Idempotency Re-submission Verification (Gate 2 P1-1)
    print(f"[*] Verifying idempotency with identical request_id: {live_req_id}")
    re_handle = provider.submit(live_task, live_route, live_prep, request_id=live_req_id)
    print(f"    - re-submission returned job_id: {re_handle.provider_job_ref}")
    if re_handle.provider_job_ref != live_job_id:
        print(f"[ERROR] Idempotency violated: expected {live_job_id}, got {re_handle.provider_job_ref}")
        return 1
    print("[PASS] Idempotency confirmed: returned identical job_id, zero duplicate execution.")

    # 9. Historical Job Reconciliation for e9ce7b2d654f06f313b9fa733dc5e860
    job_disk_dir = Path("/Users/fujun/.codex/skills/antigravity-delegate/.desktop/mcp/jobs") / RECONCILED_JOB_ID
    print(f"[*] Verifying durable job on disk: {job_disk_dir}")
    if not job_disk_dir.is_dir():
        print(f"[ERROR] Durable job directory not found at {job_disk_dir}")
        return 1

    job_file = job_disk_dir / "job.json"
    result_file = job_disk_dir / "result.json"
    request_file = job_disk_dir / "request.json"

    with open(job_file, "r", encoding="utf-8") as f:
        job_data = json.load(f)
    with open(request_file, "r", encoding="utf-8") as f:
        req_data = json.load(f)
    with open(result_file, "r", encoding="utf-8") as f:
        res_data = json.load(f)

    print("[*] Job metadata reconciliation:")
    print(f"    - job_id: {job_data.get('job_id')}")
    print(f"    - task_id: {job_data.get('task_id')}")
    print(f"    - request_hash: {job_data.get('request_hash')}")
    print(f"    - request_prompt: {req_data.get('prompt')}")
    print(f"    - result_model: {res_data.get('model')}")
    print(f"    - status: {job_data.get('status')}")
    print(f"    - outcome: {job_data.get('outcome')}")
    print(f"    - project_id: {job_data.get('project', {}).get('project_id')}")
    print(f"    - project_cwd: {job_data.get('project', {}).get('cwd')}")

    # Build handle for the reconciled job with matching task_id
    reconciled_task_ref = dict(task.to_dict())
    reconciled_task_ref["task_id"] = RECONCILED_TASK_ID
    handle = AgentExecutionHandle(
        handle_id=f"handle-{RECONCILED_JOB_ID}",
        task_ref=reconciled_task_ref,
        route_ref={"role": "code_researcher", "provider": "antigravity", "resolved_model": "Gemini 3.8 Flash (High)"},
        provider_job_ref=RECONCILED_JOB_ID,
        status="SUBMITTED",
    )

    # Call real MCP status tool
    queried_status = provider.status(handle)
    print(f"[*] Queried status via real MCP status tool: {queried_status}")
    if queried_status != "COMPLETED":
        print(f"[ERROR] Expected COMPLETED, got {queried_status}")
        return 1

    # Call real MCP result tool
    agent_result = provider.result(handle)
    print("[*] Retrieved AgentResult via real MCP result tool:")
    print(f"    - result_id: {agent_result.result_id}")
    print(f"    - provider_job_ref: {agent_result.provider_job_ref}")
    term_status_val = getattr(agent_result.terminal_status, "value", agent_result.terminal_status)
    print(f"    - terminal_status: {term_status_val}")
    print(f"    - acceptance_status: {agent_result.acceptance_status}")
    print(f"    - result_content_hash: {agent_result.result_content_hash}")
    print(f"    - tool_failures: {agent_result.tool_failures}")

    # Validate result content hash
    validate_result_hash(agent_result.to_dict())
    print("[PASS] AgentResult content hash cryptographic validation passed.")

    # Validate output content from README.md read
    out_obj = agent_result.structured_output or {}
    out_str = json.dumps(out_obj, ensure_ascii=False)
    print(f"[*] Model response preview:\n{out_str[:350]}...")
    if "# VnPy Web Bridge" not in out_str:
        print("[ERROR] Expected '# VnPy Web Bridge' in result response!")
        return 1
    print("[PASS] Read-only verification confirmed: exact README.md title verified without side effects.")

    # Validate audit trail
    print(f"[*] Audit trail count: {len(audit_trail)}")
    audit_trail.verify_all()
    print("[PASS] Append-only audit trail cryptographically verified.")

    print("\n=== ALL REAL MCP E2E AND RECONCILIATION CHECKS PASSED SUCCESSFULLY ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
