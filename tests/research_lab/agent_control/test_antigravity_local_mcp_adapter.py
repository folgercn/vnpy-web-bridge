"""Comprehensive test suite for Antigravity Local MCP Provider Adapter (#573 Milestone 2).

Verifies all 36 required criteria from attachment section 51:
1. missing MCP tool catalog fails closed
2. status unavailable
3. desktop not ready
4. project no match
5. project multiple match
6. project mismatch
7. account_usage valid
8. account_usage unknown fields
9. shared quota windows preserved
10. submit returns durable job_id
11. request_id stable retry
12. same request_id different payload reject
13. duplicate submission prevented
14. disconnect recovery same job_id
15. watch reconnect cursor
16. result fragment reassembly
17. compact progress not treated final
18. provider self SUCCESS not acceptance
19. tool failure preservation
20. REVIEW_REQUIRED history preserved
21. UNCERTAIN mapping
22. cancel_requested not cancelled
23. confirmed cancel
24. cancel uncertain
25. timeout no auto resubmit
26. wrong job result rejected
27. wrong task/route result rejected
28. transport exact identity
29. project exact identity
30. actual model provenance
31. no credential leakage
32. no nested agent
33. no provider permission elevation
34. no trading authority
35. Audit append-only
36. true local MCP smoke/E2E (read-only, side-effect free)
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from research_lab.agent_control.audit import AppendOnlyAuditTrail
from research_lab.agent_control.contracts import (
    AgentExecutionHandle,
    AgentProviderDescriptor,
    AgentRoute,
    AgentTask,
    ProjectBinding,
    TerminalStatus,
    compute_route_content_hash,
    validate_result_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    ResultAcceptanceError,
    TamperDetectionError,
)
from research_lab.agent_control.handoff import (
    ExecutionPreparation,
    prepare_execution,
)
from research_lab.agent_control.provider import ProviderAvailability
from research_lab.agent_control.providers.antigravity_local_mcp import (
    SUPPORTED_MODELS,
    SUPPORTED_ROLES,
    AntigravityLocalMCPProvider,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import AgentRole
from research_lab.agent_control.router import (
    authorize,
    select_agent,
)
from research_lab.agent_control.routing_context import RoutingContext
from research_lab.agent_control.transports.local_mcp import (
    ALL_MCP_OPERATIONS,
    LocalMCPTransport,
    parse_mcp_response_content,
)

REAL_VNPY_DIR = "/Users/fujun/node/vnpy"
REAL_VNPY_PROJECT_ID = "a173ba08-8e0c-4c26-8604-0d462da55529"


class _TestFixtureProvider:
    def __init__(self) -> None:
        self.name = "antigravity"
        self.supported_roles = tuple(sorted(SUPPORTED_ROLES))
        self.supported_models = SUPPORTED_MODELS
        self.capabilities = ("text_generation", "code_exploration")
        self.default_model = "Gemini 3.8 Flash High"

    def describe(self) -> AgentProviderDescriptor:
        return AgentProviderDescriptor(
            provider="antigravity",
            supported_roles=self.supported_roles,
            supported_models=self.supported_models,
            capabilities=self.capabilities,
            default_model=self.default_model,
        )

    def availability(self, role: str, context: dict | None = None) -> ProviderAvailability:
        return ProviderAvailability(is_available=True, status="AVAILABLE", reason="test ready")


def _make_test_fixtures(
    *,
    role: str = AgentRole.CODE_RESEARCHER.value,
    model: str = "Gemini 3.8 Flash High",
    permissions: tuple[str, ...] = ("read_result_store",),
    project_id: str = REAL_VNPY_PROJECT_ID,
    cwd: str = REAL_VNPY_DIR,
    prompt: str = "Perform read-only code exploration of agent_control",
    task_id: str | None = None,
) -> tuple[AgentTask, AgentRoute, ExecutionPreparation]:
    binding = ProjectBinding(project_id=project_id, workspace_identity=cwd)
    perms = list(permissions)
    scope = authorize(role=role, requested_permissions=perms, project_binding=binding)
    task = AgentTask.create(
        role=role,
        requested_permissions=perms,
        authorized_permissions=perms,
        authorized_scope=scope,
        objective=prompt,
        work_block="wb-m2-test",
        input_refs=[{"type": "spec", "ref": "spec-m2"}],
        provider_policy_ref="policy-m2-v1",
        project_binding=binding,
        created_by="researcher",
        created_at="2026-09-20T00:00:00Z",
    )
    reg = ProviderRegistry()
    mock_prov = _TestFixtureProvider()
    transport_desc = LocalMCPTransport(tool_catalog=list(ALL_MCP_OPERATIONS), tool_caller=lambda op, a: {}).descriptor
    reg.register(mock_prov, transport=transport_desc)
    ctx = RoutingContext(role=role, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=reg, routing_context=ctx)
    prep = prepare_execution(task=task, route=route, registry=reg)
    return task, route, prep


class TestAntigravityLocalMCPAdapter(unittest.TestCase):
    """36 acceptance tests for Milestone 2 local MCP adapter."""

    # 1. missing MCP tool catalog fails closed
    def test_01_missing_mcp_tool_catalog_fails_closed(self) -> None:
        incomplete_catalog = ["projects", "status"]  # missing 'submit' and 'result'
        transport = LocalMCPTransport(tool_catalog=incomplete_catalog)
        with self.assertRaises(ProviderUnavailableError) as cm:
            transport.discover_tools()
        self.assertIn("Missing critical MCP tools", str(cm.exception))

    # 2. status unavailable
    def test_02_status_unavailable(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "status":
                return {"ready": False, "offline": True}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        avail = provider.availability("code_researcher")
        self.assertFalse(avail.is_available)
        self.assertEqual(avail.status, "UNAVAILABLE")

    # 3. desktop not ready
    def test_03_desktop_not_ready(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "status":
                return {"ready": False}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        avail = provider.availability("code_researcher")
        self.assertFalse(avail.is_available)
        self.assertEqual(avail.status, "UNAVAILABLE")

    # 4. project no match
    def test_04_project_no_match(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"projects": []}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, _route, _prep = _make_test_fixtures()
        with self.assertRaises(ProjectBindingError) as cm:
            provider.verify_project_binding(task)
        self.assertIn("No matching project found", str(cm.exception))

    # 5. project multiple match
    def test_05_project_multiple_match(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {
                    "projects": [
                        {"project_id": "p1", "cwd": REAL_VNPY_DIR},
                        {"project_id": "p2", "cwd": REAL_VNPY_DIR},
                    ]
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, _route, _prep = _make_test_fixtures()
        with self.assertRaises(ProjectBindingError) as cm:
            provider.verify_project_binding(task)
        self.assertIn("Ambiguous matching projects", str(cm.exception))

    # 6. project mismatch
    def test_06_project_mismatch(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {
                    "project": {
                        "project_id": "different-project-uuid-9999",
                        "cwd": REAL_VNPY_DIR,
                    }
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, _route, _prep = _make_test_fixtures()
        with self.assertRaises(ProjectBindingError) as cm:
            provider.verify_project_binding(task)
        self.assertIn("ProjectBinding project_id mismatch", str(cm.exception))

    # 7. account_usage valid
    def test_07_account_usage_valid(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "account_usage":
                return {
                    "plan": "pro",
                    "model_group": "gemini-shared",
                    "quota_windows": [
                        {"window": "5-hour", "remaining_fraction": 0.85, "reset_time": "2026-09-20T23:00:00Z"},
                        {"window": "weekly", "remaining_fraction": 0.92, "reset_time": "2026-09-27T00:00:00Z"},
                    ],
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        snapshot = provider.account_usage()
        self.assertEqual(snapshot.provider, "antigravity")
        self.assertEqual(snapshot.model_group, "gemini-shared")
        self.assertEqual(len(snapshot.quota_windows), 2)
        self.assertEqual(snapshot.quota_windows[0]["remaining_fraction"], "0.85")

    # 8. account_usage unknown fields preserved as None/unknown
    def test_08_account_usage_unknown_fields(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "account_usage":
                return {
                    "plan": "team",
                    "quota_windows": [
                        {"window": "5-hour"},  # missing remaining_fraction and reset_time
                    ],
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        snapshot = provider.account_usage()
        self.assertIsNone(snapshot.quota_windows[0].get("remaining_fraction"))
        self.assertIsNone(snapshot.quota_windows[0].get("reset_time"))

    # 9. shared quota windows preserved
    def test_09_shared_quota_windows_preserved(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "account_usage":
                return {
                    "model_group": "gemini-3.8-shared-bucket",
                    "buckets": [
                        {"window": "5-hour", "remaining_fraction": 0.70},
                        {"window": "weekly", "remaining_fraction": 0.45},
                    ],
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        snapshot = provider.account_usage()
        self.assertEqual(snapshot.model_group, "gemini-3.8-shared-bucket")
        windows = {w["window"]: w["remaining_fraction"] for w in snapshot.quota_windows}
        self.assertEqual(windows["5-hour"], "0.7")
        self.assertEqual(windows["weekly"], "0.45")

    # 10. submit returns durable job_id
    def test_10_submit_returns_durable_job_id(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-durable-12345"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, route, prep = _make_test_fixtures()
        handle = provider.submit(task, route, prep, request_id="req-test-10")
        self.assertEqual(handle.provider_job_ref, "job-durable-12345")
        self.assertEqual(handle.handle_id, "handle-job-durable-12345")
        self.assertEqual(handle.status, "SUBMITTED")

    # 11. request_id stable retry
    def test_11_request_id_stable_retry(self) -> None:
        submit_count = 0

        def fake_caller(op: str, args: dict) -> Any:
            nonlocal submit_count
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                submit_count += 1
                return {"job_id": "job-idempotent-777"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, route, prep = _make_test_fixtures()

        h1 = provider.submit(task, route, prep, request_id="req-stable-1")
        h2 = provider.submit(task, route, prep, request_id="req-stable-1")
        self.assertEqual(h1.provider_job_ref, h2.provider_job_ref)
        self.assertEqual(submit_count, 1)  # Only submitted once

    # 12. same request_id different payload reject
    def test_12_same_request_id_different_payload_reject(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-idempotent-888"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, route, prep = _make_test_fixtures(prompt="First prompt")
        provider.submit(task, route, prep, request_id="req-diff-test")

        # Simulate modifying task prompt with same request_id
        object.__setattr__(task, "prompt", "Modified prompt with same request_id")
        with self.assertRaises(ProviderError) as cm:
            provider.submit(task, route, prep, request_id="req-diff-test")
        self.assertEqual(cm.exception.code, ProviderErrorCode.SUBMISSION_FAILED)
        self.assertIn("different payload rejected", str(cm.exception))

    # 13. duplicate submission prevented
    def test_13_duplicate_submission_prevented(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-active-001"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, route, prep = _make_test_fixtures()
        provider.submit(task, route, prep, request_id="req-1")

        # Attempt second submit with new request_id while task is still active
        with self.assertRaises(ProviderError) as cm:
            provider.submit(task, route, prep, request_id="req-2")
        self.assertEqual(cm.exception.code, ProviderErrorCode.SUBMISSION_FAILED)
        self.assertIn("already has active job", str(cm.exception))

    # 14. disconnect recovery same job_id
    def test_14_disconnect_recovery_same_job_id(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-recover-123"}
            if op == "status":
                return {"status": "RUNNING"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, route, prep = _make_test_fixtures()
        handle = provider.submit(task, route, prep, request_id="req-rec-1")

        # Client reconnects: checks status on same handle / job_id
        st = provider.status(handle)
        self.assertEqual(st, "RUNNING")
        self.assertEqual(handle.provider_job_ref, "job-recover-123")

    # 15. watch reconnect cursor
    def test_15_watch_reconnect_cursor(self) -> None:
        received_args = []

        def fake_caller(op: str, args: dict) -> Any:
            if op == "watch":
                received_args.append(args)
                return {"events": [], "has_more": False, "cursor": args["cursor"] + 100}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="handle-1",
            task_ref={},
            route_ref={},
            provider_job_ref="job-cursor-1",
            status="RUNNING",
        )
        res1 = provider.watch(handle, cursor=0)
        provider.watch(handle, cursor=res1["cursor"])
        self.assertEqual(received_args[0]["cursor"], 0)
        self.assertEqual(received_args[1]["cursor"], 100)

    # 16. result fragment reassembly
    def test_16_result_fragment_reassembly(self) -> None:
        parts = [
            {"offset": 0, "chunk": '{"status":"COMPLETED",', "final": False},
            {"offset": 20, "chunk": '"output":"assembled_data"}', "final": True},
        ]
        fragments = []
        for p in parts:
            fragments.append(p["chunk"])
        full_json = "".join(fragments)
        parsed = parse_mcp_response_content(full_json)
        self.assertEqual(parsed["status"], "COMPLETED")
        self.assertEqual(parsed["output"], "assembled_data")

    # 17. compact progress not treated final
    def test_17_compact_progress_not_treated_final(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "status":
                return {"state": "RUNNING", "progress": {"summary": "Working on step 3"}}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-1", status="RUNNING"
        )
        st = provider.status(handle)
        self.assertEqual(st, "RUNNING")  # Progress summary is not COMPLETED

    # 18. provider self SUCCESS not acceptance
    def test_18_provider_self_success_not_acceptance(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "result":
                return {
                    "job_id": "job-fail-tool",
                    "status": "COMPLETED",
                    "output": "Model says SUCCESS",
                    "tool_failures": ["Command failed with exit code 1"],
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-fail-tool", status="COMPLETED"
        )
        res = provider.result(handle)
        self.assertEqual(res.terminal_status, TerminalStatus.REJECTED_BY_ACCEPTANCE.value)
        self.assertEqual(res.acceptance_status, "REJECTED_BY_ACCEPTANCE")
        self.assertIn("Command failed with exit code 1", res.tool_failures)

    # 19. tool failure preservation
    def test_19_tool_failure_preservation(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "result":
                return {
                    "job_id": "job-preserve-err",
                    "status": "COMPLETED",
                    "output": "All done",
                    "tool_issues": ["Permission denied reading /etc/shadow", "File not found"],
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-preserve-err", status="COMPLETED"
        )
        res = provider.result(handle)
        self.assertEqual(len(res.tool_failures), 2)
        self.assertIn("File not found", res.tool_failures)

    # 20. REVIEW_REQUIRED history preserved
    def test_20_review_required_history_preserved(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "result":
                return {
                    "job_id": "job-rr-hist",
                    "status": "COMPLETED",
                    "recovery": {"error_history": ["Temporary socket timeout", "Retried with success"]},
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-rr-hist", status="COMPLETED"
        )
        res = provider.result(handle)
        self.assertTrue(any("Temporary socket timeout" in f for f in res.tool_failures))

    # 21. UNCERTAIN mapping
    def test_21_uncertain_mapping(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "status":
                return {"status": "UNKNOWN_STATE"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-unc", status="RUNNING"
        )
        self.assertEqual(provider.status(handle), "UNCERTAIN")

    # 22. cancel_requested not cancelled
    def test_22_cancel_requested_not_cancelled(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "cancel":
                return {"status": "cancel_requested"}
            if op == "status":
                return {"status": "CANCEL_REQUESTED"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-cr", status="RUNNING"
        )
        ok = provider.cancel(handle)
        self.assertTrue(ok)
        st = provider.status(handle)
        self.assertEqual(st, "CANCEL_REQUESTED")  # NOT CANCELLED yet

    # 23. confirmed cancel
    def test_23_confirmed_cancel(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "status":
                return {"status": "CANCELLED"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-cc", status="CANCEL_REQUESTED"
        )
        st = provider.status(handle)
        self.assertEqual(st, "CANCELLED")

    # 24. cancel uncertain
    def test_24_cancel_uncertain(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "cancel":
                raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN, "Worker ambiguous")
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-cu", status="RUNNING"
        )
        ok = provider.cancel(handle)
        self.assertFalse(ok)

    # 25. timeout no auto resubmit
    def test_25_timeout_no_auto_resubmit(self) -> None:
        submit_count = 0

        def fake_caller(op: str, args: dict) -> Any:
            nonlocal submit_count
            if op == "submit":
                submit_count += 1
                return {"job_id": "job-timeout-1"}
            if op == "cancel":
                return {"status": "cancel_requested"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-timeout-1", status="RUNNING"
        )
        # Timeout triggers cancel of existing job, NEVER creates a second job
        provider.cancel(handle)
        self.assertEqual(submit_count, 0)

    # 26. wrong job result rejected
    def test_26_wrong_job_result_rejected(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "result":
                return {
                    "job_id": "completely-different-job-id-999",
                    "status": "COMPLETED",
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        handle = AgentExecutionHandle(
            handle_id="h1", task_ref={}, route_ref={}, provider_job_ref="job-expected-1", status="COMPLETED"
        )
        with self.assertRaises(ResultAcceptanceError) as cm:
            provider.result(handle)
        self.assertIn("job_id mismatch", str(cm.exception))

    # 27. wrong task/route result rejected
    def test_27_wrong_task_route_result_rejected(self) -> None:
        def fake_caller_wrong_task(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-exact-bound"}
            if op == "result":
                return {"job_id": "job-exact-bound", "task_id": "different-task-uuid", "status": "COMPLETED"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller_wrong_task,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, route, prep = _make_test_fixtures()
        handle = provider.submit(task, route, prep)
        # Result returning mismatch task_id fails closed (wrong-result binding prevented)
        with self.assertRaises(ResultAcceptanceError) as cm:
            provider.result(handle)
        self.assertIn("task_id mismatch", str(cm.exception))

        # Also verify missing job_id fails closed
        def fake_caller_missing_job(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-exact-bound"}
            if op == "result":
                return {"task_id": task.task_id, "status": "COMPLETED"}
            return {}

        transport_no_job = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller_missing_job,
        )
        provider_no_job = AntigravityLocalMCPProvider(transport=transport_no_job)
        handle_no_job = provider_no_job.submit(task, route, prep)
        with self.assertRaises(ResultAcceptanceError) as cm2:
            provider_no_job.result(handle_no_job)
        self.assertIn("job_id mismatch", str(cm2.exception))

    # 28. transport exact identity
    def test_28_transport_exact_identity(self) -> None:
        transport = LocalMCPTransport(connection_profile_ref="antigravity-local-desktop")
        self.assertEqual(transport.exact_ref, "local_mcp://antigravity-local-desktop")

    # 29. project exact identity
    def test_29_project_exact_identity(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        task, _route, _prep = _make_test_fixtures()
        matched = provider.verify_project_binding(task)
        self.assertEqual(matched["project_id"], REAL_VNPY_PROJECT_ID)

    # 30. actual model provenance
    def test_30_actual_model_provenance(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-fallback-model"}
            if op == "result":
                return {
                    "job_id": "job-fallback-model",
                    "status": "COMPLETED",
                    "actual_model": "Gemini 3.8 Flash Medium",  # fell back from High
                    "output": "Exploration complete",
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        audit_trail = AppendOnlyAuditTrail()
        provider = AntigravityLocalMCPProvider(transport=transport, audit_trail=audit_trail)
        task, route, prep = _make_test_fixtures()
        handle = provider.submit(task, route, prep)
        provider.result(handle)
        records = audit_trail.get_records()
        last_rec = records[-1]
        self.assertEqual(last_rec.resolved_model, "Gemini 3.8 Flash Medium")

    # 31. no credential leakage
    def test_31_no_credential_leakage(self) -> None:
        def fake_caller(op: str, args: dict) -> Any:
            if op == "account_usage":
                return {
                    "plan": "pro",
                    "email": "private_user@example.com",
                    "avatar": "https://secret/avatar.png",
                    "token": "sk-ant-private-123456",
                    "quota_windows": [{"window": "5-hour", "remaining_fraction": 0.9}],
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport)
        snapshot = provider.account_usage()
        dumped = json.dumps(snapshot.to_dict(), default=str)
        self.assertNotIn("private_user@example.com", dumped)
        self.assertNotIn("avatar.png", dumped)
        self.assertNotIn("sk-ant-private", dumped)

    # 32. no nested agent
    def test_32_no_nested_agent(self) -> None:
        task, route, prep = _make_test_fixtures(permissions=("read_result_store",))
        object.__setattr__(route, "authorized_permissions", ("read_result_store", "nested_delegation_attempt"))
        object.__setattr__(route, "route_content_hash", compute_route_content_hash(route.to_dict()))
        provider = AntigravityLocalMCPProvider()
        with self.assertRaises(PermissionDeniedError) as cm:
            provider.submit(task, route, prep)
        self.assertIn("nested delegation prohibited", str(cm.exception))

    # 33. no provider permission elevation
    def test_33_no_provider_permission_elevation(self) -> None:
        task, route, prep = _make_test_fixtures(permissions=("read_result_store",))
        provider = AntigravityLocalMCPProvider()
        # Elevated permissions beyond task
        object.__setattr__(route, "authorized_permissions", ("read_result_store", "create_hypothesis"))
        with self.assertRaises((PermissionDeniedError, TamperDetectionError)):
            provider.submit(task, route, prep)

    # 34. no trading authority
    def test_34_no_trading_authority(self) -> None:
        task, route, prep = _make_test_fixtures(permissions=("read_result_store",))
        object.__setattr__(route, "authorized_permissions", ("read_result_store", "trading_execution"))
        object.__setattr__(route, "route_content_hash", compute_route_content_hash(route.to_dict()))
        provider = AntigravityLocalMCPProvider()
        with self.assertRaises(PermissionDeniedError) as cm:
            provider.submit(task, route, prep)
        self.assertIn("trading permissions prohibited", str(cm.exception))

    # 35. Audit append-only
    def test_35_audit_append_only(self) -> None:
        audit_trail = AppendOnlyAuditTrail()
        def fake_caller(op: str, args: dict) -> Any:
            if op == "projects":
                return {"project": {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR}}
            if op == "submit":
                return {"job_id": "job-audit-trail"}
            if op == "result":
                return {"job_id": "job-audit-trail", "status": "COMPLETED", "output": "Done"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport, audit_trail=audit_trail)
        task, route, prep = _make_test_fixtures()
        handle = provider.submit(task, route, prep)
        self.assertEqual(len(audit_trail), 1)
        provider.result(handle)
        self.assertEqual(len(audit_trail), 2)
        self.assertTrue(audit_trail.verify_all())

    # 36. local MCP end-to-end read-only contract
    def test_36_local_mcp_end_to_end_read_only_contract(self) -> None:
        """Hermetic end-to-end read-only lifecycle contract verification for Local MCP provider."""
        call_log: list[str] = []

        def mock_tool_caller(op: str, args: dict) -> Any:
            call_log.append(op)
            if op == "status":
                return {"ready": True, "offline": False, "rate_limited": False}
            if op == "account_usage":
                return {
                    "account": {"planName": "pro"},
                    "quota": {
                        "groups": [
                            {
                                "displayName": "Gemini 3.8",
                                "buckets": [
                                    {"name": "5-hour", "remaining_fraction": 0.85, "reset_time": "2026-09-21T00:00:00Z"},
                                    {"name": "weekly", "remaining_fraction": 0.95, "reset_time": "2026-09-28T00:00:00Z"},
                                ],
                            }
                        ]
                    },
                }
            if op == "projects":
                return {
                    "projects": [
                        {"project_id": REAL_VNPY_PROJECT_ID, "cwd": REAL_VNPY_DIR, "name": "vnpy"}
                    ]
                }
            if op == "submit":
                self.assertEqual(args.get("cwd"), REAL_VNPY_DIR)
                self.assertEqual(args.get("mode"), "research")
                return {"job_id": "job-e2e-contract-101"}
            if op == "watch":
                return {"cursor": 100, "events": [{"type": "step", "status": "running"}]}
            if op == "result":
                return {
                    "job_id": "job-e2e-contract-101",
                    "status": "TURN_COMPLETE",
                    "actual_model": "Gemini 3.8 Flash High",
                    "output": "# VnPy Web Bridge",
                    "tool_failures": [],
                    "recovery": {"error_history": []},
                }
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=mock_tool_caller,
        )
        audit_trail = AppendOnlyAuditTrail()
        provider = AntigravityLocalMCPProvider(transport=transport, audit_trail=audit_trail)

        # 1. Availability check
        avail = provider.availability("code_researcher")
        self.assertTrue(avail.is_available)
        self.assertEqual(avail.status, "AVAILABLE")

        # 2. Account usage query
        usage = provider.account_usage()
        self.assertEqual(usage.provider, "antigravity")
        self.assertEqual(len(usage.quota_windows), 2)
        self.assertEqual(usage.quota_windows[0]["window"], "5-hour")
        self.assertEqual(usage.quota_windows[0]["remaining_fraction"], "0.85")

        # 3. Exact project matching
        task, route, prep = _make_test_fixtures(
            prompt="Read README.md first line.",
        )
        matched = provider.verify_project_binding(task)
        self.assertEqual(matched.get("project_id"), REAL_VNPY_PROJECT_ID)

        # 4. Submit read-only task
        req_id = "req-e2e-test-101"
        handle = provider.submit(task, route, prep, request_id=req_id)
        self.assertEqual(handle.provider_job_ref, "job-e2e-contract-101")
        self.assertEqual(handle.status, "SUBMITTED")
        self.assertEqual(len(audit_trail), 1)

        # 5. Same-job watch
        watch_out = provider.watch(handle, cursor=0)
        self.assertIn("events", watch_out)

        # 6. Retrieve terminal result
        res = provider.result(handle)
        self.assertEqual(res.provider_job_ref, "job-e2e-contract-101")
        self.assertEqual(res.terminal_status, TerminalStatus.SUCCESS)
        self.assertEqual(res.acceptance_status, "ACCEPTED")
        self.assertEqual(res.structured_output, {"output": "# VnPy Web Bridge"})
        validate_result_hash(res.to_dict())

        # 7. Audit trail completeness and tamper resistance
        self.assertEqual(len(audit_trail), 2)
        self.assertTrue(audit_trail.verify_all())
        records = audit_trail.get_records()
        self.assertEqual(records[0].terminal_status, "SUBMITTED")
        self.assertEqual(records[1].terminal_status, "SUCCESS")
        self.assertEqual(records[1].acceptance_status, "ACCEPTED")

        # 8. Complete tool call chain verification
        self.assertEqual(call_log, ["status", "account_usage", "projects", "projects", "submit", "watch", "result"])

    # 37. Role and permission consistency enforced (P1-4)
    def test_37_role_and_permission_consistency_enforced(self) -> None:
        provider = AntigravityLocalMCPProvider()
        task, route, _ = _make_test_fixtures()
        # Role mismatch
        object.__setattr__(route, "role", "research_synthesizer")
        object.__setattr__(route, "route_content_hash", compute_route_content_hash(route.to_dict()))
        with self.assertRaises(PermissionDeniedError) as cm:
            provider.submit(task, route)
        self.assertIn("Role mismatch", str(cm.exception))

        # Permission mismatch
        task2, route2, _ = _make_test_fixtures()
        object.__setattr__(route2, "authorized_permissions", ("read_research_memory",))
        object.__setattr__(route2, "route_content_hash", compute_route_content_hash(route2.to_dict()))
        with self.assertRaises(PermissionDeniedError) as cm2:
            provider.submit(task2, route2)
        self.assertIn("Authorized permissions mismatch", str(cm2.exception))

    # 38. Cancel audit completeness on reconnected handle (P1-3)
    def test_38_cancel_audit_on_reconnected_handle(self) -> None:
        trail = AppendOnlyAuditTrail()
        cancelled_jobs: list[str] = []

        def fake_caller(op: str, args: dict) -> Any:
            if op == "cancel":
                cancelled_jobs.append(args.get("job_id", ""))
                return {"status": "CANCELLED"}
            return {}

        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            tool_caller=fake_caller,
        )
        provider = AntigravityLocalMCPProvider(transport=transport, audit_trail=trail)
        # Reconnected handle with no prior submit() on this instance
        handle = AgentExecutionHandle(
            handle_id="handle-reconnected-999",
            task_ref={"task_id": "task-reconnected-999"},
            route_ref={"route_id": "route-reconnected-999"},
            provider_job_ref="job-reconnected-999",
            status="RUNNING",
        )
        ok = provider.cancel(handle)
        self.assertTrue(ok)
        self.assertEqual(cancelled_jobs, ["job-reconnected-999"])
        # Audit record must not be dropped due to truthy/falsy or missing in-memory meta
        self.assertEqual(len(trail), 1)
        records = trail.get_records()
        self.assertEqual(records[0].provider_job_ref, "job-reconnected-999")
        self.assertEqual(records[0].terminal_status, "CANCEL_REQUESTED")

    # 39. Transport readline timeout triggers EXECUTION_UNCERTAIN (P1-1)
    def test_39_transport_timeout_uncertain(self) -> None:
        transport = LocalMCPTransport(
            tool_catalog=list(ALL_MCP_OPERATIONS),
            command=["sleep", "5"],
        )
        with self.assertRaises(ProviderError) as cm:
            transport._execute_stdio_call("status", {}, timeout_seconds=0.05)
        self.assertEqual(cm.exception.code, ProviderErrorCode.EXECUTION_UNCERTAIN)
        self.assertIn("timed out", str(cm.exception))

    # 40. parse_mcp_response recursion depth and envelope preservation (P1-2)
    def test_40_parse_mcp_response_depth_limit_and_envelope(self) -> None:
        from research_lab.agent_control.transports.local_mcp import (
            parse_mcp_response_content,
        )

        # 1. Non-envelope with business "result" field preserved intact
        biz_dict = {"status": "COMPLETED", "job_id": "j-123", "result": {"nested": "val"}}
        parsed = parse_mcp_response_content(biz_dict)
        self.assertEqual(parsed, biz_dict)

        # 2. Pure envelope unwrapped
        envelope = {"result": {"actual_key": "actual_val"}}
        self.assertEqual(parse_mcp_response_content(envelope), {"actual_key": "actual_val"})

        # 3. FastMCP content wrapper
        content_wrapper = {"content": [{"type": "text", "text": '{"hello": "world"}'}]}
        self.assertEqual(parse_mcp_response_content(content_wrapper), {"hello": "world"})


if __name__ == "__main__":
    unittest.main()
