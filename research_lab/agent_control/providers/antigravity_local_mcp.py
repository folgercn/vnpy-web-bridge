"""Antigravity Local MCP Provider Adapter (#573 Milestone 2).

Architecture Rule:
Role -> Access Control -> Agent Router -> Agent Provider (AntigravityLocalMCPProvider)
    -> Provider Transport (LocalMCPTransport) -> Real FastMCP server

Boundary Rules:
1. Wrap existing local FastMCP capabilities only.
2. Provider SUCCESS != Acceptance SUCCESS.
3. request_id / task_id / job_id strictly separated; durable job_id persisted immediately.
4. Duplicate submissions strictly prevented; same-job recovery on disconnect.
5. ProjectBinding must exact-match projects(cwd); no fallback to desktop selected project.
6. Retain all tool failures and error histories; UNCERTAIN is a first-class state.
7. Append-only audit trail for all lifecycle transitions.
8. No trading authority, no nested agent, no privilege elevation.
9. Secrets, auth tokens, passwords, sessions, avatars, and emails redacted from business objects.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from collections.abc import Callable
from typing import Any

from research_lab.agent_control.audit import AppendOnlyAuditTrail
from research_lab.agent_control.contracts import (
    AgentAuditRecord,
    AgentExecutionHandle,
    AgentProviderDescriptor,
    AgentResult,
    AgentRoute,
    AgentTask,
    AgentUsageSnapshot,
    TerminalStatus,
    validate_route_hash,
    validate_task_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    ResultAcceptanceError,
)
from research_lab.agent_control.handoff import (
    ExecutionPreparation,
    validate_preparation_hash,
)
from research_lab.agent_control.provider import AgentProvider, ProviderAvailability
from research_lab.agent_control.transports.local_mcp import LocalMCPTransport

SUPPORTED_ROLES = frozenset(
    {
        "alpha_generator",
        "code_researcher",
        "data_researcher",
        "external_researcher",
        "research_synthesizer",
    }
)

SUPPORTED_MODELS = (
    "Gemini 3.8 Flash High",
    "Gemini 3.8 Flash Medium",
    "Gemini 3.7 Flash High",
)


class AntigravityLocalMCPProvider(AgentProvider):
    """Local MCP provider adapter connecting Agent Control to local Antigravity FastMCP."""

    def __init__(
        self,
        transport: LocalMCPTransport | None = None,
        *,
        audit_trail: AppendOnlyAuditTrail | None = None,
    ) -> None:
        self._transport = transport if transport is not None else LocalMCPTransport()
        self._audit_trail = audit_trail if audit_trail is not None else AppendOnlyAuditTrail()
        # In-memory deduplication and submission tracking: (task_id, request_id) -> record
        self._submissions: dict[tuple[str, str], dict[str, Any]] = {}
        # Active jobs tracking: task_id -> job_id
        self._active_jobs: dict[str, str] = {}
        # Job terminal status: job_id -> status
        self._job_statuses: dict[str, str] = {}
        # Job to task/route mapping
        self._job_metadata: dict[str, dict[str, Any]] = {}

    @property
    def transport(self) -> LocalMCPTransport:
        return self._transport

    @property
    def audit_trail(self) -> AppendOnlyAuditTrail:
        return self._audit_trail

    def describe(self) -> AgentProviderDescriptor:
        """Return static descriptor of this provider, supported roles, and models."""
        return AgentProviderDescriptor(
            provider="antigravity",
            supported_roles=tuple(sorted(SUPPORTED_ROLES)),
            supported_models=SUPPORTED_MODELS,
            capabilities=("text_generation", "code_exploration", "mcp_tool_execution"),
            default_model="Gemini 3.8 Flash High",
        )

    def availability(
        self,
        role: str,
        context: dict[str, Any] | None = None,
    ) -> ProviderAvailability:
        """Check whether the local MCP backend is currently available to serve the role."""
        if role not in SUPPORTED_ROLES:
            return ProviderAvailability(
                is_available=False,
                status="UNAVAILABLE",
                reason=f"Role '{role}' is not supported by provider 'antigravity'",
            )

        try:
            # 1. Verify critical tools exist in catalog
            self._transport.discover_tools()

            # 2. Probe status tool
            status_data = self._transport.call_tool("status", {})
            if not isinstance(status_data, dict):
                return ProviderAvailability(
                    is_available=False,
                    status="UNAVAILABLE",
                    reason="Invalid status response from local MCP server",
                )

            # Check if backend explicitly indicates unavailable or rate limited
            if status_data.get("rate_limited"):
                return ProviderAvailability(
                    is_available=False,
                    status="RATE_LIMITED",
                    reason="Antigravity backend is currently rate limited",
                )

            if status_data.get("offline") or status_data.get("ready") is False:
                return ProviderAvailability(
                    is_available=False,
                    status="UNAVAILABLE",
                    reason="Antigravity desktop backend is not ready or signed in",
                )

            return ProviderAvailability(
                is_available=True,
                status="AVAILABLE",
                reason="Antigravity local MCP server and desktop backend ready",
            )
        except ProviderUnavailableError as e:
            return ProviderAvailability(
                is_available=False,
                status="UNAVAILABLE",
                reason=f"MCP provider unavailable: {e.message}",
            )
        except ProviderError as e:
            if e.code == ProviderErrorCode.EXECUTION_UNCERTAIN:
                return ProviderAvailability(
                    is_available=False,
                    status="UNKNOWN",
                    reason=f"Status probe uncertain: {e.message}",
                )
            return ProviderAvailability(
                is_available=False,
                status="UNAVAILABLE",
                reason=f"Status probe failed: {e.message}",
            )
        except Exception as e:  # noqa: BLE001
            return ProviderAvailability(
                is_available=False,
                status="UNKNOWN",
                reason=f"Unexpected status error: {e}",
            )

    def account_usage(self) -> AgentUsageSnapshot:
        """Query account usage and map to AgentUsageSnapshot, redacting private info."""
        raw = self._transport.call_tool("account_usage", {})
        if not isinstance(raw, dict):
            raise ProviderError(
                ProviderErrorCode.QUOTA_UNAVAILABLE,
                "Invalid response from account_usage tool",
            )

        account_info = raw.get("account", {}) if isinstance(raw.get("account"), dict) else {}
        _plan = str(account_info.get("planName") or raw.get("plan", "unknown"))

        quota_info = raw.get("quota", {}) if isinstance(raw.get("quota"), dict) else {}
        groups = quota_info.get("groups", []) if isinstance(quota_info.get("groups"), list) else []

        model_group = str(raw.get("model_group", "gemini-shared"))
        windows: list[dict[str, Any]] = []

        if groups:
            for g in groups:
                if isinstance(g, dict):
                    g_name = str(g.get("displayName", ""))
                    if "gemini" in g_name.lower():
                        model_group = g_name
                    buckets = g.get("buckets", [])
                    if isinstance(buckets, list):
                        for b in buckets:
                            if isinstance(b, dict):
                                rem = b.get("remaining_fraction")
                                if rem is None and "remainingFraction" in b:
                                    rem = b.get("remainingFraction")
                                reset_time = b.get("reset_time") or b.get("resetTime")
                                window_name = b.get("window") or b.get("name") or b.get("bucketId") or "unknown"
                                windows.append(
                                    {
                                        "remaining_fraction": rem,
                                        "reset_time": reset_time,
                                        "window": str(window_name),
                                    }
                                )
        else:
            raw_windows = raw.get("quota_windows") or raw.get("buckets") or []
            if isinstance(raw_windows, list):
                for w in raw_windows:
                    if isinstance(w, dict):
                        rem = w.get("remaining_fraction")
                        if rem is None and "remainingFraction" in w:
                            rem = w.get("remainingFraction")
                        reset_time = w.get("reset_time") or w.get("resetTime")
                        window_name = w.get("window") or w.get("name") or "unknown"
                        windows.append(
                            {
                                "remaining_fraction": rem,
                                "reset_time": reset_time,
                                "window": str(window_name),
                            }
                        )

            if not windows:
                if "five_hour" in raw or "fiveHour" in raw:
                    fh = raw.get("five_hour") or raw.get("fiveHour") or {}
                    windows.append(
                        {
                            "remaining_fraction": fh.get("remaining_fraction") or fh.get("remainingFraction"),
                            "reset_time": fh.get("reset_time") or fh.get("resetTime"),
                            "window": "5-hour",
                        }
                    )
                if "weekly" in raw:
                    wk = raw.get("weekly") or {}
                    windows.append(
                        {
                            "remaining_fraction": wk.get("remaining_fraction") or wk.get("remainingFraction"),
                            "reset_time": wk.get("reset_time") or wk.get("resetTime"),
                            "window": "weekly",
                        }
                    )

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return AgentUsageSnapshot.create(
            provider="antigravity",
            model_group=model_group,
            quota_windows=windows,
            captured_at=now_iso,
        )

    def verify_project_binding(
        self,
        task: AgentTask,
        cwd: str | None = None,
    ) -> dict[str, Any]:
        """Query projects(cwd=...) and verify exact match with task.project_binding."""
        target_cwd = (
            cwd
            or task.project_binding.get("cwd")
            or task.project_binding.get("workspace_identity")
            or task.project_binding.get("workspace_root", "")
        )
        if not target_cwd:
            raise ProjectBindingError(
                "Task project binding missing cwd / workspace_identity",
                details={"project_binding": dict(task.project_binding)},
            )

        resp = self._transport.call_tool("projects", {"cwd": target_cwd})
        if not isinstance(resp, dict):
            raise ProjectBindingError(
                f"Invalid projects response for cwd '{target_cwd}'",
                details={"response": str(resp)},
            )

        # Response may return {"project": {...}} or list of projects
        matched_proj: dict[str, Any] | None = None
        if "project" in resp and isinstance(resp["project"], dict):
            matched_proj = resp["project"]
        elif "projects" in resp and isinstance(resp["projects"], list):
            matching = [
                p for p in resp["projects"]
                if isinstance(p, dict)
                and (
                    p.get("cwd") == target_cwd
                    or target_cwd in (p.get("folders") or [])
                )
            ]
            if len(matching) == 1:
                matched_proj = matching[0]
            elif len(matching) > 1:
                raise ProjectBindingError(
                    f"Ambiguous matching projects for cwd '{target_cwd}': multiple found ({len(matching)})",
                    details={"matched_count": len(matching)},
                )
            else:
                raise ProjectBindingError(
                    f"No matching project found for cwd '{target_cwd}'",
                    details={"cwd": target_cwd},
                )
        else:
            raise ProjectBindingError(
                f"No matching project found for cwd '{target_cwd}'",
                details={"response": resp},
            )

        if not matched_proj:
            raise ProjectBindingError(
                f"No project resolved for cwd '{target_cwd}' (fail-closed, no selected project fallback)",
                details={"cwd": target_cwd},
            )

        expected_project_id = task.project_binding.get("project_id")
        actual_project_id = matched_proj.get("project_id") or matched_proj.get("id")
        if not actual_project_id or actual_project_id != expected_project_id:
            raise ProjectBindingError(
                f"ProjectBinding project_id mismatch: task expected '{expected_project_id}', resolved '{actual_project_id}'",
                details={
                    "actual_project_id": actual_project_id,
                    "expected_project_id": expected_project_id,
                },
            )

        return matched_proj

    def submit(
        self,
        task: AgentTask,
        route: AgentRoute,
        preparation: ExecutionPreparation | None = None,
        request_id: str | None = None,
    ) -> AgentExecutionHandle:
        """Submit an authorized task along its route, enforcing strict idempotency and boundary checks."""
        # 1. Independent boundary re-validation
        validate_task_hash(task.to_dict())
        validate_route_hash(route.to_dict())
        if preparation is not None:
            validate_preparation_hash(preparation.to_dict())
            if preparation.task_id != task.task_id:
                raise PermissionDeniedError("Preparation task_id does not match task.task_id")
            if preparation.route_id != route.route_id:
                raise PermissionDeniedError("Preparation route_id does not match route.route_id")

        # 2. Hard Invariant checks first: no nested agent, no trading authority
        for perm in list(task.authorized_permissions) + list(route.authorized_permissions):
            if "trading" in perm.lower() or "order" in perm.lower():
                raise PermissionDeniedError("Hard invariant violation: trading permissions prohibited")
            if "nested" in perm.lower() or "delegate_child" in perm.lower():
                raise PermissionDeniedError("Hard invariant violation: nested delegation prohibited")

        # 3. Role and model validation & consistency
        if task.role not in SUPPORTED_ROLES or route.role not in SUPPORTED_ROLES:
            raise PermissionDeniedError(f"Unsupported role for provider antigravity: {task.role}")
        if task.role != route.role:
            raise PermissionDeniedError(f"Role mismatch between Task ('{task.role}') and Route ('{route.role}')")
        if tuple(task.authorized_permissions) != tuple(route.authorized_permissions):
            raise PermissionDeniedError("Authorized permissions mismatch between Task and Route")
        if route.resolved_model not in SUPPORTED_MODELS:
            raise ProviderUnavailableError(f"Unsupported model: {route.resolved_model}")

        # 3. Transport exact identity validation
        if (
            route.transport_ref
            and route.transport_ref != self._transport.exact_ref
            and route.transport_ref != self._transport.descriptor.connection_profile_ref
        ):
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Route transport_ref '{route.transport_ref}' does not match provider transport '{self._transport.exact_ref}'",
            )

        # 4. ProjectBinding exact verification
        self.verify_project_binding(task)

        # 6. Request ID determination and Idempotency Enforcement
        effective_req_id = request_id
        if not effective_req_id:
            raw_hash_source = f"{task.task_id}:{route.route_id}:{task.task_content_hash}"
            digest = hashlib.sha256(raw_hash_source.encode("utf-8")).hexdigest()
            effective_req_id = f"req-{digest[:16]}"

        sub_key = (task.task_id, effective_req_id)
        task_prompt = getattr(task, "prompt", None) or getattr(task, "objective", "")
        payload_signature = hashlib.sha256(
            json.dumps(
                {
                    "permissions": list(task.authorized_permissions),
                    "prompt": task_prompt,
                    "request_id": effective_req_id,
                    "task_id": task.task_id,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

        # Check existing submission with same (task_id, request_id)
        if sub_key in self._submissions:
            existing = self._submissions[sub_key]
            if existing["payload_signature"] == payload_signature:
                # Safe idempotent return of existing handle
                existing_job_id = existing["job_id"]
                return AgentExecutionHandle(
                    handle_id=f"handle-{existing_job_id}",
                    task_ref=dict(task.to_dict()),
                    route_ref=dict(route.to_dict()),
                    provider_job_ref=existing_job_id,
                    status=self._job_statuses.get(existing_job_id, "SUBMITTED"),
                )
            else:
                # Same request_id with different input rejected
                raise ProviderError(
                    ProviderErrorCode.SUBMISSION_FAILED,
                    f"Same request_id '{effective_req_id}' for task '{task.task_id}' with different payload rejected",
                    details={"request_id": effective_req_id, "task_id": task.task_id},
                )

        # Duplicate submission prevention: If task already has active/running job
        if task.task_id in self._active_jobs:
            active_job_id = self._active_jobs[task.task_id]
            current_status = self._job_statuses.get(active_job_id, "RUNNING")
            if current_status not in {"COMPLETED", "FAILED", "CANCELLED", "REJECTED_BY_ACCEPTANCE"}:
                raise ProviderError(
                    ProviderErrorCode.SUBMISSION_FAILED,
                    f"Duplicate submission prevented: task '{task.task_id}' already has active job '{active_job_id}' (status={current_status})",
                    details={"active_job_id": active_job_id, "task_id": task.task_id},
                )

        # 7. Real MCP submission
        submit_args = {
            "cwd": (
                task.project_binding.get("cwd")
                or task.project_binding.get("workspace_identity")
                or task.project_binding.get("workspace_root", "")
            ),
            "mode": "research" if "research" in task.role else "implement",
            "prompt": task_prompt,
            "request_id": effective_req_id,
            "task_id": task.task_id,
            "timeout_seconds": 600,
        }
        resp = self._transport.call_tool("submit", submit_args)
        if not isinstance(resp, dict) or ("job_id" not in resp and "id" not in resp):
            raise ProviderError(
                ProviderErrorCode.SUBMISSION_FAILED,
                "submit tool failed to return durable job_id",
                details={"response": resp},
            )

        job_id = str(resp.get("job_id") or resp.get("id"))
        handle = AgentExecutionHandle(
            handle_id=f"handle-{job_id}",
            task_ref=dict(task.to_dict()),
            route_ref=dict(route.to_dict()),
            provider_job_ref=job_id,
            status="SUBMITTED",
        )

        # Persist submission and active job state
        self._submissions[sub_key] = {
            "job_id": job_id,
            "payload_signature": payload_signature,
            "submitted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._active_jobs[task.task_id] = job_id
        self._job_statuses[job_id] = "SUBMITTED"
        self._job_metadata[job_id] = {
            "effective_req_id": effective_req_id,
            "project_binding": dict(task.project_binding),
            "route": route,
            "task": task,
        }

        # 8. Append-only audit record
        self._record_audit_event(
            task=task,
            route=route,
            job_id=job_id,
            terminal_status="SUBMITTED",
            acceptance_status=None,
        )

        return handle

    def status(self, handle: AgentExecutionHandle) -> str:
        """Query execution status of the job via MCP status tool."""
        job_id = handle.provider_job_ref
        try:
            resp = self._transport.call_tool("status", {"job_id": job_id})
        except ProviderError as e:
            if e.code == ProviderErrorCode.EXECUTION_UNCERTAIN:
                return "UNCERTAIN"
            raise

        if not isinstance(resp, dict):
            return "UNCERTAIN"

        raw_status = str(resp.get("status") or resp.get("state") or "").upper()
        mapped = "UNCERTAIN"
        if raw_status in ("QUEUED", "SUBMITTED"):
            mapped = "SUBMITTED"
        elif raw_status in ("EXECUTING", "RUNNING"):
            mapped = "RUNNING"
        elif raw_status in ("COMPLETED", "TURN_COMPLETE", "DONE"):
            mapped = "COMPLETED"
        elif raw_status in ("FAILED", "ERROR"):
            mapped = "FAILED"
        elif raw_status in ("CANCEL_REQUESTED",):
            mapped = "CANCEL_REQUESTED"
        elif raw_status in ("CANCELLED", "CANCELED"):
            mapped = "CANCELLED"
        elif not raw_status:
            mapped = self._job_statuses.get(job_id, "RUNNING")

        self._job_statuses[job_id] = mapped
        return mapped

    def watch(
        self,
        handle: AgentExecutionHandle,
        cursor: int = 0,
        timeout_seconds: float = 600.0,
        on_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Watch ongoing execution on the SAME job_id using watch/events."""
        job_id = handle.provider_job_ref
        resolver = self._transport.discover_tools()

        if resolver.has_operation("watch"):
            return self._transport.call_tool(
                "watch",
                {"cursor": cursor, "job_id": job_id, "timeout_seconds": timeout_seconds},
                timeout_seconds=timeout_seconds + 5,
            )
        # Fallback to events probe if watch is not registered in catalog
        return self._transport.call_tool("events", {"cursor": cursor, "job_id": job_id})

    def result(
        self,
        handle: AgentExecutionHandle,
        preparation: ExecutionPreparation | None = None,
    ) -> AgentResult:
        """Retrieve terminal execution result, preserving tool failures and binding exactness."""
        job_id = handle.provider_job_ref
        meta = self._job_metadata.get(job_id, {})
        task: AgentTask | None = meta.get("task")
        route: AgentRoute | None = meta.get("route")

        resp = self._transport.call_tool("result", {"job_id": job_id})
        if not isinstance(resp, dict):
            raise ResultAcceptanceError(
                f"Invalid result payload returned for job '{job_id}'",
                details={"response": resp},
            )

        # 1. Exact job binding and task binding verification
        resp_job_id = resp.get("job_id") or resp.get("provider_job_ref")
        if not resp_job_id or resp_job_id != job_id:
            raise ResultAcceptanceError(
                f"Result job_id mismatch: expected '{job_id}', got '{resp_job_id}' (fail closed)",
                details={"expected_job_id": job_id, "received_job_id": resp_job_id},
            )

        resp_task_id = resp.get("task_id") or (
            resp.get("task_ref", {}).get("task_id") if isinstance(resp.get("task_ref"), dict) else None
        )
        expected_task_id = (
            handle.task_ref.get("task_id")
            if isinstance(handle.task_ref, dict)
            else (task.task_id if task else None)
        )
        if resp_task_id and expected_task_id and resp_task_id != expected_task_id:
            raise ResultAcceptanceError(
                f"Result task_id mismatch: expected '{expected_task_id}', got '{resp_task_id}' (wrong-result binding prevented)",
                details={"expected_task_id": expected_task_id, "received_task_id": resp_task_id},
            )

        # 2. Extract tool issues and error history
        tool_failures: list[str] = []
        raw_issues = resp.get("tool_failures") or resp.get("tool_issues") or resp.get("issues") or []
        if isinstance(raw_issues, list):
            tool_failures.extend([str(x) for x in raw_issues])
        elif isinstance(raw_issues, str) and raw_issues.strip():
            tool_failures.append(raw_issues)

        recovery = resp.get("recovery") or {}
        error_history = recovery.get("error_history") or []
        for err in error_history:
            tool_failures.append(f"Historical error: {err}")

        # 3. Provider SUCCESS != Acceptance SUCCESS
        raw_status = str(resp.get("status") or resp.get("terminal_status") or "COMPLETED").upper()
        uncertainty: str | None = None
        acceptance_status: str = "ACCEPTED"
        terminal_status = TerminalStatus.SUCCESS

        if raw_status in ("CANCELLED", "CANCELED"):
            terminal_status = TerminalStatus.CANCELLED
            acceptance_status = "CANCELLED"
        elif raw_status in ("FAILED", "ERROR"):
            terminal_status = TerminalStatus.FAILED
            acceptance_status = "REJECTED_BY_ACCEPTANCE"
        elif raw_status in ("UNCERTAIN", "WORKER_LOST"):
            terminal_status = TerminalStatus.UNCERTAIN
            uncertainty = "Execution outcome uncertain"
            acceptance_status = "REJECTED_BY_ACCEPTANCE"
        elif tool_failures:
            # Model self SUCCESS with unresolved tool issues rejected by acceptance
            terminal_status = TerminalStatus.REJECTED_BY_ACCEPTANCE
            acceptance_status = "REJECTED_BY_ACCEPTANCE"
            uncertainty = f"Execution contains {len(tool_failures)} tool failure(s)"
        else:
            terminal_status = TerminalStatus.SUCCESS
            acceptance_status = "ACCEPTED"

        # 4. Actual model provenance
        actual_model = resp.get("actual_model") or resp.get("model") or (route.resolved_model if route else "unknown")

        # 5. Build AgentResult
        structured_out = (
            resp.get("structured_output")
            or resp.get("result")
            or resp.get("output")
            or ({"response": resp["response"]} if resp.get("response") is not None else None)
        )
        if not isinstance(structured_out, dict):
            structured_out = {"output": structured_out} if structured_out is not None else None

        agent_result = AgentResult.create(
            task_ref=dict(handle.task_ref),
            route_ref=dict(handle.route_ref),
            provider_job_ref=job_id,
            terminal_status=terminal_status,
            raw_result_ref=f"mcp://antigravity-local-desktop/jobs/{job_id}/result",
            structured_output=structured_out,
            tool_failures=tool_failures,
            uncertainty=uncertainty,
            acceptance_status=acceptance_status,
        )

        self._job_statuses[job_id] = terminal_status.value

        # 6. Append-only audit record
        audit_task = task if task is not None else handle.task_ref
        audit_route = route if route is not None else handle.route_ref
        if audit_task is not None and audit_route is not None:
            self._record_audit_event(
                task=audit_task,
                route=audit_route,
                job_id=job_id,
                terminal_status=terminal_status.value,
                acceptance_status=acceptance_status,
                actual_model=actual_model,
                result=agent_result,
            )

        return agent_result

    def cancel(self, handle: AgentExecutionHandle) -> bool:
        """Request cancellation for this bridge-owned job; records CANCEL_REQUESTED."""
        job_id = handle.provider_job_ref
        try:
            _ = self._transport.call_tool("cancel", {"job_id": job_id})
            self._job_statuses[job_id] = "CANCEL_REQUESTED"
            meta = self._job_metadata.get(job_id, {})
            task = meta.get("task")
            route = meta.get("route")
            audit_task = task if task is not None else handle.task_ref
            audit_route = route if route is not None else handle.route_ref
            if audit_task is not None and audit_route is not None:
                self._record_audit_event(
                    task=audit_task,
                    route=audit_route,
                    job_id=job_id,
                    terminal_status="CANCEL_REQUESTED",
                    acceptance_status="CANCEL_REQUESTED",
                )
            return True
        except Exception:  # noqa: BLE001
            self._job_statuses[job_id] = "UNCERTAIN"
            return False

    def message(
        self,
        handle: AgentExecutionHandle,
        prompt: str,
        request_id: str,
        timeout_seconds: float = 600.0,
    ) -> AgentExecutionHandle:
        """Continue a finished work block's SAME conversation; active tasks return TASK_BUSY."""
        current_status = self.status(handle)
        if current_status in ("RUNNING", "SUBMITTED"):
            raise ProviderError(
                ProviderErrorCode.EXECUTION_FAILED,
                f"Cannot message task '{handle.task_ref.get('task_id')}': task is active (TASK_BUSY)",
            )

        task_id = handle.task_ref.get("task_id", "")
        args = {
            "prompt": prompt,
            "request_id": request_id,
            "task_id": task_id,
            "timeout_seconds": timeout_seconds,
        }
        resp = self._transport.call_tool("message", args)
        if not isinstance(resp, dict) or "job_id" not in resp:
            raise ProviderError(
                ProviderErrorCode.EXECUTION_FAILED,
                "message tool failed to return new job_id",
            )
        new_job_id = str(resp["job_id"])
        new_handle = AgentExecutionHandle(
            handle_id=f"handle-{new_job_id}",
            task_ref=dict(handle.task_ref),
            route_ref=dict(handle.route_ref),
            provider_job_ref=new_job_id,
            status="SUBMITTED",
        )
        self._active_jobs[task_id] = new_job_id
        self._job_statuses[new_job_id] = "SUBMITTED"
        return new_handle

    def _record_audit_event(
        self,
        task: AgentTask | dict[str, Any],
        route: AgentRoute | dict[str, Any],
        job_id: str,
        terminal_status: str,
        acceptance_status: str | None,
        actual_model: str | None = None,
        result: AgentResult | None = None,
    ) -> None:
        """Create and append an immutable, tamper-resistant AgentAuditRecord."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        res_ref = {"result_id": result.result_id} if result else None
        task_dict = task.to_dict() if hasattr(task, "to_dict") else dict(task)
        route_dict = route.to_dict() if hasattr(route, "to_dict") else dict(route)
        role = getattr(task, "role", None) or task_dict.get("role", "code_researcher")
        task_id = getattr(task, "task_id", None) or task_dict.get("task_id", "")
        resolved_model = (
            actual_model
            or getattr(route, "resolved_model", None)
            or route_dict.get("resolved_model", "Gemini 3.8 Flash High")
        )
        binding = getattr(task, "project_binding", None) or task_dict.get("project_binding", {})
        req_perms = getattr(task, "requested_permissions", None) or task_dict.get("requested_permissions", ())
        auth_perms = getattr(task, "authorized_permissions", None) or task_dict.get("authorized_permissions", ())

        record = AgentAuditRecord.create(
            role=role,
            provider="antigravity",
            resolved_model=resolved_model,
            policy_version="research_lab.agent_policy.v1",
            task_ref=dict(task_dict),
            route_ref=dict(route_dict),
            provider_job_ref=job_id,
            project_binding=dict(binding),
            input_refs=[{"task_id": task_id}],
            requested_permissions=list(req_perms),
            authorized_permissions=list(auth_perms),
            usage_snapshot_ref=None,
            terminal_status=terminal_status,
            result_ref=res_ref,
            acceptance_status=acceptance_status,
            recorded_at=now_iso,
        )
        self._audit_trail.append(record)
