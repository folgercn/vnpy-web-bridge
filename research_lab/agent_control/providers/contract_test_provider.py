"""Deterministic In-Memory Test Provider for Boundary Verification (#573 Milestone 8).

Architecture Rule:
Role -> Access Control -> Agent Router -> Agent Provider (ContractTestProvider)
    -> Provider Transport (DirectSDKTestTransport)

Boundary Rules:
1. Pure in-memory, deterministic execution provider solely for contract/boundary verification.
2. Completely independent from Antigravity MCP; NO Antigravity adapter imports or coupling.
3. NEVER calls real network, never requires API keys, never connects to real trading accounts.
4. Preserves exact task/route/preparation contracts, durable job references, and idempotency.
5. Emits standard AgentResult envelopes; provider SUCCESS != scientific admission.
6. Unified error taxonomy; errors NEVER convert to scientific REJECT / CriticDecision / Evidence.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
from typing import Any

from research_lab.agent_control.contracts import (
    AgentExecutionHandle,
    AgentProviderDescriptor,
    AgentResult,
    AgentRoute,
    AgentTask,
    TerminalStatus,
    _clean_for_canonical,
    validate_route_hash,
    validate_scope_hash,
    validate_task_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
)
from research_lab.agent_control.handoff import (
    ExecutionPreparation,
    validate_preparation_hash,
)
from research_lab.agent_control.provider import ProviderAvailability
from research_lab.agent_control.transports.direct_sdk_test import (
    DEFAULT_DIRECT_SDK_CAPABILITIES,
    DirectSDKTestTransport,
)

CONTRACT_TEST_PROVIDER_NAME = "contract_test_provider"
CONTRACT_TEST_SUPPORTED_MODELS = (
    "test-model-standard",
    "test-model-large",
)
CONTRACT_TEST_DEFAULT_MODEL = "test-model-standard"
CONTRACT_TEST_SUPPORTED_ROLES = frozenset(
    {
        "alpha_generator",
        "code_researcher",
        "data_researcher",
        "external_researcher",
        "research_synthesizer",
    }
)


class ContractTestProvider:
    """Deterministic, in-memory execution provider satisfying the AgentProvider interface."""

    def __init__(
        self,
        transport: DirectSDKTestTransport | None = None,
        provider_name: str = CONTRACT_TEST_PROVIDER_NAME,
        supported_models: tuple[str, ...] = CONTRACT_TEST_SUPPORTED_MODELS,
        default_model: str = CONTRACT_TEST_DEFAULT_MODEL,
        supported_roles: frozenset[str] = CONTRACT_TEST_SUPPORTED_ROLES,
    ) -> None:
        self._provider_name = provider_name
        self._supported_models = supported_models
        self._default_model = default_model
        self._supported_roles = supported_roles
        self._transport = transport or DirectSDKTestTransport()

        # In-memory durable state storage
        self._submissions: dict[str, dict[str, Any]] = {}
        self._active_jobs: dict[str, str] = {}  # task_id -> job_id
        self._job_metadata: dict[str, dict[str, Any]] = {}
        self._job_statuses: dict[str, str] = {}
        self._job_outputs: dict[str, Any] = {}
        self._custom_availabilities: dict[str, ProviderAvailability] = {}
        self._failure_injections: dict[str, Exception] = {}
        self._cancel_confirmed_jobs: set[str] = set()

    def describe(self) -> AgentProviderDescriptor:
        """Return the static descriptor of this test provider."""
        return AgentProviderDescriptor(
            provider=self._provider_name,
            supported_roles=tuple(sorted(self._supported_roles)),
            supported_models=self._supported_models,
            default_model=self._default_model,
            capabilities=DEFAULT_DIRECT_SDK_CAPABILITIES,
        )

    def describe_transport(self) -> Any:
        """Return the transport connection descriptor."""
        return self._transport.descriptor

    @property
    def transport(self) -> DirectSDKTestTransport:
        return self._transport

    def set_availability(self, role: str, availability: ProviderAvailability) -> None:
        """Test hook to configure availability status for a role."""
        self._custom_availabilities[role] = availability

    def availability(
        self,
        role: str,
        context: dict[str, Any] | None = None,
    ) -> ProviderAvailability:
        """Check provider availability fail-closed."""
        if role in self._custom_availabilities:
            return self._custom_availabilities[role]

        if not self._transport.is_connected:
            return ProviderAvailability(
                is_available=False,
                status="UNAVAILABLE",
                reason=f"Transport '{self._transport.descriptor.connection_profile_ref}' is disconnected",
            )

        if role not in self._supported_roles:
            return ProviderAvailability(
                is_available=False,
                status="UNAVAILABLE",
                reason=f"Role '{role}' is not supported by {self._provider_name}",
            )

        return ProviderAvailability(
            is_available=True,
            status="AVAILABLE",
            reason=f"{self._provider_name} ready to serve role '{role}' via {self._transport.descriptor.exact_ref}",
        )

    def inject_failure(self, operation: str, exception: Exception) -> None:
        """Inject failure for a given operation ('submit', 'result', 'status', 'cancel')."""
        self._failure_injections[operation] = exception

    def clear_injections(self) -> None:
        self._failure_injections.clear()

    def set_configured_output(self, key: str, output: Any) -> None:
        """Configure structured output or raw text for a specific task_id or job_id."""
        self._job_outputs[key] = output

    def submit(
        self,
        task: AgentTask,
        route: AgentRoute,
        preparation: ExecutionPreparation | None = None,
        request_id: str | None = None,
    ) -> AgentExecutionHandle:
        """Submit task along route with strict boundary verification and durable idempotency."""
        # 0. Check injected failure
        if "submit" in self._failure_injections:
            raise self._failure_injections["submit"]

        # 1. Transport availability check
        if not self._transport.is_connected:
            raise ProviderUnavailableError(
                f"Transport for '{self._provider_name}' is disconnected or unavailable",
                details={"provider": self._provider_name},
            )

        # 2. Tamper checks fail-closed
        validate_task_hash(task.to_dict())
        validate_route_hash(route.to_dict())
        if task.authorization_scope_ref and isinstance(task.authorization_scope_ref, dict):
            validate_scope_hash(task.authorization_scope_ref)

        if preparation is not None:
            validate_preparation_hash(preparation.to_dict())
            if preparation.task_id != task.task_id:
                raise PermissionDeniedError(
                    f"Preparation task_id '{preparation.task_id}' does not match task '{task.task_id}'"
                )
            if preparation.route_id != route.route_id:
                raise PermissionDeniedError(
                    f"Preparation route_id '{preparation.route_id}' does not match route '{route.route_id}'"
                )
            if preparation.provider != self._provider_name:
                raise PermissionDeniedError(
                    f"Preparation provider '{preparation.provider}' does not match '{self._provider_name}'"
                )
            if preparation.model != route.resolved_model:
                raise PermissionDeniedError(
                    f"Preparation model '{preparation.model}' does not match route '{route.resolved_model}'"
                )
            if tuple(preparation.authorized_permissions) != tuple(task.authorized_permissions):
                raise PermissionDeniedError("Preparation permissions mismatch with task")
            if dict(preparation.project_binding) != dict(task.project_binding):
                raise PermissionDeniedError("Preparation project binding mismatch with task")

        # 3. Security & Invariant verification
        for perm in list(task.authorized_permissions) + list(route.authorized_permissions):
            if "trading" in perm.lower() or "order" in perm.lower():
                raise PermissionDeniedError("Hard invariant violation: trading permissions prohibited")
            if "nested" in perm.lower() or "delegate_child" in perm.lower():
                raise PermissionDeniedError("Hard invariant violation: nested delegation prohibited")

        # 4. Identity & Capability checks
        if task.role not in self._supported_roles:
            raise PermissionDeniedError(f"Role '{task.role}' not supported by provider '{self._provider_name}'")
        if task.role != route.role:
            raise PermissionDeniedError(f"Role mismatch between task ('{task.role}') and route ('{route.role}')")
        if route.provider != self._provider_name:
            raise PermissionDeniedError(
                f"Route provider '{route.provider}' does not match '{self._provider_name}'"
            )
        if route.resolved_model not in self._supported_models:
            raise PermissionDeniedError(
                f"Model '{route.resolved_model}' is not supported by '{self._provider_name}'"
            )
        if tuple(task.authorized_permissions) != tuple(route.authorized_permissions):
            raise PermissionDeniedError("Authorized permissions mismatch between Task and Route")

        effective_req_id = (request_id or "").strip() or f"req-{task.task_id}"
        sub_key = f"{effective_req_id}::{task.task_id}"

        # 5. Payload signature for idempotency
        payload_data = {
            "authorized_permissions": sorted(task.authorized_permissions),
            "model": route.resolved_model,
            "project_binding": dict(task.project_binding),
            "objective": getattr(task, "objective", getattr(task, "prompt", "")),
            "provider": self._provider_name,
            "role": task.role,
            "task_id": task.task_id,
        }
        payload_signature = hashlib.sha256(
            json.dumps(_clean_for_canonical(payload_data), sort_keys=True).encode("utf-8")
        ).hexdigest()

        # Check existing submission under same (request_id, task_id)
        if sub_key in self._submissions:
            existing = self._submissions[sub_key]
            if existing["payload_signature"] == payload_signature:
                existing_job_id = existing["job_id"]
                return AgentExecutionHandle(
                    handle_id=f"handle-{existing_job_id}",
                    task_ref=dict(task.to_dict()),
                    route_ref=dict(route.to_dict()),
                    provider_job_ref=existing_job_id,
                    status=self._job_statuses.get(existing_job_id, "SUBMITTED"),
                )
            raise ProviderError(
                ProviderErrorCode.SUBMISSION_FAILED,
                f"Conflicting payload for existing request_id '{effective_req_id}' on task '{task.task_id}'",
                details={"request_id": effective_req_id, "task_id": task.task_id},
            )

        # Duplicate submission check for currently active jobs
        if task.task_id in self._active_jobs:
            active_job_id = self._active_jobs[task.task_id]
            cur_status = self._job_statuses.get(active_job_id, "RUNNING")
            if cur_status not in {"COMPLETED", "FAILED", "CANCELLED", "REJECTED_BY_ACCEPTANCE"}:
                raise ProviderError(
                    ProviderErrorCode.SUBMISSION_FAILED,
                    f"Duplicate submission rejected: task '{task.task_id}' already has active job '{active_job_id}' (status={cur_status})",
                    details={"active_job_id": active_job_id, "task_id": task.task_id},
                )

        # 6. Generate durable job reference
        job_hash = hashlib.sha256(f"{task.task_id}::{effective_req_id}".encode()).hexdigest()[:10]
        job_id = f"testjob-{job_hash}"

        self._submissions[sub_key] = {
            "job_id": job_id,
            "payload_signature": payload_signature,
            "submitted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._active_jobs[task.task_id] = job_id
        self._job_statuses[job_id] = "COMPLETED"
        self._job_metadata[job_id] = {
            "effective_req_id": effective_req_id,
            "preparation": preparation,
            "route": route,
            "task": task,
        }

        # Invoke transport to record interaction
        self._transport.invoke(
            "execute",
            {
                "input": payload_data,
                "job_id": job_id,
                "request_id": effective_req_id,
            },
        )

        return AgentExecutionHandle(
            handle_id=f"handle-{job_id}",
            task_ref=dict(task.to_dict()),
            route_ref=dict(route.to_dict()),
            provider_job_ref=job_id,
            status="SUBMITTED",
        )

    def status(self, handle: AgentExecutionHandle) -> str:
        """Query execution status for an active handle."""
        if "status" in self._failure_injections:
            raise self._failure_injections["status"]

        job_id = handle.provider_job_ref
        if job_id not in self._job_statuses:
            return "UNCERTAIN"
        return self._job_statuses[job_id]

    def set_job_status(self, job_id: str, status: str) -> None:
        """Test hook to alter a job's status."""
        self._job_statuses[job_id] = status

    def cancel(self, handle: AgentExecutionHandle) -> bool:
        """Request cancellation of an active handle."""
        if "cancel" in self._failure_injections:
            raise self._failure_injections["cancel"]

        job_id = handle.provider_job_ref
        if job_id not in self._job_statuses:
            return False

        current = self._job_statuses[job_id]
        if current in {"COMPLETED", "FAILED", "CANCELLED"}:
            return False

        if job_id in self._cancel_confirmed_jobs:
            self._job_statuses[job_id] = "CANCELLED"
        else:
            self._job_statuses[job_id] = "CANCEL_REQUESTED"
        return True

    def confirm_cancel(self, job_id: str) -> None:
        """Simulate backend confirmed cancellation."""
        self._cancel_confirmed_jobs.add(job_id)
        self._job_statuses[job_id] = "CANCELLED"

    def result(
        self,
        handle: AgentExecutionHandle,
        preparation: ExecutionPreparation | None = None,
    ) -> AgentResult:
        """Retrieve terminal execution result and perform acceptance check."""
        if "result" in self._failure_injections:
            raise self._failure_injections["result"]

        job_id = handle.provider_job_ref
        meta = self._job_metadata.get(job_id, {})
        task: AgentTask | None = meta.get("task")
        route: AgentRoute | None = meta.get("route")

        if task is None or route is None:
            raise ProviderError(
                ProviderErrorCode.EXECUTION_FAILED,
                f"No submission metadata found for job '{job_id}'",
                details={"job_id": job_id},
            )

        job_status = self._job_statuses.get(job_id, "COMPLETED")

        # Check configured output by job_id or task_id
        configured = self._job_outputs.get(job_id, self._job_outputs.get(task.task_id))

        terminal_status = TerminalStatus.SUCCESS.value
        acceptance_status = "ACCEPTED"
        tool_failures: list[str] = []
        raw_result_ref: str | None = None
        structured_output: dict[str, Any] | None = None

        if job_status == "FAILED":
            terminal_status = TerminalStatus.FAILED.value
            acceptance_status = "REJECTED"
            tool_failures.append("Execution failure injected")
        elif job_status in {"CANCEL_REQUESTED", "CANCELLED"}:
            terminal_status = TerminalStatus.CANCELLED.value
            acceptance_status = "REJECTED"
        elif job_status == "UNCERTAIN":
            terminal_status = TerminalStatus.UNCERTAIN.value
            acceptance_status = "REJECTED"
            tool_failures.append("Execution state uncertain")
        elif configured is not None:
            if isinstance(configured, dict):
                structured_output = copy.deepcopy(configured)
                raw_result_ref = json.dumps(structured_output)
            elif isinstance(configured, str):
                raw_result_ref = configured
                # If valid json, also populate structured_output
                try:
                    loaded = json.loads(configured)
                    if isinstance(loaded, dict):
                        structured_output = loaded
                except (json.JSONDecodeError, TypeError, ValueError):
                    structured_output = {"text": configured}
            elif configured is False:
                # Explicit empty deliverable test
                raw_result_ref = ""
                structured_output = {}
        else:
            # Default minimal valid deliverable
            structured_output = {
                "output": f"Executed task '{task.task_id}' successfully by {self._provider_name}",
                "status": "SUCCESS",
            }
            raw_result_ref = json.dumps(structured_output)

        # Provider SUCCESS != Acceptance SUCCESS enforcement:
        # If terminal_status is SUCCESS but deliverable is empty, acceptance MUST reject
        if terminal_status == TerminalStatus.SUCCESS.value:
            has_content = False
            if raw_result_ref and raw_result_ref.strip() or structured_output and any(bool(v) for v in structured_output.values()):
                has_content = True

            if not has_content:
                acceptance_status = "REJECTED"
                tool_failures.append("Provider self-reported SUCCESS but delivered empty deliverable")

        # Create standard AgentResult
        agent_result = AgentResult.create(
            task_ref=dict(handle.task_ref),
            route_ref=dict(handle.route_ref),
            provider_job_ref=job_id,
            terminal_status=terminal_status,
            raw_result_ref=raw_result_ref,
            structured_output=structured_output,
            tool_failures=tool_failures,
            acceptance_status=acceptance_status,
        )

        return agent_result
