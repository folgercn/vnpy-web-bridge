"""Private Control API client for the Execution Orchestrator.

Only this client crosses the Control/Execution boundary.  It validates every
outgoing command against the shared typed model and validates every status
response against the frozen read-only projection schema.  In particular,
timeouts never retry a mutating request: callers may query the same receipt by
reusing its idempotency key instead.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from app.control_execution_projection import (
    ReceiptProjectionError,
    validate_command_response,
    validate_execution_receipt,
)
from app.execution.errors import CommandValidationError
from app.execution.models import CommandEnvelope, validate_identifier
from app.schemas.control_execution import (
    ExecutionCompletionProjection,
    ExecutionStatusProjection,
)


class ExecutionClientError(RuntimeError):
    """Base error for an unavailable or invalid Execution boundary."""

    status_code = 502
    code = "EXECUTION_UNAVAILABLE"

    def __init__(self, message: str, *, detail: Any = None) -> None:
        self.message = message
        self.detail = detail
        super().__init__(message)


class ExecutionTimeoutError(ExecutionClientError):
    status_code = 504
    code = "EXECUTION_UNKNOWN_OUTCOME"


class ExecutionUnknownOutcomeError(ExecutionClientError):
    """A command result is unknown and must be resolved by receipt query."""

    status_code = 503
    code = "EXECUTION_UNKNOWN_OUTCOME"


class ExecutionProtocolError(ExecutionClientError):
    status_code = 502
    code = "EXECUTION_PROTOCOL_ERROR"


class ExecutionRejectedError(ExecutionClientError):
    status_code = 409
    code = "EXECUTION_COMMAND_REJECTED"

    def __init__(
        self, message: str, *, status_code: int = 409, detail: Any = None
    ) -> None:
        super().__init__(message, detail=detail)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ExecutionClientSettings:
    """Environment-backed network settings for the private client."""

    base_url: str = "http://execution-orchestrator:8090"
    timeout_seconds: float = 5.0
    shared_secret: str = ""

    @classmethod
    def from_env(cls) -> ExecutionClientSettings:
        defaults = cls()
        base_url = (
            os.getenv("CONTROL_EXECUTION_BASE_URL")
            or os.getenv("EXECUTION_ORCHESTRATOR_URL")
            or defaults.base_url
        ).rstrip("/")
        raw_timeout = os.getenv(
            "CONTROL_EXECUTION_TIMEOUT_SECONDS", str(defaults.timeout_seconds)
        )
        try:
            timeout = max(0.1, min(float(raw_timeout), 60.0))
        except ValueError:
            timeout = defaults.timeout_seconds
        return cls(
            base_url=base_url,
            timeout_seconds=timeout,
            shared_secret=os.getenv("CONTROL_EXECUTION_SHARED_SECRET", "").strip(),
        )


def _unwrap(body: Any) -> Any:
    """Accept a raw contract response or the project's ``ok/data`` envelope."""

    if isinstance(body, Mapping) and body.get("ok") is True and "data" in body:
        return body["data"]
    return body


class ExecutionClient:
    """Strict, idempotent HTTP client for the private Execution API."""

    command_path = "/internal/v1/commands"
    status_path = "/internal/v1/status"
    completion_path = "/internal/v1/completions/latest"
    receipt_path = "/internal/v1/receipts"
    live_path = "/health/live"
    ready_path = "/health/ready"
    version_path = "/version"

    def __init__(
        self,
        settings: ExecutionClientSettings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings or ExecutionClientSettings.from_env()
        self._transport = transport

    def _url(self, path: str) -> str:
        return f"{self.settings.base_url}{path}"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        actor: Mapping[str, str] | None = None,
    ) -> Any:
        headers = {
            "Accept": "application/json",
            "X-Control-Service": "control-api",
        }
        if self.settings.shared_secret:
            headers["X-Control-Execution-Secret"] = self.settings.shared_secret
        if actor:
            headers["X-Control-Actor-Principal"] = str(actor["principal"])
            headers["X-Control-Actor-Role"] = str(actor["role"])
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.timeout_seconds,
                transport=self._transport,
                headers=headers,
            ) as client:
                response = await client.request(method, self._url(path), json=json_body)
        except (httpx.TimeoutException, asyncio.TimeoutError) as exc:
            raise ExecutionTimeoutError(
                "Execution 请求超时；结果未知，只能查询同一 receipt",
                detail={"path": path, "query_same_intent_only": True},
            ) from exc
        except httpx.HTTPError as exc:
            raise ExecutionClientError(
                "Execution 服务不可用",
                detail={"path": path, "error": str(exc)},
            ) from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise ExecutionProtocolError(
                "Execution 返回了非 JSON 响应",
                detail={"status_code": response.status_code},
            ) from exc
        body = _unwrap(body)
        if response.status_code >= 400:
            detail = (
                body.get("error", body.get("detail", body))
                if isinstance(body, Mapping)
                else body
            )
            message = (
                "Execution 命令被拒绝"
                if response.status_code < 500
                else "Execution 服务错误"
            )
            raise ExecutionRejectedError(
                message,
                status_code=response.status_code,
                detail=detail,
            )
        return body

    async def submit(
        self,
        command: CommandEnvelope | Mapping[str, Any],
    ) -> dict[str, Any]:
        """Submit one already-idempotent typed command without retries."""

        try:
            envelope = (
                command
                if isinstance(command, CommandEnvelope)
                else CommandEnvelope.model_validate(command)
            )
        except (CommandValidationError, ValueError, TypeError) as exc:
            raise ExecutionProtocolError(
                "Control→Execution command 不符合冻结 schema",
                detail={"error": str(exc)},
            ) from exc
        try:
            body = await self._request(
                "POST",
                self.command_path,
                json_body=envelope.model_dump(mode="json"),
                actor=envelope.actor.as_dict(),
            )
        except ExecutionTimeoutError as exc:
            detail = dict(exc.detail or {})
            detail.update(
                {
                    "idempotency_key": envelope.idempotency_key,
                    "query_receipt_path": f"{self.receipt_path}/{envelope.idempotency_key}",
                    "query_same_intent_only": True,
                }
            )
            raise ExecutionTimeoutError(exc.message, detail=detail) from exc
        except ExecutionRejectedError as exc:
            if exc.status_code < 500:
                raise
            detail = (
                dict(exc.detail or {})
                if isinstance(exc.detail, Mapping)
                else {"detail": exc.detail}
            )
            detail.update(
                {
                    "idempotency_key": envelope.idempotency_key,
                    "query_receipt_path": f"{self.receipt_path}/{envelope.idempotency_key}",
                    "query_same_intent_only": True,
                }
            )
            raise ExecutionUnknownOutcomeError(
                "Execution 命令结果未知；只能查询同一 durable receipt",
                detail=detail,
            ) from exc
        try:
            return validate_command_response(body)
        except ReceiptProjectionError as exc:
            raise ExecutionProtocolError(
                "Execution command receipt 不符合冻结合同",
                detail={"error": str(exc)},
            ) from exc

    async def receipt(
        self,
        idempotency_key: str,
        *,
        actor: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Query one durable receipt; this method never creates a command."""

        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ExecutionProtocolError(
                "idempotency_key is required for receipt query"
            )
        body = await self._request(
            "GET",
            f"{self.receipt_path}/{idempotency_key}",
            actor=actor,
        )
        try:
            return validate_execution_receipt(body)
        except ReceiptProjectionError as exc:
            raise ExecutionProtocolError(
                "Execution receipt 不符合冻结合同",
                detail={"error": str(exc)},
            ) from exc

    async def status(self) -> ExecutionStatusProjection:
        body = await self._request("GET", self.status_path)
        try:
            return ExecutionStatusProjection.model_validate(body)
        except (ValueError, TypeError) as exc:
            raise ExecutionProtocolError(
                "Execution status projection 不符合冻结 schema",
                detail={"error": str(exc)},
            ) from exc

    async def overview(self) -> dict[str, Any]:
        """Read the status projection; overview is never a second state source."""

        projection = await self.status()
        return projection.model_dump(mode="json")

    async def latest_completion(self) -> ExecutionCompletionProjection | None:
        """Read the latest immutable completion identity without mutation."""

        body = await self._request("GET", self.completion_path)
        if body is None:
            return None
        try:
            return ExecutionCompletionProjection.model_validate(body)
        except (ValueError, TypeError) as exc:
            raise ExecutionProtocolError(
                "Execution completion projection 不符合冻结 schema",
                detail={"error": str(exc)},
            ) from exc

    async def completion(self, plan_id: str) -> ExecutionCompletionProjection | None:
        """Read one exact historical completion identity without mutation."""

        try:
            validate_identifier(plan_id, "plan_id")
        except CommandValidationError as exc:
            raise ExecutionProtocolError(
                "Execution completion plan_id 不合法",
                detail={"error": str(exc)},
            ) from exc
        body = await self._request(
            "GET", f"{self.completion_path.rsplit('/', 1)[0]}/{plan_id}"
        )
        if body is None:
            return None
        try:
            return ExecutionCompletionProjection.model_validate(body)
        except (ValueError, TypeError) as exc:
            raise ExecutionProtocolError(
                "Execution completion projection 不符合冻结 schema",
                detail={"error": str(exc)},
            ) from exc

    async def ready(self) -> dict[str, Any]:
        """Run Execution's authenticated Gateway/durable-state readiness probe."""

        body = await self._request("GET", self.ready_path)
        if not isinstance(body, Mapping):
            raise ExecutionProtocolError(
                "Execution readiness response 必须是 JSON object"
            )
        if (
            body.get("service") != "execution-orchestrator"
            or body.get("status") != "ready"
        ):
            raise ExecutionProtocolError(
                "Execution readiness response 不符合冻结合同",
                detail={"status": body.get("status"), "service": body.get("service")},
            )
        return dict(body)

    async def probe(self, path: str = live_path) -> dict[str, Any]:
        """Probe reachability; business reconciliation is reported separately."""

        body = await self._request("GET", path)
        if not isinstance(body, Mapping):
            raise ExecutionProtocolError("Execution health response 必须是 JSON object")
        return dict(body)

    async def close(self) -> None:
        """Compatibility hook; requests use short-lived clients by design."""


execution_client = ExecutionClient()
ControlExecutionClient = ExecutionClient


__all__ = [
    "ControlExecutionClient",
    "ExecutionClient",
    "ExecutionClientError",
    "ExecutionClientSettings",
    "ExecutionProtocolError",
    "ExecutionRejectedError",
    "ExecutionTimeoutError",
    "ExecutionUnknownOutcomeError",
    "execution_client",
]
