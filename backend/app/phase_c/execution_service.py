"""Dedicated offline Phase C execution projection service (no trading imports)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request

from app.phase_c.adapters import (
    ExpectedVersionError,
    IdempotencyConflictError,
    WorkflowAdapterError,
)
from app.phase_c.models import (
    AuthorizationCommandDTO,
    AuthorizationStatusDTO,
    ExecutionProjectionDTO,
)
from shared.phase_c_workflow.v1 import canonical_json


@dataclass(frozen=True)
class ExecutionSettings:
    state_path: Path
    secret: str
    custody_url: str
    custody_secret: str

    @classmethod
    def from_env(cls) -> ExecutionSettings:
        return cls(
            Path(os.environ["PHASE_C_EXECUTION_STATE_PATH"]),
            os.environ["PHASE_C_EXECUTION_SHARED_SECRET"],
            os.environ["PHASE_C_CUSTODY_URL"],
            os.environ["PHASE_C_CUSTODY_SHARED_SECRET"],
        )


class PhaseCExecutionService:
    def __init__(self, settings: ExecutionSettings, *, receipt_lookup: Callable[[str], dict[str, Any] | None] | None = None) -> None:
        self.settings = settings
        self.receipt_lookup = receipt_lookup or self._remote_receipt
        self.settings.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _remote_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        try:
            with httpx.Client(timeout=3.0, headers={"X-Phase-C-Principal": "phase-c-execution", "X-Phase-C-Custody-Secret": self.settings.custody_secret}) as client:
                response = client.get(f"{self.settings.custody_url.rstrip('/')}/internal/v1/receipts/{receipt_id}")
        except httpx.HTTPError as exc:
            raise WorkflowAdapterError("custody receipt lookup outcome unknown") from exc
        if response.status_code == 404: return None
        if response.status_code != 200: raise WorkflowAdapterError("custody receipt lookup rejected")
        body = response.json()
        return body if isinstance(body, dict) else None

    def _load(self) -> dict[str, Any]:
        if not self.settings.state_path.exists():
            return {"version": 0, "requested_state": "DISABLED", "artifact_id": None, "receipt_id": None, "commands": {}, "audit": [], "archive": []}
        try:
            raw = self.settings.state_path.read_bytes()
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or set(envelope) != {"schema_version", "payload", "payload_sha256"} or envelope["schema_version"] != "phase-c-execution-state-v1":
                raise ValueError
            payload = envelope["payload"]
            if not isinstance(payload, dict) or hashlib.sha256(canonical_json(payload)).hexdigest() != envelope["payload_sha256"] or raw != canonical_json(envelope):
                raise ValueError
            required = {"version", "requested_state", "artifact_id", "receipt_id", "commands", "audit", "archive"}
            if set(payload) != required or not isinstance(payload["version"], int) or payload["requested_state"] not in {"DISABLED", "ENABLE_REQUESTED", "REVOKED"} or not isinstance(payload["commands"], dict) or not isinstance(payload["audit"], list) or not isinstance(payload["archive"], list):
                raise ValueError
            return payload
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise WorkflowAdapterError("phase-c execution durable state is invalid") from exc

    def _save(self, value: dict[str, Any]) -> None:
        payload = canonical_json(value)
        raw = canonical_json({"schema_version": "phase-c-execution-state-v1", "payload": value, "payload_sha256": hashlib.sha256(payload).hexdigest()})
        fd, name = tempfile.mkstemp(prefix=".phase-c-execution-", dir=self.settings.state_path.parent)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0: raise OSError("state write failed")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(name, self.settings.state_path)

    def status(self) -> AuthorizationStatusDTO:
        state = self._load()
        return AuthorizationStatusDTO(version=state["version"], requested_state=state["requested_state"], artifact_id=state["artifact_id"], receipt_id=state["receipt_id"])

    def command(self, request: AuthorizationCommandDTO, *, receipt: dict[str, Any]) -> AuthorizationStatusDTO:
        state = self._load(); fingerprint = hashlib.sha256(canonical_json(request.model_dump(mode="json"))).hexdigest()
        old = state["commands"].get(request.idempotency_key)
        if old:
            if old["fingerprint"] != fingerprint: raise IdempotencyConflictError("authorization idempotency conflict")
            return AuthorizationStatusDTO.model_validate(old["status"])
        if request.expected_version != state["version"]: raise ExpectedVersionError("authorization expected version conflict")
        if receipt.get("receipt_id") != request.custody_receipt_id or receipt.get("artifact_id") != request.authorization_artifact_id or receipt.get("receipt_type") != "install":
            raise WorkflowAdapterError("execution command lacks a verified custody install receipt")
        state["version"] += 1; state["requested_state"] = "ENABLE_REQUESTED" if request.action == "enable" else "REVOKED"; state["artifact_id"] = request.authorization_artifact_id; state["receipt_id"] = request.custody_receipt_id
        status = self.status_from(state).model_dump(mode="json")
        event = {"command_id": request.command_id, "idempotency_key": request.idempotency_key, "action": request.action, "version": state["version"], "runtime_mutation_allowed": False}
        state["commands"][request.idempotency_key] = {"fingerprint": fingerprint, "status": status}; state["audit"].append(event); state["archive"].append({"kind": "authorization-command", **event}); self._save(state)
        return AuthorizationStatusDTO.model_validate(status)

    @staticmethod
    def status_from(state: dict[str, Any]) -> AuthorizationStatusDTO:
        return AuthorizationStatusDTO(version=state["version"], requested_state=state["requested_state"], artifact_id=state["artifact_id"], receipt_id=state["receipt_id"])
    def receipt(self, key: str) -> AuthorizationStatusDTO | None:
        found = self._load()["commands"].get(key); return AuthorizationStatusDTO.model_validate(found["status"]) if found else None
    def projection(self) -> ExecutionProjectionDTO:
        state = self._load(); return ExecutionProjectionDTO(status="ARCHIVED" if state["archive"] else "OFFLINE", audit=state["audit"], archive=state["archive"])


def create_app(service: PhaseCExecutionService | None = None) -> FastAPI:
    if service is None: raise RuntimeError("Phase C execution requires explicit settings")
    app = FastAPI(title="Phase C Execution", docs_url=None, redoc_url=None)
    def auth(request: Request) -> None:
        if not hmac.compare_digest(request.headers.get("X-Phase-C-Execution-Secret", ""), service.settings.secret) or request.headers.get("X-Phase-C-Principal") != "control-api": raise HTTPException(401, "execution authentication failed")
    @app.get("/internal/v1/authorization/status")
    def status(request: Request) -> dict[str, Any]: auth(request); return service.status().model_dump(mode="json")
    @app.get("/internal/v1/authorization/receipts/{key}")
    def receipt(key: str, request: Request) -> dict[str, Any]:
        auth(request); result = service.receipt(key)
        if result is None: raise HTTPException(404, "receipt not found")
        return result.model_dump(mode="json")
    @app.post("/internal/v1/authorization/commands")
    def command(payload: AuthorizationCommandDTO, request: Request) -> dict[str, Any]:
        auth(request)
        try:
            receipt_value = service.receipt_lookup(payload.custody_receipt_id)
            if receipt_value is None: raise WorkflowAdapterError("custody receipt not found")
            return service.command(payload, receipt=receipt_value).model_dump(mode="json")
        except WorkflowAdapterError as exc:
            raise HTTPException(exc.status_code, detail={"code": exc.code}) from exc
    @app.get("/internal/v1/projection")
    def projection(request: Request) -> dict[str, Any]: auth(request); return service.projection().model_dump(mode="json")
    return app
