"""Private artifact-custody adapter; the custody ledger remains sole writer."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from app.phase_c.adapters import (
    ExpectedVersionError,
    IdempotencyConflictError,
    WorkflowAdapterError,
)
from app.phase_c.models import CustodyReceiptDTO, SignedArtifactUploadDTO
from shared.artifact_custody.v1 import ArtifactCustody, CustodyError
from shared.phase_c_workflow.v1 import (
    ARTIFACT_POLICY,
    PhaseCWorkflowError,
    validate_phase_c_artifact,
)
from shared.trust_contracts.v1 import canonical_json_line


def _schema(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")


@dataclass(frozen=True)
class CustodyPolicy:
    keyring_path: str
    keyring_raw_sha256: str
    key_purpose: str


@dataclass(frozen=True)
class CustodySettings:
    root: Path
    writer_id: str
    writer_epoch: int
    secret: str
    allowed_principals: frozenset[str]
    policies: dict[str, CustodyPolicy]

    @classmethod
    def from_env(cls) -> CustodySettings:
        root = Path(os.environ["PHASE_C_CUSTODY_ROOT"])
        secret = os.environ["PHASE_C_CUSTODY_SHARED_SECRET"].strip()
        raw = json.loads(os.environ["PHASE_C_CUSTODY_POLICIES_JSON"])
        if not root.is_absolute() or not secret or not isinstance(raw, dict):
            raise RuntimeError("Phase C custody configuration is invalid")
        policies = {
            domain: CustodyPolicy(**raw[domain]) for domain in ARTIFACT_POLICY
        }
        if set(raw) != set(ARTIFACT_POLICY) or any(
            not item.keyring_path.startswith("/") or len(item.keyring_raw_sha256) != 64 or not item.key_purpose
            for item in policies.values()
        ):
            raise RuntimeError("Phase C custody trust policy is invalid")
        return cls(root, os.getenv("PHASE_C_CUSTODY_WRITER_ID", "artifact-custody"), int(os.environ["PHASE_C_CUSTODY_WRITER_EPOCH"]), secret, frozenset({"control-api", "phase-c-execution"}), policies)


class ArtifactCustodyService:
    """A narrow request façade over the durable Phase B ``ArtifactCustody``."""

    def __init__(self, settings: CustodySettings) -> None:
        self.settings = settings

    def _custody(self) -> ArtifactCustody:
        return ArtifactCustody(
            self.settings.root,
            writer_id=self.settings.writer_id,
            writer_epoch=self.settings.writer_epoch,
            schema_registry={schema: _schema for _kind, schema, _purpose in ARTIFACT_POLICY.values()},
        )

    @staticmethod
    def _receipt(raw: dict[str, Any], *, signed: dict[str, Any], keyring_raw_sha256: str) -> CustodyReceiptDTO:
        artifact = signed["artifact"]
        return CustodyReceiptDTO(
            receipt_id=raw["receipt_id"], receipt_type="install", artifact_id=raw["artifact_id"],
            artifact_type=artifact["artifact_type"], trust_domain=artifact["trust_domain"], schema_ref=artifact["schema_ref"],
            artifact_sha256=raw["artifact_raw_sha256"], custody_version=raw["resulting_version"],
            idempotency_key=raw["idempotency_key"], signer_key_id=signed["signer_key_id"], signer_key_version=signed["signer_key_version"],
            keyring_raw_sha256=keyring_raw_sha256, signed_artifact_sha256=hashlib.sha256(canonical_json_line(signed)).hexdigest(), scope=artifact["scope"], expires_at=signed["expires_at"],
        )

    def publish_install(self, payload: SignedArtifactUploadDTO, *, principal: str) -> CustodyReceiptDTO:
        try:
            signed = payload.signed_artifact
            if signed.get("request_id") != payload.signing_request_id:
                raise WorkflowAdapterError("signed artifact request_id does not match upload request")
            domain = signed.get("domain")
            if not isinstance(domain, str) or domain not in self.settings.policies:
                raise WorkflowAdapterError("signed artifact domain is not allowlisted")
            validate_phase_c_artifact(signed.get("artifact"), domain=domain)
            policy = self.settings.policies[domain]
            with self._custody() as custody:
                published = custody.publish_signed(
                    signed, keyring_path=policy.keyring_path, expected_domain=domain,
                    expected_key_purpose=policy.key_purpose, expected_keyring_raw_sha256=policy.keyring_raw_sha256,
                    actor_id=principal, idempotency_key=payload.idempotency_key,
                    correlation_id=payload.correlation_id, expected_version=payload.expected_custody_version,
                )
                installed = custody.record(
                    "install", published["artifact_id"], actor_id=principal,
                    idempotency_key=f"install-{payload.idempotency_key}", correlation_id=payload.correlation_id,
                    expected_version=published["resulting_version"],
                )
                return self._receipt(installed, signed=signed, keyring_raw_sha256=policy.keyring_raw_sha256)
        except CustodyError as exc:
            if exc.code == "CUSTODY_EXPECTED_VERSION_MISMATCH":
                raise ExpectedVersionError(exc.code) from exc
            if "IDEMPOTENCY" in exc.code:
                raise IdempotencyConflictError(exc.code) from exc
            raise WorkflowAdapterError(exc.code) from exc
        except PhaseCWorkflowError as exc:
            raise WorkflowAdapterError("signed artifact violates Phase C allowlist") from exc

    def receipt(self, receipt_id: str) -> CustodyReceiptDTO | None:
        try:
            with self._custody() as custody:
                raw = custody.read_receipt(receipt_id)
                signed = custody.read_signed_artifact(raw["artifact_id"])
            policy = self.settings.policies[signed["domain"]]
            return self._receipt(raw, signed=signed, keyring_raw_sha256=policy.keyring_raw_sha256) if raw["receipt_type"] == "install" else None
        except CustodyError as exc:
            if exc.code == "CUSTODY_RECEIPT_NOT_FOUND":
                return None
            raise WorkflowAdapterError(exc.code) from exc

    def receipt_by_idempotency(self, idempotency_key: str) -> CustodyReceiptDTO | None:
        try:
            with self._custody() as custody:
                raw = custody.read_receipt_by_idempotency(f"install-{idempotency_key}")
                signed = custody.read_signed_artifact(raw["artifact_id"])
            policy = self.settings.policies[signed["domain"]]
            return self._receipt(raw, signed=signed, keyring_raw_sha256=policy.keyring_raw_sha256) if raw["receipt_type"] == "install" else None
        except CustodyError as exc:
            if exc.code == "CUSTODY_RECEIPT_NOT_FOUND":
                return None
            raise WorkflowAdapterError(exc.code) from exc


def create_app(service: ArtifactCustodyService | None = None) -> FastAPI:
    target = service or ArtifactCustodyService(CustodySettings.from_env())
    app = FastAPI(title="Phase C Artifact Custody", docs_url=None, redoc_url=None)

    def auth(request: Request) -> str:
        secret = request.headers.get("X-Phase-C-Custody-Secret", "")
        principal = request.headers.get("X-Phase-C-Principal", "")
        if not hmac.compare_digest(secret, target.settings.secret) or principal not in target.settings.allowed_principals:
            raise HTTPException(401, "custody authentication failed")
        return principal

    @app.post("/internal/v1/publish-install")
    def publish_install(payload: SignedArtifactUploadDTO, request: Request) -> dict[str, Any]:
        try:
            return target.publish_install(payload, principal=auth(request)).model_dump(mode="json")
        except WorkflowAdapterError as exc:
            raise HTTPException(exc.status_code, detail={"code": exc.code}) from exc

    @app.get("/internal/v1/receipts/{receipt_id}")
    def receipt(receipt_id: str, request: Request) -> dict[str, Any]:
        result = target.receipt(receipt_id) if auth(request) else None
        if result is None:
            raise HTTPException(404, "receipt not found")
        return result.model_dump(mode="json")
    @app.get("/internal/v1/receipts-by-idempotency/{idempotency_key}")
    def receipt_by_idempotency(idempotency_key: str, request: Request) -> dict[str, Any]:
        result = target.receipt_by_idempotency(idempotency_key) if auth(request) else None
        if result is None:
            raise HTTPException(404, "receipt not found")
        return result.model_dump(mode="json")
    return app
