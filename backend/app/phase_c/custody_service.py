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
from phase_b_workers.contracts import (
    HealthSnapshot,
    ReadinessSnapshot,
    WorkerIdentity,
    isoformat,
)
from phase_b_workers.projections import build_projection, publish_projection

from app.phase_c.adapters import (
    ExpectedVersionError,
    IdempotencyConflictError,
    WorkflowAdapterError,
)
from app.phase_c.models import (
    CustodyReceiptDTO,
    SignedArtifactUploadDTO,
    TrustedKeylessTargetPlanUploadDTO,
)
from shared.artifact_contracts.v1 import ContractError as ArtifactContractError
from shared.artifact_contracts.v1 import validate_artifact_envelope
from shared.artifact_custody.v1 import ArtifactCustody, CustodyError
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    TargetPlan,
)
from shared.phase_c_workflow.v1 import (
    ARTIFACT_POLICY,
    PhaseCWorkflowError,
    validate_phase_c_artifact,
)
from shared.trust_contracts.v1 import canonical_json_line


def _schema(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")


def _target_plan_schema(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise TypeError("target plan payload must be an object")
    TargetPlan.from_mapping(payload)


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
    # Execution receives a distinct read-only credential.  The Control secret
    # can never be used to retrieve an order-bearing target-plan artifact.
    execution_read_secret: str = ""
    projection_dir: Path | None = None
    trusted_keyless_simnow_enabled: bool = False

    @classmethod
    def from_env(cls) -> CustodySettings:
        root = Path(os.environ["PHASE_C_CUSTODY_ROOT"])
        secret = os.environ["PHASE_C_CUSTODY_SHARED_SECRET"].strip()
        execution_read_secret = os.environ[
            "PHASE_C_CUSTODY_EXECUTION_READ_SECRET"
        ].strip()
        projection_raw = os.getenv("PHASE_C_CUSTODY_PROJECTION_DIR", "").strip()
        projection_dir = Path(projection_raw) if projection_raw else None
        policies_json = os.getenv("PHASE_C_CUSTODY_POLICIES_JSON", "").strip()
        keyless_only = os.getenv("SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED", "").lower() in {
            "1",
            "true",
            "yes",
        }
        raw = json.loads(policies_json) if policies_json else {}
        if (
            not root.is_absolute()
            or not secret
            or not execution_read_secret
            or hmac.compare_digest(secret, execution_read_secret)
            or not isinstance(raw, dict)
            or (projection_dir is not None and not projection_dir.is_absolute())
        ):
            raise RuntimeError("Phase C custody configuration is invalid")
        policies = (
            {domain: CustodyPolicy(**raw[domain]) for domain in ARTIFACT_POLICY}
            if raw
            else {}
        )
        if (not raw and not keyless_only) or (raw and set(raw) != set(ARTIFACT_POLICY)) or any(
            not item.keyring_path.startswith("/")
            or len(item.keyring_raw_sha256) != 64
            or not item.key_purpose
            for item in policies.values()
        ):
            raise RuntimeError("Phase C custody trust policy is invalid")
        return cls(
            root,
            os.getenv("PHASE_C_CUSTODY_WRITER_ID", "artifact-custody"),
            int(os.environ["PHASE_C_CUSTODY_WRITER_EPOCH"]),
            secret,
            # ``phase-c-execution`` remains receipt-only for the preserved
            # offline E2E.  It has neither publish nor artifact-read access.
            frozenset({"control-api", "phase-c-execution"}),
            policies,
            execution_read_secret,
            projection_dir,
            keyless_only,
        )


class ArtifactCustodyService:
    """A narrow request façade over the durable Phase B ``ArtifactCustody``."""

    def __init__(self, settings: CustodySettings) -> None:
        self.settings = settings

    def _custody(self) -> ArtifactCustody:
        return ArtifactCustody(
            self.settings.root,
            writer_id=self.settings.writer_id,
            writer_epoch=self.settings.writer_epoch,
            schema_registry={
                **{
                    schema: _schema
                    for _kind, schema, _purpose in ARTIFACT_POLICY.values()
                },
                TARGET_PLAN_SCHEMA_VERSION: _target_plan_schema,
                KEYLESS_TARGET_PLAN_SCHEMA_VERSION: _target_plan_schema,
            },
        )

    @staticmethod
    def _receipt(
        raw: dict[str, Any], *, signed: dict[str, Any], keyring_raw_sha256: str
    ) -> CustodyReceiptDTO:
        artifact = signed["artifact"]
        return CustodyReceiptDTO(
            receipt_id=raw["receipt_id"],
            receipt_type="install",
            artifact_id=raw["artifact_id"],
            artifact_type=artifact["artifact_type"],
            trust_domain=artifact["trust_domain"],
            schema_ref=artifact["schema_ref"],
            artifact_sha256=raw["artifact_raw_sha256"],
            custody_version=raw["resulting_version"],
            idempotency_key=raw["idempotency_key"],
            signer_key_id=signed["signer_key_id"],
            signer_key_version=signed["signer_key_version"],
            keyring_raw_sha256=keyring_raw_sha256,
            signed_artifact_sha256=hashlib.sha256(
                canonical_json_line(signed)
            ).hexdigest(),
            scope=artifact["scope"],
            expires_at=signed["expires_at"],
        )

    def publish_install(
        self, payload: SignedArtifactUploadDTO, *, principal: str
    ) -> CustodyReceiptDTO:
        try:
            signed = payload.signed_artifact
            if signed.get("request_id") != payload.signing_request_id:
                raise WorkflowAdapterError(
                    "signed artifact request_id does not match upload request"
                )
            domain = signed.get("domain")
            if not isinstance(domain, str) or domain not in self.settings.policies:
                raise WorkflowAdapterError("signed artifact domain is not allowlisted")
            validate_phase_c_artifact(signed.get("artifact"), domain=domain)
            policy = self.settings.policies[domain]
            with self._custody() as custody:
                published = custody.publish_signed(
                    signed,
                    keyring_path=policy.keyring_path,
                    expected_domain=domain,
                    expected_key_purpose=policy.key_purpose,
                    expected_keyring_raw_sha256=policy.keyring_raw_sha256,
                    actor_id=principal,
                    idempotency_key=payload.idempotency_key,
                    correlation_id=payload.correlation_id,
                    expected_version=payload.expected_custody_version,
                )
                installed = custody.record(
                    "install",
                    published["artifact_id"],
                    actor_id=principal,
                    idempotency_key=f"install-{payload.idempotency_key}",
                    correlation_id=payload.correlation_id,
                    expected_version=published["resulting_version"],
                )
                return self._receipt(
                    installed,
                    signed=signed,
                    keyring_raw_sha256=policy.keyring_raw_sha256,
                )
        except CustodyError as exc:
            if exc.code == "CUSTODY_EXPECTED_VERSION_MISMATCH":
                raise ExpectedVersionError(exc.code) from exc
            if "IDEMPOTENCY" in exc.code:
                raise IdempotencyConflictError(exc.code) from exc
            raise WorkflowAdapterError(exc.code) from exc
        except PhaseCWorkflowError as exc:
            raise WorkflowAdapterError(
                "signed artifact violates Phase C allowlist"
            ) from exc

    @staticmethod
    def _keyless_receipt(raw: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
        payload = artifact["payload"]
        return {
            "receipt_id": raw["receipt_id"],
            "receipt_type": "install",
            "artifact_id": raw["artifact_id"],
            "artifact_type": "simnow-target-plan",
            "trust_domain": "runtime_authorization",
            "schema_ref": KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
            "artifact_sha256": artifact["raw_sha256"],
            "scope": payload["scope"],
            "expires_at": payload["expires_at"],
            "custody_version": raw["resulting_version"],
            "idempotency_key": raw["idempotency_key"],
            "verified": True,
            "installed": True,
            "custody_writer": "artifact-custody",
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }

    def publish_trusted_keyless_target_plan(
        self, payload: TrustedKeylessTargetPlanUploadDTO, *, principal: str
    ) -> dict[str, Any]:
        """Create-only custody install for the one fixed local SIMNOW tuple."""

        if not self.settings.trusted_keyless_simnow_enabled:
            raise WorkflowAdapterError("trusted keyless SIMNOW custody is disabled")
        try:
            artifact = validate_artifact_envelope(payload.artifact)
            plan = TargetPlan.from_mapping(artifact["payload"])
            if (
                not plan.is_trusted_keyless_simnow
                or artifact["artifact_type"] != "simnow-target-plan"
                or artifact["trust_domain"] != "runtime_authorization"
                or artifact["schema_ref"] != KEYLESS_TARGET_PLAN_SCHEMA_VERSION
                or artifact["scope"] != TRUSTED_KEYLESS_SIMNOW_SCOPE
                or artifact["scope"] != plan.raw["scope"]
            ):
                raise WorkflowAdapterError("keyless target plan tuple is invalid")
            with self._custody() as custody:
                published = custody.publish(
                    artifact,
                    actor_id=principal,
                    idempotency_key=payload.idempotency_key,
                    correlation_id=payload.correlation_id,
                    expected_version=payload.expected_custody_version,
                )
                installed = custody.record(
                    "install",
                    str(published["artifact_id"]),
                    actor_id=principal,
                    idempotency_key=f"install-{payload.idempotency_key}",
                    correlation_id=payload.correlation_id,
                    expected_version=int(published["resulting_version"]),
                )
            return self._keyless_receipt(installed, artifact)
        except CustodyError as exc:
            if exc.code == "CUSTODY_EXPECTED_VERSION_MISMATCH":
                raise ExpectedVersionError(exc.code) from exc
            if "IDEMPOTENCY" in exc.code:
                raise IdempotencyConflictError(exc.code) from exc
            raise WorkflowAdapterError(exc.code) from exc
        except (ArtifactContractError, CommodityExecutionContractError) as exc:
            raise WorkflowAdapterError("keyless target plan artifact is invalid") from exc

    def receipt(self, receipt_id: str) -> CustodyReceiptDTO | dict[str, Any] | None:
        try:
            with self._custody() as custody:
                raw = custody.read_receipt(receipt_id)
                artifact = custody.read_artifact(raw["artifact_id"])
                if raw["receipt_type"] == "install" and artifact.get("schema_ref") == KEYLESS_TARGET_PLAN_SCHEMA_VERSION:
                    return self._keyless_receipt(raw, artifact)
                signed = custody.read_signed_artifact(raw["artifact_id"])
            policy = self.settings.policies[signed["domain"]]
            return (
                self._receipt(
                    raw, signed=signed, keyring_raw_sha256=policy.keyring_raw_sha256
                )
                if raw["receipt_type"] == "install"
                else None
            )
        except CustodyError as exc:
            if exc.code == "CUSTODY_RECEIPT_NOT_FOUND":
                return None
            raise WorkflowAdapterError(exc.code) from exc

    def receipt_by_idempotency(
        self, idempotency_key: str
    ) -> CustodyReceiptDTO | dict[str, Any] | None:
        try:
            with self._custody() as custody:
                raw = custody.read_receipt_by_idempotency(f"install-{idempotency_key}")
                artifact = custody.read_artifact(raw["artifact_id"])
                if raw["receipt_type"] == "install" and artifact.get("schema_ref") == KEYLESS_TARGET_PLAN_SCHEMA_VERSION:
                    return self._keyless_receipt(raw, artifact)
                signed = custody.read_signed_artifact(raw["artifact_id"])
            policy = self.settings.policies[signed["domain"]]
            return (
                self._receipt(
                    raw, signed=signed, keyring_raw_sha256=policy.keyring_raw_sha256
                )
                if raw["receipt_type"] == "install"
                else None
            )
        except CustodyError as exc:
            if exc.code == "CUSTODY_RECEIPT_NOT_FOUND":
                return None
            raise WorkflowAdapterError(exc.code) from exc

    def artifact_for_execution(self, artifact_id: str) -> dict[str, Any] | None:
        """Return one verified target-plan envelope to Execution only.

        This is deliberately narrower than the custody ledger: it neither
        exposes records nor allows Control to inspect order-bearing payloads.
        """

        try:
            with self._custody() as custody:
                artifact = custody.read_artifact(artifact_id)
            if (
                not isinstance(artifact, dict)
                or artifact.get("artifact_type") != "simnow-target-plan"
                or artifact.get("trust_domain") != "runtime_authorization"
            ):
                raise WorkflowAdapterError("custody artifact is not an execution target plan")
            if artifact.get("schema_ref") == TARGET_PLAN_SCHEMA_VERSION:
                with self._custody() as custody:
                    signed = custody.read_signed_artifact(artifact_id)
                artifact = signed.get("artifact")
            elif artifact.get("schema_ref") != KEYLESS_TARGET_PLAN_SCHEMA_VERSION:
                raise WorkflowAdapterError("custody artifact is not an execution target plan")
            if not isinstance(artifact, dict):
                raise WorkflowAdapterError("custody artifact is not an execution target plan")
            raw = canonical_json_line(artifact)
            return {
                "artifact_id": artifact_id,
                "artifact_raw_sha256": hashlib.sha256(raw).hexdigest(),
                "artifact": artifact,
            }
        except CustodyError as exc:
            if exc.code in {
                "CUSTODY_ARTIFACT_NOT_FOUND",
                "CUSTODY_SIGNED_ARTIFACT_NOT_FOUND",
                "CUSTODY_ARTIFACT_ID_INVALID",
            }:
                return None
            raise WorkflowAdapterError(exc.code) from exc

    def publish_projection(self) -> None:
        """Emit the monitor-only custody health projection when configured."""

        if self.settings.projection_dir is None:
            return
        checked_at = isoformat()
        with self._custody() as custody:
            audit = custody.audit()
        projection = build_projection(
            service_id="artifact-custody",
            generation=f"custody-v{audit['version']}",
            health=HealthSnapshot(
                service_id="artifact-custody",
                status="healthy",
                checked_at_utc=checked_at,
                process_started_at_utc=checked_at,
                dependencies={"ledger_version": audit["version"]},
            ),
            readiness=ReadinessSnapshot(
                service_id="artifact-custody",
                ready=True,
                checked_at_utc=checked_at,
                version_compatible=True,
                config_loaded=True,
                dependencies_ready=True,
                state_recovered=True,
            ),
            version=WorkerIdentity.from_environment(
                "artifact-custody", runtime_mode="final-validation"
            ),
        )
        publish_projection(self.settings.projection_dir, projection)


def create_app(service: ArtifactCustodyService | None = None) -> FastAPI:
    target = service or ArtifactCustodyService(CustodySettings.from_env())
    app = FastAPI(title="Phase C Artifact Custody", docs_url=None, redoc_url=None)

    def control_auth(request: Request) -> str:
        secret = request.headers.get("X-Phase-C-Custody-Secret", "")
        principal = request.headers.get("X-Phase-C-Principal", "")
        if (
            not hmac.compare_digest(secret, target.settings.secret)
            or principal not in target.settings.allowed_principals
        ):
            raise HTTPException(401, "custody authentication failed")
        return principal

    def shared_receipt_auth(request: Request) -> str:
        secret = request.headers.get("X-Phase-C-Custody-Secret", "")
        principal = request.headers.get("X-Phase-C-Principal", "")
        if (
            not hmac.compare_digest(secret, target.settings.secret)
            or principal not in target.settings.allowed_principals
        ):
            raise HTTPException(401, "custody receipt authentication failed")
        return principal

    def execution_read_auth(request: Request) -> None:
        secret = request.headers.get("X-Phase-C-Custody-Secret", "")
        principal = request.headers.get("X-Phase-C-Principal", "")
        if (
            principal != "execution-orchestrator"
            or not target.settings.execution_read_secret
            or not hmac.compare_digest(secret, target.settings.execution_read_secret)
        ):
            raise HTTPException(401, "execution custody authentication failed")

    @app.post("/internal/v1/publish-install")
    def publish_install(
        payload: SignedArtifactUploadDTO, request: Request
    ) -> dict[str, Any]:
        try:
            return target.publish_install(payload, principal=control_auth(request)).model_dump(
                mode="json"
            )
        except WorkflowAdapterError as exc:
            raise HTTPException(exc.status_code, detail={"code": exc.code}) from exc

    @app.post("/internal/v1/publish-keyless-simnow-target-plan")
    def publish_keyless_simnow_target_plan(
        payload: TrustedKeylessTargetPlanUploadDTO, request: Request
    ) -> dict[str, Any]:
        try:
            return target.publish_trusted_keyless_target_plan(
                payload, principal=control_auth(request)
            )
        except WorkflowAdapterError as exc:
            raise HTTPException(exc.status_code, detail={"code": exc.code}) from exc

    @app.get("/internal/v1/receipts/{receipt_id}")
    def receipt(receipt_id: str, request: Request) -> dict[str, Any]:
        # Control may retain receipt evidence; Execution reads the exact same
        # receipt using its dedicated read-only credential.
        principal = request.headers.get("X-Phase-C-Principal", "")
        if principal == "execution-orchestrator":
            execution_read_auth(request)
        else:
            shared_receipt_auth(request)
        result = target.receipt(receipt_id)
        if result is None:
            raise HTTPException(404, "receipt not found")
        return result if isinstance(result, dict) else result.model_dump(mode="json")

    @app.get("/internal/v1/receipts-by-idempotency/{idempotency_key}")
    def receipt_by_idempotency(
        idempotency_key: str, request: Request
    ) -> dict[str, Any]:
        result = (
            target.receipt_by_idempotency(idempotency_key)
            if control_auth(request)
            else None
        )
        if result is None:
            raise HTTPException(404, "receipt not found")
        return result if isinstance(result, dict) else result.model_dump(mode="json")

    @app.get("/internal/v1/artifacts/{artifact_id}")
    def artifact(artifact_id: str, request: Request) -> dict[str, Any]:
        execution_read_auth(request)
        result = target.artifact_for_execution(artifact_id)
        if result is None:
            raise HTTPException(404, "artifact not found")
        return result

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {"status": "live", "production": False, "live_trading_authorized": False, "countable_forward": False}

    @app.get("/health/ready")
    def ready() -> dict[str, Any]:
        try:
            target.publish_projection()
        except (CustodyError, OSError) as exc:
            raise HTTPException(503, "custody durable state is unavailable") from exc
        return {"status": "ready", "production": False, "live_trading_authorized": False, "countable_forward": False}

    @app.get("/version")
    def version() -> dict[str, Any]:
        return {"service": "artifact-custody", "version": "issue-291-final", "production": False, "live_trading_authorized": False, "countable_forward": False}

    return app
