"""Private artifact-custody adapter; the custody ledger remains sole writer."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
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
    ContinuousEventPublicationProjectionDTO,
    CustodyCurrentVersionDTO,
    CustodyReceiptDTO,
    SignedArtifactUploadDTO,
    TargetPlanCustodyReceiptEvidenceDTO,
    TargetPlanPublicationProjectionDTO,
    TrustedKeylessContinuousEventArtifactDTO,
    TrustedKeylessContinuousEventInstallContinuationDTO,
    TrustedKeylessContinuousEventReceiptDTO,
    TrustedKeylessContinuousEventUploadDTO,
    TrustedKeylessTargetPlanInstallContinuationDTO,
    TrustedKeylessTargetPlanUploadDTO,
)
from shared.artifact_contracts.v1 import ContractError as ArtifactContractError
from shared.artifact_contracts.v1 import validate_artifact_envelope
from shared.artifact_custody.v1 import ArtifactCustody, CustodyError
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
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
from shared.phase_c_workflow.continuous_event_v1 import (
    CONTINUOUS_EVENT_ARTIFACT_TYPE,
    CONTINUOUS_EVENT_SCHEMA_VERSION,
    CONTINUOUS_EVENT_SCOPE,
    CONTINUOUS_EVENT_TRUST_DOMAIN,
    ContinuousEventContractError,
    validate_simnow_continuous_event_v1,
)
from shared.trust_contracts.v1 import canonical_json_line


class CustodyEvidenceReadError(WorkflowAdapterError):
    """Permanent custody evidence/contract damage on a read-only path."""

    status_code = 503


class TargetPlanPublicationNotFoundError(WorkflowAdapterError):
    """Install-only continuation has no immutable publish predecessor."""

    code = "PHASE_C_TARGET_PLAN_PUBLICATION_NOT_FOUND"


class ContinuousEventPublicationNotFoundError(WorkflowAdapterError):
    """Install-only continuation has no immutable event publication."""

    code = "PHASE_C_CONTINUOUS_EVENT_PUBLICATION_NOT_FOUND"


class CustodyWriterBusyError(WorkflowAdapterError):
    """The single custody writer is temporarily occupied by another request."""

    code = "PHASE_C_CUSTODY_WRITER_BUSY"
    status_code = 503


_PHASE_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


_RETRYABLE_CUSTODY_READ_CODES = frozenset(
    {
        "CUSTODY_DIRECTORY_INVALID",
        "CUSTODY_DIRECTORY_PERMISSIONS_INVALID",
        "CUSTODY_FILE_CHANGED_DURING_READ",
        "CUSTODY_FILE_READ_FAILED",
        "CUSTODY_ROOT_NOT_PINNED",
        "CUSTODY_ROOT_PERMISSIONS_INVALID",
        "CUSTODY_WRITER_ALREADY_ACTIVE",
    }
)


def _raise_custody_read_failure(exc: CustodyError, *, subject: str) -> None:
    if exc.code == "CUSTODY_WRITER_ALREADY_ACTIVE":
        raise CustodyWriterBusyError(
            "custody writer is temporarily busy; retry the exact same intent"
        ) from exc
    if exc.code in _RETRYABLE_CUSTODY_READ_CODES:
        raise WorkflowAdapterError(
            f"custody {subject} read is unavailable", status_code=503
        ) from exc
    raise CustodyEvidenceReadError(
        f"custody {subject} evidence is invalid: {exc.code}"
    ) from exc


def _raise_custody_mutation_failure(exc: CustodyError) -> None:
    if exc.code == "CUSTODY_EXPECTED_VERSION_MISMATCH":
        raise ExpectedVersionError(exc.code) from exc
    if "IDEMPOTENCY" in exc.code:
        raise IdempotencyConflictError(exc.code) from exc
    if exc.code == "CUSTODY_WRITER_ALREADY_ACTIVE":
        raise CustodyWriterBusyError(
            "custody writer is temporarily busy; retry the exact same intent"
        ) from exc
    raise WorkflowAdapterError(exc.code) from exc


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
        keyless_only = os.getenv(
            "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED", ""
        ).lower() in {
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
        if (
            (not raw and not keyless_only)
            or (raw and set(raw) != set(ARTIFACT_POLICY))
            or any(
                not item.keyring_path.startswith("/")
                or len(item.keyring_raw_sha256) != 64
                or not item.key_purpose
                for item in policies.values()
            )
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

    def _custody(self, *, read_only: bool = False) -> ArtifactCustody:
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
                KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION: _target_plan_schema,
                KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION: _target_plan_schema,
                CONTINUOUS_EVENT_SCHEMA_VERSION: validate_simnow_continuous_event_v1,
            },
            read_only=read_only,
        )

    def _read_root_absent(self) -> bool:
        """Classify a never-initialized root without creating any state."""

        try:
            self.settings.root.lstat()
        except FileNotFoundError:
            return True
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody durable root is unavailable", status_code=503
            ) from exc
        return False

    @staticmethod
    def _phase_idempotency_key(value: str) -> str:
        if (
            not isinstance(value, str)
            or len(value.encode("utf-8")) > 128
            or _PHASE_IDEMPOTENCY_RE.fullmatch(value) is None
        ):
            raise WorkflowAdapterError("target-plan idempotency key is invalid")
        return value

    @staticmethod
    def _receipt_sha256(receipt: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json_line(receipt)).hexdigest()

    @staticmethod
    def _trusted_keyless_target_plan(
        value: dict[str, Any],
    ) -> tuple[dict[str, Any], TargetPlan]:
        try:
            artifact = validate_artifact_envelope(value)
            plan = TargetPlan.from_mapping(artifact["payload"])
        except (ArtifactContractError, CommodityExecutionContractError) as exc:
            raise WorkflowAdapterError(
                "keyless target plan artifact is invalid"
            ) from exc
        if (
            not plan.is_trusted_keyless_simnow
            or artifact["artifact_type"] != "simnow-target-plan"
            or artifact["trust_domain"] != "runtime_authorization"
            or artifact["schema_ref"]
            not in {
                KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
                KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
                KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
            }
            or artifact["schema_ref"] != plan.raw["schema_version"]
            or artifact["scope"] != TRUSTED_KEYLESS_SIMNOW_SCOPE
            or artifact["scope"] != plan.raw["scope"]
        ):
            raise WorkflowAdapterError("keyless target plan tuple is invalid")
        return artifact, plan

    @staticmethod
    def _trusted_keyless_continuous_event(
        value: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            artifact = validate_artifact_envelope(value)
            payload = validate_simnow_continuous_event_v1(artifact["payload"])
        except (ArtifactContractError, ContinuousEventContractError) as exc:
            raise WorkflowAdapterError(
                "keyless continuous event artifact is invalid"
            ) from exc
        if (
            artifact["artifact_type"] != CONTINUOUS_EVENT_ARTIFACT_TYPE
            or artifact["trust_domain"] != CONTINUOUS_EVENT_TRUST_DOMAIN
            or artifact["schema_ref"] != CONTINUOUS_EVENT_SCHEMA_VERSION
            or artifact["scope"] != CONTINUOUS_EVENT_SCOPE
            or artifact["generated_at"] != payload["verified_at"]
            or artifact["predecessor_refs"]
            or artifact["lineage"]
        ):
            raise WorkflowAdapterError("keyless continuous event tuple is invalid")
        return artifact, payload

    @staticmethod
    def _assert_receipt_artifact_binding(
        receipt: dict[str, Any],
        artifact: dict[str, Any],
        *,
        receipt_type: str,
        idempotency_key: str,
    ) -> None:
        if (
            receipt.get("receipt_type") != receipt_type
            or receipt.get("idempotency_key") != idempotency_key
            or receipt.get("artifact_id") != artifact["artifact_id"]
            or receipt.get("artifact_type") != artifact["artifact_type"]
            or receipt.get("trust_domain") != artifact["trust_domain"]
            or receipt.get("artifact_canonical_sha256") != artifact["canonical_sha256"]
            or receipt.get("artifact_raw_sha256") != artifact["raw_sha256"]
            or receipt.get("schema_ref") != artifact["schema_ref"]
            or receipt.get("predecessor_refs") != artifact["predecessor_refs"]
            or receipt.get("lineage") != artifact["lineage"]
        ):
            raise CustodyEvidenceReadError(
                "custody target-plan receipt/artifact binding is invalid"
            )

    @staticmethod
    def _read_optional_receipt(
        custody: ArtifactCustody, idempotency_key: str
    ) -> dict[str, Any] | None:
        try:
            return custody.read_receipt_by_idempotency(idempotency_key)
        except CustodyError as exc:
            if exc.code == "CUSTODY_RECEIPT_NOT_FOUND":
                return None
            raise

    def current_version(self) -> CustodyCurrentVersionDTO:
        """Read the sole ledger CAS version without creating custody state."""

        root = self.settings.root
        try:
            if not root.exists():
                version = 0
            else:
                root_stat = root.lstat()
                if (
                    not root.is_absolute()
                    or root.resolve() != root
                    or not stat.S_ISDIR(root_stat.st_mode)
                    or stat.S_IMODE(root_stat.st_mode) != 0o700
                ):
                    raise WorkflowAdapterError("custody durable root is invalid")
                entries = {entry.name for entry in root.iterdir()}
                if not entries:
                    version = 0
                else:
                    required = {
                        ".writer.lock",
                        ".tmp",
                        "artifacts",
                        "epochs",
                        "receipts",
                    }
                    if entries != required or not any((root / "epochs").iterdir()):
                        raise WorkflowAdapterError(
                            "custody durable state is incomplete"
                        )
                    with self._custody(read_only=True) as custody:
                        version = int(custody.audit()["version"])
            return CustodyCurrentVersionDTO(version=version)
        except WorkflowAdapterError:
            raise
        except (CustodyError, OSError, TypeError, ValueError) as exc:
            raise WorkflowAdapterError("custody durable state is unavailable") from exc

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
            _raise_custody_mutation_failure(exc)
        except PhaseCWorkflowError as exc:
            raise WorkflowAdapterError(
                "signed artifact violates Phase C allowlist"
            ) from exc

    @staticmethod
    def _keyless_receipt(
        raw: dict[str, Any], artifact: dict[str, Any]
    ) -> dict[str, Any]:
        payload = artifact["payload"]
        return {
            "receipt_id": raw["receipt_id"],
            "receipt_type": "install",
            "artifact_id": raw["artifact_id"],
            "artifact_type": "simnow-target-plan",
            "trust_domain": "runtime_authorization",
            "schema_ref": artifact["schema_ref"],
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
            artifact, _plan = self._trusted_keyless_target_plan(payload.artifact)
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
            _raise_custody_mutation_failure(exc)
        except (ArtifactContractError, CommodityExecutionContractError) as exc:
            raise WorkflowAdapterError(
                "keyless target plan artifact is invalid"
            ) from exc

    def target_plan_publication(
        self, idempotency_key: str
    ) -> TargetPlanPublicationProjectionDTO:
        """Project one publish/install pair without mutating custody state."""

        key = self._phase_idempotency_key(idempotency_key)
        install_key = f"install-{key}"
        if self._read_root_absent():
            return TargetPlanPublicationProjectionDTO(
                state="NOT_PUBLISHED",
                idempotency_key=key,
                install_idempotency_key=install_key,
                observed_custody_version=0,
            )
        try:
            # Once the root path exists, only ArtifactCustody's shared lock may
            # classify it.  A concurrently initializing/locked or incomplete
            # root is unavailable, never a stale NOT_PUBLISHED observation.
            with self._custody(read_only=True) as custody:
                observed_version = int(custody.audit()["version"])
                published = self._read_optional_receipt(custody, key)
                installed = self._read_optional_receipt(custody, install_key)
                if published is None:
                    if installed is not None:
                        raise CustodyEvidenceReadError(
                            "custody install exists without its phase publication"
                        )
                    return TargetPlanPublicationProjectionDTO(
                        state="NOT_PUBLISHED",
                        idempotency_key=key,
                        install_idempotency_key=install_key,
                        observed_custody_version=observed_version,
                    )
                artifact = custody.read_artifact(str(published["artifact_id"]))
                try:
                    artifact, plan = self._trusted_keyless_target_plan(artifact)
                except WorkflowAdapterError as exc:
                    raise CustodyEvidenceReadError(
                        "custody target-plan publication artifact is invalid"
                    ) from exc
                self._assert_receipt_artifact_binding(
                    published,
                    artifact,
                    receipt_type="publish",
                    idempotency_key=key,
                )
                if installed is not None:
                    self._assert_receipt_artifact_binding(
                        installed,
                        artifact,
                        receipt_type="install",
                        idempotency_key=install_key,
                    )
                    if (
                        installed.get("actor_id") != published.get("actor_id")
                        or installed.get("correlation_id")
                        != published.get("correlation_id")
                        or installed.get("expected_version")
                        != published.get("resulting_version")
                    ):
                        raise CustodyEvidenceReadError(
                            "custody target-plan install lineage is invalid"
                        )
                common: dict[str, Any] = {
                    "state": (
                        "INSTALLED"
                        if installed is not None
                        else "PUBLISHED_NOT_INSTALLED"
                    ),
                    "idempotency_key": key,
                    "install_idempotency_key": install_key,
                    "observed_custody_version": observed_version,
                    "publisher_principal": published["actor_id"],
                    "correlation_id": published["correlation_id"],
                    "artifact_id": artifact["artifact_id"],
                    "artifact_canonical_sha256": artifact["canonical_sha256"],
                    "artifact_raw_sha256": artifact["raw_sha256"],
                    "artifact_schema_ref": artifact["schema_ref"],
                    "plan_schema_version": plan.raw["schema_version"],
                    "plan_id": plan.raw["plan_id"],
                    "plan_hash": plan.raw["plan_hash"],
                    "plan_phase": plan.raw["phase"],
                    "scope": plan.raw["scope"],
                    "plan_expires_at": plan.raw["expires_at"],
                    "publish_receipt_id": published["receipt_id"],
                    "publish_receipt_sha256": self._receipt_sha256(published),
                    "publish_expected_custody_version": published["expected_version"],
                    "publish_resulting_custody_version": published["resulting_version"],
                }
                if installed is not None:
                    common.update(
                        install_receipt_id=installed["receipt_id"],
                        install_receipt_sha256=self._receipt_sha256(installed),
                        install_expected_custody_version=installed["expected_version"],
                        install_resulting_custody_version=installed[
                            "resulting_version"
                        ],
                    )
                return TargetPlanPublicationProjectionDTO.model_validate(common)
        except CustodyEvidenceReadError:
            raise
        except CustodyError as exc:
            _raise_custody_read_failure(exc, subject="target-plan publication")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody target-plan publication read is unavailable",
                status_code=503,
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody target-plan publication evidence is invalid"
            ) from exc

    def install_published_trusted_keyless_target_plan(
        self,
        payload: TrustedKeylessTargetPlanInstallContinuationDTO,
        *,
        principal: str,
    ) -> dict[str, Any]:
        """Install the stored artifact bound by an exact publication receipt.

        The shared-lock projection is only an availability/preflight check.
        Every publication, envelope, schema and plan pin is re-read under the
        custody writer's exclusive lock immediately before the sole allowed
        mutation: ``record("install", ...)``.
        """

        if not self.settings.trusted_keyless_simnow_enabled:
            raise WorkflowAdapterError("trusted keyless SIMNOW custody is disabled")
        projection = self.target_plan_publication(payload.idempotency_key)
        if projection.state == "NOT_PUBLISHED":
            raise TargetPlanPublicationNotFoundError(
                "target-plan publication does not exist; install cannot continue"
            )
        if (
            payload.publisher_principal != principal
            or projection.publisher_principal != payload.publisher_principal
            or projection.correlation_id != payload.correlation_id
            or projection.publish_receipt_id != payload.publish_receipt_id
            or projection.publish_receipt_sha256 != payload.publish_receipt_sha256
            or projection.publish_expected_custody_version
            != payload.publish_expected_custody_version
            or projection.publish_resulting_custody_version
            != payload.publish_resulting_custody_version
            or projection.artifact_id != payload.artifact_id
            or projection.artifact_canonical_sha256 != payload.artifact_canonical_sha256
            or projection.artifact_raw_sha256 != payload.artifact_raw_sha256
            or projection.artifact_schema_ref != payload.artifact_schema_ref
            or projection.plan_schema_version != payload.plan_schema_version
            or projection.plan_id != payload.plan_id
            or projection.plan_hash != payload.plan_hash
            or projection.plan_phase != payload.plan_phase
            or projection.scope != payload.scope
            or projection.plan_expires_at != payload.plan_expires_at
        ):
            raise IdempotencyConflictError(
                "install continuation does not match the original publication"
            )
        try:
            with self._custody() as custody:
                published = custody.read_receipt_by_idempotency(payload.idempotency_key)
                published_by_id = custody.read_receipt(payload.publish_receipt_id)
                if canonical_json_line(published) != canonical_json_line(
                    published_by_id
                ):
                    raise CustodyEvidenceReadError(
                        "install continuation publication receipt is cross-spliced"
                    )
                stored_artifact = custody.read_artifact(str(published["artifact_id"]))
                try:
                    artifact, plan = self._trusted_keyless_target_plan(stored_artifact)
                except WorkflowAdapterError as exc:
                    raise CustodyEvidenceReadError(
                        "stored install continuation target-plan artifact is invalid"
                    ) from exc
                self._assert_receipt_artifact_binding(
                    published,
                    artifact,
                    receipt_type="publish",
                    idempotency_key=payload.idempotency_key,
                )
                if (
                    published["receipt_id"] != payload.publish_receipt_id
                    or self._receipt_sha256(published) != payload.publish_receipt_sha256
                    or published["actor_id"] != payload.publisher_principal
                    or payload.publisher_principal != principal
                    or published["correlation_id"] != payload.correlation_id
                    or published["expected_version"]
                    != payload.publish_expected_custody_version
                    or published["resulting_version"]
                    != payload.publish_resulting_custody_version
                    or artifact["artifact_id"] != payload.artifact_id
                    or artifact["canonical_sha256"] != payload.artifact_canonical_sha256
                    or artifact["raw_sha256"] != payload.artifact_raw_sha256
                    or artifact["schema_ref"] != payload.artifact_schema_ref
                    or plan.raw["schema_version"] != payload.plan_schema_version
                    or plan.raw["plan_id"] != payload.plan_id
                    or plan.raw["plan_hash"] != payload.plan_hash
                    or plan.raw["phase"] != payload.plan_phase
                    or plan.raw["scope"] != payload.scope.model_dump(mode="json")
                    or plan.raw["expires_at"] != payload.plan_expires_at
                ):
                    raise IdempotencyConflictError(
                        "install continuation publication binding changed"
                    )
                installed_before = self._read_optional_receipt(
                    custody, f"install-{payload.idempotency_key}"
                )
                if installed_before is not None:
                    self._assert_receipt_artifact_binding(
                        installed_before,
                        artifact,
                        receipt_type="install",
                        idempotency_key=f"install-{payload.idempotency_key}",
                    )
                    if (
                        installed_before["actor_id"] != principal
                        or installed_before["correlation_id"] != payload.correlation_id
                        or installed_before["expected_version"]
                        != payload.publish_resulting_custody_version
                    ):
                        raise CustodyEvidenceReadError(
                            "stored install continuation receipt binding is invalid"
                        )
                installed = custody.record(
                    "install",
                    artifact["artifact_id"],
                    actor_id=principal,
                    idempotency_key=f"install-{payload.idempotency_key}",
                    correlation_id=payload.correlation_id,
                    expected_version=payload.publish_resulting_custody_version,
                )
            return self._keyless_receipt(installed, artifact)
        except (CustodyEvidenceReadError, IdempotencyConflictError):
            raise
        except CustodyError as exc:
            _raise_custody_mutation_failure(exc)

    @staticmethod
    def _continuous_event_receipt(
        raw: dict[str, Any],
        artifact: dict[str, Any],
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        payload = artifact["payload"]
        return TrustedKeylessContinuousEventReceiptDTO(
            receipt_id=raw["receipt_id"],
            receipt_type="install",
            artifact_id=artifact["artifact_id"],
            artifact_type=CONTINUOUS_EVENT_ARTIFACT_TYPE,
            trust_domain=CONTINUOUS_EVENT_TRUST_DOMAIN,
            schema_ref=CONTINUOUS_EVENT_SCHEMA_VERSION,
            artifact_sha256=artifact["raw_sha256"],
            event_id=payload["event_id"],
            trigger_kind=payload["trigger_kind"],
            daily_official_day=payload["daily"]["official_day"],
            custody_version=raw["resulting_version"],
            idempotency_key=raw["idempotency_key"],
            verified=True,
            installed=True,
            custody_writer="artifact-custody",
        )

    def publish_trusted_keyless_continuous_event(
        self,
        payload: TrustedKeylessContinuousEventUploadDTO,
        *,
        principal: str,
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        """Create-only publish/install for one verified no-authority event."""

        if not self.settings.trusted_keyless_simnow_enabled:
            raise WorkflowAdapterError("trusted keyless SIMNOW custody is disabled")
        artifact, event = self._trusted_keyless_continuous_event(payload.artifact)
        if payload.idempotency_key != event["event_id"]:
            raise IdempotencyConflictError(
                "continuous event idempotency key does not bind event ID"
            )
        verified_at = datetime.fromisoformat(
            str(event["verified_at"]).removesuffix("Z") + "+00:00"
        )
        age = (datetime.now(timezone.utc) - verified_at).total_seconds()
        if age > 60 or age < -2:
            raise WorkflowAdapterError(
                "continuous event account verification is stale",
                code="PHASE_C_CONTINUOUS_EVENT_FACTS_STALE",
                status_code=409,
                retryable=False,
            )
        try:
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
                    artifact["artifact_id"],
                    actor_id=principal,
                    idempotency_key=f"install-{payload.idempotency_key}",
                    correlation_id=payload.correlation_id,
                    expected_version=published["resulting_version"],
                )
            return self._continuous_event_receipt(installed, artifact)
        except CustodyError as exc:
            _raise_custody_mutation_failure(exc)

    def continuous_event_publication(
        self,
        idempotency_key: str,
    ) -> ContinuousEventPublicationProjectionDTO:
        """Read one event's publish/install state without exposing raw bytes."""

        key = self._phase_idempotency_key(idempotency_key)
        install_key = f"install-{key}"
        if self._read_root_absent():
            return ContinuousEventPublicationProjectionDTO(
                state="NOT_PUBLISHED",
                idempotency_key=key,
                install_idempotency_key=install_key,
                observed_custody_version=0,
            )
        try:
            with self._custody(read_only=True) as custody:
                observed_version = int(custody.audit()["version"])
                published = self._read_optional_receipt(custody, key)
                installed = self._read_optional_receipt(custody, install_key)
                if published is None:
                    if installed is not None:
                        raise CustodyEvidenceReadError(
                            "custody event install exists without publication"
                        )
                    return ContinuousEventPublicationProjectionDTO(
                        state="NOT_PUBLISHED",
                        idempotency_key=key,
                        install_idempotency_key=install_key,
                        observed_custody_version=observed_version,
                    )
                artifact = custody.read_artifact(str(published["artifact_id"]))
                try:
                    artifact, event = self._trusted_keyless_continuous_event(artifact)
                except WorkflowAdapterError as exc:
                    raise CustodyEvidenceReadError(
                        "custody continuous event publication artifact is invalid"
                    ) from exc
                self._assert_receipt_artifact_binding(
                    published,
                    artifact,
                    receipt_type="publish",
                    idempotency_key=key,
                )
                if installed is not None:
                    self._assert_receipt_artifact_binding(
                        installed,
                        artifact,
                        receipt_type="install",
                        idempotency_key=install_key,
                    )
                    if (
                        installed.get("actor_id") != published.get("actor_id")
                        or installed.get("correlation_id")
                        != published.get("correlation_id")
                        or installed.get("expected_version")
                        != published.get("resulting_version")
                    ):
                        raise CustodyEvidenceReadError(
                            "custody continuous event install lineage is invalid"
                        )
                monthly = event["monthly"]
                daily = event["daily"]
                desired = event["desired_target"]
                facts = event["account_facts"]
                predecessor = event["predecessor"]
                common: dict[str, Any] = {
                    "state": (
                        "INSTALLED"
                        if installed is not None
                        else "PUBLISHED_NOT_INSTALLED"
                    ),
                    "idempotency_key": key,
                    "install_idempotency_key": install_key,
                    "observed_custody_version": observed_version,
                    "publisher_principal": published["actor_id"],
                    "correlation_id": published["correlation_id"],
                    "artifact_id": artifact["artifact_id"],
                    "artifact_canonical_sha256": artifact["canonical_sha256"],
                    "artifact_raw_sha256": artifact["raw_sha256"],
                    "artifact_schema_ref": artifact["schema_ref"],
                    "event_id": event["event_id"],
                    "source_event_raw_sha256": event["source_event_raw_sha256"],
                    "selection_id": event["selection_id"],
                    "selection_sha256": event["selection_sha256"],
                    "selection_raw_sha256": event["selection_raw_sha256"],
                    "candidate_id": event["candidate_id"],
                    "trigger_kind": event["trigger_kind"],
                    "monthly_final_target_sha256": monthly["final_target_sha256"],
                    "daily_artifact_id": daily["artifact_id"],
                    "daily_artifact_raw_sha256": daily["artifact_raw_sha256"],
                    "daily_official_day": daily["official_day"],
                    "desired_target_position_hash": desired["target_position_hash"],
                    "account_facts_id": facts["snapshot_id"],
                    "account_facts_sha256": facts["account_facts_sha256"],
                    "predecessor_mode": predecessor["mode"],
                    "predecessor_terminal_target_id": predecessor["terminal_target_id"],
                    "predecessor_terminal_target_raw_sha256": predecessor[
                        "terminal_target_raw_sha256"
                    ],
                    "publish_receipt_id": published["receipt_id"],
                    "publish_receipt_sha256": self._receipt_sha256(published),
                    "publish_expected_custody_version": published["expected_version"],
                    "publish_resulting_custody_version": published["resulting_version"],
                }
                if installed is not None:
                    common.update(
                        install_receipt_id=installed["receipt_id"],
                        install_receipt_sha256=self._receipt_sha256(installed),
                        install_expected_custody_version=installed["expected_version"],
                        install_resulting_custody_version=installed[
                            "resulting_version"
                        ],
                    )
                return ContinuousEventPublicationProjectionDTO.model_validate(common)
        except CustodyEvidenceReadError:
            raise
        except CustodyError as exc:
            _raise_custody_read_failure(exc, subject="continuous event publication")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody continuous event publication read is unavailable",
                status_code=503,
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody continuous event publication evidence is invalid"
            ) from exc

    def install_published_trusted_keyless_continuous_event(
        self,
        payload: TrustedKeylessContinuousEventInstallContinuationDTO,
        *,
        principal: str,
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        """Continue only an exact event install; never republish."""

        if not self.settings.trusted_keyless_simnow_enabled:
            raise WorkflowAdapterError("trusted keyless SIMNOW custody is disabled")
        projection = self.continuous_event_publication(payload.idempotency_key)
        if projection.state == "NOT_PUBLISHED":
            raise ContinuousEventPublicationNotFoundError(
                "continuous event publication does not exist"
            )
        artifact, event = self._trusted_keyless_continuous_event(payload.artifact)
        if payload.idempotency_key != event["event_id"]:
            raise IdempotencyConflictError(
                "continuous event idempotency key does not bind event ID"
            )
        monthly = event["monthly"]
        daily = event["daily"]
        desired = event["desired_target"]
        facts = event["account_facts"]
        predecessor = event["predecessor"]
        if (
            projection.publisher_principal != principal
            or projection.correlation_id != payload.correlation_id
            or projection.publish_receipt_id != payload.publish_receipt_id
            or projection.publish_receipt_sha256 != payload.publish_receipt_sha256
            or projection.publish_expected_custody_version
            != payload.publish_expected_custody_version
            or projection.publish_resulting_custody_version
            != payload.publish_resulting_custody_version
            or projection.artifact_id != artifact["artifact_id"]
            or projection.artifact_canonical_sha256 != artifact["canonical_sha256"]
            or projection.artifact_raw_sha256 != artifact["raw_sha256"]
            or projection.artifact_schema_ref != artifact["schema_ref"]
            or projection.event_id != event["event_id"]
            or projection.source_event_raw_sha256 != event["source_event_raw_sha256"]
            or projection.selection_id != event["selection_id"]
            or projection.selection_sha256 != event["selection_sha256"]
            or projection.selection_raw_sha256 != event["selection_raw_sha256"]
            or projection.candidate_id != event["candidate_id"]
            or projection.trigger_kind != event["trigger_kind"]
            or projection.monthly_final_target_sha256 != monthly["final_target_sha256"]
            or projection.daily_artifact_id != daily["artifact_id"]
            or projection.daily_artifact_raw_sha256 != daily["artifact_raw_sha256"]
            or projection.daily_official_day != daily["official_day"]
            or projection.desired_target_position_hash
            != desired["target_position_hash"]
            or projection.account_facts_id != facts["snapshot_id"]
            or projection.account_facts_sha256 != facts["account_facts_sha256"]
            or projection.predecessor_mode != predecessor["mode"]
            or projection.predecessor_terminal_target_id
            != predecessor["terminal_target_id"]
            or projection.predecessor_terminal_target_raw_sha256
            != predecessor["terminal_target_raw_sha256"]
        ):
            raise IdempotencyConflictError(
                "event install continuation does not match publication"
            )
        try:
            with self._custody() as custody:
                published = custody.read_receipt_by_idempotency(payload.idempotency_key)
                stored_artifact = custody.read_artifact(artifact["artifact_id"])
                if canonical_json_line(stored_artifact) != canonical_json_line(
                    artifact
                ):
                    raise CustodyEvidenceReadError(
                        "event continuation artifact bytes changed"
                    )
                self._assert_receipt_artifact_binding(
                    published,
                    artifact,
                    receipt_type="publish",
                    idempotency_key=payload.idempotency_key,
                )
                if (
                    published["receipt_id"] != payload.publish_receipt_id
                    or self._receipt_sha256(published) != payload.publish_receipt_sha256
                    or published["actor_id"] != principal
                    or published["correlation_id"] != payload.correlation_id
                    or published["expected_version"]
                    != payload.publish_expected_custody_version
                    or published["resulting_version"]
                    != payload.publish_resulting_custody_version
                ):
                    raise IdempotencyConflictError(
                        "event continuation publication binding changed"
                    )
                installed = custody.record(
                    "install",
                    artifact["artifact_id"],
                    actor_id=principal,
                    idempotency_key=f"install-{payload.idempotency_key}",
                    correlation_id=payload.correlation_id,
                    expected_version=payload.publish_resulting_custody_version,
                )
            return self._continuous_event_receipt(installed, artifact)
        except (CustodyEvidenceReadError, IdempotencyConflictError):
            raise
        except CustodyError as exc:
            _raise_custody_mutation_failure(exc)

    def installed_continuous_event(
        self,
        idempotency_key: str,
    ) -> TrustedKeylessContinuousEventArtifactDTO | None:
        """Read an installed event for Control; Execution has no route access."""

        key = self._phase_idempotency_key(idempotency_key)
        if self._read_root_absent():
            return None
        try:
            with self._custody(read_only=True) as custody:
                installed = custody.read_receipt_by_idempotency(f"install-{key}")
                artifact = custody.read_artifact(str(installed["artifact_id"]))
            artifact, _event = self._trusted_keyless_continuous_event(artifact)
            self._assert_receipt_artifact_binding(
                installed,
                artifact,
                receipt_type="install",
                idempotency_key=f"install-{key}",
            )
            return TrustedKeylessContinuousEventArtifactDTO(
                idempotency_key=key,
                artifact_id=artifact["artifact_id"],
                artifact_raw_sha256=hashlib.sha256(
                    canonical_json_line(artifact)
                ).hexdigest(),
                artifact=artifact,
            )
        except CustodyEvidenceReadError:
            raise
        except CustodyError as exc:
            if exc.code in {
                "CUSTODY_RECEIPT_NOT_FOUND",
                "CUSTODY_ARTIFACT_NOT_FOUND",
                "CUSTODY_ROOT_NOT_FOUND",
            }:
                return None
            _raise_custody_read_failure(exc, subject="continuous event")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody continuous event read is unavailable", status_code=503
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody continuous event evidence is invalid"
            ) from exc

    def target_plan_receipt_evidence(
        self, receipt_id: str
    ) -> TargetPlanCustodyReceiptEvidenceDTO | None:
        """Return pins for one immutable keyless publish/install receipt."""

        if self._read_root_absent():
            return None
        try:
            with self._custody(read_only=True) as custody:
                raw = custody.read_receipt(receipt_id)
                artifact = custody.read_artifact(str(raw["artifact_id"]))
            try:
                artifact, _plan = self._trusted_keyless_target_plan(artifact)
            except WorkflowAdapterError as exc:
                raise CustodyEvidenceReadError(
                    "custody target-plan receipt artifact is invalid"
                ) from exc
            receipt_type = raw.get("receipt_type")
            if receipt_type not in {"publish", "install"}:
                raise CustodyEvidenceReadError(
                    "custody target-plan receipt type is invalid"
                )
            self._assert_receipt_artifact_binding(
                raw,
                artifact,
                receipt_type=receipt_type,
                idempotency_key=str(raw["idempotency_key"]),
            )
            return TargetPlanCustodyReceiptEvidenceDTO(
                receipt_id=raw["receipt_id"],
                receipt_sha256=self._receipt_sha256(raw),
                receipt_type=receipt_type,
                artifact_id=artifact["artifact_id"],
                artifact_canonical_sha256=artifact["canonical_sha256"],
                artifact_raw_sha256=artifact["raw_sha256"],
                artifact_schema_ref=artifact["schema_ref"],
                actor_id=raw["actor_id"],
                idempotency_key=raw["idempotency_key"],
                correlation_id=raw["correlation_id"],
                expected_custody_version=raw["expected_version"],
                resulting_custody_version=raw["resulting_version"],
            )
        except CustodyEvidenceReadError:
            raise
        except CustodyError as exc:
            if exc.code in {
                "CUSTODY_RECEIPT_NOT_FOUND",
                "CUSTODY_ARTIFACT_NOT_FOUND",
                "CUSTODY_ROOT_NOT_FOUND",
            }:
                return None
            _raise_custody_read_failure(exc, subject="target-plan receipt")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody target-plan receipt read is unavailable", status_code=503
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody target-plan receipt evidence is invalid"
            ) from exc

    def receipt(
        self, receipt_id: str
    ) -> (
        CustodyReceiptDTO
        | TrustedKeylessContinuousEventReceiptDTO
        | dict[str, Any]
        | None
    ):
        if self._read_root_absent():
            return None
        try:
            with self._custody(read_only=True) as custody:
                raw = custody.read_receipt(receipt_id)
                artifact = custody.read_artifact(raw["artifact_id"])
                if raw["receipt_type"] == "install" and artifact.get("schema_ref") in {
                    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
                    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
                    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
                }:
                    return self._keyless_receipt(raw, artifact)
                if (
                    raw["receipt_type"] == "install"
                    and artifact.get("schema_ref") == CONTINUOUS_EVENT_SCHEMA_VERSION
                ):
                    artifact, _event = self._trusted_keyless_continuous_event(artifact)
                    return self._continuous_event_receipt(raw, artifact)
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
            if exc.code in {"CUSTODY_RECEIPT_NOT_FOUND", "CUSTODY_ROOT_NOT_FOUND"}:
                return None
            _raise_custody_read_failure(exc, subject="receipt")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody receipt read is unavailable", status_code=503
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody receipt evidence is invalid"
            ) from exc

    def receipt_by_idempotency(
        self, idempotency_key: str
    ) -> (
        CustodyReceiptDTO
        | TrustedKeylessContinuousEventReceiptDTO
        | dict[str, Any]
        | None
    ):
        if self._read_root_absent():
            return None
        try:
            with self._custody(read_only=True) as custody:
                raw = custody.read_receipt_by_idempotency(f"install-{idempotency_key}")
                artifact = custody.read_artifact(raw["artifact_id"])
                if raw["receipt_type"] == "install" and artifact.get("schema_ref") in {
                    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
                    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
                    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
                }:
                    return self._keyless_receipt(raw, artifact)
                if (
                    raw["receipt_type"] == "install"
                    and artifact.get("schema_ref") == CONTINUOUS_EVENT_SCHEMA_VERSION
                ):
                    artifact, _event = self._trusted_keyless_continuous_event(artifact)
                    return self._continuous_event_receipt(raw, artifact)
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
            if exc.code in {"CUSTODY_RECEIPT_NOT_FOUND", "CUSTODY_ROOT_NOT_FOUND"}:
                return None
            _raise_custody_read_failure(exc, subject="idempotency")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody idempotency read is unavailable", status_code=503
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody idempotency evidence is invalid"
            ) from exc

    def artifact_for_execution(self, artifact_id: str) -> dict[str, Any] | None:
        """Return one verified target-plan envelope to Execution only.

        This is deliberately narrower than the custody ledger: it neither
        exposes records nor allows Control to inspect order-bearing payloads.
        """

        if self._read_root_absent():
            return None
        try:
            with self._custody(read_only=True) as custody:
                artifact = custody.read_artifact(artifact_id)
            if (
                not isinstance(artifact, dict)
                or artifact.get("artifact_type") != "simnow-target-plan"
                or artifact.get("trust_domain") != "runtime_authorization"
            ):
                raise CustodyEvidenceReadError(
                    "custody artifact is not an execution target plan"
                )
            if artifact.get("schema_ref") == TARGET_PLAN_SCHEMA_VERSION:
                with self._custody(read_only=True) as custody:
                    signed = custody.read_signed_artifact(artifact_id)
                artifact = signed.get("artifact")
            elif artifact.get("schema_ref") not in {
                KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
                KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
                KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
            }:
                raise CustodyEvidenceReadError(
                    "custody artifact is not an execution target plan"
                )
            if not isinstance(artifact, dict):
                raise CustodyEvidenceReadError(
                    "custody artifact is not an execution target plan"
                )
            raw = canonical_json_line(artifact)
            return {
                "artifact_id": artifact_id,
                "artifact_raw_sha256": hashlib.sha256(raw).hexdigest(),
                "artifact": artifact,
            }
        except CustodyError as exc:
            if exc.code in {
                "CUSTODY_ARTIFACT_NOT_FOUND",
                "CUSTODY_ARTIFACT_ID_INVALID",
                "CUSTODY_ROOT_NOT_FOUND",
            }:
                return None
            _raise_custody_read_failure(exc, subject="artifact")
        except OSError as exc:
            raise WorkflowAdapterError(
                "custody artifact read is unavailable", status_code=503
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CustodyEvidenceReadError(
                "custody artifact evidence is invalid"
            ) from exc

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

    def continuous_event_control_auth(request: Request) -> str:
        principal = control_auth(request)
        if principal != "control-api":
            raise HTTPException(401, "continuous event custody authentication failed")
        return principal

    @app.post("/internal/v1/publish-install")
    def publish_install(
        payload: SignedArtifactUploadDTO, request: Request
    ) -> dict[str, Any]:
        try:
            return target.publish_install(
                payload, principal=control_auth(request)
            ).model_dump(mode="json")
        except WorkflowAdapterError as exc:
            raise HTTPException(exc.status_code, detail={"code": exc.code}) from exc

    @app.get("/internal/v1/current-version")
    def current_version(request: Request) -> dict[str, Any]:
        control_auth(request)
        try:
            return target.current_version().model_dump(mode="json")
        except WorkflowAdapterError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_VERSION_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc

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

    @app.get("/internal/v1/target-plan-publications/by-idempotency/{idempotency_key}")
    def target_plan_publication(
        idempotency_key: str, request: Request
    ) -> dict[str, Any]:
        # Publication recovery is a pins-only projection: it contains no
        # order payload.  Control and Execution use distinct credentials to
        # read the same immutable custody evidence.
        principal = request.headers.get("X-Phase-C-Principal", "")
        if principal == "execution-orchestrator":
            execution_read_auth(request)
        else:
            control_auth(request)
        try:
            return target.target_plan_publication(idempotency_key).model_dump(
                mode="json"
            )
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_TARGET_PLAN_PUBLICATION_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                exc.status_code,
                detail={
                    "code": exc.code,
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc

    @app.post("/internal/v1/install-published-keyless-simnow-target-plan")
    def install_published_keyless_simnow_target_plan(
        payload: TrustedKeylessTargetPlanInstallContinuationDTO,
        request: Request,
    ) -> dict[str, Any]:
        try:
            return target.install_published_trusted_keyless_target_plan(
                payload,
                principal=control_auth(request),
            )
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_TARGET_PLAN_PUBLICATION_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                exc.status_code,
                detail={
                    "code": exc.code,
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc

    @app.post("/internal/v1/publish-keyless-simnow-continuous-event")
    def publish_keyless_simnow_continuous_event(
        payload: TrustedKeylessContinuousEventUploadDTO,
        request: Request,
    ) -> dict[str, Any]:
        try:
            return target.publish_trusted_keyless_continuous_event(
                payload,
                principal=continuous_event_control_auth(request),
            ).model_dump(mode="json")
        except WorkflowAdapterError as exc:
            raise HTTPException(
                exc.status_code,
                detail={
                    "code": exc.code,
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc

    @app.get(
        "/internal/v1/continuous-event-publications/by-idempotency/{idempotency_key}"
    )
    def continuous_event_publication(
        idempotency_key: str,
        request: Request,
    ) -> dict[str, Any]:
        continuous_event_control_auth(request)
        try:
            return target.continuous_event_publication(idempotency_key).model_dump(
                mode="json"
            )
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CONTINUOUS_EVENT_PUBLICATION_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                exc.status_code,
                detail={
                    "code": exc.code,
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc

    @app.post("/internal/v1/install-published-keyless-simnow-continuous-event")
    def install_published_keyless_simnow_continuous_event(
        payload: TrustedKeylessContinuousEventInstallContinuationDTO,
        request: Request,
    ) -> dict[str, Any]:
        try:
            return target.install_published_trusted_keyless_continuous_event(
                payload,
                principal=continuous_event_control_auth(request),
            ).model_dump(mode="json")
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CONTINUOUS_EVENT_PUBLICATION_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                exc.status_code,
                detail={
                    "code": exc.code,
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc

    @app.get("/internal/v1/continuous-events/by-idempotency/{idempotency_key}")
    def installed_continuous_event(
        idempotency_key: str,
        request: Request,
    ) -> dict[str, Any]:
        # Event bytes are non-authoritative but Control-only.  Execution can
        # read target plans through its dedicated route, never event bundles.
        continuous_event_control_auth(request)
        try:
            result = target.installed_continuous_event(idempotency_key)
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CONTINUOUS_EVENT_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                exc.status_code,
                detail={
                    "code": exc.code,
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc
        if result is None:
            raise HTTPException(404, "continuous event not installed")
        return result.model_dump(mode="json")

    @app.get("/internal/v1/target-plan-receipts/{receipt_id}")
    def target_plan_receipt_evidence(
        receipt_id: str, request: Request
    ) -> dict[str, Any]:
        execution_read_auth(request)
        try:
            result = target.target_plan_receipt_evidence(receipt_id)
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_TARGET_PLAN_RECEIPT_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_TARGET_PLAN_RECEIPT_READ_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": exc.retryable,
                },
            ) from exc
        if result is None:
            raise HTTPException(404, "target-plan receipt not found")
        return result.model_dump(mode="json")

    @app.get("/internal/v1/receipts/{receipt_id}")
    def receipt(receipt_id: str, request: Request) -> dict[str, Any]:
        # Control may retain receipt evidence; Execution reads the exact same
        # receipt using its dedicated read-only credential.
        principal = request.headers.get("X-Phase-C-Principal", "")
        if principal == "execution-orchestrator":
            execution_read_auth(request)
        else:
            shared_receipt_auth(request)
        try:
            result = target.receipt(receipt_id)
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_RECEIPT_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_RECEIPT_READ_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc
        if result is None:
            raise HTTPException(404, "receipt not found")
        if principal == "execution-orchestrator" and isinstance(
            result, TrustedKeylessContinuousEventReceiptDTO
        ):
            raise HTTPException(404, "receipt not found")
        return result if isinstance(result, dict) else result.model_dump(mode="json")

    @app.get("/internal/v1/receipts-by-idempotency/{idempotency_key}")
    def receipt_by_idempotency(
        idempotency_key: str, request: Request
    ) -> dict[str, Any]:
        # The dedicated Execution credential may resolve the same install
        # receipt for crash recovery.  This route returns receipt evidence
        # only; order-bearing artifacts remain behind the separate exact-id
        # execution read route.
        principal = request.headers.get("X-Phase-C-Principal", "")
        if principal == "execution-orchestrator":
            execution_read_auth(request)
        else:
            control_auth(request)
        try:
            result = target.receipt_by_idempotency(idempotency_key)
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_IDEMPOTENCY_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_IDEMPOTENCY_READ_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc
        if result is None:
            raise HTTPException(404, "receipt not found")
        if principal == "execution-orchestrator" and isinstance(
            result, TrustedKeylessContinuousEventReceiptDTO
        ):
            raise HTTPException(404, "receipt not found")
        return result if isinstance(result, dict) else result.model_dump(mode="json")

    @app.get("/internal/v1/artifacts/{artifact_id}")
    def artifact(artifact_id: str, request: Request) -> dict[str, Any]:
        execution_read_auth(request)
        try:
            result = target.artifact_for_execution(artifact_id)
        except CustodyEvidenceReadError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_ARTIFACT_EVIDENCE_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except WorkflowAdapterError as exc:
            raise HTTPException(
                503,
                detail={
                    "code": "PHASE_C_CUSTODY_ARTIFACT_READ_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc
        if result is None:
            raise HTTPException(404, "artifact not found")
        return result

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {
            "status": "live",
            "production": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }

    @app.get("/health/ready")
    def ready() -> dict[str, Any]:
        try:
            target.publish_projection()
        except (CustodyError, OSError) as exc:
            raise HTTPException(503, "custody durable state is unavailable") from exc
        return {
            "status": "ready",
            "production": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }

    @app.get("/version")
    def version() -> dict[str, Any]:
        return {
            "service": "artifact-custody",
            "version": "issue-291-final",
            "production": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }

    return app
