"""Final, internal-only SIMNOW execution integration.

The runtime is intentionally not an HTTP API.  Control continues to submit
only :class:`CommandEnvelope` lifecycle commands.  This adapter verifies the
custody-backed immutable target plan before delegating every state transition
and every possible broker mutation to the existing ``ExecutionOrchestrator``.
It never imports legacy ``TradeService`` or ``commodity_simnow`` code.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from app.phase_c.models import (
    TargetPlanCustodyReceiptEvidenceDTO,
    TargetPlanPublicationProjectionDTO,
)
from shared.artifact_contracts.v1 import (
    ContractError as ArtifactContractError,
)
from shared.artifact_contracts.v1 import (
    validate_artifact_envelope,
)
from shared.commodity_execution.v1 import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    CommodityExecutionContractError,
    TargetPlan,
    TrustedKeylessCustodyReceipt,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    canonical_json,
    sha256_json,
    target_position_projection_hash,
    utc_now,
)
from shared.trust_contracts.v1 import canonical_json_line, sha256_bytes

from .active_plan_resume import (
    TERMINAL_INTENT_STATES,
    classify_active_plan_intents,
    expected_send_intent_bindings,
    require_active_resume_boundary,
    require_first_send_snapshot_closure,
    require_snapshot_order_ownership,
    require_snapshot_state_compatibility,
)
from .errors import (
    ActiveResumeFreshSnapshotRequired,
    AuthorityRejected,
    GatewayConfigurationError,
    GatewayUnavailable,
    MutationRejected,
    PlanRejected,
    RepositoryUnavailableError,
    StartQuoteEvidenceInvalid,
    StartQuoteReplanRequired,
    StartQuoteSourceUnavailable,
)
from .formal_tick_reader import (
    FormalTickBinding,
    FormalTickEvidenceInvalid,
    FormalTickReadError,
    FormalTickRequest,
    FormalTickSourceUnavailable,
    read_simnow_continuous_v3_formal_tick_bindings,
)
from .models import CommandEnvelope, LeaderToken, validate_identifier
from .orchestrator import CommandResponse, ExecutionOrchestrator
from .start_quote_proof import (
    ExecutionStartQuotePriceIncompatible,
    ExecutionStartQuoteProofError,
    build_execution_start_quote_proof,
    quote_proof_for_order,
    validate_execution_start_quote_proof,
)


class TargetPlanRepository(Protocol):
    """Execution-owned plan storage; only exact immutable plan bytes are kept."""

    def put(self, plan: TargetPlan) -> None: ...

    def get(self, plan_id: str) -> TargetPlan | None: ...

    def find_authority(
        self, artifact_id: str, artifact_sha256: str
    ) -> TargetPlan | None: ...

    def probe(self) -> None: ...


class CustodyReadClient(Protocol):
    """Read-only custody protocol; it has no publish, sign, or revoke method."""

    def receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...

    def receipt_by_idempotency(
        self, idempotency_key: str
    ) -> Mapping[str, Any] | None: ...

    def target_plan_publication(self, idempotency_key: str) -> Mapping[str, Any]: ...

    def target_plan_receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...

    def artifact(self, artifact_id: str) -> Mapping[str, Any] | None: ...

    def probe(self) -> None: ...


class InMemoryTargetPlanRepository:
    """Small repository for offline/unit tests with create-only semantics."""

    def __init__(self) -> None:
        self._plans: dict[str, TargetPlan] = {}
        self._lock = RLock()

    def put(self, plan: TargetPlan) -> None:
        with self._lock:
            prior = self._plans.get(plan.plan_id)
            if prior is not None and prior.plan_hash != plan.plan_hash:
                raise PlanRejected("target plan id is already bound to another hash")
            self._plans.setdefault(plan.plan_id, plan)

    def get(self, plan_id: str) -> TargetPlan | None:
        validate_identifier(plan_id, "plan_id")
        with self._lock:
            return self._plans.get(plan_id)

    def find_authority(
        self, artifact_id: str, artifact_sha256: str
    ) -> TargetPlan | None:
        validate_identifier(artifact_id, "artifact_id")
        for plan in tuple(self._plans.values()):
            if (
                plan.authority_id == artifact_id
                and plan.authority_hash == artifact_sha256
            ):
                return plan
        return None

    def probe(self) -> None:
        with self._lock:
            for plan in self._plans.values():
                TargetPlan.from_mapping(plan.as_dict())


class DurableTargetPlanRepository:
    """Create-only plan directory that survives an Execution process restart."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        if not self.root.is_absolute():
            raise ValueError("target plan root must be absolute")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            self.root.resolve() != self.root
            or self.root.stat().st_mode & 0o777 != 0o700
        ):
            raise ValueError("target plan root must be pinned mode 0700")
        self._lock_path = self.root / ".target-plan.lock"

    def _path(self, plan_id: str) -> Path:
        validate_identifier(plan_id, "plan_id")
        return self.root / f"{plan_id}.json"

    def _locked(self):
        class _Guard:
            def __init__(self, path: Path) -> None:
                self.path = path
                self.fd = -1

            def __enter__(self):
                try:
                    self.fd = os.open(
                        self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600
                    )
                    fcntl.flock(self.fd, fcntl.LOCK_EX)
                except OSError as exc:
                    if self.fd >= 0:
                        try:
                            os.close(self.fd)
                        except OSError:
                            pass
                        finally:
                            self.fd = -1
                    raise RepositoryUnavailableError(
                        "durable target plan lock is unavailable"
                    ) from exc
                return self

            def __exit__(self, *_: object) -> None:
                failure: OSError | None = None
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                except OSError as exc:
                    failure = exc
                try:
                    os.close(self.fd)
                except OSError as exc:
                    failure = failure or exc
                finally:
                    self.fd = -1
                if failure is not None:
                    raise RepositoryUnavailableError(
                        "durable target plan lock release failed"
                    ) from failure

        return _Guard(self._lock_path)

    @staticmethod
    def _read(path: Path) -> TargetPlan | None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RepositoryUnavailableError(
                "durable target plan metadata is unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise PlanRejected("durable target plan file is unsafe")

        fd = -1
        try:
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
            ):
                raise PlanRejected("durable target plan file changed during read")
            with os.fdopen(fd, "rb", closefd=True) as stream:
                fd = -1
                raw = stream.read()
        except PlanRejected:
            raise
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PlanRejected("durable target plan file is unsafe") from exc
            raise RepositoryUnavailableError(
                "durable target plan read is unavailable"
            ) from exc
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as exc:
                    raise RepositoryUnavailableError(
                        "durable target plan read close failed"
                    ) from exc

        try:
            plan = TargetPlan.from_mapping(json.loads(raw))
            if canonical_json(plan.as_dict()) != raw:
                raise ValueError("target plan is not canonical")
            return plan
        except (
            UnicodeDecodeError,
            ValueError,
            CommodityExecutionContractError,
        ) as exc:
            raise PlanRejected("durable target plan is invalid") from exc

    def put(self, plan: TargetPlan) -> None:
        path = self._path(plan.plan_id)
        raw = canonical_json(plan.as_dict())
        with self._locked():
            prior = self._read(path)
            if prior is not None:
                if prior.plan_hash != plan.plan_hash:
                    raise PlanRejected(
                        "target plan id is already bound to another hash"
                    )
                return
            fd, temporary = tempfile.mkstemp(prefix=".target-plan-", dir=self.root)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("target plan write failed")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temporary, path)
                directory_fd = os.open(
                    self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except FileExistsError:
                prior = self._read(path)
                if prior is None or prior.plan_hash != plan.plan_hash:
                    raise PlanRejected(
                        "target plan id is already bound to another hash"
                    )
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def get(self, plan_id: str) -> TargetPlan | None:
        return self._read(self._path(plan_id))

    def find_authority(
        self, artifact_id: str, artifact_sha256: str
    ) -> TargetPlan | None:
        validate_identifier(artifact_id, "artifact_id")
        for path in sorted(self.root.glob("*.json")):
            plan = self._read(path)
            if plan is not None and (
                plan.authority_id == artifact_id
                and plan.authority_hash == artifact_sha256
            ):
                return plan
        return None

    def probe(self) -> None:
        with self._locked():
            for path in self.root.glob("*.json"):
                if self._read(path) is None:
                    raise PlanRejected("durable target plan disappeared during probe")


class _CallableCustodyClient:
    """Compatibility seam for offline tests; it cannot supply an artifact."""

    def __init__(self, receipt: Callable[[str], Mapping[str, Any] | None]) -> None:
        self._receipt = receipt

    def receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        return self._receipt(receipt_id)

    def receipt_by_idempotency(self, idempotency_key: str) -> Mapping[str, Any] | None:
        del idempotency_key
        return None

    def target_plan_publication(self, idempotency_key: str) -> Mapping[str, Any]:
        return TargetPlanPublicationProjectionDTO(
            state="NOT_PUBLISHED",
            idempotency_key=idempotency_key,
            install_idempotency_key=f"install-{idempotency_key}",
            observed_custody_version=0,
        ).model_dump(mode="json")

    def target_plan_receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        del receipt_id
        return None

    def artifact(self, artifact_id: str) -> Mapping[str, Any] | None:
        return None

    def probe(self) -> None:
        return None


class FinalExecutionRuntime:
    """The sole adapter from verified plans to the established execution core.

    ``allow_simnow_execution`` defaults to false and must be explicitly set by
    deployment code immediately before a separately authorised test.  It is a
    local runtime gate, not an authority encoded in a receipt or plan.
    """

    def __init__(
        self,
        orchestrator: ExecutionOrchestrator,
        *,
        plans: TargetPlanRepository,
        custody: CustodyReadClient | None = None,
        custody_receipt: Callable[[str], Mapping[str, Any] | None] | None = None,
        allowed_scope: Mapping[str, Any] | None = None,
        allow_simnow_execution: bool = False,
        allow_trusted_keyless_simnow: bool = False,
        max_order_volume: int = 1,
        formal_tick_bindings_reader: Callable[
            [tuple[FormalTickRequest, ...]], tuple[FormalTickBinding, ...]
        ] = read_simnow_continuous_v3_formal_tick_bindings,
        quote_clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if orchestrator.environment.upper() != "SIMNOW":
            raise ValueError("final execution runtime requires SIMNOW environment")
        self.orchestrator = orchestrator
        self.plans = plans
        if custody is not None and custody_receipt is not None:
            raise ValueError(
                "provide either custody client or custody_receipt callback"
            )
        if custody is None:
            if custody_receipt is None:
                raise ValueError("final execution runtime requires a custody reader")
            custody = _CallableCustodyClient(custody_receipt)
        self.custody = custody
        self.allowed_scope = dict(allowed_scope) if allowed_scope is not None else None
        self.allow_simnow_execution = bool(allow_simnow_execution)
        self.allow_trusted_keyless_simnow = bool(allow_trusted_keyless_simnow)
        if not callable(formal_tick_bindings_reader) or not callable(quote_clock):
            raise ValueError("final execution formal tick reader/clock is invalid")
        self.formal_tick_bindings_reader = formal_tick_bindings_reader
        self.quote_clock = quote_clock
        self._active_plan_resume_lock = RLock()
        if (
            not isinstance(max_order_volume, int)
            or isinstance(max_order_volume, bool)
            or max_order_volume < 1
        ):
            raise ValueError("final execution max order volume must be positive")
        self.max_order_volume = max_order_volume

    def _receipt_for(self, plan: TargetPlan) -> VerifiedCustodyReceipt | None:
        if plan.is_trusted_keyless_simnow:
            if not self.allow_trusted_keyless_simnow:
                raise AuthorityRejected("trusted keyless SIMNOW custody is disabled")
            if (
                self.allowed_scope is not None
                and plan.raw["scope"] != self.allowed_scope
            ):
                raise AuthorityRejected(
                    "keyless target plan scope is not locally allowlisted"
                )
            # Custody artifact/receipt bindings are rechecked during preview
            # and again immediately before start.  Keyless plans carry no
            # runtime-authorization receipt by design.
            return None
        try:
            raw = self.custody.receipt(str(plan.raw["authority_receipt_id"]))
        except Exception as exc:  # custody response is unknown, never assume success
            raise AuthorityRejected(
                "custody receipt lookup outcome is unknown"
            ) from exc
        if raw is None:
            raise AuthorityRejected("custody receipt is unavailable")
        try:
            receipt = VerifiedCustodyReceipt.from_mapping(raw)
        except CommodityExecutionContractError as exc:
            raise AuthorityRejected(
                "custody receipt is not strict verified evidence"
            ) from exc
        if (
            receipt.raw["artifact_type"],
            receipt.raw["trust_domain"],
            receipt.raw["schema_ref"],
        ) != (
            "runtime-authorization",
            "runtime_authorization",
            "phase-c-runtime-authorization-v1",
        ):
            raise AuthorityRejected(
                "custody receipt does not identify runtime authorization"
            )
        expected = {
            "receipt_id": plan.raw["authority_receipt_id"],
            "artifact_id": plan.raw["authority_artifact_id"],
            "artifact_sha256": plan.raw["authority_artifact_sha256"],
            "signer_key_id": plan.raw["signer_key_id"],
            "signer_key_version": plan.raw["signer_key_version"],
            "keyring_raw_sha256": plan.raw["keyring_raw_sha256"],
            "expires_at": plan.raw["expires_at"],
        }
        if (
            receipt.receipt_sha256 != plan.raw["authority_receipt_sha256"]
            or any(receipt.raw[field] != value for field, value in expected.items())
            or receipt.scope != plan.raw["scope"]
            or (self.allowed_scope is not None and receipt.scope != self.allowed_scope)
            or receipt.expires_at() <= utc_now()
        ):
            raise AuthorityRejected(
                "custody receipt does not match immutable target plan"
            )
        return receipt

    def _target_plan_from_custody_receipt(
        self,
        raw_receipt: Mapping[str, Any],
        *,
        require_current_expiry: bool,
    ) -> tuple[
        TargetPlan,
        VerifiedCustodyReceipt | TrustedKeylessCustodyReceipt,
        str,
    ]:
        """Verify one receipt/artifact/plan chain without installing the plan."""

        try:
            receipt = (
                TrustedKeylessCustodyReceipt.from_mapping(raw_receipt)
                if raw_receipt.get("schema_ref")
                in {
                    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
                    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
                    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
                }
                else VerifiedCustodyReceipt.from_mapping(raw_receipt)
            )
        except CommodityExecutionContractError as exc:
            raise AuthorityRejected(
                "custody receipt is not strict verified evidence"
            ) from exc
        keyless = isinstance(receipt, TrustedKeylessCustodyReceipt)
        if keyless and not self.allow_trusted_keyless_simnow:
            raise AuthorityRejected("trusted keyless SIMNOW custody is disabled")
        if (
            receipt.raw["artifact_type"],
            receipt.raw["trust_domain"],
            receipt.raw["schema_ref"],
        ) != (
            "simnow-target-plan",
            "runtime_authorization",
            receipt.raw["schema_ref"] if keyless else TARGET_PLAN_SCHEMA_VERSION,
        ):
            raise PlanRejected("SIMNOW preview receipt does not identify a target plan")
        try:
            response = self.custody.artifact(receipt.artifact_id)
        except (AuthorityRejected, PlanRejected, GatewayConfigurationError):
            raise
        except Exception as exc:
            raise GatewayUnavailable(
                "custody artifact lookup outcome is unknown"
            ) from exc
        if response is None:
            raise AuthorityRejected("custody target plan artifact is unavailable")
        if not isinstance(response, Mapping) or set(response) != {
            "artifact_id",
            "artifact_raw_sha256",
            "artifact",
        }:
            raise PlanRejected("custody target plan artifact response is not exact")
        artifact_value = response["artifact"]
        if not isinstance(artifact_value, Mapping):
            raise PlanRejected("custody target plan artifact is not an object")
        try:
            artifact = validate_artifact_envelope(artifact_value)
            envelope_raw_sha256 = sha256_bytes(canonical_json_line(artifact))
            payload = artifact["payload"]
            plan = TargetPlan.from_mapping(
                payload, max_order_volume=self.max_order_volume
            )
        except (ArtifactContractError, CommodityExecutionContractError) as exc:
            raise PlanRejected("custody target plan artifact is invalid") from exc
        if (
            response["artifact_id"] != receipt.artifact_id
            or response["artifact_raw_sha256"] != envelope_raw_sha256
            or receipt.artifact_sha256 != artifact["raw_sha256"]
        ):
            raise PlanRejected("custody target plan artifact/receipt binding mismatch")
        if (
            artifact["artifact_id"] != receipt.artifact_id
            or artifact["artifact_type"] != receipt.raw["artifact_type"]
            or artifact["trust_domain"] != receipt.raw["trust_domain"]
            or artifact["schema_ref"] != receipt.raw["schema_ref"]
            or artifact["schema_ref"] != plan.raw["schema_version"]
            or artifact["scope"] != receipt.scope
            or artifact["scope"] != plan.raw["scope"]
            or receipt.scope != plan.raw["scope"]
            or (self.allowed_scope is not None and receipt.scope != self.allowed_scope)
            or (keyless and not plan.is_trusted_keyless_simnow)
            or (not keyless and plan.is_trusted_keyless_simnow)
            or (keyless and receipt.raw["expires_at"] != plan.raw["expires_at"])
            or (
                (require_current_expiry or not keyless)
                and receipt.expires_at() <= utc_now()
            )
        ):
            raise PlanRejected("custody target plan receipt scope/expiry mismatch")
        self._plan_from_value(plan)
        return plan, receipt, envelope_raw_sha256

    def _target_plan_from_publication(
        self, publication: TargetPlanPublicationProjectionDTO
    ) -> tuple[TargetPlan, str]:
        """Rehash one published artifact against every authenticated pin."""

        if publication.state == "NOT_PUBLISHED" or publication.artifact_id is None:
            raise PlanRejected("custody publication does not identify an artifact")
        try:
            response = self.custody.artifact(publication.artifact_id)
        except (AuthorityRejected, PlanRejected, GatewayConfigurationError):
            raise
        except Exception as exc:
            raise GatewayUnavailable(
                "custody publication artifact lookup outcome is unknown"
            ) from exc
        if response is None:
            raise AuthorityRejected("custody publication artifact is unavailable")
        if not isinstance(response, Mapping) or set(response) != {
            "artifact_id",
            "artifact_raw_sha256",
            "artifact",
        }:
            raise PlanRejected("custody publication artifact response is not exact")
        artifact_value = response["artifact"]
        if not isinstance(artifact_value, Mapping):
            raise PlanRejected("custody publication artifact is not an object")
        try:
            artifact = validate_artifact_envelope(artifact_value)
            artifact_envelope_sha256 = sha256_bytes(canonical_json_line(artifact))
            plan = TargetPlan.from_mapping(
                artifact["payload"], max_order_volume=self.max_order_volume
            )
        except (ArtifactContractError, CommodityExecutionContractError) as exc:
            raise PlanRejected("custody publication artifact is invalid") from exc
        if (
            response["artifact_id"] != publication.artifact_id
            or response["artifact_raw_sha256"] != artifact_envelope_sha256
            or artifact["artifact_id"] != publication.artifact_id
            or artifact["artifact_type"] != "simnow-target-plan"
            or artifact["trust_domain"] != "runtime_authorization"
            or artifact["canonical_sha256"] != publication.artifact_canonical_sha256
            or artifact["raw_sha256"] != publication.artifact_raw_sha256
            or artifact["schema_ref"] != publication.artifact_schema_ref
            or artifact["schema_ref"] != publication.plan_schema_version
            or artifact["schema_ref"] != plan.raw["schema_version"]
            or plan.plan_id != publication.plan_id
            or plan.plan_hash != publication.plan_hash
            or plan.raw["phase"] != publication.plan_phase
            or artifact["scope"] != plan.raw["scope"]
            or (
                self.allowed_scope is not None
                and artifact["scope"] != self.allowed_scope
            )
            or not plan.is_trusted_keyless_simnow
        ):
            raise PlanRejected("custody publication artifact/plan binding mismatches")
        self._plan_from_value(plan)
        return plan, artifact_envelope_sha256

    def _target_plan_receipt_evidence(
        self, receipt_id: str
    ) -> TargetPlanCustodyReceiptEvidenceDTO:
        try:
            raw = self.custody.target_plan_receipt(receipt_id)
        except (AuthorityRejected, PlanRejected, GatewayConfigurationError):
            raise
        except Exception as exc:
            raise GatewayUnavailable(
                "custody target-plan receipt lookup outcome is unknown"
            ) from exc
        if raw is None:
            raise AuthorityRejected("custody target-plan receipt is unavailable")
        try:
            evidence = TargetPlanCustodyReceiptEvidenceDTO.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise PlanRejected(
                "custody target-plan receipt is not strict evidence"
            ) from exc
        if evidence.receipt_id != receipt_id:
            raise PlanRejected("custody target-plan receipt id binding mismatches")
        return evidence

    @staticmethod
    def _require_publication_receipt_binding(
        publication: TargetPlanPublicationProjectionDTO,
        evidence: TargetPlanCustodyReceiptEvidenceDTO,
        *,
        install: bool,
    ) -> None:
        if install:
            expected = {
                "receipt_id": publication.install_receipt_id,
                "receipt_sha256": publication.install_receipt_sha256,
                "receipt_type": "install",
                "idempotency_key": publication.install_idempotency_key,
                "expected_custody_version": (
                    publication.install_expected_custody_version
                ),
                "resulting_custody_version": (
                    publication.install_resulting_custody_version
                ),
            }
        else:
            expected = {
                "receipt_id": publication.publish_receipt_id,
                "receipt_sha256": publication.publish_receipt_sha256,
                "receipt_type": "publish",
                "idempotency_key": publication.idempotency_key,
                "expected_custody_version": (
                    publication.publish_expected_custody_version
                ),
                "resulting_custody_version": (
                    publication.publish_resulting_custody_version
                ),
            }
        common = {
            "artifact_id": publication.artifact_id,
            "artifact_canonical_sha256": publication.artifact_canonical_sha256,
            "artifact_raw_sha256": publication.artifact_raw_sha256,
            "artifact_schema_ref": publication.artifact_schema_ref,
            "actor_id": publication.publisher_principal,
            "correlation_id": publication.correlation_id,
        }
        if any(
            getattr(evidence, field) != value
            for field, value in {**expected, **common}.items()
        ):
            raise PlanRejected(
                "custody target-plan receipt/publication binding mismatches"
            )

    def _preview_from_custody(
        self, receipt_id: str, *, require_current_expiry: bool = True
    ) -> tuple[TargetPlan, VerifiedCustodyReceipt | TrustedKeylessCustodyReceipt]:
        """Fetch, cross-check and install a plan before a SIMNOW preview exists.

        The Control command supplies only a receipt id.  Order requests never
        traverse Control: they are read from the exact custody artifact here.
        """

        try:
            raw_receipt = self.custody.receipt(receipt_id)
        except Exception as exc:
            raise AuthorityRejected(
                "custody receipt lookup outcome is unknown"
            ) from exc
        if raw_receipt is None:
            raise AuthorityRejected("custody receipt is unavailable")
        plan, receipt, _artifact_envelope_sha256 = (
            self._target_plan_from_custody_receipt(
                raw_receipt, require_current_expiry=require_current_expiry
            )
        )
        self.plans.put(plan)
        return plan, receipt

    def preview_from_custody(self, receipt_id: str) -> TargetPlan:
        """Public internal helper retained for runners/tests; installs no authority."""

        return self._preview_from_custody(receipt_id)[0]

    def readiness(self) -> None:
        """Required-mode readiness proves local state and custody are readable."""

        self.plans.probe()
        try:
            self.custody.probe()
        except Exception as exc:
            raise AuthorityRejected("custody read-only readiness failed") from exc

    def completion_projection(
        self, *, plan_id: str | None = None
    ) -> dict[str, Any] | None:
        """Project one completed immutable TargetPlan v2/v3, if any.

        Completion identity is derived exclusively from the append-only
        ``final_plan_completed`` archive record and the already-installed
        create-only TargetPlan.  Historical broker rows and authority/custody
        material intentionally remain inside Execution.  Supplying ``plan_id``
        searches the complete archive so crash recovery never mistakes a newer
        unrelated completion for an unexecuted historical event.
        """

        state = self.orchestrator.repository.snapshot()
        completed = next(
            (
                entry
                for entry in reversed(state["terminal_archive"])
                if entry.get("kind") == "final_plan_completed"
                and (plan_id is None or entry.get("plan_id") == plan_id)
            ),
            None,
        )
        if completed is None:
            return None
        if "target_position_hash" not in completed:
            raise PlanRejected("latest completion predates the target-position binding")
        plan = self.plans.get(str(completed["plan_id"]))
        if plan is None:
            raise PlanRejected("latest completed target plan is not installed")
        try:
            plan = TargetPlan.from_mapping(
                plan.as_dict(), max_order_volume=self.max_order_volume
            )
        except CommodityExecutionContractError as exc:
            raise PlanRejected("latest completed target plan is invalid") from exc
        if plan.plan_hash != completed["plan_hash"]:
            raise PlanRejected("latest completion target plan hash mismatches")
        plan_schema_version = plan.raw["schema_version"]
        if plan_schema_version not in {
            KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        }:
            raise PlanRejected("latest completion target plan is not v2/v3")
        if (
            completed["target_position_hash"]
            != plan.raw["expected_after_position_hash"]
        ):
            raise PlanRejected("latest completion target position hash mismatches")
        positions = completed.get("positions")
        if not isinstance(positions, Mapping):
            raise PlanRejected("latest completion target positions are unavailable")
        try:
            projected_target_hash = target_position_projection_hash(
                positions,
                account_scope=plan.raw["account_scope"],
                environment=plan.raw["environment"],
            )
        except CommodityExecutionContractError as exc:
            raise PlanRejected(
                "latest completion target positions are invalid"
            ) from exc
        if projected_target_hash != completed["target_position_hash"]:
            raise PlanRejected(
                "latest completion archived positions do not match target semantics"
            )
        projection = {
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "schema_version": plan_schema_version,
            "phase": plan.raw["phase"],
            "lineage": dict(plan.raw["lineage"]),
            "expected_after_position_hash": plan.raw["expected_after_position_hash"],
            "target_position_hash": completed["target_position_hash"],
            "archived_at": completed["archived_at"],
        }
        if plan_schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
            creation_quote_proof_sha256 = sha256_json(plan.raw["creation_quote_proof"])
            start_quote_proof = self._persisted_start_quote_proof_for_plan(plan)
            if start_quote_proof is None:
                raise PlanRejected(
                    "latest v3 completion start quote proof is unavailable"
                )
            proof_pins = {
                "execution_run_id": plan.raw["execution_run_id"],
                "creation_quote_proof_sha256": creation_quote_proof_sha256,
                "start_quote_proof_sha256": start_quote_proof["proof_sha256"],
            }
            if any(
                completed.get(field) != value for field, value in proof_pins.items()
            ):
                raise PlanRejected(
                    "latest v3 completion quote proof binding mismatches"
                )
            projection.update(proof_pins)
        elif any(
            field in completed
            for field in (
                "execution_run_id",
                "creation_quote_proof_sha256",
                "start_quote_proof_sha256",
            )
        ):
            raise PlanRejected("latest v2 completion contains v3 quote proof binding")
        return projection

    def latest_completion_projection(self) -> dict[str, Any] | None:
        """Project the latest completed immutable TargetPlan v2/v3, if any."""

        return self.completion_projection()

    def recovery_projection(self, *, custody_idempotency_key: str) -> dict[str, Any]:
        """Classify one custody key without changing custody or plan storage.

        The authenticated publication projection distinguishes never-published,
        published-only, and installed custody state.  This method is read-only:
        it never publishes, continues an install, or writes the plan repository.
        """

        validate_identifier(custody_idempotency_key, "custody_idempotency_key")
        try:
            raw_publication = self.custody.target_plan_publication(
                custody_idempotency_key
            )
        except (AuthorityRejected, PlanRejected, GatewayConfigurationError):
            raise
        except Exception as exc:
            raise GatewayUnavailable(
                "custody publication lookup outcome is unknown"
            ) from exc
        try:
            publication = TargetPlanPublicationProjectionDTO.model_validate(
                raw_publication
            )
        except (TypeError, ValueError) as exc:
            raise PlanRejected(
                "custody publication projection is not strict evidence"
            ) from exc
        if publication.idempotency_key != custody_idempotency_key:
            raise PlanRejected("custody publication key binding mismatches")
        if publication.state == "NOT_PUBLISHED":
            preimage = {
                "schema_version": "web_bridge_execution_target_plan_recovery_v1",
                "state": "BEFORE_CUSTODY",
                "custody_idempotency_key": custody_idempotency_key,
                "production_allowed": False,
                "live_trading_authorized": False,
                "countable_forward": False,
            }
            return {**preimage, "recovery_sha256": sha256_json(preimage)}
        publish_evidence = self._target_plan_receipt_evidence(
            str(publication.publish_receipt_id)
        )
        self._require_publication_receipt_binding(
            publication, publish_evidence, install=False
        )
        plan, artifact_envelope_sha256 = self._target_plan_from_publication(publication)
        plan_schema_version = plan.raw["schema_version"]
        if plan_schema_version not in {
            KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        }:
            raise PlanRejected("recovery target plan is not v2/v3")
        v3_identity = (
            {
                "execution_run_id": plan.raw["execution_run_id"],
                "creation_quote_proof_sha256": sha256_json(
                    plan.raw["creation_quote_proof"]
                ),
            }
            if plan_schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            else {}
        )
        if publication.state == "PUBLISHED_NOT_INSTALLED":
            if self.plans.get(plan.plan_id) is not None:
                raise PlanRejected(
                    "local target plan exists without custody install evidence"
                )
            install_only_allowed = (
                publication.observed_custody_version
                == publication.publish_resulting_custody_version
            )
            preimage = {
                "schema_version": (
                    "web_bridge_execution_target_plan_recovery_v3"
                    if v3_identity
                    else "web_bridge_execution_target_plan_recovery_v2"
                ),
                "state": "CUSTODY_PUBLISHED_NOT_INSTALLED",
                "custody_idempotency_key": custody_idempotency_key,
                "custody_install_idempotency_key": publication.install_idempotency_key,
                "observed_custody_version": publication.observed_custody_version,
                "publisher_principal": publication.publisher_principal,
                "correlation_id": publication.correlation_id,
                "publish_receipt_id": publication.publish_receipt_id,
                "publish_receipt_sha256": publication.publish_receipt_sha256,
                "publish_expected_custody_version": (
                    publication.publish_expected_custody_version
                ),
                "publish_resulting_custody_version": (
                    publication.publish_resulting_custody_version
                ),
                "artifact_id": publication.artifact_id,
                "artifact_canonical_sha256": publication.artifact_canonical_sha256,
                "artifact_sha256": publication.artifact_raw_sha256,
                "artifact_schema_ref": publication.artifact_schema_ref,
                "artifact_envelope_sha256": artifact_envelope_sha256,
                "installed": False,
                "install_only_allowed": install_only_allowed,
                "recovery_action": (
                    "INSTALL_ONLY" if install_only_allowed else "STOP_VERSION_DRIFT"
                ),
                "target_plan_schema_version": plan.raw["schema_version"],
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "phase": plan.raw["phase"],
                "lineage": dict(plan.raw["lineage"]),
                "account_scope": plan.raw["account_scope"],
                "environment": plan.raw["environment"],
                "gateway_name": plan.raw["gateway_name"],
                "generated_at": plan.raw["generated_at"],
                "expires_at": plan.raw["expires_at"],
                "expected_before_position_hash": plan.raw[
                    "expected_before_position_hash"
                ],
                "expected_after_position_hash": plan.raw[
                    "expected_after_position_hash"
                ],
                "order_set_sha256": plan.raw["order_set_sha256"],
                **v3_identity,
                "production_allowed": False,
                "live_trading_authorized": False,
                "countable_forward": False,
            }
            return {**preimage, "recovery_sha256": sha256_json(preimage)}

        install_evidence = self._target_plan_receipt_evidence(
            str(publication.install_receipt_id)
        )
        self._require_publication_receipt_binding(
            publication, install_evidence, install=True
        )
        try:
            raw_receipt = self.custody.receipt(str(publication.install_receipt_id))
        except (AuthorityRejected, PlanRejected, GatewayConfigurationError):
            raise
        except Exception as exc:
            raise GatewayUnavailable(
                "custody install receipt lookup outcome is unknown"
            ) from exc
        if raw_receipt is None:
            raise AuthorityRejected("custody install receipt is unavailable")
        receipt_plan, receipt, receipt_envelope_sha256 = (
            self._target_plan_from_custody_receipt(
                raw_receipt, require_current_expiry=False
            )
        )
        if not isinstance(receipt, TrustedKeylessCustodyReceipt):
            raise PlanRejected("recovery receipt is not trusted keyless custody")
        if (
            receipt_plan.as_dict() != plan.as_dict()
            or receipt_envelope_sha256 != artifact_envelope_sha256
            or receipt.receipt_id != publication.install_receipt_id
            or receipt.raw["idempotency_key"] != publication.install_idempotency_key
            or receipt.raw["custody_version"]
            != publication.install_resulting_custody_version
            or receipt.artifact_id != publication.artifact_id
            or receipt.artifact_sha256 != publication.artifact_raw_sha256
        ):
            raise PlanRejected("custody installation/publication binding mismatches")
        installed = self.plans.get(plan.plan_id)
        if installed is not None:
            try:
                installed = TargetPlan.from_mapping(
                    installed.as_dict(), max_order_volume=self.max_order_volume
                )
            except CommodityExecutionContractError as exc:
                raise PlanRejected("installed recovery target plan is invalid") from exc
            if (
                installed.plan_hash != plan.plan_hash
                or installed.as_dict() != plan.as_dict()
            ):
                raise PlanRejected("installed recovery target plan binding mismatches")

        v3_start = (
            self._v3_start_recovery_fields(plan, receipt)
            if plan_schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            and installed is not None
            else (
                {
                    "start_quote_proof_state": "NOT_INSTALLED",
                    "start_quote_proof_sha256": None,
                    "can_start_same_plan": False,
                }
                if plan_schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
                else {}
            )
        )
        preimage = {
            "schema_version": (
                "web_bridge_execution_target_plan_recovery_v3"
                if v3_identity
                else "web_bridge_execution_target_plan_recovery_v1"
            ),
            "state": (
                "INSTALLED"
                if installed is not None
                else "CUSTODY_PUBLISHED_NOT_PREVIEWED"
            ),
            "custody_idempotency_key": custody_idempotency_key,
            "custody_install_idempotency_key": publication.install_idempotency_key,
            "custody_version": receipt.raw["custody_version"],
            "receipt_id": receipt.receipt_id,
            "receipt_sha256": receipt.receipt_sha256,
            "artifact_id": receipt.artifact_id,
            "artifact_sha256": receipt.artifact_sha256,
            "artifact_envelope_sha256": artifact_envelope_sha256,
            "installed": installed is not None,
            "target_plan_schema_version": plan.raw["schema_version"],
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "phase": plan.raw["phase"],
            "lineage": dict(plan.raw["lineage"]),
            "account_scope": plan.raw["account_scope"],
            "environment": plan.raw["environment"],
            "gateway_name": plan.raw["gateway_name"],
            "generated_at": plan.raw["generated_at"],
            "expires_at": plan.raw["expires_at"],
            "expected_before_position_hash": plan.raw["expected_before_position_hash"],
            "expected_after_position_hash": plan.raw["expected_after_position_hash"],
            "order_set_sha256": plan.raw["order_set_sha256"],
            **v3_identity,
            **v3_start,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }
        return {**preimage, "recovery_sha256": sha256_json(preimage)}

    def _persisted_start_quote_proof_for_plan(
        self, plan: TargetPlan
    ) -> dict[str, Any] | None:
        """Return the one durable start proof bound to ``plan``, if present."""

        matched: dict[str, dict[str, Any]] = {}
        receipts = self.orchestrator.repository.snapshot().get("receipts", {})
        if not isinstance(receipts, Mapping):
            raise PlanRejected("Execution command receipts are invalid")
        for receipt in receipts.values():
            if not isinstance(receipt, Mapping):
                raise PlanRejected("Execution command receipt is invalid")
            result = receipt.get("result")
            if not isinstance(result, Mapping) or (
                "execution_start_quote_proof" not in result
            ):
                continue
            evidence = result["execution_start_quote_proof"]
            if not isinstance(evidence, Mapping):
                raise PlanRejected("persisted execution start quote proof is invalid")
            references_plan = (
                evidence.get("plan_id") == plan.plan_id
                or evidence.get("plan_hash") == plan.plan_hash
            )
            if not references_plan:
                continue
            try:
                proof = validate_execution_start_quote_proof(evidence, plan=plan)
            except ValueError as exc:
                raise PlanRejected(
                    "persisted execution start quote proof mismatches target plan"
                ) from exc
            matched[proof["proof_sha256"]] = proof
        if len(matched) > 1:
            raise PlanRejected("multiple execution start quote proofs bind target plan")
        return next(iter(matched.values()), None)

    def _v3_start_recovery_fields(
        self,
        plan: TargetPlan,
        receipt: TrustedKeylessCustodyReceipt,
    ) -> dict[str, Any]:
        """Classify v3 start evidence without persisting or exposing tick rows."""

        persisted = self._persisted_start_quote_proof_for_plan(plan)
        if persisted is not None:
            return {
                "start_quote_proof_state": "STARTED_MATCHED",
                "start_quote_proof_sha256": persisted["proof_sha256"],
                "can_start_same_plan": False,
            }
        state = self.orchestrator.repository.snapshot()
        active = state.get("plan", {})
        completion_exists = any(
            isinstance(row, Mapping)
            and row.get("kind") == "final_plan_completed"
            and row.get("plan_id") == plan.plan_id
            and row.get("plan_hash") == plan.plan_hash
            for row in state.get("terminal_archive", ())
        )
        if (
            isinstance(active, Mapping)
            and active.get("state") == "ACTIVE"
            and active.get("plan_id") == plan.plan_id
            and active.get("plan_hash") == plan.plan_hash
        ) or completion_exists:
            raise PlanRejected("v3 started target plan lacks durable start quote proof")
        if not self._v3_same_plan_start_boundary(state, plan=plan, receipt=receipt):
            return {
                "start_quote_proof_state": "NOT_STARTED",
                "start_quote_proof_sha256": None,
                "can_start_same_plan": False,
            }
        try:
            proof = self._fresh_start_quote_proof(plan)
        except StartQuoteReplanRequired:
            state_name = "REPLAN_REQUIRED"
        except StartQuoteSourceUnavailable:
            state_name = "SOURCE_UNAVAILABLE"
        except StartQuoteEvidenceInvalid:
            state_name = "EVIDENCE_INVALID"
        else:
            post_quote_state = self.orchestrator.repository.snapshot()
            if (
                post_quote_state.get("state_version") != state.get("state_version")
                or post_quote_state.get("state_hash") != state.get("state_hash")
                or not self._v3_same_plan_start_boundary(
                    post_quote_state, plan=plan, receipt=receipt
                )
            ):
                return {
                    "start_quote_proof_state": "EVIDENCE_INVALID",
                    "start_quote_proof_sha256": None,
                    "can_start_same_plan": False,
                }
            return {
                "start_quote_proof_state": "READY",
                "start_quote_proof_sha256": proof["proof_sha256"],
                "can_start_same_plan": True,
            }
        return {
            "start_quote_proof_state": state_name,
            "start_quote_proof_sha256": None,
            "can_start_same_plan": False,
        }

    def _v3_same_plan_start_boundary(
        self,
        state: Mapping[str, Any],
        *,
        plan: TargetPlan,
        receipt: TrustedKeylessCustodyReceipt,
    ) -> bool:
        active = state.get("plan")
        authority = state.get("authority")
        reconciliation = state.get("reconciliation")
        broker = state.get("broker")
        if not all(
            isinstance(value, Mapping)
            for value in (active, authority, reconciliation, broker)
        ):
            return False
        expected_preview_id = f"preview-{plan.plan_hash[:16]}"
        try:
            current_position_hash = before_position_projection_hash(
                broker.get("positions"),
                account_scope=self.orchestrator.scope,
                environment=self.orchestrator.environment,
            )
        except CommodityExecutionContractError:
            return False
        return bool(
            state.get("lifecycle") == "READY"
            and active.get("state") == "PREVIEWED"
            and active.get("plan_id") == expected_preview_id
            and active.get("plan_hash") == plan.plan_hash
            and active.get("preview_mode") == "simnow_preview"
            and active.get("preview_receipt_id") == receipt.receipt_id
            and active.get("preview_receipt_sha256") == receipt.receipt_sha256
            and active.get("preview_artifact_id") == receipt.artifact_id
            and active.get("preview_artifact_sha256") == receipt.artifact_sha256
            and authority.get("state") == "ENABLED"
            and authority.get("artifact_id") == plan.authority_id
            and authority.get("artifact_hash") == plan.authority_hash
            and authority.get("expires_at") == plan.raw["expires_at"]
            and reconciliation.get("state") == "RECONCILED"
            and reconciliation.get("unknown_outcomes") == 0
            and current_position_hash == plan.raw["expected_before_position_hash"]
            and receipt.expires_at() > utc_now()
        )

    def _plan(self, plan_id: str, *, plan_hash: str | None = None) -> TargetPlan:
        plan = self.plans.get(plan_id)
        if plan is None:
            raise PlanRejected("target plan is not installed in Execution")
        if plan_hash is not None and plan.plan_hash != plan_hash:
            raise PlanRejected("target plan hash does not match installed plan")
        try:
            plan = TargetPlan.from_mapping(
                plan.as_dict(), max_order_volume=self.max_order_volume
            )
        except CommodityExecutionContractError as exc:
            raise PlanRejected(
                "installed target plan exceeds local order bound"
            ) from exc
        if plan.raw["account_scope"] != self.orchestrator.scope:
            raise PlanRejected("target plan account scope does not match Execution")
        if plan.raw["environment"] != "SIMNOW":
            raise PlanRejected("target plan environment is not SIMNOW")
        self._receipt_for(plan)
        return plan

    def install_target_plan(self, raw: Mapping[str, Any]) -> TargetPlan:
        """Verify and retain an immutable plan; this cannot start or send anything."""

        try:
            plan = TargetPlan.from_mapping(raw, max_order_volume=self.max_order_volume)
        except CommodityExecutionContractError as exc:
            raise PlanRejected("target plan contract is invalid") from exc
        if plan.is_trusted_keyless_simnow:
            raise PlanRejected("keyless target plans must be installed from custody")
        self._plan_from_value(plan)
        self.plans.put(plan)
        return plan

    def _plan_from_value(self, plan: TargetPlan) -> None:
        if plan.raw["account_scope"] != self.orchestrator.scope:
            raise PlanRejected("target plan account scope does not match Execution")
        if plan.raw["environment"] != "SIMNOW":
            raise PlanRejected("target plan environment is not SIMNOW")
        self._receipt_for(plan)

    def _halt_runner_after_failure(self, reason: str) -> None:
        """Cancel acknowledged work before recording a terminal runner halt.

        ``emergency_stop`` is the existing fenced cancellation/revocation
        sequence.  If it cannot establish every cancellation outcome, it has
        already retained UNKNOWN/HALTED state; do not overwrite that evidence
        with a less-specific lifecycle transition.
        """

        self.orchestrator.emergency_stop(reason=reason)
        if self.orchestrator.repository.snapshot().get("unknown_outcomes"):
            # The unknown intent must remain durable and reconciliation-gated;
            # do not overwrite HALTED_UNKNOWN_OUTCOME after cancelling only
            # the independently acknowledged siblings.
            return
        self.orchestrator.fail_closed_halt(reason)

    def _finalization_evidence(self) -> dict[str, Any] | None:
        """Re-verify runtime-only proof before a reconcile can complete a plan."""

        state = self.orchestrator.repository.snapshot()
        active = state["plan"]
        if active.get("state") != "ACTIVE":
            return None
        plan = self._plan(str(active["plan_id"]), plan_hash=str(active["plan_hash"]))
        proof = {
            field: active.get(field)
            for field in (
                "preview_receipt_id",
                "preview_receipt_sha256",
                "preview_artifact_id",
                "preview_artifact_sha256",
            )
        }
        if (
            active.get("preview_mode") != "simnow_preview"
            or any(not isinstance(value, str) for value in proof.values())
            or proof["preview_receipt_id"] == "unknown00"
            or proof["preview_receipt_sha256"] == "0" * 64
            or proof["preview_artifact_id"] == "unknown00"
            or proof["preview_artifact_sha256"] == "0" * 64
        ):
            raise PlanRejected("SIMNOW active plan lacks durable preview proof")
        preview_plan, preview_receipt = self._preview_from_custody(
            str(proof["preview_receipt_id"]), require_current_expiry=False
        )
        if (
            preview_plan.plan_hash != plan.plan_hash
            or preview_receipt.receipt_sha256 != proof["preview_receipt_sha256"]
            or preview_receipt.artifact_id != proof["preview_artifact_id"]
            or preview_receipt.artifact_sha256 != proof["preview_artifact_sha256"]
        ):
            raise PlanRejected("SIMNOW preview custody evidence changed after restart")
        expected_bindings = expected_send_intent_bindings(
            plan,
            account_scope=self.orchestrator.scope,
            environment=self.orchestrator.environment,
        )
        # Existing intent rows are checked before reconciliation reads the
        # gateway, while a legitimately missing child remains PENDING.
        classify_active_plan_intents(state, plan=plan, bindings=expected_bindings)
        evidence = {
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "expected_after_position_hash": str(
                plan.raw["expected_after_position_hash"]
            ),
            "authority_artifact_id": plan.authority_id,
            "authority_artifact_sha256": plan.authority_hash,
            "authority_receipt_id": str(
                plan.raw.get("authority_receipt_id", "keyless-custody")
            ),
            "authority_receipt_sha256": str(
                plan.raw.get("authority_receipt_sha256", "0" * 64)
            ),
            "preview_receipt_id": str(proof["preview_receipt_id"]),
            "preview_receipt_sha256": str(proof["preview_receipt_sha256"]),
            "preview_artifact_id": str(proof["preview_artifact_id"]),
            "preview_artifact_sha256": str(proof["preview_artifact_sha256"]),
            "expected_send_intent_bindings": [
                {
                    **{
                        field: binding[field]
                        for field in (
                            "intent_id",
                            "idempotency_key",
                            "request_hash",
                            "receipt_id",
                            "receipt_hash",
                        )
                    },
                    "action": "send",
                    "target_intent_id": None,
                    "plan_id": plan.plan_id,
                    "plan_hash": plan.plan_hash,
                }
                for binding in expected_bindings
            ],
        }
        if plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
            start_quote_proof = self._persisted_start_quote_proof_for_plan(plan)
            if start_quote_proof is None:
                raise PlanRejected(
                    "SIMNOW v3 active plan lacks durable start quote proof"
                )
            for binding in expected_bindings:
                intent = state["send_intents"].get(binding["intent_id"])
                if intent is None:
                    continue
                if not isinstance(intent, Mapping):
                    raise PlanRejected("SIMNOW v3 send intent is invalid")
                try:
                    persisted_order_proof = validate_execution_start_quote_proof(
                        intent.get("execution_start_quote_proof"),
                        plan=plan,
                        expected_order_refs=(binding["order_ref"],),
                    )
                except ValueError as exc:
                    raise PlanRejected(
                        "SIMNOW v3 send intent start quote proof does not bind order"
                    ) from exc
                if (
                    intent.get("execution_start_quote_proof_sha256")
                    != persisted_order_proof["proof_sha256"]
                ):
                    raise PlanRejected(
                        "SIMNOW v3 send intent start quote proof mismatches"
                    )
            evidence.update(
                {
                    "execution_run_id": plan.raw["execution_run_id"],
                    "creation_quote_proof_sha256": sha256_json(
                        plan.raw["creation_quote_proof"]
                    ),
                    "start_quote_proof_sha256": start_quote_proof["proof_sha256"],
                }
            )
        return evidence

    def _expired_revoked_rollover_recovery(self, rollover: Mapping[str, Any] | None) -> bool:
        """Allow query-only rollover recovery, never a revoked completion.

        The authority expiry is persisted from the immutable TargetPlan by the
        existing ``enable`` gate.  Recheck that equality here so an arbitrary
        revoked status projection cannot suppress normal finalization.
        """

        if rollover is None:
            return False
        state = self.orchestrator.repository.snapshot()
        active = state.get("plan", {})
        authority = state.get("authority", {})
        if (
            not isinstance(active, Mapping)
            or not isinstance(authority, Mapping)
            or active.get("state") != "ACTIVE"
            or authority.get("state") != "REVOKED"
            or rollover.get("plan_id") != active.get("plan_id")
            or rollover.get("plan_hash") != active.get("plan_hash")
        ):
            return False
        plan = self._plan(str(active["plan_id"]), plan_hash=str(active["plan_hash"]))
        if (
            authority.get("artifact_id") != plan.authority_id
            or authority.get("artifact_hash") != plan.authority_hash
            or authority.get("expires_at") != plan.raw["expires_at"]
        ):
            return False
        try:
            expires_at = datetime.fromisoformat(
                str(authority["expires_at"]).removesuffix("Z") + "+00:00"
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanRejected("SIMNOW revoked authority expiry is invalid") from exc
        return expires_at <= utc_now()

    def _trading_day_rollover_evidence(self) -> dict[str, Any] | None:
        """Prove the narrow fixed CTP LIMIT->GFD day-session boundary."""

        state = self.orchestrator.repository.snapshot()
        active = state.get("plan", {})
        if active.get("state") != "ACTIVE":
            return None
        plan = self._plan(str(active["plan_id"]), plan_hash=str(active["plan_hash"]))
        if (
            plan.raw.get("schema_version") != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            or plan.raw.get("environment") != "SIMNOW"
            or plan.raw.get("gateway_name") != "CTP"
            or any(order.get("type") != "LIMIT" for order in plan.raw["orders"])
        ):
            return None
        generated_at = plan.raw.get("generated_at")
        try:
            generated = datetime.fromisoformat(
                generated_at.removesuffix("Z") + "+00:00"
            )
        except (AttributeError, TypeError, ValueError):
            return None
        local = generated.astimezone(timezone(timedelta(hours=8)))
        minute = local.hour * 60 + local.minute
        if not (8 * 60 + 30 <= minute < 15 * 60):
            return None
        bindings = expected_send_intent_bindings(
            plan,
            account_scope=self.orchestrator.scope,
            environment=self.orchestrator.environment,
        )
        return {
            "schema_version": "execution_gfd_rollover_evidence_v1",
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "intent_trading_day": local.strftime("%Y%m%d"),
            "time_condition": "GFD",
            "intent_ids": sorted(binding["intent_id"] for binding in bindings),
        }

    def resume_active_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Resume only the immutable deterministic children of one ACTIVE plan.

        Existing children are never handed back to ``send_plan_order``: a
        terminal child is reused, and every nonterminal child is query-only.
        Only an absent deterministic child can take the canonical first-send
        path.  Current v2 plans do not carry the required formal quote proof,
        so that missing-child branch remains fail-closed for v2.
        """

        # Local imports avoid making the core execution package depend on the
        # HTTP application at import time while still enforcing the same strict
        # Control/Execution DTO for direct runtime callers.
        from app.schemas.control_execution import (
            ExecutionActivePlanResumeProjection,
            ExecutionActivePlanResumeRequest,
            ExecutionLeaderTokenProjection,
        )

        parsed = ExecutionActivePlanResumeRequest.from_mapping(request).as_dict()
        leader = ExecutionLeaderTokenProjection.from_mapping(parsed["leader_token"])
        token = leader.token_dict()
        terminal_states = TERMINAL_INTENT_STATES
        with self._active_plan_resume_lock:
            plan = self._plan(parsed["plan_id"], plan_hash=parsed["plan_hash"])
            if leader.scope != self.orchestrator.scope:
                raise PlanRejected("resume leader token scope mismatches Execution")
            self.orchestrator.fencer.admission(
                leader_epoch=leader.epoch,
                fencing_token=leader.fencing_token,
                token=token,
            )
            snapshot = parsed["reconciliation_snapshot"]
            state = self.orchestrator.repository.snapshot()
            require_active_resume_boundary(
                state,
                plan=plan,
                snapshot=snapshot,
                account_scope=self.orchestrator.scope,
                environment=self.orchestrator.environment,
            )
            bindings = expected_send_intent_bindings(
                plan,
                account_scope=self.orchestrator.scope,
                environment=self.orchestrator.environment,
            )
            finalization_proof = self._finalization_evidence()
            if (
                finalization_proof is None
                or finalization_proof["plan_id"] != plan.plan_id
                or finalization_proof["plan_hash"] != plan.plan_hash
                or [
                    row["intent_id"]
                    for row in finalization_proof["expected_send_intent_bindings"]
                ]
                != [binding["intent_id"] for binding in bindings]
            ):
                raise PlanRejected(
                    "ACTIVE target plan lacks exact immutable custody binding"
                )
            existing = classify_active_plan_intents(state, plan=plan, bindings=bindings)
            require_snapshot_order_ownership(snapshot, existing=existing)
            missing = [
                binding
                for binding in bindings
                if existing[binding["intent_id"]] is None
            ]
            require_snapshot_state_compatibility(
                state,
                snapshot,
                expected_intent_ids={binding["intent_id"] for binding in bindings},
                has_missing_intent=bool(missing),
            )
            if missing and plan.raw["schema_version"] == (
                KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
            ):
                raise PlanRejected(
                    "TargetPlan v2 missing intent has no formal quote proof; first send is blocked"
                )
            if missing:
                require_first_send_snapshot_closure(state, snapshot)

            actions: dict[str, str] = {}
            effective_states: dict[str, str] = {}

            missing_quote_proof: dict[str, Any] | None = None
            if (
                missing
                and plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            ):
                # Missing-child quote admission must be fully read-only.  Do
                # not query an existing intent (which can advance durable
                # reconciliation state) until every fresh proof required by
                # this resume is materialized and validated.
                missing_quote_proof = self._fresh_start_quote_proof(
                    plan,
                    order_refs=tuple(row["order_ref"] for row in missing),
                )
                post_quote_state = self.orchestrator.repository.snapshot()
                require_active_resume_boundary(
                    post_quote_state,
                    plan=plan,
                    snapshot=snapshot,
                    account_scope=self.orchestrator.scope,
                    environment=self.orchestrator.environment,
                )
                post_quote_existing = classify_active_plan_intents(
                    post_quote_state, plan=plan, bindings=bindings
                )
                if {
                    binding["intent_id"]
                    for binding in bindings
                    if post_quote_existing[binding["intent_id"]] is None
                } != {binding["intent_id"] for binding in missing}:
                    raise PlanRejected(
                        "deterministic intent set changed during fresh quote read"
                    )
                require_snapshot_state_compatibility(
                    post_quote_state,
                    snapshot,
                    expected_intent_ids={binding["intent_id"] for binding in bindings},
                    has_missing_intent=True,
                )
                require_first_send_snapshot_closure(post_quote_state, snapshot)

            def require_current_active() -> None:
                current = self.orchestrator.repository.snapshot()
                active = current.get("plan", {})
                if (
                    active.get("state") != "ACTIVE"
                    or active.get("plan_id") != plan.plan_id
                    or active.get("plan_hash") != plan.plan_hash
                ):
                    raise PlanRejected("ACTIVE target plan changed during resume")
                self.orchestrator.fencer.admission(
                    leader_epoch=leader.epoch,
                    fencing_token=leader.fencing_token,
                    token=token,
                )

            for binding in bindings:
                intent_id = binding["intent_id"]
                raw = existing[intent_id]
                if raw is None:
                    continue
                require_current_active()
                if raw.get("state") in terminal_states:
                    actions[intent_id] = "TERMINAL_REUSED"
                    effective_states[intent_id] = str(raw["state"])
                elif raw.get("state") in {
                    "PERSISTED",
                    "SUBMITTED",
                    "UNKNOWN_OUTCOME",
                }:
                    result = self.orchestrator.query_intent(intent_id)
                    actions[intent_id] = "QUERY_ONLY"
                    queried_state = str(result.get("state", "UNKNOWN_OUTCOME")).upper()
                    effective_states[intent_id] = (
                        "UNKNOWN_OUTCOME"
                        if queried_state in {"UNKNOWN", "UNKNOWN_OUTCOME", ""}
                        else queried_state
                    )
                else:
                    actions[intent_id] = "REUSED"
                    effective_states[intent_id] = str(raw["state"])

            if missing and any(action == "QUERY_ONLY" for action in actions.values()):
                raise ActiveResumeFreshSnapshotRequired(
                    "existing intent query advanced durable state; obtain a fresh reconciliation snapshot"
                )

            if missing:
                current_before_missing = self.orchestrator.repository.snapshot()
                require_active_resume_boundary(
                    current_before_missing,
                    plan=plan,
                    snapshot=snapshot,
                    account_scope=self.orchestrator.scope,
                    environment=self.orchestrator.environment,
                )
                current_existing = classify_active_plan_intents(
                    current_before_missing, plan=plan, bindings=bindings
                )
                if {
                    binding["intent_id"]
                    for binding in bindings
                    if current_existing[binding["intent_id"]] is None
                } != {binding["intent_id"] for binding in missing}:
                    raise PlanRejected(
                        "deterministic intent set changed before first send"
                    )
                require_snapshot_state_compatibility(
                    current_before_missing,
                    snapshot,
                    expected_intent_ids={binding["intent_id"] for binding in bindings},
                    has_missing_intent=True,
                )
                require_first_send_snapshot_closure(current_before_missing, snapshot)
                for binding in missing:
                    require_current_active()
                    result = self.send_plan_order(
                        plan.plan_id,
                        binding["order_ref"],
                        token=token,
                        execution_start_quote_proof=missing_quote_proof,
                    )
                    actions[binding["intent_id"]] = "FIRST_SEND"
                    effective_states[binding["intent_id"]] = str(
                        result.get("state", "")
                    )

            final_state = self.orchestrator.repository.snapshot()
            final_existing = classify_active_plan_intents(
                final_state, plan=plan, bindings=bindings
            )
            rows: list[dict[str, str]] = []
            for binding in bindings:
                intent_id = binding["intent_id"]
                raw = final_existing[intent_id]
                if raw is None:
                    raise PlanRejected(
                        "deterministic send intent disappeared during resume"
                    )
                durable_state = str(raw["state"])
                row_state = effective_states.get(intent_id, durable_state)
                if durable_state in terminal_states:
                    row_state = durable_state
                rows.append(
                    {
                        "intent_id": intent_id,
                        "state": row_state,
                        "resume_action": actions[intent_id],
                    }
                )
            terminal_count = sum(row["state"] in terminal_states for row in rows)
            preimage = {
                "schema_version": "web_bridge_execution_active_plan_resume_v1",
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "state": ("TERMINAL" if terminal_count == len(bindings) else "ACTIVE"),
                "expected_intent_count": len(bindings),
                "terminal_intent_count": terminal_count,
                "queried_intent_count": sum(
                    action == "QUERY_ONLY" for action in actions.values()
                ),
                "new_intent_count": sum(
                    action == "FIRST_SEND" for action in actions.values()
                ),
                "reused_intent_count": sum(
                    action != "FIRST_SEND" for action in actions.values()
                ),
                "intents": rows,
                "production_allowed": False,
                "live_trading_authorized": False,
                "countable_forward": False,
            }
            return ExecutionActivePlanResumeProjection.from_mapping(
                {**preimage, "resume_sha256": sha256_json(preimage)}
            ).as_dict()

    def _fresh_start_quote_proof(
        self, plan: TargetPlan, *, order_refs: tuple[str, ...] | None = None
    ) -> dict[str, Any]:
        try:
            return build_execution_start_quote_proof(
                plan,
                order_refs=order_refs,
                reader=self.formal_tick_bindings_reader,
                clock=self.quote_clock,
            )
        except ExecutionStartQuotePriceIncompatible as exc:
            raise StartQuoteReplanRequired(str(exc)) from exc
        except FormalTickSourceUnavailable as exc:
            raise StartQuoteSourceUnavailable(str(exc)) from exc
        except (
            FormalTickEvidenceInvalid,
            FormalTickReadError,
            ExecutionStartQuoteProofError,
            TypeError,
            ValueError,
        ) as exc:
            raise StartQuoteEvidenceInvalid(str(exc)) from exc

    def _persisted_start_quote_proof(
        self, envelope: CommandEnvelope, plan: TargetPlan
    ) -> dict[str, Any] | None:
        key = f"{envelope.actor.service}:{envelope.idempotency_key}"
        receipt = self.orchestrator.repository.snapshot().get("receipts", {}).get(key)
        if receipt is None:
            return None
        if (
            not isinstance(receipt, Mapping)
            or receipt.get("command_hash") != envelope.command_hash()
            or receipt.get("status") != "COMPLETED"
            or not isinstance(receipt.get("result"), Mapping)
            or receipt["result"].get("accepted") is not True
        ):
            raise StartQuoteEvidenceInvalid(
                "persisted start receipt does not bind exact accepted command"
            )
        try:
            return validate_execution_start_quote_proof(
                receipt["result"].get("execution_start_quote_proof"), plan=plan
            )
        except ValueError as exc:
            raise StartQuoteEvidenceInvalid(
                "persisted execution start quote proof is invalid"
            ) from exc

    def process_command(
        self, command: CommandEnvelope | Mapping[str, Any]
    ) -> CommandResponse:
        """Accept lifecycle commands only, with plan/receipt gates before enable/start."""

        envelope = (
            command
            if isinstance(command, CommandEnvelope)
            else CommandEnvelope.from_mapping(command)
        )
        if (
            envelope.command == "preview"
            and envelope.payload["mode"] == "simnow_preview"
        ):
            plan, receipt = self._preview_from_custody(envelope.payload["receipt_id"])
            if (
                envelope.payload["plan_hash"] != plan.plan_hash
                or envelope.payload["artifact_hash"] != receipt.artifact_sha256
            ):
                raise PlanRejected("SIMNOW preview plan/artifact hash mismatch")
            return self.orchestrator.process_command(
                envelope,
                preview_evidence={
                    "plan_hash": plan.plan_hash,
                    "receipt_id": receipt.receipt_id,
                    "receipt_sha256": receipt.receipt_sha256,
                    "artifact_id": receipt.artifact_id,
                    "artifact_sha256": receipt.artifact_sha256,
                },
            )
        if envelope.command == "enable":
            plan = self.plans.find_authority(
                envelope.payload["authority_artifact_id"],
                envelope.payload["authority_hash"],
            )
            if plan is None:
                raise AuthorityRejected("no installed target plan binds this authority")
            self._plan_from_value(plan)
            if envelope.payload["expires_at"] != plan.raw["expires_at"]:
                raise AuthorityRejected("enable authority expiry is not receipt-bound")
        elif envelope.command == "start":
            if not self.allow_simnow_execution:
                raise AuthorityRejected("SIMNOW execution is locally disabled")
            plan = self._plan(
                envelope.payload["plan_id"], plan_hash=envelope.payload["plan_hash"]
            )
            persisted_quote_proof = (
                self._persisted_start_quote_proof(envelope, plan)
                if plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
                else None
            )
            if persisted_quote_proof is not None:
                response = self.orchestrator.process_command(
                    envelope, start_evidence=persisted_quote_proof
                )
                return self._dispatch_accepted_start(
                    response, plan=plan, quote_proof=persisted_quote_proof
                )
            prior = self.orchestrator.repository.snapshot()
            expected_preview_id = f"preview-{plan.plan_hash[:16]}"
            try:
                current_position_hash = before_position_projection_hash(
                    prior["broker"].get("positions"),
                    account_scope=self.orchestrator.scope,
                    environment=self.orchestrator.environment,
                )
            except CommodityExecutionContractError as exc:
                raise PlanRejected(
                    "SIMNOW start current position projection is invalid"
                ) from exc
            if (
                prior["plan"].get("state") != "PREVIEWED"
                or prior["plan"].get("plan_id") != expected_preview_id
                or prior["plan"].get("plan_hash") != plan.plan_hash
                or prior["plan"].get("preview_mode") != "simnow_preview"
                or not isinstance(prior["plan"].get("preview_receipt_id"), str)
                or prior["plan"].get("preview_receipt_id") == "unknown00"
                or prior["plan"].get("preview_receipt_sha256") == "0" * 64
                or prior["plan"].get("preview_artifact_id") == "unknown00"
                or prior["plan"].get("preview_artifact_sha256") == "0" * 64
                or prior["reconciliation"].get("state") != "RECONCILED"
                or current_position_hash != plan.raw["expected_before_position_hash"]
            ):
                raise PlanRejected(
                    "SIMNOW start lacks matching preview/reconciliation/position proof"
                )
            preview_plan, preview_receipt = self._preview_from_custody(
                str(prior["plan"]["preview_receipt_id"])
            )
            if (
                preview_plan.plan_hash != plan.plan_hash
                or preview_receipt.receipt_sha256
                != prior["plan"]["preview_receipt_sha256"]
                or preview_receipt.artifact_id != prior["plan"]["preview_artifact_id"]
                or preview_receipt.artifact_sha256
                != prior["plan"]["preview_artifact_sha256"]
            ):
                raise PlanRejected(
                    "SIMNOW preview custody evidence changed after restart"
                )
            if (
                envelope.expected.leader_epoch is None
                or envelope.expected.fencing_token is None
            ):
                raise MutationRejected("SIMNOW start requires an explicit leader fence")
            self.orchestrator.fencer.admission(
                leader_epoch=envelope.expected.leader_epoch,
                fencing_token=envelope.expected.fencing_token,
                token=self.orchestrator.fencer.token,
            )
            quote_proof = (
                self._fresh_start_quote_proof(plan)
                if plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
                else None
            )
            response = self.orchestrator.process_command(
                envelope, start_evidence=quote_proof
            )
            return self._dispatch_accepted_start(
                response, plan=plan, quote_proof=quote_proof
            )
        rollover_evidence = None
        finalization_evidence = None
        if envelope.command == "reconcile":
            rollover_evidence = self._trading_day_rollover_evidence()
            finalization_evidence = self._finalization_evidence()
            if self._expired_revoked_rollover_recovery(rollover_evidence):
                finalization_evidence = None
        return self.orchestrator.process_command(
            envelope,
            finalization_evidence=finalization_evidence,
            rollover_evidence=rollover_evidence,
        )

    def _dispatch_accepted_start(
        self,
        response: CommandResponse,
        *,
        plan: TargetPlan,
        quote_proof: Mapping[str, Any] | None,
    ) -> CommandResponse:
        if response.result.get("accepted") is not True:
            return response
        token = self.orchestrator.fencer.token
        if token is None:
            raise MutationRejected("SIMNOW runner lost its leader token")
        proof_for_missing = quote_proof
        if (
            response.reused
            and plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
        ):
            state = self.orchestrator.repository.snapshot()
            bindings = expected_send_intent_bindings(
                plan,
                account_scope=self.orchestrator.scope,
                environment=self.orchestrator.environment,
            )
            missing_refs = tuple(
                binding["order_ref"]
                for binding in bindings
                if state["intent_keys"].get(binding["idempotency_key"])
                != binding["intent_id"]
            )
            if missing_refs:
                proof_for_missing = self._fresh_start_quote_proof(
                    plan, order_refs=missing_refs
                )
        for order in plan.orders:
            dispatch_proof = proof_for_missing
            if plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
                state = self.orchestrator.repository.snapshot()
                binding = next(
                    item
                    for item in expected_send_intent_bindings(
                        plan,
                        account_scope=self.orchestrator.scope,
                        environment=self.orchestrator.environment,
                    )
                    if item["order_ref"] == order.reference
                )
                existing_id = state["intent_keys"].get(binding["idempotency_key"])
                existing = state["send_intents"].get(existing_id, {})
                if (
                    isinstance(existing, Mapping)
                    and existing.get("execution_start_quote_proof") is not None
                ):
                    dispatch_proof = existing["execution_start_quote_proof"]
            try:
                result = self.send_plan_order(
                    plan.plan_id,
                    order.reference,
                    token=token,
                    execution_start_quote_proof=dispatch_proof,
                )
            except Exception as exc:
                self._halt_runner_after_failure(
                    f"SIMNOW runner order {order.reference} failed: {exc}"
                )
                raise
            if result.get("accepted") is not True or str(
                result.get("state", "")
            ).upper() not in {"SUBMITTED", "ACKNOWLEDGED"}:
                self._halt_runner_after_failure(
                    f"SIMNOW runner order {order.reference} was not accepted"
                )
                raise MutationRejected(
                    "SIMNOW runner order was rejected or has unknown outcome"
                )
        return response

    def _token(
        self, token: LeaderToken | Mapping[str, Any] | None
    ) -> LeaderToken | Mapping[str, Any]:
        if token is None:
            raise MutationRejected(
                "SIMNOW plan mutation requires an explicit leader token"
            )
        return token

    def send_plan_order(
        self,
        plan_id: str,
        order_ref: str,
        *,
        token: LeaderToken | Mapping[str, Any] | None,
        execution_start_quote_proof: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit one plan order through the canonical Execution adapter."""

        if not self.allow_simnow_execution:
            raise AuthorityRejected("SIMNOW execution is locally disabled")
        plan = self._plan(plan_id)
        order = plan.order(order_ref)
        binding = next(
            item
            for item in expected_send_intent_bindings(
                plan,
                account_scope=self.orchestrator.scope,
                environment=self.orchestrator.environment,
            )
            if item["order_ref"] == order.reference
        )
        idempotency_key = binding["idempotency_key"]
        intent_id = binding["intent_id"]
        status = self.orchestrator.status()
        # A halted lifecycle must never admit a *new* send.  The exact same
        # deterministic intent is still handed to the core, which returns its
        # durable UNKNOWN_OUTCOME/reconciled result without replaying the RPC.
        existing = self.orchestrator.repository.snapshot()["intent_keys"].get(
            idempotency_key
        )
        if (
            status["lifecycle"] != "READY"
            or status["plan"]["state"] != "ACTIVE"
            or status["plan"]["plan_id"] != plan.plan_id
            or status["plan"]["plan_hash"] != plan.plan_hash
        ) and existing != intent_id:
            raise PlanRejected(
                "target plan is not the active reconciled execution plan"
            )
        leader = self._token(token)
        order_quote_proof = None
        if plan.raw["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
            if execution_start_quote_proof is None:
                raise StartQuoteEvidenceInvalid(
                    "TargetPlan v3 first send lacks execution start quote proof"
                )
            try:
                order_quote_proof = quote_proof_for_order(
                    execution_start_quote_proof,
                    plan=plan,
                    order_ref=order.reference,
                )
            except ExecutionStartQuotePriceIncompatible as exc:
                raise StartQuoteReplanRequired(str(exc)) from exc
            except ValueError as exc:
                raise StartQuoteEvidenceInvalid(str(exc)) from exc
        return self.orchestrator.submit_planned_order(
            order.as_dict(),
            idempotency_key=idempotency_key,
            plan_id=plan.plan_id,
            plan_hash=plan.plan_hash,
            leader_epoch=int(
                leader.epoch if isinstance(leader, LeaderToken) else leader["epoch"]
            ),
            fencing_token=int(
                leader.fencing_token
                if isinstance(leader, LeaderToken)
                else leader["fencing_token"]
            ),
            token=leader,
            intent_id=intent_id,
            execution_start_quote_proof=order_quote_proof,
        )

    def cancel_plan_intent(
        self,
        plan_id: str,
        intent_id: str,
        *,
        token: LeaderToken | Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Cancel a plan-owned intent through the canonical Execution adapter."""

        plan = self._plan(plan_id)
        intent_id = validate_identifier(intent_id, "intent_id")
        raw = self.orchestrator.repository.snapshot()["send_intents"].get(intent_id)
        if not isinstance(raw, Mapping) or (
            raw.get("plan_id") != plan.plan_id or raw.get("plan_hash") != plan.plan_hash
        ):
            raise PlanRejected("intent is not owned by this immutable target plan")
        leader = self._token(token)
        cancel_seed = sha256_json(
            {
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "intent_id": intent_id,
            }
        )
        return self.orchestrator.cancel_planned_intent(
            intent_id,
            idempotency_key=f"cancel-{cancel_seed[:30]}",
            plan_id=plan.plan_id,
            plan_hash=plan.plan_hash,
            leader_epoch=int(
                leader.epoch if isinstance(leader, LeaderToken) else leader["epoch"]
            ),
            fencing_token=int(
                leader.fencing_token
                if isinstance(leader, LeaderToken)
                else leader["fencing_token"]
            ),
            token=leader,
            intent_id=f"cancel-{cancel_seed[:24]}",
        )


__all__ = [
    "CustodyReadClient",
    "DurableTargetPlanRepository",
    "FinalExecutionRuntime",
    "InMemoryTargetPlanRepository",
    "TargetPlanRepository",
]
