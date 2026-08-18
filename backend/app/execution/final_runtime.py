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
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from shared.artifact_contracts.v1 import (
    ContractError as ArtifactContractError,
)
from shared.artifact_contracts.v1 import (
    validate_artifact_envelope,
)
from shared.commodity_execution.v1 import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
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

from .errors import (
    AuthorityRejected,
    GatewayUnavailable,
    MutationRejected,
    PlanRejected,
    RepositoryUnavailableError,
)
from .models import CommandEnvelope, LeaderToken, validate_identifier
from .orchestrator import CommandResponse, ExecutionOrchestrator


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
        except (AuthorityRejected, PlanRejected):
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
        """Project one completed immutable TargetPlan v2, if any.

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
        if plan.raw["schema_version"] != KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION:
            raise PlanRejected("latest completion target plan is not v2")
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
        return {
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "schema_version": plan.raw["schema_version"],
            "phase": plan.raw["phase"],
            "lineage": dict(plan.raw["lineage"]),
            "expected_after_position_hash": plan.raw["expected_after_position_hash"],
            "target_position_hash": completed["target_position_hash"],
            "archived_at": completed["archived_at"],
        }

    def latest_completion_projection(self) -> dict[str, Any] | None:
        """Project the latest completed immutable TargetPlan v2, if any."""

        return self.completion_projection()

    def recovery_projection(self, *, custody_idempotency_key: str) -> dict[str, Any]:
        """Classify one custody key without changing custody or plan storage.

        A missing receipt is ``BEFORE_CUSTODY``.  A verified receipt/artifact
        chain is returned with the exact immutable v2 plan identity and an
        explicit local installation state, so a response lost before preview
        can reuse the original receipt rather than publish a second identity.
        """

        validate_identifier(custody_idempotency_key, "custody_idempotency_key")
        try:
            raw_receipt = self.custody.receipt_by_idempotency(custody_idempotency_key)
        except (AuthorityRejected, PlanRejected):
            raise
        except Exception as exc:
            raise GatewayUnavailable(
                "custody idempotency lookup outcome is unknown"
            ) from exc
        if raw_receipt is None:
            preimage = {
                "schema_version": "web_bridge_execution_target_plan_recovery_v1",
                "state": "BEFORE_CUSTODY",
                "custody_idempotency_key": custody_idempotency_key,
                "production_allowed": False,
                "live_trading_authorized": False,
                "countable_forward": False,
            }
            return {**preimage, "recovery_sha256": sha256_json(preimage)}
        plan, receipt, artifact_envelope_sha256 = (
            self._target_plan_from_custody_receipt(
                raw_receipt, require_current_expiry=False
            )
        )
        if not isinstance(receipt, TrustedKeylessCustodyReceipt):
            raise PlanRejected("recovery receipt is not trusted keyless custody")
        if plan.raw["schema_version"] != KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION:
            raise PlanRejected("recovery target plan is not v2")
        if receipt.raw["idempotency_key"] != f"install-{custody_idempotency_key}":
            raise PlanRejected("recovery custody idempotency binding mismatches")
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

        preimage = {
            "schema_version": "web_bridge_execution_target_plan_recovery_v1",
            "state": (
                "INSTALLED"
                if installed is not None
                else "CUSTODY_PUBLISHED_NOT_PREVIEWED"
            ),
            "custody_idempotency_key": custody_idempotency_key,
            "custody_install_idempotency_key": receipt.raw["idempotency_key"],
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
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }
        return {**preimage, "recovery_sha256": sha256_json(preimage)}

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

    def _finalization_evidence(self) -> dict[str, str] | None:
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
        return {
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
        }

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
            response = self.orchestrator.process_command(envelope)
            if response.result.get("accepted") is True:
                token = self.orchestrator.fencer.token
                if (
                    token is None
                ):  # admission above prevents this; preserve fail-closed behaviour
                    raise MutationRejected("SIMNOW runner lost its leader token")
                for order in plan.orders:
                    try:
                        result = self.send_plan_order(
                            plan.plan_id, order.reference, token=token
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
        finalization_evidence = (
            self._finalization_evidence() if envelope.command == "reconcile" else None
        )
        return self.orchestrator.process_command(
            envelope, finalization_evidence=finalization_evidence
        )

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
    ) -> dict[str, Any]:
        """Submit one plan order through the canonical Execution adapter."""

        if not self.allow_simnow_execution:
            raise AuthorityRejected("SIMNOW execution is locally disabled")
        plan = self._plan(plan_id)
        order = plan.order(order_ref)
        intent_seed = sha256_json(
            {
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "order_ref": order.reference,
            }
        )
        idempotency_key = f"send-{intent_seed[:32]}"
        intent_id = f"intent-{intent_seed[:24]}"
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
