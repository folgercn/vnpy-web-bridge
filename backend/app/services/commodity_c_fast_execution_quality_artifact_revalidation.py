from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from app.schemas.commodity_c_fast_execution_quality_runtime import (
    ArtifactRole,
    CFastExecutionQualityArtifactVerificationDTO,
    CFastExecutionQualityRuntimeRevalidationDTO,
    CFastExecutionQualityVerifiedRuntimeInputsDTO,
    RevalidationTrigger,
)
from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionQualityCollectionPolicyV2DTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPlanDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
)


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
ARTIFACT_ROLES: tuple[ArtifactRole, ...] = (
    "signed_p0_acceptance",
    "collection_admission",
    "execution_policy",
    "signed_snapshot",
    "virtual_intent_plan",
    "contract_spec_set",
    "custody_binding",
)
_REQUIRED_BINDINGS: dict[ArtifactRole, frozenset[ArtifactRole]] = {
    "signed_p0_acceptance": frozenset(),
    "collection_admission": frozenset({"signed_p0_acceptance", "execution_policy"}),
    "execution_policy": frozenset(),
    "signed_snapshot": frozenset({"contract_spec_set"}),
    "virtual_intent_plan": frozenset(
        {"execution_policy", "signed_snapshot", "contract_spec_set"}
    ),
    "contract_spec_set": frozenset(),
    "custody_binding": frozenset(ARTIFACT_ROLES[:-1]),
}
_TEMPORAL_ROLES = frozenset(
    {
        "signed_p0_acceptance",
        "collection_admission",
        "signed_snapshot",
        "custody_binding",
    }
)
_CONTRACT_BOUND_ROLES = frozenset(
    {
        "signed_p0_acceptance",
        "collection_admission",
        "signed_snapshot",
        "virtual_intent_plan",
        "contract_spec_set",
        "custody_binding",
    }
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


class CFastExecutionQualityArtifactRevalidationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ArtifactVerificationRequest:
    role: ArtifactRole
    path: Path
    payload: Mapping[str, Any]
    raw: bytes
    raw_sha256: str
    canonical_sha256: str
    observed_at_utc: datetime


@dataclass(frozen=True, slots=True)
class SignedArtifactVerification:
    """Role verifier output tied to the exact bytes in its request.

    Only the four fields needed by the Tick worker may carry a typed value.
    The stable-file adapter validates their role, exact-contract and hash joins
    before releasing one atomic runtime-input bundle.
    """

    verification: CFastExecutionQualityArtifactVerificationDTO
    preverified_plan: CFastVirtualIntentPlanDTO | None = None
    source_snapshot_receipt_sha256: str | None = None
    score_policy: CFastExecutionQualityCollectionPolicyV2DTO | None = None
    contract_specs: tuple[CFastExecutionQualityContractSpecDTO, ...] | None = None


class SignedArtifactVerifier(Protocol):
    def __call__(
        self,
        request: ArtifactVerificationRequest,
    ) -> SignedArtifactVerification: ...


class SignedArtifactBundleVerifier(Protocol):
    """Verify one complete stable-read generation as a single unit.

    Production roles have semantic dependencies (snapshot -> plan -> specs)
    that cannot be safely reconstructed by seven isolated callbacks.  The
    bundle callback receives only the exact bytes already retained by this
    adapter and must return one result for every role.
    """

    def __call__(
        self,
        requests: Mapping[ArtifactRole, ArtifactVerificationRequest],
    ) -> Mapping[ArtifactRole, SignedArtifactVerification]: ...


@dataclass(frozen=True)
class _ExactArtifact:
    path: Path
    payload: dict[str, Any]
    raw: bytes
    raw_sha256: str
    canonical_sha256: str
    identity: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class _CustodyRootGuard:
    path: Path
    fd: int
    identity: tuple[int, int, int, int, int]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True, init=False)
class CommodityCFastExecutionQualityArtifactRevalidator:
    """Stable-file join for seven independently verified signed artifacts.

    Signature and source-contract replay remain role-specific and are supplied
    as immutable callbacks. This adapter owns exact-file custody, complete role
    coverage, cross-artifact hash joins, validity joins and final rereads. It
    has no Tick, QuestDB, RPC, account, position or order dependency.
    """

    _artifact_paths: Mapping[ArtifactRole, Path]
    _artifact_verifiers: Mapping[ArtifactRole, SignedArtifactVerifier] | None
    _artifact_bundle_verifier: SignedArtifactBundleVerifier | None
    custody_root: Path
    expected_custody_root_path_sha256: str
    expected_custody_identity_sha256: str
    expected_owner_uid: int

    def __init__(
        self,
        *,
        artifact_paths: Mapping[ArtifactRole, Path],
        artifact_verifiers: Mapping[ArtifactRole, SignedArtifactVerifier] | None = None,
        artifact_bundle_verifier: SignedArtifactBundleVerifier | None = None,
        custody_root: Path,
        expected_custody_root_path_sha256: str,
        expected_custody_identity_sha256: str,
        expected_owner_uid: int = 0,
    ) -> None:
        if (
            _SHA256_PATTERN.fullmatch(expected_custody_root_path_sha256) is None
            or _SHA256_PATTERN.fullmatch(expected_custody_identity_sha256) is None
            or type(expected_owner_uid) is not int
            or expected_owner_uid < 0
        ):
            raise CFastExecutionQualityArtifactRevalidationError(
                "ARTIFACT_REVALIDATION_CONFIG_PIN_INVALID"
            )
        object.__setattr__(
            self,
            "_artifact_paths",
            MappingProxyType(dict(artifact_paths)),
        )
        if (artifact_verifiers is None) == (artifact_bundle_verifier is None):
            raise CFastExecutionQualityArtifactRevalidationError(
                "ARTIFACT_VERIFIER_MODE_INVALID"
            )
        object.__setattr__(
            self,
            "_artifact_verifiers",
            (
                MappingProxyType(dict(artifact_verifiers))
                if artifact_verifiers is not None
                else None
            ),
        )
        object.__setattr__(
            self,
            "_artifact_bundle_verifier",
            artifact_bundle_verifier,
        )
        object.__setattr__(self, "custody_root", custody_root)
        object.__setattr__(
            self,
            "expected_custody_root_path_sha256",
            expected_custody_root_path_sha256,
        )
        object.__setattr__(
            self,
            "expected_custody_identity_sha256",
            expected_custody_identity_sha256,
        )
        object.__setattr__(self, "expected_owner_uid", expected_owner_uid)

    def __call__(
        self,
        trigger: RevalidationTrigger,
        observed_at_utc: datetime,
    ) -> CFastExecutionQualityVerifiedRuntimeInputsDTO:
        self._require_utc(observed_at_utc)
        root = self._open_custody_root()
        if set(self._artifact_paths) != set(ARTIFACT_ROLES):
            os.close(root.fd)
            raise CFastExecutionQualityArtifactRevalidationError(
                "ARTIFACT_PATH_SET_INCOMPLETE"
            )
        if self._artifact_verifiers is not None and set(
            self._artifact_verifiers
        ) != set(ARTIFACT_ROLES):
            os.close(root.fd)
            raise CFastExecutionQualityArtifactRevalidationError(
                "ARTIFACT_VERIFIER_SET_INCOMPLETE"
            )
        try:
            opened: dict[ArtifactRole, _ExactArtifact] = {}
            resolved_names: set[str] = set()
            for role in ARTIFACT_ROLES:
                artifact = self._read_exact(role, self._artifact_paths[role], root)
                if artifact.path.name in resolved_names:
                    raise CFastExecutionQualityArtifactRevalidationError(
                        "ARTIFACT_PATH_COLLISION"
                    )
                resolved_names.add(artifact.path.name)
                opened[role] = artifact

            requests = {
                role: ArtifactVerificationRequest(
                    role=role,
                    path=opened[role].path,
                    payload=opened[role].payload,
                    raw=opened[role].raw,
                    raw_sha256=opened[role].raw_sha256,
                    canonical_sha256=opened[role].canonical_sha256,
                    observed_at_utc=observed_at_utc,
                )
                for role in ARTIFACT_ROLES
            }
            if self._artifact_bundle_verifier is not None:
                candidates = dict(self._artifact_bundle_verifier(requests))
                if set(candidates) != set(ARTIFACT_ROLES):
                    raise CFastExecutionQualityArtifactRevalidationError(
                        "ARTIFACT_BUNDLE_VERIFIER_RESULT_SET_INCOMPLETE"
                    )
            else:
                assert self._artifact_verifiers is not None
                candidates = {
                    role: self._artifact_verifiers[role](requests[role])
                    for role in ARTIFACT_ROLES
                }

            verified: dict[
                ArtifactRole, CFastExecutionQualityArtifactVerificationDTO
            ] = {}
            signed_results: dict[ArtifactRole, SignedArtifactVerification] = {}
            for role in ARTIFACT_ROLES:
                artifact = opened[role]
                candidate = candidates[role]
                if type(candidate) is not SignedArtifactVerification:
                    raise CFastExecutionQualityArtifactRevalidationError(
                        "ARTIFACT_VERIFIER_RESULT_TYPE_INVALID"
                    )
                result = CFastExecutionQualityArtifactVerificationDTO.model_validate(
                    candidate.verification
                )
                if (
                    result.artifact_role != role
                    or not hmac.compare_digest(result.raw_sha256, artifact.raw_sha256)
                    or not hmac.compare_digest(
                        result.canonical_sha256, artifact.canonical_sha256
                    )
                ):
                    raise CFastExecutionQualityArtifactRevalidationError(
                        "ARTIFACT_VERIFIER_IDENTITY_MISMATCH"
                    )
                verified[role] = result
                signed_results[role] = candidate

            self._verify_join(verified, opened, observed_at_utc)
            typed_inputs = self._verify_typed_inputs(signed_results)
            for role in ARTIFACT_ROLES:
                reread = self._read_exact(role, self._artifact_paths[role], root)
                original = opened[role]
                if reread.raw != original.raw or reread.identity != original.identity:
                    raise CFastExecutionQualityArtifactRevalidationError(
                        "ARTIFACT_CHANGED_DURING_REVALIDATION"
                    )
            self._verify_open_custody_root(root)
        finally:
            os.close(root.fd)

        exact_contracts = next(
            result.exact_contracts
            for result in verified.values()
            if result.exact_contracts
        )
        valid_until = min(
            result.valid_until_utc
            for result in verified.values()
            if result.valid_until_utc is not None
        )
        core = {
            "schema_version": (
                "commodity_c_fast_execution_quality_runtime_revalidation_v1"
            ),
            "trigger": trigger,
            "revalidated_at_utc": observed_at_utc.isoformat().replace("+00:00", "Z"),
            "valid_until_utc": valid_until.isoformat().replace("+00:00", "Z"),
            "exact_contracts": list(exact_contracts),
            "signed_p0_acceptance_sha256": opened["signed_p0_acceptance"].raw_sha256,
            "collection_admission_sha256": opened["collection_admission"].raw_sha256,
            "execution_policy_sha256": opened["execution_policy"].raw_sha256,
            "signed_snapshot_sha256": opened["signed_snapshot"].raw_sha256,
            "virtual_intent_plan_sha256": opened["virtual_intent_plan"].raw_sha256,
            "contract_spec_set_sha256": opened["contract_spec_set"].raw_sha256,
            "custody_binding_sha256": opened["custody_binding"].raw_sha256,
            "verified_signer_domains": {
                role: list(verified[role].verified_signer_domain_public_key_sha256)
                for role in ARTIFACT_ROLES
            },
            "p0_acceptance_state": "VERIFIED",
            "collection_admission_state": "VERIFIED",
            "execution_policy_state": "VERIFIED",
            "signed_snapshot_state": "VERIFIED",
            "virtual_intent_plan_state": "VERIFIED",
            "contract_spec_state": "VERIFIED",
            "custody_state": "VERIFIED",
            **_FALSE_AUTHORITY,
        }
        receipt = CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
            {**core, "receipt_sha256": _sha256(_canonical_json(core))}
        )
        bundle_core = {
            "schema_version": (
                "commodity_c_fast_execution_quality_verified_runtime_inputs_v1"
            ),
            "revalidation_receipt": receipt.model_dump(mode="json"),
            "preverified_plan": typed_inputs["preverified_plan"].model_dump(
                mode="json"
            ),
            "source_snapshot_receipt_sha256": typed_inputs[
                "source_snapshot_receipt_sha256"
            ],
            "score_policy": typed_inputs["score_policy"].model_dump(mode="json"),
            "score_policy_hash": _sha256(
                _canonical_json(
                    typed_inputs["score_policy"].model_dump(mode="json")
                )
            ),
            "contract_specs": [
                spec.model_dump(mode="json")
                for spec in typed_inputs["contract_specs"]
            ],
        }
        return CFastExecutionQualityVerifiedRuntimeInputsDTO.model_validate(
            {
                **bundle_core,
                "verified_inputs_sha256": _sha256(_canonical_json(bundle_core)),
            }
        )

    @staticmethod
    def _verify_typed_inputs(
        results: Mapping[ArtifactRole, SignedArtifactVerification],
    ) -> dict[str, Any]:
        expected_fields: dict[ArtifactRole, tuple[str, ...]] = {
            "signed_p0_acceptance": (),
            "collection_admission": (),
            "execution_policy": ("score_policy",),
            "signed_snapshot": ("source_snapshot_receipt_sha256",),
            "virtual_intent_plan": ("preverified_plan",),
            "contract_spec_set": ("contract_specs",),
            "custody_binding": (),
        }
        fields = (
            "preverified_plan",
            "source_snapshot_receipt_sha256",
            "score_policy",
            "contract_specs",
        )
        for role in ARTIFACT_ROLES:
            populated = tuple(
                field for field in fields if getattr(results[role], field) is not None
            )
            if populated != expected_fields[role]:
                raise CFastExecutionQualityArtifactRevalidationError(
                    "ARTIFACT_TYPED_INPUT_ROLE_MISMATCH"
                )
        plan = results["virtual_intent_plan"].preverified_plan
        source_receipt = results["signed_snapshot"].source_snapshot_receipt_sha256
        policy = results["execution_policy"].score_policy
        specs = results["contract_spec_set"].contract_specs
        if (
            type(plan) is not CFastVirtualIntentPlanDTO
            or not isinstance(source_receipt, str)
            or type(policy) is not CFastExecutionQualityCollectionPolicyV2DTO
            or type(specs) is not tuple
            or any(type(spec) is not CFastExecutionQualityContractSpecDTO for spec in specs)
        ):
            raise CFastExecutionQualityArtifactRevalidationError(
                "ARTIFACT_TYPED_INPUT_TYPE_INVALID"
            )
        return {
            "preverified_plan": CFastVirtualIntentPlanDTO.model_validate(
                plan.model_dump(mode="json")
            ),
            "source_snapshot_receipt_sha256": source_receipt,
            "score_policy": CFastExecutionQualityCollectionPolicyV2DTO.model_validate(
                policy.model_dump(mode="json")
            ),
            "contract_specs": tuple(
                CFastExecutionQualityContractSpecDTO.model_validate(
                    spec.model_dump(mode="json")
                )
                for spec in specs
            ),
        }

    def _verify_join(
        self,
        verified: Mapping[ArtifactRole, CFastExecutionQualityArtifactVerificationDTO],
        opened: Mapping[ArtifactRole, _ExactArtifact],
        observed_at_utc: datetime,
    ) -> None:
        if any(not verified[role].exact_contracts for role in _CONTRACT_BOUND_ROLES):
            raise CFastExecutionQualityArtifactRevalidationError(
                "EXACT_CONTRACT_SET_MISSING"
            )
        contract_sets = {
            verified[role].exact_contracts for role in _CONTRACT_BOUND_ROLES
        }
        if len(contract_sets) != 1:
            raise CFastExecutionQualityArtifactRevalidationError(
                "EXACT_CONTRACT_SET_MISMATCH"
            )
        for role in _TEMPORAL_ROLES:
            expiry = verified[role].valid_until_utc
            if expiry is None or expiry <= observed_at_utc:
                raise CFastExecutionQualityArtifactRevalidationError(
                    "ARTIFACT_EXPIRED_OR_MISSING_EXPIRY"
                )
        for role in ARTIFACT_ROLES:
            bindings = verified[role].bound_artifact_raw_sha256
            required = _REQUIRED_BINDINGS[role]
            if set(bindings) != set(required):
                raise CFastExecutionQualityArtifactRevalidationError(
                    "ARTIFACT_BINDING_SET_MISMATCH"
                )
            for bound_role, digest in bindings.items():
                if not hmac.compare_digest(digest, opened[bound_role].raw_sha256):
                    raise CFastExecutionQualityArtifactRevalidationError(
                        "ARTIFACT_BINDING_DIGEST_MISMATCH"
                    )

    def _open_custody_root(self) -> _CustodyRootGuard:
        root = self.custody_root.expanduser()
        try:
            if (
                not root.is_absolute()
                or root.resolve(strict=True) != root
                or not self._safe_parent_chain(root)
            ):
                raise OSError
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            fd = os.open(root, flags)
            info = os.fstat(fd)
        except OSError as exc:
            raise CFastExecutionQualityArtifactRevalidationError(
                "CUSTODY_ROOT_INVALID"
            ) from exc
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.expected_owner_uid
            or mode & 0o022
        ):
            os.close(fd)
            raise CFastExecutionQualityArtifactRevalidationError("CUSTODY_ROOT_INVALID")
        path_sha256 = _sha256(str(root).encode("utf-8"))
        identity = _sha256(
            _canonical_json(
                {
                    "path_sha256": path_sha256,
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "owner_uid": info.st_uid,
                    "owner_gid": info.st_gid,
                    "mode": mode,
                }
            )
        )
        if not hmac.compare_digest(
            path_sha256, self.expected_custody_root_path_sha256
        ) or not hmac.compare_digest(identity, self.expected_custody_identity_sha256):
            os.close(fd)
            raise CFastExecutionQualityArtifactRevalidationError(
                "CUSTODY_ROOT_PIN_MISMATCH"
            )
        guard = _CustodyRootGuard(
            path=root,
            fd=fd,
            identity=(
                info.st_dev,
                info.st_ino,
                info.st_uid,
                info.st_gid,
                info.st_mode,
            ),
        )
        try:
            self._verify_open_custody_root(guard)
        except Exception:
            os.close(fd)
            raise
        return guard

    def _verify_open_custody_root(self, guard: _CustodyRootGuard) -> None:
        try:
            fd_info = os.fstat(guard.fd)
            path_info = guard.path.lstat()
        except OSError as exc:
            raise CFastExecutionQualityArtifactRevalidationError(
                "CUSTODY_ROOT_CHANGED"
            ) from exc
        current = tuple(
            getattr(path_info, field)
            for field in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
        )
        retained = tuple(
            getattr(fd_info, field)
            for field in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
        )
        if (
            current != guard.identity
            or retained != guard.identity
            or not self._safe_parent_chain(guard.path)
        ):
            raise CFastExecutionQualityArtifactRevalidationError("CUSTODY_ROOT_CHANGED")

    def _safe_parent_chain(self, path: Path) -> bool:
        current = path
        while True:
            try:
                info = current.lstat()
            except OSError:
                return False
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, self.expected_owner_uid}
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                return False
            if current.parent == current:
                return True
            current = current.parent

    def _read_exact(
        self,
        role: ArtifactRole,
        path: Path,
        root: _CustodyRootGuard,
    ) -> _ExactArtifact:
        candidate = path.expanduser()
        if not candidate.is_absolute() or candidate.parent != root.path:
            raise CFastExecutionQualityArtifactRevalidationError(
                "ARTIFACT_OUTSIDE_CUSTODY_ROOT"
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(candidate.name, flags, dir_fd=root.fd)
            try:
                before = os.fstat(fd)
                mode = stat.S_IMODE(before.st_mode)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != self.expected_owner_uid
                    or mode & 0o022
                    or before.st_size <= 0
                    or before.st_size > MAX_ARTIFACT_BYTES
                ):
                    raise OSError
                raw = self._read_fd_exact(fd, before.st_size)
                os.lseek(fd, 0, os.SEEK_SET)
                if self._read_fd_exact(fd, before.st_size) != raw:
                    raise OSError
                after = os.fstat(fd)
            finally:
                os.close(fd)
            path_info = os.stat(
                candidate.name,
                dir_fd=root.fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise CFastExecutionQualityArtifactRevalidationError(
                f"{role.upper()}_FILE_INVALID"
            ) from exc
        identity = tuple(
            getattr(after, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_size",
                "st_mtime_ns",
            )
        )
        path_identity = tuple(
            getattr(path_info, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_size",
                "st_mtime_ns",
            )
        )
        if identity != path_identity or before != after:
            raise CFastExecutionQualityArtifactRevalidationError(
                f"{role.upper()}_FILE_CHANGED"
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
            canonical = _canonical_json(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CFastExecutionQualityArtifactRevalidationError(
                f"{role.upper()}_JSON_INVALID"
            ) from exc
        if not isinstance(payload, dict) or raw != canonical + b"\n":
            raise CFastExecutionQualityArtifactRevalidationError(
                f"{role.upper()}_NOT_EXACT_CANONICAL_JSON"
            )
        return _ExactArtifact(
            path=candidate,
            payload=payload,
            raw=raw,
            raw_sha256=_sha256(raw),
            canonical_sha256=_sha256(canonical),
            identity=identity,
        )

    @staticmethod
    def _read_fd_exact(fd: int, expected_size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise OSError("artifact ended before fstat size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise OSError("artifact grew beyond fstat size")
        return b"".join(chunks)

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise CFastExecutionQualityArtifactRevalidationError(
                "REVALIDATION_CLOCK_MUST_USE_UTC"
            )
