from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.core.commodity_strategy_identity import (
    commodity_c_fast_allocation_policy_projection,
    commodity_c_fast_allocation_policy_projection_sha256,
    commodity_executable_target_projection_sha256,
    commodity_map_output_contract_sha256,
    commodity_map_strategy_version_projection,
    commodity_map_strategy_version_projection_sha256,
)
from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_runtime_authorization import (
    CommodityCFastAllocationAcceptanceDTO,
    CommodityCFastAllocationPolicyProjectionDTO,
    CommodityCFastRuntimeAuthorizationDTO,
    CommodityCFastRuntimeAuthorizationEventDTO,
    CommodityCFastRuntimeTrustedKeyDTO,
    CommodityCFastRuntimeTrustedKeysDTO,
    CommodityMapStrategyAcceptanceDTO,
    CommodityMapStrategyVersionProjectionDTO,
)
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastRuntimeExecutableSnapshotDTO,
)

MAX_AUTHORITY_JSON_BYTES = 1024 * 1024
EVENT_FILE_RE = re.compile(r"^(\d{12})-([0-9a-f]{64})\.json$")


class CommodityCFastRuntimeAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda value: value.isoformat(),
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unsigned(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def _derived_identity(prefix: str, payload: dict[str, Any], field: str) -> str:
    binding = {
        key: value
        for key, value in payload.items()
        if key not in {field, "signature"}
    }
    return f"{prefix}{sha256_bytes(canonical_json(binding))}"


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CommodityCFastRuntimeAuthorizationError(
            f"{label.upper()}_TIMEZONE_MISSING"
        )
    return value.astimezone(timezone.utc)


def _read_exact_canonical(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise CommodityCFastRuntimeAuthorizationError(f"{label}_FILE_INVALID")
        if before.st_size > MAX_AUTHORITY_JSON_BYTES:
            raise CommodityCFastRuntimeAuthorizationError(f"{label}_SIZE_INVALID")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            raw = os.read(descriptor, MAX_AUTHORITY_JSON_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = path.lstat()
        identities = {
            (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )
            for item in (before, opened, after, final)
        }
        if len(identities) != 1 or len(raw) != opened.st_size:
            raise CommodityCFastRuntimeAuthorizationError(
                f"{label}_CHANGED_DURING_READ"
            )
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise CommodityCFastRuntimeAuthorizationError(f"{label}_ROOT_INVALID")
        if raw != canonical_json(payload) + b"\n":
            raise CommodityCFastRuntimeAuthorizationError(
                f"{label}_NOT_EXACT_CANONICAL"
            )
        return payload, raw
    except CommodityCFastRuntimeAuthorizationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommodityCFastRuntimeAuthorizationError(f"{label}_READ_INVALID") from exc


@dataclass(frozen=True, slots=True)
class VerifiedCommodityCFastRuntimeAuthorityArtifacts:
    authorization: CommodityCFastRuntimeAuthorizationDTO
    authorization_raw_sha256: str
    map_acceptance: CommodityMapStrategyAcceptanceDTO
    map_acceptance_raw_sha256: str
    allocation_acceptance: CommodityCFastAllocationAcceptanceDTO
    allocation_acceptance_raw_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedCommodityCFastRuntimeAuthorization:
    authorization: CommodityCFastRuntimeAuthorizationDTO
    map_acceptance: CommodityMapStrategyAcceptanceDTO
    allocation_acceptance: CommodityCFastAllocationAcceptanceDTO
    snapshot_sha256: str
    selected_products: tuple[str, ...]
    verified_at: datetime


class CommodityCFastRuntimeAuthorizationService:
    """Signed version authority plus restart-safe create-only runtime state."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
        enabled: bool | None = None,
        map_acceptance_path: str | Path | None = None,
        allocation_acceptance_path: str | Path | None = None,
        authorization_path: str | Path | None = None,
        trusted_keyring_path: str | Path | None = None,
        expected_keyring_raw_sha256: str | None = None,
        state_dir: str | Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.enabled = (
            bool(
                getattr(
                    self.settings,
                    "commodity_c_fast_runtime_authorization_enabled",
                    False,
                )
            )
            if enabled is None
            else enabled
        )
        self.map_acceptance_path = Path(
            map_acceptance_path
            or getattr(
                self.settings,
                "commodity_c_fast_map_strategy_acceptance_path",
                "",
            )
        ).expanduser()
        self.allocation_acceptance_path = Path(
            allocation_acceptance_path
            or getattr(
                self.settings,
                "commodity_c_fast_allocation_acceptance_path",
                "",
            )
        ).expanduser()
        self.authorization_path = Path(
            authorization_path
            or getattr(
                self.settings,
                "commodity_c_fast_runtime_authorization_path",
                "",
            )
        ).expanduser()
        self.trusted_keyring_path = Path(
            trusted_keyring_path
            or getattr(
                self.settings,
                "commodity_c_fast_runtime_authorization_trusted_keyring_path",
                "",
            )
        ).expanduser()
        self.expected_keyring_raw_sha256 = (
            expected_keyring_raw_sha256
            if expected_keyring_raw_sha256 is not None
            else getattr(
                self.settings,
                "commodity_c_fast_runtime_authorization_expected_keyring_raw_sha256",
                "",
            )
        )
        self.state_dir = Path(
            state_dir
            or getattr(
                self.settings,
                "commodity_c_fast_runtime_authorization_state_dir",
                "logs/commodity-c-fast-runtime-authorization",
            )
        ).expanduser()
        self._lock = RLock()

    def _require_configured(self) -> None:
        if not self.enabled:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_DISABLED"
            )
        paths = (
            self.map_acceptance_path,
            self.allocation_acceptance_path,
            self.authorization_path,
            self.trusted_keyring_path,
        )
        if any(not str(path).strip() or str(path) == "." for path in paths):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_CONFIG_INCOMPLETE"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", self.expected_keyring_raw_sha256):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_KEYRING_PIN_INVALID"
            )
        resolved = [path.resolve() for path in paths]
        if len(set(resolved)) != len(resolved):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_PATH_COLLISION"
            )

    def _trusted_keys(
        self,
    ) -> tuple[dict[str, tuple[CommodityCFastRuntimeTrustedKeyDTO, bytes]], bytes]:
        payload, raw = _read_exact_canonical(
            self.trusted_keyring_path, "RUNTIME_AUTHORIZATION_KEYRING"
        )
        if not hmac.compare_digest(
            sha256_bytes(raw), self.expected_keyring_raw_sha256
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_KEYRING_PIN_MISMATCH"
            )
        try:
            keyring = CommodityCFastRuntimeTrustedKeysDTO.model_validate(payload)
        except ValidationError as exc:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_KEYRING_SCHEMA_INVALID"
            ) from exc
        result: dict[
            str, tuple[CommodityCFastRuntimeTrustedKeyDTO, bytes]
        ] = {}
        foreign_materials = self._foreign_key_materials()
        for trusted in keyring.trusted_keys:
            try:
                material = base64.b64decode(
                    trusted.public_key_base64, validate=True
                )
                if len(material) != 32:
                    raise ValueError
                Ed25519PublicKey.from_public_bytes(material)
            except (ValueError, binascii.Error) as exc:
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_KEY_MATERIAL_INVALID"
                ) from exc
            if material in foreign_materials:
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_KEY_DOMAIN_COLLISION"
                )
            result[trusted.key_id] = (trusted, material)
        return result, raw

    def _foreign_key_materials(self) -> set[bytes]:
        materials: set[bytes] = set()

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                encoded = value.get("public_key_base64")
                if isinstance(encoded, str):
                    try:
                        material = base64.b64decode(encoded, validate=True)
                    except (ValueError, binascii.Error):
                        material = b""
                    if len(material) == 32:
                        materials.add(material)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        configured_json = getattr(
            self.settings,
            "commodity_c_fast_shadow_trusted_public_keys_json",
            "{}",
        )
        try:
            collect(json.loads(str(configured_json)))
        except json.JSONDecodeError as exc:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_FOREIGN_KEY_DOMAIN_INVALID"
            ) from exc
        for field in (
            "commodity_c_fast_simnow_execution_permit_trusted_keyring_path",
            "commodity_c_fast_simnow_research_acceptance_trusted_keyring_path",
            "commodity_c_fast_simnow_research_keyring_path",
            "commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path",
            "commodity_c_fast_fee_statement_trusted_keyring_path",
        ):
            configured = str(getattr(self.settings, field, "") or "").strip()
            if not configured:
                continue
            path = Path(configured).expanduser()
            if path.resolve() == self.trusted_keyring_path.resolve():
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_KEYRING_PATH_COLLISION"
                )
            try:
                collect(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_FOREIGN_KEY_DOMAIN_INVALID"
                ) from exc
        return materials

    @staticmethod
    def _verify_signature(
        payload: dict[str, Any],
        *,
        signer_key_id: str,
        reviewer_role: str,
        expected_role: str,
        trusted_keys: dict[
            str, tuple[CommodityCFastRuntimeTrustedKeyDTO, bytes]
        ],
        label: str,
    ) -> None:
        selected = trusted_keys.get(signer_key_id)
        if (
            selected is None
            or selected[0].signer_role != expected_role
            or selected[0].reviewer_role != reviewer_role
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                f"{label}_SIGNER_NOT_TRUSTED"
            )
        try:
            signature = base64.b64decode(str(payload["signature"]), validate=True)
            if len(signature) != 64:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(selected[1]).verify(
                signature, canonical_json(_unsigned(payload))
            )
        except (ValueError, binascii.Error, InvalidSignature, KeyError) as exc:
            raise CommodityCFastRuntimeAuthorizationError(
                f"{label}_SIGNATURE_INVALID"
            ) from exc

    def verified_artifacts(
        self,
    ) -> VerifiedCommodityCFastRuntimeAuthorityArtifacts:
        self._require_configured()
        trusted_keys, keyring_raw = self._trusted_keys()
        map_payload, map_raw = _read_exact_canonical(
            self.map_acceptance_path, "MAP_ACCEPTANCE"
        )
        allocation_payload, allocation_raw = _read_exact_canonical(
            self.allocation_acceptance_path, "C_FAST_ALLOCATION_ACCEPTANCE"
        )
        authorization_payload, authorization_raw = _read_exact_canonical(
            self.authorization_path, "RUNTIME_AUTHORIZATION"
        )
        try:
            map_acceptance = CommodityMapStrategyAcceptanceDTO.model_validate(
                map_payload
            )
            allocation_acceptance = (
                CommodityCFastAllocationAcceptanceDTO.model_validate(
                    allocation_payload
                )
            )
            authorization = CommodityCFastRuntimeAuthorizationDTO.model_validate(
                authorization_payload
            )
        except ValidationError as exc:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORITY_ARTIFACT_SCHEMA_INVALID"
            ) from exc
        if map_acceptance.acceptance_id != _derived_identity(
            "commodity-map-accept-v1-", map_payload, "acceptance_id"
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "MAP_ACCEPTANCE_ID_MISMATCH"
            )
        if allocation_acceptance.acceptance_id != _derived_identity(
            "commodity-c-fast-allocation-accept-v1-",
            allocation_payload,
            "acceptance_id",
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "C_FAST_ALLOCATION_ACCEPTANCE_ID_MISMATCH"
            )
        if authorization.authorization_id != _derived_identity(
            "commodity-c-fast-runtime-auth-v1-",
            authorization_payload,
            "authorization_id",
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_ID_MISMATCH"
            )
        self._verify_signature(
            map_payload,
            signer_key_id=map_acceptance.signer_key_id,
            reviewer_role=map_acceptance.reviewer_role,
            expected_role="map_strategy_acceptance",
            trusted_keys=trusted_keys,
            label="MAP_ACCEPTANCE",
        )
        self._verify_signature(
            allocation_payload,
            signer_key_id=allocation_acceptance.signer_key_id,
            reviewer_role=allocation_acceptance.reviewer_role,
            expected_role="c_fast_allocation_acceptance",
            trusted_keys=trusted_keys,
            label="C_FAST_ALLOCATION_ACCEPTANCE",
        )
        self._verify_signature(
            authorization_payload,
            signer_key_id=authorization.signer_key_id,
            reviewer_role=authorization.reviewer_role,
            expected_role="simnow_runtime_authorization",
            trusted_keys=trusted_keys,
            label="RUNTIME_AUTHORIZATION",
        )
        map_projection_payload = map_acceptance.projection.model_dump(mode="json")
        allocation_projection_payload = (
            allocation_acceptance.projection.model_dump(mode="json")
        )
        if map_acceptance.projection_sha256 != sha256_bytes(
            canonical_json(map_projection_payload)
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "MAP_ACCEPTANCE_PROJECTION_HASH_MISMATCH"
            )
        if allocation_acceptance.projection_sha256 != sha256_bytes(
            canonical_json(allocation_projection_payload)
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "C_FAST_ALLOCATION_ACCEPTANCE_PROJECTION_HASH_MISMATCH"
            )
        if (
            allocation_acceptance.map_strategy_identity
            != map_acceptance.projection.strategy_identity
            or allocation_acceptance.map_output_contract_sha256
            != commodity_map_output_contract_sha256()
            or allocation_acceptance.projection.map_output_contract_sha256
            != allocation_acceptance.map_output_contract_sha256
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "MAP_C_FAST_ACCEPTANCE_CHAIN_MISMATCH"
            )
        map_raw_sha256 = sha256_bytes(map_raw)
        allocation_raw_sha256 = sha256_bytes(allocation_raw)
        if (
            authorization.map_acceptance_id != map_acceptance.acceptance_id
            or authorization.map_acceptance_raw_sha256 != map_raw_sha256
            or authorization.map_strategy_projection_sha256
            != map_acceptance.projection_sha256
            or authorization.c_fast_allocation_acceptance_id
            != allocation_acceptance.acceptance_id
            or authorization.c_fast_allocation_acceptance_raw_sha256
            != allocation_raw_sha256
            or authorization.c_fast_allocation_projection_sha256
            != allocation_acceptance.projection_sha256
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_ACCEPTANCE_BINDING_MISMATCH"
            )
        if not set(authorization.allowed_products).issubset(
            allocation_acceptance.projection.product_pool
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_PRODUCT_SCOPE_INVALID"
            )
        limits = authorization.risk_limits
        policy = allocation_acceptance.projection
        if (
            limits.max_product_abs_weight > policy.max_integer_product_abs
            or limits.max_sector_gross_weight > policy.max_integer_sector_gross
            or limits.max_portfolio_gross_weight
            > policy.max_integer_portfolio_gross
            or limits.max_portfolio_abs_net_weight > policy.max_integer_abs_net
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_RISK_SCOPE_INVALID"
            )
        now = _utc(self.clock(), "clock")
        for artifact, label in (
            (map_acceptance, "MAP_ACCEPTANCE"),
            (allocation_acceptance, "C_FAST_ALLOCATION_ACCEPTANCE"),
        ):
            if not (
                _utc(artifact.issued_at, f"{label}_issued_at")
                <= _utc(artifact.not_before, f"{label}_not_before")
                <= now
                < _utc(artifact.expires_at, f"{label}_expires_at")
            ):
                raise CommodityCFastRuntimeAuthorizationError(
                    f"{label}_TIMING_INVALID"
                )
        valid_from = _utc(authorization.valid_from, "authorization_valid_from")
        issued_at = _utc(authorization.issued_at, "authorization_issued_at")
        if issued_at > valid_from or now < valid_from:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_TIMING_INVALID"
            )
        if authorization.valid_until is not None and now >= _utc(
            authorization.valid_until, "authorization_valid_until"
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_EXPIRED"
            )
        # Detect a swap after all cross-artifact checks.
        if (
            _read_exact_canonical(self.map_acceptance_path, "MAP_ACCEPTANCE")[1]
            != map_raw
            or _read_exact_canonical(
                self.allocation_acceptance_path,
                "C_FAST_ALLOCATION_ACCEPTANCE",
            )[1]
            != allocation_raw
            or _read_exact_canonical(
                self.authorization_path, "RUNTIME_AUTHORIZATION"
            )[1]
            != authorization_raw
            or _read_exact_canonical(
                self.trusted_keyring_path, "RUNTIME_AUTHORIZATION_KEYRING"
            )[1]
            != keyring_raw
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORITY_CHANGED_DURING_VERIFY"
            )
        return VerifiedCommodityCFastRuntimeAuthorityArtifacts(
            authorization=authorization,
            authorization_raw_sha256=sha256_bytes(authorization_raw),
            map_acceptance=map_acceptance,
            map_acceptance_raw_sha256=map_raw_sha256,
            allocation_acceptance=allocation_acceptance,
            allocation_acceptance_raw_sha256=allocation_raw_sha256,
        )

    def _ensure_state_dir(self) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.state_dir.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_STATE_DIR_INVALID"
            )

    def _events(self) -> list[tuple[CommodityCFastRuntimeAuthorizationEventDTO, bytes]]:
        if not self.state_dir.exists():
            return []
        self._ensure_state_dir()
        files = sorted(self.state_dir.glob("*.json"))
        events: list[
            tuple[CommodityCFastRuntimeAuthorizationEventDTO, bytes]
        ] = []
        previous_sha256: str | None = None
        for expected_sequence, path in enumerate(files, start=1):
            match = EVENT_FILE_RE.fullmatch(path.name)
            if match is None or int(match.group(1)) != expected_sequence:
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_AUDIT_SEQUENCE_INVALID"
                )
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_AUDIT_FILE_INVALID"
                )
            payload, raw = _read_exact_canonical(
                path, "RUNTIME_AUTHORIZATION_AUDIT_EVENT"
            )
            try:
                event = CommodityCFastRuntimeAuthorizationEventDTO.model_validate(
                    payload
                )
            except ValidationError as exc:
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_AUDIT_SCHEMA_INVALID"
                ) from exc
            event_core = {
                key: value
                for key, value in payload.items()
                if key not in {"event_id", "event_sha256"}
            }
            computed = sha256_bytes(canonical_json(event_core))
            if (
                event.sequence != expected_sequence
                or event.event_sha256 != computed
                or event.event_id != f"cfast-runtime-event-{computed}"
                or match.group(2) != computed
                or event.previous_event_sha256 != previous_sha256
            ):
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_AUDIT_CHAIN_INVALID"
                )
            previous_sha256 = sha256_bytes(raw)
            events.append((event, raw))
        return events

    def _append_event(
        self,
        *,
        event_type: str,
        actor: str,
        reason: str,
        artifacts: VerifiedCommodityCFastRuntimeAuthorityArtifacts | None = None,
        pinned_event: CommodityCFastRuntimeAuthorizationEventDTO | None = None,
    ) -> CommodityCFastRuntimeAuthorizationEventDTO:
        if (artifacts is None) == (pinned_event is None):
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_AUDIT_IDENTITY_INVALID"
            )
        self._ensure_state_dir()
        events = self._events()
        sequence = len(events) + 1
        if artifacts is not None:
            authorization_id = artifacts.authorization.authorization_id
            authorization_raw_sha256 = artifacts.authorization_raw_sha256
            map_acceptance_raw_sha256 = artifacts.map_acceptance_raw_sha256
            allocation_acceptance_raw_sha256 = (
                artifacts.allocation_acceptance_raw_sha256
            )
        else:
            assert pinned_event is not None
            authorization_id = pinned_event.authorization_id
            authorization_raw_sha256 = pinned_event.authorization_raw_sha256
            map_acceptance_raw_sha256 = pinned_event.map_acceptance_raw_sha256
            allocation_acceptance_raw_sha256 = (
                pinned_event.c_fast_allocation_acceptance_raw_sha256
            )
        core = {
            "schema_version": "commodity_c_fast_runtime_authorization_event_v1",
            "sequence": sequence,
            "event_type": event_type,
            "occurred_at": _utc(self.clock(), "clock").isoformat(),
            "actor": actor,
            "reason": reason,
            "authorization_id": authorization_id,
            "authorization_raw_sha256": authorization_raw_sha256,
            "map_acceptance_raw_sha256": map_acceptance_raw_sha256,
            "c_fast_allocation_acceptance_raw_sha256": (
                allocation_acceptance_raw_sha256
            ),
            "previous_event_sha256": (
                sha256_bytes(events[-1][1]) if events else None
            ),
        }
        event_sha256 = sha256_bytes(canonical_json(core))
        payload = {
            **core,
            "event_id": f"cfast-runtime-event-{event_sha256}",
            "event_sha256": event_sha256,
        }
        event = CommodityCFastRuntimeAuthorizationEventDTO.model_validate(payload)
        target = self.state_dir / f"{sequence:012d}-{event_sha256}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags, 0o600)
            try:
                raw = canonical_json(payload) + b"\n"
                written = os.write(descriptor, raw)
                if written != len(raw):
                    raise OSError("short write")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_AUDIT_CREATE_FAILED"
            ) from exc
        return event

    def status(self) -> dict[str, Any]:
        if not self.enabled:
            return {
                "state": "DISABLED",
                "production_allowed": False,
                "live_allowed": False,
                "countable_forward": False,
            }
        with self._lock:
            events = self._events()
            if not events:
                return {
                    "state": "NOT_ENABLED",
                    "production_allowed": False,
                    "live_allowed": False,
                    "countable_forward": False,
                }
            latest = events[-1][0]
            state = "ACTIVE" if latest.event_type == "ENABLED" else latest.event_type
            result: dict[str, Any] = {
                "state": state,
                "authorization_id": latest.authorization_id,
                "reason": latest.reason,
                "updated_at": latest.occurred_at.isoformat(),
                "audit_sequence": latest.sequence,
                "production_allowed": False,
                "live_allowed": False,
                "countable_forward": False,
            }
            if state != "ACTIVE":
                return result
            try:
                artifacts = self.verified_artifacts()
            except CommodityCFastRuntimeAuthorizationError as exc:
                # Expiry and all authority drift are durable hard revocations.
                event_type = (
                    "EXPIRED"
                    if exc.code
                    in {
                        "RUNTIME_AUTHORIZATION_EXPIRED",
                        "MAP_ACCEPTANCE_TIMING_INVALID",
                        "C_FAST_ALLOCATION_ACCEPTANCE_TIMING_INVALID",
                    }
                    else "HARD_DRIFT_REVOKED"
                )
                self._append_event(
                    event_type=event_type,
                    actor="runtime-verifier",
                    reason=exc.code,
                    pinned_event=latest,
                )
                return self.status()
            result.update(
                {
                    "valid_from": artifacts.authorization.valid_from.isoformat(),
                    "valid_until": (
                        artifacts.authorization.valid_until.isoformat()
                        if artifacts.authorization.valid_until
                        else None
                    ),
                    "until_revoked": artifacts.authorization.until_revoked,
                    "expected_simnow_account_sha256": (
                        artifacts.authorization.expected_simnow_account_sha256
                    ),
                    "allowed_execution_lane": (
                        artifacts.authorization.allowed_execution_lane
                    ),
                    "signed_snapshots_only": (
                        artifacts.authorization.signed_snapshots_only
                    ),
                    "continuous": artifacts.authorization.continuous,
                    "map_acceptance_id": artifacts.map_acceptance.acceptance_id,
                    "map_acceptance_state": "ACTIVE",
                    "c_fast_allocation_acceptance_id": (
                        artifacts.allocation_acceptance.acceptance_id
                    ),
                    "c_fast_allocation_acceptance_state": "ACTIVE",
                    "allowed_products": artifacts.authorization.allowed_products,
                    "max_selected_products": (
                        artifacts.authorization.max_selected_products
                    ),
                    "max_child_order_lots": (
                        artifacts.authorization.max_child_order_lots
                    ),
                    "risk_limits": artifacts.authorization.risk_limits.model_dump(
                        mode="json"
                    ),
                }
            )
            return result

    def readonly_state(self) -> str:
        """Return fail-closed runtime state without creating audit events."""

        if not self.enabled:
            return "DISABLED"
        with self._lock:
            events = self._events()
            if not events:
                return "NOT_ENABLED"
            latest = events[-1][0]
            return "ACTIVE" if latest.event_type == "ENABLED" else latest.event_type

    def enable(self, *, authorized_by: str, reason: str) -> dict[str, Any]:
        if len(reason) < 8:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_REASON_INVALID"
            )
        with self._lock:
            artifacts = self.verified_artifacts()
            events = self._events()
            if events and events[-1][0].event_type == "ENABLED":
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_ALREADY_ACTIVE"
                )
            if any(
                event.authorization_id == artifacts.authorization.authorization_id
                for event, _ in events
            ):
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_ID_ALREADY_USED"
                )
            self._append_event(
                event_type="ENABLED",
                actor=authorized_by,
                reason=reason,
                artifacts=artifacts,
            )
            return self.status()

    def revoke(self, *, revoked_by: str, reason: str) -> dict[str, Any]:
        if len(reason) < 3:
            raise CommodityCFastRuntimeAuthorizationError(
                "RUNTIME_AUTHORIZATION_REASON_INVALID"
            )
        with self._lock:
            events = self._events()
            if not events or events[-1][0].event_type != "ENABLED":
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_NOT_ACTIVE"
                )
            latest = events[-1][0]
            self._append_event(
                event_type="REVOKED",
                actor=revoked_by,
                reason=reason,
                pinned_event=latest,
            )
            return self.status()

    def _hard_revoke(
        self,
        *,
        code: str,
        artifacts: VerifiedCommodityCFastRuntimeAuthorityArtifacts,
    ) -> None:
        events = self._events()
        if events and events[-1][0].event_type == "ENABLED":
            self._append_event(
                event_type="HARD_DRIFT_REVOKED",
                actor="runtime-verifier",
                reason=code,
                artifacts=artifacts,
            )
        raise CommodityCFastRuntimeAuthorizationError(code)

    def verify_snapshot(
        self,
        *,
        snapshot: CommodityCFastRuntimeExecutableSnapshotDTO,
        snapshot_sha256: str,
        actual_account_sha256: str,
        selected_products: list[str],
        snapshot_signature_verified: bool,
    ) -> VerifiedCommodityCFastRuntimeAuthorization:
        with self._lock:
            status = self.status()
            if status["state"] != "ACTIVE":
                raise CommodityCFastRuntimeAuthorizationError(
                    "RUNTIME_AUTHORIZATION_NOT_ACTIVE"
                )
            artifacts = self.verified_artifacts()
            authorization = artifacts.authorization
            map_acceptance = artifacts.map_acceptance
            allocation_acceptance = artifacts.allocation_acceptance

            def hard(condition: bool, code: str) -> None:
                if condition:
                    self._hard_revoke(code=code, artifacts=artifacts)

            hard(
                not isinstance(snapshot, CommodityCFastRuntimeExecutableSnapshotDTO),
                "RUNTIME_SNAPSHOT_SCHEMA_REQUIRED",
            )
            hard(not snapshot_signature_verified, "SNAPSHOT_SIGNATURE_NOT_VERIFIED")
            hard(
                not re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256),
                "SNAPSHOT_SHA256_INVALID",
            )
            hard(
                not hmac.compare_digest(
                    actual_account_sha256,
                    authorization.expected_simnow_account_sha256,
                ),
                "RUNTIME_AUTHORIZATION_ACCOUNT_DRIFT",
            )
            products = list(selected_products)
            hard(
                products != sorted(products)
                or len(products) != len(set(products))
                or len(products) > authorization.max_selected_products
                or not set(products).issubset(authorization.allowed_products),
                "RUNTIME_AUTHORIZATION_PRODUCT_SCOPE_DRIFT",
            )
            hard(
                snapshot.execution_lane != authorization.allowed_execution_lane
                or snapshot.production_allowed
                or snapshot.countable_forward,
                "RUNTIME_AUTHORIZATION_EXECUTION_LANE_DRIFT",
            )
            map_projection = commodity_map_strategy_version_projection(snapshot)
            allocation_projection = commodity_c_fast_allocation_policy_projection(
                snapshot
            )
            # Revalidate typed projections as a second schema boundary.
            CommodityMapStrategyVersionProjectionDTO.model_validate(map_projection)
            CommodityCFastAllocationPolicyProjectionDTO.model_validate(
                allocation_projection
            )
            map_projection_sha256 = (
                commodity_map_strategy_version_projection_sha256(snapshot)
            )
            allocation_projection_sha256 = (
                commodity_c_fast_allocation_policy_projection_sha256(snapshot)
            )
            hard(
                map_projection_sha256 != map_acceptance.projection_sha256
                or map_projection
                != map_acceptance.projection.model_dump(mode="json"),
                "MAP_ACCEPTANCE_VERSION_DRIFT",
            )
            hard(
                allocation_projection_sha256
                != allocation_acceptance.projection_sha256
                or allocation_projection
                != allocation_acceptance.projection.model_dump(mode="json"),
                "C_FAST_ALLOCATION_POLICY_DRIFT",
            )
            hard(
                snapshot.map_acceptance_id != map_acceptance.acceptance_id
                or snapshot.map_acceptance_raw_sha256
                != artifacts.map_acceptance_raw_sha256
                or snapshot.map_strategy_projection_sha256
                != map_projection_sha256
                or snapshot.c_fast_allocation_acceptance_id
                != allocation_acceptance.acceptance_id
                or snapshot.c_fast_allocation_acceptance_raw_sha256
                != artifacts.allocation_acceptance_raw_sha256
                or snapshot.c_fast_allocation_projection_sha256
                != allocation_projection_sha256
                or snapshot.runtime_selected_products != products,
                "SNAPSHOT_ACCEPTANCE_BINDING_DRIFT",
            )
            hard(
                snapshot.executable_target_binding_sha256
                != commodity_executable_target_projection_sha256(snapshot),
                "SNAPSHOT_EXECUTABLE_TARGET_BINDING_INVALID",
            )
            limits = authorization.risk_limits
            nav = float(snapshot.virtual_nav_cny)
            product_weights: dict[str, float] = {}
            sector_weights: dict[str, float] = {}
            for row in snapshot.targets:
                weight = (
                    row.target_quantity
                    * row.reference_open_price
                    * row.multiplier
                    / nav
                )
                product_weights[row.product] = weight
                sector_weights[row.sector] = sector_weights.get(row.sector, 0.0) + abs(
                    weight
                )
            hard(
                any(
                    abs(weight) > limits.max_product_abs_weight + 1e-12
                    for weight in product_weights.values()
                )
                or any(
                    gross > limits.max_sector_gross_weight + 1e-12
                    for gross in sector_weights.values()
                )
                or sum(abs(weight) for weight in product_weights.values())
                > limits.max_portfolio_gross_weight + 1e-12
                or abs(sum(product_weights.values()))
                > limits.max_portfolio_abs_net_weight + 1e-12,
                "RUNTIME_AUTHORIZATION_RISK_LIMIT_DRIFT",
            )
            return VerifiedCommodityCFastRuntimeAuthorization(
                authorization=authorization,
                map_acceptance=map_acceptance,
                allocation_acceptance=allocation_acceptance,
                snapshot_sha256=snapshot_sha256,
                selected_products=tuple(products),
                verified_at=_utc(self.clock(), "clock"),
            )


commodity_c_fast_runtime_authorization_service = (
    CommodityCFastRuntimeAuthorizationService()
)


__all__ = [
    "CommodityCFastRuntimeAuthorizationError",
    "CommodityCFastRuntimeAuthorizationService",
    "VerifiedCommodityCFastRuntimeAuthorization",
    "commodity_c_fast_runtime_authorization_service",
]
