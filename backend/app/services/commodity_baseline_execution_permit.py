from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.errors import (
    CommodityBaselineExecutionPermitError,
    CommodityBaselineExecutionPermitReplayError,
)
from app.schemas.commodity_baseline_execution_permit import (
    CommodityBaselineExecutionPermitDTO,
    CommodityBaselinePermitTrustedKeysDTO,
    CommodityBaselineRiskEnvelopeDTO,
    baseline_order_set_sha256,
    baseline_price_policy_sha256,
    canonical_json,
    derived_baseline_permit_id,
    sha256_bytes,
    unsigned_baseline_permit_payload,
)
from app.schemas.trade import OrderRequestDTO
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service


MAX_JSON_BYTES = 1024 * 1024
MAX_MARKER_BYTES = 32 * 1024


@dataclass
class PreparedCommodityBaselinePermit:
    permit: CommodityBaselineExecutionPermitDTO
    permit_raw: bytes
    keyring_raw: bytes
    permit_path: Path
    keyring_path: Path
    plan_hash: str
    execution_plan_core_sha256: str
    execution_session_id: str
    strategy_id: str
    strategy_version: str
    phase: str
    account_sha256: str
    resolved_gateway_name: str
    price_policy_id: str
    next_child_index: int = 0
    consumed: "_ConsumedCommodityBaselinePermit | None" = None


@dataclass(frozen=True)
class _ConsumedCommodityBaselinePermit:
    marker_path: Path
    consume_root_identity: tuple[int, ...]
    marker_raw_sha256: str


def _account_id(row: dict[str, Any]) -> str:
    return str(
        row.get("accountid")
        or row.get("account_id")
        or row.get("vt_accountid")
        or row.get("id")
        or ""
    )


def _account_gateway(row: dict[str, Any]) -> str:
    return str(row.get("gateway_name") or row.get("gateway") or "")


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class CommodityBaselineExecutionPermitService:
    """Offline-signed, one-shot phase authority for non-C_FAST SimNow plans."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        rpc: VnpyRpcService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.rpc = rpc or rpc_service
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def prepare(
        self,
        *,
        plan_hash: str,
        execution_plan_core_sha256: str,
        execution_session_id: str,
        strategy_id: str,
        strategy_version: str,
        phase: str,
        account_sha256: str,
        resolved_gateway_name: str,
        price_policy_ids_by_phase: dict[str, str],
        planned_orders_by_phase: dict[str, list[dict[str, Any]]],
        expected_risk_envelopes_by_phase: dict[str, dict[str, Any]],
        require_companion_permit: bool,
    ) -> PreparedCommodityBaselinePermit:
        if not self.settings.commodity_baseline_execution_permit_enabled:
            self._raise("BASELINE_EXECUTION_PERMIT_DISABLED")
        if (
            phase not in {"close", "open"}
            or not planned_orders_by_phase.get(phase)
            or phase not in price_policy_ids_by_phase
            or phase not in expected_risk_envelopes_by_phase
        ):
            self._raise("BASELINE_EXECUTION_PERMIT_PHASE_INPUT_INVALID")
        keyring_path = Path(
            self.settings.commodity_baseline_execution_permit_trusted_keyring_path
        ).expanduser()
        keyring_payload, keyring_raw = self._read_exact_canonical_json(
            keyring_path,
            "BASELINE_EXECUTION_PERMIT_KEYRING",
        )
        if not hmac.compare_digest(
            sha256_bytes(keyring_raw),
            self.settings.commodity_baseline_execution_permit_expected_keyring_raw_sha256,
        ):
            self._raise("BASELINE_EXECUTION_PERMIT_KEYRING_PIN_MISMATCH")
        try:
            keyring = CommodityBaselinePermitTrustedKeysDTO.model_validate(
                keyring_payload
            )
        except ValidationError as exc:
            raise CommodityBaselineExecutionPermitError(
                detail={"reason": "BASELINE_EXECUTION_PERMIT_SCHEMA_INVALID"}
            ) from exc
        phases = [phase]
        companion = "open" if phase == "close" else "close"
        if require_companion_permit and planned_orders_by_phase.get(companion):
            if (
                companion not in price_policy_ids_by_phase
                or companion not in expected_risk_envelopes_by_phase
            ):
                self._raise("BASELINE_EXECUTION_PERMIT_PHASE_INPUT_INVALID")
            phases.append(companion)
        phase_paths = [self._permit_path(candidate) for candidate in phases]
        if len({path.resolve() for path in phase_paths}) != len(phase_paths):
            self._raise("BASELINE_EXECUTION_PERMIT_PATH_COLLISION")
        verified: dict[
            str,
            tuple[CommodityBaselineExecutionPermitDTO, bytes, Path],
        ] = {}
        seen_ids: set[str] = set()
        seen_nonces: set[str] = set()
        for candidate_phase, permit_path in zip(
            phases,
            phase_paths,
            strict=True,
        ):
            if permit_path.resolve() == keyring_path.resolve():
                self._raise("BASELINE_EXECUTION_PERMIT_PATH_COLLISION")
            permit_payload, permit_raw = self._read_exact_canonical_json(
                permit_path,
                f"BASELINE_EXECUTION_{candidate_phase.upper()}_PERMIT",
            )
            try:
                candidate = CommodityBaselineExecutionPermitDTO.model_validate(
                    permit_payload
                )
            except ValidationError as exc:
                raise CommodityBaselineExecutionPermitError(
                    detail={"reason": "BASELINE_EXECUTION_PERMIT_SCHEMA_INVALID"}
                ) from exc
            self._verify_signature(candidate, keyring)
            self._verify_static_scope(
                candidate,
                plan_hash=plan_hash,
                execution_plan_core_sha256=execution_plan_core_sha256,
                execution_session_id=execution_session_id,
                strategy_id=strategy_id,
                strategy_version=strategy_version,
                phase=candidate_phase,
                account_sha256=account_sha256,
                resolved_gateway_name=resolved_gateway_name,
                price_policy_id=price_policy_ids_by_phase[candidate_phase],
                planned_orders=planned_orders_by_phase[candidate_phase],
                expected_risk_envelope=(
                    expected_risk_envelopes_by_phase[candidate_phase]
                ),
            )
            if candidate.permit_id in seen_ids or candidate.nonce in seen_nonces:
                self._raise("BASELINE_EXECUTION_PHASE_PERMITS_NOT_INDEPENDENT")
            seen_ids.add(candidate.permit_id)
            seen_nonces.add(candidate.nonce)
            verified[candidate_phase] = (candidate, permit_raw, permit_path)
        self._verify_live_account(
            account_sha256=account_sha256,
            resolved_gateway_name=resolved_gateway_name,
        )
        permit, permit_raw, permit_path = verified[phase]
        return PreparedCommodityBaselinePermit(
            permit=permit,
            permit_raw=permit_raw,
            keyring_raw=keyring_raw,
            permit_path=permit_path,
            keyring_path=keyring_path,
            plan_hash=plan_hash,
            execution_plan_core_sha256=execution_plan_core_sha256,
            execution_session_id=execution_session_id,
            strategy_id=strategy_id,
            strategy_version=strategy_version,
            phase=phase,
            account_sha256=account_sha256,
            resolved_gateway_name=resolved_gateway_name,
            price_policy_id=price_policy_ids_by_phase[phase],
        )

    def _permit_path(self, phase: str) -> Path:
        if phase == "close":
            configured = self.settings.commodity_baseline_execution_permit_close_path
        elif phase == "open":
            configured = self.settings.commodity_baseline_execution_permit_open_path
        else:
            self._raise("BASELINE_EXECUTION_PHASE_INVALID")
        return Path(configured).expanduser()

    def final_guard(
        self,
        prepared: PreparedCommodityBaselinePermit,
        *,
        actual_order: OrderRequestDTO,
        child_index: int,
        plan_hash: str,
        execution_plan_core_sha256: str,
        execution_session_id: str,
        strategy_id: str,
        strategy_version: str,
        phase: str,
        account_sha256: str,
        resolved_gateway_name: str,
        price_policy_id: str,
        expected_risk_envelope: dict[str, Any],
    ) -> None:
        """Consume/revalidate while RPC call-lock and dispatch-abort lock are held."""

        if type(prepared) is not PreparedCommodityBaselinePermit:
            self._raise("BASELINE_EXECUTION_PERMIT_CONTEXT_INVALID")
        if (
            child_index != prepared.next_child_index
            or plan_hash != prepared.plan_hash
            or execution_plan_core_sha256 != prepared.execution_plan_core_sha256
            or execution_session_id != prepared.execution_session_id
            or strategy_id != prepared.strategy_id
            or strategy_version != prepared.strategy_version
            or phase != prepared.phase
            or account_sha256 != prepared.account_sha256
            or resolved_gateway_name != prepared.resolved_gateway_name
            or price_policy_id != prepared.price_policy_id
        ):
            self._raise("BASELINE_EXECUTION_PERMIT_FINAL_SCOPE_DRIFT")
        permit_payload, permit_raw = self._read_exact_canonical_json(
            prepared.permit_path,
            "BASELINE_EXECUTION_PERMIT",
        )
        keyring_payload, keyring_raw = self._read_exact_canonical_json(
            prepared.keyring_path,
            "BASELINE_EXECUTION_PERMIT_KEYRING",
        )
        if permit_raw != prepared.permit_raw or keyring_raw != prepared.keyring_raw:
            self._raise("BASELINE_EXECUTION_PERMIT_INPUT_CHANGED")
        try:
            live_permit = CommodityBaselineExecutionPermitDTO.model_validate(
                permit_payload
            )
            live_keyring = CommodityBaselinePermitTrustedKeysDTO.model_validate(
                keyring_payload
            )
        except ValidationError as exc:
            raise CommodityBaselineExecutionPermitError(
                detail={"reason": "BASELINE_EXECUTION_PERMIT_SCHEMA_INVALID"}
            ) from exc
        if live_permit != prepared.permit:
            self._raise("BASELINE_EXECUTION_PERMIT_INPUT_CHANGED")
        self._verify_signature(live_permit, live_keyring)
        self._verify_timing(live_permit)
        self._verify_risk_envelope(
            live_permit.risk_envelope,
            expected_risk_envelope,
        )
        self._verify_live_account(
            account_sha256=account_sha256,
            resolved_gateway_name=resolved_gateway_name,
        )
        if child_index >= len(live_permit.orders):
            self._raise("BASELINE_EXECUTION_PERMIT_CHILD_OUT_OF_SCOPE")
        scope = live_permit.orders[child_index]
        actual = OrderRequestDTO.model_validate(actual_order.model_dump(mode="python"))
        actual_gateway = actual.gateway_name or self.settings.default_gateway_name
        if (
            actual.symbol != scope.symbol
            or actual.exchange != scope.exchange
            or actual.direction != scope.direction
            or actual.offset != scope.offset
            or actual.type != scope.type
            or int(actual.volume) != scope.volume
            or actual.reference != scope.reference
            or actual.confirm is not True
            or actual_gateway != resolved_gateway_name
            or not (scope.minimum_price <= float(actual.price) <= scope.maximum_price)
        ):
            self._raise("BASELINE_EXECUTION_PERMIT_FINAL_ORDER_MISMATCH")
        if prepared.consumed is None:
            prepared.consumed = self._consume(live_permit)
        self._verify_consume_marker(prepared, prepared.consumed)
        prepared.next_child_index += 1

    def _verify_static_scope(
        self,
        permit: CommodityBaselineExecutionPermitDTO,
        **scope: Any,
    ) -> None:
        if derived_baseline_permit_id(permit) != permit.permit_id:
            self._raise("BASELINE_EXECUTION_PERMIT_ID_MISMATCH")
        self._verify_timing(permit)
        exact_fields = (
            "plan_hash",
            "execution_plan_core_sha256",
            "execution_session_id",
            "strategy_id",
            "strategy_version",
            "phase",
            "account_sha256",
            "resolved_gateway_name",
            "price_policy_id",
        )
        if any(getattr(permit, field) != scope[field] for field in exact_fields):
            self._raise("BASELINE_EXECUTION_PERMIT_SCOPE_MISMATCH")
        expected_policy_hash = baseline_price_policy_sha256(
            price_policy_id=scope["price_policy_id"],
            max_quote_age_seconds=(permit.risk_envelope.max_quote_age_seconds),
            max_spread_ticks=permit.risk_envelope.max_spread_ticks,
        )
        if permit.price_policy_sha256 != expected_policy_hash:
            self._raise("BASELINE_EXECUTION_PERMIT_PRICE_POLICY_MISMATCH")
        planned = scope["planned_orders"]
        if len(planned) != len(permit.orders):
            self._raise("BASELINE_EXECUTION_PERMIT_ORDER_SET_MISMATCH")
        for expected, authorized in zip(planned, permit.orders, strict=True):
            if {
                "symbol": str(expected["symbol"]),
                "exchange": str(expected["exchange"]),
                "direction": str(expected["direction"]),
                "offset": str(expected["offset"]),
                "type": "limit",
                "volume": int(expected["volume"]),
                "reference": str(expected["reference"]),
            } != {
                "symbol": authorized.symbol,
                "exchange": authorized.exchange,
                "direction": authorized.direction,
                "offset": authorized.offset,
                "type": authorized.type,
                "volume": authorized.volume,
                "reference": authorized.reference,
            }:
                self._raise("BASELINE_EXECUTION_PERMIT_ORDER_SET_MISMATCH")
        if permit.order_set_sha256 != baseline_order_set_sha256(permit.orders):
            self._raise("BASELINE_EXECUTION_PERMIT_ORDER_SET_MISMATCH")
        self._verify_risk_envelope(
            permit.risk_envelope,
            scope["expected_risk_envelope"],
        )

    def _verify_timing(
        self,
        permit: CommodityBaselineExecutionPermitDTO,
    ) -> None:
        now = self._utc_now()
        issued = permit.issued_at_utc.astimezone(timezone.utc)
        not_before = permit.not_before_utc.astimezone(timezone.utc)
        expires = permit.expires_at_utc.astimezone(timezone.utc)
        if (
            issued > not_before
            or not_before > now
            or now >= expires
            or expires - issued
            > timedelta(
                seconds=self.settings.commodity_baseline_execution_permit_max_ttl_seconds
            )
        ):
            self._raise("BASELINE_EXECUTION_PERMIT_TIMING_INVALID")

    def _verify_risk_envelope(
        self,
        observed: CommodityBaselineRiskEnvelopeDTO,
        expected: dict[str, Any],
    ) -> None:
        try:
            normalized = CommodityBaselineRiskEnvelopeDTO.model_validate(expected)
        except ValidationError as exc:
            raise CommodityBaselineExecutionPermitError(
                detail={"reason": "BASELINE_EXECUTION_EXPECTED_RISK_INVALID"}
            ) from exc
        if observed != normalized:
            self._raise("BASELINE_EXECUTION_PERMIT_RISK_ENVELOPE_DRIFT")

    def _verify_signature(
        self,
        permit: CommodityBaselineExecutionPermitDTO,
        keyring: CommodityBaselinePermitTrustedKeysDTO,
    ) -> None:
        foreign = self._configured_foreign_key_materials()
        selected: bytes | None = None
        seen: set[bytes] = set()
        for trusted in keyring.trusted_keys:
            try:
                material = base64.b64decode(
                    trusted.public_key_base64,
                    validate=True,
                )
                if (
                    len(material) != 32
                    or base64.b64encode(material).decode("ascii")
                    != trusted.public_key_base64
                ):
                    raise ValueError
                Ed25519PublicKey.from_public_bytes(material)
            except (ValueError, binascii.Error) as exc:
                raise CommodityBaselineExecutionPermitError(
                    detail={"reason": "BASELINE_EXECUTION_KEYRING_INVALID"}
                ) from exc
            if material in seen or material in foreign:
                self._raise("BASELINE_EXECUTION_KEY_DOMAIN_REUSE")
            seen.add(material)
            if trusted.key_id == permit.signer_key_id:
                selected = material
        if selected is None:
            self._raise("BASELINE_EXECUTION_SIGNER_NOT_TRUSTED")
        try:
            signature = base64.b64decode(permit.signature, validate=True)
            if (
                len(signature) != 64
                or base64.b64encode(signature).decode("ascii") != permit.signature
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(selected).verify(
                signature,
                canonical_json(unsigned_baseline_permit_payload(permit)),
            )
        except (ValueError, binascii.Error, InvalidSignature) as exc:
            raise CommodityBaselineExecutionPermitError(
                detail={"reason": "BASELINE_EXECUTION_SIGNATURE_INVALID"}
            ) from exc

    def _configured_foreign_key_materials(self) -> set[bytes]:
        materials: set[bytes] = set()
        own_fields = {
            "commodity_baseline_execution_permit_trusted_keyring_path",
        }
        for field, configured in self.settings.model_dump(mode="python").items():
            if field in own_fields:
                continue
            if field.endswith("trusted_public_keys_json"):
                try:
                    payload = json.loads(str(configured))
                except json.JSONDecodeError as exc:
                    self._raise_from(
                        "BASELINE_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED",
                        exc,
                    )
                self._collect_public_key_materials(payload, materials)
            elif field.endswith("keyring_path") and configured:
                try:
                    payload, _ = self._read_exact_canonical_json(
                        Path(str(configured)).expanduser(),
                        "BASELINE_EXECUTION_FOREIGN_KEYRING",
                    )
                except CommodityBaselineExecutionPermitError as exc:
                    self._raise_from(
                        "BASELINE_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED",
                        exc,
                    )
                self._collect_public_key_materials(payload, materials)
        return materials

    @classmethod
    def _collect_public_key_materials(
        cls,
        payload: Any,
        materials: set[bytes],
    ) -> None:
        if isinstance(payload, dict):
            encoded = payload.get("public_key_base64")
            if isinstance(encoded, str):
                try:
                    material = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error) as exc:
                    cls._raise_from(
                        "BASELINE_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED",
                        exc,
                    )
                if len(material) != 32:
                    cls._raise("BASELINE_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED")
                materials.add(material)
            for value in payload.values():
                cls._collect_public_key_materials(value, materials)
        elif isinstance(payload, list):
            for value in payload:
                cls._collect_public_key_materials(value, materials)

    def _verify_live_account(
        self,
        *,
        account_sha256: str,
        resolved_gateway_name: str,
    ) -> None:
        if (
            resolved_gateway_name != self.settings.commodity_simnow_gateway_name
            or resolved_gateway_name != self.settings.vnpy_gateway_name
        ):
            self._raise("BASELINE_EXECUTION_GATEWAY_DRIFT")
        allowlist = {
            item.strip().lower()
            for item in self.settings.commodity_simnow_account_hashes.split(",")
            if item.strip()
        }
        matches: list[str] = []
        for account in self.rpc.get_accounts():
            if _account_gateway(account) != resolved_gateway_name:
                continue
            account_id = _account_id(account)
            if not account_id:
                continue
            digest = hashlib.sha256(account_id.encode("utf-8")).hexdigest()
            if digest in allowlist:
                matches.append(digest)
        if matches != [account_sha256]:
            self._raise("BASELINE_EXECUTION_ACCOUNT_DRIFT")

    def _consume(
        self,
        permit: CommodityBaselineExecutionPermitDTO,
    ) -> _ConsumedCommodityBaselinePermit:
        root = self._consume_root()
        consumed_at = self._utc_now().isoformat().replace("+00:00", "Z")
        marker = {
            "schema_version": "commodity_baseline_execution_permit_consume_v1",
            "purpose": "commodity_baseline_phase_one_shot_consume",
            "permit_id": permit.permit_id,
            "permit_sha256": sha256_bytes(
                canonical_json(permit.model_dump(mode="json"))
            ),
            "nonce": permit.nonce,
            "strategy_id": permit.strategy_id,
            "strategy_version": permit.strategy_version,
            "plan_hash": permit.plan_hash,
            "execution_plan_core_sha256": permit.execution_plan_core_sha256,
            "execution_session_id": permit.execution_session_id,
            "phase": permit.phase,
            "account_sha256": permit.account_sha256,
            "resolved_gateway_name": permit.resolved_gateway_name,
            "order_set_sha256": permit.order_set_sha256,
            "consumed_at_utc": consumed_at,
            "replay_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "c_fast_authority_reused": False,
            "manual_authority_reused": False,
        }
        marker_raw = canonical_json(marker) + b"\n"
        marker_path = root / f"{permit.permit_id}.consumed.json"
        root_fd, root_identity = self._open_consume_root(root)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(marker_path.name, flags, 0o600, dir_fd=root_fd)
        except OSError as exc:
            os.close(root_fd)
            if exc.errno == errno.EEXIST:
                raise CommodityBaselineExecutionPermitReplayError(
                    detail={"reason": "BASELINE_EXECUTION_PERMIT_ALREADY_CONSUMED"}
                ) from exc
            self._raise_from("BASELINE_EXECUTION_CONSUME_CREATE_FAILED", exc)
        try:
            written = 0
            while written < len(marker_raw):
                count = os.write(descriptor, marker_raw[written:])
                if count <= 0:
                    raise OSError("short write")
                written += count
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_size != len(marker_raw)
            ):
                raise OSError("unsafe consume marker")
        except OSError as exc:
            self._raise_from("BASELINE_EXECUTION_CONSUME_WRITE_FAILED", exc)
        finally:
            os.close(descriptor)
        try:
            os.fsync(root_fd)
        except OSError as exc:
            self._raise_from("BASELINE_EXECUTION_CONSUME_WRITE_FAILED", exc)
        finally:
            os.close(root_fd)
        return _ConsumedCommodityBaselinePermit(
            marker_path=marker_path,
            consume_root_identity=root_identity,
            marker_raw_sha256=sha256_bytes(marker_raw),
        )

    def _verify_consume_marker(
        self,
        prepared: PreparedCommodityBaselinePermit,
        consumed: _ConsumedCommodityBaselinePermit,
    ) -> None:
        raw = self._read_private_marker(
            consumed.marker_path,
            consumed.consume_root_identity,
        )
        if not hmac.compare_digest(sha256_bytes(raw), consumed.marker_raw_sha256):
            self._raise("BASELINE_EXECUTION_CONSUME_MARKER_CHANGED")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._raise_from("BASELINE_EXECUTION_CONSUME_MARKER_INVALID", exc)
        if (
            raw != canonical_json(payload) + b"\n"
            or payload.get("permit_id") != prepared.permit.permit_id
            or payload.get("permit_sha256")
            != sha256_bytes(canonical_json(prepared.permit.model_dump(mode="json")))
            or payload.get("order_set_sha256") != prepared.permit.order_set_sha256
        ):
            self._raise("BASELINE_EXECUTION_CONSUME_MARKER_INVALID")

    def _consume_root(self) -> Path:
        root = Path(
            self.settings.commodity_baseline_execution_permit_consume_root
        ).expanduser()
        if not root.is_absolute():
            root = (Path.cwd() / root).resolve()
        try:
            try:
                existing = root.lstat()
                if (
                    not stat.S_ISDIR(existing.st_mode)
                    or stat.S_IMODE(existing.st_mode) != 0o700
                    or existing.st_uid != os.getuid()
                ):
                    raise OSError
            except FileNotFoundError:
                try:
                    root.mkdir(mode=0o700, parents=True, exist_ok=False)
                except FileExistsError:
                    existing = root.lstat()
                    if (
                        not stat.S_ISDIR(existing.st_mode)
                        or stat.S_IMODE(existing.st_mode) != 0o700
                        or existing.st_uid != os.getuid()
                    ):
                        raise OSError
                else:
                    root.chmod(0o700)
            metadata = root.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or root.resolve(strict=True) != root
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.getuid()
            ):
                raise OSError
        except OSError as exc:
            self._raise_from("BASELINE_EXECUTION_CONSUME_ROOT_INVALID", exc)
        return root

    @classmethod
    def _open_consume_root(
        cls,
        root: Path,
    ) -> tuple[int, tuple[int, ...]]:
        descriptor = -1
        try:
            before = root.lstat()
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(root, flags)
            opened = os.fstat(descriptor)
            after = root.lstat()
            identities = {cls._root_identity(row) for row in (before, opened, after)}
            if (
                len(identities) != 1
                or not stat.S_ISDIR(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o700
                or opened.st_uid != os.getuid()
            ):
                raise OSError
            return descriptor, cls._root_identity(opened)
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            cls._raise_from("BASELINE_EXECUTION_CONSUME_ROOT_INVALID", exc)

    @staticmethod
    def _root_identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
        )

    @classmethod
    def _read_private_marker(
        cls,
        path: Path,
        expected_root_identity: tuple[int, ...],
    ) -> bytes:
        root_fd = -1
        try:
            root_fd, observed = cls._open_consume_root(path.parent)
            if observed != expected_root_identity:
                raise OSError
            before_path = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path.name, flags, dir_fd=root_fd)
            try:
                before = os.fstat(descriptor)
                if before.st_size <= 0 or before.st_size > MAX_MARKER_BYTES:
                    raise OSError
                raw = cls._read_fd_bounded(descriptor, MAX_MARKER_BYTES)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after_path = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
            identities = {
                _stable_file_identity(row)
                for row in (before_path, before, after, after_path)
            }
            if (
                len(identities) != 1
                or not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or len(raw) != before.st_size
            ):
                raise OSError
            return raw
        except OSError as exc:
            cls._raise_from("BASELINE_EXECUTION_CONSUME_MARKER_INVALID", exc)
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    @classmethod
    def _read_exact_canonical_json(
        cls,
        path: Path,
        label: str,
    ) -> tuple[dict[str, Any], bytes]:
        try:
            path_before = path.lstat()
            if (
                not stat.S_ISREG(path_before.st_mode)
                or path_before.st_size <= 0
                or path_before.st_size > MAX_JSON_BYTES
            ):
                raise OSError
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                before = os.fstat(descriptor)
                raw = cls._read_fd_bounded(descriptor, MAX_JSON_BYTES)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            path_after = path.lstat()
            if (
                len(
                    {
                        _stable_file_identity(row)
                        for row in (path_before, before, after, path_after)
                    }
                )
                != 1
                or len(raw) != before.st_size
            ):
                raise OSError
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict) or raw != canonical_json(payload) + b"\n":
                raise OSError
            return payload, raw
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CommodityBaselineExecutionPermitError(
                detail={"reason": f"{label}_READ_INVALID"}
            ) from exc

    @staticmethod
    def _read_fd_bounded(descriptor: int, maximum: int) -> bytes:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _utc_now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            self._raise("BASELINE_EXECUTION_CLOCK_INVALID")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _raise(reason: str) -> None:
        raise CommodityBaselineExecutionPermitError(detail={"reason": reason})

    @staticmethod
    def _raise_from(reason: str, exc: BaseException) -> None:
        raise CommodityBaselineExecutionPermitError(detail={"reason": reason}) from exc


commodity_baseline_execution_permit_service = CommodityBaselineExecutionPermitService()


__all__ = [
    "CommodityBaselineExecutionPermitService",
    "PreparedCommodityBaselinePermit",
    "commodity_baseline_execution_permit_service",
]
