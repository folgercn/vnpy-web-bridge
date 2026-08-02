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
from threading import RLock, local
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.errors import (
    ManualExecutionPermitError,
    ManualExecutionPermitReplayError,
)
from app.schemas.manual_execution_permit import (
    ManualExecutionPermitDTO,
    ManualOrderSubmissionDTO,
    canonical_json,
    derived_manual_permit_id,
    manual_order_request_fingerprint,
    sha256_bytes,
    unsigned_manual_permit_payload,
)
from app.services.trade_service import TradeService, trade_service
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service


MAX_MARKER_BYTES = 16 * 1024


@dataclass(frozen=True)
class _ConsumedManualPermit:
    permit: ManualExecutionPermitDTO
    permit_raw_sha256: str
    order_request_sha256: str
    marker_path: Path
    consume_root_identity: tuple[int, ...]
    marker_raw_sha256: str
    operator: str
    account_sha256: str
    resolved_gateway_name: str


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


class ManualExecutionPermitService:
    """One-shot human permit boundary for the legacy manual order route."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        trade: TradeService | None = None,
        rpc: VnpyRpcService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.trade = trade or trade_service
        self.rpc = rpc or rpc_service
        if self.trade.rpc is not self.rpc:
            raise TypeError("manual permit trade and RPC services must match")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._capability: object | None = None
        self._capability_lock = RLock()
        self._operation_context = local()

    def submit(
        self,
        submission: ManualOrderSubmissionDTO,
        *,
        operator: str,
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        """Verify and consume exactly one manual permit before guarded send."""

        if not self.settings.manual_execution_permit_enabled:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_PERMIT_DISABLED"}
            )
        if not isinstance(operator, str) or not operator:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_OPERATOR_INVALID"}
            )
        try:
            candidate = ManualOrderSubmissionDTO.model_validate(
                submission.model_dump(mode="python")
            )
        except ValidationError as exc:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_SUBMISSION_INVALID"}
            ) from exc

        permit = candidate.execution_permit
        order = candidate.order
        resolved_gateway = (
            order.gateway_name or self.trade.settings.default_gateway_name
        )
        account_sha256 = self._verify_permit(
            permit,
            order=order,
            operator=operator,
            resolved_gateway_name=resolved_gateway,
        )
        order_request_sha256 = manual_order_request_fingerprint(
            order,
            resolved_gateway_name=resolved_gateway,
        )
        consumed = self._consume(
            permit,
            operator=operator,
            account_sha256=account_sha256,
            resolved_gateway_name=resolved_gateway,
            order_request_sha256=order_request_sha256,
        )
        if hasattr(self._operation_context, "consumed"):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONTEXT_OCCUPIED"}
            )
        self._operation_context.consumed = consumed
        try:
            return self.trade._send_manual_permitted_order(
                order.to_order_request(),
                manual_execution_owner=self,
                manual_execution_capability=self._manual_capability(),
                source_ip=source_ip,
                operator=operator,
                pre_rpc_guard=self._manual_pre_rpc_guard,
            )
        finally:
            del self._operation_context.consumed

    def _manual_capability(self) -> object:
        with self._capability_lock:
            if self._capability is None:
                self._capability = self.trade._bind_manual_execution_capability(
                    self
                )
            return self._capability

    def _manual_pre_rpc_guard(self, actual_order_request_sha256: str) -> None:
        """Run inside VnpyRpcService's shared non-idempotent send lock."""

        consumed = getattr(self._operation_context, "consumed", None)
        if type(consumed) is not _ConsumedManualPermit:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONTEXT_MISSING"}
            )
        if not hmac.compare_digest(
            actual_order_request_sha256,
            consumed.order_request_sha256,
        ):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_FINAL_PAYLOAD_MISMATCH"}
            )
        marker_raw = self._read_exact_private_marker(
            consumed.marker_path,
            consumed.consume_root_identity,
        )
        if not hmac.compare_digest(
            sha256_bytes(marker_raw), consumed.marker_raw_sha256
        ):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_MARKER_CHANGED"}
            )
        try:
            marker = json.loads(marker_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_MARKER_INVALID"}
            ) from exc
        expected_marker = self._marker_payload(
            consumed.permit,
            operator=consumed.operator,
            account_sha256=consumed.account_sha256,
            resolved_gateway_name=consumed.resolved_gateway_name,
            order_request_sha256=consumed.order_request_sha256,
            consumed_at_utc=str(marker.get("consumed_at_utc") or ""),
        )
        if marker != expected_marker or marker_raw != canonical_json(marker) + b"\n":
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_MARKER_INVALID"}
            )
        permit_raw_sha256 = sha256_bytes(
            canonical_json(consumed.permit.model_dump(mode="json"))
        )
        if not hmac.compare_digest(
            permit_raw_sha256, consumed.permit_raw_sha256
        ):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_PERMIT_CHANGED"}
            )
        account_sha256 = self._verify_permit(
            consumed.permit,
            order=consumed.permit.order,
            operator=consumed.operator,
            resolved_gateway_name=consumed.resolved_gateway_name,
        )
        if not hmac.compare_digest(account_sha256, consumed.account_sha256):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_FINAL_ACCOUNT_MISMATCH"}
            )

    def _verify_permit(
        self,
        permit: ManualExecutionPermitDTO,
        *,
        order: Any,
        operator: str,
        resolved_gateway_name: str,
    ) -> str:
        if derived_manual_permit_id(permit) != permit.permit_id:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_PERMIT_ID_MISMATCH"}
            )
        if permit.order != order:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_ORDER_SCOPE_MISMATCH"}
            )
        if permit.operator != operator:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_OPERATOR_MISMATCH"}
            )
        if permit.resolved_gateway_name != resolved_gateway_name:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_GATEWAY_MISMATCH"}
            )
        if resolved_gateway_name != self.settings.vnpy_gateway_name:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_RPC_GATEWAY_MISMATCH"}
            )
        now = self._utc_now()
        issued = permit.issued_at_utc.astimezone(timezone.utc)
        not_before = permit.not_before_utc.astimezone(timezone.utc)
        expires = permit.expires_at_utc.astimezone(timezone.utc)
        max_lifetime = timedelta(
            seconds=self.settings.manual_execution_permit_max_ttl_seconds
        )
        if (
            issued > not_before
            or not_before > now
            or now >= expires
            or expires - issued > max_lifetime
        ):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_PERMIT_EXPIRED_OR_NOT_YET_VALID"}
            )
        key = self._trusted_keys().get(permit.signer_key_id)
        if key is None:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_SIGNER_NOT_TRUSTED"}
            )
        try:
            signature = base64.b64decode(permit.signature, validate=True)
            key.verify(
                signature,
                canonical_json(unsigned_manual_permit_payload(permit)),
            )
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_SIGNATURE_INVALID"}
            ) from exc
        account_sha256 = self._resolve_account_hash(resolved_gateway_name)
        if not hmac.compare_digest(account_sha256, permit.account_sha256):
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_ACCOUNT_MISMATCH"}
            )
        return account_sha256

    def _trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        try:
            raw = json.loads(
                self.settings.manual_execution_permit_trusted_public_keys_json
            )
        except json.JSONDecodeError as exc:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_KEYRING_INVALID"}
            ) from exc
        if not isinstance(raw, dict) or not raw:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_KEYRING_EMPTY"}
            )
        foreign = self._configured_foreign_key_materials()
        keys: dict[str, Ed25519PublicKey] = {}
        seen: set[bytes] = set()
        for key_id, entry in raw.items():
            if (
                not isinstance(key_id, str)
                or not (8 <= len(key_id) <= 128)
                or not isinstance(entry, dict)
                or set(entry) != {"public_key_base64", "purpose"}
                or entry.get("purpose") != "manual_execution_permit_signer"
            ):
                raise ManualExecutionPermitError(
                    detail={"reason": "MANUAL_EXECUTION_KEYRING_INVALID"}
                )
            try:
                material = base64.b64decode(
                    str(entry["public_key_base64"]), validate=True
                )
                if (
                    len(material) != 32
                    or base64.b64encode(material).decode("ascii")
                    != entry["public_key_base64"]
                ):
                    raise ValueError
                key = Ed25519PublicKey.from_public_bytes(material)
            except (ValueError, binascii.Error) as exc:
                raise ManualExecutionPermitError(
                    detail={"reason": "MANUAL_EXECUTION_KEYRING_INVALID"}
                ) from exc
            if material in seen or material in foreign:
                raise ManualExecutionPermitError(
                    detail={"reason": "MANUAL_EXECUTION_KEY_DOMAIN_REUSE"}
                )
            seen.add(material)
            keys[key_id] = key
        return keys

    def _configured_foreign_key_materials(self) -> set[bytes]:
        materials: set[bytes] = set()
        for field, configured in self.settings.model_dump(mode="python").items():
            if not field.startswith("commodity_"):
                continue
            if field.endswith("trusted_public_keys_json"):
                try:
                    payload = json.loads(str(configured))
                except json.JSONDecodeError as exc:
                    raise ManualExecutionPermitError(
                        detail={
                            "reason": (
                                "MANUAL_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED"
                            )
                        }
                    ) from exc
                self._collect_public_key_materials(payload, materials)
            elif field.endswith("keyring_path") and configured:
                try:
                    payload = json.loads(
                        Path(str(configured))
                        .expanduser()
                        .read_text(encoding="utf-8")
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ManualExecutionPermitError(
                        detail={
                            "reason": (
                                "MANUAL_EXECUTION_FOREIGN_KEY_DOMAIN_UNVERIFIED"
                            )
                        }
                    ) from exc
                self._collect_public_key_materials(payload, materials)
        return materials

    @classmethod
    def _collect_public_key_materials(
        cls,
        value: Any,
        materials: set[bytes],
    ) -> None:
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
                cls._collect_public_key_materials(child, materials)
            return
        if isinstance(value, list):
            for child in value:
                cls._collect_public_key_materials(child, materials)
            return
        if isinstance(value, str):
            try:
                material = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error):
                return
            if len(material) == 32:
                materials.add(material)

    def _resolve_account_hash(self, resolved_gateway_name: str) -> str:
        allowlist = {
            item.strip().lower()
            for item in self.settings.manual_execution_permit_account_hashes.split(",")
            if item.strip()
        }
        matches: list[str] = []
        for account in self.rpc.get_accounts():
            gateway = _account_gateway(account)
            account_id = _account_id(account)
            if gateway != resolved_gateway_name or not account_id:
                continue
            digest = hashlib.sha256(account_id.encode("utf-8")).hexdigest()
            if digest in allowlist:
                matches.append(digest)
        if len(matches) != 1:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_ACCOUNT_NOT_UNIQUE"}
            )
        return matches[0]

    def _consume(
        self,
        permit: ManualExecutionPermitDTO,
        *,
        operator: str,
        account_sha256: str,
        resolved_gateway_name: str,
        order_request_sha256: str,
    ) -> _ConsumedManualPermit:
        root = self._consume_root()
        consumed_at = self._utc_now().isoformat().replace("+00:00", "Z")
        marker = self._marker_payload(
            permit,
            operator=operator,
            account_sha256=account_sha256,
            resolved_gateway_name=resolved_gateway_name,
            order_request_sha256=order_request_sha256,
            consumed_at_utc=consumed_at,
        )
        marker_raw = canonical_json(marker) + b"\n"
        marker_path = root / f"{permit.permit_id}.consumed.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        root_fd, root_identity = self._open_consume_root(root)
        try:
            descriptor = os.open(
                marker_path.name,
                flags,
                0o600,
                dir_fd=root_fd,
            )
        except OSError as exc:
            os.close(root_fd)
            if exc.errno == errno.EEXIST:
                raise ManualExecutionPermitReplayError(
                    detail={"reason": "MANUAL_EXECUTION_PERMIT_ALREADY_CONSUMED"}
                ) from exc
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_CREATE_FAILED"}
            ) from exc
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
            os.close(root_fd)
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_WRITE_FAILED"}
            ) from exc
        finally:
            os.close(descriptor)
        try:
            os.fsync(root_fd)
        except OSError as exc:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_WRITE_FAILED"}
            ) from exc
        finally:
            os.close(root_fd)
        return _ConsumedManualPermit(
            permit=permit,
            permit_raw_sha256=sha256_bytes(
                canonical_json(permit.model_dump(mode="json"))
            ),
            order_request_sha256=order_request_sha256,
            marker_path=marker_path,
            consume_root_identity=root_identity,
            marker_raw_sha256=sha256_bytes(marker_raw),
            operator=operator,
            account_sha256=account_sha256,
            resolved_gateway_name=resolved_gateway_name,
        )

    @staticmethod
    def _marker_payload(
        permit: ManualExecutionPermitDTO,
        *,
        operator: str,
        account_sha256: str,
        resolved_gateway_name: str,
        order_request_sha256: str,
        consumed_at_utc: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": "manual_execution_permit_consume_v1",
            "purpose": "manual_order_one_shot_consume",
            "permit_id": permit.permit_id,
            "permit_sha256": sha256_bytes(
                canonical_json(permit.model_dump(mode="json"))
            ),
            "nonce": permit.nonce,
            "operator": operator,
            "account_sha256": account_sha256,
            "resolved_gateway_name": resolved_gateway_name,
            "order_request_sha256": order_request_sha256,
            "consumed_at_utc": consumed_at_utc,
            "replay_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "automatic_dispatch_authorized": False,
            "c_fast_authority_reused": False,
        }

    def _consume_root(self) -> Path:
        root = Path(
            self.settings.manual_execution_permit_consume_root
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
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_ROOT_INVALID"}
            ) from exc
        return root

    @classmethod
    def _open_consume_root(
        cls,
        root: Path,
    ) -> tuple[int, tuple[int, ...]]:
        descriptor = -1
        try:
            path_before = root.lstat()
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            descriptor = os.open(root, flags)
            opened = os.fstat(descriptor)
            path_after = root.lstat()
            identities = {
                cls._root_identity(row)
                for row in (path_before, opened, path_after)
            }
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
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_ROOT_INVALID"}
            ) from exc

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
    def _read_exact_private_marker(
        cls,
        path: Path,
        expected_root_identity: tuple[int, ...],
    ) -> bytes:
        root_fd = -1
        try:
            root_fd, observed_root_identity = cls._open_consume_root(path.parent)
            if observed_root_identity != expected_root_identity:
                raise OSError
            before_path = os.stat(
                path.name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            descriptor = os.open(path.name, flags, dir_fd=root_fd)
            try:
                before = os.fstat(descriptor)
                if before.st_size <= 0 or before.st_size > MAX_MARKER_BYTES:
                    raise OSError
                chunks: list[bytes] = []
                remaining = MAX_MARKER_BYTES + 1
                while remaining > 0:
                    chunk = os.read(descriptor, min(4096, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after_path = os.stat(
                path.name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            identities = {
                (
                    row.st_dev,
                    row.st_ino,
                    stat.S_IFMT(row.st_mode),
                    stat.S_IMODE(row.st_mode),
                    row.st_uid,
                    row.st_nlink,
                    row.st_size,
                    row.st_mtime_ns,
                    row.st_ctime_ns,
                )
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
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CONSUME_MARKER_INVALID"}
            ) from exc
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    def _utc_now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ManualExecutionPermitError(
                detail={"reason": "MANUAL_EXECUTION_CLOCK_INVALID"}
            )
        return now.astimezone(timezone.utc)


manual_execution_permit_service = ManualExecutionPermitService()


__all__ = [
    "ManualExecutionPermitService",
    "manual_execution_permit_service",
]
