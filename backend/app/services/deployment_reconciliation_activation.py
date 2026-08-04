from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    CommodityInitialBaselineStateDTO,
    DeploymentInitialBaselineCommodityCheckpointDTO,
    DeploymentLegacyMigrationCommodityCheckpointDTO,
    DeploymentOnlineRecheckCheckpointDTO,
    DeploymentReconciliationActivationHeadV2DTO,
    DeploymentReconciliationActivationIntentDTO,
    DeploymentReconciliationActivationMarkerDTO,
    DeploymentReconciliationOwnerBindingDTO,
    DeploymentReconciliationOwnerCapturePairDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    DeploymentRpcRecheckServedProofDTO,
    SafeRestartOnlineRecheckDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.deployment_initial_baseline_reconciliation import (
    _build_initial_baseline_checkpoint,
    _build_initial_baseline_commodity_checkpoint,
    build_initial_baseline_reconciliation_evidence,
    canonical_initial_baseline_checkpoint_bytes,
    canonical_initial_baseline_commodity_checkpoint_bytes,
    canonical_initial_baseline_evidence_bytes,
    derive_initial_baseline_rpc_identity,
    verify_initial_baseline_input_bundle,
)
from app.services.deployment_legacy_migration_reconciliation import (
    _build_legacy_migration_checkpoint,
    _build_legacy_migration_commodity_checkpoint,
    build_legacy_migration_empty_inventory,
    build_legacy_migration_reconciliation_evidence,
    canonical_legacy_migration_checkpoint_bytes,
    canonical_legacy_migration_commodity_checkpoint_bytes,
    canonical_legacy_migration_evidence_bytes,
    canonical_legacy_migration_inventory_bytes,
    derive_legacy_migration_rpc_identity,
    verify_legacy_migration_input_bundle,
)
from app.services.deployment_reconciliation_custody import (
    DeploymentReconciliationCustodyError,
    DeploymentReconciliationCustodyRepository,
    DeploymentReconciliationCustodySession,
    DeploymentReconciliationCustodySnapshot,
)
from app.services.deployment_restart_reconciliation import (
    _build_post_restart_checkpoint,
    _build_restart_reconciliation_evidence,
    canonical_post_restart_checkpoint_bytes,
    canonical_restart_reconciliation_bytes,
    derive_post_restart_recheck_identity,
    verify_planned_restart_input_bundle,
)


class DeploymentReconciliationActivationError(RuntimeError):
    """C2b owner activation failed without changing deployment authority."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class _ModeInputs:
    mode: str
    raw: Mapping[str, Any]
    verified: object
    rpc_request_id: str
    owner_challenge: str
    initial_capture_id: str
    initial_challenge: str
    fresh_capture_id: str
    fresh_challenge: str
    initial_rpc: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO | None
    legacy_inventory_raw: bytes | None = None


@dataclass(frozen=True)
class _ModeEvidence:
    checkpoint: object
    checkpoint_raw: bytes
    evidence: object
    evidence_raw: bytes


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _artifact_bytes(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _core_sha256(value: object) -> str:
    return _sha256(_canonical_bytes(value))


def _model_payload(value: object) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError("activation artifact must be a model or mapping")


def _parse_exact(raw: bytes, model: type, label: str):
    try:
        value = model.model_validate_json(raw)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentReconciliationActivationError(
            "RECONCILIATION_OUTPUT_INVALID", f"{label} is invalid"
        ) from exc
    if raw != _artifact_bytes(value.model_dump(mode="json")):
        raise DeploymentReconciliationActivationError(
            "RECONCILIATION_OUTPUT_NONCANONICAL",
            f"{label} bytes are not canonical",
        )
    return value


def _authority_false_payload() -> dict[str, bool]:
    return {
        "external_high_water_verified": False,
        "target_runtime_verified": False,
        "reconciliation_completed": False,
        "windows_fence_released": False,
        "authority_restore_allowed": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }


class DeploymentReconciliationActivationService:
    """C2b exact owner capture and non-authorizing activation transaction."""

    def __init__(
        self,
        *,
        repository: DeploymentReconciliationCustodyRepository,
        commodity_owner: Any,
        clock: Any | None = None,
    ) -> None:
        self.repository = repository
        self.owner = commodity_owner
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        from app.services.commodity_simnow import CommoditySimNowService

        if type(self.owner) is not CommoditySimNowService:
            raise TypeError("C2b requires the exact CommoditySimNow owner")
        if getattr(self.owner, "deployment_drain", None) is None:
            raise ValueError("Commodity owner must expose the deployment drain")
        if Path(self.owner.deployment_drain.root).expanduser().absolute() != (
            self.repository.root
        ):
            raise ValueError("Commodity owner and custody repository roots differ")

    def reconcile(
        self,
        *,
        operator: str,
        reason: str,
    ) -> DeploymentReconciliationActivationHeadV2DTO:
        if not isinstance(operator, str) or not operator.strip():
            raise ValueError("operator must be non-empty")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be non-empty")
        self._assert_production_rpc_transport()
        with self.repository.locked() as session:
            self.owner._bind_deployment_reconciliation_owner()
            before = session.snapshot(captured_at=self._now())
            self.owner._assert_deployment_reconciliation_local_state()
            expected_account_hash = self._expected_account_hash()
            owner_binding = self._build_owner_binding(
                session=session,
                snapshot=before,
                expected_account_hash=expected_account_hash,
            )
            stable_slot = self._intent_slot(
                snapshot=before,
                owner_binding=owner_binding,
                activation_sequence=1,
                previous_head_raw_sha256=None,
            )
            run_id = f"deployment-c2b-run-{stable_slot}"
            mode_inputs = self._prepare_mode_inputs(before, run_id)
            intent = self._load_or_create_intent(
                session=session,
                snapshot=before,
                owner_binding=owner_binding,
                mode_inputs=mode_inputs,
                slot=stable_slot,
                operator=operator.strip(),
                reason=reason.strip(),
            )
            intent_raw = _artifact_bytes(intent.model_dump(mode="json"))
            session.write_blob(
                f"{_sha256(intent_raw)}.json",
                intent.model_dump(mode="json"),
            )

            capture_guard = getattr(
                self.owner, "_deployment_reconciliation_capture_guard", None
            )
            if not callable(capture_guard):
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_OWNER_CAPABILITY_MISSING",
                    "Commodity owner has no C2 capture capability",
                )
            with capture_guard():
                session.assert_live()
                initial_rpc, commodity_checkpoint_raw = self._initial_capture(
                    session=session,
                    intent=intent,
                    mode_inputs=mode_inputs,
                )
                served_proof, served_fresh_rpc, served_proof_raw = (
                    self._load_or_create_fresh_served_proof(
                        session=session,
                        intent=intent,
                        initial_rpc=initial_rpc,
                    )
                )
                pair, pair_raw = self._load_or_create_capture_pair(
                    session=session,
                    intent=intent,
                    intent_raw=intent_raw,
                    initial_rpc=initial_rpc,
                    served_proof=served_proof,
                    fresh_rpc=served_fresh_rpc,
                )
                fresh_rpc = pair.fresh_rpc
                captured_at = pair.captured_at
                mode_evidence = self._build_mode_evidence(
                    intent=intent,
                    inputs=mode_inputs,
                    initial_rpc=initial_rpc,
                    fresh_rpc=fresh_rpc,
                    commodity_checkpoint_raw=commodity_checkpoint_raw,
                )
                self._write_stage_copies(
                    session=session,
                    stable_basename=f"{intent.intent_id}.mode-checkpoint.json",
                    raw=mode_evidence.checkpoint_raw,
                    payload=_model_payload(mode_evidence.checkpoint),
                )
                self._write_stage_copies(
                    session=session,
                    stable_basename=f"{intent.intent_id}.mode-evidence.json",
                    raw=mode_evidence.evidence_raw,
                    payload=_model_payload(mode_evidence.evidence),
                )
                after = session.snapshot(captured_at=self._now())
                self._assert_same_input_inventory(before, after)
                after_owner_binding = self._build_owner_binding(
                    session=session,
                    snapshot=after,
                    expected_account_hash=expected_account_hash,
                )
                if after_owner_binding != owner_binding:
                    raise DeploymentReconciliationActivationError(
                        "RECONCILIATION_OWNER_STATE_CHANGED",
                        "Commodity owner binding changed during capture",
                    )
                marker = self._build_marker(
                    intent=intent,
                    pair=pair,
                    pair_raw=pair_raw,
                    mode_evidence=mode_evidence,
                    prepared_at=captured_at,
                )
                marker_raw = _artifact_bytes(marker.model_dump(mode="json"))
                self._write_stage_copies(
                    session=session,
                    stable_basename=f"{intent.intent_id}.activation-marker.json",
                    raw=marker_raw,
                    payload=marker.model_dump(mode="json"),
                    content_basename=Path(marker.marker_path).name,
                )
                self._assert_production_rpc_transport()
                head = self._build_head(
                    intent,
                    marker,
                    marker_raw,
                    served_proof,
                    served_proof_raw,
                )
                stored_head = session.write_head(
                    Path(head.activation_head_path).name,
                    head.model_dump(mode="json"),
                )
                if stored_head.raw != _artifact_bytes(head.model_dump(mode="json")):
                    raise DeploymentReconciliationActivationError(
                        "RECONCILIATION_HEAD_READBACK_MISMATCH",
                        "activation head readback is not exact",
                    )
                session.assert_live()
                return head

    def _assert_production_rpc_transport(self) -> None:
        if self.owner.settings.app_env.lower() == "test":
            return
        from app.services.vnpy_rpc_service import BridgeRpcClient, VnpyRpcService

        rpc = self.owner.rpc
        shadowed_rpc_methods = {
            name
            for name in vars(rpc)
            if callable(getattr(VnpyRpcService, name, None))
        }
        expected_binding = (
            self.owner.settings.vnpy_rpc_req_address,
            self.owner.settings.vnpy_rpc_pub_address,
            self.owner.settings.vnpy_gateway_name,
        )
        if (
            type(rpc) is not VnpyRpcService
            or rpc.settings is not self.owner.settings
            or not rpc.started
            or type(rpc.client) is not BridgeRpcClient
            or rpc.client.service is not rpc
            or rpc._deployment_transport_binding != expected_binding
            or rpc._deployment_transport_generation < 1
            or rpc.last_connected_at is None
            or shadowed_rpc_methods
            or {
                "get_deployment_safety_snapshot_v1",
                "recheck_deployment_safety_snapshot_v1",
            }.intersection(vars(rpc.client))
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_RPC_TRANSPORT_INVALID",
                "production C2b requires one sealed and owner-bound RPC transport",
            )

    def _now(self) -> datetime:
        value = self.clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timezone.utc.utcoffset(value)
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_CLOCK_INVALID", "activation clock must return UTC"
            )
        return value

    def _now_not_before(self, minimum: datetime) -> datetime:
        observed = self._now()
        return max(observed, minimum)

    def _expected_account_hash(self) -> str:
        configured = sorted(
            {
                item.strip().lower()
                for item in self.owner.settings.commodity_simnow_account_hashes.split(
                    ","
                )
                if item.strip()
            }
        )
        if len(configured) != 1 or any(
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in configured
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_ACCOUNT_SCOPE_INVALID",
                "C2 requires exactly one configured account hash",
            )
        return configured[0]

    def _build_owner_binding(
        self,
        *,
        session: DeploymentReconciliationCustodySession,
        snapshot: DeploymentReconciliationCustodySnapshot,
        expected_account_hash: str,
    ) -> DeploymentReconciliationOwnerBindingDTO:
        session.assert_live()
        state_path = (
            Path(self.owner.settings.commodity_simnow_state_path)
            .expanduser()
            .absolute()
        )
        state_fields = self._read_owner_state_file(state_path)
        owner_state = {
            "schema_version": "commodity-simnow-v1",
            "completed_state": self.owner._completed_state,
            "active_plan": self.owner.current_plan,
            "state_load_error": self.owner._state_load_error,
            "enabled": self.owner.enabled,
            "manual_approval": self.owner.manual_approval,
            "simnow_mode": self.owner.simnow_mode,
            "auto_dispatch_authorized": self.owner.auto_dispatch_authorized,
            "shakedown_auto_dispatch_authorized": (
                self.owner.shakedown_auto_dispatch_authorized
            ),
            "c_fast_shakedown_auto_dispatch_authorized": (
                self.owner.c_fast_shakedown_auto_dispatch_authorized
            ),
            "c_fast_continuous_authorized": self.owner.c_fast_continuous_authorized,
            "template_authorized": self.owner.template_authorized,
        }
        allowlist = sorted(
            {
                item.strip().lower()
                for item in self.owner.settings.commodity_simnow_account_hashes.split(
                    ","
                )
                if item.strip()
            }
        )
        payload: dict[str, Any] = {
            "schema_version": ("web_bridge_deployment_reconciliation_owner_binding_v1"),
            "purpose": "bind_unique_frozen_commodity_owner_for_reconciliation",
            "owner_kind": "COMMODITY_SIMNOW",
            "deployment_runtime_instance_id": (
                snapshot.inventory.actual_runtime_instance_id
            ),
            "deployment_execution_epoch": snapshot.inventory.actual_execution_epoch,
            "deployment_state_generation": snapshot.inventory.actual_state_generation,
            "deployment_state_commitment_raw_sha256": (
                snapshot.inventory.actual_head_commitment_raw_sha256
            ),
            "custody_root_path_sha256": _sha256(
                str(self.repository.root).encode("utf-8")
            ),
            "custody_root_device": snapshot.inventory.custody_root_device,
            "custody_root_inode": snapshot.inventory.custody_root_inode,
            "deployment_lock_device": snapshot.inventory.lock_file_device,
            "deployment_lock_inode": snapshot.inventory.lock_file_inode,
            "commodity_state_version": "commodity-simnow-v1",
            "commodity_state_path_sha256": _sha256(str(state_path).encode("utf-8")),
            **state_fields,
            "commodity_state_checkpoint_sha256": _core_sha256(owner_state),
            "gateway_name": self.owner.settings.vnpy_gateway_name,
            "rpc_request_endpoint_sha256": _sha256(
                self.owner.settings.vnpy_rpc_req_address.encode("utf-8")
            ),
            "rpc_publish_endpoint_sha256": _sha256(
                self.owner.settings.vnpy_rpc_pub_address.encode("utf-8")
            ),
            "expected_account_hash": expected_account_hash,
            "account_allowlist": allowlist,
            "account_allowlist_sha256": _core_sha256(allowlist),
            "expected_account_allowlisted": True,
            "web_trade_enabled": False,
            "execution_authority_revoked": True,
            "auto_dispatch_stopped": True,
            "deployment_authorized": False,
            "automatic_deploy_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }
        digest = _core_sha256(payload)
        try:
            return DeploymentReconciliationOwnerBindingDTO.model_validate(
                {
                    **payload,
                    "owner_binding_id": (
                        f"deployment-reconciliation-owner-binding-{digest}"
                    ),
                    "owner_binding_core_sha256": digest,
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_OWNER_BINDING_INVALID",
                "Commodity owner binding is invalid",
            ) from exc

    def _read_owner_state_file(self, path: Path) -> dict[str, Any]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return {
                "commodity_state_file_present": False,
                "commodity_state_device": None,
                "commodity_state_inode": None,
                "commodity_state_uid": None,
                "commodity_state_gid": None,
                "commodity_state_mode": None,
                "commodity_state_nlink": None,
                "commodity_state_raw_sha256": None,
            }
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_OWNER_STATE_INSECURE",
                "Commodity durable state is not owner-only and single-link",
            )
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                opened = os.fstat(fd)
                if opened.st_dev != info.st_dev or opened.st_ino != info.st_ino:
                    raise DeploymentReconciliationActivationError(
                        "RECONCILIATION_OWNER_STATE_CHANGED",
                        "Commodity durable state changed before read",
                    )
                chunks: list[bytes] = []
                remaining = opened.st_size + 1
                while remaining:
                    chunk = os.read(fd, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_OWNER_STATE_READ_FAILED",
                "Commodity durable state cannot be read securely",
            ) from exc
        if len(raw) != info.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_OWNER_STATE_CHANGED",
                "Commodity durable state changed during read",
            )
        return {
            "commodity_state_file_present": True,
            "commodity_state_device": info.st_dev,
            "commodity_state_inode": info.st_ino,
            "commodity_state_uid": info.st_uid,
            "commodity_state_gid": info.st_gid,
            "commodity_state_mode": stat.S_IMODE(info.st_mode),
            "commodity_state_nlink": info.st_nlink,
            "commodity_state_raw_sha256": _sha256(raw),
        }

    @staticmethod
    def _intent_slot(
        *,
        snapshot: DeploymentReconciliationCustodySnapshot,
        owner_binding: DeploymentReconciliationOwnerBindingDTO,
        activation_sequence: int,
        previous_head_raw_sha256: str | None,
    ) -> str:
        inventory = snapshot.inventory
        stable = {
            "domain": "issue267-c2b-intent-slot-v1",
            "mode": inventory.mode,
            "custody_inventory_digest_sha256": inventory.inventory_digest_sha256,
            "genesis_commitment_raw_sha256": (inventory.genesis_commitment_raw_sha256),
            "current_state_commitment_raw_sha256": (
                inventory.actual_head_commitment_raw_sha256
            ),
            "current_state_raw_sha256": inventory.actual_state_raw_sha256,
            "current_epoch_anchor_raw_sha256": (
                inventory.actual_epoch_anchor_raw_sha256
            ),
            "current_state_generation": inventory.actual_state_generation,
            "current_runtime_instance_id": inventory.actual_runtime_instance_id,
            "current_execution_epoch": inventory.actual_execution_epoch,
            "owner_binding_core_sha256": owner_binding.owner_binding_core_sha256,
            "expected_account_hash": owner_binding.expected_account_hash,
            "activation_sequence": activation_sequence,
            "previous_activation_head_raw_sha256": previous_head_raw_sha256,
        }
        return _core_sha256(stable)

    def _load_or_create_intent(
        self,
        *,
        session: DeploymentReconciliationCustodySession,
        snapshot: DeploymentReconciliationCustodySnapshot,
        owner_binding: DeploymentReconciliationOwnerBindingDTO,
        mode_inputs: _ModeInputs,
        slot: str,
        operator: str,
        reason: str,
    ) -> DeploymentReconciliationActivationIntentDTO:
        intent_id = f"deployment-reconciliation-intent-{slot}"
        basename = f"{intent_id}.json"
        try:
            existing = session.read_intent(basename)
        except DeploymentReconciliationCustodyError as exc:
            if exc.code not in {
                "CUSTODY_DIRECTORY_OPEN_FAILED",
                "CUSTODY_FILE_OPEN_FAILED",
            }:
                raise
        else:
            intent = _parse_exact(
                existing.raw,
                DeploymentReconciliationActivationIntentDTO,
                "activation intent",
            )
            if (
                intent.intent_slot_sha256 != slot
                or intent.operator != operator
                or intent.reason != reason
                or intent.owner_binding != owner_binding
                or intent.custody_inventory_digest_sha256
                != snapshot.inventory.inventory_digest_sha256
                or intent.current_state_commitment_raw_sha256
                != snapshot.inventory.actual_head_commitment_raw_sha256
                or (
                    intent.rpc_request_id,
                    intent.owner_challenge,
                    intent.initial_capture_id,
                    intent.initial_challenge,
                    intent.fresh_capture_id,
                    intent.fresh_challenge,
                )
                != (
                    mode_inputs.rpc_request_id,
                    mode_inputs.owner_challenge,
                    mode_inputs.initial_capture_id,
                    mode_inputs.initial_challenge,
                    mode_inputs.fresh_capture_id,
                    mode_inputs.fresh_challenge,
                )
            ):
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_INTENT_COLLISION",
                    "existing deterministic intent does not match this retry",
                )
            self._verify_stored_intent_inputs(
                session=session,
                intent=intent,
                current_snapshot=snapshot,
            )
            return intent

        inventory = snapshot.inventory
        owner_raw = _artifact_bytes(owner_binding.model_dump(mode="json"))
        inventory_raw = _artifact_bytes(inventory.model_dump(mode="json"))
        payload: dict[str, Any] = {
            "schema_version": "web_bridge_deployment_reconciliation_intent_v1",
            "purpose": "prepare_deterministic_owner_reconciliation_capture",
            "mode": inventory.mode,
            "intent_slot_sha256": slot,
            "reconciliation_run_id": f"deployment-c2b-run-{slot}",
            "operator": operator,
            "reason": reason,
            "custody_inventory_id": inventory.inventory_id,
            "custody_inventory_core_sha256": inventory.inventory_core_sha256,
            "custody_inventory_raw_sha256": _sha256(inventory_raw),
            "custody_inventory_digest_sha256": inventory.inventory_digest_sha256,
            "genesis_commitment_raw_sha256": (inventory.genesis_commitment_raw_sha256),
            "current_state_commitment_raw_sha256": (
                inventory.actual_head_commitment_raw_sha256
            ),
            "current_state_raw_sha256": inventory.actual_state_raw_sha256,
            "current_epoch_anchor_raw_sha256": (
                inventory.actual_epoch_anchor_raw_sha256
            ),
            "current_state_generation": inventory.actual_state_generation,
            "current_runtime_instance_id": inventory.actual_runtime_instance_id,
            "current_execution_epoch": inventory.actual_execution_epoch,
            "owner_binding_raw_sha256": _sha256(owner_raw),
            "owner_binding": owner_binding.model_dump(mode="json"),
            "rpc_request_id": mode_inputs.rpc_request_id,
            "owner_challenge": mode_inputs.owner_challenge,
            "initial_capture_id": mode_inputs.initial_capture_id,
            "initial_challenge": mode_inputs.initial_challenge,
            "fresh_capture_id": mode_inputs.fresh_capture_id,
            "fresh_challenge": mode_inputs.fresh_challenge,
            "activation_sequence": 1,
            "previous_activation_head_id": None,
            "previous_activation_head_raw_sha256": None,
            "previous_activation_head_core_sha256": None,
            **_authority_false_payload(),
        }
        core = dict(payload)
        digest = _core_sha256(core)
        try:
            intent = DeploymentReconciliationActivationIntentDTO.model_validate(
                {
                    **payload,
                    "intent_id": intent_id,
                    "intent_core_sha256": digest,
                    "intent_path": f"reconciliation-intents/{intent_id}.json",
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_INTENT_INVALID",
                "deterministic reconciliation intent is invalid",
            ) from exc
        session.write_blob(
            f"{intent.custody_inventory_raw_sha256}.json",
            inventory.model_dump(mode="json"),
        )
        session.write_blob(
            f"{intent.owner_binding_raw_sha256}.json",
            owner_binding.model_dump(mode="json"),
        )
        session.write_intent(basename, intent.model_dump(mode="json"))
        return intent

    def _verify_stored_intent_inputs(
        self,
        *,
        session: DeploymentReconciliationCustodySession,
        intent: DeploymentReconciliationActivationIntentDTO,
        current_snapshot: DeploymentReconciliationCustodySnapshot,
    ) -> None:
        from app.schemas.deployment_drain import (
            DeploymentReconciliationCustodyInventoryDTO,
        )

        inventory_artifact = session.read_blob(
            f"{intent.custody_inventory_raw_sha256}.json"
        )
        owner_artifact = session.read_blob(f"{intent.owner_binding_raw_sha256}.json")
        stored_inventory = _parse_exact(
            inventory_artifact.raw,
            DeploymentReconciliationCustodyInventoryDTO,
            "intent custody inventory",
        )
        stored_owner = _parse_exact(
            owner_artifact.raw,
            DeploymentReconciliationOwnerBindingDTO,
            "intent owner binding",
        )
        if (
            _sha256(inventory_artifact.raw) != intent.custody_inventory_raw_sha256
            or stored_inventory.inventory_id != intent.custody_inventory_id
            or stored_inventory.inventory_core_sha256
            != intent.custody_inventory_core_sha256
            or stored_inventory.inventory_digest_sha256
            != current_snapshot.inventory.inventory_digest_sha256
            or stored_inventory.actual_head_commitment_raw_sha256
            != current_snapshot.inventory.actual_head_commitment_raw_sha256
            or _sha256(owner_artifact.raw) != intent.owner_binding_raw_sha256
            or stored_owner != intent.owner_binding
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_INTENT_INPUT_BLOB_INVALID",
                "persisted intent input blobs do not match current custody",
            )

    def _prepare_mode_inputs(
        self,
        snapshot: DeploymentReconciliationCustodySnapshot,
        run_id: str,
    ) -> _ModeInputs:
        if snapshot.inventory.mode == "PLANNED_RESTART":
            return self._planned_inputs(snapshot, run_id)
        if snapshot.inventory.mode == "INITIAL_BASELINE":
            return self._initial_inputs(snapshot, run_id)
        if snapshot.inventory.mode == "LEGACY_MIGRATION_BASELINE":
            return self._legacy_inputs(snapshot, run_id)
        raise DeploymentReconciliationActivationError(
            "RECONCILIATION_MODE_INVALID", "custody reconciliation mode is invalid"
        )

    @staticmethod
    def _commitment_raws(
        snapshot: DeploymentReconciliationCustodySnapshot,
    ) -> list[bytes]:
        return [
            snapshot.raw_for(f"state-commitments/{generation:020d}.json")
            for generation in range(1, snapshot.inventory.actual_state_generation + 1)
        ]

    def _initial_inputs(
        self,
        snapshot: DeploymentReconciliationCustodySnapshot,
        run_id: str,
    ) -> _ModeInputs:
        chain = self._commitment_raws(snapshot)
        genesis = chain[0]
        anchor = snapshot.raw_for("epoch-anchor.json")
        verified = verify_initial_baseline_input_bundle(
            genesis_state_commitment_raw=genesis,
            state_commitment_chain_raw=chain,
            current_epoch_anchor_raw=anchor,
            current_runtime_instance_id=(snapshot.inventory.actual_runtime_instance_id),
            current_execution_epoch=snapshot.inventory.actual_execution_epoch,
        )
        request_id, owner_challenge, recheck_id, fresh_challenge = (
            derive_initial_baseline_rpc_identity(
                reconciliation_run_id=run_id,
                genesis_commitment_raw_sha256=_sha256(genesis),
                current_state_commitment_raw_sha256=_sha256(chain[-1]),
                current_runtime_instance_id=(
                    snapshot.inventory.actual_runtime_instance_id
                ),
                current_execution_epoch=(snapshot.inventory.actual_execution_epoch),
                expected_account_hash=self._expected_account_hash(),
            )
        )
        return _ModeInputs(
            mode="INITIAL_BASELINE",
            raw={"genesis": genesis, "anchor": anchor, "chain": chain},
            verified=verified,
            rpc_request_id=request_id,
            owner_challenge=owner_challenge,
            initial_capture_id=request_id,
            initial_challenge=owner_challenge,
            fresh_capture_id=recheck_id,
            fresh_challenge=fresh_challenge,
            initial_rpc=None,
        )

    def _legacy_inputs(
        self,
        snapshot: DeploymentReconciliationCustodySnapshot,
        run_id: str,
    ) -> _ModeInputs:
        archive_entries = [
            entry
            for entry in snapshot.inventory.entries
            if entry.role == "LEGACY_SOURCE_ARCHIVE"
            and Path(entry.relative_path).name.startswith("archive-")
        ]
        if len(archive_entries) != 1:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_LEGACY_ARCHIVE_INVALID",
                "legacy mode requires one exact source archive",
            )
        from app.schemas.deployment_drain import (
            DeploymentLegacyMigrationSourceArchiveDTO,
        )

        archive_raw = snapshot.raw_for(archive_entries[0].relative_path)
        archive = _parse_exact(
            archive_raw,
            DeploymentLegacyMigrationSourceArchiveDTO,
            "legacy source archive",
        )
        source_state = snapshot.raw_for(archive.source_state_path)
        source_anchor = snapshot.raw_for(archive.source_epoch_anchor_path)
        inventory = build_legacy_migration_empty_inventory(
            source_state_raw=source_state,
            source_epoch_anchor_raw=source_anchor,
        )
        inventory_raw = canonical_legacy_migration_inventory_bytes(inventory)
        chain = self._commitment_raws(snapshot)
        genesis = chain[0]
        anchor = snapshot.raw_for("epoch-anchor.json")
        verified = verify_legacy_migration_input_bundle(
            source_state_raw=source_state,
            source_epoch_anchor_raw=source_anchor,
            inventory_manifest_raw=inventory_raw,
            genesis_state_commitment_raw=genesis,
            state_commitment_chain_raw=chain,
            current_epoch_anchor_raw=anchor,
            current_runtime_instance_id=(snapshot.inventory.actual_runtime_instance_id),
            current_execution_epoch=snapshot.inventory.actual_execution_epoch,
        )
        request_id, owner_challenge, recheck_id, fresh_challenge = (
            derive_legacy_migration_rpc_identity(
                reconciliation_run_id=run_id,
                source_schema_version=archive.source_schema_version,
                source_state_raw_sha256=_sha256(source_state),
                source_epoch_anchor_raw_sha256=_sha256(source_anchor),
                inventory_raw_sha256=_sha256(inventory_raw),
                genesis_commitment_raw_sha256=_sha256(genesis),
                current_state_commitment_raw_sha256=_sha256(chain[-1]),
                current_epoch_anchor_raw_sha256=_sha256(anchor),
                current_runtime_instance_id=(
                    snapshot.inventory.actual_runtime_instance_id
                ),
                current_execution_epoch=(snapshot.inventory.actual_execution_epoch),
                expected_account_hash=self._expected_account_hash(),
            )
        )
        return _ModeInputs(
            mode="LEGACY_MIGRATION_BASELINE",
            raw={
                "source_state": source_state,
                "source_anchor": source_anchor,
                "archive": archive_raw,
                "inventory": inventory_raw,
                "genesis": genesis,
                "anchor": anchor,
                "chain": chain,
            },
            verified=verified,
            rpc_request_id=request_id,
            owner_challenge=owner_challenge,
            initial_capture_id=request_id,
            initial_challenge=owner_challenge,
            fresh_capture_id=recheck_id,
            fresh_challenge=fresh_challenge,
            initial_rpc=None,
            legacy_inventory_raw=inventory_raw,
        )

    def _planned_inputs(
        self,
        snapshot: DeploymentReconciliationCustodySnapshot,
        run_id: str,
    ) -> _ModeInputs:
        state = snapshot.inventory.actual_state
        receipt_id = state.get("consumed_receipt_id")
        if not isinstance(receipt_id, str):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_PLANNED_POINTER_INVALID",
                "planned restart has no consumed receipt",
            )
        receipt = snapshot.raw_for(f"receipts/{receipt_id}.json")
        online_raw = snapshot.raw_for(f"rechecks/{receipt_id}.online-recheck.json")
        online = _parse_exact(
            online_raw, SafeRestartOnlineRecheckDTO, "consumed online recheck"
        )
        original_checkpoint = snapshot.raw_for(
            f"checkpoints/checkpoint-{online.original_checkpoint_raw_sha256}.json"
        )
        recheck_checkpoint = snapshot.raw_for(
            f"checkpoints/checkpoint-{online.recheck_checkpoint_raw_sha256}.json"
        )
        consumed_checkpoint = _parse_exact(
            recheck_checkpoint,
            DeploymentOnlineRecheckCheckpointDTO,
            "consumed recheck checkpoint",
        )
        consume_intent = snapshot.raw_for(f"consumes/{receipt_id}.consume-intent.json")
        consume_marker = snapshot.raw_for(f"consumes/{receipt_id}.consume-marker.json")
        commitments = self._commitment_raws(snapshot)
        preconsume_hash = state.get("preconsume_state_commitment_raw_sha256")
        matches = [
            index
            for index, raw in enumerate(commitments)
            if _sha256(raw) == preconsume_hash
        ]
        if len(matches) != 1:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_PRECONSUME_POINTER_INVALID",
                "planned restart preconsume commitment is absent or ambiguous",
            )
        planned_chain = commitments[matches[0] :]
        anchor = snapshot.raw_for("epoch-anchor.json")
        verified = verify_planned_restart_input_bundle(
            receipt_raw=receipt,
            original_checkpoint_raw=original_checkpoint,
            consumed_recheck_checkpoint_raw=recheck_checkpoint,
            consume_intent_raw=consume_intent,
            consume_marker_raw=consume_marker,
            consumed_online_recheck_raw=online_raw,
            preconsume_state_commitment_raw=planned_chain[0],
            state_commitment_chain_raw=planned_chain,
            current_epoch_anchor_raw=anchor,
            current_runtime_instance_id=(snapshot.inventory.actual_runtime_instance_id),
            current_execution_epoch=snapshot.inventory.actual_execution_epoch,
        )
        fresh_id, fresh_challenge = derive_post_restart_recheck_identity(
            reconciliation_run_id=run_id,
            receipt_id=receipt_id,
            consume_marker_raw_sha256=_sha256(consume_marker),
            current_state_commitment_raw_sha256=_sha256(planned_chain[-1]),
            current_runtime_instance_id=(snapshot.inventory.actual_runtime_instance_id),
            current_execution_epoch=snapshot.inventory.actual_execution_epoch,
        )
        initial_rpc = consumed_checkpoint.rpc
        return _ModeInputs(
            mode="PLANNED_RESTART",
            raw={
                "receipt": receipt,
                "original_checkpoint": original_checkpoint,
                "recheck_checkpoint": recheck_checkpoint,
                "consume_intent": consume_intent,
                "consume_marker": consume_marker,
                "online": online_raw,
                "preconsume": planned_chain[0],
                "chain": planned_chain,
                "anchor": anchor,
            },
            verified=verified,
            rpc_request_id=initial_rpc.request_id,
            owner_challenge=initial_rpc.owner_challenge,
            initial_capture_id=initial_rpc.recheck_id,
            initial_challenge=initial_rpc.fresh_challenge,
            fresh_capture_id=fresh_id,
            fresh_challenge=fresh_challenge,
            initial_rpc=initial_rpc,
        )

    def _initial_capture(
        self,
        *,
        session: DeploymentReconciliationCustodySession,
        intent: DeploymentReconciliationActivationIntentDTO,
        mode_inputs: _ModeInputs,
    ) -> tuple[
        DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
        bytes | None,
    ]:
        if mode_inputs.mode == "PLANNED_RESTART":
            if mode_inputs.initial_rpc is None:
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_PLANNED_CAPTURE_INVALID",
                    "planned restart has no consumed owner recheck",
                )
            return mode_inputs.initial_rpc, None

        basename = f"{intent.intent_id}.commodity-checkpoint.json"
        model = (
            DeploymentInitialBaselineCommodityCheckpointDTO
            if mode_inputs.mode == "INITIAL_BASELINE"
            else DeploymentLegacyMigrationCommodityCheckpointDTO
        )
        try:
            existing = session.read_blob(basename)
        except DeploymentReconciliationCustodyError as exc:
            if exc.code not in {
                "CUSTODY_DIRECTORY_OPEN_FAILED",
                "CUSTODY_FILE_OPEN_FAILED",
            }:
                raise
        else:
            checkpoint = _parse_exact(existing.raw, model, "Commodity checkpoint")
            expected, expected_raw = self._build_commodity_checkpoint(
                intent=intent,
                mode_inputs=mode_inputs,
                initial=checkpoint.initial_rpc,
                captured_at=checkpoint.captured_at,
            )
            if existing.raw != expected_raw:
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_COMMODITY_CHECKPOINT_COLLISION",
                    "persisted Commodity checkpoint has different bindings",
                )
            self._write_stage_copies(
                session=session,
                stable_basename=basename,
                raw=expected_raw,
                payload=expected.model_dump(mode="json"),
            )
            return expected.initial_rpc, expected_raw

        try:
            arguments = {
                "request_id": intent.rpc_request_id,
                "challenge": intent.owner_challenge,
            }
            if self.owner.settings.app_env.lower() == "test":
                initial = self.owner.rpc.capture_deployment_facts(**arguments)
            else:
                from app.services.vnpy_rpc_service import VnpyRpcService

                self._assert_production_rpc_transport()
                initial = VnpyRpcService.capture_deployment_facts(
                    self.owner.rpc,
                    **arguments,
                )
        except Exception as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_INITIAL_CAPTURE_INDETERMINATE",
                "initial Windows capture did not complete deterministically",
            ) from exc
        if not isinstance(initial, DeploymentRpcFactsDTO):
            try:
                initial = DeploymentRpcFactsDTO.model_validate(initial)
            except (TypeError, ValueError, ValidationError) as exc:
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_INITIAL_CAPTURE_INVALID",
                    "initial Windows capture is invalid",
                ) from exc
        checkpoint, raw = self._build_commodity_checkpoint(
            intent=intent,
            mode_inputs=mode_inputs,
            initial=initial,
            captured_at=initial.captured_at,
        )
        stored = session.write_blob(basename, checkpoint.model_dump(mode="json"))
        if stored.raw != raw:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_COMMODITY_CHECKPOINT_READBACK_MISMATCH",
                "Commodity checkpoint readback is not exact",
            )
        self._write_stage_copies(
            session=session,
            stable_basename=basename,
            raw=raw,
            payload=checkpoint.model_dump(mode="json"),
        )
        return initial, raw

    def _build_commodity_checkpoint(
        self,
        *,
        intent: DeploymentReconciliationActivationIntentDTO,
        mode_inputs: _ModeInputs,
        initial: DeploymentRpcFactsDTO,
        captured_at: datetime,
    ) -> tuple[
        DeploymentInitialBaselineCommodityCheckpointDTO
        | DeploymentLegacyMigrationCommodityCheckpointDTO,
        bytes,
    ]:
        commodity_state = self._commodity_state(intent, initial)
        if mode_inputs.mode == "INITIAL_BASELINE":
            checkpoint = _build_initial_baseline_commodity_checkpoint(
                reconciliation_run_id=intent.reconciliation_run_id,
                genesis_commitment_raw_sha256=(intent.genesis_commitment_raw_sha256),
                current_state_commitment_raw_sha256=(
                    intent.current_state_commitment_raw_sha256
                ),
                current_runtime_instance_id=intent.current_runtime_instance_id,
                current_execution_epoch=intent.current_execution_epoch,
                expected_account_hash=intent.owner_binding.expected_account_hash,
                commodity_state=commodity_state,
                initial_rpc=initial,
                captured_at=captured_at,
            )
            raw = canonical_initial_baseline_commodity_checkpoint_bytes(checkpoint)
        else:
            verified = mode_inputs.verified
            inventory_raw = mode_inputs.legacy_inventory_raw
            if inventory_raw is None:
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_LEGACY_INVENTORY_MISSING",
                    "legacy inventory manifest is unavailable",
                )
            checkpoint = _build_legacy_migration_commodity_checkpoint(
                reconciliation_run_id=intent.reconciliation_run_id,
                source_schema_version=verified.source_schema_version,
                source_state_raw_sha256=verified.source_state_raw_sha256,
                source_epoch_anchor_raw_sha256=(
                    verified.source_epoch_anchor_raw_sha256
                ),
                inventory_raw_sha256=_sha256(inventory_raw),
                inventory_id=verified.inventory.inventory_id,
                inventory_core_sha256=verified.inventory.inventory_core_sha256,
                genesis_commitment_raw_sha256=(verified.genesis_commitment_raw_sha256),
                current_state_commitment_raw_sha256=(
                    verified.current_commitment_raw_sha256
                ),
                current_epoch_anchor_raw_sha256=(
                    verified.current_epoch_anchor_raw_sha256
                ),
                current_runtime_instance_id=intent.current_runtime_instance_id,
                current_execution_epoch=intent.current_execution_epoch,
                expected_account_hash=intent.owner_binding.expected_account_hash,
                commodity_state=commodity_state,
                initial_rpc=initial,
                captured_at=captured_at,
            )
            raw = canonical_legacy_migration_commodity_checkpoint_bytes(checkpoint)
        return checkpoint, raw

    @staticmethod
    def _write_stage_copies(
        *,
        session: DeploymentReconciliationCustodySession,
        stable_basename: str,
        raw: bytes,
        payload: Mapping[str, Any],
        content_basename: str | None = None,
    ) -> None:
        """Publish one deterministic WAL slot and its content-addressed copy."""

        stable = session.write_blob(stable_basename, payload)
        if stable.raw != raw:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_STAGE_READBACK_MISMATCH",
                f"reconciliation stage readback differs: {stable_basename}",
            )
        content_name = content_basename or f"{_sha256(raw)}.json"
        content = session.write_blob(content_name, payload)
        if content.raw != raw or content.raw_sha256 != _sha256(raw):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_STAGE_CONTENT_MISMATCH",
                f"reconciliation stage content copy differs: {content_name}",
            )

    def _load_or_create_capture_pair(
        self,
        *,
        session: DeploymentReconciliationCustodySession,
        intent: DeploymentReconciliationActivationIntentDTO,
        intent_raw: bytes,
        initial_rpc: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
        served_proof: DeploymentRpcRecheckServedProofDTO,
        fresh_rpc: DeploymentRpcRecheckFactsDTO,
    ) -> tuple[DeploymentReconciliationOwnerCapturePairDTO, bytes]:
        basename = f"{intent.intent_id}.capture-pair.json"
        try:
            existing = session.read_blob(basename)
        except DeploymentReconciliationCustodyError as exc:
            if exc.code not in {
                "CUSTODY_DIRECTORY_OPEN_FAILED",
                "CUSTODY_FILE_OPEN_FAILED",
            }:
                raise
        else:
            pair = _parse_exact(
                existing.raw,
                DeploymentReconciliationOwnerCapturePairDTO,
                "owner capture pair",
            )
            expected = self._build_capture_pair(
                intent=intent,
                intent_raw=intent_raw,
                initial_rpc=initial_rpc,
                fresh_rpc=fresh_rpc,
                captured_at=pair.captured_at,
            )
            expected_raw = _artifact_bytes(expected.model_dump(mode="json"))
            if existing.raw != expected_raw:
                raise DeploymentReconciliationActivationError(
                    "RECONCILIATION_CAPTURE_PAIR_COLLISION",
                    "persisted owner capture pair has different bindings",
                )
            self._write_stage_copies(
                session=session,
                stable_basename=basename,
                raw=expected_raw,
                payload=expected.model_dump(mode="json"),
            )
            return expected, expected_raw

        captured_at = fresh_rpc.captured_at
        pair = self._build_capture_pair(
            intent=intent,
            intent_raw=intent_raw,
            initial_rpc=initial_rpc,
            fresh_rpc=fresh_rpc,
            captured_at=captured_at,
        )
        raw = _artifact_bytes(pair.model_dump(mode="json"))
        self._write_stage_copies(
            session=session,
            stable_basename=basename,
            raw=raw,
            payload=pair.model_dump(mode="json"),
        )
        return pair, raw

    def _load_or_create_fresh_served_proof(
        self,
        *,
        session: DeploymentReconciliationCustodySession,
        intent: DeploymentReconciliationActivationIntentDTO,
        initial_rpc: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
    ) -> tuple[
        DeploymentRpcRecheckServedProofDTO,
        DeploymentRpcRecheckFactsDTO,
        bytes,
    ]:
        basename = f"{intent.intent_id}.fresh-served-proof.json"
        pair_basename = f"{intent.intent_id}.capture-pair.json"
        try:
            existing = session.read_blob(basename)
        except DeploymentReconciliationCustodyError as exc:
            if exc.code not in {
                "CUSTODY_DIRECTORY_OPEN_FAILED",
                "CUSTODY_FILE_OPEN_FAILED",
            }:
                raise
        else:
            proof = _parse_exact(
                existing.raw,
                DeploymentRpcRecheckServedProofDTO,
                "fresh RPC served proof",
            )
            try:
                pair_blob = session.read_blob(pair_basename)
            except DeploymentReconciliationCustodyError as exc:
                if exc.code not in {
                    "CUSTODY_DIRECTORY_OPEN_FAILED",
                    "CUSTODY_FILE_OPEN_FAILED",
                }:
                    raise
                capture = self._fresh_capture(intent, initial_rpc)
                fresh_rpc = capture.facts
            else:
                pair = _parse_exact(
                    pair_blob.raw,
                    DeploymentReconciliationOwnerCapturePairDTO,
                    "owner capture pair",
                )
                fresh_rpc = pair.fresh_rpc
            self._assert_served_proof_bindings(intent, initial_rpc, proof, fresh_rpc)
            self._write_stage_copies(
                session=session,
                stable_basename=basename,
                raw=existing.raw,
                payload=proof.model_dump(mode="json"),
                content_basename=f"{existing.raw_sha256}.json",
            )
            return proof, fresh_rpc, existing.raw

        try:
            session.read_blob(pair_basename)
        except DeploymentReconciliationCustodyError as exc:
            if exc.code not in {
                "CUSTODY_DIRECTORY_OPEN_FAILED",
                "CUSTODY_FILE_OPEN_FAILED",
            }:
                raise
        else:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_SERVED_PROOF_MISSING",
                "capture pair exists without its transport served proof",
            )

        capture = self._fresh_capture(intent, initial_rpc)
        proof = capture.served_proof
        fresh_rpc = capture.facts
        self._assert_served_proof_bindings(intent, initial_rpc, proof, fresh_rpc)
        raw = _artifact_bytes(proof.model_dump(mode="json"))
        self._write_stage_copies(
            session=session,
            stable_basename=basename,
            raw=raw,
            payload=proof.model_dump(mode="json"),
        )
        return proof, fresh_rpc, raw

    @staticmethod
    def _assert_served_proof_bindings(
        intent: DeploymentReconciliationActivationIntentDTO,
        initial: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
        proof: DeploymentRpcRecheckServedProofDTO,
        fresh_rpc: DeploymentRpcRecheckFactsDTO,
    ) -> None:
        initial_execution_sha = (
            deployment_rpc_execution_facts_sha256(initial)
            if isinstance(initial, DeploymentRpcFactsDTO)
            else initial.execution_facts_canonical_sha256
        )
        if (
            proof.request_id != intent.rpc_request_id
            or proof.owner_challenge != intent.owner_challenge
            or proof.recheck_id != intent.fresh_capture_id
            or proof.fresh_challenge != intent.fresh_challenge
            or proof.original_server_instance_id != initial.server_instance_id
            or proof.original_fact_generation != initial.fact_generation
            or proof.original_execution_facts_canonical_sha256 != initial_execution_sha
            or proof.request_id != fresh_rpc.request_id
            or proof.owner_challenge != fresh_rpc.owner_challenge
            or proof.recheck_id != fresh_rpc.recheck_id
            or proof.fresh_challenge != fresh_rpc.fresh_challenge
            or proof.server_instance_id != fresh_rpc.server_instance_id
            or proof.fact_generation != fresh_rpc.fact_generation
            or proof.execution_facts_canonical_sha256
            != fresh_rpc.execution_facts_canonical_sha256
            or proof.gateway_name != intent.owner_binding.gateway_name
            or proof.rpc_request_endpoint_sha256
            != intent.owner_binding.rpc_request_endpoint_sha256
            or proof.rpc_publish_endpoint_sha256
            != intent.owner_binding.rpc_publish_endpoint_sha256
            or proof.fresh_rpc_raw_sha256
            != _sha256(_artifact_bytes(fresh_rpc.model_dump(mode="json")))
            or DeploymentRpcRecheckServedProofDTO._parse_utc_text(
                proof.captured_at_utc_raw, "captured_at_utc_raw"
            )
            != fresh_rpc.captured_at
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_SERVED_PROOF_BINDING_INVALID",
                "fresh served proof does not bind the intent and initial facts",
            )

    def _commodity_state(
        self,
        intent: DeploymentReconciliationActivationIntentDTO,
        initial: DeploymentRpcFactsDTO,
    ) -> CommodityInitialBaselineStateDTO:
        active_orders_sha = _core_sha256(initial.active_orders)
        positions_sha = _core_sha256(initial.positions)
        try:
            return CommodityInitialBaselineStateDTO.model_validate(
                {
                    "schema_version": (
                        "web_bridge_initial_baseline_commodity_state_v1"
                    ),
                    "commodity_state_version": "commodity-simnow-v1",
                    "commodity_state_checkpoint_sha256": (
                        intent.owner_binding.commodity_state_checkpoint_sha256
                    ),
                    "execution_plan_status": "IDLE",
                    "execution_plan_hash": None,
                    "plan_version": 0,
                    "web_trade_enabled": False,
                    "execution_authority_revoked": True,
                    "auto_dispatch_stopped": True,
                    "unknown_outcome": False,
                    "reconcile_required": False,
                    "rpc_generation": initial.fact_generation,
                    "active_orders_snapshot_sha256": active_orders_sha,
                    "positions_snapshot_sha256": positions_sha,
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_COMMODITY_STATE_INVALID",
                "Commodity owner state cannot form a frozen baseline",
            ) from exc

    def _fresh_capture(
        self,
        intent: DeploymentReconciliationActivationIntentDTO,
        initial: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
    ) -> Any:
        execution_sha = (
            deployment_rpc_execution_facts_sha256(initial)
            if isinstance(initial, DeploymentRpcFactsDTO)
            else initial.execution_facts_canonical_sha256
        )
        try:
            arguments = {
                "request_id": intent.rpc_request_id,
                "owner_challenge": intent.owner_challenge,
                "recheck_id": intent.fresh_capture_id,
                "fresh_challenge": intent.fresh_challenge,
                "original_server_instance_id": initial.server_instance_id,
                "original_fact_generation": initial.fact_generation,
                "original_execution_facts_canonical_sha256": execution_sha,
            }
            if self.owner.settings.app_env.lower() == "test":
                capture = getattr(
                    self.owner.rpc,
                    "capture_deployment_recheck_served_proof",
                    None,
                )
                if not callable(capture):
                    raise TypeError("test RPC has no served-proof transport seam")
                fresh = capture(**arguments)
            else:
                from app.services.vnpy_rpc_service import VnpyRpcService

                self._assert_production_rpc_transport()
                fresh = VnpyRpcService.capture_deployment_recheck_served_proof(
                    self.owner.rpc,
                    **arguments,
                )
        except Exception as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_FRESH_CAPTURE_INDETERMINATE",
                "fresh Windows recheck did not complete deterministically",
            ) from exc
        try:
            from app.services.vnpy_rpc_service import (
                VerifiedDeploymentRecheckCapture,
            )

            if type(fresh) is not VerifiedDeploymentRecheckCapture:
                raise TypeError("served-proof transport returned a bare DTO")
            DeploymentRpcRecheckFactsDTO.model_validate(fresh.facts)
            DeploymentRpcRecheckServedProofDTO.model_validate(fresh.served_proof)
            return fresh
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_FRESH_CAPTURE_INVALID",
                "fresh Windows recheck is invalid",
            ) from exc

    @staticmethod
    def _build_capture_pair(
        *,
        intent: DeploymentReconciliationActivationIntentDTO,
        intent_raw: bytes,
        initial_rpc: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
        fresh_rpc: DeploymentRpcRecheckFactsDTO,
        captured_at: datetime,
    ) -> DeploymentReconciliationOwnerCapturePairDTO:
        initial_raw = _artifact_bytes(initial_rpc.model_dump(mode="json"))
        fresh_raw = _artifact_bytes(fresh_rpc.model_dump(mode="json"))
        initial_execution_sha = (
            deployment_rpc_execution_facts_sha256(initial_rpc)
            if isinstance(initial_rpc, DeploymentRpcFactsDTO)
            else initial_rpc.execution_facts_canonical_sha256
        )
        payload: dict[str, Any] = {
            "schema_version": ("web_bridge_deployment_reconciliation_capture_pair_v1"),
            "purpose": "record_two_stable_frozen_owner_rpc_captures",
            "mode": intent.mode,
            "intent_id": intent.intent_id,
            "intent_raw_sha256": _sha256(intent_raw),
            "intent_core_sha256": intent.intent_core_sha256,
            "owner_binding_id": intent.owner_binding.owner_binding_id,
            "owner_binding_core_sha256": (
                intent.owner_binding.owner_binding_core_sha256
            ),
            "expected_account_hash": intent.owner_binding.expected_account_hash,
            "rpc_request_id": intent.rpc_request_id,
            "owner_challenge": intent.owner_challenge,
            "initial_capture_id": intent.initial_capture_id,
            "initial_challenge": intent.initial_challenge,
            "fresh_capture_id": intent.fresh_capture_id,
            "fresh_challenge": intent.fresh_challenge,
            "commodity_state_raw_sha256": (
                intent.owner_binding.commodity_state_raw_sha256
            ),
            "commodity_state_checkpoint_sha256": (
                intent.owner_binding.commodity_state_checkpoint_sha256
            ),
            "initial_rpc_raw_sha256": _sha256(initial_raw),
            "initial_rpc": initial_rpc.model_dump(mode="json"),
            "fresh_rpc_raw_sha256": _sha256(fresh_raw),
            "fresh_rpc": fresh_rpc.model_dump(mode="json"),
            "initial_execution_facts_canonical_sha256": initial_execution_sha,
            "fresh_execution_facts_canonical_sha256": (
                fresh_rpc.execution_facts_canonical_sha256
            ),
            "captured_at": captured_at,
            "same_owner_cycle_verified": True,
            "two_capture_facts_verified": True,
            **_authority_false_payload(),
        }
        probe_payload = {
            **payload,
            "initial_rpc": initial_rpc,
            "fresh_rpc": fresh_rpc,
        }
        probe = DeploymentReconciliationOwnerCapturePairDTO.model_construct(
            **probe_payload,
            capture_pair_id=("deployment-reconciliation-capture-pair-" + "1" * 64),
            capture_pair_core_sha256="1" * 64,
        )
        core = probe.model_dump(mode="json")
        core.pop("capture_pair_id")
        core.pop("capture_pair_core_sha256")
        digest = _core_sha256(core)
        try:
            return DeploymentReconciliationOwnerCapturePairDTO.model_validate(
                {
                    **payload,
                    "capture_pair_id": (
                        f"deployment-reconciliation-capture-pair-{digest}"
                    ),
                    "capture_pair_core_sha256": digest,
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_CAPTURE_PAIR_INVALID",
                "owner captures are not stable and frozen",
            ) from exc

    def _build_mode_evidence(
        self,
        *,
        intent: DeploymentReconciliationActivationIntentDTO,
        inputs: _ModeInputs,
        initial_rpc: DeploymentRpcFactsDTO | DeploymentRpcRecheckFactsDTO,
        fresh_rpc: DeploymentRpcRecheckFactsDTO,
        commodity_checkpoint_raw: bytes | None,
    ) -> _ModeEvidence:
        captured_at = fresh_rpc.captured_at
        if inputs.mode == "PLANNED_RESTART":
            raw = inputs.raw
            checkpoint = _build_post_restart_checkpoint(
                receipt_raw=raw["receipt"],
                original_checkpoint_raw=raw["original_checkpoint"],
                consumed_recheck_checkpoint_raw=raw["recheck_checkpoint"],
                consume_intent_raw=raw["consume_intent"],
                consume_marker_raw=raw["consume_marker"],
                consumed_online_recheck_raw=raw["online"],
                preconsume_state_commitment_raw=raw["preconsume"],
                state_commitment_chain_raw=raw["chain"],
                current_epoch_anchor_raw=raw["anchor"],
                reconciliation_run_id=intent.reconciliation_run_id,
                current_runtime_instance_id=intent.current_runtime_instance_id,
                current_execution_epoch=intent.current_execution_epoch,
                windows_rpc=fresh_rpc,
                captured_at=captured_at,
            )
            checkpoint_raw = canonical_post_restart_checkpoint_bytes(checkpoint)
            evidence = _build_restart_reconciliation_evidence(
                checkpoint_raw=checkpoint_raw,
                receipt_raw=raw["receipt"],
                original_checkpoint_raw=raw["original_checkpoint"],
                consumed_recheck_checkpoint_raw=raw["recheck_checkpoint"],
                consume_intent_raw=raw["consume_intent"],
                consume_marker_raw=raw["consume_marker"],
                consumed_online_recheck_raw=raw["online"],
                preconsume_state_commitment_raw=raw["preconsume"],
                state_commitment_chain_raw=raw["chain"],
                current_epoch_anchor_raw=raw["anchor"],
                reconciled_at=captured_at,
            )
            evidence_raw = canonical_restart_reconciliation_bytes(evidence)
            return _ModeEvidence(
                checkpoint=checkpoint,
                checkpoint_raw=checkpoint_raw,
                evidence=evidence,
                evidence_raw=evidence_raw,
            )

        if commodity_checkpoint_raw is None or not isinstance(
            initial_rpc, DeploymentRpcFactsDTO
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_BASELINE_CHECKPOINT_MISSING",
                "baseline reconciliation lacks its durable initial capture",
            )
        raw = inputs.raw
        if inputs.mode == "INITIAL_BASELINE":
            arguments = {
                "genesis_state_commitment_raw": raw["genesis"],
                "state_commitment_chain_raw": raw["chain"],
                "current_epoch_anchor_raw": raw["anchor"],
                "reconciliation_run_id": intent.reconciliation_run_id,
                "current_runtime_instance_id": intent.current_runtime_instance_id,
                "current_execution_epoch": intent.current_execution_epoch,
                "expected_account_hash": intent.owner_binding.expected_account_hash,
                "commodity_checkpoint_raw": commodity_checkpoint_raw,
                "fresh_rpc": fresh_rpc,
            }
            checkpoint = _build_initial_baseline_checkpoint(
                **arguments, captured_at=captured_at
            )
            checkpoint_raw = canonical_initial_baseline_checkpoint_bytes(checkpoint)
            evidence = build_initial_baseline_reconciliation_evidence(
                checkpoint_raw=checkpoint_raw,
                **arguments,
            )
            evidence_raw = canonical_initial_baseline_evidence_bytes(evidence)
        else:
            arguments = {
                "source_state_raw": raw["source_state"],
                "source_epoch_anchor_raw": raw["source_anchor"],
                "inventory_manifest_raw": raw["inventory"],
                "genesis_state_commitment_raw": raw["genesis"],
                "state_commitment_chain_raw": raw["chain"],
                "current_epoch_anchor_raw": raw["anchor"],
                "reconciliation_run_id": intent.reconciliation_run_id,
                "current_runtime_instance_id": intent.current_runtime_instance_id,
                "current_execution_epoch": intent.current_execution_epoch,
                "expected_account_hash": intent.owner_binding.expected_account_hash,
                "commodity_checkpoint_raw": commodity_checkpoint_raw,
                "fresh_rpc": fresh_rpc,
            }
            checkpoint = _build_legacy_migration_checkpoint(
                **arguments, captured_at=captured_at
            )
            checkpoint_raw = canonical_legacy_migration_checkpoint_bytes(checkpoint)
            evidence = build_legacy_migration_reconciliation_evidence(
                checkpoint_raw=checkpoint_raw,
                **arguments,
            )
            evidence_raw = canonical_legacy_migration_evidence_bytes(evidence)
        return _ModeEvidence(
            checkpoint=checkpoint,
            checkpoint_raw=checkpoint_raw,
            evidence=evidence,
            evidence_raw=evidence_raw,
        )

    @staticmethod
    def _assert_same_input_inventory(
        before: DeploymentReconciliationCustodySnapshot,
        after: DeploymentReconciliationCustodySnapshot,
    ) -> None:
        left = before.inventory
        right = after.inventory
        stable_fields = (
            "mode",
            "inventory_digest_sha256",
            "custody_root_path_sha256",
            "custody_root_device",
            "custody_root_inode",
            "lock_file_device",
            "lock_file_inode",
            "genesis_commitment_raw_sha256",
            "actual_state_raw_sha256",
            "actual_epoch_anchor_raw_sha256",
            "actual_head_commitment_raw_sha256",
            "actual_state_generation",
            "actual_drain_epoch",
            "actual_execution_epoch",
            "actual_runtime_instance_id",
        )
        if any(
            getattr(left, field) != getattr(right, field) for field in stable_fields
        ):
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_CUSTODY_CHANGED",
                "deployment custody changed during owner capture",
            )

    @staticmethod
    def _build_marker(
        *,
        intent: DeploymentReconciliationActivationIntentDTO,
        pair: DeploymentReconciliationOwnerCapturePairDTO,
        pair_raw: bytes,
        mode_evidence: _ModeEvidence,
        prepared_at: datetime,
    ) -> DeploymentReconciliationActivationMarkerDTO:
        evidence = mode_evidence.evidence
        checkpoint = mode_evidence.checkpoint
        evidence_raw_sha = _sha256(mode_evidence.evidence_raw)
        payload: dict[str, Any] = {
            "schema_version": (
                "web_bridge_deployment_reconciliation_activation_marker_v1"
            ),
            "purpose": "prepare_non_authorizing_owner_reconciliation_activation",
            "mode": intent.mode,
            "intent_id": intent.intent_id,
            "intent_raw_sha256": _sha256(
                _artifact_bytes(intent.model_dump(mode="json"))
            ),
            "intent_core_sha256": intent.intent_core_sha256,
            "custody_inventory_id": intent.custody_inventory_id,
            "custody_inventory_raw_sha256": intent.custody_inventory_raw_sha256,
            "capture_pair_id": pair.capture_pair_id,
            "capture_pair_raw_sha256": _sha256(pair_raw),
            "capture_pair_core_sha256": pair.capture_pair_core_sha256,
            "capture_pair": pair.model_dump(mode="json"),
            "mode_evidence_schema_version": evidence.schema_version,
            "mode_evidence_id": evidence.reconciliation_id,
            "mode_evidence_raw_sha256": evidence_raw_sha,
            "mode_evidence_core_sha256": evidence.reconciliation_core_sha256,
            "mode_evidence_blob_path": (
                f"reconciliation-blobs/{evidence_raw_sha}.json"
            ),
            "mode_checkpoint_id": checkpoint.checkpoint_id,
            "mode_checkpoint_raw_sha256": _sha256(mode_evidence.checkpoint_raw),
            "mode_checkpoint_core_sha256": checkpoint.checkpoint_core_sha256,
            "mode_checkpoint": checkpoint.model_dump(mode="json"),
            "mode_evidence": evidence.model_dump(mode="json"),
            "current_state_commitment_raw_sha256": (
                intent.current_state_commitment_raw_sha256
            ),
            "current_runtime_instance_id": intent.current_runtime_instance_id,
            "current_execution_epoch": intent.current_execution_epoch,
            "expected_account_hash": intent.owner_binding.expected_account_hash,
            "prepared_at": prepared_at,
            "custody_inventory_verified": True,
            "commodity_owner_verified": True,
            "expected_account_allowlist_verified": True,
            "two_capture_facts_verified": True,
            "mode_reconciliation_evidence_verified": True,
            "activation_marker_prepared": True,
            **_authority_false_payload(),
        }
        probe = DeploymentReconciliationActivationMarkerDTO.model_construct(
            **{
                **payload,
                "capture_pair": pair,
                "mode_checkpoint": checkpoint,
                "mode_evidence": evidence,
            },
            marker_id=("deployment-reconciliation-activation-marker-" + "1" * 64),
            marker_core_sha256="1" * 64,
            marker_path=(
                "reconciliation-blobs/activation-marker-" + "1" * 64 + ".json"
            ),
        )
        core = probe.model_dump(mode="json")
        core.pop("marker_id")
        core.pop("marker_core_sha256")
        core.pop("marker_path")
        digest = _core_sha256(core)
        try:
            return DeploymentReconciliationActivationMarkerDTO.model_validate(
                {
                    **payload,
                    "marker_id": (
                        "deployment-reconciliation-activation-marker-" + digest
                    ),
                    "marker_core_sha256": digest,
                    "marker_path": (
                        f"reconciliation-blobs/activation-marker-{digest}.json"
                    ),
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_ACTIVATION_MARKER_INVALID",
                "activation marker closure is invalid",
            ) from exc

    @staticmethod
    def _build_head(
        intent: DeploymentReconciliationActivationIntentDTO,
        marker: DeploymentReconciliationActivationMarkerDTO,
        marker_raw: bytes,
        served_proof: DeploymentRpcRecheckServedProofDTO,
        served_proof_raw: bytes,
    ) -> DeploymentReconciliationActivationHeadV2DTO:
        served_proof_raw_sha = _sha256(served_proof_raw)
        payload: dict[str, Any] = {
            "schema_version": (
                "web_bridge_deployment_reconciliation_activation_head_v2"
            ),
            "purpose": (
                "commit_non_authorizing_owner_reconciliation_activation_with_"
                "served_proof"
            ),
            "mode": intent.mode,
            "activation_sequence": intent.activation_sequence,
            "previous_activation_head_id": intent.previous_activation_head_id,
            "previous_activation_head_raw_sha256": (
                intent.previous_activation_head_raw_sha256
            ),
            "previous_activation_head_core_sha256": (
                intent.previous_activation_head_core_sha256
            ),
            "marker_id": marker.marker_id,
            "marker_raw_sha256": _sha256(marker_raw),
            "marker_core_sha256": marker.marker_core_sha256,
            "marker": marker.model_dump(mode="json"),
            "intent_id": intent.intent_id,
            "custody_inventory_id": intent.custody_inventory_id,
            "current_state_commitment_raw_sha256": (
                intent.current_state_commitment_raw_sha256
            ),
            "current_runtime_instance_id": intent.current_runtime_instance_id,
            "current_execution_epoch": intent.current_execution_epoch,
            "expected_account_hash": intent.owner_binding.expected_account_hash,
            "activated_at": marker.prepared_at,
            "owner_reconciliation_activation_recorded": True,
            "fresh_rpc_served_proof_id": served_proof.proof_id,
            "fresh_rpc_served_proof_raw_sha256": served_proof_raw_sha,
            "fresh_rpc_served_proof_core_sha256": (served_proof.proof_core_sha256),
            "fresh_rpc_served_proof_blob_path": (
                f"reconciliation-blobs/{served_proof_raw_sha}.json"
            ),
            "gateway_name": intent.owner_binding.gateway_name,
            "rpc_request_endpoint_sha256": (
                intent.owner_binding.rpc_request_endpoint_sha256
            ),
            "rpc_publish_endpoint_sha256": (
                intent.owner_binding.rpc_publish_endpoint_sha256
            ),
            "owner_binding_raw_sha256": intent.owner_binding_raw_sha256,
            "owner_binding": intent.owner_binding.model_dump(mode="json"),
            "intent_raw_sha256": _sha256(
                _artifact_bytes(intent.model_dump(mode="json"))
            ),
            "intent": intent.model_dump(mode="json"),
            "fresh_rpc_served_proof": served_proof.model_dump(mode="json"),
            "served_proof_closure_verified": True,
            **_authority_false_payload(),
        }
        probe = DeploymentReconciliationActivationHeadV2DTO.model_construct(
            **{
                **payload,
                "marker": marker,
                "owner_binding": intent.owner_binding,
                "intent": intent,
                "fresh_rpc_served_proof": served_proof,
            },
            activation_head_id=(
                "deployment-reconciliation-activation-head-" + "1" * 64
            ),
            activation_head_core_sha256="1" * 64,
            activation_head_path=(
                "reconciliation-heads/"
                f"{intent.current_state_commitment_raw_sha256}.json"
            ),
        )
        core = probe.model_dump(mode="json")
        core.pop("activation_head_id")
        core.pop("activation_head_core_sha256")
        core.pop("activation_head_path")
        digest = _core_sha256(core)
        try:
            return DeploymentReconciliationActivationHeadV2DTO.model_validate(
                {
                    **payload,
                    "activation_head_id": (
                        f"deployment-reconciliation-activation-head-{digest}"
                    ),
                    "activation_head_core_sha256": digest,
                    "activation_head_path": (
                        "reconciliation-heads/"
                        f"{intent.current_state_commitment_raw_sha256}.json"
                    ),
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationActivationError(
                "RECONCILIATION_ACTIVATION_HEAD_INVALID",
                "activation head commit is invalid",
            ) from exc
