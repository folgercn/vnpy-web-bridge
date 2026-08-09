from __future__ import annotations

import base64
import copy
import hashlib
import json
import unicodedata
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_ROOT = ROOT / "docs" / "schemas"
CHAIN_CONTRACT_PATH = (
    ROOT
    / "docs"
    / "architecture"
    / "windows-rpc-durable-fence-foundation-chain-v1.json"
)
SHA = "a" * 64
OTHER_SHA = "b" * 64
EMPTY_OBJECT_SHA = hashlib.sha256(b"{}").hexdigest()
ATTEMPT_DOMAIN = "vnpy.issue267.windows-foundation.install-attempt-id.v1"
ATTEMPT_INPUT = {
    "attempt_nonce_sha256": SHA,
    "bundle_sha256": SHA,
    "expected_account_sha256": SHA,
    "gateway_name": "CTP",
    "gateway_scope_sha256": EMPTY_OBJECT_SHA,
    "issue": 267,
    "service_name": "VnpyRpcService",
    "store_path_sha256": SHA,
    "store_volume_identity_sha256": SHA,
    "store_volume_serial": "A1B2C3D4",
}
ATTEMPT_CORE = hashlib.sha256(
    ATTEMPT_DOMAIN.encode("utf-8")
    + b"\x00"
    + json.dumps(
        ATTEMPT_INPUT, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
).hexdigest()
ATTEMPT_ID = f"windows-fence-install-{ATTEMPT_CORE}"
AUTHORITY = {
    "windows_fence_released": False,
    "authority_restore_allowed": False,
    "consume_authorized": False,
    "reconciliation_authorized": False,
    "deployment_authorized": False,
    "automatic_deploy_allowed": False,
    "production_allowed": False,
    "live_trading_authorized": False,
    "send_order_authorized": False,
    "cancel_order_authorized": False,
    "countable_forward": False,
}

TEST_SIGNING_IDENTITIES = {
    "dedicated-windows-foundation-manifest-signing-v1": (
        "windows-foundation-manifest-signer",
        "windows-foundation-manifest-signer:offline-v1",
    ),
    "dedicated-windows-foundation-observer-evidence-v1": (
        "windows-foundation-observer-evidence",
        "windows-foundation-observer-evidence:host-key-v1",
    ),
    "dedicated-windows-foundation-restart-authorization-v1": (
        "windows-foundation-restart-authorizer",
        "windows-foundation-restart-authorizer:operator-v1",
    ),
}


def _schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def _common_state() -> dict[str, Any]:
    return {
        "service_name": "VnpyRpcService",
        "store_id": f"windows-fence-store-{SHA}",
        "store_path_sha256": SHA,
        "trusted_clock_id": "windows-trusted-clock-0001",
        "extension_sha256": SHA,
        "launcher_sha256": SHA,
        "assembly_sha256": SHA,
        "config_sha256": SHA,
    }


def _state() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_state_v1",
        "purpose": "persist_windows_rpc_fail_closed_fence_genesis",
        "state_id": f"windows-fence-state-{SHA}",
        "state_core_sha256": SHA,
        **_common_state(),
        "store_format_version": 1,
        "store_volume_serial": "A1B2C3D4",
        "store_volume_identity_sha256": SHA,
        "state_sequence": 1,
        "previous_state_raw_sha256": None,
        "install_attempt_id": ATTEMPT_ID,
        "attempt_nonce_sha256": SHA,
        "bundle_sha256": SHA,
        "install_manifest_id": f"windows-fence-install-manifest-{SHA}",
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_id": f"windows-fence-preflight-{SHA}",
        "preflight_receipt_raw_sha256": SHA,
        "fence_epoch": 1,
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token": None,
        "active_token": None,
        "authority_grant": None,
        "staged_token_inventory": [],
        "active_token_inventory": [],
        "grant_inventory": [],
        "expected_account_sha256": SHA,
        "raw_account_row_sha256": EMPTY_OBJECT_SHA,
        "gateway_name": "CTP",
        "gateway_scope_sha256": EMPTY_OBJECT_SHA,
        "preflight_server_instance_id": "windows-rpc-server-0001",
        "preflight_fact_generation": 7,
        "preflight_execution_facts_sha256": SHA,
        "pending_send_outcomes": 0,
        "active_orders": [],
        "created_at_utc": "2026-08-05T00:00:12Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "authority": AUTHORITY,
    }


def _manifest() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_install_manifest_v1",
        "purpose": (
            "authorize_exact_windows_fence_files_and_one_post_reservation_"
            "service_config_transition_without_restart"
        ),
        "manifest_id": f"windows-fence-install-manifest-{SHA}",
        "manifest_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "attempt_nonce_sha256": SHA,
        "issued_at_utc": "2026-08-05T00:00:10Z",
        "expires_at_utc": "2026-08-05T00:05:00Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "service_name": "VnpyRpcService",
        "store_path_sha256": SHA,
        "store_volume_serial": "A1B2C3D4",
        "store_volume_identity_sha256": SHA,
        "store_id": f"windows-fence-store-{SHA}",
        "store_owner_sid_sha256": SHA,
        "store_directory_acl_sddl_sha256": SHA,
        "store_state_acl_sddl_sha256": SHA,
        "bundle_sha256": SHA,
        "publish_mode": "atomic_content_addressed_final_directory",
        "final_version_directory_path_sha256": SHA,
        "expected_final_owner_sid_sha256": SHA,
        "expected_final_directory_acl_sddl_sha256": SHA,
        "expected_component_acl_sddl_sha256": SHA,
        "extension_version": "windows-rpc-durable-fence-foundation-v1",
        "wrapper_sha256": SHA,
        "wrapper_destination_path_sha256": SHA,
        "extension_sha256": SHA,
        "extension_destination_path_sha256": SHA,
        "launcher_sha256": SHA,
        "launcher_destination_path_sha256": SHA,
        "assembly_sha256": SHA,
        "assembly_destination_path_sha256": SHA,
        "config_sha256": SHA,
        "config_destination_path_sha256": SHA,
        "service_image_path_canonical_sha256": SHA,
        "service_config_canonical_sha256": SHA,
        "expected_service_config_owner_sid_sha256": SHA,
        "expected_service_config_acl_sddl_sha256": SHA,
        "installer_write_access_after_publish": False,
        "preinstall_service_image_path_canonical_sha256": SHA,
        "preinstall_service_config_canonical_sha256": SHA,
        "safety_service_config_canonical_sha256": SHA,
        "service_config_transition_plan_sha256": SHA,
        "service_config_mutation_before_dispatch_reservation_authorized": False,
        "service_config_transition_after_dispatch_reservation_authorized": True,
        "unbound_service_config_mutation_after_observer_seal_authorized": False,
        "target_service_start_type": "DEMAND_START",
        "target_recovery_actions_disabled": True,
        "target_failure_actions_disabled": True,
        "automatic_policy_restore_authorized": False,
        "expected_installer_principal_sid_sha256": SHA,
        "expected_installer_process_image_sha256": SHA,
        "python_class_sha256": SHA,
        "python_path_sha256": SHA,
        "target_state_schema_version": "windows_rpc_durable_fence_state_v1",
        "preflight_receipt_id": f"windows-fence-preflight-{SHA}",
        "preflight_receipt_raw_sha256": SHA,
        "install_authorized": True,
        "restart_authorized": False,
        "automatic_restart_allowed": False,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.install-manifest.v1"
        ),
        "signature_algorithm": "Ed25519",
        "signer_role": "windows-foundation-manifest-signer",
        "signer_key_domain": "dedicated-windows-foundation-manifest-signing-v1",
        "signer_key_id": "windows-foundation-manifest-signer:offline-v1",
        "signer_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


def _preflight() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_zero_order_preflight_v1",
        "purpose": "prove_old_runtime_frozen_and_zero_order_before_fence_install",
        "receipt_id": f"windows-fence-preflight-{SHA}",
        "receipt_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "attempt_nonce_sha256": SHA,
        "bundle_sha256": SHA,
        "store_path_sha256": SHA,
        "store_volume_serial": "A1B2C3D4",
        "store_volume_identity_sha256": SHA,
        "service_image_path_canonical_sha256": SHA,
        "service_config_canonical_sha256": SHA,
        "service_config_owner_sid_sha256": SHA,
        "service_config_acl_sddl_sha256": SHA,
        "challenge_id": f"windows-fence-preflight-challenge-{SHA}",
        "challenge_nonce_sha256": SHA,
        "challenge_issued_at_utc": "2026-08-05T00:00:00Z",
        "snapshot_served_at_utc": "2026-08-05T00:00:01Z",
        "observed_at_utc": "2026-08-05T00:00:02Z",
        "challenge_expires_at_utc": "2026-08-05T00:00:30Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "maximum_preflight_age_seconds": 30,
        "challenge_single_use": True,
        "replay_guard_id": f"windows-fence-preflight-replay-{SHA}",
        "host_observer_id": "windows-host-observer-0001",
        "host_boot_id": "windows-host-boot-0001",
        "service_name": "VnpyRpcService",
        "service_process_id": 1234,
        "service_process_started_at_utc": "2026-08-04T23:00:00Z",
        "server_instance_id": "windows-rpc-server-0001",
        "fact_generation": 7,
        "execution_facts_canonical_sha256": SHA,
        "snapshot_raw_sha256": SHA,
        "owner_request_id": "windows-owner-request-0001",
        "owner_challenge_sha256": SHA,
        "raw_account_row_canonical_json_base64": "e30=",
        "raw_account_row_sha256": EMPTY_OBJECT_SHA,
        "expected_account_sha256": SHA,
        "gateway_name": "CTP",
        "gateway_scope_canonical_json_base64": "e30=",
        "gateway_scope_sha256": EMPTY_OBJECT_SHA,
        "linux_frozen_evidence_raw_sha256": SHA,
        "old_runtime_frozen": True,
        "web_trade_enabled": False,
        "execution_authority_revoked": True,
        "pending_send_outcomes": 0,
        "active_orders": [],
        "zero_order_preflight_verified": True,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.zero-order-preflight.v1"
        ),
        "signature_algorithm": "Ed25519",
        "signer_role": "windows-foundation-observer-evidence",
        "signer_key_domain": "dedicated-windows-foundation-observer-evidence-v1",
        "signer_key_id": "windows-foundation-observer-evidence:host-key-v1",
        "signer_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


def _component() -> dict[str, Any]:
    return {
        "destination_path_sha256": SHA,
        "manifest_sha256": SHA,
        "published_sha256": SHA,
        "readback_sha256": SHA,
        "size_bytes": 1,
        "acl_sddl_sha256": SHA,
        "acl_readback_sddl_sha256": SHA,
        "owner_sid_sha256": SHA,
        "unsafe_write_principals": [],
        "regular_file": True,
        "reparse_point": False,
        "hardlink_count": 1,
        "parent_chain_reparse_free": True,
        "hash_readback_verified": True,
        "acl_readback_verified": True,
    }


def _publish_receipt() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_publish_receipt_v1",
        "purpose": (
            "prove_exact_windows_fence_files_published_and_read_back_without_restart"
        ),
        "receipt_id": f"windows-fence-publish-receipt-{SHA}",
        "receipt_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_raw_sha256": SHA,
        "bundle_sha256": SHA,
        "publish_mode": "atomic_content_addressed_final_directory",
        "published_at_utc": "2026-08-05T00:00:18Z",
        "seal_challenge_id": f"windows-fence-publish-seal-challenge-{SHA}",
        "seal_challenge_nonce_sha256": SHA,
        "seal_challenge_issued_at_utc": "2026-08-05T00:00:18Z",
        "sealed_at_utc": "2026-08-05T00:00:20Z",
        "seal_expires_at_utc": "2026-08-05T00:00:50Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "maximum_seal_to_dispatch_seconds": 30,
        "seal_single_use": True,
        "seal_replay_guard_id": f"windows-fence-publish-seal-replay-{SHA}",
        "service_name": "VnpyRpcService",
        "final_version_directory_path_sha256": SHA,
        "final_directory_owner_sid_sha256": SHA,
        "final_directory_acl_sddl_sha256": SHA,
        "final_directory_acl_readback_sddl_sha256": SHA,
        "final_directory_unsafe_write_principals": [],
        "final_directory_create_only": True,
        "final_directory_overwrite_allowed": False,
        "installer_write_access_after_publish": False,
        "final_directory_reparse_point": False,
        "final_directory_hardlink_target": False,
        "preinstall_service_image_path_canonical_sha256": SHA,
        "preinstall_service_image_path_readback_sha256": SHA,
        "preinstall_service_config_canonical_sha256": SHA,
        "preinstall_service_config_readback_sha256": SHA,
        "target_service_image_path_canonical_sha256": SHA,
        "target_service_config_canonical_sha256": SHA,
        "safety_service_config_canonical_sha256": SHA,
        "service_config_transition_plan_sha256": SHA,
        "active_service_config_matches_preinstall": True,
        "target_service_config_not_applied": True,
        "service_config_owner_sid_sha256": SHA,
        "service_config_acl_sddl_sha256": SHA,
        "service_config_acl_readback_sddl_sha256": SHA,
        "service_config_unsafe_write_principals": [],
        "service_config_transition_plan_manifest_bound": True,
        "service_config_mutation_before_dispatch_reservation_authorized": False,
        "unbound_service_config_mutation_after_observer_seal_authorized": False,
        "components": {
            name: _component()
            for name in ("extension", "launcher", "assembly", "config")
        },
        "publish_complete": True,
        "restart_authorized": False,
        "automatic_restart_allowed": False,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.publish-receipt.v1"
        ),
        "signature_algorithm": "Ed25519",
        "signer_role": "windows-foundation-observer-evidence",
        "signer_key_domain": "dedicated-windows-foundation-observer-evidence-v1",
        "signer_key_id": "windows-foundation-observer-evidence:host-key-v1",
        "signer_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


def _event() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_install_event_v1",
        "purpose": "append_create_only_windows_fence_install_attempt_event",
        "event_id": f"windows-fence-install-event-{SHA}",
        "event_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "event_sequence": 1,
        "previous_event_id": None,
        "previous_event_raw_sha256": None,
        "event_type": "INSTALL_PREPARED",
        "attempt_state": "PREPARED_FROZEN",
        "observed_at_utc": "2026-08-05T00:00:13Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        **{
            key: value
            for key, value in _common_state().items()
            if key in {"service_name", "store_id", "store_path_sha256"}
        },
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_raw_sha256": SHA,
        "fence_state_raw_sha256": SHA,
        "publish_receipt_raw_sha256": None,
        "restart_authorization_raw_sha256": None,
        "restart_dispatch_nonce_sha256": None,
        "service_config_transition_receipt_raw_sha256": None,
        "scm_dispatch_evidence_raw_sha256": None,
        "startup_receipt_raw_sha256": None,
        "foundation_attestation_raw_sha256": None,
        "service_control_operation_id": None,
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token": None,
        "active_token": None,
        "authority_grant": None,
        "details_sha256": SHA,
        "authority": AUTHORITY,
    }


def _restart_authorization() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_restart_authorization_v1",
        "purpose": "authorize_one_exact_windows_service_restart_dispatch",
        "authorization_id": f"windows-fence-restart-authorization-{SHA}",
        "authorization_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_raw_sha256": SHA,
        "publish_receipt_raw_sha256": SHA,
        "service_config_transition_plan_sha256": SHA,
        "publish_seal_challenge_id": f"windows-fence-publish-seal-challenge-{SHA}",
        "publish_seal_expires_at_utc": "2026-08-05T00:00:50Z",
        "install_event_head_raw_sha256": SHA,
        "service_name": "VnpyRpcService",
        "expected_host_boot_id": "windows-host-boot-0001",
        "expected_service_process_id": 1234,
        "expected_service_process_started_at_utc": "2026-08-04T23:00:00Z",
        "service_control_operation_id": "windows-service-restart-0001",
        "issued_at_utc": "2026-08-05T00:00:30Z",
        "not_before_utc": "2026-08-05T00:00:30Z",
        "expires_at_utc": "2026-08-05T00:01:00Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "dispatch_nonce_sha256": SHA,
        "maximum_restart_dispatches": 1,
        "dispatch_consumption_required": True,
        "restart_authorized": True,
        "automatic_restart_allowed": False,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.restart-authorization.v1"
        ),
        "signature_algorithm": "Ed25519",
        "restart_authorizer_role": "windows-foundation-restart-authorizer",
        "restart_authorizer_key_domain": (
            "dedicated-windows-foundation-restart-authorization-v1"
        ),
        "signer_key_id": "windows-foundation-restart-authorizer:operator-v1",
        "signer_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


def _service_config_transition_receipt() -> dict[str, Any]:
    return {
        "schema_version": (
            "windows_rpc_durable_fence_service_config_transition_receipt_v1"
        ),
        "purpose": (
            "prove_one_exact_post_reservation_service_config_transition_without_restart"
        ),
        "receipt_id": f"windows-fence-service-config-transition-{SHA}",
        "receipt_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_raw_sha256": SHA,
        "publish_receipt_raw_sha256": SHA,
        "restart_authorization_raw_sha256": SHA,
        "reservation_event_id": f"windows-fence-install-event-{SHA}",
        "reservation_event_raw_sha256": SHA,
        "service_name": "VnpyRpcService",
        "host_boot_id": "windows-host-boot-0001",
        "service_control_operation_id": "windows-service-restart-0001",
        "restart_dispatch_nonce_sha256": SHA,
        "transition_plan_sha256": SHA,
        "applied_at_utc": "2026-08-05T00:00:33Z",
        "readback_at_utc": "2026-08-05T00:00:34Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "preinstall_service_image_path_canonical_sha256": SHA,
        "preinstall_service_config_canonical_sha256": SHA,
        "safety_service_config_canonical_sha256": SHA,
        "safety_service_config_readback_sha256": SHA,
        "safety_service_image_path_readback_sha256": SHA,
        "target_service_image_path_canonical_sha256": SHA,
        "target_service_image_path_readback_sha256": SHA,
        "target_service_config_canonical_sha256": SHA,
        "target_service_config_readback_sha256": SHA,
        "service_config_owner_sid_sha256": SHA,
        "service_config_acl_sddl_sha256": SHA,
        "service_config_acl_readback_sddl_sha256": SHA,
        "service_config_unsafe_write_principals": [],
        "authorized_changed_fields": [
            "FailureActions",
            "ImagePath",
            "RecoveryActions",
            "StartType",
        ],
        "safety_transition_applied_before_target_image_path": True,
        "target_service_start_type": "DEMAND_START",
        "target_recovery_actions_disabled": True,
        "target_failure_actions_disabled": True,
        "automatic_policy_restore_authorized": False,
        "service_account_unchanged": True,
        "dependencies_unchanged": True,
        "expected_service_process_id": 1234,
        "expected_service_process_started_at_utc": "2026-08-04T23:00:00Z",
        "service_process_identity_unchanged": True,
        "transition_manifest_bound": True,
        "transition_applied_once": True,
        "target_readback_verified": True,
        "post_transition_mutation_authorized": False,
        "restart_dispatched": False,
        "authority": AUTHORITY,
    }


def _scm_dispatch_evidence() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_scm_dispatch_evidence_v1",
        "purpose": "prove_exact_installer_scm_restart_call_from_host_audit_trace",
        "evidence_id": f"windows-fence-scm-dispatch-evidence-{SHA}",
        "evidence_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "install_manifest_raw_sha256": SHA,
        "restart_authorization_raw_sha256": SHA,
        "reservation_event_raw_sha256": SHA,
        "service_config_transition_receipt_raw_sha256": SHA,
        "service_name": "VnpyRpcService",
        "service_control_operation_id": "windows-service-restart-0001",
        "restart_dispatch_nonce_sha256": SHA,
        "host_boot_id": "windows-host-boot-0001",
        "audit_provider": "Microsoft-Windows-Services-host-audit",
        "audit_provider_guid_sha256": SHA,
        "audit_channel": "host-protected-scm-call-trace",
        "audit_record_sequence": 1,
        "audit_trace_id": f"windows-scm-audit-trace-{SHA}",
        "audit_trace_raw_sha256": SHA,
        "trace_challenge_id": f"windows-scm-trace-challenge-{SHA}",
        "trace_challenge_nonce_sha256": SHA,
        "trace_challenge_issued_at_utc": "2026-08-05T00:00:34Z",
        "trace_captured_at_utc": "2026-08-05T00:00:37Z",
        "trace_expires_at_utc": "2026-08-05T00:00:44Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "maximum_trace_age_seconds": 10,
        "trace_single_use": True,
        "trace_replay_guard_id": f"windows-scm-trace-replay-{SHA}",
        "caller_principal_sid_sha256": SHA,
        "caller_process_image_sha256": SHA,
        "caller_process_id": 3456,
        "caller_session_id": 0,
        "scm_api_sequence": ["ControlService(STOP)", "StartServiceW"],
        "stop_call_started_at_utc": "2026-08-05T00:00:35Z",
        "stop_call_returned_at_utc": "2026-08-05T00:00:35.500000Z",
        "stop_api_result": "SERVICE_STOPPED",
        "start_call_started_at_utc": "2026-08-05T00:00:35.600000Z",
        "start_call_returned_at_utc": "2026-08-05T00:00:36Z",
        "start_api_result": "SERVICE_RUNNING",
        "exact_caller_and_operation_verified": True,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.scm-dispatch-evidence.v1"
        ),
        "signature_algorithm": "Ed25519",
        "signer_role": "windows-foundation-observer-evidence",
        "signer_key_domain": "dedicated-windows-foundation-observer-evidence-v1",
        "signer_key_id": "windows-foundation-observer-evidence:host-key-v1",
        "signer_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


def _startup_receipt() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_startup_receipt_v1",
        "purpose": "prove_target_process_started_only_after_exact_reserved_scm_dispatch",
        "receipt_id": f"windows-fence-startup-receipt-{SHA}",
        "receipt_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "install_manifest_raw_sha256": SHA,
        "restart_authorization_raw_sha256": SHA,
        "service_config_transition_receipt_raw_sha256": SHA,
        "scm_dispatch_evidence_raw_sha256": SHA,
        "scm_audit_trace_raw_sha256": SHA,
        "restart_dispatched_event_id": f"windows-fence-install-event-{SHA}",
        "restart_dispatched_event_raw_sha256": SHA,
        "service_name": "VnpyRpcService",
        "service_control_operation_id": "windows-service-restart-0001",
        "restart_dispatch_nonce_sha256": SHA,
        "scm_call_started_at_utc": "2026-08-05T00:00:35.600000Z",
        "scm_call_returned_at_utc": "2026-08-05T00:00:36Z",
        "scm_result": "SERVICE_RUNNING",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "observed_at_utc": "2026-08-05T00:00:37Z",
        "host_boot_id": "windows-host-boot-0001",
        "service_process_id": 2345,
        "service_process_started_at_utc": "2026-08-05T00:00:36Z",
        "process_start_strictly_after_scm_call_start": True,
        "service_image_path_canonical_sha256": SHA,
        "service_config_canonical_sha256": SHA,
        "service_start_type": "DEMAND_START",
        "service_recovery_actions_disabled": True,
        "service_failure_actions_disabled": True,
        "automatic_policy_restore_authorized": False,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.startup-receipt.v1"
        ),
        "signature_algorithm": "Ed25519",
        "signer_role": "windows-foundation-observer-evidence",
        "signer_key_domain": "dedicated-windows-foundation-observer-evidence-v1",
        "signer_key_id": "windows-foundation-observer-evidence:host-key-v1",
        "signer_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


def _attestation() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_foundation_attestation_v1",
        "purpose": "prove_post_restart_windows_fence_held_without_tokens",
        "attestation_id": f"windows-fence-foundation-attestation-{SHA}",
        "attestation_core_sha256": SHA,
        "install_attempt_id": ATTEMPT_ID,
        "challenge": "windows-foundation-challenge-0001",
        "captured_at_utc": "2026-08-05T00:01:00Z",
        "served_at_utc": "2026-08-05T00:01:01Z",
        "trusted_clock_id": "windows-trusted-clock-0001",
        "install_manifest_raw_sha256": SHA,
        "preflight_receipt_raw_sha256": SHA,
        "fence_state_raw_sha256": SHA,
        "publish_receipt_raw_sha256": SHA,
        "service_config_transition_receipt_raw_sha256": SHA,
        "start_observed_event_id": f"windows-fence-install-event-{SHA}",
        "start_observed_event_raw_sha256": SHA,
        "start_observed_event_type": "START_OBSERVED",
        "restart_authorization_raw_sha256": SHA,
        "startup_receipt_raw_sha256": SHA,
        "service_control_operation_id": "windows-service-restart-0001",
        **_common_state(),
        "store_volume_serial": "A1B2C3D4",
        "store_volume_identity_sha256": SHA,
        "service_image_path_canonical_sha256": SHA,
        "service_config_canonical_sha256": SHA,
        "service_start_type": "DEMAND_START",
        "service_recovery_actions_disabled": True,
        "service_failure_actions_disabled": True,
        "automatic_policy_restore_authorized": False,
        "process_image_sha256": SHA,
        "loaded_extension_sha256": SHA,
        "effective_config_sha256": SHA,
        "store_inventory_sha256": SHA,
        "host_boot_id": "windows-host-boot-0001",
        "host_boot_started_at_utc": "2026-08-04T20:00:00Z",
        "service_instance_id": "windows-service-instance-0001",
        "service_process_id": 2345,
        "service_process_started_at_utc": "2026-08-05T00:00:36Z",
        "server_instance_id": "windows-rpc-server-0002",
        "gateway_name": "CTP",
        "gateway_scope_canonical_json_base64": "e30=",
        "gateway_scope_sha256": EMPTY_OBJECT_SHA,
        "gateway_session_id": "ctp-gateway-session-0001",
        "ctp_front_id": 1,
        "ctp_session_id": 2,
        "trading_day": "20260805",
        "raw_account_row_canonical_json_base64": "e30=",
        "raw_account_row_sha256": EMPTY_OBJECT_SHA,
        "expected_account_sha256": SHA,
        "fact_generation": 0,
        "execution_facts_canonical_sha256": SHA,
        "pending_send_outcomes": 0,
        "active_orders": [],
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token": None,
        "active_token": None,
        "authority_grant": None,
        "staged_token_inventory": [],
        "active_token_inventory": [],
        "grant_inventory": [],
        "send_without_active_token_rejected": True,
        "cancel_without_active_token_rejected": True,
        "final_registry_admission_proof": {
            "proof_mode": "in_process_final_registry_handler_non_forwarding",
            "live_mutation_rpc_probe_performed": False,
            "registry_canonical_sha256": SHA,
            "registry_owner_identity_sha256": SHA,
            "send_handler_identity_sha256": SHA,
            "cancel_handler_identity_sha256": SHA,
            "send_challenge_sha256": SHA,
            "send_request_canonical_sha256": SHA,
            "send_response_raw_sha256": SHA,
            "send_rejection_code": "WINDOWS_FENCE_ACTIVE_TOKEN_REQUIRED",
            "cancel_challenge_sha256": SHA,
            "cancel_request_canonical_sha256": SHA,
            "cancel_response_raw_sha256": SHA,
            "cancel_rejection_code": "WINDOWS_FENCE_ACTIVE_TOKEN_REQUIRED",
            "gateway_trace_canonical_sha256": SHA,
            "gateway_send_calls_before": 0,
            "gateway_send_calls_after": 0,
            "gateway_cancel_calls_before": 0,
            "gateway_cancel_calls_after": 0,
            "gateway_mutation_calls_before": 0,
            "gateway_mutation_calls_after": 0,
            "underlying_gateway_invoked": False,
            "non_forwarding_verified": True,
        },
        "foundation_evidence_verified": True,
        "authority": AUTHORITY,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": (
            "vnpy.issue267.windows-foundation.attestation.v1"
        ),
        "signature_algorithm": "Ed25519",
        "attester_role": "windows-foundation-observer-evidence",
        "attester_key_domain": "dedicated-windows-foundation-observer-evidence-v1",
        "attester_key_id": "windows-foundation-observer-evidence:host-key-v1",
        "attester_public_key_sha256": SHA,
        "signature": "A" * 86 + "==",
    }


CASES = [
    ("windows-rpc-durable-fence-state-v1.schema.json", _state),
    ("windows-rpc-durable-fence-install-manifest-v1.schema.json", _manifest),
    ("windows-rpc-durable-fence-zero-order-preflight-v1.schema.json", _preflight),
    ("windows-rpc-durable-fence-publish-receipt-v1.schema.json", _publish_receipt),
    ("windows-rpc-durable-fence-install-event-v1.schema.json", _event),
    (
        "windows-rpc-durable-fence-service-config-transition-receipt-v1.schema.json",
        _service_config_transition_receipt,
    ),
    (
        "windows-rpc-durable-fence-scm-dispatch-evidence-v1.schema.json",
        _scm_dispatch_evidence,
    ),
    ("windows-rpc-durable-fence-startup-receipt-v1.schema.json", _startup_receipt),
    (
        "windows-rpc-durable-fence-restart-authorization-v1.schema.json",
        _restart_authorization,
    ),
    ("windows-rpc-durable-fence-foundation-attestation-v1.schema.json", _attestation),
]


@pytest.mark.parametrize(("filename", "factory"), CASES)
def test_windows_fence_foundation_schemas_accept_exact_inert_examples(
    filename: str, factory: Any
) -> None:
    schema = _schema(filename)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(factory())


@pytest.mark.parametrize(("filename", "factory"), CASES)
def test_windows_fence_foundation_schemas_reject_unknown_fields(
    filename: str, factory: Any
) -> None:
    value = factory()
    value["unexpected_authority"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(filename)).validate(value)


@pytest.mark.parametrize(("filename", "factory"), CASES)
def test_every_closed_schema_object_requires_every_declared_field(
    filename: str, factory: Any
) -> None:
    del factory

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if (
                node.get("type") == "object"
                and node.get("additionalProperties") is False
            ):
                assert set(node.get("required", [])) == set(node.get("properties", {}))
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(_schema(filename))


@pytest.mark.parametrize(
    ("factory", "field"),
    [
        (_state, "token_state"),
        (_event, "token_state"),
        (_attestation, "token_state"),
    ],
)
def test_windows_fence_foundation_never_accepts_staged_or_active(
    factory: Any, field: str
) -> None:
    for forbidden in ("STAGED", "ACTIVE"):
        value = factory()
        value[field] = forbidden
        with pytest.raises(ValidationError):
            Draft202012Validator(
                _schema(
                    {
                        _state: "windows-rpc-durable-fence-state-v1.schema.json",
                        _event: (
                            "windows-rpc-durable-fence-install-event-v1.schema.json"
                        ),
                        _attestation: (
                            "windows-rpc-durable-fence-foundation-attestation-v1."
                            "schema.json"
                        ),
                    }[factory]
                )
            ).validate(value)


def test_windows_fence_foundation_rejects_authority_and_order_drift() -> None:
    state = _state()
    state["authority"] = {**AUTHORITY, "send_order_authorized": True}
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-state-v1.schema.json")
        ).validate(state)

    preflight = _preflight()
    preflight["pending_send_outcomes"] = 1
    preflight["active_orders"] = [{"vt_orderid": "CTP.1"}]
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-zero-order-preflight-v1.schema.json")
        ).validate(preflight)

    attestation = _attestation()
    attestation["active_token"] = {"token_id": "forbidden"}
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-foundation-attestation-v1.schema.json")
        ).validate(attestation)


def test_install_manifest_cannot_authorize_restart() -> None:
    manifest = copy.deepcopy(_manifest())
    manifest["restart_authorized"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-manifest-v1.schema.json")
        ).validate(manifest)

    manifest = _manifest()
    manifest["service_config_transition_after_dispatch_reservation_authorized"] = False
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-manifest-v1.schema.json")
        ).validate(manifest)


@pytest.mark.parametrize(
    ("filename", "factory", "field", "foreign_value"),
    [
        (
            "windows-rpc-durable-fence-install-manifest-v1.schema.json",
            _manifest,
            "signer_key_domain",
            "dedicated-windows-foundation-observer-evidence-v1",
        ),
        (
            "windows-rpc-durable-fence-zero-order-preflight-v1.schema.json",
            _preflight,
            "signer_key_domain",
            "dedicated-windows-foundation-manifest-signing-v1",
        ),
        (
            "windows-rpc-durable-fence-restart-authorization-v1.schema.json",
            _restart_authorization,
            "restart_authorizer_key_domain",
            "dedicated-windows-foundation-observer-evidence-v1",
        ),
    ],
)
def test_signing_domains_cannot_be_spliced(
    filename: str, factory: Any, field: str, foreign_value: str
) -> None:
    value = factory()
    value[field] = foreign_value
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(filename)).validate(value)


def test_restart_authorization_is_single_dispatch_and_non_automatic() -> None:
    schema = _schema("windows-rpc-durable-fence-restart-authorization-v1.schema.json")
    authorization = _restart_authorization()
    authorization["maximum_restart_dispatches"] = 2
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(authorization)

    authorization = _restart_authorization()
    authorization["automatic_restart_allowed"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(authorization)


def test_preflight_and_publish_receipts_are_fail_closed() -> None:
    preflight_schema = _schema(
        "windows-rpc-durable-fence-zero-order-preflight-v1.schema.json"
    )
    preflight = _preflight()
    preflight["maximum_preflight_age_seconds"] = 31
    with pytest.raises(ValidationError):
        Draft202012Validator(preflight_schema).validate(preflight)

    publish_schema = _schema("windows-rpc-durable-fence-publish-receipt-v1.schema.json")
    publish = _publish_receipt()
    publish["components"]["extension"]["reparse_point"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(publish_schema).validate(publish)

    for field, unsafe in (
        ("installer_write_access_after_publish", True),
        ("final_directory_overwrite_allowed", True),
        ("unbound_service_config_mutation_after_observer_seal_authorized", True),
    ):
        publish = _publish_receipt()
        publish[field] = unsafe
        with pytest.raises(ValidationError):
            Draft202012Validator(publish_schema).validate(publish)

    publish = _publish_receipt()
    publish["service_config_transition_plan_manifest_bound"] = False
    with pytest.raises(ValidationError):
        Draft202012Validator(publish_schema).validate(publish)


def test_final_admission_proof_cannot_claim_gateway_calls_or_live_rpc_probe() -> None:
    schema = _schema("windows-rpc-durable-fence-foundation-attestation-v1.schema.json")
    assert "foundation_closure_verified" not in schema["properties"]
    assert schema["properties"]["foundation_evidence_verified"] == {"const": True}
    for field, unsafe in (
        ("gateway_send_calls_after", 1),
        ("underlying_gateway_invoked", True),
        ("live_mutation_rpc_probe_performed", True),
    ):
        attestation = _attestation()
        attestation["final_registry_admission_proof"][field] = unsafe
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(attestation)


def test_first_install_event_has_no_predecessor() -> None:
    event = _event()
    event["previous_event_raw_sha256"] = OTHER_SHA
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
        ).validate(event)

    event = _event()
    event["publish_receipt_raw_sha256"] = SHA
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
        ).validate(event)


def test_failed_event_requires_a_predecessor_and_known_failure_frontier() -> None:
    event = _event()
    event.update(
        event_type="FAILED_FROZEN",
        attempt_state="FAILED_FROZEN",
        event_sequence=2,
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
        ).validate(event)


def _failure_artifacts() -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    artifacts["preflight"] = _artifact("preflight", _preflight())
    manifest = _manifest()
    manifest.update(
        preflight_receipt_id=_artifact_value(artifacts["preflight"])["receipt_id"],
        preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
    )
    artifacts["manifest"] = _artifact("manifest", manifest)
    state = _state()
    state.update(
        preflight_receipt_id=_artifact_value(artifacts["preflight"])["receipt_id"],
        install_manifest_id=_artifact_value(artifacts["manifest"])["manifest_id"],
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
    )
    artifacts["state"] = _artifact("state", state)

    def add_event(sequence: int, event_type: str, attempt_state: str) -> None:
        value = _event()
        value.update(
            event_id=f"windows-fence-install-event-{sequence:064x}",
            event_sequence=sequence,
            event_type=event_type,
            attempt_state=attempt_state,
            install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
            preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
            fence_state_raw_sha256=_raw_sha(artifacts["state"]),
        )
        if sequence == 1:
            value.update(previous_event_id=None, previous_event_raw_sha256=None)
        else:
            predecessor = artifacts[f"event_{sequence - 1}"]
            predecessor_value = _artifact_value(predecessor)
            value.update(
                previous_event_id=predecessor_value["event_id"],
                previous_event_raw_sha256=_raw_sha(predecessor),
            )
        if sequence >= 2:
            value["publish_receipt_raw_sha256"] = _raw_sha(artifacts["publish"])
        if sequence >= 3:
            value.update(
                restart_authorization_raw_sha256=_raw_sha(
                    artifacts["restart_authorization"]
                ),
                restart_dispatch_nonce_sha256=SHA,
                service_control_operation_id="windows-service-restart-0001",
            )
        if sequence >= 4:
            value["service_config_transition_receipt_raw_sha256"] = _raw_sha(
                artifacts["service_config_transition_receipt"]
            )
        if sequence >= 5:
            value["scm_dispatch_evidence_raw_sha256"] = _raw_sha(
                artifacts["scm_dispatch_evidence"]
            )
        if sequence >= 6:
            value["startup_receipt_raw_sha256"] = _raw_sha(
                artifacts["startup_receipt"]
            )
        artifacts[f"event_{sequence}"] = _artifact("install_event", value)

    add_event(1, "INSTALL_PREPARED", "PREPARED_FROZEN")
    publish = _publish_receipt()
    publish.update(
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
    )
    artifacts["publish"] = _artifact("publish", publish)
    add_event(2, "FILES_PUBLISHED", "FILES_READY_FROZEN")

    restart_authorization = _restart_authorization()
    restart_authorization.update(
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
        publish_receipt_raw_sha256=_raw_sha(artifacts["publish"]),
        install_event_head_raw_sha256=_raw_sha(artifacts["event_2"]),
    )
    artifacts["restart_authorization"] = _artifact(
        "restart_authorization", restart_authorization
    )
    add_event(
        3, "RESTART_DISPATCH_RESERVED", "RESTART_DISPATCH_RESERVED_FROZEN"
    )

    transition = _service_config_transition_receipt()
    transition.update(
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
        publish_receipt_raw_sha256=_raw_sha(artifacts["publish"]),
        restart_authorization_raw_sha256=_raw_sha(artifacts["restart_authorization"]),
        reservation_event_id=_artifact_value(artifacts["event_3"])["event_id"],
        reservation_event_raw_sha256=_raw_sha(artifacts["event_3"]),
    )
    artifacts["service_config_transition_receipt"] = _artifact(
        "service_config_transition_receipt", transition
    )
    add_event(
        4,
        "SERVICE_CONFIG_TRANSITION_VERIFIED",
        "SERVICE_CONFIG_READY_FROZEN",
    )

    evidence = _scm_dispatch_evidence()
    evidence.update(
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        restart_authorization_raw_sha256=_raw_sha(artifacts["restart_authorization"]),
        reservation_event_raw_sha256=_raw_sha(artifacts["event_3"]),
        service_config_transition_receipt_raw_sha256=_raw_sha(
            artifacts["service_config_transition_receipt"]
        ),
    )
    artifacts["scm_dispatch_evidence"] = _artifact(
        "scm_dispatch_evidence", evidence
    )
    add_event(5, "RESTART_DISPATCHED", "RESTART_UNKNOWN_FROZEN")

    startup = _startup_receipt()
    startup.update(
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        restart_authorization_raw_sha256=_raw_sha(artifacts["restart_authorization"]),
        service_config_transition_receipt_raw_sha256=_raw_sha(
            artifacts["service_config_transition_receipt"]
        ),
        scm_dispatch_evidence_raw_sha256=_raw_sha(artifacts["scm_dispatch_evidence"]),
        restart_dispatched_event_id=_artifact_value(artifacts["event_5"])["event_id"],
        restart_dispatched_event_raw_sha256=_raw_sha(artifacts["event_5"]),
    )
    artifacts["startup_receipt"] = _artifact("startup_receipt", startup)
    add_event(6, "START_OBSERVED", "STARTED_FROZEN")
    normal_types = {
        1: ("INSTALL_PREPARED", "PREPARED_FROZEN"),
        2: ("FILES_PUBLISHED", "FILES_READY_FROZEN"),
        3: ("RESTART_DISPATCH_RESERVED", "RESTART_DISPATCH_RESERVED_FROZEN"),
        4: ("SERVICE_CONFIG_TRANSITION_VERIFIED", "SERVICE_CONFIG_READY_FROZEN"),
        5: ("RESTART_DISPATCHED", "RESTART_UNKNOWN_FROZEN"),
        6: ("START_OBSERVED", "STARTED_FROZEN"),
    }
    assert normal_types == {
        sequence: (
            _artifact_value(artifacts[f"event_{sequence}"])["event_type"],
            _artifact_value(artifacts[f"event_{sequence}"])["attempt_state"],
        )
        for sequence in range(1, 7)
    }
    return artifacts


def _canonical_raw(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if not -(2**53) + 1 <= value <= 2**53 - 1:
            raise ValueError("JCS_INTEGER_OUTSIDE_EXACT_IEEE754_RANGE")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise TypeError("JCS_FLOAT_FORBIDDEN_BY_FOUNDATION_PROFILE")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("JCS_STRING_NOT_NFC")
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("JCS_STRING_INVALID_UNICODE") from exc
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_canonical_raw(item) for item in value) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JCS_OBJECT_KEYS_MUST_BE_STRINGS")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return (
            b"{"
            + b",".join(
                _canonical_raw(key) + b":" + _canonical_raw(item)
                for key, item in items
            )
            + b"}"
        )
    raise TypeError("JCS_UNSUPPORTED_JSON_TYPE")


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def reject_float(_: str) -> None:
        raise ValueError("FOUNDATION_JSON_FLOAT_FORBIDDEN")

    def reject_constant(_: str) -> None:
        raise ValueError("FOUNDATION_JSON_NONFINITE_FORBIDDEN")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("FOUNDATION_JSON_DUPLICATE_KEY")
            value[key] = item
        return value

    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=unique_object,
        parse_float=reject_float,
        parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise TypeError("ARTIFACT_RAW_NOT_JSON_OBJECT")
    if _canonical_raw(value) != raw:
        raise ValueError("CANONICALIZATION_CORE_OR_ID_MISMATCH")
    return value


def _identity_spec(artifact_name: str) -> dict[str, Any]:
    contract = json.loads(CHAIN_CONTRACT_PATH.read_text(encoding="utf-8"))
    return next(
        item
        for item in contract["artifact_identity_and_signature_profile"]["artifacts"]
        if item["name"] == artifact_name
    )


def _test_private_key(key_domain: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"wf0-contract-test-key:{key_domain}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key_raw(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _signer_fields(artifact_name: str) -> tuple[str, str, str, str]:
    if artifact_name == "restart_authorization":
        return (
            "restart_authorizer_role",
            "restart_authorizer_key_domain",
            "signer_key_id",
            "signer_public_key_sha256",
        )
    return (
        "signer_role",
        "signer_key_domain",
        "signer_key_id",
        "signer_public_key_sha256",
    )


def _artifact(artifact_name: str, value: dict[str, Any]) -> dict[str, Any]:
    spec = _identity_spec(artifact_name)
    value = copy.deepcopy(value)
    signed = spec["signature_domain_separator"] is not None
    if signed:
        role_field, domain_field, key_id_field, pin_field = _signer_fields(
            artifact_name
        )
        identity = TEST_SIGNING_IDENTITIES[value[domain_field]]
        if (value[role_field], value[key_id_field]) != identity:
            raise ValueError("TEST_SIGNER_IDENTITY_MISMATCH")
        private_key = _test_private_key(value[domain_field])
        value[pin_field] = hashlib.sha256(_public_key_raw(private_key)).hexdigest()
    value.pop("signature", None)
    core_payload = {
        key: item
        for key, item in value.items()
        if key not in {spec["id_field"], spec["core_field"]}
    }
    core = hashlib.sha256(_canonical_raw(core_payload)).hexdigest()
    value[spec["core_field"]] = core
    value[spec["id_field"]] = f"{spec['id_prefix']}{core}"
    if signed:
        message = (
            spec["signature_domain_separator"].encode("utf-8")
            + b"\x00"
            + _canonical_raw(value)
        )
        value["signature"] = base64.b64encode(private_key.sign(message)).decode()
    return {"raw": _canonical_raw(value)}


def _verify_identity_and_signature_value(
    artifact_name: str, value: dict[str, Any]
) -> None:
    spec = _identity_spec(artifact_name)
    core_payload = {
        key: item
        for key, item in value.items()
        if key not in {spec["id_field"], spec["core_field"], "signature"}
    }
    expected_core = hashlib.sha256(_canonical_raw(core_payload)).hexdigest()
    if (
        value[spec["core_field"]] != expected_core
        or value[spec["id_field"]] != f"{spec['id_prefix']}{expected_core}"
    ):
        raise ValueError("CANONICALIZATION_CORE_OR_ID_MISMATCH")
    if spec["signature_domain_separator"] is None:
        return
    role_field, domain_field, key_id_field, pin_field = _signer_fields(artifact_name)
    identity = TEST_SIGNING_IDENTITIES.get(value[domain_field])
    if (
        identity is None
        or (value[role_field], value[key_id_field]) != identity
        or value["signature_algorithm"] != "Ed25519"
        or value["signature_domain_separator"]
        != spec["signature_domain_separator"]
    ):
        raise ValueError("SIGNING_DOMAIN_OR_PIN_MISMATCH")
    public_key_raw = _public_key_raw(_test_private_key(value[domain_field]))
    if value[pin_field] != hashlib.sha256(public_key_raw).hexdigest():
        raise ValueError("SIGNING_DOMAIN_OR_PIN_MISMATCH")
    try:
        signature = base64.b64decode(value["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("SIGNATURE_MESSAGE_OR_BASE64_MISMATCH") from exc
    if (
        len(signature) != 64
        or base64.b64encode(signature).decode("ascii") != value["signature"]
    ):
        raise ValueError("SIGNATURE_MESSAGE_OR_BASE64_MISMATCH")
    envelope = {key: item for key, item in value.items() if key != "signature"}
    message = (
        spec["signature_domain_separator"].encode("utf-8")
        + b"\x00"
        + _canonical_raw(envelope)
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("SIGNATURE_MESSAGE_OR_BASE64_MISMATCH") from exc


def _verify_artifact_identity_and_signature(
    artifact_name: str, artifact: dict[str, Any], value: dict[str, Any]
) -> None:
    if _canonical_raw(value) != artifact["raw"]:
        raise ValueError("CANONICALIZATION_CORE_OR_ID_MISMATCH")
    _verify_identity_and_signature_value(artifact_name, value)


def _artifact_value(artifact: dict[str, Any]) -> dict[str, Any]:
    return _strict_json_object(artifact["raw"])


def _replace_artifact_field(
    artifacts: dict[str, dict[str, Any]], artifact_name: str, field: str, value: Any
) -> None:
    parsed = _artifact_value(artifacts[artifact_name])
    parsed[field] = value
    artifacts[artifact_name]["raw"] = _canonical_raw(parsed)


def _raw_sha(artifact: dict[str, Any]) -> str:
    return hashlib.sha256(artifact["raw"]).hexdigest()


def _failed_event(
    sequence: int, artifacts: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    artifacts = artifacts or _failure_artifacts()
    event = _event()
    previous = artifacts[f"event_{sequence - 1}"]
    event.update(
        event_type="FAILED_FROZEN",
        attempt_state="FAILED_FROZEN",
        event_sequence=sequence,
        previous_event_id=_artifact_value(previous)["event_id"],
        previous_event_raw_sha256=_raw_sha(previous),
        install_manifest_raw_sha256=_raw_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_raw_sha(artifacts["preflight"]),
        fence_state_raw_sha256=_raw_sha(artifacts["state"]),
    )
    if sequence >= 3:
        event["publish_receipt_raw_sha256"] = _raw_sha(artifacts["publish"])
    if sequence >= 4:
        event["restart_authorization_raw_sha256"] = _raw_sha(
            artifacts["restart_authorization"]
        )
        event["restart_dispatch_nonce_sha256"] = SHA
        event["service_control_operation_id"] = "windows-service-restart-0001"
    if sequence >= 5:
        event["service_config_transition_receipt_raw_sha256"] = _raw_sha(
            artifacts["service_config_transition_receipt"]
        )
    if sequence >= 6:
        event["scm_dispatch_evidence_raw_sha256"] = _raw_sha(
            artifacts["scm_dispatch_evidence"]
        )
    if sequence >= 7:
        event["startup_receipt_raw_sha256"] = _raw_sha(artifacts["startup_receipt"])
    return _artifact("install_event", event)


def _verify_failure_frontier_profile(
    event_artifact: dict[str, Any], artifacts: dict[str, dict[str, Any]]
) -> None:
    contract = json.loads(CHAIN_CONTRACT_PATH.read_text(encoding="utf-8"))
    event = _artifact_value(event_artifact)
    matches = [
        profile
        for profile in contract["failure_frontier_profiles"]
        if profile["failed_event_sequence"] == event["event_sequence"]
    ]
    if len(matches) != 1:
        raise ValueError("FAILURE_FRONTIER_PROFILE_MISSING_OR_AMBIGUOUS")
    field_by_artifact = {
        "publish": "publish_receipt_raw_sha256",
        "restart_authorization": "restart_authorization_raw_sha256",
        "service_config_transition_receipt": (
            "service_config_transition_receipt_raw_sha256"
        ),
        "scm_dispatch_evidence": "scm_dispatch_evidence_raw_sha256",
        "startup_receipt": "startup_receipt_raw_sha256",
        "attestation": "foundation_attestation_raw_sha256",
    }
    for artifact, required in matches[0]["artifact_presence"].items():
        present = event[field_by_artifact[artifact]] is not None
        if present is not required:
            raise ValueError("FAILURE_FRONTIER_EVIDENCE_SPLICE")
    rule_ids = matches[0]["required_binding_rule_ids"]
    if any(
        contract["failure_frontier_binding_rules"][rule_id][
            "identity_and_signature_profile"
        ]
        != "artifact_identity_and_signature_profile"
        for rule_id in rule_ids
    ):
        raise ValueError("FAILURE_FRONTIER_IDENTITY_PROFILE_MISSING")
    Draft202012Validator(
        _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
    ).validate(event)
    present_names = {
        "preflight",
        "manifest",
        "state",
        *rule_ids[1:],
        *(f"event_{sequence}" for sequence in range(1, event["event_sequence"])),
    }
    parsed = {name: _artifact_value(artifacts[name]) for name in present_names}
    for name in present_names:
        _verify_artifact_identity_and_signature(
            "install_event" if name.startswith("event_") else name,
            artifacts[name],
            parsed[name],
        )
    _verify_artifact_identity_and_signature(
        "install_event", event_artifact, event
    )
    artifact_schemas = {
        "preflight": "windows-rpc-durable-fence-zero-order-preflight-v1.schema.json",
        "manifest": "windows-rpc-durable-fence-install-manifest-v1.schema.json",
        "state": "windows-rpc-durable-fence-state-v1.schema.json",
        "publish": "windows-rpc-durable-fence-publish-receipt-v1.schema.json",
        "restart_authorization": (
            "windows-rpc-durable-fence-restart-authorization-v1.schema.json"
        ),
        "service_config_transition_receipt": (
            "windows-rpc-durable-fence-service-config-transition-receipt-v1.schema.json"
        ),
        "scm_dispatch_evidence": (
            "windows-rpc-durable-fence-scm-dispatch-evidence-v1.schema.json"
        ),
        "startup_receipt": "windows-rpc-durable-fence-startup-receipt-v1.schema.json",
    }
    for artifact_name in {"preflight", "manifest", "state", *rule_ids[1:]}:
        Draft202012Validator(_schema(artifact_schemas[artifact_name])).validate(
            parsed[artifact_name]
        )
    if "base_event_chain" in rule_ids:
        for field, artifact_name in (
            ("install_manifest_raw_sha256", "manifest"),
            ("preflight_receipt_raw_sha256", "preflight"),
            ("fence_state_raw_sha256", "state"),
        ):
            if event[field] != _raw_sha(artifacts[artifact_name]):
                raise ValueError("FAILURE_FRONTIER_RAW_DIGEST_MISMATCH")
        for artifact_name in ("manifest", "preflight", "state"):
            artifact = parsed[artifact_name]
            if (
                artifact["install_attempt_id"] != event["install_attempt_id"]
                or artifact["service_name"] != event["service_name"]
                or artifact["store_path_sha256"] != event["store_path_sha256"]
            ):
                raise ValueError("FAILURE_FRONTIER_IDENTITY_SPLICE")
        if parsed["state"]["store_id"] != event["store_id"]:
            raise ValueError("FAILURE_FRONTIER_IDENTITY_SPLICE")
        for sequence in range(1, event["event_sequence"]):
            prefix_event = parsed[f"event_{sequence}"]
            Draft202012Validator(
                _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
            ).validate(prefix_event)
            if any(
                prefix_event[field] != event[field]
                for field in (
                    "install_attempt_id",
                    "service_name",
                    "store_id",
                    "store_path_sha256",
                    "trusted_clock_id",
                )
            ):
                raise ValueError("FAILURE_FRONTIER_IDENTITY_SPLICE")
            for field, artifact_name in (
                ("install_manifest_raw_sha256", "manifest"),
                ("preflight_receipt_raw_sha256", "preflight"),
                ("fence_state_raw_sha256", "state"),
            ):
                if prefix_event[field] != _raw_sha(artifacts[artifact_name]):
                    raise ValueError("FAILURE_FRONTIER_RAW_DIGEST_MISMATCH")
            stage_fields = {
                "publish_receipt_raw_sha256": (
                    2,
                    _raw_sha(artifacts["publish"]),
                ),
                "restart_authorization_raw_sha256": (
                    3,
                    _raw_sha(artifacts["restart_authorization"]),
                ),
                "service_config_transition_receipt_raw_sha256": (
                    4,
                    _raw_sha(artifacts["service_config_transition_receipt"]),
                ),
                "scm_dispatch_evidence_raw_sha256": (
                    5,
                    _raw_sha(artifacts["scm_dispatch_evidence"]),
                ),
                "startup_receipt_raw_sha256": (
                    6,
                    _raw_sha(artifacts["startup_receipt"]),
                ),
            }
            for field, (introduced_at, expected) in stage_fields.items():
                actual = prefix_event[field]
                if sequence >= introduced_at:
                    if actual != expected:
                        raise ValueError("FAILURE_FRONTIER_RAW_DIGEST_MISMATCH")
                elif actual is not None:
                    raise ValueError("FAILURE_FRONTIER_EVIDENCE_SPLICE")
            if sequence >= 3 and (
                prefix_event["restart_dispatch_nonce_sha256"] != SHA
                or prefix_event["service_control_operation_id"]
                != "windows-service-restart-0001"
            ):
                raise ValueError("FAILURE_FRONTIER_OPERATION_SPLICE")
            if sequence == 1:
                if (
                    prefix_event["previous_event_id"] is not None
                    or prefix_event["previous_event_raw_sha256"] is not None
                ):
                    raise ValueError("FAILURE_FRONTIER_PREDECESSOR_MISMATCH")
            else:
                prefix_predecessor_name = f"event_{sequence - 1}"
                if prefix_event["previous_event_id"] != parsed[
                    prefix_predecessor_name
                ]["event_id"] or prefix_event[
                    "previous_event_raw_sha256"
                ] != _raw_sha(artifacts[prefix_predecessor_name]):
                    raise ValueError("FAILURE_FRONTIER_PREDECESSOR_MISMATCH")
        previous_name = f"event_{event['event_sequence'] - 1}"
        if event["previous_event_id"] != parsed[previous_name]["event_id"] or event[
            "previous_event_raw_sha256"
        ] != _raw_sha(artifacts[previous_name]):
            raise ValueError("FAILURE_FRONTIER_PREDECESSOR_MISMATCH")
    binding_fields = {
        "publish": "publish_receipt_raw_sha256",
        "restart_authorization": "restart_authorization_raw_sha256",
        "service_config_transition_receipt": (
            "service_config_transition_receipt_raw_sha256"
        ),
        "scm_dispatch_evidence": "scm_dispatch_evidence_raw_sha256",
        "startup_receipt": "startup_receipt_raw_sha256",
    }
    cross_raw_references = {
        "publish": {
            "install_manifest_raw_sha256": "manifest",
            "preflight_receipt_raw_sha256": "preflight",
        },
        "restart_authorization": {
            "install_manifest_raw_sha256": "manifest",
            "preflight_receipt_raw_sha256": "preflight",
            "publish_receipt_raw_sha256": "publish",
            "install_event_head_raw_sha256": "event_2",
        },
        "service_config_transition_receipt": {
            "install_manifest_raw_sha256": "manifest",
            "preflight_receipt_raw_sha256": "preflight",
            "publish_receipt_raw_sha256": "publish",
            "restart_authorization_raw_sha256": "restart_authorization",
            "reservation_event_raw_sha256": "event_3",
        },
        "scm_dispatch_evidence": {
            "install_manifest_raw_sha256": "manifest",
            "restart_authorization_raw_sha256": "restart_authorization",
            "reservation_event_raw_sha256": "event_3",
            "service_config_transition_receipt_raw_sha256": (
                "service_config_transition_receipt"
            ),
        },
        "startup_receipt": {
            "install_manifest_raw_sha256": "manifest",
            "restart_authorization_raw_sha256": "restart_authorization",
            "service_config_transition_receipt_raw_sha256": (
                "service_config_transition_receipt"
            ),
            "scm_dispatch_evidence_raw_sha256": "scm_dispatch_evidence",
            "restart_dispatched_event_raw_sha256": "event_5",
        },
    }
    cross_id_references = {
        "service_config_transition_receipt": {
            "reservation_event_id": "event_3",
        },
        "startup_receipt": {
            "restart_dispatched_event_id": "event_5",
        },
    }
    for rule_id in rule_ids[1:]:
        artifact = parsed[rule_id]
        if event[binding_fields[rule_id]] != _raw_sha(artifacts[rule_id]):
            raise ValueError("FAILURE_FRONTIER_RAW_DIGEST_MISMATCH")
        if any(
            artifact[field] != _raw_sha(artifacts[target])
            for field, target in cross_raw_references[rule_id].items()
        ):
            raise ValueError("FAILURE_FRONTIER_RAW_DIGEST_MISMATCH")
        if any(
            artifact[field] != parsed[target]["event_id"]
            for field, target in cross_id_references.get(rule_id, {}).items()
        ):
            raise ValueError("FAILURE_FRONTIER_EVENT_ID_MISMATCH")
        if (
            artifact["install_attempt_id"] != event["install_attempt_id"]
            or artifact["service_name"] != event["service_name"]
        ):
            raise ValueError("FAILURE_FRONTIER_IDENTITY_SPLICE")
        if rule_id != "publish" and (
            artifact["service_control_operation_id"]
            != event["service_control_operation_id"]
            or artifact[
                "dispatch_nonce_sha256"
                if rule_id == "restart_authorization"
                else "restart_dispatch_nonce_sha256"
            ]
            != event["restart_dispatch_nonce_sha256"]
        ):
            raise ValueError("FAILURE_FRONTIER_OPERATION_SPLICE")

    present_roots = {
        "preflight",
        "manifest",
        "state",
        "events",
        *rule_ids[1:],
    }
    equality_fixture: dict[str, Any] = {
        name: parsed[name] for name in present_roots if name != "events"
    }
    equality_fixture["events"] = [
        parsed[f"event_{sequence}"]
        for sequence in range(1, event["event_sequence"])
    ] + [event]
    contract_equalities = {
        group["id"]: group["paths"] for group in contract["required_equalities"]
    }
    equality_group_ids = {
        group_id
        for rule_id in rule_ids
        for group_id in contract["failure_frontier_binding_rules"][rule_id][
            "equality_groups"
        ]
    }
    for group_id in equality_group_ids:
        values: list[Any] = []
        for path in contract_equalities[group_id]:
            if (
                path.split(".", maxsplit=1)[0].split("[", maxsplit=1)[0]
                not in present_roots
            ):
                continue
            try:
                values.extend(_resolve_contract_path(equality_fixture, path))
            except (IndexError, KeyError):
                continue
        if values and any(value != values[0] for value in values[1:]):
            raise ValueError(f"FAILURE_FRONTIER_EQUALITY_MISMATCH:{group_id}")


def _verify_startup_dispatch_order(receipt: dict[str, Any]) -> None:
    call_started = datetime.fromisoformat(receipt["scm_call_started_at_utc"])
    process_started = datetime.fromisoformat(receipt["service_process_started_at_utc"])
    call_returned = datetime.fromisoformat(receipt["scm_call_returned_at_utc"])
    observed = datetime.fromisoformat(receipt["observed_at_utc"])
    if not call_started < process_started <= call_returned <= observed:
        raise ValueError("PROCESS_START_NOT_AFTER_BOUND_SCM_DISPATCH")


def _verify_scm_dispatch_evidence_order(
    evidence: dict[str, Any],
    event5_observed_at_utc: str = "2026-08-05T00:00:37.100000Z",
    startup_observed_at_utc: str = "2026-08-05T00:00:37.200000Z",
) -> None:
    times = [
        datetime.fromisoformat(evidence[field])
        for field in (
            "trace_challenge_issued_at_utc",
            "stop_call_started_at_utc",
            "stop_call_returned_at_utc",
            "start_call_started_at_utc",
            "start_call_returned_at_utc",
            "trace_captured_at_utc",
            "trace_expires_at_utc",
        )
    ]
    if any(later < earlier for earlier, later in pairwise(times)):
        raise ValueError("SCM_AUDIT_TRACE_CALLER_OPERATION_OR_RESULT_MISMATCH")
    if (times[5] - times[0]).total_seconds() > evidence["maximum_trace_age_seconds"]:
        raise ValueError("SCM_AUDIT_TRACE_CALLER_OPERATION_OR_RESULT_MISMATCH")
    event5_observed = datetime.fromisoformat(event5_observed_at_utc)
    startup_observed = datetime.fromisoformat(startup_observed_at_utc)
    if not times[5] <= event5_observed <= startup_observed <= times[6]:
        raise ValueError("SCM_AUDIT_TRACE_CALLER_OPERATION_OR_RESULT_MISMATCH")


@pytest.mark.parametrize("sequence", range(2, 8))
def test_failed_frontier_profiles_accept_exact_stage_and_reject_future_evidence(
    sequence: int,
) -> None:
    schema = _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
    artifacts = _failure_artifacts()
    event_artifact = _failed_event(sequence, artifacts)
    event = _artifact_value(event_artifact)
    Draft202012Validator(schema).validate(event)
    artifact_schemas = {
        "preflight": "windows-rpc-durable-fence-zero-order-preflight-v1.schema.json",
        "manifest": "windows-rpc-durable-fence-install-manifest-v1.schema.json",
        "state": "windows-rpc-durable-fence-state-v1.schema.json",
        "publish": "windows-rpc-durable-fence-publish-receipt-v1.schema.json",
        "restart_authorization": (
            "windows-rpc-durable-fence-restart-authorization-v1.schema.json"
        ),
        "service_config_transition_receipt": (
            "windows-rpc-durable-fence-service-config-transition-receipt-v1.schema.json"
        ),
        "scm_dispatch_evidence": (
            "windows-rpc-durable-fence-scm-dispatch-evidence-v1.schema.json"
        ),
        "startup_receipt": ("windows-rpc-durable-fence-startup-receipt-v1.schema.json"),
    }
    profile = next(
        item
        for item in json.loads(CHAIN_CONTRACT_PATH.read_text(encoding="utf-8"))[
            "failure_frontier_profiles"
        ]
        if item["failed_event_sequence"] == sequence
    )
    present_artifacts = {
        "preflight",
        "manifest",
        "state",
        *profile["required_binding_rule_ids"][1:],
    }
    for artifact_name in present_artifacts:
        Draft202012Validator(_schema(artifact_schemas[artifact_name])).validate(
            _artifact_value(artifacts[artifact_name])
        )
    _verify_failure_frontier_profile(event_artifact, artifacts)

    future_field = {
        2: "publish_receipt_raw_sha256",
        3: "restart_authorization_raw_sha256",
        4: "service_config_transition_receipt_raw_sha256",
        5: "scm_dispatch_evidence_raw_sha256",
        6: "startup_receipt_raw_sha256",
        7: "foundation_attestation_raw_sha256",
    }[sequence]
    tampered = copy.deepcopy(event)
    tampered[future_field] = SHA
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(tampered)
    with pytest.raises(ValueError, match="FAILURE_FRONTIER_EVIDENCE_SPLICE"):
        _verify_failure_frontier_profile(
            _artifact("install_event", tampered), artifacts
        )

    base_identity_splice = copy.deepcopy(artifacts)
    _replace_artifact_field(
        base_identity_splice, "manifest", "service_name", "OtherService"
    )
    with pytest.raises(ValueError):
        _verify_failure_frontier_profile(event_artifact, base_identity_splice)
    if sequence >= 3:
        predecessor_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            predecessor_splice, "event_2", "previous_event_raw_sha256", OTHER_SHA
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, predecessor_splice)
        prefix_event_id_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            prefix_event_id_splice,
            "event_2",
            "event_id",
            f"windows-fence-install-event-{OTHER_SHA}",
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, prefix_event_id_splice)
        prefix_evidence_splice = copy.deepcopy(artifacts)
        prefix_field = {
            3: "publish_receipt_raw_sha256",
            4: "restart_authorization_raw_sha256",
            5: "service_config_transition_receipt_raw_sha256",
            6: "scm_dispatch_evidence_raw_sha256",
            7: "startup_receipt_raw_sha256",
        }[sequence]
        _replace_artifact_field(
            prefix_evidence_splice,
            f"event_{sequence - 1}",
            prefix_field,
            OTHER_SHA,
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, prefix_evidence_splice)

    if sequence >= 3:
        digest_splice = copy.deepcopy(event)
        digest_splice["publish_receipt_raw_sha256"] = OTHER_SHA
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(
                _artifact("install_event", digest_splice), artifacts
            )
    if sequence >= 4:
        identity_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            identity_splice,
            "restart_authorization",
            "install_attempt_id",
            f"windows-fence-install-{OTHER_SHA}",
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, identity_splice)
        cross_raw_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            cross_raw_splice,
            "restart_authorization",
            "publish_receipt_raw_sha256",
            OTHER_SHA,
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, cross_raw_splice)
        auth_manifest_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            auth_manifest_splice,
            "restart_authorization",
            "install_manifest_raw_sha256",
            OTHER_SHA,
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, auth_manifest_splice)
        operation_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            operation_splice,
            "restart_authorization",
            "service_control_operation_id",
            "windows-service-restart-9999",
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, operation_splice)
        nonce_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            nonce_splice,
            "restart_authorization",
            "dispatch_nonce_sha256",
            OTHER_SHA,
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, nonce_splice)
    if sequence >= 5:
        event_id_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            event_id_splice,
            "service_config_transition_receipt",
            "reservation_event_id",
            f"windows-fence-install-event-{OTHER_SHA}",
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, event_id_splice)

    equality_splice = copy.deepcopy(artifacts)
    equality_target = {
        2: ("manifest", "trusted_clock_id", "other-trusted-clock-0001"),
        3: ("publish", "bundle_sha256", OTHER_SHA),
        4: ("restart_authorization", "expected_host_boot_id", "other-host-boot-0001"),
        5: ("service_config_transition_receipt", "transition_plan_sha256", OTHER_SHA),
        6: ("scm_dispatch_evidence", "caller_principal_sid_sha256", OTHER_SHA),
        7: ("startup_receipt", "scm_audit_trace_raw_sha256", OTHER_SHA),
    }[sequence]
    target_artifact, target_field, target_value = equality_target
    _replace_artifact_field(
        equality_splice, target_artifact, target_field, target_value
    )
    with pytest.raises(ValueError):
        _verify_failure_frontier_profile(event_artifact, equality_splice)
    if sequence >= 7:
        event_id_splice = copy.deepcopy(artifacts)
        _replace_artifact_field(
            event_id_splice,
            "startup_receipt",
            "restart_dispatched_event_id",
            f"windows-fence-install-event-{OTHER_SHA}",
        )
        with pytest.raises(ValueError):
            _verify_failure_frontier_profile(event_artifact, event_id_splice)


def test_startup_receipt_rejects_process_started_before_exact_scm_dispatch() -> None:
    receipt = _startup_receipt()
    _verify_startup_dispatch_order(receipt)
    receipt["service_process_started_at_utc"] = "2026-08-05T00:00:34Z"
    with pytest.raises(ValueError, match="PROCESS_START_NOT_AFTER_BOUND_SCM_DISPATCH"):
        _verify_startup_dispatch_order(receipt)


def _rebind_failure_sequence_4_to_restart_authorization(
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    event_3 = _artifact_value(artifacts["event_3"])
    event_3["restart_authorization_raw_sha256"] = _raw_sha(
        artifacts["restart_authorization"]
    )
    artifacts["event_3"] = _artifact("install_event", event_3)
    return _failed_event(4, artifacts)


def test_failure_frontier_rejects_signature_core_id_and_canonical_raw_attacks() -> None:
    invalid_signature = _failure_artifacts()
    _replace_artifact_field(
        invalid_signature,
        "restart_authorization",
        "signature",
        "B" * 86 + "==",
    )
    event = _rebind_failure_sequence_4_to_restart_authorization(invalid_signature)
    with pytest.raises(ValueError, match="SIGNATURE_MESSAGE_OR_BASE64_MISMATCH"):
        _verify_failure_frontier_profile(event, invalid_signature)

    forged_core_and_id = _failure_artifacts()
    authorization = _artifact_value(forged_core_and_id["restart_authorization"])
    authorization["authorization_core_sha256"] = OTHER_SHA
    authorization["authorization_id"] = (
        f"windows-fence-restart-authorization-{OTHER_SHA}"
    )
    forged_core_and_id["restart_authorization"]["raw"] = _canonical_raw(
        authorization
    )
    event = _rebind_failure_sequence_4_to_restart_authorization(forged_core_and_id)
    with pytest.raises(ValueError, match="CANONICALIZATION_CORE_OR_ID_MISMATCH"):
        _verify_failure_frontier_profile(event, forged_core_and_id)

    noncanonical = _failure_artifacts()
    noncanonical["restart_authorization"]["raw"] = (
        b" " + noncanonical["restart_authorization"]["raw"]
    )
    event = _rebind_failure_sequence_4_to_restart_authorization(noncanonical)
    with pytest.raises(ValueError, match="CANONICALIZATION_CORE_OR_ID_MISMATCH"):
        _verify_failure_frontier_profile(event, noncanonical)


def test_strict_foundation_json_rejects_duplicate_float_nonfinite_and_non_nfc() -> None:
    raw = _failure_artifacts()["restart_authorization"]["raw"]
    variants = (
        b'{"schema_version":"duplicate",' + raw[1:],
        raw.replace(b'"maximum_restart_dispatches":1', b'"maximum_restart_dispatches":1.0'),
        raw.replace(b'"maximum_restart_dispatches":1', b'"maximum_restart_dispatches":NaN'),
        raw.replace(b"VnpyRpcService", "VnpyRpcServicee\u0301".encode()),
    )
    for variant in variants:
        with pytest.raises((TypeError, ValueError)):
            _artifact_value({"raw": variant})


def test_terminal_failed_event_requires_exact_canonical_raw() -> None:
    artifacts = _failure_artifacts()
    event_artifact = _failed_event(4, artifacts)
    duplicate = {
        "raw": b'{"event_type":"FOUNDATION_VERIFIED",'
        + event_artifact["raw"][1:]
    }
    with pytest.raises(ValueError, match="FOUNDATION_JSON_DUPLICATE_KEY"):
        _verify_failure_frontier_profile(duplicate, artifacts)

    noncanonical = {"raw": b" " + event_artifact["raw"]}
    with pytest.raises(ValueError, match="CANONICALIZATION_CORE_OR_ID_MISMATCH"):
        _verify_failure_frontier_profile(noncanonical, artifacts)


def test_scm_dispatch_evidence_rejects_spliced_caller_trace_or_time() -> None:
    schema = _schema("windows-rpc-durable-fence-scm-dispatch-evidence-v1.schema.json")
    evidence = _scm_dispatch_evidence()
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(evidence)
    _verify_scm_dispatch_evidence_order(evidence)
    for field, invalid_value in (
        ("exact_caller_and_operation_verified", False),
        ("scm_api_sequence", ["StartServiceW"]),
        ("trace_single_use", False),
    ):
        invalid = copy.deepcopy(evidence)
        invalid[field] = invalid_value
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(invalid)
    evidence["start_call_started_at_utc"] = "2026-08-05T00:00:34Z"
    with pytest.raises(
        ValueError, match="SCM_AUDIT_TRACE_CALLER_OPERATION_OR_RESULT_MISMATCH"
    ):
        _verify_scm_dispatch_evidence_order(evidence)
    evidence = _scm_dispatch_evidence()
    with pytest.raises(
        ValueError, match="SCM_AUDIT_TRACE_CALLER_OPERATION_OR_RESULT_MISMATCH"
    ):
        _verify_scm_dispatch_evidence_order(
            evidence, startup_observed_at_utc="2026-08-05T00:00:45Z"
        )


def test_install_event_type_cannot_splice_another_attempt_state() -> None:
    event = _event()
    event["attempt_state"] = "VERIFIED_FROZEN"
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
        ).validate(event)

    event = _event()
    event.update(
        event_type="RESTART_DISPATCHED",
        attempt_state="RESTART_UNKNOWN_FROZEN",
        event_sequence=2,
        previous_event_id=f"windows-fence-install-event-{OTHER_SHA}",
        previous_event_raw_sha256=OTHER_SHA,
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
        ).validate(event)


def test_restart_dispatch_reservation_consumes_nonce_before_scm_stage() -> None:
    schema = _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
    event = _event()
    event.update(
        event_type="RESTART_DISPATCH_RESERVED",
        attempt_state="RESTART_DISPATCH_RESERVED_FROZEN",
        event_sequence=3,
        previous_event_id=f"windows-fence-install-event-{OTHER_SHA}",
        previous_event_raw_sha256=OTHER_SHA,
        publish_receipt_raw_sha256=SHA,
        restart_authorization_raw_sha256=SHA,
        restart_dispatch_nonce_sha256=SHA,
        service_control_operation_id="windows-service-restart-0001",
    )
    Draft202012Validator(schema).validate(event)

    for field in ("restart_dispatch_nonce_sha256", "service_control_operation_id"):
        invalid = copy.deepcopy(event)
        invalid[field] = None
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(invalid)


def test_service_config_transition_requires_reserved_identity_and_precedes_restart() -> (
    None
):
    receipt_schema = _schema(
        "windows-rpc-durable-fence-service-config-transition-receipt-v1.schema.json"
    )
    receipt = _service_config_transition_receipt()
    Draft202012Validator(receipt_schema, format_checker=FormatChecker()).validate(
        receipt
    )
    for field, invalid_value in (
        ("reservation_event_raw_sha256", None),
        ("service_process_identity_unchanged", False),
        ("authorized_changed_fields", ["ImagePath"]),
        ("safety_transition_applied_before_target_image_path", False),
        ("target_service_start_type", "AUTO_START"),
        ("target_recovery_actions_disabled", False),
        ("restart_dispatched", True),
    ):
        invalid = copy.deepcopy(receipt)
        invalid[field] = invalid_value
        with pytest.raises(ValidationError):
            Draft202012Validator(receipt_schema).validate(invalid)

    event = _event()
    event.update(
        event_type="SERVICE_CONFIG_TRANSITION_VERIFIED",
        attempt_state="SERVICE_CONFIG_READY_FROZEN",
        event_sequence=4,
        previous_event_id=f"windows-fence-install-event-{OTHER_SHA}",
        previous_event_raw_sha256=OTHER_SHA,
        publish_receipt_raw_sha256=SHA,
        restart_authorization_raw_sha256=SHA,
        restart_dispatch_nonce_sha256=SHA,
        service_config_transition_receipt_raw_sha256=SHA,
        service_control_operation_id="windows-service-restart-0001",
    )
    event_schema = _schema("windows-rpc-durable-fence-install-event-v1.schema.json")
    Draft202012Validator(event_schema).validate(event)
    event["service_config_transition_receipt_raw_sha256"] = None
    with pytest.raises(ValidationError):
        Draft202012Validator(event_schema).validate(event)

    dispatched = _event()
    dispatched.update(
        event_type="RESTART_DISPATCHED",
        attempt_state="RESTART_UNKNOWN_FROZEN",
        event_sequence=5,
        previous_event_id=f"windows-fence-install-event-{OTHER_SHA}",
        previous_event_raw_sha256=OTHER_SHA,
        publish_receipt_raw_sha256=SHA,
        restart_authorization_raw_sha256=SHA,
        restart_dispatch_nonce_sha256=SHA,
        service_config_transition_receipt_raw_sha256=SHA,
        scm_dispatch_evidence_raw_sha256=SHA,
        service_control_operation_id="windows-service-restart-0001",
    )
    Draft202012Validator(event_schema).validate(dispatched)
    dispatched["scm_dispatch_evidence_raw_sha256"] = None
    with pytest.raises(ValidationError):
        Draft202012Validator(event_schema).validate(dispatched)


def test_cross_artifact_chain_contract_freezes_all_reviewed_rejections() -> None:
    contract = json.loads(CHAIN_CONTRACT_PATH.read_text(encoding="utf-8"))
    assert contract["schema_version"] == (
        "windows_rpc_durable_fence_foundation_chain_v1"
    )
    assert contract["status"] == (
        "wf2_bundle_and_manifest_verifier_implemented_not_signed_not_installed"
    )
    assert contract["raw_digest_algorithm"] == "sha256_of_exact_raw_bytes"
    assert contract["validation_order"] == [
        "zero_order_preflight",
        "install_manifest",
        "fence_state",
        "publish_receipt",
        "install_events_1_through_2",
        "restart_authorization",
        "install_event_3_restart_dispatch_reserved",
        "service_config_transition_receipt",
        "install_event_4_service_config_transition_verified",
        "scm_dispatch_evidence",
        "install_event_5_restart_dispatched",
        "startup_receipt",
        "install_event_6_start_observed",
        "foundation_attestation",
        "install_event_7_foundation_verified",
    ]

    equality_ids = {group["id"] for group in contract["required_equalities"]}
    assert equality_ids == {
        "one_install_attempt",
        "one_service",
        "one_store_path",
        "one_store_id",
        "one_store_volume_serial",
        "one_store_volume_identity",
        "one_attempt_nonce",
        "one_preflight_receipt_id",
        "one_manifest_id",
        "one_preflight_server_projection",
        "one_preflight_fact_generation",
        "one_preflight_execution_facts",
        "one_account",
        "one_raw_account_row",
        "one_raw_account_canonical_payload",
        "one_gateway_scope",
        "one_gateway_scope_canonical_payload",
        "one_gateway_name",
        "one_trusted_clock",
        "one_host_boot",
        "one_old_service_process_id",
        "one_old_service_process_start",
        "one_bundle",
        "one_final_version_directory",
        "one_final_owner",
        "one_final_directory_acl",
        "one_component_acl",
        "one_extension",
        "one_launcher",
        "one_assembly",
        "one_config",
        "one_extension_destination",
        "one_launcher_destination",
        "one_assembly_destination",
        "one_config_destination",
        "one_service_image_path",
        "one_preinstall_service_image_path",
        "one_service_config",
        "one_preinstall_service_config",
        "one_service_config_owner",
        "one_service_config_acl",
        "one_safety_service_config",
        "one_service_config_transition_plan",
        "one_scm_audit_trace",
        "one_scm_start_call_start",
        "one_scm_start_call_return",
        "one_scm_start_call_result",
        "one_installer_principal",
        "one_installer_process_image",
        "one_running_launcher",
        "one_loaded_extension",
        "one_effective_config",
        "one_publish_seal",
        "one_publish_seal_expiry",
        "one_new_service_process_id",
        "one_new_service_process_start",
        "one_restart_dispatch_nonce",
        "one_restart_operation",
    }
    assert all(len(group["paths"]) >= 2 for group in contract["required_equalities"])

    bindings = set(contract["required_raw_digest_bindings"])
    assert {
        "manifest.preflight_receipt_raw_sha256=sha256(preflight.raw)",
        "restart_authorization.publish_receipt_raw_sha256=sha256(publish.raw)",
        "restart_authorization.install_manifest_raw_sha256=sha256(manifest.raw)",
        "restart_authorization.preflight_receipt_raw_sha256=sha256(preflight.raw)",
        "restart_authorization.install_event_head_raw_sha256=sha256(events[1].raw)",
        "attestation.install_manifest_raw_sha256=sha256(manifest.raw)",
        "attestation.preflight_receipt_raw_sha256=sha256(preflight.raw)",
        "attestation.fence_state_raw_sha256=sha256(state.raw)",
        "attestation.publish_receipt_raw_sha256=sha256(publish.raw)",
        "service_config_transition_receipt.reservation_event_raw_sha256=sha256(events[2].raw)",
        "events[4..6].scm_dispatch_evidence_raw_sha256=sha256(scm_dispatch_evidence.raw)",
        "attestation.service_config_transition_receipt_raw_sha256=sha256(service_config_transition_receipt.raw)",
        "attestation.start_observed_event_raw_sha256=sha256(events[5].raw)",
        "attestation.startup_receipt_raw_sha256=sha256(startup_receipt.raw)=events[5].startup_receipt_raw_sha256",
        "events[6].foundation_attestation_raw_sha256=sha256(attestation.raw)",
    } <= bindings
    assert (
        contract["normal_closure_profile"]["required_equalities_scope"]
        == "this_normal_closure_profile_only"
    )
    failure_profiles = contract["failure_frontier_profiles"]
    assert [item["failed_event_sequence"] for item in failure_profiles] == list(
        range(2, 8)
    )
    assert all(
        item["artifact_presence"]["attestation"] is False for item in failure_profiles
    )
    expected_failure_rules = [
        "base_event_chain",
        "publish",
        "restart_authorization",
        "service_config_transition_receipt",
        "scm_dispatch_evidence",
        "startup_receipt",
    ]
    assert [item["required_binding_rule_ids"] for item in failure_profiles] == [
        expected_failure_rules[:index] for index in range(1, 7)
    ]
    assert set(contract["failure_frontier_binding_rules"]) == set(
        expected_failure_rules
    )
    for rule in contract["failure_frontier_binding_rules"].values():
        assert set(rule) == {
            "identity_and_signature_profile",
            "raw_digest_bindings",
            "equality_groups",
        }
        assert (
            rule["identity_and_signature_profile"]
            == "artifact_identity_and_signature_profile"
        )
        assert rule["raw_digest_bindings"]
        assert set(rule["equality_groups"]) <= equality_ids
    assert "terminal_FAILED_FROZEN_event" in contract[
        "failure_frontier_identity_and_signature_scope"
    ]

    assert len(contract["time_and_freshness_rules"]) == 12
    assert len(contract["identity_transition_rules"]) == 9
    assert len(contract["publish_immutability_rules"]) == 15
    assert len(contract["canonical_payload_digest_rules"]) == 6
    attempt_identity = contract["deterministic_install_attempt_identity"]
    assert attempt_identity["domain_separator"] == ATTEMPT_DOMAIN
    assert set(attempt_identity["input_object"]) == set(ATTEMPT_INPUT)
    assert attempt_identity["same_inputs_same_id_required"] is True
    event_chain = contract["event_chain"]
    assert event_chain["normal_types"] == [
        "INSTALL_PREPARED",
        "FILES_PUBLISHED",
        "RESTART_DISPATCH_RESERVED",
        "SERVICE_CONFIG_TRANSITION_VERIFIED",
        "RESTART_DISPATCHED",
        "START_OBSERVED",
        "FOUNDATION_VERIFIED",
    ]
    assert event_chain["sequences"] == [1, 2, 3, 4, 5, 6, 7]
    assert event_chain["restart_dispatch_count"] == 1
    assert event_chain["restart_dispatch_nonce_consumed_once"] is True
    assert event_chain["restart_dispatch_reservation_event_sequence"] == 3
    assert event_chain["service_config_transition_event_sequence"] == 4
    assert "before_any_SCM_call" in event_chain["reservation_publish_rule"]
    assert (
        "never_call_SCM_restart_again"
        in (event_chain["head_at_or_after_reservation_recovery"])
    )
    assert event_chain["foundation_verified_is_terminal"] is True
    assert event_chain["failed_frozen_is_terminal"] is True

    domains = contract["signing_domains"]
    named_domains = [
        domains[name]
        for name in (
            "manifest",
            "observer_evidence",
            "restart_authorization",
        )
    ]
    assert len(set(named_domains)) == len(named_domains)
    assert domains["manifest"] == "dedicated-windows-foundation-manifest-signing-v1"
    assert domains["observer_evidence"] == (
        "dedicated-windows-foundation-observer-evidence-v1"
    )
    assert domains["restart_authorization"] == (
        "dedicated-windows-foundation-restart-authorization-v1"
    )
    assert domains["publish_receipt_signer"] == "observer_evidence"
    assert domains["private_key_domains_pairwise_distinct"] is True
    assert domains["target_runtime_private_keys_allowed"] is False

    profile = contract["artifact_identity_and_signature_profile"]
    assert profile["canonicalization_profile"] == (
        "windows-foundation-canonical-json-v1"
    )
    assert "RFC8785_JCS_UTF8" in profile["canonicalization_definition"]
    assert "excluding_signature_only" in profile["signed_envelope_definition"]
    assert "0x00" in profile["signature_message_definition"]
    assert len(profile["artifacts"]) == 10
    assert {
        item["name"]
        for item in profile["artifacts"]
        if item["signature_domain_separator"] is not None
    } == {
        "preflight",
        "manifest",
        "publish",
        "restart_authorization",
        "scm_dispatch_evidence",
        "startup_receipt",
        "attestation",
    }

    rejection_codes = set(contract["mandatory_rejection_codes"])
    assert {
        "RAW_DIGEST_MISMATCH",
        "INSTALL_ATTEMPT_MISMATCH",
        "PREFLIGHT_STALE_REPLAYED_OR_TIME_REVERSED",
        "RESTART_AUTHORIZATION_EXPIRED_EARLY_REPLAYED_OR_CONSUMED",
        "EVENT_SEQUENCE_GAP_FORK_REORDER_REPEAT_OR_TERMINAL_SUCCESSOR",
        "CANONICALIZATION_CORE_OR_ID_MISMATCH",
        "SIGNATURE_MESSAGE_OR_BASE64_MISMATCH",
        "PUBLISH_SEAL_EXPIRED_OR_POST_SEAL_DRIFT",
        "OLD_SERVICE_IDENTITY_MISMATCH_OR_NEW_IDENTITY_NOT_OBSERVED",
        "DETERMINISTIC_ATTEMPT_ID_MISMATCH",
        "STORE_VOLUME_IDENTITY_MISMATCH",
        "PREFLIGHT_STATE_PROJECTION_MISMATCH",
        "CANONICAL_PAYLOAD_DIGEST_MISMATCH",
        "UNAUTHORIZED_SERVICE_CONFIG_TRANSITION",
        "SERVICE_CONFIG_TRANSITION_BEFORE_RESERVATION_OR_RECEIPT_MISMATCH",
        "UNSAFE_AUTO_START_OR_RECOVERY_POLICY",
        "PROCESS_START_NOT_AFTER_BOUND_SCM_DISPATCH",
        "SCM_AUDIT_TRACE_CALLER_OPERATION_OR_RESULT_MISMATCH",
        "FAILURE_FRONTIER_EVIDENCE_SPLICE",
        "FAILURE_FRONTIER_RAW_DIGEST_OR_IDENTITY_MISMATCH",
        "FINAL_REGISTRY_HANDLER_IDENTITY_MISMATCH",
        "UNDERLYING_GATEWAY_CALL_OBSERVED",
        "LIVE_MUTATION_RPC_PROBE_FORBIDDEN",
    } <= rejection_codes
    assert contract["implementation_requirement"].startswith(
        "WF-2_through_WF-5_verifiers_must_reject_every_listed_mismatch"
    )
    assert all(value is False for value in contract["authority"].values())


def _cross_artifact_fixture() -> dict[str, Any]:
    events = []
    for index in range(7):
        event = _event()
        if index >= 1:
            event["publish_receipt_raw_sha256"] = SHA
        if index >= 2:
            event["restart_authorization_raw_sha256"] = SHA
            event["restart_dispatch_nonce_sha256"] = SHA
            event["service_control_operation_id"] = "windows-service-restart-0001"
        if index >= 3:
            event["service_config_transition_receipt_raw_sha256"] = SHA
        if index >= 4:
            event["scm_dispatch_evidence_raw_sha256"] = SHA
        if index >= 5:
            event["startup_receipt_raw_sha256"] = SHA
        if index == 6:
            event["foundation_attestation_raw_sha256"] = SHA
        events.append(event)
    return {
        "preflight": _preflight(),
        "manifest": _manifest(),
        "state": _state(),
        "publish": _publish_receipt(),
        "events": events,
        "restart_authorization": _restart_authorization(),
        "service_config_transition_receipt": _service_config_transition_receipt(),
        "scm_dispatch_evidence": _scm_dispatch_evidence(),
        "startup_receipt": _startup_receipt(),
        "attestation": _attestation(),
    }


def _resolve_contract_path(fixture: dict[str, Any], path: str) -> list[Any]:
    values: list[Any] = [fixture]
    for segment in path.split("."):
        next_values: list[Any] = []
        if "[" in segment:
            name, selector = segment[:-1].split("[", maxsplit=1)
            for value in values:
                collection = value[name]
                if selector == "*":
                    next_values.extend(collection)
                else:
                    next_values.append(collection[int(selector)])
        else:
            next_values.extend(value[segment] for value in values)
        values = next_values
    return values


def _verify_contract_equalities(fixture: dict[str, Any]) -> None:
    contract = json.loads(CHAIN_CONTRACT_PATH.read_text(encoding="utf-8"))
    for group in contract["required_equalities"]:
        values = [
            item
            for path in group["paths"]
            for item in _resolve_contract_path(fixture, path)
        ]
        if any(value != values[0] for value in values[1:]):
            raise ValueError(group["id"])


def _verify_canonical_payload_digests(fixture: dict[str, Any]) -> None:
    for payload_field, digest_field in (
        ("raw_account_row_canonical_json_base64", "raw_account_row_sha256"),
        ("gateway_scope_canonical_json_base64", "gateway_scope_sha256"),
    ):
        for artifact_name in ("preflight", "attestation"):
            artifact = fixture[artifact_name]
            raw = base64.b64decode(artifact[payload_field], validate=True)
            parsed = json.loads(raw)
            canonical = json.dumps(
                parsed, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            if (
                canonical != raw
                or hashlib.sha256(raw).hexdigest() != artifact[digest_field]
            ):
                raise ValueError("CANONICAL_PAYLOAD_DIGEST_MISMATCH")


def _verify_deterministic_attempt_identity(fixture: dict[str, Any]) -> None:
    contract = json.loads(CHAIN_CONTRACT_PATH.read_text(encoding="utf-8"))
    identity = contract["deterministic_install_attempt_identity"]
    inputs = {}
    for name, source in identity["input_object"].items():
        if "const" in source:
            inputs[name] = source["const"]
        else:
            values = _resolve_contract_path(fixture, source["path"])
            assert len(values) == 1
            inputs[name] = values[0]
    digest = hashlib.sha256(
        identity["domain_separator"].encode("utf-8")
        + b"\x00"
        + json.dumps(
            inputs, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    ).hexdigest()
    if fixture["preflight"]["install_attempt_id"] != f"windows-fence-install-{digest}":
        raise ValueError("DETERMINISTIC_ATTEMPT_ID_MISMATCH")


@pytest.mark.parametrize(
    ("mutation", "rejection_group"),
    [
        (("state", "store_id"), "one_store_id"),
        (
            ("attestation", "store_volume_identity_sha256"),
            "one_store_volume_identity",
        ),
        (
            ("state", "preflight_execution_facts_sha256"),
            "one_preflight_execution_facts",
        ),
        (("attestation", "host_boot_id"), "one_host_boot"),
        (("scm_dispatch_evidence", "trusted_clock_id"), "one_trusted_clock"),
        (
            ("attestation", "raw_account_row_canonical_json_base64"),
            "one_raw_account_canonical_payload",
        ),
        (
            ("publish", "components", "extension", "acl_readback_sddl_sha256"),
            "one_component_acl",
        ),
        (
            ("restart_authorization", "expected_service_process_id"),
            "one_old_service_process_id",
        ),
        (
            (
                "service_config_transition_receipt",
                "target_service_config_readback_sha256",
            ),
            "one_service_config",
        ),
    ],
)
def test_cross_artifact_equality_mutations_are_machine_rejected(
    mutation: tuple[str, ...], rejection_group: str
) -> None:
    fixture = _cross_artifact_fixture()
    _verify_contract_equalities(fixture)
    target: dict[str, Any] = fixture
    for segment in mutation[:-1]:
        target = target[segment]
    if mutation[-1] == "store_id":
        target[mutation[-1]] = f"windows-fence-store-{OTHER_SHA}"
    elif mutation[-1] == "expected_service_process_id":
        target[mutation[-1]] = 4321
    else:
        target[mutation[-1]] = OTHER_SHA
    with pytest.raises(ValueError, match=rejection_group):
        _verify_contract_equalities(fixture)


def test_canonical_payload_digest_and_attempt_derivation_are_machine_rejected() -> None:
    fixture = _cross_artifact_fixture()
    _verify_contract_equalities(fixture)
    _verify_canonical_payload_digests(fixture)
    _verify_deterministic_attempt_identity(fixture)

    wrong_payload_digest = copy.deepcopy(fixture)
    for artifact_name in ("preflight", "state", "attestation"):
        wrong_payload_digest[artifact_name]["raw_account_row_sha256"] = OTHER_SHA
    _verify_contract_equalities(wrong_payload_digest)
    with pytest.raises(ValueError, match="CANONICAL_PAYLOAD_DIGEST_MISMATCH"):
        _verify_canonical_payload_digests(wrong_payload_digest)

    wrong_attempt = copy.deepcopy(fixture)
    wrong_id = f"windows-fence-install-{OTHER_SHA}"
    for artifact_name in (
        "preflight",
        "manifest",
        "state",
        "publish",
        "restart_authorization",
        "service_config_transition_receipt",
        "scm_dispatch_evidence",
        "startup_receipt",
        "attestation",
    ):
        wrong_attempt[artifact_name]["install_attempt_id"] = wrong_id
    for event in wrong_attempt["events"]:
        event["install_attempt_id"] = wrong_id
    _verify_contract_equalities(wrong_attempt)
    with pytest.raises(ValueError, match="DETERMINISTIC_ATTEMPT_ID_MISMATCH"):
        _verify_deterministic_attempt_identity(wrong_attempt)
