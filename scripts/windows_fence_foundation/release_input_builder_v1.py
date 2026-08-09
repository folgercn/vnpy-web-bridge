"""Pure release-input to deterministic unsigned manifest builder (offline only)."""

from __future__ import annotations

import base64
import hashlib
import subprocess
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .bundle_v1 import build_windows_fence_bundle_v1, verify_windows_fence_bundle_v1
from .contracts import AUTHORITY_FIELDS, canonical_json_bytes
from .manifest_v1 import (
    MANIFEST_ID_PREFIX,
    derive_install_attempt_id_v1,
    parse_install_manifest_candidate_v1,
)
from .offline_signing_v1 import OfflineSigningError, require_fresh_zero_preflight_v1
from .target_contract_v1 import (
    derive_windows_foundation_target_v1,
    parse_windows_foundation_target_policy_v1,
)
from .trust_pins_v1 import WindowsFoundationTrustPinsV1

PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(item) for item in value]
    return value


def _require_clean_approved_worktree(source_root: Path, approved: str) -> None:
    try:
        top = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        head = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            [
                "git",
                "-C",
                str(source_root),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        superproject = subprocess.run(
            [
                "git",
                "-C",
                str(source_root),
                "rev-parse",
                "--show-superproject-working-tree",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise OfflineSigningError("RELEASE_SOURCE_WORKTREE_REQUIRED") from exc
    if Path(top).resolve() != source_root.resolve() or superproject:
        raise OfflineSigningError("RELEASE_SOURCE_WORKTREE_REQUIRED")
    if head != approved or status:
        raise OfflineSigningError("RELEASE_SOURCE_REVISION_OR_CLEANLINESS_INVALID")


def build_release_input_manifest_v1(
    source_root: Path,
    *,
    release_input: Mapping[str, Any],
    pins: WindowsFoundationTrustPinsV1,
    now: datetime,
) -> tuple[bytes, bytes, bytes]:
    """Build exact bundle/index and a complete unsigned manifest from fixed inputs."""
    required = {
        "approved_source_sha256",
        "config_raw",
        "store_binding",
        "keyring_raw",
        "keyring_path",
        "target_policy",
        "preinstall_image_path",
        "preinstall_python_class",
        "preinstall_python_path",
        "preinstall_start_type",
        "preinstall_failure_actions",
        "preinstall_recovery_actions",
        "attempt_nonce_sha256",
        "issued_at_utc",
        "expires_at_utc",
        "trusted_clock_id",
        "preflight_raw",
    }
    if (
        set(release_input) != required
        or not isinstance(release_input["approved_source_sha256"], str)
        or len(release_input["approved_source_sha256"]) != 40
    ):
        raise OfflineSigningError("RELEASE_INPUT_FIELDS_INVALID")
    _require_clean_approved_worktree(
        source_root, release_input["approved_source_sha256"]
    )
    preflight = require_fresh_zero_preflight_v1(
        release_input["preflight_raw"], pin=pins.observer, now=now
    )
    bundle = build_windows_fence_bundle_v1(
        source_root,
        config_raw=release_input["config_raw"],
        expected_store_binding=release_input["store_binding"],
        public_keyring_raw=release_input["keyring_raw"],
        keyring_canonical_path=Path(release_input["keyring_path"]),
        expected_source_sha256=release_input["approved_source_sha256"],
    )
    verified = verify_windows_fence_bundle_v1(
        bundle.bundle_raw,
        bundle.index_raw,
        expected_store_binding=release_input["store_binding"],
    )
    policy = parse_windows_foundation_target_policy_v1(release_input["target_policy"])
    target = derive_windows_foundation_target_v1(
        policy=policy,
        bundle_sha256=verified.bundle_sha256,
        wrapper_sha256=verified.component_sha256s["wrapper"],
        extension_sha256=verified.component_sha256s["extension"],
        launcher_sha256=verified.component_sha256s["launcher"],
        assembly_sha256=verified.component_sha256s["assembly"],
        config_sha256=verified.component_sha256s["config"],
        preinstall_image_path=release_input["preinstall_image_path"],
        preinstall_python_class=release_input["preinstall_python_class"],
        preinstall_python_path=release_input["preinstall_python_path"],
        preinstall_start_type=release_input["preinstall_start_type"],
        preinstall_failure_actions=release_input["preinstall_failure_actions"],
        preinstall_recovery_actions=release_input["preinstall_recovery_actions"],
    )
    attempt_inputs = {
        "attempt_nonce_sha256": release_input["attempt_nonce_sha256"],
        "bundle_sha256": verified.bundle_sha256,
        "service_name": policy.service_name,
        "store_path_sha256": target.manifest_bindings["store_path_sha256"],
        "store_volume_serial": policy.store_volume_serial,
        "store_volume_identity_sha256": policy.store_volume_identity_sha256,
        "expected_account_sha256": preflight.value["expected_account_sha256"],
        "gateway_name": preflight.value["gateway_name"],
        "gateway_scope_sha256": preflight.value["gateway_scope_sha256"],
    }
    attempt_id, _immutable = derive_install_attempt_id_v1(attempt_inputs)
    draft: dict[str, Any] = {
        **_thaw(target.manifest_bindings),
        "schema_version": "windows_rpc_durable_fence_install_manifest_v1",
        "purpose": "authorize_exact_windows_fence_files_and_one_post_reservation_service_config_transition_without_restart",
        "install_attempt_id": attempt_id,
        "attempt_nonce_sha256": release_input["attempt_nonce_sha256"],
        "expected_account_sha256": preflight.value["expected_account_sha256"],
        "gateway_name": preflight.value["gateway_name"],
        "gateway_scope_sha256": preflight.value["gateway_scope_sha256"],
        "issued_at_utc": release_input["issued_at_utc"],
        "expires_at_utc": release_input["expires_at_utc"],
        "trusted_clock_id": release_input["trusted_clock_id"],
        "preflight_receipt_id": preflight.value["receipt_id"],
        "preflight_receipt_raw_sha256": preflight.raw_sha256,
        "install_authorized": True,
        "restart_authorized": False,
        "automatic_restart_allowed": False,
        "authority": {field: False for field in AUTHORITY_FIELDS},
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": "vnpy.issue267.windows-foundation.install-manifest.v1",
        "signature_algorithm": "Ed25519",
        "signer_role": pins.manifest.role,
        "signer_key_domain": pins.manifest.key_domain,
        "signer_key_id": pins.manifest.key_id,
        "signer_public_key_sha256": pins.manifest.public_key_sha256,
    }
    core = hashlib.sha256(canonical_json_bytes(draft)).hexdigest()
    draft["manifest_core_sha256"] = core
    draft["manifest_id"] = MANIFEST_ID_PREFIX + core
    parse_install_manifest_candidate_v1(
        canonical_json_bytes({**draft, "signature": PLACEHOLDER_SIGNATURE})
    )
    return bundle.bundle_raw, bundle.index_raw, canonical_json_bytes(draft)
