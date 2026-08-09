"""Sealed Windows final-installer bootstrap.

The command line deliberately carries only bundle, manifest, and nonce-root
paths. It never accepts a keyring, expected hash, target projection,
expected-bindings JSON, service configuration, authority, credentials, or a
private key.
"""

from __future__ import annotations

import argparse
import os
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bundle_v1 import COMPONENT_PATHS, verify_windows_fence_bundle_v1
from .installer_windows_v1 import FinalWindowsFenceInstallerV1, InstallResultV1
from .installer_trust_anchor_v1 import (
    KEYRING_PURPOSE,
    KEYRING_SCHEMA_VERSION,
    canonical_public_keyring_v1,
    load_production_installer_trust_anchor_v1,
    validate_anchor_keyring_bytes_v1,
)
from .manifest_v1 import (
    WindowsInstallAttemptNonceRegistryV1,
    parse_install_manifest_candidate_v1,
    verify_and_reserve_install_manifest_v1,
    verify_install_manifest_v1,
)
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1
from .target_contract_v1 import (
    derive_windows_foundation_target_v1,
    parse_windows_foundation_target_policy_v1,
)
from .trust_pins_v1 import WindowsFoundationTrustPinsV1
from .win32_fs import WindowsFilesystemFactsAdapter


class WindowsFinalInstallerBootstrapError(RuntimeError):
    """Stable fail-closed bootstrap error."""


def _canonical_keyring(
    raw: bytes, expected_raw_sha256: str
) -> WindowsFoundationTrustPinsV1:
    try:
        return canonical_public_keyring_v1(raw, expected_raw_sha256)
    except Exception as exc:
        raise WindowsFinalInstallerBootstrapError(str(exc)) from exc


def _manifest_bindings_from_native_facts(
    candidate: Mapping[str, Any],
    *,
    bundle: Any,
    host: NativeWindowsFenceInstallerHostV1,
) -> Any:
    try:
        policy = parse_windows_foundation_target_policy_v1(candidate["target_policy"])
        pre = host.query_scm_readback(policy.service_name)
        return derive_windows_foundation_target_v1(
            policy=policy,
            bundle_sha256=bundle.bundle_sha256,
            wrapper_sha256=bundle.component_sha256s["wrapper"],
            extension_sha256=bundle.component_sha256s["extension"],
            launcher_sha256=bundle.component_sha256s["launcher"],
            assembly_sha256=bundle.component_sha256s["assembly"],
            config_sha256=bundle.component_sha256s["config"],
            preinstall_image_path=pre.image_path,
            preinstall_python_class=pre.python_class,
            preinstall_python_path=pre.python_path,
            preinstall_start_type=pre.start_type,
            preinstall_failure_actions=list(pre.failure_actions),
            preinstall_recovery_actions=list(pre.recovery_actions),
        )
    except Exception as exc:
        raise WindowsFinalInstallerBootstrapError(
            "NATIVE_PREINSTALL_FACTS_INVALID"
        ) from exc


def run_sealed_final_windows_installer_v1(
    *,
    bundle_path: Path,
    manifest_path: Path,
    nonce_registry_root: Path,
    dry_run: bool,
) -> InstallResultV1 | str:
    """The sole native installation entry; all trust inputs stay internal."""
    if os.name != "nt":
        raise WindowsFinalInstallerBootstrapError(
            "WINDOWS_INSTALLER_BOOTSTRAP_REQUIRED"
        )
    anchor = load_production_installer_trust_anchor_v1()
    try:
        bundle_raw = bundle_path.read_bytes()
        manifest_raw = manifest_path.read_bytes()
        keyring_raw = anchor.keyring_path.read_bytes()
        index_raw = bundle_path.with_suffix(
            bundle_path.suffix + ".index.json"
        ).read_bytes()
    except OSError as exc:
        raise WindowsFinalInstallerBootstrapError(
            "BOOTSTRAP_INPUT_READ_FAILED"
        ) from exc
    try:
        validate_anchor_keyring_bytes_v1(anchor, keyring_raw)
        pins = _canonical_keyring(keyring_raw, anchor.keyring_raw_sha256)
    except Exception as exc:
        raise WindowsFinalInstallerBootstrapError(
            "INSTALLER_TRUST_KEYRING_MISMATCH"
        ) from exc
    if (
        pins.manifest != anchor.manifest
        or pins.observer != anchor.observer
        or pins.restart != anchor.restart
    ):
        raise WindowsFinalInstallerBootstrapError("INSTALLER_TRUST_ANCHOR_PIN_MISMATCH")
    candidate = parse_install_manifest_candidate_v1(manifest_raw)
    store_binding = {
        key: candidate[key]
        for key in (
            "service_name",
            "store_path_sha256",
            "store_volume_serial",
            "store_volume_identity_sha256",
            "store_owner_sid_sha256",
            "store_directory_acl_sddl_sha256",
            "store_state_acl_sddl_sha256",
        )
    }
    bundle = verify_windows_fence_bundle_v1(
        bundle_raw, index_raw, expected_store_binding=store_binding
    )
    if bundle.expected_source_sha256 != anchor.expected_source_sha256:
        raise WindowsFinalInstallerBootstrapError("INSTALLER_TRUST_SOURCE_REVISION_MISMATCH")
    if candidate["bundle_sha256"] != bundle.bundle_sha256:
        raise WindowsFinalInstallerBootstrapError("BUNDLE_MANIFEST_SHA_MISMATCH")
    host = NativeWindowsFenceInstallerHostV1()
    projection = _manifest_bindings_from_native_facts(
        candidate, bundle=bundle, host=host
    )
    attempt_inputs = {
        key: candidate[key]
        for key in (
            "attempt_nonce_sha256",
            "bundle_sha256",
            "service_name",
            "store_path_sha256",
            "store_volume_serial",
            "store_volume_identity_sha256",
            "expected_account_sha256",
            "gateway_name",
            "gateway_scope_sha256",
        )
    }
    kwargs = {
        "raw": manifest_raw,
        "trust_pins": pins,
        "expected_bindings": projection.manifest_bindings,
        "install_attempt_inputs": attempt_inputs,
        "now": datetime.now(timezone.utc),
    }
    if not dry_run:
        manifest = verify_and_reserve_install_manifest_v1(
            **kwargs,
            nonce_registry=WindowsInstallAttemptNonceRegistryV1(
                nonce_registry_root,
                filesystem=WindowsFilesystemFactsAdapter(),
                expected_root_facts=pins.nonce_registry_root_facts,
                owner_sid=pins.nonce_registry_owner_sid,
                acl_sddl=pins.nonce_registry_acl_sddl,
            ),
        )
    else:
        manifest = verify_install_manifest_v1(**kwargs)
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(bundle_raw)) as archive:
            public_config_raw = archive.read(COMPONENT_PATHS["config"])
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise WindowsFinalInstallerBootstrapError(
            "BUNDLE_PUBLIC_CONFIG_READ_FAILED"
        ) from exc
    if not host.is_real_windows_host:
        raise WindowsFinalInstallerBootstrapError("WINDOWS_INSTALLER_BOOTSTRAP_REQUIRED")
    if dry_run:
        # Native facts above already performed the query-only host preflight.
        return "WINDOWS_INSTALLER_NATIVE_PREFLIGHT_OK"
    installer = FinalWindowsFenceInstallerV1(
        host=host,
        manifest=manifest,
        bundle=bundle,
        target_projection=projection,
        public_config_raw=public_config_raw,
    )
    installer.stage_and_publish(bundle_raw=bundle_raw)
    return installer.reserve_event3_and_apply_target()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="windows-final-installer-bootstrap-v1")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--nonce-registry-root", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    options = parser.parse_args(argv)
    result = run_sealed_final_windows_installer_v1(
        bundle_path=options.bundle,
        manifest_path=options.manifest,
        nonce_registry_root=options.nonce_registry_root,
        dry_run=options.dry_run,
    )
    print(result)
    return 0


__all__ = [
    "KEYRING_PURPOSE",
    "KEYRING_SCHEMA_VERSION",
    "WindowsFinalInstallerBootstrapError",
    "main",
    "run_sealed_final_windows_installer_v1",
]


if __name__ == "__main__":  # pragma: no cover - Windows CI invokes this entry.
    raise SystemExit(main())
