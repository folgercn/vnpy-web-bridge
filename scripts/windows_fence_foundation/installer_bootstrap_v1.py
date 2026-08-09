"""Sealed Windows final-installer bootstrap.

The command line deliberately carries paths plus immutable raw digests only.
It never accepts an unsigned target projection, expected-bindings JSON, service
configuration, authority, credentials, or a private key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bundle_v1 import COMPONENT_PATHS, verify_windows_fence_bundle_v1
from .contracts import canonical_json_bytes
from .installer_entry_v1 import (
    VerifiedFinalInstallerInputsV1,
    run_installed_final_windows_installer_entry_v1,
)
from .manifest_v1 import (
    FilesystemInstallAttemptNonceRegistryV1,
    parse_install_manifest_candidate_v1,
    verify_and_reserve_install_manifest_v1,
    verify_install_manifest_v1,
)
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1
from .target_contract_v1 import (
    derive_windows_foundation_target_v1,
    parse_windows_foundation_target_policy_v1,
)
from .trust_pins_v1 import FoundationPublicKeyPin, WindowsFoundationTrustPinsV1
from .win32_fs import PathSecurityFacts, WindowsFilesystemFactsAdapter

KEYRING_SCHEMA_VERSION = "windows_rpc_durable_fence_trust_keyring_v1"
KEYRING_PURPOSE = "pin_windows_fence_public_verification_keys_and_nonce_root"
_KEYRING_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "manifest",
        "observer",
        "restart",
        "nonce_registry_root_facts",
    }
)
_PIN_FIELDS = frozenset(
    {"key_domain", "role", "key_id", "public_key_b64", "public_key_sha256"}
)
_FACT_FIELDS = frozenset(PathSecurityFacts.__dataclass_fields__)


class WindowsFinalInstallerBootstrapError(RuntimeError):
    """Stable fail-closed bootstrap error."""


def _read_exact(path: Path, expected_sha256: str, code: str) -> bytes:
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise WindowsFinalInstallerBootstrapError(f"{code}_EXPECTED_SHA_INVALID")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WindowsFinalInstallerBootstrapError(f"{code}_READ_FAILED") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise WindowsFinalInstallerBootstrapError(f"{code}_SHA_MISMATCH")
    return raw


def _canonical_keyring(
    raw: bytes, expected_raw_sha256: str
) -> WindowsFoundationTrustPinsV1:
    if hashlib.sha256(raw).hexdigest() != expected_raw_sha256:
        raise WindowsFinalInstallerBootstrapError("KEYRING_RAW_SHA_MISMATCH")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WindowsFinalInstallerBootstrapError("KEYRING_JSON_INVALID") from exc
    if (
        not isinstance(value, dict)
        or canonical_json_bytes(value) != raw
        or set(value) != _KEYRING_FIELDS
    ):
        raise WindowsFinalInstallerBootstrapError("KEYRING_NOT_CANONICAL")
    if (
        value["schema_version"] != KEYRING_SCHEMA_VERSION
        or value["purpose"] != KEYRING_PURPOSE
    ):
        raise WindowsFinalInstallerBootstrapError("KEYRING_CONSTANT_MISMATCH")

    def pin(name: str) -> FoundationPublicKeyPin:
        item = value[name]
        if not isinstance(item, dict) or set(item) != _PIN_FIELDS:
            raise WindowsFinalInstallerBootstrapError("KEYRING_PIN_FIELDS_INVALID")
        try:
            raw_key = base64.b64decode(item["public_key_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise WindowsFinalInstallerBootstrapError(
                "KEYRING_PIN_ENCODING_INVALID"
            ) from exc
        return FoundationPublicKeyPin(
            key_domain=item["key_domain"],
            role=item["role"],
            key_id=item["key_id"],
            public_key_raw=raw_key,
            public_key_sha256=item["public_key_sha256"],
        )

    facts = value["nonce_registry_root_facts"]
    if not isinstance(facts, dict) or set(facts) != _FACT_FIELDS:
        raise WindowsFinalInstallerBootstrapError("KEYRING_NONCE_FACTS_INVALID")
    try:
        nonce_facts = PathSecurityFacts(
            **{
                key: tuple(item)
                if key in {"unsafe_write_principals", "write_principal_sid_sha256s"}
                else item
                for key, item in facts.items()
            }
        )
        return WindowsFoundationTrustPinsV1(
            manifest=pin("manifest"),
            observer=pin("observer"),
            restart=pin("restart"),
            nonce_registry_root_facts=nonce_facts,
        )
    except Exception as exc:  # trust dataclasses intentionally expose only stable codes
        raise WindowsFinalInstallerBootstrapError("KEYRING_TRUST_PINS_INVALID") from exc


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


def build_verified_final_installer_inputs_v1(
    *,
    bundle_path: Path,
    manifest_path: Path,
    keyring_path: Path,
    expected_source_sha256: str,
    keyring_raw_sha256: str,
    nonce_registry_root: Path,
    reserve_nonce: bool,
) -> VerifiedFinalInstallerInputsV1:
    """Build sealed inputs from signed bytes and host-captured preinstall facts."""
    if os.name != "nt":
        raise WindowsFinalInstallerBootstrapError(
            "WINDOWS_INSTALLER_BOOTSTRAP_REQUIRED"
        )
    bundle_raw = _read_exact(bundle_path, expected_source_sha256, "BUNDLE_SOURCE")
    try:
        manifest_raw = manifest_path.read_bytes()
        keyring_raw = keyring_path.read_bytes()
        index_raw = bundle_path.with_suffix(
            bundle_path.suffix + ".index.json"
        ).read_bytes()
    except OSError as exc:
        raise WindowsFinalInstallerBootstrapError(
            "BOOTSTRAP_INPUT_READ_FAILED"
        ) from exc
    pins = _canonical_keyring(keyring_raw, keyring_raw_sha256)
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
    if reserve_nonce:
        manifest = verify_and_reserve_install_manifest_v1(
            **kwargs,
            nonce_registry=FilesystemInstallAttemptNonceRegistryV1(
                nonce_registry_root,
                filesystem=WindowsFilesystemFactsAdapter(),
                expected_root_facts=pins.nonce_registry_root_facts,
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
    return VerifiedFinalInstallerInputsV1(
        bundle_raw=bundle_raw,
        bundle=bundle,
        manifest=manifest,
        target_projection=projection,
        public_config_raw=public_config_raw,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="windows-final-installer-bootstrap-v1")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--keyring-raw-sha256", required=True)
    parser.add_argument("--nonce-registry-root", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    options = parser.parse_args(argv)
    inputs = build_verified_final_installer_inputs_v1(
        bundle_path=options.bundle,
        manifest_path=options.manifest,
        keyring_path=options.keyring,
        expected_source_sha256=options.expected_source_sha256,
        keyring_raw_sha256=options.keyring_raw_sha256,
        nonce_registry_root=options.nonce_registry_root,
        reserve_nonce=not options.dry_run,
    )
    print(
        run_installed_final_windows_installer_entry_v1(inputs, dry_run=options.dry_run)
    )
    return 0


__all__ = [
    "KEYRING_PURPOSE",
    "KEYRING_SCHEMA_VERSION",
    "WindowsFinalInstallerBootstrapError",
    "build_verified_final_installer_inputs_v1",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - Windows CI invokes this entry.
    raise SystemExit(main())
