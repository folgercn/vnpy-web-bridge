from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.installer_bootstrap_v1 import (
    KEYRING_PURPOSE,
    KEYRING_SCHEMA_VERSION,
    WindowsFinalInstallerBootstrapError,
    _canonical_keyring,
    build_verified_final_installer_inputs_v1,
)
from scripts.windows_fence_foundation.installer_trust_anchor_v1 import (
    InstallerBootstrapTrustAnchorError,
    InstallerBootstrapTrustAnchorV1,
)
from scripts.windows_fence_foundation.trust_pins_v1 import (
    MANIFEST_KEY_DOMAIN,
    MANIFEST_SIGNER_ROLE,
    OBSERVER_KEY_DOMAIN,
    OBSERVER_SIGNER_ROLE,
    RESTART_KEY_DOMAIN,
    RESTART_SIGNER_ROLE,
)


def _pin(
    private: Ed25519PrivateKey, *, domain: str, role: str, suffix: str
) -> dict[str, str]:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "key_domain": domain,
        "role": role,
        "key_id": f"{role}:{suffix}",
        "public_key_b64": base64.b64encode(raw).decode("ascii"),
        "public_key_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _keyring_raw() -> bytes:
    facts = {
        "path_sha256": "a" * 64,
        "volume_serial": "A1B2C3D4",
        "volume_identity_sha256": "b" * 64,
        "file_identity": "A1B2C3D4:1",
        "owner_sid_sha256": hashlib.sha256(b"test-owner").hexdigest(),
        "acl_sddl_sha256": hashlib.sha256(b"test-acl").hexdigest(),
        "unsafe_write_principals": [],
        "write_principal_sid_sha256s": ["e" * 64],
        "regular_file": False,
        "directory": True,
        "reparse_point": False,
        "parent_chain_reparse_free": True,
        "hardlink_count": 1,
        "alternate_data_streams": False,
        "dacl_protected": True,
        "inherited_ace_count": 0,
    }
    return canonical_json_bytes(
        {
            "schema_version": KEYRING_SCHEMA_VERSION,
            "purpose": KEYRING_PURPOSE,
            "manifest": _pin(
                Ed25519PrivateKey.from_private_bytes(b"1" * 32),
                domain=MANIFEST_KEY_DOMAIN,
                role=MANIFEST_SIGNER_ROLE,
                suffix="bootstrap-key-001",
            ),
            "observer": _pin(
                Ed25519PrivateKey.from_private_bytes(b"2" * 32),
                domain=OBSERVER_KEY_DOMAIN,
                role=OBSERVER_SIGNER_ROLE,
                suffix="bootstrap-key-002",
            ),
            "restart": _pin(
                Ed25519PrivateKey.from_private_bytes(b"3" * 32),
                domain=RESTART_KEY_DOMAIN,
                role=RESTART_SIGNER_ROLE,
                suffix="bootstrap-key-003",
            ),
            "nonce_registry_root_facts": facts,
            "nonce_registry_owner_sid": "test-owner",
            "nonce_registry_acl_sddl": "test-acl",
        }
    )


def test_bootstrap_keyring_is_canonical_sha_pinned_and_domain_separated() -> None:
    raw = _keyring_raw()
    pins = _canonical_keyring(raw, hashlib.sha256(raw).hexdigest())
    assert pins.manifest.key_domain == MANIFEST_KEY_DOMAIN
    assert pins.observer.key_id != pins.restart.key_id
    with pytest.raises(WindowsFinalInstallerBootstrapError, match="RAW_SHA"):
        _canonical_keyring(raw, "0" * 64)


@pytest.mark.skipif(os.name == "nt", reason="Windows bootstrap path is native-only")
def test_bootstrap_never_accepts_portable_inputs() -> None:
    with pytest.raises(WindowsFinalInstallerBootstrapError, match="REQUIRED"):
        build_verified_final_installer_inputs_v1(
            bundle_path=Path("bundle.zip"),
            manifest_path=Path("manifest.json"),
            keyring_path=Path("keyring.json"),
            expected_source_sha256="a" * 64,
            keyring_raw_sha256="b" * 64,
            nonce_registry_root=Path("nonce"),
            reserve_nonce=False,
        )


def test_production_anchor_rejects_placeholder_hashes() -> None:
    with pytest.raises(InstallerBootstrapTrustAnchorError, match="ANCHOR_INVALID"):
        InstallerBootstrapTrustAnchorV1(
            keyring_path=Path("/ProgramData/vnpy/keyring.json"),
            keyring_raw_sha256="0" * 64,
            expected_source_sha256="a" * 64,
        )
