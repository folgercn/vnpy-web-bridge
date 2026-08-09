from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.generate_installer_trust_anchor_v1 import (
    generate_installer_trust_anchor_v1,
)
from scripts.windows_fence_foundation.installer_bootstrap_v1 import (
    KEYRING_PURPOSE,
    KEYRING_SCHEMA_VERSION,
    WindowsFinalInstallerBootstrapError,
    _canonical_keyring,
)
from scripts.windows_fence_foundation.installer_trust_anchor_v1 import (
    InstallerBootstrapTrustAnchorError,
    InstallerBootstrapTrustAnchorV1,
    load_production_installer_trust_anchor_v1,
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


def test_direct_source_import_cannot_bypass_generated_archive_anchor() -> None:
    with pytest.raises(InstallerBootstrapTrustAnchorError, match="ANCHOR_MISSING"):
        load_production_installer_trust_anchor_v1()


def test_production_anchor_rejects_placeholder_hashes() -> None:
    raw = _keyring_raw()
    pins = _canonical_keyring(raw, hashlib.sha256(raw).hexdigest())
    with pytest.raises(InstallerBootstrapTrustAnchorError, match="ANCHOR_INVALID"):
        InstallerBootstrapTrustAnchorV1(
            keyring_path=Path("/ProgramData/vnpy/keyring.json"),
            keyring_raw_sha256="0" * 64,
            expected_source_sha256="a" * 64,
            manifest=pins.manifest,
            observer=pins.observer,
            restart=pins.restart,
        )


def test_public_only_anchor_generator_emits_pinned_module(tmp_path: Path) -> None:
    keyring = tmp_path / "public-keyring.json"
    output = tmp_path / "_installer_trust_anchor_generated_v1.py"
    raw = _keyring_raw()
    keyring.write_bytes(raw)
    generate_installer_trust_anchor_v1(
        public_keyring_path=keyring,
        keyring_canonical_path=Path("/ProgramData/vnpy/keyring.json"),
        expected_source_sha256="a" * 64,
        output=output,
    )
    generated = output.read_text(encoding="utf-8")
    assert hashlib.sha256(raw).hexdigest() in generated
    assert "public_key_raw" in generated
