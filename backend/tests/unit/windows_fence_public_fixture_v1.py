"""Public-only installer-keyring fixture; intentionally contains no private key."""

from __future__ import annotations

import base64
import hashlib

from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.installer_trust_anchor_v1 import (
    KEYRING_PURPOSE,
    KEYRING_SCHEMA_VERSION,
)
from scripts.windows_fence_foundation.trust_pins_v1 import (
    MANIFEST_KEY_DOMAIN,
    MANIFEST_SIGNER_ROLE,
    OBSERVER_KEY_DOMAIN,
    OBSERVER_SIGNER_ROLE,
    RESTART_KEY_DOMAIN,
    RESTART_SIGNER_ROLE,
)


def public_keyring_raw_v1() -> bytes:
    def pin(*, raw: bytes, domain: str, role: str, suffix: str) -> dict[str, str]:
        return {
            "key_domain": domain,
            "role": role,
            "key_id": f"{role}:{suffix}",
            "public_key_b64": base64.b64encode(raw).decode("ascii"),
            "public_key_sha256": hashlib.sha256(raw).hexdigest(),
        }

    return canonical_json_bytes(
        {
            "schema_version": KEYRING_SCHEMA_VERSION,
            "purpose": KEYRING_PURPOSE,
            "manifest": pin(
                raw=b"a" * 32,
                domain=MANIFEST_KEY_DOMAIN,
                role=MANIFEST_SIGNER_ROLE,
                suffix="public-fixture-001",
            ),
            "observer": pin(
                raw=b"b" * 32,
                domain=OBSERVER_KEY_DOMAIN,
                role=OBSERVER_SIGNER_ROLE,
                suffix="public-fixture-002",
            ),
            "restart": pin(
                raw=b"c" * 32,
                domain=RESTART_KEY_DOMAIN,
                role=RESTART_SIGNER_ROLE,
                suffix="public-fixture-003",
            ),
            "nonce_registry_root_facts": {
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
            },
            "nonce_registry_owner_sid": "test-owner",
            "nonce_registry_acl_sddl": "test-acl",
        }
    )
