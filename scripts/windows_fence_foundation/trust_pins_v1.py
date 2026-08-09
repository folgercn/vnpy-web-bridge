"""Externally provisioned, domain-separated WF-2 Ed25519 trust pins."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .win32_fs import PathSecurityFacts

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MANIFEST_SIGNER_ROLE = "windows-foundation-manifest-signer"
MANIFEST_KEY_DOMAIN = "dedicated-windows-foundation-manifest-signing-v1"
OBSERVER_SIGNER_ROLE = "windows-foundation-observer-evidence"
OBSERVER_KEY_DOMAIN = "dedicated-windows-foundation-observer-evidence-v1"
RESTART_SIGNER_ROLE = "windows-foundation-restart-authorizer"
RESTART_KEY_DOMAIN = "dedicated-windows-foundation-restart-authorization-v1"


class TrustPinError(ValueError):
    """A stable, fail-closed trust-pin rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FoundationPublicKeyPin:
    key_domain: str
    role: str
    key_id: str
    public_key_raw: bytes
    public_key_sha256: str

    def __post_init__(self) -> None:
        if type(self.public_key_raw) is not bytes or len(self.public_key_raw) != 32:
            raise TrustPinError("TRUST_PIN_PUBLIC_KEY_INVALID")
        if not isinstance(self.public_key_sha256, str) or not SHA256_RE.fullmatch(
            self.public_key_sha256
        ):
            raise TrustPinError("TRUST_PIN_PUBLIC_KEY_SHA256_INVALID")
        if hashlib.sha256(self.public_key_raw).hexdigest() != self.public_key_sha256:
            raise TrustPinError("TRUST_PIN_PUBLIC_KEY_SHA256_MISMATCH")


@dataclass(frozen=True)
class WindowsFoundationTrustPinsV1:
    """The three fixed WF-2 trust domains; key reuse is forbidden."""

    manifest: FoundationPublicKeyPin
    observer: FoundationPublicKeyPin
    restart: FoundationPublicKeyPin
    nonce_registry_root_facts: PathSecurityFacts
    nonce_registry_owner_sid: str
    nonce_registry_acl_sddl: str

    def __post_init__(self) -> None:
        facts = self.nonce_registry_root_facts
        if (
            not isinstance(facts, PathSecurityFacts)
            or not SHA256_RE.fullmatch(facts.path_sha256)
            or not SHA256_RE.fullmatch(facts.volume_identity_sha256)
            or re.fullmatch(r"[A-F0-9]{8,32}", facts.volume_serial) is None
            or not SHA256_RE.fullmatch(facts.owner_sid_sha256)
            or not SHA256_RE.fullmatch(facts.acl_sddl_sha256)
            or not facts.file_identity
            or not facts.directory
            or facts.regular_file
            or facts.reparse_point
            or not facts.parent_chain_reparse_free
            or facts.unsafe_write_principals
            or len(facts.write_principal_sid_sha256s) != 1
            or not SHA256_RE.fullmatch(facts.write_principal_sid_sha256s[0])
            or facts.alternate_data_streams
            or not facts.dacl_protected
            or facts.inherited_ace_count != 0
        ):
            raise TrustPinError("NONCE_REGISTRY_ROOT_FACTS_INVALID")
        if (
            not isinstance(self.nonce_registry_owner_sid, str)
            or not self.nonce_registry_owner_sid
            or not isinstance(self.nonce_registry_acl_sddl, str)
            or not self.nonce_registry_acl_sddl
            or hashlib.sha256(self.nonce_registry_owner_sid.encode("utf-8")).hexdigest()
            != facts.owner_sid_sha256
            or hashlib.sha256(self.nonce_registry_acl_sddl.encode("utf-8")).hexdigest()
            != facts.acl_sddl_sha256
        ):
            raise TrustPinError("NONCE_REGISTRY_SECURITY_EXPECTATION_INVALID")
        if any(
            not isinstance(pin, FoundationPublicKeyPin)
            for pin in (self.manifest, self.observer, self.restart)
        ):
            raise TrustPinError("TRUST_PIN_TYPE_INVALID")
        expected = (
            (
                self.manifest,
                MANIFEST_KEY_DOMAIN,
                MANIFEST_SIGNER_ROLE,
                f"{MANIFEST_SIGNER_ROLE}:",
            ),
            (
                self.observer,
                OBSERVER_KEY_DOMAIN,
                OBSERVER_SIGNER_ROLE,
                f"{OBSERVER_SIGNER_ROLE}:",
            ),
            (
                self.restart,
                RESTART_KEY_DOMAIN,
                RESTART_SIGNER_ROLE,
                f"{RESTART_SIGNER_ROLE}:",
            ),
        )
        for pin, domain, role, key_id_prefix in expected:
            if pin.key_domain != domain or pin.role != role:
                raise TrustPinError("TRUST_PIN_DOMAIN_OR_ROLE_MISMATCH")
            if not isinstance(pin.key_id, str) or (
                re.fullmatch(
                    rf"{re.escape(key_id_prefix)}[A-Za-z0-9][A-Za-z0-9._:-]{{7,127}}",
                    pin.key_id,
                )
                is None
            ):
                raise TrustPinError("TRUST_PIN_KEY_ID_INVALID")

        for attribute, code in (
            ("public_key_raw", "TRUST_PIN_PUBLIC_KEY_REUSE_FORBIDDEN"),
            ("public_key_sha256", "TRUST_PIN_PUBLIC_KEY_REUSE_FORBIDDEN"),
            ("key_id", "TRUST_PIN_KEY_ID_REUSE_FORBIDDEN"),
        ):
            values = {getattr(pin, attribute) for pin, *_ in expected}
            if len(values) != 3:
                raise TrustPinError(code)
