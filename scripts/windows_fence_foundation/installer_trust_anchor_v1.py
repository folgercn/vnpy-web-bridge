"""Build-provided public trust root for the sealed Windows installer."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import ntpath
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .contracts import canonical_json_bytes
from .trust_pins_v1 import FoundationPublicKeyPin, WindowsFoundationTrustPinsV1
from .win32_fs import PathSecurityFacts

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
        "nonce_registry_owner_sid",
        "nonce_registry_acl_sddl",
    }
)
_PIN_FIELDS = frozenset(
    {"key_domain", "role", "key_id", "public_key_b64", "public_key_sha256"}
)
_FACT_FIELDS = frozenset(PathSecurityFacts.__dataclass_fields__)
_SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class InstallerBootstrapTrustAnchorError(RuntimeError):
    """The distributable lacks a non-placeholder public trust root."""


def _is_expected_source_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and _SOURCE_SHA_RE.fullmatch(value) is not None
        and value != "0" * len(value)
    )


def _canonical_windows_absolute_path(value: object) -> PureWindowsPath | None:
    """Return a local Windows absolute path without using the host OS semantics."""
    if not isinstance(value, Path):
        return None
    candidate = PureWindowsPath(str(value))
    if (
        not ntpath.isabs(str(value))
        or not candidate.is_absolute()
        or re.fullmatch(r"[A-Za-z]:", candidate.drive) is None
    ):
        return None
    return candidate


def canonical_public_keyring_v1(
    raw: bytes, expected_raw_sha256: str
) -> WindowsFoundationTrustPinsV1:
    """Parse only the exact canonical public installer keyring bytes."""
    if hashlib.sha256(raw).hexdigest() != expected_raw_sha256:
        raise InstallerBootstrapTrustAnchorError("KEYRING_RAW_SHA_MISMATCH")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerBootstrapTrustAnchorError("KEYRING_JSON_INVALID") from exc
    if (
        not isinstance(value, dict)
        or canonical_json_bytes(value) != raw
        or set(value) != _KEYRING_FIELDS
        or value.get("schema_version") != KEYRING_SCHEMA_VERSION
        or value.get("purpose") != KEYRING_PURPOSE
    ):
        raise InstallerBootstrapTrustAnchorError("KEYRING_NOT_CANONICAL")

    def pin(name: str) -> FoundationPublicKeyPin:
        item = value[name]
        if not isinstance(item, dict) or set(item) != _PIN_FIELDS:
            raise InstallerBootstrapTrustAnchorError("KEYRING_PIN_FIELDS_INVALID")
        try:
            raw_key = base64.b64decode(item["public_key_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise InstallerBootstrapTrustAnchorError(
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
        raise InstallerBootstrapTrustAnchorError("KEYRING_NONCE_FACTS_INVALID")
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
            nonce_registry_owner_sid=value["nonce_registry_owner_sid"],
            nonce_registry_acl_sddl=value["nonce_registry_acl_sddl"],
        )
    except Exception as exc:
        raise InstallerBootstrapTrustAnchorError("KEYRING_TRUST_PINS_INVALID") from exc


def render_installer_trust_anchor_generated_module_v1(
    *,
    public_keyring_raw: bytes,
    keyring_canonical_path: Path,
    expected_source_sha256: str,
) -> bytes:
    """Render generated public-only bytes; private key input is impossible."""
    keyring_sha256 = hashlib.sha256(public_keyring_raw).hexdigest()
    pins = canonical_public_keyring_v1(public_keyring_raw, keyring_sha256)
    canonical_keyring_path = _canonical_windows_absolute_path(keyring_canonical_path)
    if canonical_keyring_path is None or not _is_expected_source_sha256(
        expected_source_sha256
    ):
        raise InstallerBootstrapTrustAnchorError(
            "INSTALLER_TRUST_ANCHOR_GENERATION_INPUT_INVALID"
        )

    def pin(name: str) -> str:
        value = getattr(pins, name)
        return (
            f"    {name}=FoundationPublicKeyPin(key_domain={value.key_domain!r}, "
            f"role={value.role!r}, key_id={value.key_id!r}, public_key_raw={value.public_key_raw!r}, "
            f"public_key_sha256={value.public_key_sha256!r}),\n"
        )

    source = (
        "# generated from public keyring bytes; never contains a private key\n"
        "from pathlib import Path\n"
        "from .installer_trust_anchor_v1 import InstallerBootstrapTrustAnchorV1\n"
        "from .trust_pins_v1 import FoundationPublicKeyPin\n\n"
        "PRODUCTION_INSTALLER_TRUST_ANCHOR_V1 = InstallerBootstrapTrustAnchorV1(\n"
        f"    keyring_path=Path({canonical_keyring_path.as_posix()!r}),\n"
        f"    keyring_raw_sha256={keyring_sha256!r},\n"
        f"    expected_source_sha256={expected_source_sha256!r},\n"
        f"{pin('manifest')}{pin('observer')}{pin('restart')})\n"
    )
    return source.encode("utf-8")


@dataclass(frozen=True)
class InstallerBootstrapTrustAnchorV1:
    """Immutable public inputs generated from a public keyring at package build."""

    keyring_path: Path
    keyring_raw_sha256: str
    expected_source_sha256: str
    manifest: FoundationPublicKeyPin
    observer: FoundationPublicKeyPin
    restart: FoundationPublicKeyPin

    def __post_init__(self) -> None:
        if (
            not isinstance(self.keyring_path, Path)
            or _canonical_windows_absolute_path(self.keyring_path) is None
            or any(
                not isinstance(value, str)
                or (
                    len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                    or value == "0" * 64
                )
                for value in (self.keyring_raw_sha256,)
            )
            or not _is_expected_source_sha256(self.expected_source_sha256)
            or len({self.manifest.key_id, self.observer.key_id, self.restart.key_id})
            != 3
        ):
            raise InstallerBootstrapTrustAnchorError("INSTALLER_TRUST_ANCHOR_INVALID")


def load_production_installer_trust_anchor_v1() -> InstallerBootstrapTrustAnchorV1:
    """Load only the build-generated anchor; no argv/environment fallback exists."""
    try:
        module = importlib.import_module(
            f"{__package__}._installer_trust_anchor_generated_v1"
        )
        module_path = getattr(module, "__file__", "")
        raw_sha256 = getattr(module, "__verified_foundation_raw_sha256__", "")
        if (
            not isinstance(module_path, str)
            or not module_path.startswith("<verified-foundation-assembly>/")
            or not isinstance(raw_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", raw_sha256) is None
            or raw_sha256 == "0" * 64
        ):
            raise InstallerBootstrapTrustAnchorError(
                "INSTALLER_TRUST_ANCHOR_IMPORT_UNVERIFIED"
            )
        PRODUCTION_INSTALLER_TRUST_ANCHOR_V1 = getattr(
            module, "PRODUCTION_INSTALLER_TRUST_ANCHOR_V1"
        )
    except Exception as exc:
        if isinstance(exc, InstallerBootstrapTrustAnchorError):
            raise
        raise InstallerBootstrapTrustAnchorError(
            "INSTALLER_TRUST_ANCHOR_MISSING"
        ) from exc
    if not isinstance(
        PRODUCTION_INSTALLER_TRUST_ANCHOR_V1, InstallerBootstrapTrustAnchorV1
    ):
        raise InstallerBootstrapTrustAnchorError("INSTALLER_TRUST_ANCHOR_INVALID")
    return PRODUCTION_INSTALLER_TRUST_ANCHOR_V1


def validate_anchor_keyring_bytes_v1(
    anchor: InstallerBootstrapTrustAnchorV1, raw: bytes
) -> None:
    if hashlib.sha256(raw).hexdigest() != anchor.keyring_raw_sha256:
        raise InstallerBootstrapTrustAnchorError("INSTALLER_TRUST_KEYRING_MISMATCH")


__all__ = [
    "InstallerBootstrapTrustAnchorError",
    "InstallerBootstrapTrustAnchorV1",
    "KEYRING_PURPOSE",
    "KEYRING_SCHEMA_VERSION",
    "canonical_public_keyring_v1",
    "load_production_installer_trust_anchor_v1",
    "render_installer_trust_anchor_generated_module_v1",
    "validate_anchor_keyring_bytes_v1",
]
