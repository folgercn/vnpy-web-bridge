"""Build-provided public trust root for the sealed Windows installer."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


class InstallerBootstrapTrustAnchorError(RuntimeError):
    """The distributable lacks a non-placeholder public trust root."""


@dataclass(frozen=True)
class InstallerBootstrapTrustAnchorV1:
    """Immutable public inputs generated from a public keyring at package build."""

    keyring_path: Path
    keyring_raw_sha256: str
    expected_source_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.keyring_path, Path)
            or not self.keyring_path.is_absolute()
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                or value == "0" * 64
                for value in (self.keyring_raw_sha256, self.expected_source_sha256)
            )
        ):
            raise InstallerBootstrapTrustAnchorError("INSTALLER_TRUST_ANCHOR_INVALID")


def load_production_installer_trust_anchor_v1() -> InstallerBootstrapTrustAnchorV1:
    """Load only the build-generated anchor; no argv/environment fallback exists."""
    try:
        from ._installer_trust_anchor_generated_v1 import (  # type: ignore[import-not-found]
            PRODUCTION_INSTALLER_TRUST_ANCHOR_V1,
        )
    except Exception as exc:
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
    "load_production_installer_trust_anchor_v1",
    "validate_anchor_keyring_bytes_v1",
]
