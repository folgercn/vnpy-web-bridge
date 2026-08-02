from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from app.schemas.commodity_c_fast_fee_statement import (
    CommodityCFastFeeBindingEvidenceDTO,
    REQUIRED_EXCLUDED_AUTHORITY_DOMAINS,
)


_CONTEXT_SEAL = object()
TrustProfile = tuple[
    str,
    tuple[tuple[str, str], ...],
    tuple[tuple[str, tuple[str, ...]], ...],
    str,
]


def _sha256_json(value: object) -> str:
    raw = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _canonical_raw_pins(
    values: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(domain), str(value)) for domain, value in values.items()))


def _canonical_public_pins(
    values: Mapping[str, tuple[str, ...] | list[str]],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple(
        sorted(
            (str(domain), tuple(sorted(str(value) for value in pins)))
            for domain, pins in values.items()
        )
    )


@dataclass(frozen=True, slots=True)
class FeeBindingTrustContext:
    """Process-local capability minted from stable-read deployment trust roots.

    This object is deliberately excluded from every DTO and repository artifact.
    Its private seal also prevents ordinary callers from constructing a context
    by copying self-reported hashes out of fee evidence.
    """

    fee_keyring_raw_sha256: str
    excluded_authority_raw_pins: tuple[tuple[str, str], ...]
    excluded_authority_public_pins: tuple[
        tuple[str, tuple[str, ...]], ...
    ]
    excluded_authority_set_sha256: str
    allowed_profiles: tuple[TrustProfile, ...]
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _CONTEXT_SEAL:
            raise ValueError(
                "FeeBindingTrustContext must come from stable-read trust roots"
            )
        expected_domains = tuple(sorted(REQUIRED_EXCLUDED_AUTHORITY_DOMAINS))
        active_profile = (
            self.fee_keyring_raw_sha256,
            self.excluded_authority_raw_pins,
            self.excluded_authority_public_pins,
            self.excluded_authority_set_sha256,
        )
        if (
            tuple(domain for domain, _ in self.excluded_authority_raw_pins)
            != expected_domains
            or tuple(
                domain for domain, _ in self.excluded_authority_public_pins
            )
            != expected_domains
            or self.excluded_authority_set_sha256
            != _sha256_json(
                {
                    "raw_pins": self.excluded_authority_raw_pins,
                    "public_pins": self.excluded_authority_public_pins,
                }
            )
            or not self.allowed_profiles
            or self.allowed_profiles[0] != active_profile
            or len(set(self.allowed_profiles)) != len(self.allowed_profiles)
            or any(
                not _valid_profile(profile)
                for profile in self.allowed_profiles
            )
        ):
            raise ValueError("fee binding trust context is incomplete")

    def __reduce__(self) -> object:
        raise TypeError("FeeBindingTrustContext is process-local and non-serializable")

    def assert_matches(
        self,
        evidence: CommodityCFastFeeBindingEvidenceDTO,
    ) -> None:
        raw_pins = _canonical_raw_pins(
            evidence.excluded_authority_keyring_raw_sha256s
        )
        public_pins = _canonical_public_pins(
            evidence.excluded_authority_public_key_sha256s
        )
        observed = (
            evidence.trusted_keyring_raw_sha256,
            raw_pins,
            public_pins,
            _sha256_json(
                {"raw_pins": raw_pins, "public_pins": public_pins}
            ),
        )
        if observed not in self.allowed_profiles:
            raise ValueError(
                "fee binding evidence is not rooted in the external trust context"
            )


def _mint_fee_binding_trust_context(
    *,
    fee_keyring_raw_sha256: str,
    excluded_authority_keyring_raw_sha256s: Mapping[str, str],
    excluded_authority_public_key_sha256s: Mapping[
        str, tuple[str, ...] | list[str]
    ],
    historical_profiles: Sequence[Mapping[str, Any]] = (),
) -> FeeBindingTrustContext:
    raw_pins = _canonical_raw_pins(
        excluded_authority_keyring_raw_sha256s
    )
    public_pins = _canonical_public_pins(
        excluded_authority_public_key_sha256s
    )
    active_set_sha256 = _sha256_json(
        {"raw_pins": raw_pins, "public_pins": public_pins}
    )
    profiles: list[TrustProfile] = [
        (
            fee_keyring_raw_sha256,
            raw_pins,
            public_pins,
            active_set_sha256,
        )
    ]
    profile_ids: set[str] = set()
    for raw_profile in historical_profiles:
        profile_id = str(raw_profile.get("profile_id") or "")
        if set(raw_profile) != {
            "profile_id",
            "fee_keyring_raw_sha256",
            "excluded_authority_keyring_raw_sha256s",
            "excluded_authority_public_key_sha256s",
        } or not re.fullmatch(
            r"[A-Za-z0-9._-]{8,128}",
            profile_id,
        ) or profile_id in profile_ids:
            raise ValueError("historical fee trust profile is invalid")
        profile_ids.add(profile_id)
        historical_raw = _canonical_raw_pins(
            raw_profile["excluded_authority_keyring_raw_sha256s"]
        )
        historical_public = _canonical_public_pins(
            raw_profile["excluded_authority_public_key_sha256s"]
        )
        historical_set_sha256 = _sha256_json(
            {
                "raw_pins": historical_raw,
                "public_pins": historical_public,
            }
        )
        profile: TrustProfile = (
            str(raw_profile["fee_keyring_raw_sha256"]),
            historical_raw,
            historical_public,
            historical_set_sha256,
        )
        if not _valid_profile(profile):
            raise ValueError("historical fee trust profile pins are invalid")
        profiles.append(profile)
    return FeeBindingTrustContext(
        fee_keyring_raw_sha256=fee_keyring_raw_sha256,
        excluded_authority_raw_pins=raw_pins,
        excluded_authority_public_pins=public_pins,
        excluded_authority_set_sha256=active_set_sha256,
        allowed_profiles=tuple(profiles),
        _seal=_CONTEXT_SEAL,
    )


def _valid_profile(profile: TrustProfile) -> bool:
    fee_pin, raw_pins, public_pins, set_sha256 = profile
    domains = tuple(sorted(REQUIRED_EXCLUDED_AUTHORITY_DOMAINS))
    sha = re.compile(r"[0-9a-f]{64}")
    raw_values = tuple(pin for _, pin in raw_pins)
    public_values = tuple(
        pin for _, pins in public_pins for pin in pins
    )
    return (
        sha.fullmatch(fee_pin) is not None
        and tuple(domain for domain, _ in raw_pins) == domains
        and tuple(domain for domain, _ in public_pins) == domains
        and all(sha.fullmatch(pin) for _, pin in raw_pins)
        and len(set(raw_values)) == len(raw_values)
        and fee_pin not in raw_values
        and all(
            pins and all(sha.fullmatch(pin) for pin in pins)
            for domain, pins in public_pins
            if domain != "MANUAL_EXECUTION_PERMIT"
        )
        and len(set(public_values)) == len(public_values)
        and set_sha256
        == _sha256_json(
            {"raw_pins": raw_pins, "public_pins": public_pins}
        )
    )
