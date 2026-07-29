"""Fail-closed NTP and observation-clock quality checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .errors import RegistryError
from .timeutil import require_utc


@dataclass(frozen=True)
class TrustedClockSample:
    trusted_now: datetime
    sampled_at: datetime
    ntp_offset_milliseconds: int


def validate_observation_clock(
    observed_at: datetime,
    *,
    sample: TrustedClockSample,
    max_abs_ntp_offset_milliseconds: int = 1_000,
    max_sample_age_seconds: int = 300,
    max_future_skew_seconds: int = 5,
) -> datetime:
    observed = require_utc(observed_at, "observed_at")
    trusted_now = require_utc(sample.trusted_now, "trusted clock now")
    sampled_at = require_utc(sample.sampled_at, "NTP sampled_at")
    if isinstance(sample.ntp_offset_milliseconds, bool) or not isinstance(
        sample.ntp_offset_milliseconds, int
    ):
        raise RegistryError("NTP offset must be an integer")
    if abs(sample.ntp_offset_milliseconds) > max_abs_ntp_offset_milliseconds:
        raise RegistryError("NTP offset exceeds frozen tolerance")
    age = trusted_now - sampled_at
    if age < timedelta(0) or age > timedelta(seconds=max_sample_age_seconds):
        raise RegistryError("NTP sample is stale or from the future")
    if observed > trusted_now + timedelta(seconds=max_future_skew_seconds):
        raise RegistryError("observation timestamp is in the future")
    return observed
