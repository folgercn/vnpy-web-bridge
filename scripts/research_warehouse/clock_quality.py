"""Fail-closed NTP and observation-clock quality checks."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from .errors import RegistryError
from .timeutil import require_utc


@dataclass(frozen=True)
class TrustedClockSample:
    trusted_now: datetime
    sampled_at: datetime
    ntp_offset_milliseconds: int


def validate_live_clock_sample(
    sample: TrustedClockSample,
    *,
    local_now: datetime,
    max_local_alignment_seconds: int = 5,
) -> None:
    trusted_now = require_utc(sample.trusted_now, "trusted clock now")
    local = require_utc(local_now, "local wall clock now")
    sampled_at = require_utc(sample.sampled_at, "NTP sampled_at")
    if isinstance(sample.ntp_offset_milliseconds, bool) or not isinstance(
        sample.ntp_offset_milliseconds,
        int,
    ):
        raise RegistryError("NTP offset must be an integer")
    if abs(sample.ntp_offset_milliseconds) > 1_000:
        raise RegistryError("NTP offset exceeds frozen tolerance")
    age = trusted_now - sampled_at
    if age < timedelta(0) or age > timedelta(seconds=300):
        raise RegistryError("NTP sample is stale or from the future")
    expected = local + timedelta(milliseconds=sample.ntp_offset_milliseconds)
    if abs(trusted_now - expected) > timedelta(
        seconds=max_local_alignment_seconds
    ):
        raise RegistryError("trusted clock is not aligned with live wall time")


def trusted_time_after(
    sample: TrustedClockSample,
    *,
    elapsed_seconds: float,
    max_elapsed_seconds: float,
) -> datetime:
    if (
        isinstance(elapsed_seconds, bool)
        or not isinstance(elapsed_seconds, (int, float))
        or not math.isfinite(elapsed_seconds)
        or elapsed_seconds < 0
        or elapsed_seconds > max_elapsed_seconds
    ):
        raise RegistryError("trusted monotonic request duration is invalid")
    response_received_at = require_utc(
        sample.trusted_now,
        "trusted clock now",
    ) + timedelta(seconds=elapsed_seconds)
    sampled_at = require_utc(sample.sampled_at, "NTP sampled_at")
    sample_age = response_received_at - sampled_at
    if sample_age < timedelta(0) or sample_age > timedelta(seconds=300):
        raise RegistryError("NTP sample is stale at response time")
    return response_received_at


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
