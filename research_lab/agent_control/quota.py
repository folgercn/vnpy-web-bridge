"""Provider-neutral quota facts, contracts, and Antigravity normalization (#573 Milestone 3).

Rules:
1. QuotaStatus is strictly closed: HEALTHY, CONSTRAINED, EXHAUSTED, UNKNOWN.
2. Conservative multi-window evaluation:
   - Any required window EXHAUSTED -> group is EXHAUSTED.
   - Any required window UNKNOWN (without exhaustion) -> group is UNKNOWN.
   - All windows >= healthy_threshold -> HEALTHY.
   - Otherwise CONSTRAINED.
3. High and Medium models sharing a quota group cannot forge independent balances.
4. Facts-only: NO token price optimizer, NO ML scoring, NO speculation on consumption ratios.
5. Strict redaction: Never persist credentials, tokens, avatars, or raw emails.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from research_lab.agent_control.contracts import (
    AgentUsageSnapshot,
    validate_usage_hash,
)
from research_lab.agent_control.errors import ProviderError, ProviderErrorCode


class QuotaStatus(str, Enum):
    """Closed state taxonomy for quota availability."""

    HEALTHY = "HEALTHY"
    CONSTRAINED = "CONSTRAINED"
    EXHAUSTED = "EXHAUSTED"
    UNKNOWN = "UNKNOWN"


def evaluate_window_status(
    remaining_fraction: float | None,
    healthy_threshold: float = 0.30,
) -> QuotaStatus:
    """Evaluate single quota window status conservatively."""
    if remaining_fraction is None:
        return QuotaStatus.UNKNOWN
    try:
        val = float(remaining_fraction)
    except (ValueError, TypeError):
        return QuotaStatus.UNKNOWN

    if val <= 0.0:
        return QuotaStatus.EXHAUSTED
    if val >= healthy_threshold:
        return QuotaStatus.HEALTHY
    return QuotaStatus.CONSTRAINED


def evaluate_group_status(
    windows: Sequence[QuotaWindowSnapshot],
) -> QuotaStatus:
    """Evaluate overall group status using conservative multi-window aggregation.

    Rules:
    - Empty windows -> UNKNOWN
    - Any window EXHAUSTED -> EXHAUSTED (fail-closed)
    - Any window UNKNOWN -> UNKNOWN (conservative)
    - Any window CONSTRAINED -> CONSTRAINED
    - All windows HEALTHY -> HEALTHY
    """
    if not windows:
        return QuotaStatus.UNKNOWN

    statuses = [w.status for w in windows]
    if QuotaStatus.EXHAUSTED in statuses:
        return QuotaStatus.EXHAUSTED
    if QuotaStatus.UNKNOWN in statuses:
        return QuotaStatus.UNKNOWN
    if QuotaStatus.CONSTRAINED in statuses:
        return QuotaStatus.CONSTRAINED
    return QuotaStatus.HEALTHY


@dataclass(frozen=True)
class QuotaWindowSnapshot:
    """Provider-neutral snapshot of a single quota window."""

    window: str
    remaining_fraction: float | None
    reset_time: str | None
    status: QuotaStatus

    def to_dict(self) -> dict[str, Any]:
        return {
            "remaining_fraction": self.remaining_fraction,
            "reset_time": self.reset_time,
            "status": self.status.value,
            "window": self.window,
        }


@dataclass(frozen=True)
class ModelQuotaBinding:
    """Explicit mapping from a canonical model to its underlying quota group."""

    provider: str
    model: str
    quota_group_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "provider": self.provider,
            "quota_group_id": self.quota_group_id,
        }


@dataclass(frozen=True)
class QuotaGroupSnapshot:
    """Provider-neutral snapshot of a quota group with multiple windows."""

    group_id: str
    display_name: str
    status: QuotaStatus
    windows: tuple[QuotaWindowSnapshot, ...]
    bound_models: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "windows", tuple(self.windows))
        object.__setattr__(self, "bound_models", tuple(self.bound_models))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bound_models": list(self.bound_models),
            "display_name": self.display_name,
            "group_id": self.group_id,
            "status": self.status.value,
            "windows": [w.to_dict() for w in self.windows],
        }


@dataclass(frozen=True)
class ProviderQuotaFacts:
    """Aggregated, provider-neutral quota facts derived from an exact AgentUsageSnapshot."""

    provider: str
    snapshot_ref: str
    captured_at: str
    groups: tuple[QuotaGroupSnapshot, ...]
    model_bindings: tuple[ModelQuotaBinding, ...] = ()
    is_stale: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "groups", tuple(self.groups))
        object.__setattr__(self, "model_bindings", tuple(self.model_bindings))

    def get_group(self, group_id: str) -> QuotaGroupSnapshot | None:
        for g in self.groups:
            if g.group_id == group_id:
                return g
        return None

    def get_group_for_model(self, model: str) -> QuotaGroupSnapshot | None:
        # First check explicit model bindings
        for b in self.model_bindings:
            if b.model == model:
                return self.get_group(b.quota_group_id)
        # Next check bound_models declared inside groups
        for g in self.groups:
            if model in g.bound_models:
                return g
        return None

    def get_status_for_model(self, model: str) -> QuotaStatus:
        grp = self.get_group_for_model(model)
        if grp is None:
            return QuotaStatus.UNKNOWN
        return grp.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "groups": [g.to_dict() for g in self.groups],
            "is_stale": self.is_stale,
            "model_bindings": [b.to_dict() for b in self.model_bindings],
            "provider": self.provider,
            "snapshot_ref": self.snapshot_ref,
        }


# Default Antigravity model bindings to the shared Gemini quota group
ANTIGRAVITY_GEMINI_MODELS = (
    "Gemini 3.8 Flash High",
    "Gemini 3.8 Flash Medium",
    "Gemini 3.7 Flash High",
    "Gemini 3.5 Flash",
)


class AntigravityQuotaNormalizer:
    """Provider-specific normalizer converting Antigravity AgentUsageSnapshot into neutral Quota Facts."""

    PROVIDER_NAME = "antigravity"
    DEFAULT_GEMINI_GROUP_ID = "gemini-shared"

    @classmethod
    def normalize(
        cls,
        snapshot: AgentUsageSnapshot,
        *,
        healthy_threshold: float = 0.30,
        max_age_seconds: float = 300.0,
        current_time: str | datetime.datetime | None = None,
        custom_model_bindings: Sequence[ModelQuotaBinding] | None = None,
    ) -> ProviderQuotaFacts:
        """Parse and normalize an Antigravity AgentUsageSnapshot into neutral facts."""
        if not isinstance(snapshot, AgentUsageSnapshot):
            raise ProviderError(
                ProviderErrorCode.QUOTA_UNAVAILABLE,
                f"snapshot must be an AgentUsageSnapshot, got {type(snapshot).__name__}",
            )

        # 1. Tamper check fail-closed
        validate_usage_hash(snapshot.to_dict())

        # 2. Provider match check
        if snapshot.provider != cls.PROVIDER_NAME:
            raise ProviderError(
                ProviderErrorCode.QUOTA_UNAVAILABLE,
                f"AntigravityQuotaNormalizer cannot normalize snapshot for provider '{snapshot.provider}'",
                details={"snapshot_provider": snapshot.provider, "expected_provider": cls.PROVIDER_NAME},
            )

        # 3. Staleness check
        is_stale = cls.is_snapshot_stale(
            snapshot.captured_at,
            max_age_seconds=max_age_seconds,
            current_time=current_time,
        )

        # 4. Group windows by group/bucket
        # Antigravity snapshot quota_windows might have window identifiers
        parsed_windows: list[QuotaWindowSnapshot] = []
        for raw_w in snapshot.quota_windows:
            rem = raw_w.get("remaining_fraction")
            # Parse fraction safely
            rem_val: float | None = None
            if rem is not None:
                try:
                    rem_val = float(rem)
                except (ValueError, TypeError):
                    rem_val = None

            reset_time = str(raw_w.get("reset_time")) if raw_w.get("reset_time") is not None else None
            window_name = str(raw_w.get("window") or raw_w.get("bucketId") or "unknown")

            w_status = evaluate_window_status(rem_val, healthy_threshold=healthy_threshold)
            parsed_windows.append(
                QuotaWindowSnapshot(
                    window=window_name,
                    remaining_fraction=rem_val,
                    reset_time=reset_time,
                    status=w_status,
                )
            )

        # Build group
        group_id = cls.DEFAULT_GEMINI_GROUP_ID
        display_name = snapshot.model_group or "Gemini Models"
        group_status = evaluate_group_status(parsed_windows)

        bound_models = tuple(ANTIGRAVITY_GEMINI_MODELS)
        group = QuotaGroupSnapshot(
            group_id=group_id,
            display_name=display_name,
            status=group_status,
            windows=tuple(parsed_windows),
            bound_models=bound_models,
        )

        # Model bindings
        bindings: list[ModelQuotaBinding] = []
        for m in bound_models:
            bindings.append(
                ModelQuotaBinding(
                    provider=cls.PROVIDER_NAME,
                    model=m,
                    quota_group_id=group_id,
                )
            )

        if custom_model_bindings:
            bindings.extend(custom_model_bindings)

        snapshot_ref = f"{snapshot.snapshot_id}@{snapshot.usage_content_hash}"
        return ProviderQuotaFacts(
            provider=cls.PROVIDER_NAME,
            snapshot_ref=snapshot_ref,
            captured_at=snapshot.captured_at,
            groups=(group,),
            model_bindings=tuple(bindings),
            is_stale=is_stale,
        )

    @classmethod
    def is_snapshot_stale(
        cls,
        captured_at_iso: str,
        max_age_seconds: float = 300.0,
        current_time: str | datetime.datetime | None = None,
    ) -> bool:
        """Determine if snapshot captured_at exceeds max_age_seconds."""
        if not captured_at_iso:
            return True
        try:
            # Parse captured_at
            # Handle ISO string with timezone or without
            clean_iso = captured_at_iso.replace("Z", "+00:00")
            dt_captured = datetime.datetime.fromisoformat(clean_iso)
            if dt_captured.tzinfo is None:
                dt_captured = dt_captured.replace(tzinfo=datetime.timezone.utc)

            if current_time is None:
                dt_now = datetime.datetime.now(datetime.timezone.utc)
            elif isinstance(current_time, datetime.datetime):
                dt_now = current_time
                if dt_now.tzinfo is None:
                    dt_now = dt_now.replace(tzinfo=datetime.timezone.utc)
            else:
                clean_now = str(current_time).replace("Z", "+00:00")
                dt_now = datetime.datetime.fromisoformat(clean_now)
                if dt_now.tzinfo is None:
                    dt_now = dt_now.replace(tzinfo=datetime.timezone.utc)

            age = (dt_now - dt_captured).total_seconds()
            return age > max_age_seconds or age < -60.0  # Also fail if timestamp is far in the future
        except (ValueError, TypeError, OverflowError):
            return True
