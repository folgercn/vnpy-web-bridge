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
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from research_lab.agent_control.contracts import (
    AgentUsageSnapshot,
    validate_usage_hash,
)
from research_lab.agent_control.errors import (
    ProviderError,
    ProviderErrorCode,
    TamperDetectionError,
)


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


DEFAULT_BINDING_PROFILE_VERSION = "2026-09-m3.v1"
DEFAULT_BINDING_SOURCE = "versioned_provider_profile"


@dataclass(frozen=True)
class ModelQuotaBinding:
    """Explicit mapping from a canonical model to its underlying quota group."""

    provider: str
    model: str
    quota_group_id: str
    binding_profile_version: str = DEFAULT_BINDING_PROFILE_VERSION
    binding_source: str = DEFAULT_BINDING_SOURCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_profile_version": self.binding_profile_version,
            "binding_source": self.binding_source,
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


def compute_quota_facts_provenance_hash(
    *,
    provider: str,
    snapshot_ref: str,
    captured_at: str,
    is_stale: bool,
    groups: Sequence[QuotaGroupSnapshot],
    model_bindings: Sequence[ModelQuotaBinding],
    binding_profile_version: str,
    binding_source: str,
) -> str:
    """Deterministic cryptographic SHA-256 hash binding snapshot exact ref, windows, groups, and profile."""
    payload = {
        "binding_profile_version": binding_profile_version,
        "binding_source": binding_source,
        "captured_at": captured_at,
        "groups": [g.to_dict() for g in groups],
        "is_stale": is_stale,
        "model_bindings": [b.to_dict() for b in model_bindings],
        "provider": provider,
        "snapshot_ref": snapshot_ref,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProviderQuotaFacts:
    """Aggregated, provider-neutral quota facts derived from an exact AgentUsageSnapshot."""

    provider: str
    snapshot_ref: str
    captured_at: str
    groups: tuple[QuotaGroupSnapshot, ...]
    model_bindings: tuple[ModelQuotaBinding, ...] = ()
    binding_profile_version: str = DEFAULT_BINDING_PROFILE_VERSION
    binding_source: str = DEFAULT_BINDING_SOURCE
    is_stale: bool = False
    provenance_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "groups", tuple(self.groups))
        object.__setattr__(self, "model_bindings", tuple(self.model_bindings))
        calc_hash = compute_quota_facts_provenance_hash(
            provider=self.provider,
            snapshot_ref=self.snapshot_ref,
            captured_at=self.captured_at,
            is_stale=self.is_stale,
            groups=self.groups,
            model_bindings=self.model_bindings,
            binding_profile_version=self.binding_profile_version,
            binding_source=self.binding_source,
        )
        if self.provenance_hash and self.provenance_hash != calc_hash:
            raise TamperDetectionError(
                f"ProviderQuotaFacts internal provenance_hash mismatch: expected '{calc_hash}', got '{self.provenance_hash}'"
            )
        if not self.provenance_hash:
            object.__setattr__(self, "provenance_hash", calc_hash)

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
            "binding_profile_version": self.binding_profile_version,
            "binding_source": self.binding_source,
            "captured_at": self.captured_at,
            "groups": [g.to_dict() for g in self.groups],
            "is_stale": self.is_stale,
            "model_bindings": [b.to_dict() for b in self.model_bindings],
            "provenance_hash": self.provenance_hash,
            "provider": self.provider,
            "snapshot_ref": self.snapshot_ref,
        }


def verify_quota_facts_provenance(injected: ProviderQuotaFacts, expected: ProviderQuotaFacts) -> None:
    """Strict exact-equality validation ensuring injected facts exactly match deterministic recomputed facts."""
    if not isinstance(injected, ProviderQuotaFacts):
        raise TamperDetectionError(
            f"injected facts must be an instance of ProviderQuotaFacts, got {type(injected).__name__}"
        )
    if injected.provider != expected.provider:
        raise TamperDetectionError(
            f"injected quota_facts provider '{injected.provider}' mismatch with expected provider '{expected.provider}'"
        )
    if injected.snapshot_ref != expected.snapshot_ref:
        raise TamperDetectionError(
            f"injected quota_facts snapshot_ref '{injected.snapshot_ref}' mismatch with expected exact ref '{expected.snapshot_ref}'"
        )
    if injected.captured_at != expected.captured_at:
        raise TamperDetectionError(
            f"injected quota_facts captured_at '{injected.captured_at}' mismatch with expected '{expected.captured_at}'"
        )
    if injected.is_stale != expected.is_stale:
        raise TamperDetectionError(
            f"injected quota_facts freshness is_stale '{injected.is_stale}' mismatch with expected '{expected.is_stale}'"
        )
    if injected.binding_profile_version != expected.binding_profile_version:
        raise TamperDetectionError(
            f"injected quota_facts binding_profile_version '{injected.binding_profile_version}' mismatch with expected '{expected.binding_profile_version}'"
        )
    if injected.binding_source != expected.binding_source:
        raise TamperDetectionError(
            f"injected quota_facts binding_source '{injected.binding_source}' mismatch with expected '{expected.binding_source}'"
        )
    if len(injected.groups) != len(expected.groups):
        raise TamperDetectionError(
            f"injected quota_facts groups count {len(injected.groups)} mismatch with expected {len(expected.groups)}"
        )
    for i, (ig, eg) in enumerate(zip(injected.groups, expected.groups)):
        if ig.group_id != eg.group_id:
            raise TamperDetectionError(
                f"injected quota_facts group[{i}] group_id '{ig.group_id}' mismatch with expected '{eg.group_id}'"
            )
        if ig.display_name != eg.display_name:
            raise TamperDetectionError(
                f"injected quota_facts group[{i}] display_name '{ig.display_name}' mismatch with expected '{eg.display_name}'"
            )
        if ig.status != eg.status:
            raise TamperDetectionError(
                f"injected quota_facts group '{ig.group_id}' status mismatch: expected '{eg.status.value}', got '{ig.status.value}'"
            )
        if ig.bound_models != eg.bound_models:
            raise TamperDetectionError(
                f"injected quota_facts group '{ig.group_id}' bound_models mismatch: expected {eg.bound_models}, got {ig.bound_models}"
            )
        if len(ig.windows) != len(eg.windows):
            raise TamperDetectionError(
                f"injected quota_facts group '{ig.group_id}' windows count {len(ig.windows)} mismatch with expected {len(eg.windows)}"
            )
        for j, (iw, ew) in enumerate(zip(ig.windows, eg.windows)):
            if iw.window != ew.window:
                raise TamperDetectionError(
                    f"injected quota_facts group '{ig.group_id}' window[{j}] name '{iw.window}' mismatch with expected '{ew.window}'"
                )
            if iw.remaining_fraction != ew.remaining_fraction:
                raise TamperDetectionError(
                    f"injected quota_facts group '{ig.group_id}' window '{iw.window}' remaining_fraction mismatch: expected {ew.remaining_fraction}, got {iw.remaining_fraction}"
                )
            if iw.reset_time != ew.reset_time:
                raise TamperDetectionError(
                    f"injected quota_facts group '{ig.group_id}' window '{iw.window}' reset_time mismatch: expected '{ew.reset_time}', got '{iw.reset_time}'"
                )
            if iw.status != ew.status:
                raise TamperDetectionError(
                    f"injected quota_facts group '{ig.group_id}' window '{iw.window}' status mismatch: expected '{ew.status.value}', got '{iw.status.value}'"
                )
    if len(injected.model_bindings) != len(expected.model_bindings):
        raise TamperDetectionError(
            f"injected quota_facts model_bindings count {len(injected.model_bindings)} mismatch with expected {len(expected.model_bindings)}"
        )
    for i, (ib, eb) in enumerate(zip(injected.model_bindings, expected.model_bindings)):
        if ib != eb:
            raise TamperDetectionError(
                f"injected quota_facts model_bindings[{i}] mismatch: expected {eb}, got {ib}"
            )
    if injected.provenance_hash != expected.provenance_hash:
        raise TamperDetectionError(
            f"injected quota_facts provenance_hash mismatch: expected '{expected.provenance_hash}', got '{injected.provenance_hash}'"
        )
    if injected != expected:
        raise TamperDetectionError(
            "injected quota_facts does not exactly match deterministic facts recomputed from ground truth snapshot"
        )



# Versioned model binding profile for Antigravity Gemini Models
# Semantics: Real-time quota windows from account_usage + Versioned provider model binding profile
ANTIGRAVITY_BINDING_PROFILE_VERSION = "2026-09-m3.v1"
ANTIGRAVITY_GEMINI_MODEL_MAP: dict[str, str] = {
    "Gemini 3.8 Flash High": "gemini-shared",
    "Gemini 3.8 Flash Medium": "gemini-shared",
    "Gemini 3.7 Flash High": "gemini-shared",
    "Gemini 3.5 Flash": "gemini-shared",
}
ANTIGRAVITY_GEMINI_MODELS = tuple(ANTIGRAVITY_GEMINI_MODEL_MAP.keys())


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
        binding_profile_version: str = ANTIGRAVITY_BINDING_PROFILE_VERSION,
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

        # 3. Profile version check
        if not binding_profile_version or binding_profile_version != ANTIGRAVITY_BINDING_PROFILE_VERSION:
            raise ProviderError(
                ProviderErrorCode.QUOTA_UNAVAILABLE,
                f"Unsupported or mismatched binding_profile_version: '{binding_profile_version}'",
                details={"expected_version": ANTIGRAVITY_BINDING_PROFILE_VERSION, "actual_version": binding_profile_version},
            )

        # 4. Staleness check
        is_stale = cls.is_snapshot_stale(
            snapshot.captured_at,
            max_age_seconds=max_age_seconds,
            current_time=current_time,
        )

        # 5. Group windows by group/bucket
        grouped_windows: dict[str, list[QuotaWindowSnapshot]] = {}
        group_display_names: dict[str, str] = {}

        for raw_w in snapshot.quota_windows:
            rem = raw_w.get("remaining_fraction")
            rem_val: float | None = None
            if rem is not None:
                try:
                    rem_val = float(rem)
                except (ValueError, TypeError):
                    rem_val = None

            reset_time = str(raw_w.get("reset_time")) if raw_w.get("reset_time") is not None else None
            window_name = str(raw_w.get("window") or raw_w.get("bucketId") or "unknown")

            w_status = evaluate_window_status(rem_val, healthy_threshold=healthy_threshold)
            parsed_w = QuotaWindowSnapshot(
                window=window_name,
                remaining_fraction=rem_val,
                reset_time=reset_time,
                status=w_status,
            )

            w_group_id = str(raw_w.get("group_id") or raw_w.get("quota_group_id") or cls.DEFAULT_GEMINI_GROUP_ID)
            w_display = str(raw_w.get("group_display_name") or raw_w.get("model_group") or snapshot.model_group or "Gemini Models")

            if w_group_id not in grouped_windows:
                grouped_windows[w_group_id] = []
                group_display_names[w_group_id] = w_display
            grouped_windows[w_group_id].append(parsed_w)

        if not grouped_windows:
            default_gid = cls.DEFAULT_GEMINI_GROUP_ID
            grouped_windows[default_gid] = []
            group_display_names[default_gid] = snapshot.model_group or "Gemini Models"

        # Base bindings from versioned profile
        bindings_dict: dict[str, ModelQuotaBinding] = {}
        for m, grp in ANTIGRAVITY_GEMINI_MODEL_MAP.items():
            bindings_dict[m] = ModelQuotaBinding(
                provider=cls.PROVIDER_NAME,
                model=m,
                quota_group_id=grp,
                binding_profile_version=binding_profile_version,
                binding_source=DEFAULT_BINDING_SOURCE,
            )

        if custom_model_bindings:
            for b in custom_model_bindings:
                bindings_dict[b.model] = b
                if b.quota_group_id not in grouped_windows:
                    grouped_windows[b.quota_group_id] = []
                    group_display_names[b.quota_group_id] = b.quota_group_id

        all_bindings = tuple(bindings_dict.values())

        groups_list: list[QuotaGroupSnapshot] = []
        for gid, w_list in grouped_windows.items():
            g_status = evaluate_group_status(w_list)
            bound_models = tuple(b.model for b in all_bindings if b.quota_group_id == gid)
            groups_list.append(
                QuotaGroupSnapshot(
                    group_id=gid,
                    display_name=group_display_names.get(gid, gid),
                    status=g_status,
                    windows=tuple(w_list),
                    bound_models=bound_models,
                )
            )

        snapshot_ref = f"{snapshot.snapshot_id}@{snapshot.usage_content_hash}"
        return ProviderQuotaFacts(
            provider=cls.PROVIDER_NAME,
            snapshot_ref=snapshot_ref,
            captured_at=snapshot.captured_at,
            groups=tuple(groups_list),
            model_bindings=all_bindings,
            binding_profile_version=binding_profile_version,
            binding_source=DEFAULT_BINDING_SOURCE,
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
