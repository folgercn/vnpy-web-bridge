"""AlphaHypothesis Contract, Canonicalization, Validation, and Dedup Boundaries.

Implements #563 (parent #562) MVP specifications for the Alpha Discovery Engine.
Passing these checks validates structural and semantic integrity for research
propositions, but never authorizes execution, screening, or trading.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from research_lab.contracts import v2

SCHEMA_VERSION = "research_lab.alpha_hypothesis.v1"
HASH_PROFILE = "research-json-v1"

ALLOWED_ORIGIN_TYPES = frozenset({
    "human",
    "astra",
    "sol",
    "paper",
    "observation",
    "prior_study",
    "external_research",
})

ALLOWED_DIRECTIONS = frozenset({"positive", "negative"})

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
REVISION_PATTERN = re.compile(r"^rev\.[1-9][0-9]*$")
TIME_PATTERN = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")

# Strictly forbidden fields: runtime, execution, evidence, results, critic/scores
FORBIDDEN_FIELDS = frozenset({
    # Runtime & Execution
    "run_id",
    "spec_id",
    "task_id",
    "execution_engine",
    "snapshot_path",
    "seed",
    "fee_model",
    "output_dir",
    "worker",
    "retry",
    # Results & Evidence
    "evidence",
    "evidence_id",
    "result",
    "metrics",
    "sharpe",
    "ic",
    "pnl",
    "returns",
    "drawdown",
    "win_rate",
    "trade_blotter",
    "equity_curve",
    # Critic & Promotion Gate
    "review",
    "review_id",
    "critic",
    "score",
    "rank",
    "recommendation",
    "decision",
    "gate_decision",
    "status",
    "promote",
    "reject",
    "need_more_evidence",
})

ALLOWED_TOP_LEVEL_FIELDS = frozenset({
    "schema_version",
    "hash_profile",
    "hypothesis_id",
    "revision",
    "hypothesis_content_hash",
    "title",
    "economic_rationale",
    "signal_family",
    "signal_definition",
    "source_features",
    "target",
    "expected_direction",
    "holding_horizon",
    "universe",
    "frequency",
    "known_risks",
    "falsification_conditions",
    "proposed_screening_methods",
    "provenance",
    "parent_hypothesis_ref",
    "related_hypothesis_refs",
    "duplicate_of",
})

CORE_SCIENTIFIC_FIELDS = (
    "signal_family",
    "signal_definition",
    "source_features",
    "target",
    "expected_direction",
    "holding_horizon",
    "universe",
    "frequency",
    "economic_rationale",
)

# Textual patterns in descriptions that attempt to inject results/evidence
RESULT_CLAIM_PATTERNS = [
    re.compile(r"\bsharpe\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"\bic\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"回测赚钱", re.IGNORECASE),
    re.compile(r"已验证有效", re.IGNORECASE),
    re.compile(r"\bpromote\b", re.IGNORECASE),
    re.compile(r"推荐交易", re.IGNORECASE),
]


class HypothesisRef(BaseModel):
    """Immutable reference to an AlphaHypothesis revision."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    revision: str
    content_hash: str

    @field_validator("hypothesis_id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not ID_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid hypothesis_id: {v!r}")
        return v

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, v: str) -> str:
        if not REVISION_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid revision format: {v!r}")
        return v

    @field_validator("content_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        if not HASH_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid content_hash format: {v!r}")
        return v


class HypothesisProvenance(BaseModel):
    """Provenance and origin tracking for AlphaHypothesis."""

    model_config = ConfigDict(extra="forbid")

    origin_type: Literal[
        "human",
        "astra",
        "sol",
        "paper",
        "observation",
        "prior_study",
        "external_research",
    ]
    origin_ref: str = Field(min_length=1)
    created_by: str = Field(min_length=1)
    created_at: str

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, v: str) -> str:
        if not TIME_PATTERN.fullmatch(v):
            raise ValueError(f"created_at must be UTC timestamp YYYY-MM-DDTHH:MM:SS.ffffffZ, got {v!r}")
        return v


class AlphaHypothesis(BaseModel):
    """Contract for an immutable, falsifiable Alpha Hypothesis (#563).

    Describes 'why a signal may predict future return and how it can be falsified'.
    Does not contain experiment runs, execution specs, evidence, or critic scores.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.alpha_hypothesis.v1"] = SCHEMA_VERSION
    hash_profile: Literal["research-json-v1"] = HASH_PROFILE
    hypothesis_id: str
    revision: str = "rev.1"
    hypothesis_content_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[a-f0-9]{64}$",
        description="Canonical SHA-256 digest of the entire revision record (excluding itself).",
    )

    title: str = Field(min_length=1)
    economic_rationale: str = Field(min_length=1)
    signal_family: str = Field(min_length=1)
    signal_definition: str = Field(min_length=1)
    source_features: list[str] = Field(min_length=1)
    target: str = Field(min_length=1)
    expected_direction: Literal["positive", "negative"]
    holding_horizon: str = Field(min_length=1)
    universe: str | dict[str, Any] = Field(...)
    frequency: str = Field(min_length=1)

    known_risks: list[str] = Field(min_length=1)
    falsification_conditions: list[str] = Field(min_length=1)
    proposed_screening_methods: list[str] = Field(min_length=1)

    provenance: HypothesisProvenance
    parent_hypothesis_ref: HypothesisRef | None = None
    related_hypothesis_refs: list[HypothesisRef] | None = None
    duplicate_of: HypothesisRef | None = None

    @field_validator("hypothesis_id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not ID_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid hypothesis_id: {v!r}")
        return v

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, v: str) -> str:
        if not REVISION_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid revision format: {v!r}")
        return v

    @field_validator("source_features", "known_risks", "falsification_conditions", "proposed_screening_methods")
    @classmethod
    def validate_non_empty_strings(cls, items: list[str]) -> list[str]:
        if not items:
            raise ValueError("List must not be empty")
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("List items must be non-empty strings")
        return items

    @field_validator("economic_rationale", "title")
    @classmethod
    def validate_no_result_claims(cls, text: str) -> str:
        for pat in RESULT_CLAIM_PATTERNS:
            if pat.search(text):
                raise ValueError(f"Result or evidence claim forbidden in hypothesis: {text!r}")
        return text

    @property
    def scientific_identity_hash(self) -> str:
        """Compute stable content hash for the core scientific proposition."""
        return compute_scientific_identity_hash(self.model_dump())


def compute_hypothesis_content_hash(data: dict[str, Any]) -> str:
    """Compute repository-pinned research-json-v1 SHA-256 digest of hypothesis revision record."""
    clean = {k: v for k, v in data.items() if k != "hypothesis_content_hash"}
    return v2.digest(clean)


def compute_semantic_hash(data: dict[str, Any]) -> str:
    """Compute stable content hash for the core scientific proposition (Alpha Idea identity).

    Strictly bound to CORE_SCIENTIFIC_FIELDS.
    Ignores revision, title, metadata, risks, falsification_conditions,
    proposed_screening_methods, provenance, and dictionary key order.
    Used for exact duplicate identification: two hypotheses sharing the identical
    scientific proposition represent the same Alpha Idea.
    """
    source_features = sorted(data.get("source_features", []))
    universe = data.get("universe")

    semantic_payload = {
        "economic_rationale": str(data.get("economic_rationale", "")).strip(),
        "expected_direction": data.get("expected_direction"),
        "frequency": str(data.get("frequency", "")).strip(),
        "holding_horizon": str(data.get("holding_horizon", "")).strip(),
        "signal_definition": str(data.get("signal_definition", "")).strip(),
        "signal_family": str(data.get("signal_family", "")).strip(),
        "source_features": source_features,
        "target": str(data.get("target", "")).strip(),
        "universe": universe,
    }
    return v2.digest(semantic_payload)


# Alias for explicit clarity between revision record content hash and scientific identity hash
compute_scientific_identity_hash = compute_semantic_hash


def compute_structured_key(data: dict[str, Any]) -> str:
    """Compute structured similarity key for 'potentially_related' identification.

    Returns deterministic key:
    family={family}|target={target}|dir={dir}|horizon={horizon}|universe={universe}|freq={freq}
    """
    family = str(data.get("signal_family", "")).strip().lower()
    target = str(data.get("target", "")).strip().lower()
    direction = str(data.get("expected_direction", "")).strip().lower()
    horizon = str(data.get("holding_horizon", "")).strip().lower()
    freq = str(data.get("frequency", "")).strip().lower()

    universe = data.get("universe")
    if isinstance(universe, dict):
        universe_repr = v2.canonical(universe)
    else:
        universe_repr = str(universe).strip().lower()

    return f"family={family}|target={target}|dir={direction}|horizon={horizon}|universe={universe_repr}|freq={freq}"


def is_exact_duplicate(h1: dict[str, Any], h2: dict[str, Any]) -> bool:
    """Check if two hypotheses are exact duplicates based on semantic hash."""
    return compute_semantic_hash(h1) == compute_semantic_hash(h2)


def is_potentially_related(h1: dict[str, Any], h2: dict[str, Any]) -> bool:
    """Check if two hypotheses share the same structured similarity key."""
    return compute_structured_key(h1) == compute_structured_key(h2)


def validate_hypothesis(data: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed validation of an AlphaHypothesis dictionary against contract.

    Returns the validated dictionary or raises ValueError.
    """
    if not isinstance(data, dict):
        raise TypeError(f"Hypothesis must be a dict, got {type(data)}")

    # Check for unknown top-level fields (fail closed)
    extra_fields = set(data.keys()) - ALLOWED_TOP_LEVEL_FIELDS
    if extra_fields:
        raise ValueError(f"Forbidden extra fields in hypothesis: {sorted(extra_fields)}")

    # Check for forbidden result/evidence/runtime fields in root or nested
    for forbidden in FORBIDDEN_FIELDS:
        if forbidden in data:
            raise ValueError(f"Forbidden field present in hypothesis: {forbidden!r}")

    # Check schema version and hash profile
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Unknown or unsupported schema_version: {data.get('schema_version')!r}")
    if data.get("hash_profile") != HASH_PROFILE:
        raise ValueError(f"Unknown or unsupported hash_profile: {data.get('hash_profile')!r}")

    # Enforce non-empty, cryptographically valid hypothesis_content_hash matching canonical content
    if "hypothesis_content_hash" not in data:
        raise ValueError("Missing required field: 'hypothesis_content_hash'")
    declared_hash = data.get("hypothesis_content_hash")
    if not isinstance(declared_hash, str) or not declared_hash.strip():
        raise ValueError(f"hypothesis_content_hash must be non-empty string, got {declared_hash!r}")
    if not HASH_PATTERN.fullmatch(declared_hash):
        raise ValueError(f"hypothesis_content_hash must be 64-character lowercase hex SHA-256 digest, got {declared_hash!r}")

    expected_hash = compute_hypothesis_content_hash(data)
    if declared_hash != expected_hash:
        raise ValueError(f"hypothesis_content_hash mismatch: declared {declared_hash}, computed {expected_hash}")

    # Parse and validate via Pydantic model
    try:
        model = AlphaHypothesis.model_validate(data)
    except Exception as err:
        raise ValueError(f"Hypothesis validation failed: {err}") from err

    return model.model_dump(exclude_none=True)


def parse_revision_number(revision: str) -> int:
    """Extract integer from 'rev.N'."""
    match = REVISION_PATTERN.fullmatch(revision)
    if not match:
        raise ValueError(f"Invalid revision format: {revision!r}")
    return int(revision.split(".")[1])


def is_valid_revision(parent: dict[str, Any], child: dict[str, Any]) -> tuple[bool, str]:
    """Determine whether child is a valid revision of parent.

    A valid revision retains the identical core scientific proposition:
    - Same hypothesis_id
    - Incrementing revision (child rev > parent rev)
    - parent_hypothesis_ref matching parent identity and content hash
    - Identical core scientific fields (signal_definition, source_features, target,
      expected_direction, holding_horizon, universe, frequency, economic_rationale)

    If core scientific fields change, it MUST be a new hypothesis instead of revision.
    """
    validate_hypothesis(parent)
    validate_hypothesis(child)

    if child.get("hypothesis_id") != parent.get("hypothesis_id"):
        return False, f"hypothesis_id mismatch: child has {child.get('hypothesis_id')}, parent has {parent.get('hypothesis_id')}"

    parent_rev = parse_revision_number(parent.get("revision", "rev.1"))
    child_rev = parse_revision_number(child.get("revision", "rev.1"))
    if child_rev <= parent_rev:
        return False, f"child revision ({child.get('revision')}) must be greater than parent ({parent.get('revision')})"

    parent_ref = child.get("parent_hypothesis_ref")
    if not parent_ref:
        return False, "child revision missing parent_hypothesis_ref"

    expected_parent_hash = parent.get("hypothesis_content_hash") or compute_hypothesis_content_hash(parent)
    if parent_ref.get("hypothesis_id") != parent.get("hypothesis_id") or \
       parent_ref.get("revision") != parent.get("revision") or \
       parent_ref.get("content_hash") != expected_parent_hash:
        return False, f"parent_hypothesis_ref does not match parent record: {parent_ref}"

    # Check for changes in core scientific proposition
    for field_name in CORE_SCIENTIFIC_FIELDS:
        p_val = parent.get(field_name)
        c_val = child.get(field_name)
        if field_name == "source_features":
            if sorted(p_val or []) != sorted(c_val or []):
                return False, f"Core scientific field {field_name!r} changed: cannot disguise as revision, must create new hypothesis"
        elif p_val != c_val:
            return False, f"Core scientific field {field_name!r} changed: cannot disguise as revision, must create new hypothesis"

    return True, ""


def create_revision(
    parent: dict[str, Any],
    updates: dict[str, Any],
    *,
    created_by: str,
    origin_ref: str | None = None,
) -> dict[str, Any]:
    """Helper to safely create a new revision of an existing hypothesis.

    Enforces that core scientific fields cannot be mutated.
    """
    validate_hypothesis(parent)
    if "hypothesis_id" in updates and updates["hypothesis_id"] != parent["hypothesis_id"]:
        raise ValueError(f"Cannot change hypothesis_id in revision: {updates['hypothesis_id']!r} != {parent['hypothesis_id']!r}")

    parent_rev_num = parse_revision_number(parent["revision"])
    next_rev = f"rev.{parent_rev_num + 1}"
    parent_hash = parent.get("hypothesis_content_hash") or compute_hypothesis_content_hash(parent)

    # Disallow core scientific mutations in updates
    for field_name in CORE_SCIENTIFIC_FIELDS:
        if field_name in updates and updates[field_name] != parent.get(field_name):
            raise ValueError(f"Cannot mutate core scientific field {field_name!r} in a revision. Create a new hypothesis instead.")

    child = dict(parent)
    child.update(updates)
    child["revision"] = next_rev
    child["parent_hypothesis_ref"] = {
        "hypothesis_id": parent["hypothesis_id"],
        "revision": parent["revision"],
        "content_hash": parent_hash,
    }

    # Update provenance
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    child["provenance"] = {
        "origin_type": parent["provenance"]["origin_type"],
        "origin_ref": origin_ref or f"revision of {parent['hypothesis_id']}@{parent['revision']}",
        "created_by": created_by,
        "created_at": now_utc,
    }

    # Recompute content hash
    child["hypothesis_content_hash"] = compute_hypothesis_content_hash(child)
    validate_hypothesis(child)
    return child
