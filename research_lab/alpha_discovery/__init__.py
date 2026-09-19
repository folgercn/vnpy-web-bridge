"""Alpha Discovery MVP: AlphaHypothesis Contract, Normalization and Dedup."""

from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    compute_hypothesis_content_hash,
    compute_semantic_hash,
    compute_structured_key,
    is_exact_duplicate,
    is_potentially_related,
    is_valid_revision,
    validate_hypothesis,
)

__all__ = [
    "AlphaHypothesis",
    "compute_hypothesis_content_hash",
    "compute_semantic_hash",
    "compute_structured_key",
    "is_exact_duplicate",
    "is_potentially_related",
    "is_valid_revision",
    "validate_hypothesis",
]
