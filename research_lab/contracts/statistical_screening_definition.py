"""Pinned constants for Protocol v2 statistical_screening profile unblock (#569)."""

PROFILE_NAME = "research_lab.statistical_screening.v1"
PAYLOAD_PREFIX = "research_lab.statistical_screening."
CRITERIA_ID = "research_lab.statistical_screening.review_evidence.criteria"
ROLE_PROFILE = "research_lab.artifact_roles.v2.candidate1"
SYNTHETIC_FIXTURE_PATH = "research_lab/tests/fixtures/synthetic_statistical_screening_data.csv"
SYNTHETIC_FIXTURE_SHA256 = "12d9c9ca772825b230cca6f9923af535eeadd04475d96b23807c98b90749f87e"
SYNTHETIC_FIXTURE_BYTES = 1060

ALLOWED_METHODS = frozenset({
    "coverage",
    "simple_correlation",
    "direction_consistency",
    "stability_split",
    "leakage_audit",
    "outlier_sensitivity",
    "cost_sensitivity",
})

ALLOWED_STATUSES = frozenset({
    "COMPLETED",
    "INSUFFICIENT_DATA",
    "FAILED",
})
