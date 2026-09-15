from __future__ import annotations

from typing import Protocol

from research_lab.critic import CriticAgent
from research_lab.database import ResultStore
from research_lab.schemas import CriticReview


class PersistedValidationReviewer(Protocol):
    """Reviews only a validation result already persisted by the caller."""

    def review_persisted(self, validation_id: str, *, candidate_id: str) -> CriticReview: ...


class CriticReviewAdapter:
    """Default local adapter that preserves the Critic Agent review behavior."""

    def __init__(self, store: ResultStore) -> None:
        self._critic = CriticAgent(store)

    def review_persisted(self, validation_id: str, *, candidate_id: str) -> CriticReview:
        return self._critic.review_persisted(validation_id, candidate_id=candidate_id)
