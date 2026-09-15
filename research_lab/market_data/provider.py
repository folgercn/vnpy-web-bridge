from __future__ import annotations

from abc import ABC, abstractmethod

from typing import TYPE_CHECKING

from research_lab.schemas import ExperimentSpec

if TYPE_CHECKING:
    from .dataset import NormalizedDataset


class MarketDataError(ValueError):
    """Raised when a provider cannot produce a valid normalized dataset."""


class MarketDataProvider(ABC):
    """Replaceable boundary between an experiment's data request and data rows."""

    @abstractmethod
    def load(self, experiment: ExperimentSpec) -> "NormalizedDataset":
        """Resolve an experiment dataset request into a NormalizedDataset."""
        raise NotImplementedError


class DefaultMarketDataProvider(MarketDataProvider):
    """Resolve the built-in dataset request types without exposing Runner to them."""

    def load(self, experiment: ExperimentSpec) -> "NormalizedDataset":
        if experiment.dataset.provider == "inline":
            from .inline import InlinePriceProvider

            return InlinePriceProvider().load(experiment)
        if experiment.dataset.provider == "local_csv":
            from .local_csv import LocalCSVProvider

            return LocalCSVProvider().load(experiment)
        raise MarketDataError(f"unsupported dataset provider: {experiment.dataset.provider}")
