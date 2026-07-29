"""Frozen cross-plane identity for the ten-product commodity strategy."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final


COMMODITY_FROZEN_SECTOR_MAP_V1_ID: Final = "COMMODITY_FROZEN_SECTOR_MAP_V1"

COMMODITY_FROZEN_SECTOR_MAP_V1: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ag": "precious",
        "al": "nonferrous",
        "au": "precious",
        "bu": "energy_chemical",
        "cu": "nonferrous",
        "rb": "ferrous",
        "ru": "energy_chemical",
        "sc": "energy",
        "sp": "light_industry",
        "zn": "nonferrous",
    }
)


def commodity_frozen_sector_map_v1() -> dict[str, str]:
    """Return a mutable plane-local copy without exposing the frozen mapping."""

    return dict(COMMODITY_FROZEN_SECTOR_MAP_V1)
