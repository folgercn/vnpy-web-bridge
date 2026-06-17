from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from app.schemas.common import to_plain_dict


class Side(Enum):
    LONG = "long"


@dataclass
class Sample:
    side: Side
    ts: datetime
    price: float
    volume: int


def test_to_plain_dict_serializes_enum_datetime_and_numbers() -> None:
    data = to_plain_dict(
        Sample(
            side=Side.LONG,
            ts=datetime(2026, 6, 17, 10, 0, tzinfo=timezone.utc),
            price=12.5,
            volume=2,
        )
    )

    assert data == {
        "side": "long",
        "ts": "2026-06-17T10:00:00+00:00",
        "price": 12.5,
        "volume": 2,
    }
