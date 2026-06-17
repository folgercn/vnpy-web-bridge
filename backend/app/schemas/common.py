from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any


STATUS_VALUE_MAP = {
    "提交中": "submitting",
    "未成交": "not_traded",
    "部分成交": "part_traded",
    "全部成交": "all_traded",
    "已撤销": "cancelled",
    "拒单": "rejected",
}

ENUM_VALUE_MAP = {
    "多": "long",
    "空": "short",
    "开": "open",
    "平": "close",
    "平今": "closetoday",
    "平昨": "closeyesterday",
    "限价": "limit",
    "市价": "market",
    "SHFE": "SHFE",
    "DCE": "DCE",
    "CZCE": "CZCE",
    "CFFEX": "CFFEX",
    "INE": "INE",
    "GFEX": "GFEX",
}

NORMALIZED_FIELDS = {"direction", "offset", "type", "status"}


def enum_to_string(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def iso_datetime(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


def to_plain_value(value: Any) -> Any:
    value = enum_to_string(value)
    value = iso_datetime(value)

    if is_dataclass(value):
        return to_plain_dict(asdict(value))
    if isinstance(value, dict):
        return {str(k): to_plain_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_plain_value(v) for v in value]
    if hasattr(value, "__dict__") and not isinstance(value, type):
        return to_plain_dict(value.__dict__)
    return value


def to_plain_dict(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if is_dataclass(obj):
        raw = asdict(obj)
    elif isinstance(obj, dict):
        raw = obj
    else:
        raw = getattr(obj, "__dict__", {"value": obj})

    data = {str(k): to_plain_value(v) for k, v in raw.items() if not str(k).startswith("_")}
    for key in NORMALIZED_FIELDS & data.keys():
        data[key] = normalize_enum_field(key, data[key])
    return data


def normalize_enum_field(key: str, value: Any) -> Any:
    raw = str(value)
    if key == "status":
        return STATUS_VALUE_MAP.get(raw, raw.lower())
    return ENUM_VALUE_MAP.get(raw, raw.lower())


def to_plain_list(items: Any) -> list[dict[str, Any]]:
    if not items:
        return []
    return [to_plain_dict(item) for item in items]
