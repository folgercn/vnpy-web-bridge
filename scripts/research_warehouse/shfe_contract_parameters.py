"""Read-only SHFE exact-contract expiry evidence for #362 STATIC_CORE.

The SHFE Contract Parameters data set is an exchange-published fact about one
already-selected exact contract.  It never participates in PIT ranking or
target construction.  It is only admissible when the signed official calendar
cannot cover that contract's delivery month.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any
from zoneinfo import ZoneInfo

from .canonical import parse_json_strict, sha256
from .errors import RegistryError
from .m2_runtime_input import require_sha
from .timeutil import format_utc, parse_utc

SOURCE_ID = "shfe-contract-parameters-v1"
HOST = "www.shfe.com.cn"
MAX_RAW_BYTES = 4 * 1024 * 1024
_INSTRUMENT_RE = re.compile(r"^[a-z]{2}[0-9]{4}$")
_CHINA_TZ = ZoneInfo("Asia/Shanghai")


class ShfeContractParameterError(RegistryError):
    """Official exact-contract expiry evidence is malformed or unpinned."""


@dataclass(frozen=True)
class ShfeContractParameterEvidence:
    """A root/config-pinned read-only SHFE raw response observation."""

    query_day: date
    observed_at: datetime
    raw: bytes
    raw_sha256: str

    @property
    def endpoint(self) -> str:
        return endpoint_for_day(self.query_day)

    @property
    def raw_bytes(self) -> int:
        return len(self.raw)


def endpoint_for_day(query_day: date) -> str:
    return (
        f"https://{HOST}/data/busiparamdata/future/"
        f"ContractBaseInfo{query_day.strftime('%Y%m%d')}.dat"
    )


def _day(value: object, label: str) -> date:
    if not isinstance(value, str) or len(value) != 8 or not value.isdigit():
        raise ShfeContractParameterError(f"{label} is invalid")
    try:
        parsed = datetime.strptime(value, "%Y%m%d").replace(tzinfo=_CHINA_TZ).date()
    except ValueError as exc:
        raise ShfeContractParameterError(f"{label} is invalid") from exc
    if parsed.strftime("%Y%m%d") != value:
        raise ShfeContractParameterError(f"{label} is not canonical")
    return parsed


def evidence_from_raw(
    *,
    query_day: date,
    observed_at: str,
    raw: bytes,
    expected_raw_sha256: str,
) -> ShfeContractParameterEvidence:
    """Bind an existing captured SHFE raw response without network access."""

    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RAW_BYTES:
        raise ShfeContractParameterError("SHFE contract parameter raw is invalid")
    expected = require_sha(expected_raw_sha256, "SHFE contract parameter raw")
    if sha256(raw) != expected:
        raise ShfeContractParameterError("SHFE contract parameter raw hash drifted")
    parsed_observed = parse_utc(observed_at, "SHFE contract parameter observed_at")
    # Strictly parse now, before admitting bytes into a proof.
    _rows(raw, query_day=query_day, observed_at=parsed_observed)
    return ShfeContractParameterEvidence(
        query_day=query_day,
        observed_at=parsed_observed,
        raw=raw,
        raw_sha256=expected,
    )


def evidence_from_pinned_raw(
    *,
    observed_at: str,
    raw: bytes,
    expected_raw_sha256: str,
) -> ShfeContractParameterEvidence:
    """Bind a pinned response using its own strict exchange report date."""

    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RAW_BYTES:
        raise ShfeContractParameterError("SHFE contract parameter raw is invalid")
    payload = parse_json_strict(raw, "SHFE contract parameter raw")
    if not isinstance(payload, dict):
        raise ShfeContractParameterError("SHFE contract parameter response shape mismatch")
    return evidence_from_raw(
        query_day=_day(payload.get("report_date"), "SHFE contract parameter report date"),
        observed_at=observed_at,
        raw=raw,
        expected_raw_sha256=expected_raw_sha256,
    )


def _rows(
    raw: bytes,
    *,
    query_day: date,
    observed_at: datetime | None = None,
) -> list[dict[str, Any]]:
    payload = parse_json_strict(raw, "SHFE contract parameter raw")
    if not isinstance(payload, dict) or set(payload) != {
        "ContractBaseInfo",
        "report_date",
        "update_date",
    }:
        raise ShfeContractParameterError("SHFE contract parameter response shape mismatch")
    expected_day = query_day.strftime("%Y%m%d")
    if payload["report_date"] != expected_day:
        raise ShfeContractParameterError("SHFE contract parameter report day mismatch")
    if not isinstance(payload["update_date"], str):
        raise ShfeContractParameterError("SHFE contract parameter update time is invalid")
    try:
        updated = datetime.strptime(
            payload["update_date"], "%Y%m%d %H:%M:%S"
        ).replace(tzinfo=_CHINA_TZ)
    except ValueError as exc:
        raise ShfeContractParameterError(
            "SHFE contract parameter update time is invalid"
        ) from exc
    if updated.strftime("%Y%m%d %H:%M:%S") != payload["update_date"] or updated.date() != query_day:
        raise ShfeContractParameterError("SHFE contract parameter update day mismatch")
    if observed_at is not None and observed_at < updated:
        raise ShfeContractParameterError(
            "SHFE contract parameter observation precedes exchange update"
        )
    rows = payload["ContractBaseInfo"]
    if not isinstance(rows, list) or not rows:
        raise ShfeContractParameterError("SHFE contract parameter rows are missing")
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ShfeContractParameterError("SHFE contract parameter row is invalid")
        # Every selected row is bound to the endpoint's business date.  Other
        # exchange columns may evolve and are deliberately not a contract.
        if row.get("TRADINGDAY") != expected_day:
            continue
        result.append(row)
    if not result:
        raise ShfeContractParameterError("SHFE contract parameter query day mismatch")
    return result


def expiry_for_exact_contract(
    evidence: ShfeContractParameterEvidence,
    *,
    exact_contract: str,
) -> date:
    """Return one exact SHFE ``EXPIREDATE``; ambiguity is fail-closed."""

    if not isinstance(exact_contract, str) or not exact_contract.startswith("SHFE."):
        raise ShfeContractParameterError("SHFE exact contract is invalid")
    instrument = exact_contract.removeprefix("SHFE.")
    if _INSTRUMENT_RE.fullmatch(instrument) is None:
        raise ShfeContractParameterError("SHFE exact contract is invalid")
    rows = [
        row
        for row in _rows(
            evidence.raw,
            query_day=evidence.query_day,
            observed_at=evidence.observed_at,
        )
        if row.get("INSTRUMENTID") == instrument
    ]
    if len(rows) != 1:
        raise ShfeContractParameterError("SHFE exact contract parameter is missing or ambiguous")
    row = rows[0]
    if row.get("EXCHANGEID") != "SHFE" or row.get("COMMODITYID") != instrument[:-4]:
        raise ShfeContractParameterError("SHFE exact contract parameter identity mismatch")
    return _day(row.get("EXPIREDATE"), "SHFE contract EXPIREDATE")


def lineage_for_exact_contract(
    evidence: ShfeContractParameterEvidence,
    *,
    exact_contract: str,
) -> dict[str, object]:
    """Canonical metadata retained by v3 source evidence, never authority."""

    expiry = expiry_for_exact_contract(evidence, exact_contract=exact_contract)
    return {
        "source_id": SOURCE_ID,
        "endpoint": evidence.endpoint,
        "query_day": evidence.query_day.isoformat(),
        "observed_at": format_utc(
            evidence.observed_at, "SHFE contract parameter observed_at"
        ),
        "raw_sha256": evidence.raw_sha256,
        "raw_bytes": evidence.raw_bytes,
        "exact_contract": exact_contract,
        "instrument_id": exact_contract.removeprefix("SHFE."),
        "expire_date": expiry.isoformat(),
    }
