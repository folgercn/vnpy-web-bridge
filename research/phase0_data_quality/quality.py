"""One declared audit: per-contract dates in original input order. No cleaning."""
import csv
import io
from datetime import date

FIELDS = ["source_official_day", "product", "exact_contract"]
METHOD = "candidate.phase0.source_order.rev1"
METRIC = {
    "metric_name": "timestamp_monotonicity_violations",
    "calculation_definition_version": "phase0.source_order.rev1",
    "unit": "integer_count",
    "sample_scope": "selected rows, adjacent within exact_contract, original CSV order",
    "precision_rule": "exact_integer",
    "undefined_policy": "null_with_reason_not_zero",
    "calculation_definition": "Compare adjacent selected dates within each exact_contract in original source order. Count current <= previous when strict=true, otherwise current < previous. Report comparisons as denominator, duplicate excess keys and reversals separately. Zero comparisons is a defined zero count, not proof of coverage."
}


def scan(raw, spec):
    req = spec["dataset_requirements"]
    start, end = (req["time_range"][k][:10] for k in ("start", "end"))
    params = {p["name"]: p["value"] for p in spec["quality_checks"][0]["parameters"]}
    strict = params.get("strict", True)
    rows = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""))
    if rows.fieldnames != FIELDS:
        raise ValueError("input columns differ from bound input definition")
    previous, seen, anomalies = {}, set(), []
    count = comparisons = violations = duplicates = reversals = 0
    for line, row in enumerate(rows, 2):
        if None in row or any(v is None or not v for v in row.values()):
            raise ValueError(f"invalid input row {line}")
        day = row["source_official_day"]
        if date.fromisoformat(day).isoformat() != day:
            raise ValueError(f"invalid date row {line}")
        if row["product"] not in req["universe"] or not start <= day < end:
            continue
        count += 1
        key = (day, row["exact_contract"])
        duplicate = key in seen
        seen.add(key)
        old = previous.get(row["exact_contract"])
        reverse = old is not None and day < old
        violation = old is not None and (day <= old if strict else day < old)
        comparisons += int(old is not None)
        violations += int(violation)
        duplicates += int(duplicate)
        reversals += int(reverse)
        if duplicate or reverse or violation:
            anomalies.append({"source_row": line, "exact_contract": row["exact_contract"],
                              "day": day, "previous_day": old, "duplicate": duplicate,
                              "reversal": reverse, "metric_violation": violation})
        previous[row["exact_contract"]] = day
    return {"row_count": count, "comparison_count": comparisons,
            "timestamp_monotonicity_violations": violations,
            "duplicate_key_excess_rows": duplicates, "source_order_reversals": reversals}, anomalies
