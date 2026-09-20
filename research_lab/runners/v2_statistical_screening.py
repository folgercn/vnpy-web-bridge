"""Minimal deterministic statistical screening execution bridge for Protocol v2 (#569).

Bridges Protocol v2 Task/Spec admission to deterministic statistical screening execution
and produces verified ExperimentRun, ArtifactManifest, and ResultEvidence records.
"""

from __future__ import annotations

import csv
import math
from pathlib import Path
from typing import Any
from uuid import uuid4

from research_lab.contracts import statistical_screening_definition as ssd
from research_lab.contracts import v2


def _compute_pearson(x_vals: list[float], y_vals: list[float]) -> float | None:
    n = len(x_vals)
    if n < 2:
        return None
    mean_x = sum(x_vals) / n
    mean_y = sum(y_vals) / n
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_vals, y_vals))
    var_x = sum((x - mean_x) ** 2 for x in x_vals)
    var_y = sum((y - mean_y) ** 2 for y in y_vals)
    if var_x <= 1e-12 or var_y <= 1e-12:
        return None
    denom = math.sqrt(var_x * var_y)
    r = cov / denom
    # Clamp to [-1.0, 1.0]
    return max(-1.0, min(1.0, r))


def _format_decimal(val: float | None, decimals: int = 6) -> str | None:
    if val is None or math.isnan(val) or math.isinf(val):
        return None
    s = f"{val:.{decimals}f}"
    # Strip trailing zeroes after decimal point while keeping at least one digit if decimal
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s == "-0" or s == "":
        s = "0"
    return s


def run_statistical_screening(
    task: dict[str, Any],
    spec: dict[str, Any],
    snapshot_path: Path | str,
    output_dir: Path | str,
    *,
    copy_snapshot: bool = True,
    _inject_failure: str | None = None,
) -> Path:
    """Execute deterministic statistical screening experiment and output verified v2 bundle."""
    out_dir = Path(output_dir).resolve()
    snap_p = Path(snapshot_path).resolve()

    if out_dir.exists():
        raise FileExistsError(f"Output directory already exists and is immutable: {out_dir}")

    if not snap_p.is_file() or snap_p.is_symlink():
        raise FileNotFoundError(f"Snapshot file missing or is symlink: {snap_p}")

    raw_bytes = snap_p.read_bytes()
    raw_sha = v2.sha(raw_bytes)
    raw_len = len(raw_bytes)

    # 1. Pre-execution admission gate
    definitions = v2.Definitions()
    v2.validate_spec(spec, task, definitions)

    # 2. Match Spec & Task requirements with physical snapshot
    spec_req = spec["dataset_requirements"]
    task_req = task["data_requirements"]
    v2.require(spec_req["snapshot_sha256"] == raw_sha == task_req["snapshot_sha256"], "Snapshot sha256 mismatch")
    v2.require(spec_req["snapshot_byte_length"] == raw_len == task_req["snapshot_byte_length"], "Snapshot byte length mismatch")

    # Create immutable staging output_dir
    materials_dir = out_dir / "materials"
    materials_dir.mkdir(parents=True, exist_ok=False)

    # Copy snapshot into materials if requested
    captured_snap = materials_dir / "snapshot.csv"
    if copy_snapshot:
        captured_snap.write_bytes(raw_bytes)

    # Write input task and spec into materials
    (materials_dir / "task.json").write_bytes(v2.canonical(task).encode("utf-8"))
    (materials_dir / "spec.json").write_bytes(v2.canonical(spec).encode("utf-8"))

    methods = spec["methods"]
    required_fields = spec_req["required_fields"]

    # 3. Parse CSV rows
    csv_text = raw_bytes.decode("utf-8")
    lines = [line for line in csv_text.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not lines:
        reader = []
        fieldnames = []
    else:
        reader = list(csv.DictReader(lines))
        fieldnames = list(reader[0].keys()) if reader else []

    # Check for missing required fields
    missing_fields = [f for f in required_fields if f not in fieldnames]

    run_id = f"run-screening-{uuid4().hex[:16]}"
    manifest_id = f"manifest-{run_id}"
    evidence_id = f"evidence-{run_id}"
    started_at = "2026-09-19T00:00:00.000000Z"
    completed_at = "2026-09-19T00:00:01.000000Z"

    # Determine execution status
    if _inject_failure is not None:
        run_status = "FAILED"
        status_reason = _inject_failure
    elif missing_fields or len(reader) == 0:
        run_status = "INSUFFICIENT_DATA"
        status_reason = f"Missing required fields: {missing_fields}" if missing_fields else "Empty snapshot sample"
    else:
        run_status = "COMPLETED"
        status_reason = None

    computation_manifest = {
        "profile": ssd.PROFILE_NAME,
        "snapshot_locator": spec_req["snapshot_locator"],
        "snapshot_sha256": raw_sha,
        "snapshot_byte_length": raw_len,
        "required_fields": required_fields,
        "methods": methods,
        "provenance": spec_req["provenance"],
        "status_reason": status_reason,
    }
    scientific_fingerprint = v2.digest(computation_manifest)

    # 4. Generate payloads according to status
    # dataset_metadata
    time_range = spec_req.get("time_range", {"start": started_at, "end": completed_at})
    dataset_metadata = {
        "profile": ssd.PROFILE_NAME,
        "snapshot_locator": "materials/snapshot.csv" if copy_snapshot else spec_req["snapshot_locator"],
        "snapshot_sha256": raw_sha,
        "snapshot_byte_length": raw_len,
        "required_fields": required_fields,
        "time_range": time_range,
        "sample_count": len(reader),
        "provenance": spec_req["provenance"],
        "limitations": "Synthetic screening test data.",
    }
    (out_dir / "dataset_metadata.json").write_bytes(v2.canonical(dataset_metadata).encode("utf-8"))

    # method_definition
    method_definition = {
        "profile": ssd.PROFILE_NAME,
        "methods": methods,
        "parameters": {},
        "limitations": "Deterministic facts-only screening without optimization.",
    }
    (out_dir / "method_definition.json").write_bytes(v2.canonical(method_definition).encode("utf-8"))

    # environment_lock
    environment_lock = {
        "profile": ssd.PROFILE_NAME,
        "source_sha256": v2.sha(Path(__file__).read_bytes()),
        "environment_details": "python-standard-library",
        "limitations": "Standard library deterministic execution.",
    }
    (out_dir / "environment_lock.json").write_bytes(v2.canonical(environment_lock).encode("utf-8"))

    # replay_instructions
    captured_snap_path = materials_dir / "snapshot.csv" if copy_snapshot else snap_p
    replay_instructions = {
        "profile": ssd.PROFILE_NAME,
        "command": (
            f"python -m research_lab.runners.v2_statistical_screening "
            f"--task {materials_dir / 'task.json'} "
            f"--spec {materials_dir / 'spec.json'} "
            f"--snapshot {captured_snap_path} "
            f"--output <replayed_output_dir>"
        ),
        "entry_point": "research_lab.runners.v2_statistical_screening:main",
        "limitations": "Deterministic one-shot CLI execution from captured materials.",
    }
    (out_dir / "replay_instructions.json").write_bytes(v2.canonical(replay_instructions).encode("utf-8"))

    typed_metrics = None
    missing_reason = None

    if run_status == "COMPLETED":
        try:
            # Calculate screening facts
            facts: dict[str, Any] = {}

            # 1. coverage
            if "coverage" in methods:
                total_rows = len(reader)
                valid_rows = 0
                timestamps = []
                for row in reader:
                    ts = row.get("timestamp")
                    if ts:
                        timestamps.append(ts)
                    # valid if all required fields are present and non-empty
                    if all(row.get(f) is not None and row.get(f) != "" for f in required_fields):
                        valid_rows += 1
                missing_rows = total_rows - valid_rows
                cov_ratio = _format_decimal(valid_rows / total_rows if total_rows > 0 else 0.0, 4)
                facts["coverage"] = {
                    "total_rows": total_rows,
                    "valid_rows": valid_rows,
                    "missing_rows": missing_rows,
                    "coverage_ratio": cov_ratio or "0",
                    "start_time": min(timestamps) if timestamps else None,
                    "end_time": max(timestamps) if timestamps else None,
                }

            # 2. simple_correlation
            if "simple_correlation" in methods:
                # We look for feature and target fields
                # Default to feature_val, target_val if not declared
                feat_field = "feature_val" if "feature_val" in fieldnames else (required_fields[0] if required_fields else "")
                tgt_field = "target_val" if "target_val" in fieldnames else (required_fields[1] if len(required_fields) > 1 else "")
                x_vals = []
                y_vals = []
                for row in reader:
                    try:
                        xv = float(row[feat_field])
                        yv = float(row[tgt_field])
                        x_vals.append(xv)
                        y_vals.append(yv)
                    except (ValueError, KeyError):
                        continue
                r = _compute_pearson(x_vals, y_vals)
                facts["simple_correlation"] = {
                    "sample_size": len(x_vals),
                    "pearson_ic": _format_decimal(r, 6),
                }

            # 3. direction_consistency
            if "direction_consistency" in methods:
                feat_field = "feature_val" if "feature_val" in fieldnames else (required_fields[0] if required_fields else "")
                tgt_field = "target_val" if "target_val" in fieldnames else (required_fields[1] if len(required_fields) > 1 else "")
                matches = 0
                total_pairs = 0
                for row in reader:
                    try:
                        xv = float(row[feat_field])
                        yv = float(row[tgt_field])
                        total_pairs += 1
                        if (xv >= 0 and yv >= 0) or (xv <= 0 and yv <= 0):
                            matches += 1
                    except (ValueError, KeyError):
                        continue
                consistency_ratio = _format_decimal(matches / total_pairs if total_pairs > 0 else 0.0, 4)
                facts["direction_consistency"] = {
                    "sample_size": total_pairs,
                    "matching_pairs": matches,
                    "consistency_ratio": consistency_ratio,
                }

            # 4. stability_split
            if "stability_split" in methods:
                feat_field = "feature_val" if "feature_val" in fieldnames else (required_fields[0] if required_fields else "")
                tgt_field = "target_val" if "target_val" in fieldnames else (required_fields[1] if len(required_fields) > 1 else "")
                valid_pairs = []
                for row in reader:
                    try:
                        xv = float(row[feat_field])
                        yv = float(row[tgt_field])
                        valid_pairs.append((xv, yv))
                    except (ValueError, KeyError):
                        continue
                n_tot = len(valid_pairs)
                mid = n_tot // 2
                half1 = valid_pairs[:mid]
                half2 = valid_pairs[mid:]
                r1 = _compute_pearson([p[0] for p in half1], [p[1] for p in half1])
                r2 = _compute_pearson([p[0] for p in half2], [p[1] for p in half2])
                diff = abs(r1 - r2) if r1 is not None and r2 is not None else None
                facts["stability_split"] = {
                    "split_point": f"index:{mid}",
                    "first_half_sample_size": len(half1),
                    "second_half_sample_size": len(half2),
                    "first_half_correlation": _format_decimal(r1, 6),
                    "second_half_correlation": _format_decimal(r2, 6),
                    "correlation_difference": _format_decimal(diff, 6),
                }

            # 5. leakage_audit
            if "leakage_audit" in methods:
                avail_col = "feature_availability_time" if "feature_availability_time" in fieldnames else ("availability_time" if "availability_time" in fieldnames else None)
                as_of_col = "as_of_time" if "as_of_time" in fieldnames else ("decision_time" if "decision_time" in fieldnames else ("timestamp" if "timestamp" in fieldnames else None))
                target_start_col = "target_start_time" if "target_start_time" in fieldnames else ("target_window_start_time" if "target_window_start_time" in fieldnames else None)

                total_rows = len(reader)
                if not (avail_col and as_of_col and target_start_col):
                    facts["leakage_audit"] = {
                        "rows_checked": total_rows,
                        "audited_fields": [f for f in [avail_col, as_of_col, target_start_col] if f],
                        "audit_coverage_ratio": "0",
                        "temporal_violation_count": 0,
                        "target_overlap_violation_count": 0,
                        "missing_availability_metadata": True,
                        "unverifiable_rows": total_rows,
                    }
                else:
                    temporal_violations = 0
                    target_overlap_violations = 0
                    unverifiable = 0
                    valid_checked = 0
                    for row in reader:
                        t_avail = row.get(avail_col)
                        t_as_of = row.get(as_of_col)
                        t_tgt = row.get(target_start_col)
                        if not t_avail or not t_as_of or not t_tgt:
                            unverifiable += 1
                            continue
                        valid_checked += 1
                        if t_avail > t_as_of:
                            temporal_violations += 1
                        if t_tgt <= t_as_of:
                            target_overlap_violations += 1

                    cov_ratio = _format_decimal(valid_checked / total_rows if total_rows > 0 else 0.0, 4) or "0"
                    facts["leakage_audit"] = {
                        "rows_checked": total_rows,
                        "audited_fields": [avail_col, as_of_col, target_start_col],
                        "audit_coverage_ratio": cov_ratio,
                        "temporal_violation_count": temporal_violations,
                        "target_overlap_violation_count": target_overlap_violations,
                        "missing_availability_metadata": False,
                        "unverifiable_rows": unverifiable,
                    }

            # 6. outlier_sensitivity
            if "outlier_sensitivity" in methods:
                feat_field = "feature_val" if "feature_val" in fieldnames else (required_fields[0] if required_fields else "")
                tgt_field = "target_val" if "target_val" in fieldnames else (required_fields[1] if len(required_fields) > 1 else "")
                pairs = []
                for row in reader:
                    try:
                        xv = float(row[feat_field])
                        yv = float(row[tgt_field])
                        pairs.append((xv, yv))
                    except (ValueError, KeyError):
                        continue

                total_samples = len(pairs)
                if total_samples < 2:
                    facts["outlier_sensitivity"] = {
                        "baseline_ic": None,
                        "trimmed_ic": None,
                        "removed_count": 0,
                        "removed_ratio": "0",
                        "ic_delta": None,
                        "baseline_direction": "neutral",
                        "trimmed_direction": "neutral",
                        "direction_preserved": False,
                    }
                else:
                    x_all = [p[0] for p in pairs]
                    y_all = [p[1] for p in pairs]
                    base_r = _compute_pearson(x_all, y_all)

                    cut_n = max(1, math.floor(total_samples * 0.01)) if total_samples >= 10 else 0
                    sorted_x = sorted(x_all)
                    sorted_y = sorted(y_all)

                    low_x, high_x = (sorted_x[cut_n], sorted_x[-(cut_n + 1)]) if cut_n > 0 else (sorted_x[0], sorted_x[-1])
                    low_y, high_y = (sorted_y[cut_n], sorted_y[-(cut_n + 1)]) if cut_n > 0 else (sorted_y[0], sorted_y[-1])

                    trimmed_pairs = [
                        (xv, yv) for xv, yv in pairs
                        if low_x <= xv <= high_x and low_y <= yv <= high_y
                    ]

                    removed_count = total_samples - len(trimmed_pairs)
                    rem_ratio = _format_decimal(removed_count / total_samples if total_samples > 0 else 0.0, 4) or "0"
                    trimmed_r = _compute_pearson([p[0] for p in trimmed_pairs], [p[1] for p in trimmed_pairs]) if len(trimmed_pairs) >= 2 else None

                    ic_delta = None
                    if base_r is not None and trimmed_r is not None:
                        ic_delta = _format_decimal(trimmed_r - base_r, 6)

                    base_dir = "positive" if (base_r is not None and base_r > 0) else ("negative" if (base_r is not None and base_r < 0) else "neutral")
                    trim_dir = "positive" if (trimmed_r is not None and trimmed_r > 0) else ("negative" if (trimmed_r is not None and trimmed_r < 0) else "neutral")
                    dir_preserved = (base_dir == trim_dir and base_dir != "neutral")

                    facts["outlier_sensitivity"] = {
                        "baseline_ic": _format_decimal(base_r, 6),
                        "trimmed_ic": _format_decimal(trimmed_r, 6),
                        "removed_count": removed_count,
                        "removed_ratio": rem_ratio,
                        "ic_delta": ic_delta,
                        "baseline_direction": base_dir,
                        "trimmed_direction": trim_dir,
                        "direction_preserved": dir_preserved,
                    }

            # 7. cost_sensitivity
            if "cost_sensitivity" in methods:
                feat_field = "feature_val" if "feature_val" in fieldnames else (required_fields[0] if required_fields else "")
                tgt_field = "target_val" if "target_val" in fieldnames else (required_fields[1] if len(required_fields) > 1 else "")

                pos_series = []
                ret_series = []
                for row in reader:
                    try:
                        fv = float(row[feat_field])
                        tv = float(row[tgt_field])
                        pos = 1.0 if fv > 0 else (-1.0 if fv < 0 else 0.0)
                        pos_series.append(pos)
                        ret_series.append(tv)
                    except (ValueError, KeyError):
                        continue

                n_obs = len(pos_series)
                if n_obs < 2:
                    facts["cost_sensitivity"] = {
                        "position_rule": "sign(feature_val)",
                        "observations": n_obs,
                        "turnover": "0",
                        "gross_screening_return": "0",
                        "net_return_0bps": "0",
                        "net_return_1bps": "0",
                        "net_return_3bps": "0",
                        "net_return_5bps": "0",
                        "net_return_10bps": "0",
                        "breakeven_cost_bps": None,
                    }
                else:
                    turnover_deltas = [abs(pos_series[0])]
                    gross_returns = []
                    for t in range(1, n_obs):
                        turnover_deltas.append(abs(pos_series[t] - pos_series[t - 1]))
                        gross_returns.append(pos_series[t - 1] * ret_series[t])

                    tot_turnover = sum(turnover_deltas)
                    tot_gross_ret = sum(gross_returns)

                    net_0 = tot_gross_ret - tot_turnover * 0.0000
                    net_1 = tot_gross_ret - tot_turnover * 0.0001
                    net_3 = tot_gross_ret - tot_turnover * 0.0003
                    net_5 = tot_gross_ret - tot_turnover * 0.0005
                    net_10 = tot_gross_ret - tot_turnover * 0.0010

                    breakeven = None
                    if tot_turnover > 1e-9:
                        be = (tot_gross_ret / tot_turnover) / 0.0001
                        breakeven = _format_decimal(be, 2)

                    facts["cost_sensitivity"] = {
                        "position_rule": "sign(feature_val)",
                        "observations": n_obs,
                        "turnover": _format_decimal(tot_turnover, 4) or "0",
                        "gross_screening_return": _format_decimal(tot_gross_ret, 6) or "0",
                        "net_return_0bps": _format_decimal(net_0, 6) or "0",
                        "net_return_1bps": _format_decimal(net_1, 6) or "0",
                        "net_return_3bps": _format_decimal(net_3, 6) or "0",
                        "net_return_5bps": _format_decimal(net_5, 6) or "0",
                        "net_return_10bps": _format_decimal(net_10, 6) or "0",
                        "breakeven_cost_bps": breakeven,
                    }

            statistical_summary = {
                "profile": ssd.PROFILE_NAME,
                "sample_count": len(reader),
                "methods_applied": methods,
                "facts": facts,
            }
            (out_dir / "statistical_summary.json").write_bytes(v2.canonical(statistical_summary).encode("utf-8"))
            typed_metrics = {
                "profile": ssd.PROFILE_NAME,
                "sample_count": len(reader),
                "methods_applied": methods,
                "facts": facts,
            }
            missing_reason = None
        except (ValueError, TypeError, ZeroDivisionError, KeyError, ArithmeticError, RuntimeError) as exc:
            run_status = "FAILED"
            status_reason = f"Screening calculation failed: {exc}"
            computation_manifest["status_reason"] = status_reason
            scientific_fingerprint = v2.digest(computation_manifest)

    if run_status != "COMPLETED":
        failure_diagnostics = {
            "profile": ssd.PROFILE_NAME,
            "error_type": "insufficient_data" if run_status == "INSUFFICIENT_DATA" else "execution_failed",
            "error_message": status_reason or "Screening execution failed.",
            "missing_fields": missing_fields,
            "snapshot_reference": spec_req["snapshot_locator"],
        }
        (out_dir / "failure_diagnostics.json").write_bytes(v2.canonical(failure_diagnostics).encode("utf-8"))
        typed_metrics = None
        missing_reason = "insufficient_data" if run_status == "INSUFFICIENT_DATA" else "execution_failed"

    # 5. Build Manifest entries
    roles = ["dataset_metadata", "method_definition", "environment_lock", "replay_instructions"]
    if run_status == "COMPLETED":
        roles.append("statistical_summary")
    else:
        roles.append("failure_diagnostics")

    manifest_entries = []
    for role in roles:
        fname = f"{role}.json"
        raw_f = (out_dir / fname).read_bytes()
        cat_entry = next(
            e for e in definitions.entries
            if e["kind"] == "payload" and e["name"] == f"{ssd.PAYLOAD_PREFIX}{role}"
        )
        manifest_entries.append({
            "artifact_id": f"art-{role}-{run_id}",
            "role": role,
            "classification": "required",
            "content_schema_ref": {
                "name": cat_entry["name"],
                "revision": cat_entry["revision"],
                "content_hash": cat_entry["content_hash"],
                "locator": cat_entry["locator"],
            },
            "availability": "present",
            "coverage": "complete",
            "relative_path": fname,
            "media_type": "application/json",
            "byte_length": len(raw_f),
            "content_sha256": v2.sha(raw_f),
            "producer": {
                "component": "research_lab.runners.v2_statistical_screening",
                "version": "rev.1",
            },
        })

    # Run record
    run_record = {
        "schema_version": "research_lab.run.v2",
        "hash_profile": "research-json-v1",
        "run_id": run_id,
        "run_status": run_status,
        "spec_id": spec["spec_id"],
        "spec_revision": spec["revision"],
        "spec_content_hash": spec["spec_content_hash"],
        "trial_context": {
            "research_stage": spec.get("research_stage", "validation"),
            "trial_kind": None,
            "retry_of_run_id": None,
            "holdout_usage_state": "not_applicable",
        },
        "resolved_computation_manifest": computation_manifest,
        "scientific_fingerprint": scientific_fingerprint,
        "timing": {
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "process_exit_code": 0 if run_status == "COMPLETED" else 1,
    }
    run_record["run_content_hash"] = v2.digest(run_record)
    (out_dir / "run.json").write_bytes(v2.canonical(run_record).encode("utf-8"))

    # Manifest record
    manifest_record = {
        "schema_version": "research_lab.artifact_manifest.v2",
        "hash_profile": "research-json-v1",
        "manifest_id": manifest_id,
        "revision": "rev.1",
        "run_id": run_id,
        "run_content_hash": run_record["run_content_hash"],
        "experiment_type": "statistical_factor",
        "artifact_profile": ssd.ROLE_PROFILE,
        "entries": manifest_entries,
    }
    manifest_record["manifest_content_hash"] = v2.digest(manifest_record)
    (out_dir / "manifest.json").write_bytes(v2.canonical(manifest_record).encode("utf-8"))

    # Evidence record
    present_artifacts = [
        {
            "manifest_id": manifest_id,
            "manifest_revision": "rev.1",
            "manifest_content_hash": manifest_record["manifest_content_hash"],
            "artifact_id": entry["artifact_id"],
            "role": entry["role"],
            "content_sha256": entry["content_sha256"],
        }
        for entry in manifest_entries
    ]

    evidence_record = {
        "schema_version": "research_lab.evidence.v2",
        "hash_profile": "research-json-v1",
        "evidence_id": evidence_id,
        "revision": "rev.1",
        "run_id": run_id,
        "run_status_snapshot": run_status,
        "run_content_hash": run_record["run_content_hash"],
        "execution_status": run_status,
        "manifest_id": manifest_id,
        "manifest_revision": "rev.1",
        "manifest_content_hash": manifest_record["manifest_content_hash"],
        "missing_reason": missing_reason,
        "supporting_artifacts": present_artifacts,
        "typed_metrics": typed_metrics,
    }
    evidence_record["evidence_content_hash"] = v2.digest(evidence_record)
    (out_dir / "evidence.json").write_bytes(v2.canonical(evidence_record).encode("utf-8"))

    # 6. Verify bundle self-consistency against Protocol v2
    v2.validate_manifest(out_dir, manifest_record, run_record, definitions, task=task, spec=spec)
    return out_dir


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for deterministic statistical screening runner."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m research_lab.runners.v2_statistical_screening",
        description="Deterministic statistical screening execution bridge for Protocol v2.",
    )
    parser.add_argument("--task", required=True, help="Path to Task JSON file")
    parser.add_argument("--spec", required=True, help="Path to Spec JSON file")
    parser.add_argument("--snapshot", required=True, help="Path to physical snapshot CSV file")
    parser.add_argument("--output", required=True, help="Path to output bundle directory")

    args = parser.parse_args(argv)

    task_p = Path(args.task).resolve()
    spec_p = Path(args.spec).resolve()
    snap_p = Path(args.snapshot).resolve()
    out_p = Path(args.output).resolve()

    if not task_p.is_file():
        raise FileNotFoundError(f"Task file not found: {task_p}")
    if not spec_p.is_file():
        raise FileNotFoundError(f"Spec file not found: {spec_p}")
    if not snap_p.is_file():
        raise FileNotFoundError(f"Snapshot file not found: {snap_p}")

    task = v2.parse(task_p.read_bytes())
    spec = v2.parse(spec_p.read_bytes())

    run_statistical_screening(
        task=task,
        spec=spec,
        snapshot_path=snap_p,
        output_dir=out_p,
    )
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
