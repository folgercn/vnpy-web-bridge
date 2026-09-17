"""Real archived objects and adversarial copies; no new research execution."""

import copy
import tarfile
from pathlib import Path

import pytest
from jsonschema import ValidationError

from research_lab.contracts import v2


@pytest.fixture
def bundle(tmp_path):
    archive = v2.ROOT / "research/phase0_data_quality/bundles/validation-rev1-ci.tar.gz"
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            relative = member.name
            assert not relative.startswith("/") and ".." not in Path(relative).parts
            assert member.isfile() or member.isdir()
            if member.isfile():
                target = tmp_path / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.extractfile(member).read())
    return tmp_path


def load(root, name):
    return v2.parse(v2.safe_read(root, name + ".json"))


def records(root):
    return {
        k: load(root, p)
        for k, p in [
            ("research_task", "materials/task"),
            ("experiment_spec", "materials/spec"),
            ("experiment_run", "run"),
            ("artifact_manifest", "manifest"),
            ("result_evidence", "evidence"),
            ("review", "review"),
        ]
    }


def reseal(obj, prefix):
    obj[prefix + "_content_hash"] = v2.digest(
        {k: v for k, v in obj.items() if k != prefix + "_content_hash"}
    )


def test_real_archived_chain(bundle):
    obj = records(bundle)
    assert v2.validate_spec(obj["experiment_spec"], obj["research_task"]) == {
        "source_order": {"strict": True}
    }
    payload = v2.validate_manifest(
        bundle, obj["artifact_manifest"], obj["experiment_run"]
    )
    assert payload["quality_summary"]["comparison_count"] == 179
    assert v2.validate_handoff(
        load(bundle, "review-request"), obj, load(bundle, "review-response")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "role",
        "duplicate",
        "path",
        "hash",
        "schema_hash",
        "schema_name",
        "missing",
        "shard",
        "debug",
        "unavailable",
        "unknown_field",
    ],
)
def test_manifest_rejects(bundle, mutation):
    obj = records(bundle)
    manifest = obj["artifact_manifest"]
    entry = manifest["entries"][0]
    if mutation == "role":
        manifest["entries"].pop()
    elif mutation == "duplicate":
        manifest["entries"][1]["artifact_id"] = entry["artifact_id"]
    elif mutation == "path":
        entry["relative_path"] = "../escape.json"
    elif mutation == "hash":
        entry["content_sha256"] = "0" * 64
    elif mutation == "schema_hash":
        entry["content_schema_ref"]["content_hash"] = "0" * 64
    elif mutation == "schema_name":
        entry["content_schema_ref"]["name"] = "unknown"
    elif mutation == "missing":
        (bundle / entry["relative_path"]).unlink()
    elif mutation == "shard":
        extra = copy.deepcopy(entry)
        extra["artifact_id"] = "shard2"
        extra["relative_path"] = "shard2.json"
        manifest["entries"].append(extra)
    elif mutation == "debug":
        entry["classification"] = "debug"
    elif mutation == "unavailable":
        entry["availability"] = "unavailable"
    else:
        manifest["verified"] = True
    reseal(manifest, "manifest")
    with pytest.raises((ValueError, ValidationError, OSError)):
        v2.validate_manifest(bundle, manifest, obj["experiment_run"])


@pytest.mark.parametrize(
    "mutation", ["method", "parameter", "unit", "range", "metric", "snapshot", "task"]
)
def test_spec_rejects(bundle, mutation):
    obj = records(bundle)
    spec = obj["experiment_spec"]
    task = obj["research_task"]
    if mutation == "method":
        spec["quality_checks"][0]["implementation_ref"] = "missing.rev1"
    elif mutation in ("parameter", "unit"):
        spec["quality_checks"][0]["parameters"] = [
            {
                "name": "wrong" if mutation == "parameter" else "strict",
                "value_type": "boolean",
                "value": True,
                "unit": "wrong" if mutation == "unit" else "dimensionless",
            }
        ]
    elif mutation == "range":
        spec["dataset_requirements"]["time_range"]["end"] = spec[
            "dataset_requirements"
        ]["time_range"]["start"]
    elif mutation == "metric":
        spec["metric_specifications"][0]["calculation_definition"] = "different formula"
    elif mutation == "snapshot":
        spec["dataset_requirements"]["snapshot_sha256"] = None
    else:
        spec["task_id"] = "other-task"
    reseal(spec, "spec")
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_spec(spec, task)


@pytest.mark.parametrize(
    "mutation",
    ["criteria", "context", "response", "payload_ref", "evidence_ref", "output"],
)
def test_handoff_rejects(bundle, mutation):
    obj = records(bundle)
    request = load(bundle, "review-request")
    response = load(bundle, "review-response")
    if mutation == "criteria":
        obj["review"]["criteria_ref"]["revision"] = "rev.2"
        reseal(obj["review"], "review")
        response["output_refs"][0] = v2.check_record(obj["review"], "review")
    elif mutation == "context":
        request["context_refs"]["experiment_run"]["content_hash"] = "0" * 64
    elif mutation == "response":
        response["in_reply_to"] = "other"
    elif mutation == "payload_ref":
        request["artifact_requirements"]["exact_refs"][0]["content_sha256"] = "0" * 64
    elif mutation == "evidence_ref":
        obj["result_evidence"]["run_id"] = "other"
        reseal(obj["result_evidence"], "evidence")
        request["context_refs"]["result_evidence"] = v2.check_record(
            obj["result_evidence"], "result_evidence"
        )
    else:
        response["output_refs"][0]["content_hash"] = "0" * 64
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, obj, response)


def test_no_links_or_external_schemas(bundle):
    (bundle / "link.json").symlink_to(bundle / "run.json")
    with pytest.raises(OSError):
        v2.safe_read(bundle, "link.json")
    with pytest.raises(ValueError, match="external schema"):
        v2.schema_check({}, {"$ref": "https://example.com/schema.json"})


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":-0}', b'{"a":9007199254740992}']
)
def test_profile_rejects(raw):
    with pytest.raises(ValueError):
        v2.parse(raw)


def test_rehashed_invalid_payload_rejected(bundle):
    obj = records(bundle)
    manifest = obj["artifact_manifest"]
    entry = next(e for e in manifest["entries"] if e["role"] == "quality_summary")
    raw = v2.canonical({"unexpected": 0}).encode()
    (bundle / entry["relative_path"]).write_bytes(raw)
    entry.update(content_sha256=v2.sha(raw), byte_length=len(raw))
    reseal(manifest, "manifest")
    with pytest.raises(ValidationError):
        v2.validate_manifest(bundle, manifest, obj["experiment_run"])


def test_both_sides_cannot_invent_criteria(bundle):
    obj = records(bundle)
    request = load(bundle, "review-request")
    response = load(bundle, "review-response")
    request["criteria_ref"]["content_hash"] = "0" * 64
    obj["review"]["criteria_ref"] = copy.deepcopy(request["criteria_ref"])
    reseal(obj["review"], "review")
    response["output_refs"][0] = v2.check_record(obj["review"], "review")
    with pytest.raises(ValueError, match="definition reference mismatch"):
        v2.validate_handoff(request, obj, response)


def test_failed_manifest_diagnostic_delivery(bundle):
    obj = records(bundle)
    run = obj["experiment_run"]
    manifest = obj["artifact_manifest"]
    run["run_status"] = "FAILED"
    reseal(run, "run")
    manifest["run_content_hash"] = run["run_content_hash"]
    template = copy.deepcopy(manifest["entries"][0])
    for entry in manifest["entries"]:
        if entry["role"] in ("quality_summary", "quality_anomalies"):
            for name in (
                "relative_path",
                "media_type",
                "byte_length",
                "content_sha256",
                "producer",
            ):
                entry.pop(name)
            entry.update(
                availability="unavailable",
                coverage="none",
                unavailable_reason="execution_interrupted",
            )
    definition = next(
        e for e in v2.Definitions().entries if e.get("role") == "failure_diagnostics"
    )
    template.update(
        artifact_id="failure",
        role="failure_diagnostics",
        relative_path="failure.json",
        content_schema_ref={
            k: definition[k] for k in ("name", "revision", "content_hash", "locator")
        },
    )
    raw = v2.canonical(
        {
            "error_type": "ValueError",
            "message": "synthetic failure",
            "stage": "quality_scan",
        }
    ).encode()
    (bundle / "failure.json").write_bytes(raw)
    template.update(content_sha256=v2.sha(raw), byte_length=len(raw))
    manifest["entries"].append(template)
    reseal(manifest, "manifest")
    assert "failure" in v2.validate_manifest(bundle, manifest, run)
    manifest["entries"].pop()
    reseal(manifest, "manifest")
    with pytest.raises(ValueError, match="missing required role"):
        v2.validate_manifest(bundle, manifest, run)


@pytest.mark.parametrize(
    "field", ["reviewer", "reviewed_at", "recommendation", "reason"]
)
def test_incomplete_self_hashed_review_rejected(bundle, field):
    obj = records(bundle)
    request = load(bundle, "review-request")
    response = load(bundle, "review-response")
    obj["review"].pop(field)
    reseal(obj["review"], "review")
    response["output_refs"][0] = v2.check_record(obj["review"], "review")
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, obj, response)


@pytest.mark.parametrize(
    "kind,field,prefix",
    [
        ("research_task", "objective", "task"),
        ("experiment_run", "timing", "run"),
        ("result_evidence", "typed_metrics", "evidence"),
    ],
)
def test_incomplete_control_rejected(bundle, kind, field, prefix):
    obj = records(bundle)
    request = load(bundle, "review-request")
    obj[kind].pop(field)
    reseal(obj[kind], prefix)
    request["context_refs"][kind] = v2.check_record(obj[kind], kind)
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, obj)


def hash_vectors():
    return v2.parse(
        v2.safe_read(v2.ROOT, "docs/research-lab/protocol-v2-hash-vectors.json")
    )


def test_research_json_v1_hash_vectors():
    assert v2.validate_hash_vectors(hash_vectors())


@pytest.mark.parametrize(
    "section,index,field,value",
    [
        ("positive", 0, "canonical_utf8", "{}"),
        ("positive", 0, "sha256", "0" * 64),
        ("positive", 9, "field_types", {"rate": "timestamp"}),
        ("positive", 12, "self_hash_field", "task_content_hash"),
        ("negative", 0, "expected", "accept"),
    ],
)
def test_hash_vector_metadata_tampering_rejected(section, index, field, value):
    vectors = hash_vectors()
    vectors[section][index][field] = value
    with pytest.raises(ValueError):
        v2.validate_hash_vectors(vectors)



@pytest.mark.parametrize(
    "section,mutation",
    [
        ("positive", "delete"),
        ("negative", "delete"),
        ("positive", "rename"),
        ("negative", "rename"),
        ("positive", "clear"),
        ("negative", "clear"),
    ],
)
def test_hash_vector_collection_tampering_rejected(section, mutation):
    vectors = hash_vectors()
    if mutation == "delete":
        vectors[section].pop()
    elif mutation == "rename":
        vectors[section][0]["name"] = "renamed"
    else:
        vectors[section].clear()
    with pytest.raises(ValueError):
        v2.validate_hash_vectors(vectors)



def test_negative_hash_vector_field_types_tampering_rejected():
    vectors = hash_vectors()
    vectors["negative"][8]["field_types"] = []
    with pytest.raises(ValueError, match="field types"):
        v2.validate_hash_vectors(vectors)


def test_legal_negative_hash_vector_input_with_bad_field_types_rejected():
    vectors = hash_vectors()
    vectors["negative"][8].update(
        raw_json='{"a":1}', field_types={"a": "decimal"}
    )
    with pytest.raises(ValueError, match="typed field must be a string"):
        v2.validate_hash_vectors(vectors)


def test_invalid_negative_raw_still_rejects_wrong_field_types_metadata():
    vectors = hash_vectors()
    vectors["negative"][0]["field_types"] = {"bogus": "decimal"}
    with pytest.raises(ValueError, match="negative hash vector field types"):
        v2.validate_hash_vectors(vectors)


def test_self_hash_excludes_only_declared_root_field():
    raw = b'{"spec_content_hash":"self","nested":{"spec_content_hash":"kept"}}'
    canonical, _ = v2.hash_json(raw, {}, "spec_content_hash")
    assert canonical == b'{"nested":{"spec_content_hash":"kept"}}'
    with pytest.raises(ValueError):
        v2.hash_json(raw, {}, "missing_content_hash")


def test_hash_json_never_guesses_string_field_types():
    raw = b'{"plain":"2024-01-01T08:00:00+08:00"}'
    canonical, content_hash = v2.hash_json(raw)
    assert canonical == raw
    assert content_hash == v2.sha(raw)
    with pytest.raises(ValueError, match="UTC timestamp"):
        v2.hash_json(raw, {"plain": "timestamp"})
    with pytest.raises(ValueError, match="invalid UTF-8"):
        v2.hash_json(b'{"plain":"\xff"}')


TREND20_METRICS = [
    {
        "metric_name": "ic_pearson_cross_sectional",
        "calculation_definition_version": "phase0.trend20.daily_pearson_ic.rev1",
        "unit": "correlation",
        "sample_scope": "daily cross sections with at least four samples",
        "precision_rule": "Round published decimal to 12 places, ROUND_HALF_EVEN; do not round daily inputs.",
        "calculation_definition": "Pearson correlation of same-day Trend20 feature and t+1..t+6 same-contract forward log return, then mean unrounded daily values.",
        "undefined_policy": "null_with_reason_not_zero",
    },
    {
        "metric_name": "top_bottom_spread",
        "calculation_definition_version": "phase0.trend20.top2_bottom2.rev1",
        "unit": "log_return",
        "sample_scope": "daily cross sections with at least four samples",
        "precision_rule": "Round published decimal to 12 places, ROUND_HALF_EVEN; do not round daily inputs.",
        "calculation_definition": "Mean unrounded daily top2 minus bottom2 same-contract forward log-return spread.",
        "undefined_policy": "null_with_reason_not_zero",
    },
]


def trend20_spec_task():
    task = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-phase0-trend20",
        "revision": "rev.1",
        "research_type": "statistical_factor",
        "objective": "Retrospective Trend20 structural contract only.",
        "data_requirements": {"date_start": "2023-01-03", "date_end_exclusive": "2024-12-31", "fields": ["settlement", "open_interest", "exact_contract"], "products": ["ag", "au", "cu", "rb", "ru", "sc"]},
    }
    reseal(task, "task")
    spec = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-phase0-trend20",
        "revision": "rev.1",
        "task_id": task["task_id"],
        "task_revision": "rev.1",
        "task_content_hash": task["task_content_hash"],
        "experiment_type": "statistical_factor",
        "research_stage": "exploration",
        "dataset_requirements": {
            "provider_kind": "historical_derived",
            "dataset_reference_uri": "candidate://phase0/trend20",
            "snapshot_selection_mode": "fixed_snapshot",
            "snapshot_sha256": "f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351",
            "universe": ["ag", "au", "cu", "rb", "ru", "sc"],
            "frequencies": ["1d"],
            "time_range": {
                "start": "2023-01-03T00:00:00.000000Z",
                "end": "2024-12-31T00:00:00.000000Z",
            },
            "required_fields": ["settlement", "open_interest", "exact_contract"],
            "pit_constraints": "No historical collector receipt proof.",
        },
        "feature_specification": {
            "feature_name": "Trend20 same exact contract",
            "implementation_ref": "phase0.trend20_same_exact_contract.feature.rev1",
            "parameters": [
                {
                    "name": "lookback_official_days",
                    "value_type": "integer",
                    "value": 20,
                    "unit": "official_day",
                }
            ],
            "pit_alignment": {
                "required_receipt": "unavailable historically",
                "signal_decision_point": "retrospective exploration",
            },
        },
        "target_specification": {
            "target_name": "forward5 log return",
            "implementation_ref": "phase0.trend20_same_exact_contract.forward5_log_return.rev1",
            "horizon_trading_days": 6,
            "return_interval": "t+1_to_t+6_same_exact_contract",
            "target_type": "forward_log_return",
        },
        "split_and_leakage_control": {
            "method": "retrospective_exploration_no_split",
            "train_window_days": 1,
            "test_window_days": 1,
            "step_size_days": 1,
            "leakage_mitigation": {
                "purging_rule": "overlapping_labels_retained_and_disclosed",
                "embargo_days": 0,
            },
        },
        "candidate_decision_criteria": {},
        "metric_specifications": copy.deepcopy(TREND20_METRICS),
        "rejection_policy": {
            "forbid_unknown_fields": True,
            "reject_unregistered_implementation": True,
            "reject_backtest_metrics_in_pure_statistical_spec": True,
        },
        "holdout_policy": {
            "mode": "not_used",
            "reason": "retrospective exploration, not a holdout.",
        },
    }
    reseal(spec, "spec")
    return task, spec


def trend20_bundle(tmp_path):
    _, spec = trend20_spec_task()
    computation = {"method_id": "phase0.trend20_same_exact_contract.rev1", "feature_parameters": {"lookback_official_days": 20}, "target_parameters": {"start_offset_official_days": 1, "end_offset_official_days": 6}, "universe": ["ag", "au", "cu", "rb", "ru", "sc"], "scientific_time": {"start": "2023-01-03T00:00:00.000000Z", "end": "2024-12-31T00:00:00.000000Z", "warmup_from": "2022-09-01T00:00:00.000000Z"}, "snapshot_sha256": "f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351", "status": "synthetic_structural_fixture_not_historical_execution"}
    run = {"schema_version": "research_lab.run.v2", "hash_profile": "research-json-v1", "run_id": "run-phase0-trend20-structural", "run_status": "COMPLETED", "spec_id": spec["spec_id"], "spec_revision": spec["revision"], "spec_content_hash": spec["spec_content_hash"], "trial_context": {"research_stage": "exploration", "trial_kind": None, "retry_of_run_id": None, "holdout_usage_state": "not_used_retrospective"}, "resolved_computation_manifest": computation, "scientific_fingerprint": v2.digest(computation), "timing": {"started_at": None, "completed_at": None, "recorded_at": "2026-09-17T00:00:00.000000Z"}, "process_exit_code": 0}
    reseal(run, "run")
    manifest = {"schema_version": "research_lab.artifact_manifest.v2", "hash_profile": "research-json-v1", "manifest_id": "manifest-phase0-trend20-structural", "revision": "rev.1", "artifact_profile": "research_lab.artifact_roles.v2.candidate1"}
    payloads = {
        "dataset_metadata": {
            "case_kind": "retrospective_trend20_structural_fixture",
            "snapshot_sha256": "f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351",
            "source_manifest": "docs/research-lab/phase0-validation/input-manifest.json",
            "source_member": "curve_contract_daily.csv",
            "source_bytes": 14187500,
            "receipt_evidence": None,
            "limitations": "Historical derived table; no collector receipt evidence; structural fixture is not a native v2 execution.",
        },
        "method_definition": {
            "method_id": "phase0.trend20_same_exact_contract.rev1",
            "feature": "log(settlement(t)/settlement(t-20 official days)) for same exact contract",
            "target": "log(settlement(t+6)/settlement(t+1)) for same exact contract",
            "selection": "eligible_curve_contract=True; maximum t open_interest per product; ties exact_contract ascending",
            "precision": "float64; published decimals rounded half-even to 12 decimal places; means use unrounded daily values",
            "limitations": "exploration; overlapping labels; no significance test; no Alpha or confirmation claim",
        },
        "environment_lock": {
            "case_kind": "retrospective_trend20_structural_fixture",
            "runtime_lock": "docs/research-lab/phase0-validation/runtime-lock.json",
            "calculation_script_sha256": "bce98d04365d8bda5200a14bcfffcb63fac6eb7ce0fae872bada6e077d940e75",
            "limitations": "Synthetic structural payload only; historical full detail remains external and unavailable.",
        },
        "replay_instructions": {
            "case_kind": "retrospective_trend20_structural_fixture",
            "input_manifest": "docs/research-lab/phase0-validation/input-manifest.json",
            "steps": "Verify fixed input hashes; calculate same-contract Trend20 and t+1..t+6 forward labels; compute daily Pearson IC; round published values half-even to 12 decimals.",
            "comparison": "Compare structural fields only; unavailable historical full sample and daily payloads prevent complete replay.",
            "limitations": "Not a prospective registration or native v2 execution.",
        },
        "statistical_summary": {
            "method_id": "phase0.trend20_same_exact_contract.rev1",
            "research_stage": "exploration",
            "sample_count": 2868,
            "date_count": 478,
            "mean_daily_pearson_ic": "-0.012667903046",
            "mean_top2_minus_bottom2_forward_log_return": "-0.001355555878",
            "precision": "half_even_12_decimal_places_from_unrounded_daily_values",
            "significance_test": "not_performed",
            "label_overlap": True,
        },
        "sample_feature_target": {
            "case_kind": "synthetic_structural_fixture_not_historical_full_detail",
            "rows": [
                {
                    "official_day": "2023-01-03",
                    "product": "rb",
                    "exact_contract": "rb2305",
                    "feature_log_return": "0.01",
                    "forward_log_return": "-0.02",
                    "split": "exploration_all",
                }
            ],
            "fields": [
                "official_day",
                "product",
                "exact_contract",
                "feature_log_return",
                "forward_log_return",
                "split",
            ],
            "units": {
                "feature_log_return": "log_return",
                "forward_log_return": "log_return",
            },
            "limitations": "Synthetic rows exercise structure only; #540 full sample payload is externally referenced and unavailable.",
        },
        "daily_ic_series": {
            "case_kind": "synthetic_structural_fixture_not_historical_full_detail",
            "metric": "daily_cross_sectional_pearson_ic",
            "precision": "half_even_12_decimal_places_from_unrounded_daily_values",
            "rows": [
                {
                    "official_day": "2023-01-03",
                    "pearson_ic": "-0.012667903046",
                    "sample_count": 6,
                    "undefined_reason": None,
                }
            ],
            "limitations": "Synthetic rows exercise structure only; #540 full daily IC payload is externally referenced and unavailable.",
        },
    }
    manifest["experiment_type"], manifest["run_id"], manifest["run_content_hash"] = (
        "statistical_factor",
        run["run_id"],
        run["run_content_hash"],
    )
    manifest["entries"] = []
    for role, content in payloads.items():
        raw = v2.canonical(content).encode()
        path = f"payload/{role}.json"
        target = tmp_path / path
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(raw)
        entry = next(
            e
            for e in v2.Definitions().entries
            if e["kind"] == "payload" and e["name"] == f"phase0.trend20.{role}"
        )
        manifest["entries"].append(
            {
                "artifact_id": role,
                "availability": "present",
                "byte_length": len(raw),
                "classification": "required"
                if role
                in {
                    "dataset_metadata",
                    "method_definition",
                    "environment_lock",
                    "replay_instructions",
                    "statistical_summary",
                }
                else "supporting",
                "content_schema_ref": {
                    k: entry[k] for k in ("name", "revision", "content_hash", "locator")
                },
                "content_sha256": v2.sha(raw),
                "coverage": "complete",
                "media_type": "application/json",
                "producer": {"component": "structural_fixture", "version": "0" * 64},
                "relative_path": path,
                "role": role,
            }
        )
    reseal(manifest, "manifest")
    return spec, run, manifest


def test_trend20_structural_statistical_delivery(tmp_path):
    task, spec = trend20_spec_task()
    assert v2.validate_spec(spec, task)["feature"]["id"].endswith("feature.rev1")
    spec, run, manifest = trend20_bundle(tmp_path)
    assert set(v2.validate_manifest(tmp_path, manifest, run, spec=spec)) == {
        e["artifact_id"] for e in manifest["entries"]
    }


@pytest.mark.parametrize(
    "mutation",
    ["missing", "wrong_definition", "corrupt", "reference", "type", "metric"],
)
def test_trend20_statistical_rejects(tmp_path, mutation):
    task, spec = trend20_spec_task()
    spec, run, manifest = trend20_bundle(tmp_path)
    if mutation == "metric":
        spec["metric_specifications"][0]["calculation_definition"] = "wrong"
        reseal(spec, "spec")
        with pytest.raises(ValueError):
            v2.validate_spec(spec, task)
        return
    entry = next(
        e
        for e in manifest["entries"]
        if e["role"]
        == (
            "statistical_summary"
            if mutation in ("wrong_definition", "type")
            else "sample_feature_target"
            if mutation == "missing"
            else "daily_ic_series"
        )
    )
    if mutation == "missing":
        (tmp_path / entry["relative_path"]).unlink()
    elif mutation == "corrupt":
        (tmp_path / entry["relative_path"]).write_bytes(b"{}")
    elif mutation == "reference":
        entry["content_schema_ref"]["revision"] = "rev.2"
    elif mutation == "type":
        data = v2.parse((tmp_path / entry["relative_path"]).read_bytes())
        data["sample_count"] = "2868"
        raw = v2.canonical(data).encode()
        (tmp_path / entry["relative_path"]).write_bytes(raw)
        entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    else:
        data = v2.parse((tmp_path / entry["relative_path"]).read_bytes())
        data["precision"] = "wrong"
        raw = v2.canonical(data).encode()
        (tmp_path / entry["relative_path"]).write_bytes(raw)
        entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    reseal(manifest, "manifest")
    with pytest.raises((ValueError, ValidationError, OSError)):
        v2.validate_manifest(tmp_path, manifest, run, spec=spec)


@pytest.mark.parametrize("field", ["research_stage", "method_id", "feature_parameters", "target_parameters", "universe", "scientific_time", "snapshot_sha256"])
def test_trend20_rehashed_run_binding_rejected(tmp_path, field):
    spec, run, manifest = trend20_bundle(tmp_path)
    if field == "research_stage":
        run["trial_context"][field] = "validation"
    elif field == "method_id":
        run["resolved_computation_manifest"][field] = "candidate.carry.rev1"
    elif field == "feature_parameters":
        run["resolved_computation_manifest"][field] = {"lookback_official_days": 19}
    elif field == "target_parameters":
        run["resolved_computation_manifest"][field] = {"start_offset_official_days": 1, "end_offset_official_days": 20}
    elif field == "universe":
        run["resolved_computation_manifest"][field] = ["rb"]
    elif field == "scientific_time":
        run["resolved_computation_manifest"][field]["end"] = "2024-12-30T00:00:00.000000Z"
    else:
        run["resolved_computation_manifest"][field] = "0" * 64
    run["scientific_fingerprint"] = v2.digest(run["resolved_computation_manifest"])
    reseal(run, "run")
    manifest["run_content_hash"] = run["run_content_hash"]
    reseal(manifest, "manifest")
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_manifest(tmp_path, manifest, run, spec=spec)


def test_trend20_rehashed_dq_run_rejected(tmp_path):
    spec, run, manifest = trend20_bundle(tmp_path)
    run["resolved_computation_manifest"]["status"] = "synthetic_structural_fixture_not_historical_execution"
    run["trial_context"]["holdout_usage_state"] = "not_used_retrospective"
    run["resolved_computation_manifest"]["method_id"] = "candidate.phase0.source_order.rev1"
    run["scientific_fingerprint"] = v2.digest(run["resolved_computation_manifest"])
    reseal(run, "run")
    manifest["run_content_hash"] = run["run_content_hash"]
    reseal(manifest, "manifest")
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_manifest(tmp_path, manifest, run, spec=spec)


def test_trend20_malformed_task_rejected():
    task, spec = trend20_spec_task()
    task.pop("data_requirements")
    reseal(task, "task")
    with pytest.raises(ValidationError):
        v2.validate_spec(spec, task)
