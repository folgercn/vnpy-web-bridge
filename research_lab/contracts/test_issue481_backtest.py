"""Synthetic-only structural contract tests for the Issue481 retrospective mapping."""

import pytest
from jsonschema import ValidationError
from research_lab.contracts import v2

P = ["ag", "au", "cu", "rb", "ru", "sc"]
SNAP = "f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351"
IDENTITIES = [
    {
        "path": path,
        "scenario": scenario,
        "product": product,
        "account_id": f"{path}:{scenario}:{product}",
    }
    for path in ("CANDIDATE", "PAIRED")
    for scenario in ("PRIMARY_2S", "STRESS_5S")
    for product in P
]


def seal(x, p):
    x[p + "_content_hash"] = v2.digest(
        {k: v for k, v in x.items() if k != p + "_content_hash"}
    )


def ref(name):
    e = next(e for e in v2.Definitions().entries if e["name"] == name)
    return {k: e[k] for k in ("name", "revision", "content_hash", "locator")}


def fixture(tmp):
    t = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-issue481",
        "revision": "rev.1",
        "research_type": "trading_backtest",
        "objective": "synthetic only",
        "data_requirements": {
            "products": P,
            "dev_dates": ["2023-01-03", "2024-12-31"],
            "warmup_from": "2022-09-01",
        },
    }
    seal(t, "task")
    s = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-issue481",
        "revision": "rev.1",
        "task_id": t["task_id"],
        "task_revision": "rev.1",
        "task_content_hash": t["task_content_hash"],
        "experiment_type": "trading_backtest",
        "research_stage": "validation",
        "dataset_requirements": {
            "products": P,
            "accounts": P,
            "time_range": {
                "start": "2023-01-03T00:00:00.000000Z",
                "end": "2024-12-31T00:00:00.000000Z",
            },
            "warmup_from": "2022-09-01",
            "snapshot_sha256": SNAP,
        },
        "method_id": "phase0.issue481_minimal_causal_replay.rev1",
        "corrected_events": 603,
        "cost_model": "official_pit_mapping_with_modeled_close_today_fee",
        "holdout_policy": "unknown",
    }
    seal(s, "spec")
    c = {
        "method_id": "phase0.issue481_minimal_causal_replay.rev1",
        "products": P,
        "corrected_events": 603,
        "stop_reason": "STOP_ECONOMIC_GATE",
        "snapshot_sha256": SNAP,
        "accounts": P,
        "dev_dates": ["2023-01-03", "2024-12-31"],
        "warmup_from": "2022-09-01",
        "cost_scenarios": {
            "primary_bbo_ticks": 1,
            "primary_window_seconds": 2,
            "stress_bbo_ticks": 3,
            "stress_window_seconds": 5,
            "stress_fee_multiplier": "1.25",
            "fee_model": "official_pit_mapping_with_modeled_close_today_fee",
        },
    }
    r = {
        "schema_version": "research_lab.run.v2",
        "hash_profile": "research-json-v1",
        "run_id": "run-issue481",
        "run_status": "COMPLETED",
        "spec_id": s["spec_id"],
        "spec_revision": "rev.1",
        "spec_content_hash": s["spec_content_hash"],
        "trial_context": {
            "research_stage": "validation",
            "trial_kind": None,
            "retry_of_run_id": None,
            "holdout_usage_state": "unknown",
        },
        "resolved_computation_manifest": c,
        "scientific_fingerprint": v2.digest(c),
        "timing": {
            "started_at": None,
            "completed_at": None,
            "recorded_at": "2026-09-17T00:00:00.000000Z",
        },
        "process_exit_code": 3,
    }
    seal(r, "run")
    data = {
        "dataset_metadata": {
            "profile": "issue481_corrected603_structural",
            "products": P,
            "snapshot_sha256": SNAP,
            "limitations": "Synthetic structural fixture; historical blotter and equity curve are external and unavailable.",
        },
        "method_definition": {
            "method": "scripts/issue481_minimal_causal_replay.py",
            "corrected_events": 603,
            "stop_reason": "STOP_ECONOMIC_GATE",
            "limitations": "Historical modeled BBO and fee assumptions; not real execution.",
        },
        "environment_lock": {
            "profile": "issue481_corrected603_structural",
            "source_sha256": "3798178e2b265f6001dc607fe89add68f1f0f583ae85ddf62ddead38e677577c",
            "limitations": "Synthetic structural fixture; historical blotter and equity curve are external and unavailable.",
        },
        "replay_instructions": {
            "profile": "issue481_corrected603_structural",
            "events": 603,
            "limitations": "Structural validation only; no historical replay is performed.",
        },
        "backtest_summary": {
            "products": P,
            "accounts": P,
            "corrected_events": 603,
            "stop_reason": "STOP_ECONOMIC_GATE",
            "net_pnl_cny": "-1",
            "fees_cny": "0",
            "account_identities": IDENTITIES,
        },
        "trade_blotter": {
            "fixture": "synthetic_structural_fixture",
            "accounts": P,
            "account_identities": IDENTITIES,
            "fills": [
                {
                    "account": "rb",
                    "product": "rb",
                    "path": "CANDIDATE",
                    "scenario": "PRIMARY_2S",
                    "account_id": "CANDIDATE:PRIMARY_2S:rb",
                    "exact_contract": "rb2401",
                    "fill_sequence": 1,
                    "fee_provenance": "modeled_close_today_or_official_pit_fee",
                }
            ],
            "limitations": "Synthetic fills only; target-changes is not a complete blotter.",
        },
        "equity_curve": {
            "fixture": "synthetic_structural_fixture",
            "accounts": P,
            "account_identities": IDENTITIES,
            "points": [
                {
                    "account": row["product"],
                    "product": row["product"],
                    "path": row["path"],
                    "scenario": row["scenario"],
                    "account_id": row["account_id"],
                    "sequence": 1,
                    "official_day": "2023-01-03",
                    "equity_cny": "0",
                }
                for row in IDENTITIES
            ],
            "limitations": "Synthetic points only; historical equity curve is external and unavailable.",
        },
    }
    m = {
        "schema_version": "research_lab.artifact_manifest.v2",
        "hash_profile": "research-json-v1",
        "manifest_id": "manifest-issue481",
        "revision": "rev.1",
        "run_id": r["run_id"],
        "run_content_hash": r["run_content_hash"],
        "experiment_type": "trading_backtest",
        "artifact_profile": "research_lab.artifact_roles.v2.candidate1",
        "entries": [],
    }
    for role, x in data.items():
        raw = v2.canonical(x).encode()
        path = tmp / (role + ".json")
        path.write_bytes(raw)
        m["entries"].append(
            {
                "artifact_id": role,
                "role": role,
                "classification": "required"
                if role
                in {
                    "dataset_metadata",
                    "method_definition",
                    "environment_lock",
                    "replay_instructions",
                    "backtest_summary",
                }
                else "supporting",
                "content_schema_ref": ref("phase0.issue481." + role),
                "availability": "present",
                "coverage": "complete",
                "relative_path": path.name,
                "media_type": "application/json",
                "byte_length": len(raw),
                "content_sha256": v2.sha(raw),
                "producer": {"component": "fixture", "version": "0"},
            }
        )
    seal(m, "manifest")
    return t, s, r, m


def validate(tmp):
    t, s, r, m = fixture(tmp)
    return v2.validate_manifest(tmp, m, r, task=t, spec=s)


def test_valid_negative_and_zero(tmp_path):
    assert len(validate(tmp_path)) == 7


@pytest.mark.parametrize(
    "kind", ["missing", "profile", "accounts", "fee", "order", "exit", "snapshot"]
)
def test_issue481_rejects(tmp_path, kind):
    t, s, r, m = fixture(tmp_path)
    if kind == "missing":
        m["entries"].pop()
    elif kind == "profile":
        m["entries"][0]["content_schema_ref"] = ref("phase0.dataset_metadata")
    elif kind == "accounts":
        e = next(e for e in m["entries"] if e["role"] == "backtest_summary")
        p = tmp_path / e["relative_path"]
        x = v2.parse(p.read_bytes())
        x["accounts"] = ["rb"]
        raw = v2.canonical(x).encode()
        p.write_bytes(raw)
        e.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    elif kind == "fee":
        e = next(e for e in m["entries"] if e["role"] == "trade_blotter")
        p = tmp_path / e["relative_path"]
        x = v2.parse(p.read_bytes())
        x["fills"][0].pop("fee_provenance")
        raw = v2.canonical(x).encode()
        p.write_bytes(raw)
        e.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    elif kind == "order":
        e = next(e for e in m["entries"] if e["role"] == "trade_blotter")
        p = tmp_path / e["relative_path"]
        x = v2.parse(p.read_bytes())
        x["fills"] *= 2
        x["fills"][1]["fill_sequence"] = 0
        raw = v2.canonical(x).encode()
        p.write_bytes(raw)
        e.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    elif kind == "exit":
        r["process_exit_code"] = 2
        seal(r, "run")
        m["run_content_hash"] = r["run_content_hash"]
    else:
        s["dataset_requirements"]["snapshot_sha256"] = "0" * 64
        seal(s, "spec")
        r["spec_content_hash"] = s["spec_content_hash"]
        seal(r, "run")
        m["run_content_hash"] = r["run_content_hash"]
    seal(m, "manifest")
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_manifest(tmp_path, m, r, task=t, spec=s)


@pytest.mark.parametrize(
    "role, field",
    [
        ("backtest_summary", "net_pnl_cny"),
        ("backtest_summary", "fees_cny"),
        ("equity_curve", "equity_cny"),
    ],
)
def test_issue481_cny_precision_rehashed(tmp_path, role, field):
    task, spec, run, manifest = fixture(tmp_path)
    entry = next(e for e in manifest["entries"] if e["role"] == role)
    path = tmp_path / entry["relative_path"]
    for value, accepted in [("-2.1234567891", True), ("-2.12345678901", False)]:
        content = v2.parse(path.read_bytes())
        if role == "equity_curve":
            content["points"][0][field] = value
        else:
            content[field] = value
        if field == "fees_cny" and value.startswith("-"):
            accepted = False
        raw = v2.canonical(content).encode()
        path.write_bytes(raw)
        entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
        seal(manifest, "manifest")
        if accepted:
            v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)
        else:
            with pytest.raises(ValidationError):
                v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)


def test_issue481_missing_equity_account_rejected(tmp_path):
    task, spec, run, manifest = fixture(tmp_path)
    entry = next(e for e in manifest["entries"] if e["role"] == "equity_curve")
    path = tmp_path / entry["relative_path"]
    content = v2.parse(path.read_bytes())
    content["points"].pop()
    raw = v2.canonical(content).encode()
    path.write_bytes(raw)
    entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    seal(manifest, "manifest")
    with pytest.raises(ValueError, match="missing equity account"):
        v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)


@pytest.mark.parametrize(
    "field, value", [("path", "PAIRED"), ("scenario", "STRESS_5S"), ("product", "rb")]
)
def test_issue481_rehashed_equity_identity_rejected(tmp_path, field, value):
    task, spec, run, manifest = fixture(tmp_path)
    entry = next(e for e in manifest["entries"] if e["role"] == "equity_curve")
    path = tmp_path / entry["relative_path"]
    content = v2.parse(path.read_bytes())
    content["points"][0][field] = value
    raw = v2.canonical(content).encode()
    path.write_bytes(raw)
    entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    seal(manifest, "manifest")
    with pytest.raises(ValueError, match="equity account identity"):
        v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)


def test_issue481_rehashed_duplicate_equity_point_rejected(tmp_path):
    task, spec, run, manifest = fixture(tmp_path)
    entry = next(e for e in manifest["entries"] if e["role"] == "equity_curve")
    path = tmp_path / entry["relative_path"]
    content = v2.parse(path.read_bytes())
    content["points"].append(content["points"][0])
    raw = v2.canonical(content).encode()
    path.write_bytes(raw)
    entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    seal(manifest, "manifest")
    with pytest.raises(ValueError, match="equity point order"):
        v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)


@pytest.mark.parametrize(
    "contract, accepted",
    [("rb2401", True), ("ag2501", True), ("rbarbitrary", False), ("ag2401", False)],
)
def test_issue481_rehashed_exact_contract_rejected(tmp_path, contract, accepted):
    task, spec, run, manifest = fixture(tmp_path)
    entry = next(e for e in manifest["entries"] if e["role"] == "trade_blotter")
    path = tmp_path / entry["relative_path"]
    content = v2.parse(path.read_bytes())
    content["fills"][0]["exact_contract"] = contract
    raw = v2.canonical(content).encode()
    path.write_bytes(raw)
    entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    seal(manifest, "manifest")
    if accepted:
        if contract.startswith("ag"):
            content["fills"][0].update(
                account="ag", product="ag", account_id="CANDIDATE:PRIMARY_2S:ag"
            )
            raw = v2.canonical(content).encode()
            path.write_bytes(raw)
            entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
            seal(manifest, "manifest")
        v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)
    else:
        with pytest.raises((ValueError, ValidationError)):
            v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)


@pytest.mark.parametrize("mutation", ["rb２４０１", "2024-99-99", "2023-02-29"])
def test_issue481_rehashed_ascii_contract_and_calendar_rejected(tmp_path, mutation):
    task, spec, run, manifest = fixture(tmp_path)
    role = "trade_blotter" if mutation.startswith("rb") else "equity_curve"
    entry = next(e for e in manifest["entries"] if e["role"] == role)
    path = tmp_path / entry["relative_path"]
    content = v2.parse(path.read_bytes())
    if role == "trade_blotter":
        content["fills"][0]["exact_contract"] = mutation
    else:
        content["points"][0]["official_day"] = mutation
    raw = v2.canonical(content).encode()
    path.write_bytes(raw)
    entry.update(byte_length=len(raw), content_sha256=v2.sha(raw))
    seal(manifest, "manifest")
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_manifest(tmp_path, manifest, run, task=task, spec=spec)
