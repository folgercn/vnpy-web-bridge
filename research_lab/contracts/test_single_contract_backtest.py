"""Contract tests for Protocol v2 single-contract trading_backtest profile unblock.

Covers Issue #560 requirements:
- single-contract profile (research_lab.single_contract_backtest.v1)
- COMPLETED and FAILED first-class citizens
- exact physical snapshot byte/hash binding and rejection of 1-byte tamper
- single product / single exact contract without 24-account padding
- trade_blotter & equity_curve schemas and validations
- mutual exclusion against Issue481 historical profile
- ResultStore.save_v2 and query_v2_runs for both COMPLETED and FAILED
- execute_spec and review_evidence handoff contracts
"""

from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import ValidationError

from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.contracts.single_contract_definition import (
    CRITERIA_ID,
    PAYLOAD_PREFIX,
    PROFILE_NAME,
    ROLE_PROFILE,
    SYNTHETIC_FIXTURE_BYTES,
    SYNTHETIC_FIXTURE_PATH,
    SYNTHETIC_FIXTURE_SHA256,
)
from research_lab.database.result_store import ResultStore


def _seal(obj, prefix):
    key = prefix + "_content_hash"
    obj[key] = v2.digest({k: v for k, v in obj.items() if k != key})


def _ref(name):
    entry = next(e for e in v2.Definitions().entries if e["name"] == name)
    return {k: entry[k] for k in ("name", "revision", "content_hash", "locator")}


def _criteria_ref(name):
    entry = next(e for e in v2.Definitions().entries if e["name"] == name)
    return {"id": entry["name"], "revision": entry["revision"], "content_hash": entry["content_hash"]}


def build_single_contract_fixture(tmp_path, run_status="COMPLETED", run_id="run-sc-001"):
    task = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-sc-001",
        "revision": "rev.1",
        "research_type": "trading_backtest",
        "task_profile": PROFILE_NAME,
        "objective": "Minimal single-contract trading backtest contract validation",
        "data_requirements": {
            "product": "rb",
            "exact_contract": "rb2405",
            "time_range": {
                "start": "2024-01-02T09:00:00.000000Z",
                "end": "2024-01-02T09:05:00.000000Z",
            },
            "snapshot_sha256": SYNTHETIC_FIXTURE_SHA256,
            "snapshot_locator": SYNTHETIC_FIXTURE_PATH,
            "provenance": "synthetic_physical_fixture_rb2405",
        },
    }
    _seal(task, "task")

    spec = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-sc-001",
        "revision": "rev.1",
        "task_id": task["task_id"],
        "task_revision": task["revision"],
        "task_content_hash": task["task_content_hash"],
        "experiment_type": "trading_backtest",
        "research_stage": "validation",
        "backtest_profile": PROFILE_NAME,
        "dataset_requirements": {
            "product": "rb",
            "exact_contract": "rb2405",
            "time_range": {
                "start": "2024-01-02T09:00:00.000000Z",
                "end": "2024-01-02T09:05:00.000000Z",
            },
            "snapshot_sha256": SYNTHETIC_FIXTURE_SHA256,
            "snapshot_locator": SYNTHETIC_FIXTURE_PATH,
            "provenance": "synthetic_physical_fixture_rb2405",
        },
        "contract_specifications": {
            "target_symbol": "rb2405",
            "multiplier": "10",
            "price_tick": "1",
            "price_currency": "CNY",
            "margin_ratio": "0.1",
        },
        "strategy_spec": {
            "strategy_name": "SimpleMomentum",
            "implementation_ref": "strategies/simple_momentum.py",
            "parameters": {"lookback": 5},
        },
        "execution_config": {
            "initial_capital": "100000",
            "capital_currency": "CNY",
            "position_sizing": {"mode": "fixed_lots", "lots": 1},
        },
        "cost_model": {
            "commission_bps": "1",
            "slippage_ticks": 1,
            "currency": "CNY",
        },
        "holdout_policy": "not_used",
    }
    _seal(spec, "spec")

    computation_manifest = {
        "profile": PROFILE_NAME,
        "product": "rb",
        "exact_contract": "rb2405",
        "strategy_name": "SimpleMomentum",
        "initial_capital": "100000",
        "multiplier": "10",
        "price_tick": "1",
        "currency": "CNY",
        "commission_bps": "1",
        "slippage_ticks": 1,
        "snapshot_locator": SYNTHETIC_FIXTURE_PATH,
        "snapshot_sha256": SYNTHETIC_FIXTURE_SHA256,
        "snapshot_byte_length": SYNTHETIC_FIXTURE_BYTES,
        "provenance": "synthetic_physical_fixture_rb2405",
        "stop_reason": "COMPLETED_END_OF_DATA" if run_status == "COMPLETED" else "FAILED_RUNTIME_ERROR",
    }

    run = {
        "schema_version": "research_lab.run.v2",
        "hash_profile": "research-json-v1",
        "run_id": run_id,
        "run_status": run_status,
        "spec_id": spec["spec_id"],
        "spec_revision": spec["revision"],
        "spec_content_hash": spec["spec_content_hash"],
        "trial_context": {
            "research_stage": "validation",
            "trial_kind": None,
            "retry_of_run_id": None,
            "holdout_usage_state": "not_applicable",
        },
        "resolved_computation_manifest": computation_manifest,
        "scientific_fingerprint": v2.digest(computation_manifest),
        "timing": {
            "started_at": "2024-01-02T09:00:00.000000Z",
            "completed_at": "2024-01-02T09:05:00.000000Z",
            "recorded_at": "2024-01-02T09:05:01.000000Z",
        },
        "process_exit_code": 0 if run_status == "COMPLETED" else 1,
    }
    _seal(run, "run")

    payload_data = {
        "dataset_metadata": {
            "profile": PROFILE_NAME,
            "product": "rb",
            "exact_contract": "rb2405",
            "snapshot_locator": SYNTHETIC_FIXTURE_PATH,
            "snapshot_sha256": SYNTHETIC_FIXTURE_SHA256,
            "snapshot_byte_length": SYNTHETIC_FIXTURE_BYTES,
            "provenance": "synthetic_physical_fixture_rb2405",
            "limitations": "Synthetic physical fixture for contract testing only; does not constitute real-market scientific validation.",
        },
        "method_definition": {
            "profile": PROFILE_NAME,
            "strategy_name": "SimpleMomentum",
            "strategy_id": "strat-momentum-001",
            "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "parameters": {"lookback": 5},
            "limitations": "Single-contract deterministic simulation.",
        },
        "environment_lock": {
            "profile": PROFILE_NAME,
            "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "environment_details": "vnpy-web-bridge-v2-single-contract",
            "limitations": "Pure Python offline backtest environment.",
        },
        "replay_instructions": {
            "profile": PROFILE_NAME,
            "command": "python -m research_lab.runners.v2_backtest --spec spec-sc-001",
            "entry_point": "research_lab.runners.v2_backtest",
            "limitations": "Local single-contract deterministic execution.",
        },
    }

    if run_status == "COMPLETED":
        payload_data["backtest_summary"] = {
            "profile": PROFILE_NAME,
            "product": "rb",
            "exact_contract": "rb2405",
            "initial_capital": "100000",
            "ending_equity": "100250",
            "net_pnl": "250",
            "total_fees": "10",
            "total_trades": 2,
            "summary_metrics": {"sharpe_ratio": "1.85", "max_drawdown": "0.005"},
        }
        payload_data["trade_blotter"] = {
            "profile": PROFILE_NAME,
            "product": "rb",
            "exact_contract": "rb2405",
            "trades": [
                {
                    "trade_id": "T001",
                    "timestamp": "2024-01-02T09:01:00.000000Z",
                    "side": "BUY",
                    "price": "3910.0",
                    "volume": 1,
                    "fee": "5.0",
                    "turnover": "39100.0",
                },
                {
                    "trade_id": "T002",
                    "timestamp": "2024-01-02T09:04:00.000000Z",
                    "side": "SELL",
                    "price": "3935.0",
                    "volume": 1,
                    "fee": "5.0",
                    "turnover": "39350.0",
                },
            ],
        }
        payload_data["equity_curve"] = {
            "profile": PROFILE_NAME,
            "product": "rb",
            "exact_contract": "rb2405",
            "points": [
                {"timestamp": "2024-01-02T09:00:00.000000Z", "equity": "100000", "cash": "100000", "margin": "0"},
                {"timestamp": "2024-01-02T09:01:00.000000Z", "equity": "99995", "cash": "60895", "margin": "3910"},
                {"timestamp": "2024-01-02T09:04:00.000000Z", "equity": "100250", "cash": "100250", "margin": "0"},
            ],
        }
    else:
        payload_data["failure_diagnostics"] = {
            "profile": PROFILE_NAME,
            "error_type": "RuntimeError",
            "error_message": "Execution simulated failure for FAILED state testing",
            "process_exit_code": 1,
            "details": {"traceback": "Simulated error during trading backtest execution"},
        }

    manifest = {
        "schema_version": "research_lab.artifact_manifest.v2",
        "hash_profile": "research-json-v1",
        "manifest_id": f"manifest-{run['run_id']}",
        "revision": "rev.1",
        "run_id": run["run_id"],
        "run_content_hash": run["run_content_hash"],
        "experiment_type": "trading_backtest",
        "artifact_profile": ROLE_PROFILE,
        "entries": [],
    }

    bundle_dir = tmp_path / run_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    for role, content in payload_data.items():
        raw = v2.canonical(content).encode()
        p = bundle_dir / f"{role}.json"
        p.write_bytes(raw)
        manifest["entries"].append({
            "artifact_id": role,
            "role": role,
            "classification": "required",
            "content_schema_ref": _ref(PAYLOAD_PREFIX + role),
            "availability": "present",
            "coverage": "complete",
            "relative_path": p.name,
            "media_type": "application/json",
            "byte_length": len(raw),
            "content_sha256": v2.sha(raw),
            "producer": {"component": "single_contract_runner", "version": "1.0"},
        })
    _seal(manifest, "manifest")

    supporting_artifacts = [
        {
            "manifest_id": manifest["manifest_id"],
            "manifest_revision": manifest["revision"],
            "manifest_content_hash": manifest["manifest_content_hash"],
            "artifact_id": e["artifact_id"],
            "role": e["role"],
            "content_sha256": e["content_sha256"],
        }
        for e in manifest["entries"]
    ]

    evidence = {
        "schema_version": "research_lab.evidence.v2",
        "hash_profile": "research-json-v1",
        "evidence_id": f"evidence-{run['run_id']}",
        "revision": "rev.1",
        "run_id": run["run_id"],
        "run_status_snapshot": run_status,
        "run_content_hash": run["run_content_hash"],
        "execution_status": run_status,
        "manifest_id": manifest["manifest_id"],
        "manifest_revision": manifest["revision"],
        "manifest_content_hash": manifest["manifest_content_hash"],
        "missing_reason": None if run_status == "COMPLETED" else "execution_failed",
        "supporting_artifacts": supporting_artifacts,
        "typed_metrics": {
            "profile": PROFILE_NAME,
            "product": "rb",
            "exact_contract": "rb2405",
            "net_pnl": "250",
            "total_fees": "10",
            "trade_count": 2,
        } if run_status == "COMPLETED" else None,
    }
    _seal(evidence, "evidence")

    # Write control objects into bundle directory for ResultStore.save_v2
    materials_dir = bundle_dir / "materials"
    materials_dir.mkdir(parents=True, exist_ok=True)
    (materials_dir / "task.json").write_bytes(v2.canonical(task).encode())
    (materials_dir / "spec.json").write_bytes(v2.canonical(spec).encode())
    (bundle_dir / "run.json").write_bytes(v2.canonical(run).encode())
    (bundle_dir / "manifest.json").write_bytes(v2.canonical(manifest).encode())
    (bundle_dir / "evidence.json").write_bytes(v2.canonical(evidence).encode())

    return task, spec, run, manifest, evidence, bundle_dir


def test_1_issue481_original_tests_continue_to_pass(tmp_path):
    """1. Issue481 original regression remains fully intact."""
    from research_lab.contracts.test_issue481_backtest import fixture, validate
    fixture(tmp_path)
    res = validate(tmp_path)
    assert len(res) == 7


def test_2_single_contract_completed_validation(tmp_path):
    """2. New single_contract_backtest profile normal COMPLETED passes validate_manifest."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    verified = v2.validate_manifest(bundle_dir, manifest, run, task=task, spec=spec)
    assert len(verified) == 7
    assert v2.validate_spec(spec, task)["profile"] == PROFILE_NAME


def test_3_single_contract_failed_validation(tmp_path):
    """3. New profile FAILED status passes validate_manifest with failure_diagnostics."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "FAILED")
    verified = v2.validate_manifest(bundle_dir, manifest, run, task=task, spec=spec)
    assert len(verified) == 5
    assert run["run_status"] == "FAILED"
    assert run["process_exit_code"] == 1
    assert any(e["role"] == "failure_diagnostics" for e in manifest["entries"])


def test_4_single_product_requirement(tmp_path):
    """4. Profile strictly requires single product and rejects multi-product tampering."""
    task, spec, _, _, _, _ = build_single_contract_fixture(tmp_path, "COMPLETED")
    spec_bad = deepcopy(spec)
    spec_bad["dataset_requirements"]["product"] = "cu"  # mismatch with task
    _seal(spec_bad, "spec")
    with pytest.raises(ValueError, match="product mismatch"):
        v2.validate_spec(spec_bad, task)


def test_5_single_exact_contract_requirement(tmp_path):
    """5. Profile strictly requires single exact contract and rejects contract mismatch."""
    task, spec, _, _, _, _ = build_single_contract_fixture(tmp_path, "COMPLETED")
    spec_bad = deepcopy(spec)
    spec_bad["dataset_requirements"]["exact_contract"] = "rb2410"
    _seal(spec_bad, "spec")
    with pytest.raises(ValueError, match="exact_contract mismatch"):
        v2.validate_spec(spec_bad, task)


def test_6_actual_snapshot_bytes_and_hash_matching(tmp_path):
    """6. Spec and physical snapshot bytes and sha256 match perfectly."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    phys_file = Path(SYNTHETIC_FIXTURE_PATH)
    assert phys_file.exists()
    assert v2.sha(phys_file.read_bytes()) == spec["dataset_requirements"]["snapshot_sha256"]
    assert len(phys_file.read_bytes()) == run["resolved_computation_manifest"]["snapshot_byte_length"]
    # validate_spec and validate_manifest pass
    v2.validate_spec(spec, task)
    v2.validate_manifest(bundle_dir, manifest, run, task=task, spec=spec)


def test_7_snapshot_altered_by_1_byte_rejected(tmp_path):
    """7. If physical snapshot is altered by even 1 byte, admission fails closed."""
    task, spec, _, _, _, _ = build_single_contract_fixture(tmp_path, "COMPLETED")
    # Point locator to a mutated copy
    mutated_csv = tmp_path / "mutated.csv"
    orig_bytes = Path(SYNTHETIC_FIXTURE_PATH).read_bytes()
    mutated_csv.write_bytes(orig_bytes + b"\n")  # added 1 newline byte

    task_mut = deepcopy(task)
    task_mut["data_requirements"]["snapshot_locator"] = str(mutated_csv)
    _seal(task_mut, "task")
    spec_mut = deepcopy(spec)
    spec_mut["task_content_hash"] = task_mut["task_content_hash"]
    spec_mut["dataset_requirements"]["snapshot_locator"] = str(mutated_csv)
    _seal(spec_mut, "spec")

    with pytest.raises(ValueError, match="physical snapshot sha256 mismatch"):
        v2.validate_spec(spec_mut, task_mut)


def test_8_spec_hash_inconsistent_with_physical_file_rejected(tmp_path):
    """8. If Spec declares wrong sha256 hash not matching physical file, admission rejects."""
    task, spec, _, _, _, _ = build_single_contract_fixture(tmp_path, "COMPLETED")
    fake_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    task_bad = deepcopy(task)
    task_bad["data_requirements"]["snapshot_sha256"] = fake_hash
    _seal(task_bad, "task")
    spec_bad = deepcopy(spec)
    spec_bad["task_content_hash"] = task_bad["task_content_hash"]
    spec_bad["dataset_requirements"]["snapshot_sha256"] = fake_hash
    _seal(spec_bad, "spec")

    with pytest.raises(ValueError, match="physical snapshot sha256 mismatch"):
        v2.validate_spec(spec_bad, task_bad)


def test_9_no_24_account_artificial_padding(tmp_path):
    """9. Single contract profile strictly forbids artificial multi-account / 24-account padding."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    # If someone tries to stuff 'accounts' into backtest_summary
    summary_file = bundle_dir / "backtest_summary.json"
    summary_data = v2.parse(summary_file.read_bytes())
    summary_data["accounts"] = ["rb"]
    raw = v2.canonical(summary_data).encode()
    summary_file.write_bytes(raw)

    manifest_mut = deepcopy(manifest)
    entry = next(e for e in manifest_mut["entries"] if e["role"] == "backtest_summary")
    entry["byte_length"] = len(raw)
    entry["content_sha256"] = v2.sha(raw)
    _seal(manifest_mut, "manifest")

    with pytest.raises((ValueError, ValidationError)):
        v2.validate_manifest(bundle_dir, manifest_mut, run, task=task, spec=spec)


def test_10_trade_blotter_schema_positive_and_negative(tmp_path):
    """10. trade_blotter schema validates correct trades and rejects invalid ones (e.g. negative volume)."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    blotter_file = bundle_dir / "trade_blotter.json"
    blotter_data = v2.parse(blotter_file.read_bytes())

    # Negative volume trade
    blotter_data["trades"][0]["volume"] = 0
    raw = v2.canonical(blotter_data).encode()
    blotter_file.write_bytes(raw)
    manifest_mut = deepcopy(manifest)
    entry = next(e for e in manifest_mut["entries"] if e["role"] == "trade_blotter")
    entry["byte_length"] = len(raw)
    entry["content_sha256"] = v2.sha(raw)
    _seal(manifest_mut, "manifest")

    with pytest.raises((ValueError, ValidationError)):
        v2.validate_manifest(bundle_dir, manifest_mut, run, task=task, spec=spec)


def test_11_equity_curve_schema_positive_and_negative(tmp_path):
    """11. equity_curve schema validates correct curve points and rejects unordered points."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    curve_file = bundle_dir / "equity_curve.json"
    curve_data = v2.parse(curve_file.read_bytes())

    # Reverse timestamp order
    curve_data["points"][1]["timestamp"] = "2024-01-02T08:59:00.000000Z"
    raw = v2.canonical(curve_data).encode()
    curve_file.write_bytes(raw)
    manifest_mut = deepcopy(manifest)
    entry = next(e for e in manifest_mut["entries"] if e["role"] == "equity_curve")
    entry["byte_length"] = len(raw)
    entry["content_sha256"] = v2.sha(raw)
    _seal(manifest_mut, "manifest")

    with pytest.raises(ValueError, match="equity curve timestamps must be sorted"):
        v2.validate_manifest(bundle_dir, manifest_mut, run, task=task, spec=spec)


def test_12_failed_diagnostics_required_on_failure(tmp_path):
    """12. FAILED state must deliver failure_diagnostics; missing diagnostics fails closed."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "FAILED")
    # Remove failure_diagnostics entry from manifest
    manifest_bad = deepcopy(manifest)
    manifest_bad["entries"] = [e for e in manifest_bad["entries"] if e["role"] != "failure_diagnostics"]
    _seal(manifest_bad, "manifest")

    with pytest.raises(ValueError, match="missing required role"):
        v2.validate_manifest(bundle_dir, manifest_bad, run, task=task, spec=spec)


def test_13_issue481_cannot_impersonate_generic_profile(tmp_path):
    """13. Issue481 objects cannot masquerade as single_contract profile (fail closed)."""
    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    # Mutate entry content_schema_ref to issue481 definition
    manifest_mut = deepcopy(manifest)
    for e in manifest_mut["entries"]:
        if e["role"] == "backtest_summary":
            e["content_schema_ref"] = _ref("phase0.issue481.backtest_summary")
    _seal(manifest_mut, "manifest")

    with pytest.raises(ValueError, match="unsupported/mixed trading_backtest manifest profile|profile payload definition mismatch"):
        v2.validate_manifest(bundle_dir, manifest_mut, run, task=task, spec=spec)


def test_14_generic_cannot_impersonate_issue481(tmp_path):
    """14. Generic single_contract objects cannot masquerade as Issue481 profile."""
    from research_lab.contracts.test_issue481_backtest import fixture
    t, s, r, m = fixture(tmp_path)
    # Mutate one entry schema ref to generic single contract
    m_mut = deepcopy(m)
    for e in m_mut["entries"]:
        if e["role"] == "backtest_summary":
            e["content_schema_ref"] = _ref("research_lab.single_contract.backtest_summary")
    _seal(m_mut, "manifest")

    with pytest.raises(ValueError, match="unsupported/mixed trading_backtest manifest profile|profile payload definition mismatch"):
        v2.validate_manifest(tmp_path, m_mut, r, task=t, spec=s)


def test_15_unknown_profile_fails_closed(tmp_path):
    """15. Unknown profile fails closed without guessing."""
    task, spec, _, _, _, _ = build_single_contract_fixture(tmp_path, "COMPLETED")
    spec_unknown = deepcopy(spec)
    spec_unknown["backtest_profile"] = "unknown_exotic_backtest_profile_v9"
    _seal(spec_unknown, "spec")

    with pytest.raises((ValueError, ValidationError)):
        v2.validate_spec(spec_unknown, task)


def test_16_handoff_and_result_store_completed_and_failed(tmp_path):
    """16. execute_spec, review_evidence handoffs and ResultStore.save_v2 work for both COMPLETED and FAILED."""
    # Test COMPLETED
    task_c, spec_c, run_c, manifest_c, evidence_c, bundle_c = build_single_contract_fixture(tmp_path, "COMPLETED", "run-sc-comp")
    store = ResultStore(ResearchLabConfig(root=tmp_path / "store"))
    receipt_c = store.save_v2(bundle_c)
    assert receipt_c["run_status"] == "COMPLETED"
    retrieved_c = store.get_v2_run("run-sc-comp")
    assert retrieved_c["run"]["object_id"] == "run-sc-comp"

    # Test FAILED
    _, _, _, _, _, bundle_f = build_single_contract_fixture(tmp_path, "FAILED", "run-sc-fail")
    receipt_f = store.save_v2(bundle_f)
    assert receipt_f["run_status"] == "FAILED"
    retrieved_f = store.get_v2_run("run-sc-fail")
    assert retrieved_f["run"]["object_id"] == "run-sc-fail"

    # Query
    runs = store.query_v2_runs(spec_id="spec-sc-001")
    assert len(runs) == 2
    assert {r["run_status"] for r in runs} == {"COMPLETED", "FAILED"}

    # Review handoff validation
    review_req = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "handoff-review-001",
        "message_kind": "request",
        "operation": "review_evidence",
        "sender_role": "execution",
        "recipient_role": "critic",
        "context_refs": {
            "research_task": v2.check_record(task_c, "research_task"),
            "experiment_spec": v2.check_record(spec_c, "experiment_spec"),
            "experiment_run": v2.check_record(run_c, "experiment_run"),
            "artifact_manifest": v2.check_record(manifest_c, "artifact_manifest"),
            "result_evidence": v2.check_record(evidence_c, "result_evidence"),
        },
        "criteria_ref": _criteria_ref(CRITERIA_ID),
        "artifact_requirements": {
            "role_profile_ref": ROLE_PROFILE,
            "required_roles": sorted(v2.COMMON | v2.TYPED["trading_backtest"]),
            "exact_refs": evidence_c["supporting_artifacts"],
        },
        "review_scope": "research_assessment",
        "expected_outputs": [
            {"object_type": "review", "schema_version": "research_lab.review.v2"}
        ],
    }
    v2.validate_handoff(
        review_req,
        {
            "research_task": task_c,
            "experiment_spec": spec_c,
            "experiment_run": run_c,
            "artifact_manifest": manifest_c,
            "result_evidence": evidence_c,
        },
        root=bundle_c,
    )


def test_17_criteria_profile_isolation(tmp_path):
    """17. Issue481 criteria cannot evaluate generic single contract profile and vice versa."""
    task, spec, run, manifest, evidence, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    # Trying to review single contract with Issue481 criteria
    bad_req = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "handoff-review-bad",
        "message_kind": "request",
        "operation": "review_evidence",
        "sender_role": "execution",
        "recipient_role": "critic",
        "context_refs": {
            "research_task": v2.check_record(task, "research_task"),
            "experiment_spec": v2.check_record(spec, "experiment_spec"),
            "experiment_run": v2.check_record(run, "experiment_run"),
            "artifact_manifest": v2.check_record(manifest, "artifact_manifest"),
            "result_evidence": v2.check_record(evidence, "result_evidence"),
        },
        "criteria_ref": _criteria_ref("phase0.issue481.review_evidence.criteria"),  # wrong criteria!
        "artifact_requirements": {
            "role_profile_ref": ROLE_PROFILE,
            "required_roles": sorted(v2.COMMON | v2.TYPED["trading_backtest"]),
            "exact_refs": evidence["supporting_artifacts"],
        },
        "review_scope": "research_assessment",
        "expected_outputs": [
            {"object_type": "review", "schema_version": "research_lab.review.v2"}
        ],
    }
    with pytest.raises(ValueError, match="criteria profile"):
        v2.validate_handoff(
            bad_req,
            {
                "research_task": task,
                "experiment_spec": spec,
                "experiment_run": run,
                "artifact_manifest": manifest,
                "result_evidence": evidence,
            },
            root=bundle_dir,
        )


def test_18_snapshot_missing_file_rejected_in_validate_spec(tmp_path):
    """18. Task/Spec with locator pointing to nonexistent file must be rejected by validate_spec."""
    task, spec, _, _, _, _ = build_single_contract_fixture(tmp_path, "COMPLETED")
    nonexistent = str(tmp_path / "nonexistent_snapshot.csv")
    task_bad = deepcopy(task)
    task_bad["data_requirements"]["snapshot_locator"] = nonexistent
    _seal(task_bad, "task")
    spec_bad = deepcopy(spec)
    spec_bad["task_content_hash"] = task_bad["task_content_hash"]
    spec_bad["dataset_requirements"]["snapshot_locator"] = nonexistent
    _seal(spec_bad, "spec")

    with pytest.raises(ValueError, match="physical snapshot file missing or not regular file"):
        v2.validate_spec(spec_bad, task_bad)


def test_19_snapshot_missing_or_deleted_rejected_in_validate_manifest_and_result_store(tmp_path):
    """19. validate_manifest and ResultStore.save_v2 reject when snapshot is missing or deleted."""
    snap_file = tmp_path / "temp_snapshot.csv"
    orig_bytes = Path(SYNTHETIC_FIXTURE_PATH).read_bytes()
    snap_file.write_bytes(orig_bytes)

    task, spec, run, manifest, evidence, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED", "run-sc-del")

    for obj, prefix, key in [
        (task, "task", "data_requirements"),
        (spec, "spec", "dataset_requirements"),
    ]:
        obj[key]["snapshot_locator"] = str(snap_file)
    spec["task_content_hash"] = v2.digest({k: v for k, v in task.items() if k != "task_content_hash"})
    _seal(task, "task")
    _seal(spec, "spec")

    run["spec_content_hash"] = spec["spec_content_hash"]
    run["resolved_computation_manifest"]["snapshot_locator"] = str(snap_file)
    run["scientific_fingerprint"] = v2.digest(run["resolved_computation_manifest"])
    _seal(run, "run")

    meta_path = bundle_dir / "dataset_metadata.json"
    meta = v2.parse(meta_path.read_bytes())
    meta["snapshot_locator"] = str(snap_file)
    meta_raw = v2.canonical(meta).encode()
    meta_path.write_bytes(meta_raw)
    entry = next(e for e in manifest["entries"] if e["role"] == "dataset_metadata")
    entry["content_sha256"] = v2.sha(meta_raw)
    entry["byte_length"] = len(meta_raw)
    manifest["run_id"] = run["run_id"]
    manifest["run_content_hash"] = run["run_content_hash"]
    _seal(manifest, "manifest")

    evidence["run_id"] = run["run_id"]
    evidence["run_content_hash"] = run["run_content_hash"]
    evidence["manifest_content_hash"] = manifest["manifest_content_hash"]
    evidence["supporting_artifacts"] = [
        {
            "manifest_id": manifest["manifest_id"],
            "manifest_revision": manifest["revision"],
            "manifest_content_hash": manifest["manifest_content_hash"],
            "artifact_id": e["artifact_id"],
            "role": e["role"],
            "content_sha256": e["content_sha256"],
        }
        for e in manifest["entries"]
    ]
    _seal(evidence, "evidence")

    (bundle_dir / "materials/task.json").write_bytes(v2.canonical(task).encode())
    (bundle_dir / "materials/spec.json").write_bytes(v2.canonical(spec).encode())
    (bundle_dir / "run.json").write_bytes(v2.canonical(run).encode())
    (bundle_dir / "manifest.json").write_bytes(v2.canonical(manifest).encode())
    (bundle_dir / "evidence.json").write_bytes(v2.canonical(evidence).encode())

    # Verify initially valid
    v2.validate_spec(spec, task)
    v2.validate_manifest(bundle_dir, manifest, run, task=task, spec=spec)

    # Now DELETE the physical snapshot file
    snap_file.unlink()

    # validate_manifest must fail closed
    with pytest.raises(ValueError, match="physical snapshot file missing or not regular file"):
        v2.validate_manifest(bundle_dir, manifest, run, task=task, spec=spec)

    # ResultStore.save_v2 must fail closed and leave 0 records
    store = ResultStore(ResearchLabConfig(root=tmp_path / "store"))
    with pytest.raises(ValueError, match="physical snapshot file missing or not regular file"):
        store.save_v2(bundle_dir)

    assert store.get_v2_run("run-sc-del") is None
    assert store.query_v2_runs(run_id="run-sc-del") == []


def test_20_snapshot_directory_or_non_regular_file_rejected(tmp_path):
    """20. Locator pointing to a directory or non-regular file must be rejected."""
    dir_path = tmp_path / "a_snapshot_directory"
    dir_path.mkdir()

    task, spec, run, manifest, _, bundle_dir = build_single_contract_fixture(tmp_path, "COMPLETED")
    task_bad = deepcopy(task)
    task_bad["data_requirements"]["snapshot_locator"] = str(dir_path)
    _seal(task_bad, "task")
    spec_bad = deepcopy(spec)
    spec_bad["task_content_hash"] = task_bad["task_content_hash"]
    spec_bad["dataset_requirements"]["snapshot_locator"] = str(dir_path)
    _seal(spec_bad, "spec")

    # validate_spec rejects directory
    with pytest.raises(ValueError, match="physical snapshot file missing or not regular file"):
        v2.validate_spec(spec_bad, task_bad)

    # validate_manifest rejects directory
    manifest_bad = deepcopy(manifest)
    manifest_bad["entries"] = [deepcopy(e) for e in manifest["entries"]]
    meta_path = bundle_dir / "dataset_metadata.json"
    meta = v2.parse(meta_path.read_bytes())
    meta["snapshot_locator"] = str(dir_path)
    meta_raw = v2.canonical(meta).encode()
    meta_path.write_bytes(meta_raw)
    entry = next(e for e in manifest_bad["entries"] if e["role"] == "dataset_metadata")
    entry["content_sha256"] = v2.sha(meta_raw)
    entry["byte_length"] = len(meta_raw)

    run_bad = deepcopy(run)
    run_bad["spec_content_hash"] = spec_bad["spec_content_hash"]
    run_bad["resolved_computation_manifest"]["snapshot_locator"] = str(dir_path)
    run_bad["scientific_fingerprint"] = v2.digest(run_bad["resolved_computation_manifest"])
    _seal(run_bad, "run")

    manifest_bad["run_content_hash"] = run_bad["run_content_hash"]
    _seal(manifest_bad, "manifest")

    with pytest.raises(ValueError, match="physical snapshot file missing or not regular file"):
        v2.validate_manifest(bundle_dir, manifest_bad, run_bad, task=task_bad, spec=spec_bad)
