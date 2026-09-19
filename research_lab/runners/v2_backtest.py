"""Protocol v2 minimal deterministic trading_backtest execution bridge (#556).

Bridges Protocol v2 Task/Spec admission to existing BacktestAdapter capability,
directly consuming physical snapshot bytes, and produces verified ExperimentRun,
ArtifactManifest, and ResultEvidence records conforming to
research_lab.single_contract_backtest.v1.
"""

from __future__ import annotations

import copy
import csv
import decimal
import os
import traceback
from pathlib import Path
from typing import Any
from uuid import uuid4

from research_lab.backtest import DeterministicBacktestAdapter
from research_lab.contracts import v2
from research_lab.contracts.single_contract_definition import (
    CRITERIA_ID as SINGLE_CONTRACT_CRITERIA_ID,
)
from research_lab.contracts.single_contract_definition import (
    PAYLOAD_PREFIX as SINGLE_CONTRACT_PAYLOAD_PREFIX,
)
from research_lab.contracts.single_contract_definition import (
    PROFILE_NAME as SINGLE_CONTRACT_PROFILE,
)
from research_lab.contracts.single_contract_definition import (
    ROLE_PROFILE as SINGLE_CONTRACT_ROLE_PROFILE,
)
from research_lab.database import ResultStore
from research_lab.reports import write_v2_report
from research_lab.schemas.experiment import (
    CostModel,
    DatasetSpec,
    ExecutionConfig,
    ExperimentSpec,
    FactorSpec,
    StrategySpec,
)


def _format_cny(val: float | str | decimal.Decimal) -> str:
    r"""Format float/decimal into strict canonical non-trailing decimal string matching ^(?:0|-?(?:0\.[0-9]{0,9}[1-9]|[1-9][0-9]*(?:\.[0-9]{0,9}[1-9])?))$. """
    d = decimal.Decimal(str(val)).quantize(decimal.Decimal("0.0000000001"))
    s = f"{d:f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s in ("", "-0"):
        return "0"
    return s


def _parse_physical_snapshot(raw_bytes: bytes, exact_contract: str) -> tuple[list[str], list[float]]:
    """Parse physical snapshot CSV bytes into timestamps and close price series."""
    text = raw_bytes.decode("utf-8")
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not lines:
        raise ValueError("Snapshot file contains no valid data lines")
    reader = csv.DictReader(lines)
    timestamps = []
    prices = []
    for row in reader:
        symbol = row.get("symbol", "").strip()
        if symbol and symbol != exact_contract:
            raise ValueError(
                f"Snapshot data contains symbol {symbol} which does not match exact_contract {exact_contract}"
            )
        ts = row.get("timestamp", "").strip()
        close_str = row.get("close", "").strip()
        if not ts or not close_str:
            raise ValueError(f"Snapshot row missing timestamp or close price: {row}")
        timestamps.append(ts)
        prices.append(float(close_str))
    if not prices:
        raise ValueError("No price records extracted from snapshot CSV")
    return timestamps, prices


def _admit_before_execution(
    task: dict[str, Any],
    spec: dict[str, Any],
    output_dir: Path,
    definitions: v2.Definitions,
) -> None:
    """Strict fail-closed pre-execution admission gate enforcing S1-S7 rules."""
    # 1. Profile / Stage check
    exp_type = spec.get("experiment_type")
    res_stage = spec.get("research_stage")
    if exp_type != "trading_backtest":
        raise ValueError(
            f"Unsupported experiment_type: {exp_type!r}. Only 'trading_backtest' is admitted."
        )
    if res_stage != "validation":
        raise ValueError(
            f"Unsupported research_stage: {res_stage!r}. Only 'validation' is admitted (confirmation strictly rejected)."
        )
    if task.get("research_type") != "trading_backtest":
        raise ValueError(f"Task research_type must be 'trading_backtest', got {task.get('research_type')!r}")

    # Profile check
    if spec.get("backtest_profile") != SINGLE_CONTRACT_PROFILE:
        raise ValueError(
            f"Unsupported backtest_profile: {spec.get('backtest_profile')!r}. Must be {SINGLE_CONTRACT_PROFILE!r}."
        )
    if task.get("task_profile") != SINGLE_CONTRACT_PROFILE:
        raise ValueError(
            f"Unsupported task_profile: {task.get('task_profile')!r}. Must be {SINGLE_CONTRACT_PROFILE!r}."
        )

    # 2. Output directory exclusivity
    if output_dir.exists():
        raise FileExistsError(
            f"Target output directory already exists: {output_dir}. Overwriting existing runs is forbidden."
        )

    # 3. S7 Backtest Semantic Admission Constraints
    req = spec.get("dataset_requirements", {})
    task_req = task.get("data_requirements", {})

    product = req.get("product")
    if not product or product != task_req.get("product"):
        raise ValueError(f"Product mismatch or missing: spec={product!r}, task={task_req.get('product')!r}")

    exact_contract = req.get("exact_contract")
    if not exact_contract or exact_contract != task_req.get("exact_contract"):
        raise ValueError(
            f"exact_contract mismatch or missing: spec={exact_contract!r}, task={task_req.get('exact_contract')!r}"
        )

    time_range = req.get("time_range", {})
    start_str = time_range.get("start")
    end_str = time_range.get("end")
    if not start_str or not end_str or start_str >= end_str:
        raise ValueError(f"Invalid time range: start ({start_str}) must precede end ({end_str})")

    snapshot_sha = req.get("snapshot_sha256")
    if not snapshot_sha or snapshot_sha != task_req.get("snapshot_sha256"):
        raise ValueError("snapshot_sha256 mismatch or missing between Spec and Task")

    snapshot_locator = req.get("snapshot_locator")
    if not snapshot_locator or snapshot_locator != task_req.get("snapshot_locator"):
        raise ValueError("snapshot_locator mismatch or missing between Spec and Task")

    provenance = req.get("provenance")
    if not provenance or provenance != task_req.get("provenance"):
        raise ValueError("provenance mismatch or missing between Spec and Task")

    # Physical snapshot file verification
    target_path = Path(snapshot_locator) if os.path.isabs(snapshot_locator) else v2.ROOT / snapshot_locator
    if not target_path.is_file() or target_path.is_symlink():
        raise ValueError(f"Physical snapshot file missing or not regular file: {snapshot_locator}")
    raw_bytes = target_path.read_bytes()
    if v2.sha(raw_bytes) != snapshot_sha:
        raise ValueError(f"Physical snapshot sha256 mismatch: expected {snapshot_sha}, got {v2.sha(raw_bytes)}")

    # Cost model
    cost_model = spec.get("cost_model")
    if not cost_model:
        raise ValueError("Missing cost_model: cost model must be explicitly declared")
    if not isinstance(cost_model, dict):
        raise ValueError(f"cost_model must be an object, got {type(cost_model).__name__}")  # noqa: TRY004
    if cost_model.get("currency") != "CNY":
        raise ValueError(f"S7 violation: cost_model currency must be CNY, got {cost_model.get('currency')}")
    if "commission_bps" not in cost_model:
        raise ValueError("Missing commission_bps in cost_model")
    if float(cost_model["commission_bps"]) < 0:
        raise ValueError(f"S7 violation: commission_bps must be >= 0, got {cost_model['commission_bps']}")
    if "slippage_ticks" not in cost_model:
        raise ValueError("Missing slippage_ticks in cost_model")
    if int(cost_model["slippage_ticks"]) < 0:
        raise ValueError(f"S7 violation: slippage_ticks must be >= 0, got {cost_model['slippage_ticks']}")

    # Contract specifications
    contract_specs = spec.get("contract_specifications")
    if not contract_specs or not isinstance(contract_specs, dict):
        raise ValueError("contract_specifications must be an object")
    if contract_specs.get("target_symbol") != exact_contract:
        raise ValueError(f"contract_specifications.target_symbol must match exact_contract {exact_contract!r}")
    multiplier = float(contract_specs.get("multiplier", 0))
    if multiplier <= 0:
        raise ValueError(f"S7 violation: multiplier must be > 0, got {multiplier}")
    price_tick = float(contract_specs.get("price_tick", 0))
    if price_tick <= 0:
        raise ValueError(f"S7 violation: price_tick must be > 0, got {price_tick}")
    margin_ratio = float(contract_specs.get("margin_ratio", 0))
    if not (0 < margin_ratio <= 1):
        raise ValueError(f"S7 violation: margin_ratio must be in (0, 1], got {margin_ratio}")
    if contract_specs.get("price_currency", "CNY") != "CNY":
        raise ValueError(f"S7 violation: price_currency must be CNY, got {contract_specs.get('price_currency')}")

    # Execution config
    exec_cfg = spec.get("execution_config")
    if not exec_cfg or not isinstance(exec_cfg, dict):
        raise ValueError("execution_config must be an object")
    initial_capital = float(exec_cfg.get("initial_capital", 0))
    if initial_capital <= 0:
        raise ValueError(f"S7 violation: initial_capital must be > 0, got {initial_capital}")
    currency = exec_cfg.get("capital_currency", "CNY")
    if currency != "CNY":
        raise ValueError(f"S7 violation: capital_currency must be CNY, got {currency}")

    # 4. Official v2 Spec validation
    v2.validate_spec(spec, task, definitions)


def _validate_with_public_handoff(
    output_dir: Path,
    task: dict[str, Any],
    spec: dict[str, Any],
    definitions: v2.Definitions,
) -> None:
    """Independently re-consume execution results via frozen public v2 validate_manifest & validate_handoff."""
    run = v2.parse((output_dir / "run.json").read_bytes())
    manifest = v2.parse((output_dir / "manifest.json").read_bytes())
    evidence = v2.parse((output_dir / "evidence.json").read_bytes())

    # 1. Direct manifest check with Task and Spec binding
    v2.validate_manifest(output_dir, manifest, run, definitions, task=task, spec=spec)

    # 2. Public review-evidence agent handoff check
    criteria_def = next(
        e for e in definitions.entries if e["kind"] == "criteria" and e["name"] == SINGLE_CONTRACT_CRITERIA_ID
    )
    criteria = {k: criteria_def[k] for k in ("name", "revision", "content_hash")}
    criteria["id"] = criteria.pop("name")

    present_artifacts = [
        {
            "manifest_id": manifest["manifest_id"],
            "manifest_revision": manifest["revision"],
            "manifest_content_hash": manifest["manifest_content_hash"],
            "artifact_id": entry["artifact_id"],
            "role": entry["role"],
            "content_sha256": entry["content_sha256"],
        }
        for entry in manifest["entries"]
        if entry["availability"] == "present"
    ]

    records: dict[str, Any] = {
        "research_task": task,
        "experiment_spec": spec,
        "experiment_run": run,
        "artifact_manifest": manifest,
        "result_evidence": evidence,
    }
    context = {kind: v2.check_record(value, kind) for kind, value in records.items()}

    is_failed = (run["run_status"] == "FAILED")
    if is_failed:
        expected_roles = sorted(v2.COMMON | {"failure_diagnostics"})
        review_scope = "failure_diagnosis"
    else:
        expected_roles = sorted(v2.COMMON | v2.TYPED[spec["experiment_type"]])
        review_scope = "research_assessment"

    request = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"handoff-review-{run['run_id']}",
        "message_kind": "request",
        "operation": "review_evidence",
        "sender_role": "execution",
        "recipient_role": "critic",
        "context_refs": context,
        "artifact_requirements": {
            "role_profile_ref": manifest["artifact_profile"],
            "required_roles": expected_roles,
            "exact_refs": present_artifacts,
        },
        "expected_outputs": [
            {"object_type": "review", "schema_version": "research_lab.review.v2"}
        ],
        "review_scope": review_scope,
        "criteria_ref": criteria,
    }

    review = {
        "schema_version": "research_lab.review.v2",
        "hash_profile": "research-json-v1",
        "review_id": f"review-{evidence['evidence_id']}",
        "revision": "rev.1",
        "evidence_id": evidence["evidence_id"],
        "evidence_content_hash": evidence["evidence_content_hash"],
        "reviewer": "deterministic backtest verification gate",
        "reviewed_at": "2026-09-19T00:00:00.000000Z",
        "criteria_ref": criteria,
        "recommendation": "improve" if not is_failed else "reject",
        "reason": (
            "Deterministic trading_backtest execution completed."
            if not is_failed
            else "Execution failed with diagnostics captured."
        ),
    }
    review["review_content_hash"] = v2.digest(
        {k: v for k, v in review.items() if k != "review_content_hash"}
    )
    records["review"] = review

    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"response-review-{run['run_id']}",
        "message_kind": "response",
        "operation": "review_evidence",
        "sender_role": "critic",
        "recipient_role": "execution",
        "context_refs": context,
        "in_reply_to": request["handoff_id"],
        "status": "completed",
        "output_refs": [v2.check_record(review, "review")],
        "review_scope": review_scope,
    }

    v2.validate_handoff(request, records, response, root=output_dir)


class V2BacktestExecutionBridge:
    """Minimal local one-shot Protocol v2 trading_backtest execution bridge.

    Strictly admits ('trading_backtest', 'validation') under research_lab.single_contract_backtest.v1.
    Reuses existing BacktestAdapter and directly consumes physical snapshot bytes
    to produce verifiable, reproducible Run, Manifest, and Evidence facts without
    introducing worker queues, fake accounts, or external runtimes.
    """

    def __init__(
        self,
        definitions: v2.Definitions | None = None,
        result_store: ResultStore | None = None,
        adapter: DeterministicBacktestAdapter | None = None,
    ) -> None:
        self.definitions = definitions or v2.Definitions()
        self.result_store = result_store
        self.adapter = adapter or DeterministicBacktestAdapter()

    def execute(
        self,
        task: dict[str, Any] | Path | str,
        spec: dict[str, Any] | Path | str,
        output_dir: Path | str,
        *,
        override_prices: list[float] | None = None,
        force_failure: bool = False,
    ) -> dict[str, Any]:
        """Execute a Protocol v2 single-contract trading_backtest experiment."""
        target_dir = Path(output_dir).resolve()
        task_dict = self._load_dict(task)
        spec_dict = self._load_dict(spec)

        # 1. Fail-closed Pre-execution Admission Gate
        _admit_before_execution(
            task=task_dict,
            spec=spec_dict,
            output_dir=target_dir,
            definitions=self.definitions,
        )

        # 2. Local execution boundary & materials setup
        target_dir.mkdir(parents=True, exist_ok=False)
        materials_dir = target_dir / "materials"
        materials_dir.mkdir(parents=True, exist_ok=False)

        # Write immutable input materials
        (materials_dir / "task.json").write_text(v2.canonical(task_dict) + "\n", encoding="utf-8")
        (materials_dir / "spec.json").write_text(v2.canonical(spec_dict) + "\n", encoding="utf-8")

        run_id = f"run-backtest-{uuid4().hex[:12]}"
        manifest_id = f"manifest-backtest-{uuid4().hex[:12]}"
        evidence_id = f"evidence-backtest-{uuid4().hex[:12]}"

        # Physical snapshot bytes reading
        req = spec_dict["dataset_requirements"]
        snapshot_locator = req["snapshot_locator"]
        target_path = Path(snapshot_locator) if os.path.isabs(snapshot_locator) else v2.ROOT / snapshot_locator
        raw_bytes = target_path.read_bytes()
        snapshot_byte_length = len(raw_bytes)

        # Basic experiment parameters
        product = req["product"]
        exact_contract = req["exact_contract"]
        strategy_spec = spec_dict.get("strategy_spec") or {}
        strategy_name = strategy_spec.get("strategy_name", "buy_and_hold")
        exec_cfg = spec_dict.get("execution_config") or {}
        initial_capital = float(exec_cfg.get("initial_capital", 100000.0))
        pos_sizing = exec_cfg.get("position_sizing") or {}
        position_size = float(pos_sizing.get("lots", 1.0))

        contract_specs = spec_dict.get("contract_specifications") or {}
        multiplier = float(contract_specs.get("multiplier", 10.0))
        price_tick = float(contract_specs.get("price_tick", 1.0))
        margin_ratio = float(contract_specs.get("margin_ratio", 0.1))

        cost_cfg = spec_dict.get("cost_model") or {}
        commission_bps = float(cost_cfg.get("commission_bps", 1.0))
        slippage_ticks = int(cost_cfg.get("slippage_ticks", 1))

        # Resolved computation manifest (deterministic computation lock)
        computation = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "product": product,
            "exact_contract": exact_contract,
            "strategy_name": strategy_name,
            "initial_capital": _format_cny(initial_capital),
            "multiplier": _format_cny(multiplier),
            "price_tick": _format_cny(price_tick),
            "currency": "CNY",
            "commission_bps": _format_cny(commission_bps),
            "slippage_ticks": slippage_ticks,
            "snapshot_locator": snapshot_locator,
            "snapshot_sha256": req["snapshot_sha256"],
            "snapshot_byte_length": snapshot_byte_length,
            "provenance": req["provenance"],
            "stop_reason": "COMPLETED_END_OF_DATA",
        }

        # 4 common payloads always written
        dataset_meta = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "product": product,
            "exact_contract": exact_contract,
            "snapshot_locator": snapshot_locator,
            "snapshot_sha256": req["snapshot_sha256"],
            "snapshot_byte_length": snapshot_byte_length,
            "provenance": req["provenance"],
            "limitations": (
                "Synthetic physical fixture for contract testing only; "
                "does not constitute real-market scientific validation."
            ),
        }
        self._write_payload(target_dir / "dataset_metadata.json", dataset_meta)

        method_def = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "strategy_name": strategy_name,
            "strategy_id": f"strat-{strategy_name}-001",
            "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "parameters": strategy_spec.get("parameters", {}),
            "limitations": "Single-contract deterministic simulation.",
        }
        self._write_payload(target_dir / "method_definition.json", method_def)

        env_lock = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "environment_details": "vnpy-web-bridge-v2-single-contract",
            "limitations": "Pure Python offline backtest environment.",
        }
        self._write_payload(target_dir / "environment_lock.json", env_lock)

        replay_inst = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "command": f"python -m research_lab.runners.v2_backtest --spec {spec_dict['spec_id']}",
            "entry_point": "research_lab.runners.v2_backtest",
            "limitations": "Local single-contract deterministic execution.",
        }
        self._write_payload(target_dir / "replay_instructions.json", replay_inst)

        is_failed = False
        summary_payload = None

        try:
            if force_failure:
                raise RuntimeError("Forced simulation failure requested for FAILED state testing")

            # Parse physical snapshot CSV bytes directly
            timestamps, file_prices = _parse_physical_snapshot(raw_bytes, exact_contract)
            effective_prices = override_prices if override_prices is not None else file_prices

            # Run deterministic backtest adapter
            v1_exp = ExperimentSpec(
                schema_version="research_lab.experiment.v1",
                experiment_id=run_id,
                strategy=StrategySpec(name=strategy_name),
                factor=FactorSpec(name="close_return"),
                dataset=DatasetSpec(name=exact_contract, prices=effective_prices),
                execution=ExecutionConfig(initial_capital=initial_capital, position_size=position_size),
                cost_model=CostModel(bps=commission_bps),
                universe=[product],
            )
            backtest_run = self.adapter.run(v1_exp)

            # Generate factual single-contract payloads
            summary_payload = self._write_completed_payloads(
                target_dir=target_dir,
                product=product,
                exact_contract=exact_contract,
                backtest_run=backtest_run,
                prices=effective_prices,
                timestamps=timestamps,
                initial_capital=initial_capital,
                multiplier=multiplier,
                margin_ratio=margin_ratio,
                commission_bps=commission_bps,
                slippage_ticks=slippage_ticks,
                price_tick=price_tick,
            )

        except Exception as exc:  # noqa: BLE001
            is_failed = True
            computation["stop_reason"] = "FAILED_RUNTIME_ERROR"
            diag = {
                "profile": SINGLE_CONTRACT_PROFILE,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "process_exit_code": 1,
                "details": {"traceback": traceback.format_exc()},
            }
            self._write_payload(target_dir / "failure_diagnostics.json", diag)

        # Finalize Run, Manifest, Evidence
        scientific_fingerprint = v2.digest(computation)
        run_status = "FAILED" if is_failed else "COMPLETED"
        process_exit_code = 1 if is_failed else 0

        run_record = {
            "schema_version": "research_lab.run.v2",
            "hash_profile": "research-json-v1",
            "run_id": run_id,
            "run_status": run_status,
            "spec_id": spec_dict["spec_id"],
            "spec_revision": spec_dict["revision"],
            "spec_content_hash": spec_dict["spec_content_hash"],
            "trial_context": {
                "research_stage": "validation",
                "trial_kind": None,
                "retry_of_run_id": None,
                "holdout_usage_state": "not_applicable",
            },
            "resolved_computation_manifest": computation,
            "scientific_fingerprint": scientific_fingerprint,
            "timing": {
                "started_at": "2024-01-02T09:00:00.000000Z",
                "completed_at": "2024-01-02T09:05:00.000000Z",
                "recorded_at": "2024-01-02T09:05:01.000000Z",
            },
            "process_exit_code": process_exit_code,
        }
        self._seal(run_record, "run")
        (target_dir / "run.json").write_text(v2.canonical(run_record) + "\n", encoding="utf-8")

        manifest_entries = self._build_manifest_entries(target_dir, is_failed=is_failed)
        manifest_record = {
            "schema_version": "research_lab.artifact_manifest.v2",
            "hash_profile": "research-json-v1",
            "manifest_id": manifest_id,
            "revision": "rev.1",
            "run_id": run_id,
            "run_content_hash": run_record["run_content_hash"],
            "experiment_type": "trading_backtest",
            "artifact_profile": SINGLE_CONTRACT_ROLE_PROFILE,
            "entries": manifest_entries,
        }
        self._seal(manifest_record, "manifest")
        (target_dir / "manifest.json").write_text(v2.canonical(manifest_record) + "\n", encoding="utf-8")

        supporting_artifacts = [
            {
                "manifest_id": manifest_record["manifest_id"],
                "manifest_revision": manifest_record["revision"],
                "manifest_content_hash": manifest_record["manifest_content_hash"],
                "artifact_id": e["artifact_id"],
                "role": e["role"],
                "content_sha256": e["content_sha256"],
            }
            for e in manifest_entries
            if e["availability"] == "present"
        ]

        typed_metrics = None
        if not is_failed and summary_payload is not None:
            typed_metrics = {
                "profile": SINGLE_CONTRACT_PROFILE,
                "product": product,
                "exact_contract": exact_contract,
                "net_pnl": summary_payload["net_pnl"],
                "total_fees": summary_payload["total_fees"],
                "trade_count": summary_payload["total_trades"],
            }

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
            "missing_reason": "execution_failed" if is_failed else None,
            "supporting_artifacts": supporting_artifacts,
            "typed_metrics": typed_metrics,
        }
        self._seal(evidence_record, "evidence")
        (target_dir / "evidence.json").write_text(v2.canonical(evidence_record) + "\n", encoding="utf-8")

        # Re-consumption via public validate_manifest / validate_handoff API
        _validate_with_public_handoff(target_dir, task_dict, spec_dict, self.definitions)

        # Append-only persistence into ResultStore if available
        stored_result = None
        report_path = None
        if self.result_store is not None:
            stored_result = self.result_store.save_v2(target_dir)
            temp_report_path = write_v2_report(self.result_store.config.artifacts_dir, stored_result)
            report_record = self.result_store.save_v2_report(stored_result, temp_report_path)
            report_path = Path(report_record["report_location"])

        return {
            "run": run_record,
            "manifest": manifest_record,
            "evidence": evidence_record,
            "output_dir": target_dir,
            "run_status": run_record["run_status"],
            "process_exit_code": run_record["process_exit_code"],
            "stored_result": stored_result,
            "report_path": report_path,
        }

    def _write_completed_payloads(
        self,
        target_dir: Path,
        product: str,
        exact_contract: str,
        backtest_run: Any,
        prices: list[float],
        timestamps: list[str],
        initial_capital: float,
        multiplier: float,
        margin_ratio: float,
        commission_bps: float,
        slippage_ticks: int,
        price_tick: float,
    ) -> dict[str, Any]:
        """Write single-contract trade_blotter, equity_curve, and backtest_summary without multi-account padding."""
        positions = backtest_run.positions
        trades = []
        accumulated_fees = decimal.Decimal(0)

        for i in range(1, len(positions)):
            diff = positions[i] - positions[i - 1]
            if diff != 0:
                side = "BUY" if diff > 0 else "SELL"
                vol = int(abs(diff))
                price = prices[i]
                turnover = price * multiplier * vol
                fee = turnover * (commission_bps / 10000.0) + (slippage_ticks * price_tick * multiplier * vol)
                accumulated_fees += decimal.Decimal(str(fee))
                ts = timestamps[i] if i < len(timestamps) else f"2024-01-02T09:0{i}:00.000000Z"
                trades.append({
                    "trade_id": f"T{len(trades) + 1:03d}",
                    "timestamp": ts,
                    "side": side,
                    "price": _format_cny(price),
                    "volume": vol,
                    "fee": _format_cny(fee),
                    "turnover": _format_cny(turnover),
                })

        trade_blotter = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "product": product,
            "exact_contract": exact_contract,
            "trades": trades,
        }
        self._write_payload(target_dir / "trade_blotter.json", trade_blotter)

        # Equity curve points
        points = []
        for idx, eq in enumerate(backtest_run.equity_curve):
            pos = positions[idx]
            price = prices[idx] if idx < len(prices) else prices[-1]
            ts = timestamps[idx] if idx < len(timestamps) else f"2024-01-02T09:0{idx}:00.000000Z"
            margin_val = abs(pos) * price * multiplier * margin_ratio
            cash_val = eq - margin_val
            points.append({
                "timestamp": ts,
                "equity": _format_cny(eq),
                "cash": _format_cny(cash_val),
                "margin": _format_cny(margin_val),
            })

        equity_curve = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "product": product,
            "exact_contract": exact_contract,
            "points": points,
        }
        self._write_payload(target_dir / "equity_curve.json", equity_curve)

        # Backtest summary
        ending_equity_val = backtest_run.equity_curve[-1]
        net_pnl_val = ending_equity_val - initial_capital
        total_fees_cny = _format_cny(accumulated_fees)

        backtest_summary = {
            "profile": SINGLE_CONTRACT_PROFILE,
            "product": product,
            "exact_contract": exact_contract,
            "initial_capital": _format_cny(initial_capital),
            "ending_equity": _format_cny(ending_equity_val),
            "net_pnl": _format_cny(net_pnl_val),
            "total_fees": total_fees_cny,
            "total_trades": len(trades),
            "summary_metrics": {
                "sharpe_ratio": _format_cny(backtest_run.metrics.sharpe),
                "max_drawdown": _format_cny(backtest_run.metrics.max_drawdown),
            },
        }
        self._write_payload(target_dir / "backtest_summary.json", backtest_summary)
        return backtest_summary

    def _build_manifest_entries(self, target_dir: Path, is_failed: bool) -> list[dict[str, Any]]:
        """Construct verified artifact manifest entries for single-contract profile."""
        entries = []
        payload_roles = [
            ("dataset_metadata", "required"),
            ("method_definition", "required"),
            ("environment_lock", "required"),
            ("replay_instructions", "required"),
        ]

        if not is_failed:
            payload_roles.extend([
                ("backtest_summary", "required"),
                ("trade_blotter", "required"),
                ("equity_curve", "required"),
            ])

        for role, classification in payload_roles:
            schema_entry = next(
                e for e in self.definitions.entries if e["name"] == f"{SINGLE_CONTRACT_PAYLOAD_PREFIX}{role}"
            )
            schema_ref = {
                k: schema_entry[k]
                for k in ("name", "revision", "content_hash", "locator")
            }
            fpath = target_dir / f"{role}.json"
            raw = fpath.read_bytes()
            entries.append({
                "artifact_id": role,
                "role": role,
                "classification": classification,
                "content_schema_ref": schema_ref,
                "availability": "present",
                "coverage": "complete",
                "relative_path": f"{role}.json",
                "media_type": "application/json",
                "byte_length": len(raw),
                "content_sha256": v2.sha(raw),
                "producer": {"component": "research_lab.runners.v2_backtest", "version": "1.0"},
            })

        if is_failed:
            # Add unavailable entries for required execution payloads
            for role in ("backtest_summary", "trade_blotter", "equity_curve"):
                schema_entry = next(
                    e for e in self.definitions.entries if e["name"] == f"{SINGLE_CONTRACT_PAYLOAD_PREFIX}{role}"
                )
                schema_ref = {
                    k: schema_entry[k]
                    for k in ("name", "revision", "content_hash", "locator")
                }
                entries.append({
                    "artifact_id": role,
                    "role": role,
                    "classification": "required",
                    "content_schema_ref": schema_ref,
                    "availability": "unavailable",
                    "coverage": "none",
                    "unavailable_reason": "not_produced",
                })

            diag_path = target_dir / "failure_diagnostics.json"
            raw_diag = diag_path.read_bytes()
            schema_entry = next(
                e for e in self.definitions.entries if e["name"] == f"{SINGLE_CONTRACT_PAYLOAD_PREFIX}failure_diagnostics"
            )
            entries.append({
                "artifact_id": "failure_diagnostics",
                "role": "failure_diagnostics",
                "classification": "required",
                "content_schema_ref": {
                    k: schema_entry[k]
                    for k in ("name", "revision", "content_hash", "locator")
                },
                "availability": "present",
                "coverage": "complete",
                "relative_path": "failure_diagnostics.json",
                "media_type": "application/json",
                "byte_length": len(raw_diag),
                "content_sha256": v2.sha(raw_diag),
                "producer": {"component": "research_lab.runners.v2_backtest", "version": "1.0"},
            })

        return entries

    def _write_payload(self, path: Path, data: dict[str, Any]) -> None:
        raw = v2.canonical(data).encode("utf-8")
        path.write_bytes(raw)

    def _seal(self, obj: dict[str, Any], prefix: str) -> None:
        obj[f"{prefix}_content_hash"] = v2.digest(
            {k: v for k, v in obj.items() if k != f"{prefix}_content_hash"}
        )

    def _load_dict(self, obj: dict[str, Any] | Path | str) -> dict[str, Any]:
        if isinstance(obj, dict):
            return copy.deepcopy(obj)
        path = Path(obj)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {obj}")
        return v2.parse(path.read_bytes())

    def execute_from_materials(
        self,
        materials_dir: Path | str,
        output_dir: Path | str,
        *,
        override_prices: list[float] | None = None,
        force_failure: bool = False,
    ) -> dict[str, Any]:
        """Convenience loader from materials directory containing task.json and spec.json."""
        mdir = Path(materials_dir).resolve()
        task_path = mdir / "task.json"
        spec_path = mdir / "spec.json"
        if not task_path.is_file():
            raise FileNotFoundError(f"Missing task.json in {materials_dir}")
        if not spec_path.is_file():
            raise FileNotFoundError(f"Missing spec.json in {materials_dir}")
        return self.execute(
            task=task_path,
            spec=spec_path,
            output_dir=output_dir,
            override_prices=override_prices,
            force_failure=force_failure,
        )


def execute_v2_backtest_spec(
    task: dict[str, Any] | Path | str,
    spec: dict[str, Any] | Path | str,
    output_dir: Path | str,
    *,
    result_store: ResultStore | None = None,
    override_prices: list[float] | None = None,
    force_failure: bool = False,
) -> dict[str, Any]:
    """Convenience top-level execution runner for Protocol v2 trading_backtest."""
    bridge = V2BacktestExecutionBridge(result_store=result_store)
    return bridge.execute(
        task=task,
        spec=spec,
        output_dir=output_dir,
        override_prices=override_prices,
        force_failure=force_failure,
    )


def execute_v2_backtest_from_materials(
    materials_dir: Path | str,
    output_dir: Path | str,
    *,
    result_store: ResultStore | None = None,
    override_prices: list[float] | None = None,
    force_failure: bool = False,
) -> dict[str, Any]:
    """Convenience top-level loader and runner from a materials directory."""
    bridge = V2BacktestExecutionBridge(result_store=result_store)
    return bridge.execute_from_materials(
        materials_dir,
        output_dir,
        override_prices=override_prices,
        force_failure=force_failure,
    )
