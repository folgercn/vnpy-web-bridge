from __future__ import annotations

import hashlib
import json
from itertools import product
from pathlib import Path
from statistics import fmean, pstdev

from research_lab.backtest import BacktestAdapter
from research_lab.experiments import load_sweep
from research_lab.reports import write_sweep_report
from research_lab.runners import ExperimentRunner
from research_lab.schemas import (
    ParameterStability, RankedTrial, SweepParameter, SweepResult, SweepSpec,
    SweepTrial, SweepTrialResult,
)


class SweepExecutionError(ValueError):
    """Raised when a declarative sweep cannot be converted into experiments."""


def generate_trials(spec: SweepSpec) -> list[SweepTrial]:
    """Build Cartesian trials in declared path/value order, with safe unique IDs."""
    trials: list[SweepTrial] = []
    for index, candidates in enumerate(product(*(item.values for item in spec.parameters)), start=1):
        values = {item.path: candidate for item, candidate in zip(spec.parameters, candidates)}
        payload = spec.experiment.model_dump(mode="python")
        for path, value in values.items():
            _set_supported_path(payload, path, value)
        payload["experiment_id"] = _trial_id(spec.sweep_id, index, values)
        try:
            experiment = spec.experiment.__class__.model_validate(payload)
        except ValueError as exc:
            raise SweepExecutionError(f"invalid values for sweep trial {index}") from exc
        trials.append(SweepTrial(experiment=experiment, parameter_values=values))
    return trials


def _set_supported_path(payload: dict[str, object], path: str, value: object) -> None:
    segments = path.split(".")
    target: dict[str, object] = payload
    for segment in segments[:-1]:
        next_target = target.get(segment)
        if not isinstance(next_target, dict):
            raise SweepExecutionError(f"unsupported sweep path: {path}")
        target = next_target
    target[segments[-1]] = value


def _trial_id(sweep_id: str, index: int, values: dict[str, object]) -> str:
    identity = {"sweep_id": sweep_id, "parameter_values": values}
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    suffix = f"-trial-{index}-{digest}"
    return f"{sweep_id[:128 - len(suffix)]}{suffix}"


class ParameterSweepEngine:
    """Local, deterministic, sequential parameter sweep executor.

    This deliberately invokes the existing ExperimentRunner one trial at a
    time. Queueing and parallel scheduling remain owned by the future #514.
    """

    execution_mode = "local_sequential"

    def __init__(self, runner: ExperimentRunner) -> None:
        self.runner = runner

    @classmethod
    def local(cls, root: Path | str, adapter: BacktestAdapter | None = None) -> "ParameterSweepEngine":
        return cls(ExperimentRunner.local(root, adapter))

    def run_yaml(self, path: Path | str) -> SweepResult:
        return self.run(load_sweep(path))

    def run(self, spec: SweepSpec) -> SweepResult:
        trials = generate_trials(spec)
        trial_results = [
            SweepTrialResult(parameter_values=trial.parameter_values, result=self.runner.run(trial.experiment))
            for trial in trials
        ]
        ranked_trials = _rank(trial_results, spec)
        stability = _stability(trial_results, spec)
        status = "completed" if len(ranked_trials) == len(trial_results) else "completed_with_failures"
        result = SweepResult(
            sweep_id=spec.sweep_id,
            status=status,
            ranking=spec.ranking,
            trials=trial_results,
            ranked_trials=ranked_trials,
            stability=stability,
        )
        stored = self.runner.store.save_sweep(result)
        report_path = write_sweep_report(self.runner.store.config.artifacts_dir, stored)
        return self.runner.store.save_sweep(stored.model_copy(update={"report_location": str(report_path)}))


def _rank(trials: list[SweepTrialResult], spec: SweepSpec) -> list[RankedTrial]:
    completed = [trial for trial in trials if trial.result.status == "completed" and trial.result.metrics is not None]
    metric = spec.ranking.metric
    if spec.ranking.direction == "maximize":
        completed.sort(key=lambda trial: (-float(getattr(trial.result.metrics, metric)), trial.result.experiment_id))
    else:
        completed.sort(key=lambda trial: (float(getattr(trial.result.metrics, metric)), trial.result.experiment_id))
    return [
        RankedTrial(
            rank=index,
            experiment_id=trial.result.experiment_id,
            parameter_values=trial.parameter_values,
            metrics=trial.result.metrics,
        )
        for index, trial in enumerate(completed, start=1)
    ]


def _stability(trials: list[SweepTrialResult], spec: SweepSpec) -> list[ParameterStability]:
    metric = spec.ranking.metric
    entries: list[ParameterStability] = []
    for parameter in spec.parameters:
        for value in parameter.values:
            scores = [
                float(getattr(trial.result.metrics, metric))
                for trial in trials
                if trial.result.status == "completed" and trial.result.metrics is not None
                and trial.parameter_values[parameter.path] == value
            ]
            if not scores:
                continue
            entries.append(ParameterStability(
                path=parameter.path,
                value=value,
                completed_trials=len(scores),
                mean_score=fmean(scores),
                best_score=max(scores) if spec.ranking.direction == "maximize" else min(scores),
                score_stddev=pstdev(scores),
            ))
    return entries
