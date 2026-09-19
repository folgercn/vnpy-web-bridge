from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from research_lab.schemas import (
    CriticReview,
    ExperimentResult,
    SweepResult,
    ValidationResult,
)


def write_report(root: Path, result: ExperimentResult) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{result.experiment_id}.report.md"
    lines = [
        f"# Experiment {result.experiment_id}",
        "",
        f"- Status: {result.status}",
        f"- Strategy: {result.strategy_name}",
        f"- Factor: {result.factor_name}",
        f"- Result artifact: {result.artifact_location or 'pending'}",
    ]
    if result.metrics:
        lines.extend([
            "", "## Performance metrics", "",
            f"- Total return: {result.metrics.total_return:.6f}",
            f"- Sharpe: {result.metrics.sharpe:.6f}",
            f"- Max drawdown: {result.metrics.max_drawdown:.6f}",
            f"- Turnover: {result.metrics.turnover:.6f}",
            f"- Transaction cost: {result.metrics.transaction_cost:.6f}",
        ])
    if result.error_code:
        lines.extend(["", "## Failure", "", f"- Code: {result.error_code}", f"- Message: {result.error_message or ''}"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def render_v2_report(receipt: dict[str, Any]) -> str:
    """Deterministically render a Protocol v2 markdown report from a stored receipt."""
    run = receipt["run"]
    evidence = receipt["evidence"]
    task = receipt["task"]
    spec = receipt["spec"]
    manifest = receipt["manifest"]
    lines = [
        f"# Protocol v2 run {run['object_id']}",
        "",
        "This report is derived from the stored result receipt and is not a fact source.",
        "",
        "## Exact references",
        "",
        f"- Task: `{task['object_id']}` {task['revision']} `{task['content_hash']}`",
        f"- Spec: `{spec['object_id']}` {spec['revision']} `{spec['content_hash']}`",
        f"- Run: `{run['object_id']}` `{run['content_hash']}`",
        f"- Manifest: `{manifest['object_id']}` {manifest['revision']} `{manifest['content_hash']}`",
        f"- Evidence: `{evidence['object_id']}` `{evidence['content_hash']}`",
        f"- Status: {receipt['run_status']}",
    ]
    return "\n".join(lines) + "\n"


def _validate_safe_run_id(run_id: str) -> str:
    """Validate that run_id is a safe single filename without path traversal or separators."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError(f"Invalid run_id: must be a non-empty string, got {run_id!r}")
    if "/" in run_id or "\\" in run_id:
        raise ValueError(f"Path separators forbidden in run_id: {run_id!r}")
    if run_id in (".", ".."):
        raise ValueError(f"Dot path references forbidden in run_id: {run_id!r}")
    if "\0" in run_id:
        raise ValueError(f"Null byte forbidden in run_id: {run_id!r}")
    path = Path(run_id)
    if path.is_absolute() or len(path.parts) != 1 or path.name != run_id:
        raise ValueError(f"Unsafe path component in run_id: {run_id!r}")
    return run_id


def write_v2_report(root: Path, receipt: dict[str, Any]) -> Path:
    """Write a create-only derived report that points to immutable Protocol v2 facts."""
    run = receipt["run"]
    run_id = _validate_safe_run_id(run["object_id"])
    reports_root = (root / "v2" / "reports").resolve()
    reports_root.mkdir(parents=True, exist_ok=True)
    path = (reports_root / f"{run_id}.report.md").resolve()
    if path.parent != reports_root:
        raise ValueError(f"Report path escapes reports directory: {path}")
    encoded = render_v2_report(receipt).encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FileExistsError(f"Refusing to overwrite existing Protocol v2 report: {path}") from None
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    return path


def write_sweep_report(root: Path, result: SweepResult) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{result.sweep_id}.sweep.report.md"
    lines = [
        f"# Parameter sweep {result.sweep_id}",
        "",
        "- Execution: local, sequential (no worker queue or parallel execution)",
        f"- Status: {result.status}",
        f"- Ranking: {result.ranking.metric} ({result.ranking.direction})",
        f"- Result artifact: {result.artifact_location or 'pending'}",
        "",
        "## Ranked completed trials",
        "",
    ]
    for trial in result.ranked_trials:
        value = getattr(trial.metrics, result.ranking.metric)
        lines.append(f"- {trial.rank}. `{trial.experiment_id}`: {value:.6f}; parameters={trial.parameter_values}")
    if not result.ranked_trials:
        lines.append("- No completed trials")
    lines.extend(["", "## Parameter stability", ""])
    for item in result.stability:
        lines.append(
            f"- `{item.path}`={item.value!r}: completed={item.completed_trials}, "
            f"mean={item.mean_score:.6f}, best={item.best_score:.6f}, stddev={item.score_stddev:.6f}"
        )
    if not result.stability:
        lines.append("- No completed trials")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_validation_report(root: Path, result: ValidationResult) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{result.validation_id}.validation.report.md"
    lines = [
        f"# Validation {result.validation_id}", "",
        "- Execution: local, sequential; each fold is run through ExperimentRunner",
        "- Scope: one requested symbol (`universe[0]`) with the deterministic adapter",
        f"- Method: {result.method}",
        f"- Status: {result.status}",
        f"- Result artifact: {result.artifact_location or 'pending'}", "",
        "## Fold results", "",
    ]
    for item in result.folds:
        is_metric = item.in_sample.metrics.total_return if item.in_sample.metrics else None
        oos_metric = item.out_of_sample.metrics.total_return if item.out_of_sample.metrics else None
        lines.append(
            f"- Fold {item.fold.index}: train=[{item.fold.train_start}, {item.fold.train_end}), "
            f"test=[{item.fold.test_start}, {item.fold.test_end}); "
            f"IS={is_metric if is_metric is not None else item.in_sample.status}; "
            f"OOS={oos_metric if oos_metric is not None else item.out_of_sample.status}"
        )
    lines.extend(["", "## Stability and degradation", ""])
    if result.stability and result.degradation:
        lines.extend([
            "- Score: %.6f / 100 (heuristic; not a promotion decision)" % result.stability.stability_score,
            "- Positive OOS fraction: %.6f" % result.stability.positive_oos_fraction,
            "- OOS Sharpe standard deviation: %.6f" % result.stability.oos_sharpe_stddev,
            "- Mean total-return delta (OOS - IS): %.6f" % result.degradation.total_return_delta,
            "- Mean Sharpe delta (OOS - IS): %.6f" % result.degradation.sharpe_delta,
        ])
    else:
        lines.append("- No completed IS/OOS fold pairs")
    lines.extend(["", "## Minimal OOS return-sign regimes", ""])
    for regime in result.regimes:
        mean = "n/a" if regime.mean_total_return is None else f"{regime.mean_total_return:.6f}"
        lines.append(f"- {regime.regime}: folds={regime.completed_folds}, mean_total_return={mean}")
    lines.extend([
        "", "## Boundary", "",
        "This artifact is a stable local validation handoff for a future Critic integration. "
        "It does not implement a Critic Agent, candidate selection, LLM evaluation, live data, or promotion.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_critic_report(root: Path, result: CriticReview) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{result.review_id}.critic.report.md"
    lines = [
        f"# Critic review {result.review_id}", "",
        f"- Validation: `{result.validation_id}`",
        f"- Candidate: `{result.candidate_id}`",
        f"- Research recommendation: **{result.recommendation}**",
        f"- Evidence confidence: {result.confidence:.3f}",
        "- Boundary: this is a local research review, never a promotion, deployment, or trading decision.",
        "", "## Findings", "",
    ]
    for item in result.findings:
        lines.extend([
            f"### {item.category}", "",
            f"- Assessment: {item.assessment} ({item.severity})",
            f"- {item.summary}",
            "- Evidence:",
            *[f"  - {evidence}" for evidence in item.evidence],
        ])
        if item.required_additional_tests:
            lines.extend(["- Required additional tests:", *[f"  - {test}" for test in item.required_additional_tests]])
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
