from __future__ import annotations

from pathlib import Path

from research_lab.schemas import ExperimentResult, SweepResult


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
