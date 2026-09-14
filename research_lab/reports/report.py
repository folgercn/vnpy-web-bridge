from __future__ import annotations

from pathlib import Path

from research_lab.schemas import ExperimentResult


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
