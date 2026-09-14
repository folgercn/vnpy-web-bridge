from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from research_lab.config import ResearchLabConfig
from research_lab.schemas import ExperimentResult, SweepResult


class ResultStore:
    """JSON artifacts plus a SQLite index for local experiment history."""

    def __init__(self, config: ResearchLabConfig) -> None:
        self.config = config
        self.config.root.mkdir(parents=True, exist_ok=True)
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.config.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS experiment_results (
                    experiment_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    strategy_name TEXT NOT NULL,
                    factor_name TEXT NOT NULL,
                    error_code TEXT,
                    artifact_location TEXT NOT NULL,
                    report_location TEXT,
                    created_at TEXT NOT NULL,
                    metrics_json TEXT,
                    result_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_results_strategy ON experiment_results(strategy_name)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_results_factor ON experiment_results(factor_name)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_results_error ON experiment_results(error_code)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sweep_results (
                    sweep_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    artifact_location TEXT NOT NULL,
                    report_location TEXT,
                    result_json TEXT NOT NULL
                )
                """
            )

    def save(self, result: ExperimentResult) -> ExperimentResult:
        artifact_path = self.config.artifacts_dir / f"{result.experiment_id}.result.json"
        stored = result.model_copy(update={"artifact_location": str(artifact_path)})
        self._write_json(artifact_path, stored.model_dump(mode="json"))
        payload = stored.model_dump_json()
        metrics_json = stored.metrics.model_dump_json() if stored.metrics else None
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO experiment_results (
                    experiment_id, status, strategy_name, factor_name, error_code,
                    artifact_location, report_location, created_at, metrics_json, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(experiment_id) DO UPDATE SET
                    status=excluded.status, strategy_name=excluded.strategy_name,
                    factor_name=excluded.factor_name, error_code=excluded.error_code,
                    artifact_location=excluded.artifact_location, report_location=excluded.report_location,
                    created_at=excluded.created_at, metrics_json=excluded.metrics_json,
                    result_json=excluded.result_json
                """,
                (
                    stored.experiment_id, stored.status, stored.strategy_name,
                    stored.factor_name, stored.error_code, stored.artifact_location,
                    stored.report_location, stored.created_at.isoformat(), metrics_json, payload,
                ),
            )
        return stored

    def get(self, experiment_id: str) -> ExperimentResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM experiment_results WHERE experiment_id = ?", (experiment_id,)
            ).fetchone()
        return ExperimentResult.model_validate_json(row["result_json"]) if row else None

    def save_sweep(self, result: SweepResult) -> SweepResult:
        artifact_path = self.config.artifacts_dir / f"{result.sweep_id}.sweep.json"
        stored = result.model_copy(update={"artifact_location": str(artifact_path)})
        self._write_json(artifact_path, stored.model_dump(mode="json"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sweep_results (sweep_id, status, artifact_location, report_location, result_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(sweep_id) DO UPDATE SET
                    status=excluded.status, artifact_location=excluded.artifact_location,
                    report_location=excluded.report_location, result_json=excluded.result_json
                """,
                (stored.sweep_id, stored.status, stored.artifact_location,
                 stored.report_location, stored.model_dump_json()),
            )
        return stored

    def get_sweep(self, sweep_id: str) -> SweepResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM sweep_results WHERE sweep_id = ?", (sweep_id,)
            ).fetchone()
        return SweepResult.model_validate_json(row["result_json"]) if row else None

    def query(
        self,
        *,
        strategy_name: str | None = None,
        factor_name: str | None = None,
        error_code: str | None = None,
    ) -> list[ExperimentResult]:
        clauses: list[str] = []
        values: list[str] = []
        for column, value in (("strategy_name", strategy_name), ("factor_name", factor_name), ("error_code", error_code)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        statement = "SELECT result_json FROM experiment_results"
        if clauses:
            statement += " WHERE " + " AND ".join(clauses)
        statement += " ORDER BY created_at DESC"
        with self._connect() as connection:
            rows = connection.execute(statement, values).fetchall()
        return [ExperimentResult.model_validate_json(row["result_json"]) for row in rows]

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        temporary_path = path.with_suffix(path.suffix + ".tmp")
        try:
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)
