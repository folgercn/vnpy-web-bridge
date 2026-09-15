from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from research_lab.config import ResearchLabConfig
from research_lab.schemas import CriticReview, ExperimentResult, SweepResult, ValidationResult


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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS critic_reviews (
                    review_id TEXT PRIMARY KEY,
                    validation_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    artifact_location TEXT NOT NULL,
                    report_location TEXT,
                    result_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_critic_validation ON critic_reviews(validation_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_critic_candidate ON critic_reviews(candidate_id)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS critic_findings (
                    review_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    assessment TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    PRIMARY KEY (review_id, category)
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_critic_failure_category ON critic_findings(category, assessment)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS validation_results (
                    validation_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    artifact_location TEXT NOT NULL,
                    report_location TEXT,
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

    def save_validation(self, result: ValidationResult) -> ValidationResult:
        artifact_path = self.config.artifacts_dir / f"{result.validation_id}.validation.json"
        stored = result.model_copy(update={"artifact_location": str(artifact_path)})
        self._write_json(artifact_path, stored.model_dump(mode="json"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO validation_results (validation_id, status, artifact_location, report_location, result_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(validation_id) DO UPDATE SET
                    status=excluded.status, artifact_location=excluded.artifact_location,
                    report_location=excluded.report_location, result_json=excluded.result_json
                """,
                (stored.validation_id, stored.status, stored.artifact_location,
                 stored.report_location, stored.model_dump_json()),
            )
        return stored

    def get_validation(self, validation_id: str) -> ValidationResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM validation_results WHERE validation_id = ?", (validation_id,)
            ).fetchone()
        return ValidationResult.model_validate_json(row["result_json"]) if row else None

    def save_critic_review(self, result: CriticReview) -> CriticReview:
        artifact_path = self.config.artifacts_dir / f"{result.review_id}.critic.json"
        stored = result.model_copy(update={"artifact_location": str(artifact_path)})
        self._write_json(artifact_path, stored.model_dump(mode="json"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO critic_reviews (
                    review_id, validation_id, candidate_id, recommendation,
                    artifact_location, report_location, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(review_id) DO UPDATE SET
                    validation_id=excluded.validation_id, candidate_id=excluded.candidate_id,
                    recommendation=excluded.recommendation, artifact_location=excluded.artifact_location,
                    report_location=excluded.report_location, result_json=excluded.result_json
                """,
                (stored.review_id, stored.validation_id, stored.candidate_id,
                 stored.recommendation, stored.artifact_location, stored.report_location,
                 stored.model_dump_json()),
            )
            connection.execute("DELETE FROM critic_findings WHERE review_id = ?", (stored.review_id,))
            connection.executemany(
                "INSERT INTO critic_findings (review_id, category, assessment, severity) VALUES (?, ?, ?, ?)",
                [(stored.review_id, item.category, item.assessment, item.severity) for item in stored.findings],
            )
        return stored

    def get_critic_review(self, review_id: str) -> CriticReview | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM critic_reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
        return CriticReview.model_validate_json(row["result_json"]) if row else None

    def query_critic_reviews(
        self, *, validation_id: str | None = None, candidate_id: str | None = None,
        category: str | None = None,
    ) -> list[CriticReview]:
        clauses: list[str] = []
        values: list[str] = []
        for column, value in (("validation_id", validation_id), ("candidate_id", candidate_id)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        statement = "SELECT DISTINCT critic_reviews.result_json FROM critic_reviews"
        if category is not None:
            statement += " JOIN critic_findings ON critic_findings.review_id = critic_reviews.review_id"
            clauses.append("critic_findings.category = ? AND critic_findings.assessment != 'pass'")
            values.append(category)
        if clauses:
            statement += " WHERE " + " AND ".join(clauses)
        statement += " ORDER BY critic_reviews.review_id"
        with self._connect() as connection:
            rows = connection.execute(statement, values).fetchall()
        return [CriticReview.model_validate_json(row["result_json"]) for row in rows]

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
