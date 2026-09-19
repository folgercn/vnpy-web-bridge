from __future__ import annotations

import json
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.reports import render_v2_report
from research_lab.schemas import (
    CriticReview,
    ExperimentResult,
    SweepResult,
    ValidationResult,
)


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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS v2_result_runs (
                    run_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    task_revision TEXT NOT NULL,
                    task_content_hash TEXT NOT NULL,
                    spec_id TEXT NOT NULL,
                    spec_revision TEXT NOT NULL,
                    spec_content_hash TEXT NOT NULL,
                    run_content_hash TEXT NOT NULL,
                    manifest_id TEXT NOT NULL,
                    manifest_revision TEXT NOT NULL,
                    manifest_content_hash TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    evidence_content_hash TEXT NOT NULL,
                    run_status TEXT NOT NULL,
                    bundle_location TEXT NOT NULL,
                    receipt_location TEXT NOT NULL,
                    receipt_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_v2_runs_task ON v2_result_runs(task_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_v2_runs_spec ON v2_result_runs(spec_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_v2_runs_task_ref ON v2_result_runs(task_id, task_revision, task_content_hash)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_v2_runs_spec_ref ON v2_result_runs(spec_id, spec_revision, spec_content_hash)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS v2_result_reports (
                    run_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    evidence_content_hash TEXT NOT NULL,
                    report_location TEXT NOT NULL,
                    report_sha256 TEXT NOT NULL
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

    def save_v2(self, bundle_dir: Path | str) -> dict[str, Any]:
        """Append one verified Protocol v2 result bundle snapshot without changing v1 storage."""
        bundle = Path(bundle_dir).resolve()
        if not bundle.is_dir():
            raise FileNotFoundError(f"Protocol v2 bundle directory does not exist: {bundle}")

        record = self._read_v2_bundle(bundle)
        run_id = _validate_safe_run_id(record["run_id"])

        with self._connect() as connection:
            existing = connection.execute(
                "SELECT run_id FROM v2_result_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing:
                raise FileExistsError(f"Protocol v2 run already stored: {run_id}")

        bundles_root = (self.config.artifacts_dir / "v2" / "bundles").resolve()
        snapshot_dir = (bundles_root / run_id).resolve()
        if snapshot_dir.parent != bundles_root:
            raise ValueError(f"Snapshot directory escapes bundles root: {snapshot_dir}")
        receipt_path = (self.config.artifacts_dir / "v2" / f"{v2.sha(run_id.encode())}.result.json").resolve()

        if bundle == snapshot_dir or bundle in snapshot_dir.parents or snapshot_dir in bundle.parents:
            raise ValueError(f"Snapshot directory cannot be nested within source bundle: {snapshot_dir}")

        if snapshot_dir.exists():
            raise FileExistsError(f"Protocol v2 bundle already exists: {snapshot_dir}")
        if receipt_path.exists():
            raise FileExistsError(f"Protocol v2 receipt already exists: {receipt_path}")

        snapshot_dir.mkdir(parents=True, exist_ok=False)
        try:
            for src_file in bundle.rglob("*"):
                if src_file.is_symlink():
                    raise ValueError(f"Symlinks are forbidden in source bundle: {src_file}")
                if src_file.is_file():
                    rel_path = src_file.relative_to(bundle)
                    dst_file = snapshot_dir / rel_path
                    self._write_bytes_create_only(dst_file, src_file.read_bytes())

            stored_record = self._read_v2_bundle(snapshot_dir)

            if stored_record["run_id"] != record["run_id"]:
                raise ValueError(f"Run ID mismatch after capture: {stored_record['run_id']} != {record['run_id']}")
            if stored_record["run_ref"] != record["run_ref"]:
                raise ValueError("Run reference mismatch after capture")
            if stored_record["spec_ref"] != record["spec_ref"]:
                raise ValueError("Spec reference mismatch after capture")
            if stored_record["task_ref"] != record["task_ref"]:
                raise ValueError("Task reference mismatch after capture")
            if stored_record["manifest_ref"] != record["manifest_ref"]:
                raise ValueError("Manifest reference mismatch after capture")
            if stored_record["evidence_ref"] != record["evidence_ref"]:
                raise ValueError("Evidence reference mismatch after capture")
            if stored_record["bundle_file_sha256"] != record["bundle_file_sha256"]:
                raise ValueError("Bundle inventory mismatch after capture")

            receipt = {
                "storage_version": "research_lab.result_store.v2",
                "task": stored_record["task_ref"],
                "spec": stored_record["spec_ref"],
                "run": stored_record["run_ref"],
                "manifest": stored_record["manifest_ref"],
                "evidence": stored_record["evidence_ref"],
                "run_status": stored_record["run_status"],
                "bundle_location": str(snapshot_dir),
                "bundle_file_sha256": stored_record["bundle_file_sha256"],
            }
            payload = v2.canonical(receipt)
            self._write_json_create_only(receipt_path, receipt)

            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO v2_result_runs (
                        run_id, task_id, task_revision, task_content_hash,
                        spec_id, spec_revision, spec_content_hash, run_content_hash,
                        manifest_id, manifest_revision, manifest_content_hash,
                        evidence_id, evidence_content_hash, run_status,
                        bundle_location, receipt_location, receipt_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        stored_record["run_id"],
                        stored_record["task_ref"]["object_id"],
                        stored_record["task_ref"]["revision"],
                        stored_record["task_ref"]["content_hash"],
                        stored_record["spec_ref"]["object_id"],
                        stored_record["spec_ref"]["revision"],
                        stored_record["spec_ref"]["content_hash"],
                        stored_record["run_ref"]["content_hash"],
                        stored_record["manifest_ref"]["object_id"],
                        stored_record["manifest_ref"]["revision"],
                        stored_record["manifest_ref"]["content_hash"],
                        stored_record["evidence_ref"]["object_id"],
                        stored_record["evidence_ref"]["content_hash"],
                        stored_record["run_status"],
                        str(snapshot_dir),
                        str(receipt_path),
                        payload,
                    ),
                )
        except Exception:
            receipt_path.unlink(missing_ok=True)
            shutil.rmtree(snapshot_dir, ignore_errors=True)
            raise

        return receipt | {"receipt_location": str(receipt_path)}

    def _verify_stored_bundle(self, receipt: dict[str, Any]) -> None:
        """Fail-closed integrity check verifying receipt and snapshot files against Protocol v2."""
        receipt_loc = Path(receipt.get("receipt_location", ""))
        if not receipt_loc.is_file():
            raise FileNotFoundError(f"Stored receipt file missing: {receipt_loc}")
        raw_receipt = receipt_loc.read_bytes()
        parsed_receipt = v2.parse(raw_receipt)
        clean_receipt = {k: v for k, v in receipt.items() if k != "receipt_location"}
        for key in (
            "storage_version",
            "task",
            "spec",
            "run",
            "manifest",
            "evidence",
            "run_status",
            "bundle_location",
            "bundle_file_sha256",
        ):
            if parsed_receipt.get(key) != clean_receipt.get(key):
                raise ValueError(f"Stored receipt content mismatch on disk for key: {key}")
        if v2.digest(parsed_receipt) != v2.digest(clean_receipt):
            raise ValueError("Stored receipt digest mismatch on disk")

        bundle_path = Path(receipt.get("bundle_location", ""))
        if not bundle_path.is_dir():
            raise FileNotFoundError(f"Stored bundle snapshot missing: {bundle_path}")

        actual_files: dict[str, Path] = {}
        for p in bundle_path.rglob("*"):
            if p.is_symlink():
                raise ValueError(f"Symlinks are forbidden in stored bundle snapshot: {p}")
            if p.is_file():
                rel = str(p.relative_to(bundle_path))
                actual_files[rel] = p

        expected_inventory: dict[str, str] = receipt.get("bundle_file_sha256", {})
        expected_set = set(expected_inventory.keys())
        actual_set = set(actual_files.keys())

        missing = expected_set - actual_set
        if missing:
            raise FileNotFoundError(f"Stored bundle missing recorded inventory files: {missing}")
        extra = actual_set - expected_set
        if extra:
            raise ValueError(f"Stored bundle contains unrecorded extra files: {extra}")

        for rel_name, expected_sha in expected_inventory.items():
            raw_bytes = v2.safe_read(bundle_path, rel_name)
            actual_sha = v2.sha(raw_bytes)
            if actual_sha != expected_sha:
                raise ValueError(
                    f"Stored bundle file sha256 mismatch for {rel_name}: expected {expected_sha}, got {actual_sha}"
                )

        snapshot_record = self._read_v2_bundle(bundle_path)
        for ref_name in ("run_ref", "manifest_ref", "evidence_ref", "task_ref", "spec_ref"):
            key = ref_name.replace("_ref", "")
            if snapshot_record[ref_name] != receipt[key]:
                raise ValueError(f"Stored bundle {key} reference mismatch")

    @staticmethod
    def _verify_row_against_receipt(row: sqlite3.Row, receipt: dict[str, Any]) -> None:
        """Verify that SQLite index columns strictly match immutable receipt identity fields."""
        checks = [
            ("run_id", row["run_id"], receipt["run"]["object_id"]),
            ("run_content_hash", row["run_content_hash"], receipt["run"]["content_hash"]),
            ("task_id", row["task_id"], receipt["task"]["object_id"]),
            ("task_revision", row["task_revision"], receipt["task"]["revision"]),
            ("task_content_hash", row["task_content_hash"], receipt["task"]["content_hash"]),
            ("spec_id", row["spec_id"], receipt["spec"]["object_id"]),
            ("spec_revision", row["spec_revision"], receipt["spec"]["revision"]),
            ("spec_content_hash", row["spec_content_hash"], receipt["spec"]["content_hash"]),
            ("manifest_id", row["manifest_id"], receipt["manifest"]["object_id"]),
            ("manifest_revision", row["manifest_revision"], receipt["manifest"]["revision"]),
            ("manifest_content_hash", row["manifest_content_hash"], receipt["manifest"]["content_hash"]),
            ("evidence_id", row["evidence_id"], receipt["evidence"]["object_id"]),
            ("evidence_content_hash", row["evidence_content_hash"], receipt["evidence"]["content_hash"]),
            ("run_status", row["run_status"], receipt["run_status"]),
            ("bundle_location", row["bundle_location"], receipt["bundle_location"]),
            ("receipt_location", row["receipt_location"], receipt.get("receipt_location")),
        ]
        for col_name, row_val, receipt_val in checks:
            if row_val != receipt_val:
                raise ValueError(
                    f"Index corruption detected: column {col_name} value '{row_val}' "
                    f"mismatches receipt fact '{receipt_val}'"
                )

    def get_v2_run(
        self,
        run_id: str,
        *,
        run_content_hash: str | None = None,
        verify: bool = True,
    ) -> dict[str, Any] | None:
        _validate_safe_run_id(run_id)
        statement = """
            SELECT
                run_id, task_id, task_revision, task_content_hash,
                spec_id, spec_revision, spec_content_hash, run_content_hash,
                manifest_id, manifest_revision, manifest_content_hash,
                evidence_id, evidence_content_hash, run_status,
                bundle_location, receipt_location, receipt_json
            FROM v2_result_runs WHERE run_id = ?
        """
        params: list[Any] = [run_id]
        if run_content_hash is not None:
            statement += " AND run_content_hash = ?"
            params.append(run_content_hash)
        with self._connect() as connection:
            row = connection.execute(statement, params).fetchone()
        if not row:
            return None
        receipt = v2.parse(row["receipt_json"].encode("utf-8"))
        receipt["receipt_location"] = row["receipt_location"]
        if verify:
            self._verify_row_against_receipt(row, receipt)
            self._verify_stored_bundle(receipt)
        return receipt

    def query_v2_runs(
        self,
        *,
        task_id: str | None = None,
        task_revision: str | None = None,
        task_content_hash: str | None = None,
        spec_id: str | None = None,
        spec_revision: str | None = None,
        spec_content_hash: str | None = None,
        run_id: str | None = None,
        run_content_hash: str | None = None,
        manifest_id: str | None = None,
        manifest_revision: str | None = None,
        manifest_content_hash: str | None = None,
        evidence_id: str | None = None,
        evidence_content_hash: str | None = None,
        run_status: str | None = None,
        verify: bool = True,
    ) -> list[dict[str, Any]]:
        if run_id is not None:
            _validate_safe_run_id(run_id)
        clauses: list[str] = []
        values: list[Any] = []
        filters = [
            ("task_id", task_id),
            ("task_revision", task_revision),
            ("task_content_hash", task_content_hash),
            ("spec_id", spec_id),
            ("spec_revision", spec_revision),
            ("spec_content_hash", spec_content_hash),
            ("run_id", run_id),
            ("run_content_hash", run_content_hash),
            ("manifest_id", manifest_id),
            ("manifest_revision", manifest_revision),
            ("manifest_content_hash", manifest_content_hash),
            ("evidence_id", evidence_id),
            ("evidence_content_hash", evidence_content_hash),
            ("run_status", run_status),
        ]
        for column, value in filters:
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        statement = """
            SELECT
                run_id, task_id, task_revision, task_content_hash,
                spec_id, spec_revision, spec_content_hash, run_content_hash,
                manifest_id, manifest_revision, manifest_content_hash,
                evidence_id, evidence_content_hash, run_status,
                bundle_location, receipt_location, receipt_json
            FROM v2_result_runs
        """
        if clauses:
            statement += " WHERE " + " AND ".join(clauses)
        statement += " ORDER BY rowid"
        with self._connect() as connection:
            rows = connection.execute(statement, values).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            receipt = v2.parse(row["receipt_json"].encode("utf-8"))
            receipt["receipt_location"] = row["receipt_location"]
            if verify:
                self._verify_row_against_receipt(row, receipt)
                self._verify_stored_bundle(receipt)
            results.append(receipt)
        return results

    def load_v2_bundle_facts(self, run_id: str) -> dict[str, Any]:
        """Load and return verified fact objects directly from the stored snapshot."""
        receipt = self.get_v2_run(run_id, verify=True)
        if receipt is None:
            raise ValueError(f"Protocol v2 run not found: {run_id}")
        bundle_dir = Path(receipt["bundle_location"])
        return {
            "task": v2.parse(v2.safe_read(bundle_dir, "materials/task.json")),
            "spec": v2.parse(v2.safe_read(bundle_dir, "materials/spec.json")),
            "run": v2.parse(v2.safe_read(bundle_dir, "run.json")),
            "manifest": v2.parse(v2.safe_read(bundle_dir, "manifest.json")),
            "evidence": v2.parse(v2.safe_read(bundle_dir, "evidence.json")),
            "bundle_dir": bundle_dir,
            "receipt": receipt,
        }

    def save_v2_report(self, receipt: dict[str, Any], report_path: Path | str) -> dict[str, Any]:
        """Index one create-only derived report bound to stored immutable Protocol v2 facts."""
        run_ref = receipt.get("run")
        if not run_ref or "object_id" not in run_ref:
            raise ValueError("Invalid receipt: missing run reference")
        run_id = _validate_safe_run_id(run_ref["object_id"])

        stored = self.get_v2_run(run_id, verify=True)
        if stored is None:
            raise ValueError(f"Protocol v2 run is not stored: {run_id}")

        for ref_key in ("run", "evidence", "task", "spec", "manifest"):
            if receipt.get(ref_key) != stored.get(ref_key):
                raise ValueError(f"Receipt {ref_key} reference mismatch with stored run facts")

        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM v2_result_reports WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise FileExistsError(f"Protocol v2 report already stored for run: {run_id}")

        src_path = Path(report_path).resolve()
        if not src_path.is_file():
            raise FileNotFoundError(f"Protocol v2 report file not found: {src_path}")
        raw_report = src_path.read_bytes()

        expected_bytes = render_v2_report(stored).encode("utf-8")
        if raw_report != expected_bytes:
            raise ValueError(
                f"Report content does not match expected deterministic report for run {run_id}"
            )

        store_report_dir = (self.config.artifacts_dir / "v2" / "reports").resolve()
        store_report_dir.mkdir(parents=True, exist_ok=True)
        store_report_path = (store_report_dir / f"{run_id}.report.md").resolve()
        if store_report_path.parent != store_report_dir:
            raise ValueError(f"Report path escapes reports directory: {store_report_path}")

        if store_report_path.exists() and src_path != store_report_path:
            raise FileExistsError(f"Protocol v2 report already exists in store: {store_report_path}")

        if src_path != store_report_path:
            self._write_bytes_create_only(store_report_path, raw_report)
            actual_report_path = store_report_path
        else:
            actual_report_path = src_path

        report_sha256 = v2.sha(raw_report)
        evidence = stored["evidence"]

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO v2_result_reports (
                    run_id, evidence_id, evidence_content_hash, report_location, report_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, evidence["object_id"], evidence["content_hash"], str(actual_report_path), report_sha256),
            )

        return {
            "run_id": run_id,
            "evidence_id": evidence["object_id"],
            "evidence_content_hash": evidence["content_hash"],
            "report_location": str(actual_report_path),
            "report_sha256": report_sha256,
        }

    def get_v2_report(self, run_id: str, *, verify: bool = True) -> dict[str, Any] | None:
        """Query and optionally verify the derived report bound to a stored Protocol v2 run."""
        _validate_safe_run_id(run_id)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT run_id, evidence_id, evidence_content_hash, report_location, report_sha256
                FROM v2_result_reports WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        if not row:
            return None
        report_info = {
            "run_id": row["run_id"],
            "evidence_id": row["evidence_id"],
            "evidence_content_hash": row["evidence_content_hash"],
            "report_location": row["report_location"],
            "report_sha256": row["report_sha256"],
        }
        if verify:
            path = Path(row["report_location"])
            if not path.is_file():
                raise FileNotFoundError(f"Report file missing: {path}")
            raw = path.read_bytes()
            if v2.sha(raw) != row["report_sha256"]:
                raise ValueError(f"Report content sha256 mismatch for run {run_id}")
            stored = self.get_v2_run(run_id, verify=True)
            if stored is None:
                raise ValueError(f"Run {run_id} referenced by report is not stored")
            if (row["evidence_id"], row["evidence_content_hash"]) != (
                stored["evidence"]["object_id"],
                stored["evidence"]["content_hash"],
            ):
                raise ValueError(f"Report index evidence reference mismatch with stored run facts for run {run_id}")
            expected_bytes = render_v2_report(stored).encode("utf-8")
            if raw != expected_bytes:
                raise ValueError(f"Report content does not match expected deterministic report for run {run_id}")
        return report_info

    @staticmethod
    def _read_v2_bundle(bundle: Path) -> dict[str, Any]:
        bundle = Path(bundle).resolve()
        if not bundle.is_dir():
            raise FileNotFoundError(f"Protocol v2 bundle directory does not exist: {bundle}")

        for p in bundle.rglob("*"):
            if p.is_symlink():
                raise ValueError(f"Symlinks are forbidden in bundle: {p}")

        file_names = {
            "task": "materials/task.json",
            "spec": "materials/spec.json",
            "run": "run.json",
            "manifest": "manifest.json",
            "evidence": "evidence.json",
        }
        raw = {name: v2.safe_read(bundle, relative) for name, relative in file_names.items()}
        task, spec, run, manifest, evidence = (v2.parse(raw[name]) for name in file_names)
        definitions = v2.Definitions()
        v2.validate_spec(spec, task, definitions)
        v2.validate_manifest(bundle, manifest, run, definitions, task=task, spec=spec)
        ResultStore._validate_v2_handoff(bundle, task, spec, run, manifest, evidence)

        if spec.get("experiment_type") == "data_quality":
            from research_lab.runners.v2_bridge import case
            case.admission(bundle / "materials")

            lock_path = bundle / "input-lock.json"
            if not lock_path.is_file():
                raise FileNotFoundError(f"Missing required input-lock.json for run: {run['run_id']}")
            lock_raw = v2.safe_read(bundle, "input-lock.json")
            lock_sha = v2.sha(lock_raw)
            if run.get("input_lock_sha256") and run["input_lock_sha256"] != lock_sha:
                raise ValueError(
                    f"input-lock.json sha256 mismatch: run declares {run['input_lock_sha256']}, got {lock_sha}"
                )
            lock = v2.parse(lock_raw)
            if lock.get("scientific_fingerprint") != run.get("scientific_fingerprint"):
                raise ValueError("input-lock.json scientific_fingerprint mismatch with run")
            if "resolved_computation_manifest" in run and lock.get("resolved_computation_manifest") != run.get("resolved_computation_manifest"):
                raise ValueError("input-lock.json resolved_computation_manifest mismatch with run")
            prep_sha = v2.sha(v2.safe_read(bundle / "materials", "preparation.json"))
            if lock.get("preparation_sha256") != prep_sha:
                raise ValueError("input-lock.json preparation_sha256 mismatch with materials/preparation.json")

        inventory: dict[str, str] = {}
        for p in bundle.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(bundle))
                inventory[rel] = v2.sha(v2.safe_read(bundle, rel))

        return {
            "run_id": run["run_id"],
            "run_status": run["run_status"],
            "task_ref": v2.check_record(task, "research_task"),
            "spec_ref": v2.check_record(spec, "experiment_spec"),
            "run_ref": v2.check_record(run, "experiment_run"),
            "manifest_ref": v2.check_record(manifest, "artifact_manifest"),
            "evidence_ref": v2.check_record(evidence, "result_evidence"),
            "bundle_file_sha256": inventory,
        }

    @staticmethod
    def _validate_v2_handoff(
        bundle: Path,
        task: dict[str, Any],
        spec: dict[str, Any],
        run: dict[str, Any],
        manifest: dict[str, Any],
        evidence: dict[str, Any],
    ) -> None:
        exp_type = spec.get("experiment_type")
        if exp_type == "trading_backtest":
            if run.get("run_status") == "FAILED":
                return
            definitions = v2.Definitions()
            criteria_id = "phase0.issue481.review_evidence.criteria"
            criteria_def = next(
                e for e in definitions.entries if e["kind"] == "criteria" and e["name"] == criteria_id
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

            request = {
                "schema_version": "research_lab.agent_handoff.v2",
                "handoff_id": f"store-review-{run['run_id']}",
                "message_kind": "request",
                "operation": "review_evidence",
                "sender_role": "execution",
                "recipient_role": "critic",
                "context_refs": context,
                "artifact_requirements": {
                    "role_profile_ref": manifest["artifact_profile"],
                    "required_roles": sorted(v2.COMMON | v2.TYPED[spec["experiment_type"]]),
                    "exact_refs": present_artifacts,
                },
                "expected_outputs": [
                    {"object_type": "review", "schema_version": "research_lab.review.v2"}
                ],
                "review_scope": "research_assessment",
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
                "recommendation": "improve",
                "reason": "Deterministic trading_backtest execution completed.",
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
                "review_scope": "research_assessment",
            }
            v2.validate_handoff(request, records, response, root=bundle)
            return

        request = {
            "schema_version": "research_lab.agent_handoff.v2",
            "handoff_id": f"store-{run['run_id']}",
            "message_kind": "request",
            "operation": "execute_spec",
            "sender_role": "research",
            "recipient_role": "execution",
            "context_refs": {
                "research_task": v2.check_record(task, "research_task"),
                "experiment_spec": v2.check_record(spec, "experiment_spec"),
            },
            "artifact_requirements": {
                "role_profile_ref": v2.ROLE_PROFILE,
                "required_roles": sorted(v2.COMMON | v2.TYPED[spec["experiment_type"]]),
                "exact_refs": [],
            },
            "expected_outputs": [
                {"object_type": "experiment_run", "schema_version": "research_lab.run.v2"},
                {"object_type": "artifact_manifest", "schema_version": "research_lab.artifact_manifest.v2"},
                {"object_type": "result_evidence", "schema_version": "research_lab.evidence.v2"},
            ],
        }
        response = {
            "schema_version": "research_lab.agent_handoff.v2",
            "handoff_id": f"stored-{run['run_id']}",
            "message_kind": "response",
            "operation": "execute_spec",
            "sender_role": "execution",
            "recipient_role": "research",
            "context_refs": request["context_refs"],
            "in_reply_to": request["handoff_id"],
            "status": "completed",
            "output_refs": [
                v2.check_record(run, "experiment_run"),
                v2.check_record(manifest, "artifact_manifest"),
                v2.check_record(evidence, "result_evidence"),
            ],
        }
        v2.validate_handoff(
            request,
            {
                "research_task": task,
                "experiment_spec": spec,
                "experiment_run": run,
                "artifact_manifest": manifest,
                "result_evidence": evidence,
            },
            response,
            root=bundle,
        )

    @staticmethod
    def _write_bytes_create_only(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Refusing to overwrite existing artifact: {path}") from None
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)

    @staticmethod
    def _write_json_create_only(path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Refusing to overwrite existing artifact: {path}") from None
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)

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
