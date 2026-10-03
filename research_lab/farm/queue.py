from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Protocol

from research_lab.schemas import ExperimentPlan, FarmClaim, FarmResultCallback, FarmTask, FarmWorker


class FarmQueueError(ValueError):
    """The persistent local queue rejected a lifecycle operation."""


class TaskQueue(Protocol):
    """Replaceable queue boundary; this MVP supplies only SQLiteTaskQueue."""

    def submit(self, plan: ExperimentPlan) -> FarmTask: ...

    def claim(self, worker_id: str, *, lease_seconds: int = 60) -> FarmClaim | None: ...


class SQLiteTaskQueue:
    """Small file-backed local queue with atomic claims and expiring leases.

    It has no listener, network endpoint, or background recovery loop. Recovery
    occurs during an explicit claim attempt, so restarting a local process is
    sufficient to recover an expired task.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def register(self, worker: FarmWorker) -> FarmWorker:
        now = _now()
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO workers(worker_id, status, registered_at, heartbeat_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(worker_id) DO UPDATE SET status=excluded.status, heartbeat_at=excluded.heartbeat_at""",
                (worker.worker_id, worker.status, _stamp(worker.registered_at), _stamp(now)),
            )
        return self.get_worker(worker.worker_id)  # type: ignore[return-value]

    def heartbeat(self, worker_id: str, *, status: str = "online") -> FarmWorker:
        with self._connection() as connection:
            changed = connection.execute(
                "UPDATE workers SET status=?, heartbeat_at=? WHERE worker_id=?",
                (status, _stamp(_now()), worker_id),
            ).rowcount
        if not changed:
            raise FarmQueueError(f"worker is not registered: {worker_id}")
        return self.get_worker(worker_id)  # type: ignore[return-value]

    def get_worker(self, worker_id: str) -> FarmWorker | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM workers WHERE worker_id=?", (worker_id,)).fetchone()
        return _worker_from_row(row) if row else None

    def workers(self) -> list[FarmWorker]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM workers ORDER BY worker_id").fetchall()
        return [_worker_from_row(row) for row in rows]

    def submit(self, plan: ExperimentPlan) -> FarmTask:
        if plan.status != "queued" or not plan.approved_by or plan.approved_at is None:
            raise FarmQueueError("only approved queued Sol plans can be submitted")
        task_id = f"farm-{plan.plan_id}"
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if row:
                existing = _task_from_row(row)
                if _task_binding(existing) != (plan.plan_id, plan.task_content_hash, plan.proposal_content_hash, plan.integrity_hash):
                    raise FarmQueueError("Farm task identity collision")
                return existing
            now = _now()
            connection.execute(
                """INSERT INTO tasks(task_id, plan_id, task_content_hash, proposal_content_hash, plan_integrity_hash,
                   status, attempt, worker_id, lease_expires_at, created_at, updated_at, error_message)
                   VALUES (?, ?, ?, ?, ?, 'queued', 0, NULL, NULL, ?, ?, NULL)""",
                (task_id, plan.plan_id, plan.task_content_hash, plan.proposal_content_hash, plan.integrity_hash, _stamp(now), _stamp(now)),
            )
        return self.get_task(task_id)  # type: ignore[return-value]

    def get_task(self, task_id: str) -> FarmTask | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return _task_from_row(row) if row else None

    def claimed_tasks(self) -> list[FarmTask]:
        """Return claim snapshots for the runtime's explicit recovery pass."""
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM tasks WHERE status='claimed' ORDER BY task_id").fetchall()
        return [_task_from_row(row) for row in rows]

    def claim(self, worker_id: str, *, lease_seconds: int = 60) -> FarmClaim | None:
        if lease_seconds < 1:
            raise FarmQueueError("lease_seconds must be positive")
        with self._connection(immediate=True) as connection:
            if connection.execute("SELECT 1 FROM workers WHERE worker_id=? AND status='online'", (worker_id,)).fetchone() is None:
                raise FarmQueueError(f"worker is not registered and online: {worker_id}")
            now = _now()
            connection.execute(
                """UPDATE tasks SET status='queued', worker_id=NULL, lease_expires_at=NULL, updated_at=?
                   WHERE status='claimed' AND lease_expires_at < ?""", (_stamp(now), _stamp(now)),
            )
            row = connection.execute("SELECT * FROM tasks WHERE status='queued' ORDER BY created_at, task_id LIMIT 1").fetchone()
            if row is None:
                return None
            lease = now + timedelta(seconds=lease_seconds)
            changed = connection.execute(
                """UPDATE tasks SET status='claimed', attempt=attempt+1, worker_id=?, lease_expires_at=?, updated_at=?
                   WHERE task_id=? AND status='queued'""",
                (worker_id, _stamp(lease), _stamp(now), row["task_id"]),
            ).rowcount
            if changed != 1:
                return None
            claimed = _task_from_row(connection.execute("SELECT * FROM tasks WHERE task_id=?", (row["task_id"],)).fetchone())
        return FarmClaim(task=claimed, worker_id=worker_id, attempt=claimed.attempt, lease_expires_at=lease)

    def validate_callback(self, callback: FarmResultCallback) -> FarmTask:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (callback.task_id,)).fetchone()
        if row is None:
            raise FarmQueueError(f"Farm task not found: {callback.task_id}")
        task = _task_from_row(row)
        if task.status != "claimed" or task.worker_id != callback.worker_id or task.attempt != callback.attempt:
            raise FarmQueueError("callback is not owned by the active Farm claim attempt")
        if task.lease_expires_at is None or task.lease_expires_at < _now():
            raise FarmQueueError("callback lease has expired")
        return task

    def finish(self, callback: FarmResultCallback, *, status: str, error_message: str | None = None) -> FarmTask:
        if status not in {"completed", "failed", "queued"}:
            raise FarmQueueError("invalid Farm completion status")
        with self._connection(immediate=True) as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (callback.task_id,)).fetchone()
            if row is None:
                raise FarmQueueError(f"Farm task not found: {callback.task_id}")
            task = _task_from_row(row)
            if task.status != "claimed" or task.worker_id != callback.worker_id or task.attempt != callback.attempt:
                raise FarmQueueError("callback is not owned by the active Farm claim attempt")
            connection.execute(
                """UPDATE tasks SET status=?, worker_id=?, lease_expires_at=NULL, error_message=?, updated_at=?
                   WHERE task_id=?""",
                (status, None if status == "queued" else callback.worker_id, error_message, _stamp(_now()), callback.task_id),
            )
        return self.get_task(callback.task_id)  # type: ignore[return-value]

    def requeue(self, callback: FarmResultCallback, plan: ExperimentPlan, *, error_message: str | None = None) -> FarmTask:
        """Rebind a retry to Sol's newly sealed queued plan version."""
        if plan.status != "queued" or not plan.approved_by:
            raise FarmQueueError("only an approved queued Sol retry can be requeued")
        with self._connection(immediate=True) as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (callback.task_id,)).fetchone()
            if row is None:
                raise FarmQueueError(f"Farm task not found: {callback.task_id}")
            task = _task_from_row(row)
            if task.status != "claimed" or task.worker_id != callback.worker_id or task.attempt != callback.attempt:
                raise FarmQueueError("callback is not owned by the active Farm claim attempt")
            connection.execute(
                """UPDATE tasks SET plan_integrity_hash=?, status='queued', worker_id=NULL, lease_expires_at=NULL,
                   error_message=?, updated_at=? WHERE task_id=?""",
                (plan.integrity_hash, error_message, _stamp(_now()), callback.task_id),
            )
        return self.get_task(callback.task_id)  # type: ignore[return-value]

    def commit_callback(
        self,
        callback: FarmResultCallback,
        transition: Callable[[FarmTask], ExperimentPlan],
    ) -> tuple[FarmTask, ExperimentPlan]:
        """Atomically hold the active claim while Sol consumes its callback.

        The plan JSON and SQLite cannot share one storage transaction. Holding
        ``BEGIN IMMEDIATE`` prevents a lease recovery/new attempt between the
        final ownership check and Sol's state transition. If Sol rejects the
        callback, the queue transaction rolls back and leaves the claim intact.
        """
        with self._connection(immediate=True) as connection:
            task = self._validate_callback(connection, callback)
            plan = transition(task)
            self._before_callback_update(task, plan)
            if plan.status == "review":
                status, owner, integrity = "completed", callback.worker_id, task.plan_integrity_hash
            elif plan.status == "queued":
                status, owner, integrity = "queued", None, plan.integrity_hash
            else:
                status, owner, integrity = "failed", callback.worker_id, task.plan_integrity_hash
            connection.execute(
                """UPDATE tasks SET plan_integrity_hash=?, status=?, worker_id=?, lease_expires_at=NULL,
                   error_message=?, updated_at=? WHERE task_id=?""",
                (integrity, status, owner, plan.error_message, _stamp(_now()), task.task_id),
            )
            updated = _task_from_row(connection.execute("SELECT * FROM tasks WHERE task_id=?", (task.task_id,)).fetchone())
        return updated, plan

    def reconcile(self, task: FarmTask, plan: ExperimentPlan) -> FarmTask:
        """Converge a claim after an interruption between Sol and queue writes.

        Only the exact task/attempt recorded by Sol can settle a queue row. It
        never creates a result or advances Sol, so its caller cannot bypass the
        ResultStore/Alpha validation performed by the original callback.
        """
        if plan.farm_task_id != task.task_id or plan.farm_attempt != task.attempt:
            return self.get_task(task.task_id) or task
        if plan.status in {"review", "archived"}:
            status, owner, integrity = "completed", task.worker_id, task.plan_integrity_hash
        elif plan.status == "failed":
            status, owner, integrity = "failed", task.worker_id, task.plan_integrity_hash
        elif plan.status == "queued":
            status, owner, integrity = "queued", None, plan.integrity_hash
        else:
            return self.get_task(task.task_id) or task
        with self._connection(immediate=True) as connection:
            changed = connection.execute(
                """UPDATE tasks SET plan_integrity_hash=?, status=?, worker_id=?, lease_expires_at=NULL,
                   error_message=?, updated_at=? WHERE task_id=? AND attempt=? AND status='claimed'""",
                (integrity, status, owner, plan.error_message, _stamp(_now()), task.task_id, task.attempt),
            ).rowcount
            if not changed:
                row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()
                return _task_from_row(row) if row else task
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()
        return _task_from_row(row)

    def release(self, claim: FarmClaim) -> None:
        callback = FarmResultCallback(task_id=claim.task.task_id, worker_id=claim.worker_id, attempt=claim.attempt,
                                      result=_placeholder_result(claim.task.plan_id))
        self.finish(callback, status="queued", error_message="Sol rejected claim before execution")

    @contextmanager
    def _connection(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        if immediate:
            connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except Exception:
            if immediate:
                connection.rollback()
            raise
        else:
            if immediate:
                connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS workers (
                    worker_id TEXT PRIMARY KEY, status TEXT NOT NULL, registered_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, task_content_hash TEXT NOT NULL,
                    proposal_content_hash TEXT NOT NULL, plan_integrity_hash TEXT NOT NULL, status TEXT NOT NULL,
                    attempt INTEGER NOT NULL, worker_id TEXT, lease_expires_at TEXT, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, error_message TEXT
                );
            """)

    def _before_callback_update(self, task: FarmTask, plan: ExperimentPlan) -> None:
        """Test seam for interruption after the durable Sol transition."""
        del task, plan

    def _validate_callback(self, connection: sqlite3.Connection, callback: FarmResultCallback) -> FarmTask:
        row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (callback.task_id,)).fetchone()
        if row is None:
            raise FarmQueueError(f"Farm task not found: {callback.task_id}")
        task = _task_from_row(row)
        if task.status != "claimed" or task.worker_id != callback.worker_id or task.attempt != callback.attempt:
            raise FarmQueueError("callback is not owned by the active Farm claim attempt")
        if task.lease_expires_at is None or task.lease_expires_at < _now():
            raise FarmQueueError("callback lease has expired")
        return task


def _task_binding(task: FarmTask) -> tuple[str, str, str, str]:
    return task.plan_id, task.task_content_hash, task.proposal_content_hash, task.plan_integrity_hash


def _task_from_row(row: sqlite3.Row) -> FarmTask:
    return FarmTask(task_id=row["task_id"], plan_id=row["plan_id"], task_content_hash=row["task_content_hash"],
                    proposal_content_hash=row["proposal_content_hash"], plan_integrity_hash=row["plan_integrity_hash"],
                    status=row["status"], attempt=row["attempt"], worker_id=row["worker_id"],
                    lease_expires_at=_read_stamp(row["lease_expires_at"]), created_at=_read_stamp(row["created_at"]),
                    updated_at=_read_stamp(row["updated_at"]), error_message=row["error_message"])


def _worker_from_row(row: sqlite3.Row) -> FarmWorker:
    return FarmWorker(worker_id=row["worker_id"], status=row["status"], registered_at=_read_stamp(row["registered_at"]),
                      heartbeat_at=_read_stamp(row["heartbeat_at"]))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _read_stamp(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _placeholder_result(plan_id: str):
    # release() does not inspect the result; a valid schema instance keeps its API uniform.
    from research_lab.schemas import ExperimentResult
    return ExperimentResult(experiment_id=plan_id, status="failed", strategy_name="farm", factor_name="farm")
