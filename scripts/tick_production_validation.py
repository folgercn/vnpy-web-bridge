from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable
from zoneinfo import ZoneInfo


CONFIRMATION = "ISSUE79_PRODUCTION"
ACTIVE_STATES = {"pending", "firing", "acknowledged", "recovering"}
SENSITIVE_KEY_PARTS = ("password", "passwd", "secret", "token", "chat_id", "dsn", "rpc_address")
PROBE_SOURCE = r'''
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import statistics
import sys
import time
import urllib.request

import psycopg

from app.core.config import Settings
from app.core.security import CurrentUser, configured_users, create_access_token
from app.services.market_data_service import QuestDbMarketDataService


def output(value):
    print(json.dumps(value, ensure_ascii=False, default=lambda item: item.isoformat() if hasattr(item, "isoformat") else str(item)))


def api_request(path, method="GET", payload=None):
    settings = Settings()
    users = configured_users(settings)
    username = next((name for name, item in users.items() if item["role"] == "admin"), None)
    if not username:
        raise RuntimeError("production admin user is not configured")
    token = create_access_token(CurrentUser(username, "admin"), settings)
    request = urllib.request.Request(
        "http://127.0.0.1:8080" + path,
        method=method,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)["data"]


def api_get(path):
    return api_request(path)


def connect():
    settings = Settings()
    if not settings.questdb_pg_dsn:
        raise RuntimeError("QUESTDB_PG_DSN is not configured")
    return settings, psycopg.connect(settings.questdb_pg_dsn, autocommit=True)


def history_candidates():
    _, conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT trading_day, count(), count_distinct(vt_symbol), min(ts), max(ts)
            FROM market_ticks
            WHERE trading_day != ''
            GROUP BY trading_day
            ORDER BY trading_day DESC
            LIMIT 30
            """
        ).fetchall()
        output([
            {"trading_day": row[0], "rows": row[1], "symbols": row[2], "start": row[3], "end": row[4]}
            for row in rows
        ])
    finally:
        conn.close()


def day_details(trading_day):
    settings, conn = connect()
    try:
        summary = conn.execute(
            "SELECT count(), count_distinct(vt_symbol), min(ts), max(ts), count_distinct(exchange), count_distinct(ingest_id) FROM market_ticks WHERE trading_day = %s",
            (trading_day,),
        ).fetchone()
        exchanges = conn.execute(
            "SELECT exchange, count(), count_distinct(vt_symbol) FROM market_ticks WHERE trading_day = %s GROUP BY exchange ORDER BY exchange",
            (trading_day,),
        ).fetchall()
        contracts = conn.execute(
            "SELECT vt_symbol, symbol, exchange, count() AS row_count FROM market_ticks WHERE trading_day = %s GROUP BY vt_symbol, symbol, exchange ORDER BY row_count DESC LIMIT 20",
            (trading_day,),
        ).fetchall()
        samples = conn.execute(
            """
            SELECT ts, received_at, ingest_id, ingest_seq, vt_symbol, symbol, exchange, trading_day, action_day,
                   last_price, bid_price_1, ask_price_1, volume, open_interest
            FROM market_ticks
            WHERE trading_day = %s
            ORDER BY ts DESC, ingest_seq DESC
            LIMIT 1000
            """,
            (trading_day,),
        ).fetchall()
        buckets = conn.execute(
            "SELECT ts, count() FROM market_ticks WHERE trading_day = %s SAMPLE BY 1s FILL(NONE) ALIGN TO CALENDAR",
            (trading_day,),
        ).fetchall()
        required_nulls = {
            "ts": 0,
            "received_at": 0,
            "ingest_id": 0,
            "ingest_seq": 0,
            "vt_symbol": 0,
            "symbol": 0,
            "exchange": 0,
            "trading_day": 0,
            "action_day": 0,
            "last_price": 0,
            "bid_price_1": 0,
            "ask_price_1": 0,
        }
        ordered = True
        previous = None
        sample_symbols = set()
        for row in samples:
            values = dict(zip(
                ("ts", "received_at", "ingest_id", "ingest_seq", "vt_symbol", "symbol", "exchange", "trading_day", "action_day", "last_price", "bid_price_1", "ask_price_1", "volume", "open_interest"),
                row,
            ))
            for key in required_nulls:
                if values[key] is None or values[key] == "":
                    required_nulls[key] += 1
            current = (values["ts"], int(values["ingest_seq"] or 0))
            if previous is not None and current > previous:
                ordered = False
            previous = current
            sample_symbols.add(values["vt_symbol"])

        market = QuestDbMarketDataService(settings)
        query_rows = market.query_ticks(vt_symbol=samples[0][4], limit=50) if samples else []
        csv_text = market.export_ticks_csv(query_rows)
        bars = (
            conn.execute(
                """
                SELECT ts, first(last_price), max(last_price), min(last_price), last(last_price)
                FROM market_ticks
                WHERE trading_day = %s AND vt_symbol = %s
                SAMPLE BY 1m FILL(NONE) ALIGN TO CALENDAR
                LIMIT 20
                """,
                (trading_day, samples[0][4]),
            ).fetchall()
            if samples
            else []
        )
        market.stop()

        tps_values = [int(row[1]) for row in buckets]
        output({
            "trading_day": trading_day,
            "rows": int(summary[0]),
            "symbols": int(summary[1]),
            "start": summary[2],
            "end": summary[3],
            "exchange_count": int(summary[4]),
            "duplicate_ingest_ids": int(summary[0]) - int(summary[5]),
            "exchanges": [{"exchange": row[0], "rows": int(row[1]), "symbols": int(row[2])} for row in exchanges],
            "contracts": [
                {"vt_symbol": row[0], "symbol": row[1], "exchange": row[2], "rows": int(row[3])}
                for row in contracts
            ],
            "active_seconds": len(tps_values),
            "peak_tps": max(tps_values) if tps_values else 0,
            "average_active_tps": round(statistics.fmean(tps_values), 2) if tps_values else 0,
            "sample_size": len(samples),
            "sample_symbols": len(sample_symbols),
            "required_field_nulls": required_nulls,
            "stable_ts_ingest_seq_order": ordered,
            "history_query_rows": len(query_rows),
            "csv_header_ok": csv_text.startswith("datetime,received_at,ingest_id,ingest_seq,"),
            "bar_rows": len(bars),
        })
    finally:
        conn.close()


def spool_files():
    settings = Settings()
    directory = Path(settings.questdb_tick_spool_dir)
    output({
        "active_exists": (directory / "ticks.active.jsonl").exists(),
        "active_bytes": (directory / "ticks.active.jsonl").stat().st_size if (directory / "ticks.active.jsonl").exists() else 0,
        "replay_files": len(list(directory.glob("ticks.replaying.*.jsonl"))),
        "bad_files": len(list(directory.glob("*.bad"))),
    })


def drop_partition(partition_day):
    _, conn = connect()
    try:
        parsed = datetime.strptime(partition_day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = parsed + timedelta(days=1)
        before = conn.execute("SELECT count() FROM market_ticks WHERE ts >= %s AND ts < %s", (parsed, end)).fetchone()[0]
        if before:
            conn.execute(f"ALTER TABLE market_ticks DROP PARTITION LIST '{partition_day}'")
        deadline = datetime.now(timezone.utc) + timedelta(seconds=30)
        remaining = before
        while datetime.now(timezone.utc) < deadline:
            remaining = conn.execute("SELECT count() FROM market_ticks WHERE ts >= %s AND ts < %s", (parsed, end)).fetchone()[0]
            if remaining == 0:
                break
            time.sleep(0.25)
        output({"partition_day": partition_day, "deleted": int(before), "remaining": int(remaining)})
    finally:
        conn.close()


action = sys.argv[1]
if action == "status":
    output(api_get("/api/market/data/status"))
elif action == "rpc":
    rpc = api_get("/api/rpc/probe")
    output({"connected": bool(rpc.get("connected")), "gateway_name": rpc.get("gateway_name")})
elif action == "subscribe":
    payload = json.loads(sys.argv[2])
    result = api_request("/api/market/subscribe", method="POST", payload=payload)
    output({"vt_symbol": result.get("vt_symbol"), "subscribed": bool(result.get("subscribed"))})
elif action == "monitor":
    output({"summary": api_get("/api/monitor/summary"), "incidents": api_get("/api/monitor/incidents")})
elif action == "history_candidates":
    history_candidates()
elif action == "day_details":
    day_details(sys.argv[2])
elif action == "spool_files":
    spool_files()
elif action == "drop_partition":
    drop_partition(sys.argv[2])
else:
    raise RuntimeError("unknown probe action: " + action)
'''


class ValidationError(RuntimeError):
    pass


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


class DockerHost:
    def __init__(self, *, web_container: str, questdb_container: str, deploy_path: Path | None = None) -> None:
        self.web_container = web_container
        self.questdb_container = questdb_container
        self.deploy_path = deploy_path.resolve() if deploy_path else None

    def run(self, args: list[str], *, input_text: str | None = None, check: bool = True, timeout: float = 180) -> CommandResult:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise ValidationError(f"command failed ({result.returncode}): {' '.join(args)}: {result.stderr.strip()}")
        return CommandResult(result.stdout, result.stderr, result.returncode)

    def docker(self, *args: str, check: bool = True, timeout: float = 180) -> CommandResult:
        return self.run(["docker", *args], check=check, timeout=timeout)

    def probe(self, action: str, value: str | None = None) -> Any:
        args = ["docker", "exec", "-i", self.web_container, "python", "-", action]
        if value is not None:
            args.append(value)
        result = self.run(args, input_text=PROBE_SOURCE, timeout=120)
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise ValidationError(f"invalid {action} probe output: {result.stdout[-1000:]}") from exc

    def container_state(self, container: str) -> dict[str, Any]:
        result = self.docker("inspect", container, "--format", "{{json .State}}")
        return json.loads(result.stdout)

    def wait_container(self, container: str, *, healthy: bool, timeout: float = 180) -> dict[str, Any]:
        deadline = time.time() + timeout
        last: dict[str, Any] = {}
        while time.time() < deadline:
            try:
                last = self.container_state(container)
            except Exception:
                last = {}
            running = bool(last.get("Running"))
            health = (last.get("Health") or {}).get("Status")
            if running and (not healthy or health == "healthy"):
                return last
            time.sleep(3)
        raise ValidationError(f"container did not recover: {container}; last_state={last}")

    def ensure_started(self) -> None:
        questdb_state = self.container_state(self.questdb_container)
        if not questdb_state.get("Running"):
            self.docker("start", self.questdb_container)
        self.wait_container(self.questdb_container, healthy=True)

        web_state = self.container_state(self.web_container)
        web_health = (web_state.get("Health") or {}).get("Status")
        if web_state.get("Restarting") or web_health == "unhealthy":
            self.restore_production_web()
        elif not web_state.get("Running"):
            self.docker("start", self.web_container)
        self.wait_container(self.web_container, healthy=True)

    def restore_production_web(self) -> None:
        if self.deploy_path is None:
            raise ValidationError("deploy path is required to recover an unhealthy Web Bridge")
        compose_file = self.deploy_path / "deployments/docker-compose.prod.yml"
        env_file = self.deploy_path / ".env"
        if not compose_file.is_file() or not env_file.is_file():
            raise ValidationError("production compose or env file is missing")

        override = self.deploy_path / "logs/watchdog/issue45-rpc-override.yml"
        override.unlink(missing_ok=True)
        maintenance = self.deploy_path / "logs/watchdog/maintenance.json"
        try:
            payload = json.loads(maintenance.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            payload = {}
        if payload.get("source") == "issue45-production-validation":
            maintenance.unlink(missing_ok=True)

        self.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(env_file),
                "-f",
                str(compose_file),
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "web-bridge",
            ],
            timeout=180,
        )

    def resource_snapshot(self) -> dict[str, Any]:
        stats = self.docker(
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            self.web_container,
            self.questdb_container,
        ).stdout.splitlines()
        questdb_size = self.docker(
            "exec", self.questdb_container, "du", "-sk", "/var/lib/questdb", check=False
        )
        questdb_kb = (
            int(questdb_size.stdout.split()[0])
            if questdb_size.returncode == 0 and questdb_size.stdout.split()
            else None
        )
        return {
            "containers": [json.loads(line) for line in stats if line.strip()],
            "questdb_data_kb": questdb_kb,
        }

    def run_load_smoke(
        self,
        *,
        count: int,
        queue_size: int,
        vt_symbol: str,
        spool_dir: str,
        base_time: str,
    ) -> dict[str, Any]:
        repo_root = Path(__file__).resolve().parents[1]
        for name in ("tick_persistence_smoke.py", "tick_persistence_load_smoke.py"):
            self.docker("cp", str(repo_root / "scripts" / name), f"{self.web_container}:/tmp/{name}")
        result = self.docker(
            "exec",
            "-e",
            "PYTHONPATH=/app/backend:/tmp",
            self.web_container,
            "python",
            "/tmp/tick_persistence_load_smoke.py",
            "--count",
            str(count),
            "--batch-size",
            str(min(1000, count)),
            "--queue-size",
            str(queue_size),
            "--vt-symbol",
            vt_symbol,
            "--spool-dir",
            spool_dir,
            "--base-time",
            base_time,
            "--timeout",
            "120",
            timeout=180,
        )
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        finally:
            self.docker("exec", self.web_container, "python", "-c", f"import shutil; shutil.rmtree({spool_dir!r}, ignore_errors=True)", check=False)


def select_complete_trading_day(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    for item in candidates:
        raw_day = str(item.get("trading_day") or "")
        try:
            trading_day = datetime.strptime(raw_day, "%Y%m%d")
            start = _as_shanghai_datetime(item["start"])
            end = _as_shanghai_datetime(item["end"])
        except (TypeError, ValueError):
            continue
        covers_night = start.date() < trading_day.date() and start.hour >= 20
        covers_day_close = end.date() == trading_day.date() and end.hour >= 14
        if covers_night and covers_day_close and int(item.get("rows") or 0) > 0:
            return item
    raise ValidationError("no historical trading_day covers both night and day sessions")


def _as_shanghai_datetime(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo("UTC"))
    return parsed.astimezone(ZoneInfo("Asia/Shanghai"))


def is_active_incident(item: dict[str, Any]) -> bool:
    return str(item.get("state") or item.get("status") or "").lower() in ACTIVE_STATES


def is_spool_clean(status: dict[str, Any], spool_files: dict[str, Any]) -> bool:
    return (
        int(status.get("spool_rows") or 0) == 0
        and int(spool_files.get("active_bytes") or 0) == 0
        and int(spool_files.get("bad_files") or 0) == 0
        and int(spool_files.get("replay_files") or 0) == 0
    )


def sanitize_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            sanitized[key] = (
                "[redacted]"
                if any(part in lowered for part in SENSITIVE_KEY_PARTS)
                else sanitize_evidence(item)
            )
        return sanitized
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, str):
        sanitized = re.sub(
            r"\b(?:https?|postgres(?:ql)?|tcp)://[^\s]+",
            "[redacted-url]",
            value,
            flags=re.IGNORECASE,
        )
        return re.sub(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", "[redacted-host]", sanitized)
    return value


class ProductionValidation:
    def __init__(self, host: DockerHost, *, outage_seconds: int, recovery_timeout: int) -> None:
        self.host = host
        self.outage_seconds = outage_seconds
        self.recovery_timeout = recovery_timeout
        self.result: dict[str, Any] = {
            "started_at": datetime.now().astimezone().isoformat(),
            "checks": [],
            "faults": [],
            "resource_samples": [],
        }

    def record(self, name: str, ok: bool, **details: Any) -> None:
        self.result["checks"].append({"name": name, "ok": ok, **details})
        if not ok:
            raise ValidationError(f"validation failed: {name}: {details}")

    def sample_resources(self, label: str) -> dict[str, Any]:
        snapshot = {"label": label, "at": datetime.now().astimezone().isoformat(), **self.host.resource_snapshot()}
        self.result["resource_samples"].append(snapshot)
        return snapshot

    def wait_status(self, predicate: Callable[[dict[str, Any]], bool], description: str, timeout: float | None = None) -> dict[str, Any]:
        deadline = time.time() + (timeout or self.recovery_timeout)
        last: dict[str, Any] = {}
        while time.time() < deadline:
            try:
                last = self.host.probe("status")
                if predicate(last):
                    return last
            except Exception:
                pass
            time.sleep(3)
        raise ValidationError(f"timed out waiting for {description}; last_status={last}")

    def preflight(self) -> None:
        self.host.ensure_started()
        state = self.host.probe("status")
        self.record("preflight_worker_alive", bool(state.get("worker_alive")), status=state)
        self.record("preflight_no_drops", int(state.get("dropped_total") or 0) == 0, dropped_total=state.get("dropped_total"))
        rpc = self.host.probe("rpc")
        self.record("preflight_rpc_connected", bool(rpc.get("connected")), rpc=rpc)
        self.result["preflight"] = state
        images = {}
        for container in (self.host.web_container, self.host.questdb_container):
            images[container] = self.host.docker("inspect", container, "--format", "{{.Config.Image}}").stdout.strip()
        self.result["images"] = images
        self.result["resources_before"] = self.sample_resources("preflight")

    def audit_history(self) -> None:
        candidates = self.host.probe("history_candidates")
        self.result["historical_candidates"] = candidates
        selected = select_complete_trading_day(candidates)
        details = self.host.probe("day_details", selected["trading_day"])
        self.result["historical_day"] = details
        self.record("historical_night_and_day", True, trading_day=details["trading_day"], start=details["start"], end=details["end"])
        self.record("historical_required_fields", not any(details["required_field_nulls"].values()), nulls=details["required_field_nulls"])
        self.record("historical_order", bool(details["stable_ts_ingest_seq_order"]))
        self.record("historical_dedup", int(details["duplicate_ingest_ids"]) == 0, duplicate_ingest_ids=details["duplicate_ingest_ids"])
        self.record("historical_query_export_bars", details["history_query_rows"] > 0 and details["csv_header_ok"] and details["bar_rows"] > 0, history_query_rows=details["history_query_rows"], bar_rows=details["bar_rows"])

    def ensure_live_tick_flow(self) -> None:
        state = self.host.probe("status")
        baseline_received = int(state.get("received_total") or 0)
        subscriptions: list[dict[str, Any]] = []
        try:
            live_status = self.wait_status(
                lambda value: int(value.get("received_total") or 0) > baseline_received,
                "existing live RPC Tick flow",
                15,
            )
        except ValidationError:
            contracts = (self.result.get("historical_day") or {}).get("contracts") or []
            for contract in contracts:
                subscriptions.append(
                    self.host.probe(
                        "subscribe",
                        json.dumps({"symbol": contract["symbol"], "exchange": contract["exchange"]}),
                    )
                )
            self.record("preflight_contract_subscriptions", bool(subscriptions) and all(item["subscribed"] for item in subscriptions), subscriptions=subscriptions)
            live_status = self.wait_status(
                lambda value: int(value.get("received_total") or 0) > baseline_received,
                "live RPC Tick flow after subscription",
                90,
            )
        self.record(
            "preflight_live_ticks",
            int(live_status.get("received_total") or 0) > baseline_received,
            before=baseline_received,
            after=live_status.get("received_total"),
            subscriptions=subscriptions,
        )

    def capacity_validation(self) -> None:
        peak_tps = int(self.result["historical_day"].get("peak_tps") or 0)
        required_tps = max(1, peak_tps * 2)
        count = max(2000, min(100_000, required_tps))
        run_id = str(int(time.time()))
        partition_day = "2099-12-31"
        base_time = f"{partition_day}T00:00:00+00:00"
        self.host.probe("drop_partition", partition_day)
        normal: dict[str, Any] = {}
        overflow: dict[str, Any] = {}
        cleanup: dict[str, Any] = {}
        try:
            normal = self.host.run_load_smoke(
                count=count,
                queue_size=count + 1,
                vt_symbol=f"ISSUE79NORMAL{run_id}.LOCAL",
                spool_dir=f"/tmp/issue79-normal-{run_id}",
                base_time=base_time,
            )
            self.record(
                "capacity_normal_2x_peak",
                normal["diff"] == 0
                and normal["dropped"] == 0
                and normal["spool_rows"] == 0
                and float(normal["enqueue_p95_ms"]) <= 10
                and float(normal["enqueue_tps"]) >= required_tps
                and float(normal["persist_tps"]) >= required_tps
                and float(normal["persistence_seconds"]) <= 2,
                required_tps=required_tps,
                result=normal,
            )

            overflow = self.host.run_load_smoke(
                count=count,
                queue_size=max(1, count // 20),
                vt_symbol=f"ISSUE79OVERFLOW{run_id}.LOCAL",
                spool_dir=f"/tmp/issue79-overflow-{run_id}",
                base_time=base_time,
            )
            self.record(
                "capacity_overflow_spool",
                overflow["diff"] == 0
                and overflow["dropped"] == 0
                and overflow["spool_rows"] == 0
                and int(overflow["spooled_total_before_drain"]) > 0
                and float(overflow["enqueue_p95_ms"]) <= 10,
                result=overflow,
            )
        finally:
            cleanup = self.host.probe("drop_partition", partition_day)
        self.record("capacity_partition_cleanup", int(cleanup["remaining"]) == 0, cleanup=cleanup)
        self.result["capacity"] = {
            "required_tps": required_tps,
            "normal": normal,
            "overflow": overflow,
            "cleanup": cleanup,
        }
        self.sample_resources("capacity_complete")

    def _wait_for_spool(self, baseline: int) -> dict[str, Any]:
        return self.wait_status(lambda value: int(value.get("spool_rows") or 0) > baseline, "tick spool growth", self.outage_seconds + 90)

    def _recover_questdb_and_drain(self, name: str) -> dict[str, Any]:
        self.host.docker("start", self.host.questdb_container)
        self.host.wait_container(self.host.questdb_container, healthy=True, timeout=self.recovery_timeout)
        drained = self.wait_status(
            lambda value: int(value.get("queue_depth") or 0) == 0 and int(value.get("spool_rows") or 0) == 0 and bool(value.get("worker_alive")),
            f"{name} backlog drain",
        )
        self.record(f"{name}_drained", int(drained.get("dropped_total") or 0) == 0, status=drained)
        return drained

    def questdb_outage(self) -> None:
        baseline = int(self.host.probe("status").get("spool_rows") or 0)
        started = datetime.now().astimezone().isoformat()
        self.host.docker("stop", "--time", "10", self.host.questdb_container, timeout=30)
        outage = self._wait_for_spool(baseline)
        time.sleep(self.outage_seconds)
        files = self.host.probe("spool_files")
        self.sample_resources("questdb_outage")
        recovered = self._recover_questdb_and_drain("questdb_outage")
        self.sample_resources("questdb_outage_recovered")
        self.result["faults"].append({"name": "questdb_outage", "started_at": started, "outage": outage, "spool_files": files, "recovered": recovered})

    def web_restart_with_backlog(self) -> None:
        baseline = int(self.host.probe("status").get("spool_rows") or 0)
        started = datetime.now().astimezone().isoformat()
        self.host.docker("stop", "--time", "10", self.host.questdb_container, timeout=30)
        before_restart = self._wait_for_spool(baseline)
        self.host.docker("restart", "--time", "5", self.host.web_container, timeout=60)
        self.host.wait_container(self.host.web_container, healthy=True, timeout=self.recovery_timeout)
        after_restart = self.host.probe("status")
        self.sample_resources("web_restart_with_backlog")
        self.record("web_restart_preserved_backlog", int(after_restart.get("spool_rows") or 0) > 0, before=before_restart, after=after_restart)
        self.host.docker("start", self.host.questdb_container)
        self.host.wait_container(self.host.questdb_container, healthy=True, timeout=self.recovery_timeout)
        time.sleep(0.25)
        self.host.docker("kill", "--signal", "KILL", self.host.web_container)
        self.host.docker("start", self.host.web_container)
        self.host.wait_container(self.host.web_container, healthy=True, timeout=self.recovery_timeout)
        after_replay_kill = self.host.probe("status")
        recovered = self.wait_status(
            lambda value: int(value.get("queue_depth") or 0) == 0 and int(value.get("spool_rows") or 0) == 0 and bool(value.get("worker_alive")),
            "replay kill backlog drain",
        )
        self.record("replay_kill_drained", int(recovered.get("dropped_total") or 0) == 0, status=recovered)
        self.sample_resources("replay_kill_recovered")
        self.result["faults"].append(
            {
                "name": "web_restart_with_backlog_and_replay_kill",
                "started_at": started,
                "before_restart": before_restart,
                "after_restart": after_restart,
                "after_replay_kill": after_replay_kill,
                "recovered": recovered,
            }
        )

    def questdb_restart(self) -> None:
        started = datetime.now().astimezone().isoformat()
        self.host.docker("restart", "--time", "5", self.host.questdb_container, timeout=60)
        self.host.wait_container(self.host.questdb_container, healthy=True, timeout=self.recovery_timeout)
        recovered = self.wait_status(lambda value: bool(value.get("worker_alive")) and int(value.get("spool_rows") or 0) == 0, "QuestDB restart recovery")
        self.record("questdb_restart_recovered", int(recovered.get("dropped_total") or 0) == 0, status=recovered)
        self.sample_resources("questdb_restart_recovered")
        self.result["faults"].append({"name": "questdb_restart", "started_at": started, "recovered": recovered})

    def final_checks(self) -> None:
        self.host.ensure_started()
        status = self.wait_status(
            lambda value: bool(value.get("worker_alive"))
            and int(value.get("queue_depth") or 0) == 0
            and int(value.get("inflight_batch_size") or 0) == 0
            and int(value.get("spool_rows") or 0) == 0
            and int(value.get("valid_total") or 0) == int(value.get("persisted_total") or 0),
            "final counter reconciliation",
        )
        spool_files = self.host.probe("spool_files")
        monitor: dict[str, Any] = {}
        active: list[dict[str, Any]] = []
        monitor_deadline = time.time() + self.recovery_timeout
        while time.time() < monitor_deadline:
            monitor = self.host.probe("monitor")
            incidents = monitor.get("incidents") or []
            if isinstance(incidents, dict):
                incidents = incidents.get("incidents") or []
            active = [item for item in incidents if is_active_incident(item)]
            if not active:
                break
            time.sleep(5)
        self.record("final_no_drops", int(status.get("dropped_total") or 0) == 0, status=status)
        self.record(
            "final_valid_equals_persisted",
            int(status.get("valid_total") or 0) == int(status.get("persisted_total") or 0),
            valid_total=status.get("valid_total"),
            persisted_total=status.get("persisted_total"),
        )
        self.record(
            "final_no_corruption",
            int(status.get("corrupt_total") or 0) == 0 and int(status.get("quarantined_rows") or 0) == 0,
            corrupt_total=status.get("corrupt_total"),
            quarantined_rows=status.get("quarantined_rows"),
        )
        self.record("final_spool_clean", is_spool_clean(status, spool_files), spool_files=spool_files)
        self.record("final_no_active_incidents", not active, active_incidents=active)
        self.result["resources_after"] = self.sample_resources("final")
        self.result["resource_peaks"] = summarize_resource_peaks(self.result["resource_samples"])
        self.result["final"] = {"status": status, "spool_files": spool_files, "monitor": monitor, "active_incidents": active}
        self.result["finished_at"] = datetime.now().astimezone().isoformat()

    def run(self, *, destructive: bool) -> dict[str, Any]:
        self.preflight()
        self.audit_history()
        self.ensure_live_tick_flow()
        self.capacity_validation()
        if destructive:
            try:
                self.questdb_outage()
                self.web_restart_with_backlog()
                self.questdb_restart()
            finally:
                self.host.ensure_started()
        self.final_checks()
        return self.result


def render_markdown(result: dict[str, Any]) -> str:
    day = result.get("historical_day") or {}
    lines = [
        "# Issue #79 Production Tick Validation",
        "",
        f"- Started: `{result.get('started_at')}`",
        f"- Finished: `{result.get('finished_at')}`",
        f"- Historical trading day: `{day.get('trading_day')}`",
        f"- Rows / symbols / exchanges: `{day.get('rows')}` / `{day.get('symbols')}` / `{day.get('exchange_count')}`",
        f"- Window: `{day.get('start')}` → `{day.get('end')}`",
        f"- Peak / average active TPS: `{day.get('peak_tps')}` / `{day.get('average_active_tps')}`",
        f"- Error: `{result.get('error') or 'none'}`",
        "",
        "## Checks",
        "",
        "| Check | Result |",
        "|---|---|",
    ]
    for check in result.get("checks") or []:
        lines.append(f"| `{check['name']}` | {'PASS' if check['ok'] else 'FAIL'} |")
    lines.extend(["", "## Fault timeline", ""])
    for fault in result.get("faults") or []:
        lines.append(f"- `{fault['name']}` started at `{fault['started_at']}` and recovered with zero pending spool rows.")
    lines.extend([
        "",
        "Sensitive DSNs, RPC addresses, credentials, bot tokens and chat IDs are intentionally omitted.",
        "",
    ])
    return "\n".join(lines)


def summarize_resource_peaks(samples: list[dict[str, Any]]) -> dict[str, Any]:
    peaks: dict[str, dict[str, float]] = {}
    for sample in samples:
        for container in sample.get("containers") or []:
            name = str(container.get("Name") or container.get("Container") or "unknown")
            item = peaks.setdefault(name, {"cpu_percent": 0.0, "memory_bytes": 0.0})
            cpu = float(str(container.get("CPUPerc") or "0").rstrip("%"))
            memory = str(container.get("MemUsage") or "0").split("/", 1)[0].strip()
            item["cpu_percent"] = max(item["cpu_percent"], cpu)
            item["memory_bytes"] = max(item["memory_bytes"], _parse_size_bytes(memory))
    questdb_sizes = [
        int(sample["questdb_data_kb"])
        for sample in samples
        if sample.get("questdb_data_kb") is not None
    ]
    return {
        "containers": peaks,
        "questdb_data_kb_min": min(questdb_sizes) if questdb_sizes else 0,
        "questdb_data_kb_max": max(questdb_sizes) if questdb_sizes else 0,
        "questdb_data_growth_kb": (questdb_sizes[-1] - questdb_sizes[0]) if questdb_sizes else 0,
    }


def _parse_size_bytes(value: str) -> float:
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
    for suffix in ("GiB", "MiB", "KiB", "B"):
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * units[suffix]
    return float(value or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue #79 production Tick persistence validation")
    parser.add_argument("--mode", choices=("audit", "full"), default="audit")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--output", type=Path, default=Path("artifacts/issue-79-production-validation.json"))
    parser.add_argument("--markdown-output", type=Path, default=Path("artifacts/issue-79-production-validation.md"))
    parser.add_argument("--web-container", default=os.getenv("WEB_CONTAINER", "vnpy-web-bridge"))
    parser.add_argument("--questdb-container", default=os.getenv("QUESTDB_CONTAINER", "vnpy-web-bridge-questdb"))
    parser.add_argument("--deploy-path", type=Path)
    parser.add_argument("--outage-seconds", type=int, default=int(os.getenv("ISSUE79_OUTAGE_SECONDS", "50")))
    parser.add_argument("--recovery-timeout", type=int, default=int(os.getenv("ISSUE79_RECOVERY_TIMEOUT", "240")))
    args = parser.parse_args()
    if args.mode == "full" and args.confirm != CONFIRMATION:
        print(f"error: --confirm {CONFIRMATION} is required for production fault injection", file=sys.stderr)
        return 2

    host = DockerHost(
        web_container=args.web_container,
        questdb_container=args.questdb_container,
        deploy_path=args.deploy_path,
    )
    validation = ProductionValidation(host, outage_seconds=args.outage_seconds, recovery_timeout=args.recovery_timeout)
    try:
        result = validation.run(destructive=args.mode == "full")
    except Exception as exc:
        validation.result["error"] = str(exc)
        validation.result["finished_at"] = datetime.now().astimezone().isoformat()
        try:
            host.ensure_started()
        except Exception as recovery_exc:
            validation.result["emergency_recovery_error"] = str(recovery_exc)
            print(f"emergency recovery failed: {recovery_exc}", file=sys.stderr)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        safe_result = sanitize_evidence(validation.result)
        args.output.write_text(json.dumps(safe_result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        args.markdown_output.write_text(render_markdown(safe_result), encoding="utf-8")
        print(f"validation failed: {sanitize_evidence(str(exc))}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    safe_result = sanitize_evidence(result)
    args.output.write_text(json.dumps(safe_result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    args.markdown_output.write_text(render_markdown(safe_result), encoding="utf-8")
    print(render_markdown(safe_result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
