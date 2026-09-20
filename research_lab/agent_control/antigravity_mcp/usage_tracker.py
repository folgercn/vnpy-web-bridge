"""Account usage tracker and ranking statistics persistence."""
import asyncio
import datetime
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from research_lab.agent_control.antigravity_mcp.config import STATS_FILE

logger = logging.getLogger("antigravity_mcp.usage_tracker")


class UsageTracker:
    """
    Tracks and persists task usage, switch frequency, and quota incidents per account.
    Provides ranking and distribution metrics (who is used most/least).
    """

    def __init__(self, stats_file: Optional[Path] = None):
        self.stats_file = Path(stats_file) if stats_file else STATS_FILE
        self._lock = asyncio.Lock()
        self._data: Dict[str, Any] = {
            "version": 1,
            "last_updated": None,
            "total_switches": 0,
            "accounts": {},
        }
        self._load()

    def _load(self) -> None:
        """Load stats from disk if file exists."""
        if not self.stats_file.exists():
            return
        try:
            content = self.stats_file.read_text(encoding="utf-8")
            loaded = json.loads(content)
            if isinstance(loaded, dict) and "accounts" in loaded:
                self._data = loaded
        except Exception as e:
            logger.warning("Failed to load usage stats from %s: %s", self.stats_file, e)

    def _save_sync(self) -> None:
        """Atomically persist current data to disk."""
        try:
            self.stats_file.parent.mkdir(parents=True, exist_ok=True)
            self._data["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            payload = json.dumps(self._data, ensure_ascii=False, indent=2)

            tmp_file = self.stats_file.with_name(f"{self.stats_file.name}.tmp.{os.getpid()}")
            tmp_file.write_text(payload, encoding="utf-8")
            tmp_file.replace(self.stats_file)
        except Exception as e:
            logger.error("Failed to persist usage stats to %s: %s", self.stats_file, e)

    def _ensure_account(self, email: str, account_id: Optional[str] = None) -> Dict[str, Any]:
        """Ensure account entry exists and return its dict."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        accounts = self._data.setdefault("accounts", {})
        if email not in accounts:
            accounts[email] = {
                "email": email,
                "account_id": account_id or "",
                "task_count": 0,
                "switch_in_count": 0,
                "rate_limit_count": 0,
                "last_used_at": None,
                "first_seen_at": now_iso,
                "recent_tasks": [],
            }
        elif account_id and not accounts[email].get("account_id"):
            accounts[email]["account_id"] = account_id
        return accounts[email]

    async def record_task(
        self,
        email: str,
        account_id: Optional[str] = None,
        task_id: Optional[str] = None,
        prompt_preview: Optional[str] = None,
    ) -> None:
        """Record an executed task dispatched to an account."""
        if not email:
            return
        async with self._lock:
            acc = self._ensure_account(email, account_id)
            acc["task_count"] += 1
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            acc["last_used_at"] = now_iso

            if task_id:
                history = acc.setdefault("recent_tasks", [])
                history.append({
                    "task_id": task_id,
                    "timestamp": now_iso,
                    "prompt_preview": (prompt_preview[:80] + "...") if prompt_preview and len(prompt_preview) > 80 else (prompt_preview or ""),
                })
                acc["recent_tasks"] = history[-10:]

            self._save_sync()
            logger.debug("Recorded task dispatch for %s (total: %d)", email, acc["task_count"])

    async def record_switch(
        self,
        from_email: Optional[str],
        to_email: str,
        account_id: Optional[str] = None,
        reason: str = "manual",
    ) -> None:
        """Record an account switch event."""
        if not to_email:
            return
        async with self._lock:
            self._data["total_switches"] = self._data.get("total_switches", 0) + 1
            acc = self._ensure_account(to_email, account_id)
            acc["switch_in_count"] += 1
            self._save_sync()
            logger.info("Recorded switch into %s from %s (reason=%s)", to_email, from_email or "none", reason)

    async def record_429(self, email: str, account_id: Optional[str] = None) -> None:
        """Record a rate-limit (429) or quota exhausted incident."""
        if not email:
            return
        async with self._lock:
            acc = self._ensure_account(email, account_id)
            acc["rate_limit_count"] += 1
            self._save_sync()
            logger.warning("Recorded 429/quota exhaustion incident for %s", email)

    def get_account_stats(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieve recorded stats for a specific account."""
        return self._data.get("accounts", {}).get(email)

    def get_task_count(self, email: str) -> int:
        """Get total task count for an account (returns 0 if not seen)."""
        acc = self.get_account_stats(email)
        return acc.get("task_count", 0) if acc else 0

    def get_leaderboard(self) -> List[Dict[str, Any]]:
        """Return leaderboard ranked by task_count in descending order."""
        accounts = list(self._data.get("accounts", {}).values())
        total_tasks = sum(a.get("task_count", 0) for a in accounts)

        accounts.sort(key=lambda a: (-a.get("task_count", 0), -a.get("switch_in_count", 0)))

        leaderboard = []
        for i, a in enumerate(accounts, start=1):
            tasks = a.get("task_count", 0)
            pct = (tasks / total_tasks * 100) if total_tasks > 0 else 0.0
            leaderboard.append({
                "rank": i,
                "email": a.get("email"),
                "account_id": a.get("account_id"),
                "task_count": tasks,
                "task_percentage": f"{pct:.1f}%",
                "switch_in_count": a.get("switch_in_count", 0),
                "rate_limit_count": a.get("rate_limit_count", 0),
                "last_used_at": a.get("last_used_at"),
            })
        return leaderboard

    def get_summary(self) -> Dict[str, Any]:
        """Return comprehensive usage overview across all accounts."""
        leaderboard = self.get_leaderboard()
        total_tasks = sum(item["task_count"] for item in leaderboard)
        total_switches = self._data.get("total_switches", 0)

        most_used = leaderboard[0]["email"] if leaderboard and leaderboard[0]["task_count"] > 0 else None
        least_used = leaderboard[-1]["email"] if leaderboard else None

        return {
            "total_tasks": total_tasks,
            "total_switches": total_switches,
            "tracked_accounts_count": len(leaderboard),
            "most_used_account": most_used,
            "least_used_account": least_used,
            "leaderboard": leaderboard,
        }
