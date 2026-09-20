"""Tests for UsageTracker persistence and leaderboard rankings."""
import asyncio
from pathlib import Path
from research_lab.agent_control.antigravity_mcp.usage_tracker import UsageTracker


def test_usage_tracker_counts_and_leaderboard(tmp_path: Path):
    async def _run():
        stats_file = tmp_path / "data" / "test_stats.json"
        tracker = UsageTracker(stats_file=stats_file)

        # Dispatch tasks
        await tracker.record_task("acc1@example.com", account_id="id-1", task_id="t-1", prompt_preview="hello 1")
        await tracker.record_task("acc1@example.com", account_id="id-1", task_id="t-2", prompt_preview="hello 2")
        await tracker.record_task("acc2@example.com", account_id="id-2", task_id="t-3", prompt_preview="hello 3")

        # Record a switch
        await tracker.record_switch(from_email="acc1@example.com", to_email="acc2@example.com", reason="test")

        # Check counts
        assert tracker.get_task_count("acc1@example.com") == 2
        assert tracker.get_task_count("acc2@example.com") == 1
        assert tracker.get_task_count("non_existent@example.com") == 0

        # Check leaderboard
        leaderboard = tracker.get_leaderboard()
        assert len(leaderboard) == 2
        assert leaderboard[0]["email"] == "acc1@example.com"
        assert leaderboard[0]["rank"] == 1
        assert leaderboard[0]["task_count"] == 2
        assert leaderboard[0]["task_percentage"] == "66.7%"

        assert leaderboard[1]["email"] == "acc2@example.com"
        assert leaderboard[1]["rank"] == 2
        assert leaderboard[1]["task_count"] == 1
        assert leaderboard[1]["task_percentage"] == "33.3%"

        # Check summary
        summary = tracker.get_summary()
        assert summary["total_tasks"] == 3
        assert summary["total_switches"] == 1
        assert summary["most_used_account"] == "acc1@example.com"
        assert summary["least_used_account"] == "acc2@example.com"

        # Test file persistence by reloading into new instance
        reloaded = UsageTracker(stats_file=stats_file)
        assert reloaded.get_task_count("acc1@example.com") == 2
        assert reloaded.get_task_count("acc2@example.com") == 1

    asyncio.run(_run())
