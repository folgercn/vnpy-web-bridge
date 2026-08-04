from __future__ import annotations

import io
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.ci import check_pr_update_comment as gate

SHA = "a" * 40
PUSHED_AT = datetime(2026, 8, 4, 4, 0, tzinfo=timezone.utc)


def _comment(
    body: object,
    created_at: str = "2026-08-04T04:00:01Z",
) -> dict[str, object]:
    return {
        "body": body,
        "created_at": created_at,
        "html_url": "https://github.example/comment/1",
    }


def test_requires_complete_head_sha_in_comment_created_after_push() -> None:
    comments = [
        _comment(SHA, "2026-08-04T03:59:59Z"),
        _comment(SHA[:12]),
        _comment(f"updated revision: {SHA}0"),
        _comment(f"current head: `{SHA}`"),
    ]

    assert gate.qualifying_comment(
        comments, head_sha=SHA, pushed_at=PUSHED_AT
    ) == comments[-1]


def test_comment_edited_after_push_does_not_satisfy_created_at_requirement() -> None:
    comment = {
        **_comment(SHA, "2026-08-04T03:59:59Z"),
        "updated_at": "2026-08-04T04:00:02Z",
    }

    assert (
        gate.qualifying_comment([comment], head_sha=SHA, pushed_at=PUSHED_AT)
        is None
    )


def test_comment_created_in_same_timestamp_second_does_not_satisfy_gate() -> None:
    assert (
        gate.qualifying_comment(
            [_comment(SHA, "2026-08-04T04:00:00Z")],
            head_sha=SHA,
            pushed_at=PUSHED_AT,
        )
        is None
    )


def test_short_polling_accepts_a_comment_that_appears_later() -> None:
    responses = iter([[], [], [_comment(SHA)]])
    now = [0.0]

    def clock() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    match = gate.wait_for_qualifying_comment(
        lambda: next(responses),
        head_sha=SHA,
        pushed_at=PUSHED_AT,
        timeout_seconds=5,
        poll_interval_seconds=1,
        clock=clock,
        sleeper=sleep,
    )

    assert match["body"] == SHA
    assert now[0] == 2


def test_poll_timeout_fails_closed() -> None:
    now = [0.0]

    with pytest.raises(gate.CommentGateError, match="no PR comment"):
        gate.wait_for_qualifying_comment(
            list,
            head_sha=SHA,
            pushed_at=PUSHED_AT,
            timeout_seconds=2,
            poll_interval_seconds=1,
            clock=lambda: now[0],
            sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
        )


def test_github_api_error_is_sanitized_and_does_not_leak_token() -> None:
    token = "top-secret-github-token"

    def fail(request: object, timeout: int) -> object:
        del timeout
        raise urllib.error.HTTPError(
            "https://api.github.test/comments",
            503,
            f"server echoed {token}",
            hdrs=None,
            fp=io.BytesIO(token.encode()),
        )

    client = gate.GitHubCommentsClient(
        token=token,
        api_url="https://api.github.test",
        opener=fail,
    )

    with pytest.raises(gate.CommentGateError) as raised:
        client.list_comments("owner/repository", 12)

    assert str(raised.value) == "GitHub API request failed with HTTP 503"
    assert token not in str(raised.value)


def test_non_pull_request_event_skips_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    for name in (
        "GITHUB_REPOSITORY",
        "PR_NUMBER",
        "PR_HEAD_SHA",
        "PR_PUSHED_AT",
        "GITHUB_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)

    assert gate.main(["--timeout-seconds", "0"]) == 0
    assert "skipped" in capsys.readouterr().out


def test_pull_request_missing_token_fails_closed_without_echoing_environment(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repository")
    monkeypatch.setenv("PR_NUMBER", "12")
    monkeypatch.setenv("PR_HEAD_SHA", SHA)
    monkeypatch.setenv("PR_PUSHED_AT", "2026-08-04T04:00:00Z")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    assert gate.main(["--timeout-seconds", "0"]) == 1
    captured = capsys.readouterr()
    assert "GITHUB_TOKEN is required" not in captured.err
    assert "missing required environment variable: GITHUB_TOKEN" in captured.err


def test_workflow_limits_pr_actions_and_uses_minimal_read_permissions() -> None:
    workflow = (
        Path(__file__).resolve().parents[3]
        / ".github/workflows/pr-update-comment-gate.yml"
    ).read_text(encoding="utf-8")
    trigger = workflow.split("  pull_request_target:\n", maxsplit=1)[1].split(
        "\n\nconcurrency:", maxsplit=1
    )[0]
    assert "types: [opened, synchronize]" in trigger
    assert "ready_for_review" not in trigger
    assert "reopened" not in trigger
    assert "contents: read" in workflow
    assert "pull-requests: read" in workflow
    assert "issues:" not in workflow
    assert "GITHUB_TOKEN: ${{ github.token }}" in workflow
    assert "secrets." not in workflow
    assert "ref: ${{ github.event.pull_request.base.sha }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "github.event.pull_request.head.sha" in workflow
