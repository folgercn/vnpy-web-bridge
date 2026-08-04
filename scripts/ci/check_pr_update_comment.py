"""Require a PR update comment for the exact head revision.

The pull-request event's ``updated_at`` value is captured when the workflow is
created by the substantive PR update.  A qualifying issue comment must be
created at or after that timestamp and contain the complete head SHA.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

FULL_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMENTS_PER_PAGE = 100
MAX_COMMENT_PAGES = 100


class CommentGateError(RuntimeError):
    """A safe, user-facing gate failure with no response or credential data."""


def parse_github_time(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise CommentGateError(f"invalid {label} timestamp") from exc
    if parsed.tzinfo is None:
        raise CommentGateError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def body_contains_full_sha(body: object, head_sha: str) -> bool:
    if not isinstance(body, str):
        return False
    pattern = re.compile(
        rf"(?<![0-9a-f]){re.escape(head_sha)}(?![0-9a-f])",
        re.IGNORECASE,
    )
    return pattern.search(body) is not None


def qualifying_comment(
    comments: list[dict[str, Any]],
    *,
    head_sha: str,
    pushed_at: datetime,
) -> dict[str, Any] | None:
    matches: list[tuple[datetime, dict[str, Any]]] = []
    for comment in comments:
        try:
            created_at = parse_github_time(
                comment.get("created_at", ""), label="comment created_at"
            )
        except CommentGateError:
            continue
        if created_at <= pushed_at or not body_contains_full_sha(
            comment.get("body"), head_sha
        ):
            continue
        matches.append((created_at, comment))
    if not matches:
        return None
    return max(matches, key=lambda item: item[0])[1]


class GitHubCommentsClient:
    def __init__(
        self,
        *,
        token: str,
        api_url: str,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        if not token:
            raise CommentGateError("GITHUB_TOKEN is required for pull requests")
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._opener = opener

    def list_comments(self, repository: str, pr_number: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        encoded_repository = "/".join(
            urllib.parse.quote(part, safe="") for part in repository.split("/")
        )
        for page in range(1, MAX_COMMENT_PAGES + 1):
            url = (
                f"{self._api_url}/repos/{encoded_repository}/issues/"
                f"{pr_number}/comments?per_page={COMMENTS_PER_PAGE}&page={page}"
            )
            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "vnpy-web-bridge-pr-update-comment-gate",
                },
            )
            try:
                with self._opener(request, timeout=15) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raise CommentGateError(
                    f"GitHub API request failed with HTTP {exc.code}"
                ) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                raise CommentGateError("GitHub API request failed") from None
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise CommentGateError("GitHub API returned invalid JSON") from None
            if not isinstance(payload, list) or not all(
                isinstance(item, dict) for item in payload
            ):
                raise CommentGateError("GitHub API returned an invalid comment list")
            comments.extend(payload)
            if len(payload) < COMMENTS_PER_PAGE:
                return comments
        raise CommentGateError("GitHub API comment pagination limit exceeded")


def wait_for_qualifying_comment(
    fetch_comments: Callable[[], list[dict[str, Any]]],
    *,
    head_sha: str,
    pushed_at: datetime,
    timeout_seconds: float,
    poll_interval_seconds: float,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if timeout_seconds < 0 or poll_interval_seconds <= 0:
        raise CommentGateError("poll timing must be positive")
    deadline = clock() + timeout_seconds
    while True:
        match = qualifying_comment(
            fetch_comments(), head_sha=head_sha, pushed_at=pushed_at
        )
        if match is not None:
            return match
        remaining = deadline - clock()
        if remaining <= 0:
            raise CommentGateError(
                f"no PR comment created after the last push contains head SHA {head_sha}"
            )
        sleeper(min(poll_interval_seconds, remaining))


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise CommentGateError(f"missing required environment variable: {name}")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=float, default=120)
    parser.add_argument("--poll-interval-seconds", type=float, default=10)
    args = parser.parse_args(argv)

    event_name = os.getenv("GITHUB_EVENT_NAME", "").strip()
    if event_name not in {"pull_request", "pull_request_target"}:
        print("PR update comment gate skipped for non-pull-request event")
        return 0

    try:
        repository = _required_env("GITHUB_REPOSITORY")
        if not REPOSITORY.fullmatch(repository):
            raise CommentGateError("GITHUB_REPOSITORY is invalid")
        raw_pr_number = _required_env("PR_NUMBER")
        try:
            pr_number = int(raw_pr_number)
        except ValueError as exc:
            raise CommentGateError("PR_NUMBER is invalid") from exc
        if pr_number <= 0:
            raise CommentGateError("PR_NUMBER is invalid")
        head_sha = _required_env("PR_HEAD_SHA").lower()
        if not FULL_SHA.fullmatch(head_sha):
            raise CommentGateError("PR_HEAD_SHA must be a complete 40-character SHA")
        pushed_at = parse_github_time(
            _required_env("PR_PUSHED_AT"), label="PR pushed_at"
        )
        client = GitHubCommentsClient(
            token=_required_env("GITHUB_TOKEN"),
            api_url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
        )
        match = wait_for_qualifying_comment(
            lambda: client.list_comments(repository, pr_number),
            head_sha=head_sha,
            pushed_at=pushed_at,
            timeout_seconds=args.timeout_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
        )
    except CommentGateError as exc:
        print(f"PR update comment gate failed: {exc}", file=sys.stderr)
        return 1

    comment_url = match.get("html_url")
    suffix = f" ({comment_url})" if isinstance(comment_url, str) else ""
    print(f"PR update comment gate passed for head SHA {head_sha}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
