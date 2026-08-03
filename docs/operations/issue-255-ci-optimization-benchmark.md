# Issue #255 CI optimization benchmark

## Baseline

PR #250 / run `30746245111`:

- overall critical path: about 10 minutes;
- backend tests: 571.12 seconds in one process;
- production image build: about 58 seconds;
- Query-v5 real OCI composition: about 82 seconds;
- no stable aggregate gate and no cancellation of superseded PR runs.

## Optimized runs

| Run | Result | Queue | Quick | Backend shards | Image | Query-v5 OCI | Gate / overall | Cache state |
| --- | --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| [`30786494305`](https://github.com/folgercn/vnpy-web-bridge/actions/runs/30786494305) | success | 19–25s | 15s | 3m47s / 2m16s / 2m53s / 2m42s | 2m27s | 1m04s | 3s / 4m12s | pip cold; Buildx mixed cold/imported |
| [`30786799608`](https://github.com/folgercn/vnpy-web-bridge/actions/runs/30786799608) | superseded cancellation probe | pending | pending | pending | pending | pending | pending | warm-cache candidate |

The first optimized run completed all required checks in 4 minutes 12 seconds
from event creation, while Quick checks returned useful feedback after 34 seconds
including queue time. The slowest backend shard remained below the four-minute
budget.

Further rows will record the superseded-run cancellation probe and warm-cache
samples before the pull request leaves draft status.

Run `30786799608` reached `in_progress` before a subsequent commit was pushed;
its final state is expected to demonstrate that the PR-scoped concurrency group
cancels obsolete work without affecting another PR or a `main` push.
