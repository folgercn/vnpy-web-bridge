"""Baseline syscall/timing breakdown for existing durable primitives.

This does not implement group commit. ``group_size`` repeats current operations
and is only a comparison of the existing per-operation fsync cost.
"""

from __future__ import annotations

import argparse
import importlib
import json
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

durable = importlib.import_module("scripts.phase_b_workers.durable")


@contextmanager
def _instrument() -> Iterator[dict[str, list[int]]]:
    timings: dict[str, list[int]] = {
        "write": [],
        "file_fsync": [],
        "parent_fsync": [],
        "replace": [],
    }
    original_write = durable.os.write
    original_fsync = durable.os.fsync
    original_replace = durable.os.replace

    def write(fd: int, data: object) -> int:
        started = time.perf_counter_ns()
        try:
            return original_write(fd, data)
        finally:
            timings["write"].append(time.perf_counter_ns() - started)

    def fsync(fd: int) -> None:
        info = durable.os.fstat(fd)
        kind = "parent_fsync" if stat.S_ISDIR(info.st_mode) else "file_fsync"
        started = time.perf_counter_ns()
        try:
            return original_fsync(fd)
        finally:
            timings[kind].append(time.perf_counter_ns() - started)

    def replace(*args: object, **kwargs: object) -> None:
        started = time.perf_counter_ns()
        try:
            return original_replace(*args, **kwargs)
        finally:
            timings["replace"].append(time.perf_counter_ns() - started)

    durable.os.write, durable.os.fsync, durable.os.replace = write, fsync, replace
    try:
        yield timings
    finally:
        durable.os.write = original_write
        durable.os.fsync = original_fsync
        durable.os.replace = original_replace


def _measure(
    iterations: int, group_size: int, operation: Callable[[int], None]
) -> dict[str, object]:
    samples: list[int] = []
    with _instrument() as counts:
        started = time.perf_counter_ns()
        for index in range(iterations):
            group_started = time.perf_counter_ns()
            for offset in range(group_size):
                operation(index * group_size + offset)
            samples.append(time.perf_counter_ns() - group_started)
        elapsed = time.perf_counter_ns() - started
    total = iterations * group_size
    ordered = sorted(samples)
    def latency(values: list[int]) -> dict[str, object]:
        if not values:
            return {
                "count": 0,
                "p50_us": None,
                "p95_us": None,
                "p99_us": None,
                "max_us": None,
            }
        values = sorted(values)

        def percentile(percent: float) -> float:
            index = min(len(values) - 1, int((len(values) - 1) * percent))
            return values[index] / 1_000
        return {
            "count": len(values),
            "p50_us": percentile(0.50),
            "p95_us": percentile(0.95),
            "p99_us": percentile(0.99),
            "max_us": values[-1] / 1_000,
        }
    return {
        "operations": total,
        "elapsed_ms": elapsed / 1_000_000,
        "per_operation_us": elapsed / total / 1_000,
        "group_p50_ms": ordered[len(ordered) // 2] / 1_000_000,
        "syscalls": {name: latency(values) for name, values in counts.items()},
    }


def run(iterations: int, groups: list[int]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="durable-fsync-") as temporary:
        root = Path(temporary)
        journal = durable.AppendOnlyJsonl(root / "journal.jsonl")
        ack = durable.AppendOnlyJsonl(root / "acks.jsonl")
        checkpoint = durable.AtomicCheckpoint(
            root / "checkpoint.json", default={"n": 0}
        )
        source_fence = durable.AtomicCheckpoint(
            root / "source_fence.json", default={"events": {}}
        )
        operations: dict[str, Callable[[int], None]] = {
            "journal_append": lambda i: journal.append({"id": str(i), "value": i}),
            "checkpoint_write": lambda i: checkpoint.write({"n": i}),
            "source_fence_checkpoint_write": lambda i: source_fence.write(
                {"events": {str(i): {"seq": i}}}
            ),
            "ack_append": lambda i: ack.append({"ingest_id": str(i), "seq": i}),
        }
        result: dict[str, object] = {
            "mode": "existing-implementation-baseline",
            "iterations": iterations,
            "group_sizes": groups,
            "durability": "real temporary-directory fsync",
            "warning": (
                "group_size repeats current per-operation fsync; "
                "it is not group commit"
            ),
            "operations": {},
        }
        for name, operation in operations.items():
            result["operations"][name] = {
                str(group): _measure(iterations, group, operation) for group in groups
            }
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--groups", default="1,32,64")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if not 100 <= args.iterations <= 1000:
        parser.error("--iterations must be between 100 and 1000")
    try:
        groups = [int(value) for value in args.groups.split(",")]
    except ValueError as exc:
        parser.error(f"invalid --groups: {exc}")
    if not groups or any(value < 1 or value > 64 for value in groups):
        parser.error("--groups values must be 1..64")
    encoded = json.dumps(run(args.iterations, groups), indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
