"""Read-only offline benchmark for the execution-quality tick reader."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

try:
    from .durable import DurableVerifiedTickStream
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from phase_b_workers.durable import DurableVerifiedTickStream


def benchmark(
    stream_dir: str | Path,
    *,
    generation: str,
    after_seq: int,
    count: int,
    legacy: bool = False,
) -> dict[str, object]:
    """Measure only consumer reads; the producer-owned stream stays read-only."""

    stream = DurableVerifiedTickStream(
        stream_dir, generation=generation, read_only=True
    )
    sequence = int(after_seq)
    limit = max(0, int(count))
    offset: int | None = None
    started = time.perf_counter()
    consumed = 0
    while consumed < limit:
        if legacy:
            tick = next(stream.iter_from(sequence, limit=1), None)
        else:
            tick, offset = stream.next_after(sequence, offset=offset)
        if tick is None:
            break
        sequence = tick.ingest_seq
        consumed += 1
    elapsed = time.perf_counter() - started
    return {
        "mode": "legacy_iter_from_limit_1" if legacy else "seek_cursor",
        "after_seq": int(after_seq),
        "consumed": consumed,
        "last_ingest_seq": sequence,
        "elapsed_seconds": round(elapsed, 6),
        "ticks_per_second": round(consumed / elapsed, 3) if elapsed else None,
        "producer_mutation": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="read-only execution-quality journal throughput benchmark"
    )
    parser.add_argument("--stream-dir", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--after-seq", type=int, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args(argv)
    print(
        json.dumps(
            benchmark(
                args.stream_dir,
                generation=args.generation,
                after_seq=args.after_seq,
                count=args.count,
                legacy=args.legacy,
            ),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
