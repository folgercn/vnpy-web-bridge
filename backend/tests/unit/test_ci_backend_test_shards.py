from pathlib import Path

from scripts.ci.backend_test_shards import (
    COLLECT_FIRST,
    REQUIRED_SEPARATED,
    SHARD_COUNT,
    build_shards,
    discover_tests,
    validate_shards,
)


def test_shards_cover_every_unit_test_exactly_once() -> None:
    shards = build_shards()
    flattened = [path for shard in shards for path in shard]

    assert len(shards) == SHARD_COUNT
    assert sorted(flattened) == discover_tests()
    assert len(flattened) == len(set(flattened))
    assert validate_shards(shards)["test_file_count"] == len(flattened)


def test_historically_slow_files_are_separated() -> None:
    shards = build_shards()
    locations = {
        path.name: index
        for index, shard in enumerate(shards)
        for path in shard
        if path.name in REQUIRED_SEPARATED
    }

    assert set(locations) == set(REQUIRED_SEPARATED)
    assert len(set(locations.values())) == len(REQUIRED_SEPARATED)


def test_new_test_file_is_assigned_deterministically() -> None:
    files = discover_tests() + [Path("backend/tests/unit/test_future_ci_case.py")]

    first = build_shards(files)
    second = build_shards(list(reversed(files)))

    assert first == second
    assert sum(Path("backend/tests/unit/test_future_ci_case.py") in shard for shard in first) == 1


def test_double_stat_revalidation_file_collects_first_in_its_shard() -> None:
    shards = build_shards()
    target = next(
        path
        for shard in shards
        for path in shard
        if path.name in COLLECT_FIRST
    )
    containing_shard = next(shard for shard in shards if target in shard)

    assert containing_shard[0] == target
