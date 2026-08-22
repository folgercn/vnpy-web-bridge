from __future__ import annotations

import copy
import importlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

materializer = importlib.import_module("simnow_experimental_materialize_target")
monthly_once = importlib.import_module("simnow_experimental_monthly_once")
_helpers = importlib.import_module("test_issue353_static_core_keyless")
_position_manager_snapshot = _helpers._position_manager_snapshot
_static_outputs = _helpers._static_outputs


def _raw(value: dict) -> bytes:
    return materializer.canonical_json_line(value)


def _route(snapshot: dict, *, ag: str | None = None) -> dict:
    routes = {row["product"]: row["exact_contract"] for row in snapshot["targets"]}
    if ag is not None:
        routes["ag"] = ag
    return {
        "schema_version": "daily-pit-route-v1",
        "mains": [
            {
                "product": product,
                "exchange": materializer.PRODUCT_EXCHANGES[product],
                "exact_contract": routes[product],
            }
            for product in materializer.PRODUCTS
        ],
    }


def _install_producers(monkeypatch: pytest.MonkeyPatch, *, snapshot: dict) -> dict[str, int]:
    projection, freeze, evidence = _static_outputs()
    calls = {"static": 0, "thermostat": 0}

    def static(_raw_source: bytes) -> SimpleNamespace:
        calls["static"] += 1
        return SimpleNamespace(
            producer_projection=copy.deepcopy(projection),
            artifacts={
                "freeze_contract": json.dumps(freeze, sort_keys=True, separators=(",", ":")).encode(),
                "target_evidence": json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(),
            },
        )

    def thermostat(_raw_source: bytes) -> SimpleNamespace:
        calls["thermostat"] += 1
        return SimpleNamespace(snapshot_draft=json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode())

    monkeypatch.setattr(monthly_once.static_producer, "produce_research_artifacts", static)
    monkeypatch.setattr(monthly_once.thermostat_producer, "produce_snapshot", thermostat)
    return calls


def _paths(tmp_path: Path, snapshot: dict) -> dict[str, Path]:
    static = tmp_path / "static-source.json"
    thermostat = tmp_path / "thermostat-source.json"
    route = tmp_path / "daily-route.json"
    static.write_bytes(b"{}")
    thermostat.write_bytes(b"{}")
    route.write_bytes(_raw(_route(snapshot)))
    return {
        "static_source_path": static,
        "thermostat_source_path": thermostat,
        "monthly_bundle_directory": tmp_path / "monthly",
        "daily_pit_route_path": route,
        "target_path": tmp_path / "target.json",
    }


def _run(paths: dict[str, Path], *, source_month: str = "2030-01") -> dict:
    return monthly_once.materialize_monthly_once(
        source_month=source_month,
        generated_at="2030-01-02T03:04:05Z",
        **paths,
    )


def test_same_month_restart_reuses_bundle_and_preserves_target_bytes_and_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    calls = _install_producers(monkeypatch, snapshot=snapshot)

    assert _run(paths)["status"] == "MATERIALIZED"
    target_before = paths["target_path"].read_bytes()
    target_mtime_before = paths["target_path"].stat().st_mtime_ns
    bundle_before = (paths["monthly_bundle_directory"] / "2030-01.json").read_bytes()

    assert _run(paths) == {
        "status": "NO_NEW_TARGET",
        "target_id": materializer.validate_target(json.loads(target_before))["target_id"],
        "monthly_bundle_created": False,
    }
    assert calls == {"static": 1, "thermostat": 1}
    assert paths["target_path"].read_bytes() == target_before
    assert paths["target_path"].stat().st_mtime_ns == target_mtime_before
    assert (paths["monthly_bundle_directory"] / "2030-01.json").read_bytes() == bundle_before


def test_route_change_reuses_monthly_bytes_and_updates_only_exact_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    calls = _install_producers(monkeypatch, snapshot=snapshot)
    _run(paths)
    before = json.loads(paths["target_path"].read_bytes())
    bundle_before = (paths["monthly_bundle_directory"] / "2030-01.json").read_bytes()

    paths["daily_pit_route_path"].write_bytes(_raw(_route(snapshot, ag="SHFE.ag3012")))
    after_result = _run(paths)
    after = json.loads(paths["target_path"].read_bytes())

    assert after_result["status"] == "MATERIALIZED"
    assert calls == {"static": 1, "thermostat": 1}
    assert (paths["monthly_bundle_directory"] / "2030-01.json").read_bytes() == bundle_before
    assert [row["quantity"] for row in after["targets"]] == [row["quantity"] for row in before["targets"]]
    assert after["targets"][0]["exact_contract"] == "SHFE.ag3012"
    assert after["target_id"] != before["target_id"]


def test_concurrent_route_update_writes_one_target_then_reuses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    _install_producers(monkeypatch, snapshot=snapshot)
    _run(paths)
    paths["daily_pit_route_path"].write_bytes(_raw(_route(snapshot, ag="SHFE.ag3012")))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: _run(paths), range(2)))

    assert sorted(result["status"] for result in results) == [
        "MATERIALIZED",
        "NO_NEW_TARGET",
    ]
    target = json.loads(paths["target_path"].read_bytes())
    assert target["targets"][0]["exact_contract"] == "SHFE.ag3012"


def test_waiting_invocation_reads_latest_daily_route_inside_target_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    _install_producers(monkeypatch, snapshot=snapshot)
    _run(paths)
    lock_attempted = Event()
    original_target_lock = monthly_once._target_lock

    @contextmanager
    def observed_target_lock(path: Path):
        lock_attempted.set()
        with original_target_lock(path):
            yield

    monkeypatch.setattr(monthly_once, "_target_lock", observed_target_lock)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        with original_target_lock(paths["target_path"]):
            waiting = executor.submit(_run, paths)
            assert lock_attempted.wait(timeout=2)
            paths["daily_pit_route_path"].write_bytes(
                _raw(_route(snapshot, ag="SHFE.ag3012"))
            )
        result = waiting.result(timeout=2)
    finally:
        executor.shutdown(wait=True)

    assert result["status"] == "MATERIALIZED"
    target = json.loads(paths["target_path"].read_bytes())
    assert target["targets"][0]["exact_contract"] == "SHFE.ag3012"


def test_concurrent_first_month_build_runs_each_producer_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    calls = _install_producers(monkeypatch, snapshot=snapshot)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: _run(paths), range(2)))

    assert sorted(result["status"] for result in results) == [
        "MATERIALIZED",
        "NO_NEW_TARGET",
    ]
    assert calls == {"static": 1, "thermostat": 1}


def test_new_month_runs_producers_once_for_that_new_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    january = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, january)
    calls = _install_producers(monkeypatch, snapshot=january)
    _run(paths)

    february = copy.deepcopy(january)
    february["source_month"] = "2030-02"
    february_calls = _install_producers(monkeypatch, snapshot=february)
    paths["daily_pit_route_path"].write_bytes(_raw(_route(february)))
    _run(paths, source_month="2030-02")

    assert calls == {"static": 1, "thermostat": 1}
    assert february_calls == {"static": 1, "thermostat": 1}
    assert (paths["monthly_bundle_directory"] / "2030-01.json").is_file()
    assert (paths["monthly_bundle_directory"] / "2030-02.json").is_file()


def test_concurrent_create_only_bundle_safely_reuses_identical_bytes(
    tmp_path: Path,
) -> None:
    projection, freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    bundle = {
        "schema_version": materializer.PLANNER_BUNDLE_SCHEMA_VERSION,
        "strategy_id": "STATIC_CORE_EQUAL",
        "source_mode": materializer.STATIC_CORE_EQUAL_MONTHLY,
        "source_month": snapshot["source_month"],
        "static_core_equal_projection": projection,
        "static_core_equal_freeze_contract": freeze,
        "static_core_equal_target_evidence": evidence,
        "position_manager_snapshot": snapshot,
    }
    path = tmp_path / "monthly" / "2030-01.json"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: monthly_once._create_only_bundle(
                    path, bundle, source_month="2030-01"
                ),
                range(2),
            )
        )

    assert sorted(result[2] for result in results) == [False, True]
    loaded, raw = materializer.read_json_stable(path, label="monthly planner bundle")
    assert raw == materializer.canonical_json_line(loaded)
    assert monthly_once.validate_monthly_bundle(
        loaded, expected_source_month="2030-01"
    ) == bundle


def test_corrupt_existing_bundle_fails_closed_before_producer_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    bundle = paths["monthly_bundle_directory"] / "2030-01.json"
    bundle.parent.mkdir()
    bundle.write_bytes(b"not-json")
    calls = _install_producers(monkeypatch, snapshot=snapshot)

    with pytest.raises(monthly_once.ExperimentalMonthlyError, match="invalid JSON"):
        _run(paths)
    assert calls == {"static": 0, "thermostat": 0}
    assert not paths["target_path"].exists()


@pytest.mark.parametrize(
    ("artifact", "field", "replacement"),
    [
        ("static_core_equal_freeze_contract", "D_candidate_id", "tampered"),
        ("static_core_equal_projection", "producer_kernel_id", "tampered"),
    ],
)
def test_canonical_existing_bundle_with_tampered_static_binding_stops_before_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    field: str,
    replacement: str,
) -> None:
    projection, freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    bundle = {
        "schema_version": materializer.PLANNER_BUNDLE_SCHEMA_VERSION,
        "strategy_id": "STATIC_CORE_EQUAL",
        "source_mode": materializer.STATIC_CORE_EQUAL_MONTHLY,
        "source_month": snapshot["source_month"],
        "static_core_equal_projection": projection,
        "static_core_equal_freeze_contract": freeze,
        "static_core_equal_target_evidence": evidence,
        "position_manager_snapshot": snapshot,
    }
    paths = _paths(tmp_path, snapshot)
    bundle_path = paths["monthly_bundle_directory"] / "2030-01.json"
    monthly_once._create_only_bundle(bundle_path, bundle, source_month="2030-01")
    tampered = json.loads(bundle_path.read_bytes())
    tampered[artifact][field] = replacement
    bundle_path.write_bytes(_raw(tampered))
    calls = _install_producers(monkeypatch, snapshot=snapshot)

    with pytest.raises(monthly_once.ExperimentalMonthlyError, match="cross-spliced"):
        _run(paths)
    assert calls == {"static": 0, "thermostat": 0}
    assert not paths["target_path"].exists()


def test_older_source_month_cannot_overwrite_a_newer_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    calls = _install_producers(monkeypatch, snapshot=snapshot)
    _run(paths)
    target_before = paths["target_path"].read_bytes()

    with pytest.raises(monthly_once.ExperimentalMonthlyError, match="strictly advance"):
        _run(paths, source_month="2029-12")
    assert calls == {"static": 1, "thermostat": 1}
    assert paths["target_path"].read_bytes() == target_before
    assert not (paths["monthly_bundle_directory"] / "2029-12.json").exists()


def test_same_month_target_with_different_monthly_bundle_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    _install_producers(monkeypatch, snapshot=snapshot)
    _run(paths)
    tampered = json.loads(paths["target_path"].read_bytes())
    tampered["monthly_quantity_sha256"] = "a" * 64
    tampered["target_id"] = materializer._target_id(tampered)
    paths["target_path"].write_bytes(_raw(tampered))
    target_before = paths["target_path"].read_bytes()

    with pytest.raises(monthly_once.ExperimentalMonthlyError, match="monthly bundle differs"):
        _run(paths)
    assert paths["target_path"].read_bytes() == target_before


def test_cross_spliced_producer_outputs_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    snapshot["targets"][0]["baseline_target_quantity"] += 1
    paths = _paths(tmp_path, snapshot)
    _install_producers(monkeypatch, snapshot=snapshot)

    with pytest.raises(monthly_once.ExperimentalMonthlyError, match="cross-spliced"):
        _run(paths)
    assert not (paths["monthly_bundle_directory"] / "2030-01.json").exists()
    assert not paths["target_path"].exists()


def test_structurally_invalid_daily_route_never_writes_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _projection, _freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence)
    paths = _paths(tmp_path, snapshot)
    _install_producers(monkeypatch, snapshot=snapshot)
    invalid = _route(snapshot)
    invalid["mains"][0]["exchange"] = "INE"
    paths["daily_pit_route_path"].write_bytes(_raw(invalid))

    with pytest.raises(monthly_once.ExperimentalMonthlyError, match="exact contract/exchange"):
        _run(paths)
    assert (paths["monthly_bundle_directory"] / "2030-01.json").is_file()
    assert not paths["target_path"].exists()
