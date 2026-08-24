from __future__ import annotations

import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

route_builder = importlib.import_module("simnow_experimental_timely_daily_route")
materializer = importlib.import_module("simnow_experimental_materialize_target")
daily_fixture = importlib.import_module("test_research_warehouse_daily_pit_main_roll_source")


class _Availability:
    raw_sha256 = daily_fixture.CALENDAR_ANCHOR_SHA

    def require_available(self, *_args, **_kwargs) -> None:
        return None


def _context(tmp_path: Path, calendar) -> SimpleNamespace:
    return SimpleNamespace(
        calendar=calendar,
        availability=_Availability(),
        runtime=SimpleNamespace(run_receipts=tmp_path / "run-receipts"),
        paths=SimpleNamespace(root=tmp_path / "warehouse"),
        registry=SimpleNamespace(raw_sha256=daily_fixture.REGISTRY_SHA),
        policy=SimpleNamespace(uid=503),
    )


def test_timely_route_reuses_frozen_kernel_and_binds_experimental_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = daily_fixture._inputs()
    receipt = json.loads(inputs["run_receipt_raw"])
    context = _context(tmp_path, inputs["calendar"])
    registry_path = tmp_path / "contract-registry.json"
    registry_path.write_bytes(inputs["contract_registry_raw"])
    receipt_path = context.runtime.run_receipts / "2026-08-18.json"
    raw_paths = {
        context.paths.root / row["raw_relative_path"]: inputs["daily_source_raw"][
            row["exchange"]
        ]
        for row in receipt["sources"]
    }

    def strict(path: Path, *_args, **_kwargs) -> bytes:
        if path == receipt_path:
            return inputs["run_receipt_raw"]
        return raw_paths[path]

    monkeypatch.setattr(route_builder, "load_run_receipt", lambda _path: receipt)
    monkeypatch.setattr(route_builder, "read_regular_strict", strict)
    monkeypatch.setattr(
        route_builder,
        "_read_private_protected_evidence",
        lambda *_args, **_kwargs: inputs["contract_registry_raw"],
    )
    monkeypatch.setattr(
        route_builder,
        "verify_daily_run_receipt",
        lambda *_args, **_kwargs: datetime(2026, 8, 18, 10, 30, tzinfo=timezone.utc),
    )
    route = route_builder.build_timely_experimental_route(
        context=context,
        official_day="2026-08-18",
        contract_registry_path=registry_path,
        expected_contract_registry_raw_sha256=(
            route_builder.sha256(inputs["contract_registry_raw"])
        ),
    )

    assert route["schema_version"] == "daily-pit-route-v1"
    assert route["metadata"]["route_mode"] == route_builder.ROUTE_MODE
    assert route["metadata"]["production"] is False
    assert [row["product"] for row in route["mains"]] == list(materializer.PRODUCTS)
    bundle = importlib.import_module("test_simnow_experimental_target")._bundle()
    target = materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=materializer.canonical_json_line(bundle),
        daily_route=route,
        daily_route_raw=materializer.canonical_json_line(route),
        generated_at="2026-08-20T10:31:00Z",
    )
    assert target["daily_route_sha256"] == route_builder.sha256(
        materializer.canonical_json_line(route)
    )
    assert target["production"] is False


def test_late_receipt_stops_without_route_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = daily_fixture._inputs()
    receipt = json.loads(inputs["run_receipt_raw"])
    context = _context(tmp_path, inputs["calendar"])
    receipt_path = context.runtime.run_receipts / "2026-08-18.json"
    monkeypatch.setattr(route_builder, "load_run_receipt", lambda _path: receipt)
    monkeypatch.setattr(
        route_builder,
        "read_regular_strict",
        lambda path, *_args, **_kwargs: inputs["run_receipt_raw"] if path == receipt_path else b"unused",
    )
    monkeypatch.setattr(
        route_builder,
        "verify_daily_run_receipt",
        lambda *_args, **_kwargs: datetime(2026, 8, 19, tzinfo=timezone.utc),
    )
    with pytest.raises(route_builder.ExperimentalTimelyRouteError, match="cutoff"):
        route_builder.build_timely_experimental_route(
            context=context,
            official_day="2026-08-18",
            contract_registry_path=tmp_path / "unused.json",
            expected_contract_registry_raw_sha256="a" * 64,
        )


def test_materializer_rejects_forged_or_nonexperimental_timely_metadata() -> None:
    bundle = importlib.import_module("test_simnow_experimental_target")._bundle()
    route = importlib.import_module("test_simnow_experimental_target")._route(bundle)
    route["metadata"] = {
        "route_mode": route_builder.ROUTE_MODE,
        "strategy_output_claim": "official",
    }
    with pytest.raises(materializer.ExperimentalTargetError, match="metadata"):
        materializer.materialize_target(
            planner_bundle=bundle,
            planner_bundle_raw=materializer.canonical_json_line(bundle),
            daily_route=route,
            daily_route_raw=materializer.canonical_json_line(route),
            generated_at="2026-08-20T10:31:00Z",
        )


def test_materializer_rejects_experimental_route_with_extra_top_level_fields() -> None:
    bundle = importlib.import_module("test_simnow_experimental_target")._bundle()
    route = importlib.import_module("test_simnow_experimental_target")._route(bundle)
    route["metadata"] = {
        "route_mode": route_builder.ROUTE_MODE,
        "strategy_output_claim": materializer.NOT_OFFICIAL_STRATEGY_OUTPUT,
        "official_day": "2026-08-20",
        "execution_day": "2026-08-21",
        "execution_cutoff_utc": "2026-08-20T16:00:00.000000Z",
        "run_receipt_id": "run-test",
        "run_receipt_raw_sha256": "a" * 64,
        "contract_registry_raw_sha256": "b" * 64,
        "production": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
    }
    route["formal_catalog_artifact"] = "forbidden"
    with pytest.raises(materializer.ExperimentalTargetError, match="metadata"):
        materializer.materialize_target(
            planner_bundle=bundle,
            planner_bundle_raw=materializer.canonical_json_line(bundle),
            daily_route=route,
            daily_route_raw=materializer.canonical_json_line(route),
            generated_at="2026-08-20T10:31:00Z",
        )


def test_service_stdout_route_is_canonical_and_consumable_by_materializer(
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    target_helpers = importlib.import_module("test_simnow_experimental_target")
    bundle = target_helpers._bundle()
    route = target_helpers._route(bundle)
    route["metadata"] = {
        "route_mode": route_builder.ROUTE_MODE,
        "strategy_output_claim": materializer.NOT_OFFICIAL_STRATEGY_OUTPUT,
        "official_day": "2026-08-20",
        "execution_day": "2026-08-21",
        "execution_cutoff_utc": "2026-08-20T16:00:00.000000Z",
        "run_receipt_id": "run-service-503",
        "run_receipt_raw_sha256": "a" * 64,
        "contract_registry_raw_sha256": "b" * 64,
        "production": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
    }
    context = SimpleNamespace(policy=SimpleNamespace(uid=503))
    projection = SimpleNamespace(
        contract_registry_path=Path("/service/private/contracts.json"),
        contract_registry_raw_sha256="b" * 64,
    )
    monkeypatch.setattr(route_builder, "_service_context", lambda _path: context)
    monkeypatch.setattr(route_builder, "_config_raw", lambda *_args, **_kwargs: b"{}")
    monkeypatch.setattr(route_builder, "_projection_from_config", lambda _raw: projection)
    monkeypatch.setattr(
        route_builder,
        "build_timely_experimental_route",
        lambda **_kwargs: route,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "simnow_experimental_timely_daily_route.py",
            "--continuous-config",
            "/service/private/continuous.json",
            "--official-day",
            "2026-08-20",
            "--output",
            "-",
        ],
    )

    assert route_builder.main() == 0
    captured = capsysbinary.readouterr()
    assert captured.out == materializer.canonical_json_line(route)
    assert json.loads(captured.err)["status"] == "EXPERIMENTAL_ROUTE_MATERIALIZED"
    target = materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=materializer.canonical_json_line(bundle),
        daily_route=json.loads(captured.out),
        daily_route_raw=captured.out,
        generated_at="2026-08-20T10:31:00Z",
    )
    assert target["daily_route_sha256"] == route_builder.sha256(captured.out)


def test_service_identity_is_required_before_private_runtime_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = SimpleNamespace(policy=SimpleNamespace(uid=503))
    monkeypatch.setattr(
        route_builder,
        "load_runtime_context_readonly",
        lambda _path: context,
    )
    monkeypatch.setattr(route_builder.os, "geteuid", lambda: 503)
    assert route_builder._service_context(Path("/runtime-input.json")) == context
    monkeypatch.setattr(route_builder.os, "geteuid", lambda: 501)
    with pytest.raises(route_builder.ExperimentalTimelyRouteError, match="identity"):
        route_builder._service_context(Path("/runtime-input.json"))


def test_stdout_route_mode_keeps_stop_payload_off_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    context = SimpleNamespace(policy=SimpleNamespace(uid=503))
    projection = SimpleNamespace(
        contract_registry_path=Path("/service/private/contracts.json"),
        contract_registry_raw_sha256="b" * 64,
    )
    monkeypatch.setattr(route_builder, "_service_context", lambda _path: context)
    monkeypatch.setattr(route_builder, "_config_raw", lambda *_args, **_kwargs: b"{}")
    monkeypatch.setattr(route_builder, "_projection_from_config", lambda _raw: projection)
    monkeypatch.setattr(
        route_builder,
        "build_timely_experimental_route",
        lambda **_kwargs: (_ for _ in ()).throw(
            route_builder.ExperimentalTimelyRouteError("timely receipt is late")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "simnow_experimental_timely_daily_route.py",
            "--continuous-config",
            "/service/private/continuous.json",
            "--official-day",
            "2026-08-20",
            "--output",
            "-",
        ],
    )

    assert route_builder.main() == 1
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert json.loads(captured.err)["status"] == "STOP"
