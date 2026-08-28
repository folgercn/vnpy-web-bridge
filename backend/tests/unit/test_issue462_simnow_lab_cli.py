from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "issue462_simnow_lab_cli", ROOT / "scripts/windows_simnow_lab/cli_v1.py"
)
assert SPEC and SPEC.loader
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


def source_target() -> dict[str, object]:
    products = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
    source = {
        "schema_version": "simnow-experimental-target-v1",
        "strategy_id": "STATIC_CORE_EQUAL",
        "source_month": "2026-08",
        "generated_at": "2026-08-27T01:02:03Z",
        "target_id": "",
        "monthly_quantity_sha256": "1" * 64,
        "daily_route_sha256": "2" * 64,
        "production": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "targets": [
            {
                "product": product,
                "exact_contract": f"{'INE' if product == 'sc' else 'SHFE'}.{product}2610",
                "quantity": index - 5,
            }
            for index, product in enumerate(products)
        ],
    }
    body = dict(source)
    body.pop("target_id")
    source["target_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    ).hexdigest()
    return source


def test_materialize_preserves_vector_and_converts_vt_symbols() -> None:
    source = source_target()

    result = cli.materialize_lab_target(source)

    assert result["schema_version"] == "simnow_lab_target_v1"
    assert [row["quantity"] for row in result["targets"]] == [row["quantity"] for row in source["targets"]]
    assert result["targets"][0]["vt_symbol"] == "ag2610.SHFE"
    assert result["targets"][7]["vt_symbol"] == "sc2610.INE"
    body = dict(result)
    target_id = body.pop("target_id")
    assert target_id == hashlib.sha256(cli.canonical_json(body)).hexdigest()


def test_materialize_rejects_cross_product_route() -> None:
    source = source_target()
    source["targets"][5]["exact_contract"] = "SHFE.cu2610"

    with pytest.raises(cli.SimNowLabCliError, match="SOURCE_TARGET_INVALID"):
        cli.materialize_lab_target(source)


def test_materialize_rejects_quantity_tamper_without_source_target_id_update() -> None:
    source = source_target()
    source["targets"][5]["quantity"] += 1

    with pytest.raises(cli.SimNowLabCliError, match="SOURCE_TARGET_INVALID"):
        cli.materialize_lab_target(source)


def test_materialize_command_writes_canonical_lab_target(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    input_path = tmp_path / "experimental.json"
    output_path = tmp_path / "lab.json"
    input_path.write_text(json.dumps(source_target()), encoding="utf-8")

    assert cli.main(["materialize", "--input", str(input_path), "--output", str(output_path)]) == 0

    value = json.loads(output_path.read_text(encoding="utf-8"))
    assert output_path.read_bytes() == cli.canonical_json(value) + b"\n"
    assert json.loads(capsys.readouterr().out)["target_id"] == value["target_id"]


def test_apply_and_get_run_use_only_lab_rpcs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[str, tuple[object, ...], int]] = []

    class FakeClient:
        def start(self, request: str, publish: str) -> None:
            assert (request, publish) == ("tcp://request", "tcp://publish")

        def stop(self) -> None:
            return None

        def join(self) -> None:
            return None

        def __getattr__(self, name: str):
            def call(*args: object, timeout: int) -> dict[str, object]:
                calls.append((name, args, timeout))
                return {"method": name}

            return call

    target_path = tmp_path / "lab.json"
    target = cli.materialize_lab_target(source_target())
    target_path.write_bytes(cli.canonical_json(target))
    monkeypatch.setattr(cli, "create_rpc_client", FakeClient)

    assert cli.main(["apply", "--target", str(target_path), "--request-address", "tcp://request", "--publish-address", "tcp://publish", "--timeout-ms", "123"]) == 0
    assert cli.main(["get-run", "--run-id", "a" * 32, "--request-address", "tcp://request", "--publish-address", "tcp://publish"]) == 0
    assert cli.main(["current", "--request-address", "tcp://request", "--publish-address", "tcp://publish"]) == 0
    assert calls == [
        ("simnow_lab_apply_target_v1", (target,), 123),
        ("simnow_lab_get_run_v1", ("a" * 32,), 30_000),
        ("simnow_lab_get_run_v1", ("CURRENT",), 30_000),
    ]
