from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path


def load_collector():
    script_path = Path(__file__).resolve().parents[3] / "scripts" / "mak_v2_collect_safety_audit.py"
    spec = importlib.util.spec_from_file_location("mak_v2_collect_safety_audit", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_build_endpoint_accepts_host_or_api_base_url() -> None:
    collector = load_collector()

    assert (
        collector.build_endpoint("https://bridge.example.com")
        == "https://bridge.example.com/api/mak-v2/testnet-observer/safety-audit"
    )
    assert (
        collector.build_endpoint("https://bridge.example.com/api/")
        == "https://bridge.example.com/api/mak-v2/testnet-observer/safety-audit"
    )


def test_write_artifacts_creates_json_and_csv_outputs(tmp_path: Path) -> None:
    collector = load_collector()
    result = {
        "overall": "PASS",
        "checks": [
            {"name": "rpc_connected", "status": "PASS", "observed": {"connected": True}},
            {"name": "order_endpoint_untouched", "status": "PASS", "observed": False},
        ],
        "snapshot": {
            "accounts": [
                {
                    "account_hash": "abc123",
                    "account_tail": "-001",
                    "gateway_name": "CTP",
                    "balance": 1000,
                    "available": 900,
                }
            ],
            "gfex_contracts": [
                {
                    "vt_symbol": "ps2609.GFEX",
                    "symbol": "ps2609",
                    "exchange": "GFEX",
                    "pricetick": 5,
                    "size": 60,
                    "gateway_name": "CTP",
                }
            ],
        },
    }

    collector.write_artifacts(result, tmp_path)

    assert json.loads((tmp_path / collector.RESULT_JSON).read_text(encoding="utf-8"))["overall"] == "PASS"
    with (tmp_path / collector.CHECKS_CSV).open(encoding="utf-8", newline="") as file_obj:
        rows = list(csv.DictReader(file_obj))
    assert rows[0] == {
        "name": "rpc_connected",
        "status": "PASS",
        "observed_json": '{"connected": true}',
    }
    with (tmp_path / collector.ACCOUNTS_CSV).open(encoding="utf-8", newline="") as file_obj:
        accounts = list(csv.DictReader(file_obj))
    assert accounts[0]["account_hash"] == "abc123"
    with (tmp_path / collector.CONTRACTS_CSV).open(encoding="utf-8", newline="") as file_obj:
        contracts = list(csv.DictReader(file_obj))
    assert contracts[0]["vt_symbol"] == "ps2609.GFEX"


def test_main_posts_expected_payload_and_preserves_non_pass_artifacts(monkeypatch, tmp_path: Path, capsys) -> None:
    collector = load_collector()
    calls: list[dict] = []

    def fake_post_safety_audit(endpoint: str, token: str, payload: dict):
        calls.append({"endpoint": endpoint, "token": token, "payload": payload})
        return {
            "overall": "WATCH",
            "checks": [{"name": "rpc_connected", "status": "WATCH", "observed": False}],
            "snapshot": {"accounts": [], "gfex_contracts": []},
        }

    monkeypatch.setenv("AUDIT_TOKEN", "secret-token-value")
    monkeypatch.setattr(collector, "post_safety_audit", fake_post_safety_audit)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mak_v2_collect_safety_audit.py",
            "--base-url",
            "https://bridge.example.com/api",
            "--token-env",
            "AUDIT_TOKEN",
            "--output-dir",
            str(tmp_path),
            "--probe-rpc",
            "--collect-rpc-snapshot",
            "--require-rpc-connected",
            "--contract",
            "GFEX.ps2609",
        ],
    )

    assert collector.main() == 1
    captured = capsys.readouterr()

    assert calls == [
        {
            "endpoint": "https://bridge.example.com/api/mak-v2/testnet-observer/safety-audit",
            "token": "secret-token-value",
            "payload": {
                "probe_rpc": True,
                "collect_rpc_snapshot": True,
                "require_rpc_connected": True,
                "expected_exact_contracts": ["GFEX.ps2609"],
            },
        }
    ]
    assert "secret-token-value" not in captured.out
    assert "secret-token-value" not in captured.err
    assert (tmp_path / collector.RESULT_JSON).exists()


def test_main_reports_missing_token_without_reading_env_file(monkeypatch, tmp_path: Path, capsys) -> None:
    collector = load_collector()
    monkeypatch.delenv("MISSING_AUDIT_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mak_v2_collect_safety_audit.py",
            "--base-url",
            "https://bridge.example.com",
            "--token-env",
            "MISSING_AUDIT_TOKEN",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert collector.main() == 2
    captured = capsys.readouterr()

    assert "MISSING_AUDIT_TOKEN" in captured.err
    assert "VNPY_WEB_BRIDGE_TOKEN" not in captured.err
    assert not (tmp_path / collector.RESULT_JSON).exists()
