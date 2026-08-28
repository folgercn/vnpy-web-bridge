from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "issue466_simnow_lab_cli", ROOT / "scripts/windows_simnow_lab/cli_v1.py"
)
assert SPEC and SPEC.loader
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)
RELEASE_SPEC = importlib.util.spec_from_file_location(
    "issue466_release", ROOT / "deployments/simnow-lab/release_v1.py"
)
assert RELEASE_SPEC and RELEASE_SPEC.loader
release_v1 = importlib.util.module_from_spec(RELEASE_SPEC)
RELEASE_SPEC.loader.exec_module(release_v1)


def source_target() -> dict[str, object]:
    products = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
    value: dict[str, object] = {
        "schema_version": "simnow-experimental-target-v1",
        "strategy_id": "STATIC_CORE_EQUAL",
        "source_month": "2026-08",
        "generated_at": "2026-08-28T01:02:03Z",
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
                "quantity": 0,
            }
            for product in products
        ],
    }
    body = dict(value)
    body.pop("target_id")
    value["target_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        + b"\n"
    ).hexdigest()
    return value


def test_plist_has_only_target_watch_and_three_workday_wakes() -> None:
    raw = (ROOT / "deployments/com.vnpy-web-bridge.simnow-lab.plist").read_text()
    assert "com.folgercn.simnow-lab" in raw
    assert "run-once" in raw
    assert "RunAtLoad" not in raw
    assert raw.count("<key>Weekday</key>") == 15
    assert "simnow-experimental-run-once.sh" not in raw


def test_dashboard_only_control_api_exposes_no_execution_or_watchlist_routes() -> None:
    code = """
import json
from app.control_api import app
print(json.dumps(sorted({route.path for route in app.routes})))
"""
    env = os.environ.copy()
    env.update(APP_ENV="test", SIMNOW_LAB_DASHBOARD_ONLY="true")
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT / "backend",
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    paths = json.loads(completed.stdout.splitlines()[-1])
    assert "/health/ready" in paths
    assert "/api/v1/simnow-lab/dashboard" in paths
    assert not any("execution" in path or "watchlist" in path for path in paths)


def test_dashboard_compose_is_read_only_and_auth_audit_uses_tmpfs() -> None:
    raw = (ROOT / "deployments/docker-compose.simnow-lab-dashboard.yml").read_text()
    assert raw.count("read_only: true") == 2
    assert "CONTROL_AUDIT_LOG_PATH: /tmp/audit.log" in raw
    assert 'VITE_SIMNOW_LAB_DASHBOARD_ONLY: "true"' in raw
    assert "execution-orchestrator" not in raw
    assert "custody" not in raw.lower()


def test_release_accepts_exact_archive_and_retries_incomplete_release(tmp_path: Path) -> None:
    sha = "a" * 40
    source = tmp_path / "source"
    root = tmp_path / "root"
    source.mkdir()
    (source / ".source-sha").write_text(f"{sha}\n", encoding="ascii")
    (source / "payload.txt").write_text("exact\n", encoding="utf-8")
    first = release_v1.build_release(source, root, sha, trusted_archive=True)
    assert (first / "payload.txt").read_text() == "exact\n"
    assert release_v1.build_release(source, root, sha, trusted_archive=True) == first
    release_v1.atomic_symlink(root / "current", first)
    assert (root / "current").resolve() == first
    assert release_v1.WINDOWS_RUNTIME.fullmatch(r"C:\quant\runtime-646e73d4")
    release_source = (ROOT / "deployments/simnow-lab/release_v1.py").read_text()
    assert "if (Test-Path '{temporary}')" in release_source
    assert "[regex]::Matches($text, [regex]::Escape('{old}')).Count -ne 1" in release_source
    assert 'env["PATH"] = f"{DOCKER.parent}' in release_source


def test_run_once_materializes_current_applies_and_gets_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source.json"
    output = tmp_path / "lab.json"
    source.write_text(json.dumps(source_target()), encoding="utf-8")
    calls: list[tuple[str, tuple[object, ...]]] = []

    def fake_rpc_call(**kwargs: object) -> object:
        method = str(kwargs["method"])
        args = kwargs["args"]
        calls.append((method, args))
        if method == cli.RPC_GET and args == ("CURRENT",):
            return {"status": "CURRENT", "active_order_count": 0, "positions": []}
        if method == cli.RPC_APPLY:
            return {"run": {"run_id": "a" * 32}}
        return {"run": {"run_id": "a" * 32, "status": "DONE", "error": None}, "orders": []}

    monkeypatch.setattr(cli, "rpc_call", fake_rpc_call)
    assert cli.main(["run-once", "--input", str(source), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["schema_version"] == "simnow_lab_target_v1"
    assert [method for method, _ in calls] == [cli.RPC_GET, cli.RPC_APPLY, cli.RPC_GET]


def test_run_once_stops_on_active_orders_before_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source.json"
    output = tmp_path / "lab.json"
    source.write_text(json.dumps(source_target()), encoding="utf-8")
    calls: list[str] = []

    def fake_rpc_call(**kwargs: object) -> object:
        calls.append(str(kwargs["method"]))
        return {"status": "CURRENT", "active_order_count": 1}

    monkeypatch.setattr(cli, "rpc_call", fake_rpc_call)
    assert cli.main(["run-once", "--input", str(source), "--output", str(output)]) == 1
    assert calls == [cli.RPC_GET]
