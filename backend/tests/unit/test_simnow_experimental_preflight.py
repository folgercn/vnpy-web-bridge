from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import simnow_experimental_preflight as preflight  # noqa: E402


def test_preflight_rejects_nonstandard_runtime_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight.os, "getegid", lambda: 20)

    with pytest.raises(preflight.PreflightStop, match="expected uid/gid") as exc:
        preflight._check_runtime_identity()

    assert exc.value.category == "runtime-identity"


def test_preflight_reports_unreadable_mount_before_quote_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "market-projection"
    path.mkdir()
    monkeypatch.setattr(preflight.os, "access", lambda *_args: False)

    with pytest.raises(preflight.PreflightStop, match="not traversable") as exc:
        preflight._check_readonly_directory(path, label="market-projection")

    assert exc.value.category == "mount"


def test_preflight_requires_keyless_setting_without_exposing_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in preflight.REQUIRED_NEGATIVE_FLAGS:
        monkeypatch.setenv(name, "false")
    monkeypatch.setenv("SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED", "false")

    with pytest.raises(preflight.PreflightStop, match="KEYLESS") as exc:
        preflight._check_environment()

    assert exc.value.category == "custody-config"


def test_preflight_classifies_account_facts_and_quotes_separately() -> None:
    facts = preflight._classify_preview_stop(
        preflight.ExperimentalRunError("Execution fresh broker facts are unavailable")
    )
    quotes = preflight._classify_preview_stop(
        preflight.ExperimentalRunError("fresh formal bid/ask evidence is unavailable")
    )

    assert facts.category == "account-facts"
    assert quotes.category == "formal-quotes"


def test_preflight_runs_preview_once_without_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_path = tmp_path / "target.json"
    bundle_path = tmp_path / "bundle.json"
    state_dir = tmp_path / "market-data"
    projection_dir = tmp_path / "market-projection"
    for path in (state_dir, projection_dir):
        path.mkdir()
    target_path.write_text("{}", encoding="utf-8")
    bundle_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(preflight, "_check_runtime_identity", lambda: None)
    monkeypatch.setattr(preflight, "_check_environment", lambda: None)
    monkeypatch.setattr(preflight, "_check_readonly_directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(preflight, "_read_inputs", lambda *_args: ({}, {}))
    monkeypatch.setattr(preflight, "_check_endpoints", lambda: None)
    async def check_execution_state(*_args: object) -> None:
        return None

    monkeypatch.setattr(preflight, "_check_execution_state", check_execution_state)
    captured: dict[str, object] = {}

    async def preview(*_args: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"status": "TARGET_PLAN_V3_DRY_RUN", "execution_mutated": False}

    monkeypatch.setattr(preflight, "preview_once", preview)

    result = asyncio.run(
        preflight.run_preflight(
            target_path=target_path,
            bundle_path=bundle_path,
            market_state_dir=state_dir,
            market_projection_dir=projection_dir,
        )
    )

    assert result["preview"] == "TARGET_PLAN_V3_DRY_RUN"
    assert "expires_at" in captured
    assert "execute" not in captured


def test_preflight_requires_exact_clear_execution_status() -> None:
    class FakeExecution:
        async def status(self) -> object:
            class Projection:
                def as_dict(self) -> dict[str, object]:
                    return {
                        "lifecycle": "READY",
                        "plan": {"state": "IDLE"},
                        "authority": {"state": "DISABLED"},
                        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
                        "send_intents": [],
                    }

            return Projection()

    asyncio.run(preflight._check_execution_state(FakeExecution()))  # type: ignore[arg-type]


def test_preflight_host_adapter_checks_config_and_image_before_run() -> None:
    source = (ROOT / "deployments/simnow-experimental-preflight.sh").read_text(
        encoding="utf-8"
    )

    assert "config -q" in source
    assert "image inspect" in source
    assert "run --rm --no-deps" in source
    assert "--entrypoint python" in source
    assert "simnow_experimental_preflight.py" in source
    assert 'add_argument("--execute"' not in source
    assert "while " not in source
    assert "sleep " not in source


def test_preflight_has_no_mutation_client_methods() -> None:
    source = (ROOT / "scripts/simnow_experimental_preflight.py").read_text(
        encoding="utf-8"
    )

    assert "install_trusted" not in source
    assert "publish-keyless" not in source
    assert "leader.acquire" not in source
    assert 'add_argument("--execute"' not in source
    assert "preview_once" in source
    assert os.linesep in source
