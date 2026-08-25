from __future__ import annotations

import asyncio
import os
import subprocess
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


def test_preflight_reads_inputs_with_stable_reader_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_path = tmp_path / "target.json"
    bundle_path = tmp_path / "monthly.json"
    target_path.write_text('{"target": true}\n', encoding="utf-8")
    bundle_path.write_text('{"bundle": true}\n', encoding="utf-8")
    target_path.chmod(0o444)
    bundle_path.chmod(0o444)
    labels: list[str] = []

    original_reader = preflight.read_json_stable

    def read(path: Path, *, label: str, **kwargs: object) -> tuple[dict[str, object], bytes]:
        labels.append(label)
        return original_reader(path, label=label, **kwargs)

    monkeypatch.setattr(preflight, "read_json_stable", read)
    monkeypatch.setattr(preflight, "_check_readonly_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(preflight, "validate_planner_bundle", lambda value: value)
    monkeypatch.setattr(
        preflight,
        "validate_test_target_bundle_binding",
        lambda target, _bundle: target,
    )

    target, bundle = preflight._read_inputs(target_path, bundle_path)

    assert target == {"target": True}
    assert bundle == {"bundle": True}
    assert labels == ["experimental target", "monthly planner bundle"]


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
                        "leader": {"held": False},
                        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
                        "broker": {"active_order_count": 0},
                        "send_intents": [],
                    }

            return Projection()

    asyncio.run(preflight._check_execution_state(FakeExecution()))  # type: ignore[arg-type]


def test_preflight_accepts_retired_terminal_revoked_zero_work_boundary() -> None:
    class FakeExecution:
        async def status(self) -> object:
            class Projection:
                def as_dict(self) -> dict[str, object]:
                    return {
                        "lifecycle": "READY",
                        "plan": {"state": "TERMINAL"},
                        "authority": {"state": "REVOKED"},
                        "leader": {"held": False},
                        "reconciliation": {
                            "state": "RECONCILED",
                            "unknown_outcomes": 0,
                        },
                        "broker": {"active_order_count": 0},
                        "send_intents": [
                            {"state": "TERMINAL"},
                            {"state": "RECONCILED"},
                        ],
                    }

            return Projection()

    asyncio.run(preflight._check_execution_state(FakeExecution()))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field,value",
    (
        ("authority", {"state": "ENABLED"}),
        ("reconciliation", {"state": "RECONCILED", "unknown_outcomes": 1}),
        ("broker", {"active_order_count": 1}),
        ("send_intents", [{"state": "PERSISTED"}]),
        ("leader", {"held": True}),
    ),
)
def test_preflight_rejects_unsafe_terminal_revoked_boundary(
    field: str, value: object
) -> None:
    class FakeExecution:
        async def status(self) -> object:
            class Projection:
                def as_dict(self) -> dict[str, object]:
                    status: dict[str, object] = {
                        "lifecycle": "READY",
                        "plan": {"state": "TERMINAL"},
                        "authority": {"state": "REVOKED"},
                        "leader": {"held": False},
                        "reconciliation": {
                            "state": "RECONCILED",
                            "unknown_outcomes": 0,
                        },
                        "broker": {"active_order_count": 0},
                        "send_intents": [],
                    }
                    status[field] = value
                    return status

            return Projection()

    with pytest.raises(preflight.PreflightStop, match="safe IDLE/DISABLED"):
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


@pytest.mark.parametrize(
    ("keyless", "expected_stop", "returncode"),
    (
        ("true", None, 0),
        ("false", "STOP custody-config=keyless-disabled", 1),
        ("", "STOP custody-config=keyless-setting-missing", 1),
    ),
)
def test_preflight_host_adapter_reads_only_active_custody_boolean(
    tmp_path: Path, keyless: str, expected_stop: str | None, returncode: int
) -> None:
    target = tmp_path / "target.json"
    monthly = tmp_path / "monthly"
    monthly.mkdir()
    target.write_text('{"source_month":"2026-08"}', encoding="utf-8")
    (monthly / "2026-08.json").write_text("{}", encoding="utf-8")
    arguments = tmp_path / "docker-arguments.json"
    fake_docker = tmp_path / "fake-docker"
    fake_docker.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$@\" >> \"$FAKE_DOCKER_ARGUMENTS\"\n"
        "if [[ \" $* \" == *\" image inspect \"* ]]; then exit 0; fi\n"
        "if [[ \" $* \" == *\" inspect --format \"* ]]; then printf '%s' \"${FAKE_KEYLESS}\"; exit 0; fi\n"
        "if [[ \" $* \" == *\" config --images \"* ]]; then echo runner:exact; exit 0; fi\n"
        "if [[ \" $* \" == *\" config -q \"* ]]; then exit 0; fi\n"
        "if [[ \" $* \" == *\" run --rm --no-deps \"* ]]; then exit 0; fi\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    environment = os.environ | {
        "SIMNOW_EXPERIMENTAL_TARGET_PATH": str(target),
        "SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR": str(monthly),
        "SIMNOW_EXPERIMENTAL_COMPOSE_FILE": str(
            ROOT / "deployments/docker-compose.simnow-experimental.yml"
        ),
        "SIMNOW_EXPERIMENTAL_PROJECT_DIRECTORY": str(ROOT),
        "SIMNOW_EXPERIMENTAL_DOCKER_BIN": str(fake_docker),
        "COMPOSE_PROJECT_NAME": "active-project",
        "FAKE_DOCKER_ARGUMENTS": str(arguments),
        "FAKE_KEYLESS": keyless,
    }

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "deployments/simnow-experimental-preflight.sh")],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == returncode
    if expected_stop is not None:
        assert expected_stop in result.stdout + result.stderr
    commands = arguments.read_text(encoding="utf-8")
    assert "inspect\n--format\n" in commands
    assert "active-project-artifact-custody-1" in commands
    if returncode == 0:
        assert "simnow_experimental_preflight.py" in commands
    assert "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED=true" not in result.stdout
    assert "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED=false" not in result.stdout
    assert "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED" in commands
    assert "PHASE_C_CUSTODY_SHARED_SECRET" not in result.stdout + result.stderr


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
