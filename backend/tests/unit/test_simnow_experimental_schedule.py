from __future__ import annotations

import json
import os
import plistlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

from scripts.ci.classify_changes import classify, classify_phase_a, classify_phase_b

ROOT = Path(__file__).resolve().parents[3]


def test_experimental_launchd_only_wakes_one_shot_runner() -> None:
    path = ROOT / "deployments/com.vnpy-web-bridge.simnow-experimental.plist"
    payload = plistlib.loads(path.read_bytes())

    assert payload["Label"] == "com.vnpy-web-bridge.simnow-experimental"
    assert payload["ProgramArguments"] == [
        "/bin/bash",
        "/Users/fujun/services/vnpy-web-bridge/deployments/simnow-experimental-run-once.sh",
    ]
    assert payload["WatchPaths"] == [
        "/Users/fujun/services/vnpy-web-bridge/runtime/simnow-experimental/target.json"
    ]
    assert "RunAtLoad" not in payload
    assert "KeepAlive" not in payload
    assert len(payload["StartCalendarInterval"]) == 10
    assert {entry["Weekday"] for entry in payload["StartCalendarInterval"]} == {
        1,
        2,
        3,
        4,
        5,
    }
    assert {entry["Hour"] for entry in payload["StartCalendarInterval"]} == {9, 13}


def _launcher_environment(tmp_path: Path, *, target_path: Path, docker_bin: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "SIMNOW_EXPERIMENTAL_TARGET_PATH": str(target_path),
            "SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR": str(tmp_path / "monthly"),
            "SIMNOW_EXPERIMENTAL_COMPOSE_FILE": str(
                ROOT / "deployments/docker-compose.simnow-experimental.yml"
            ),
            "SIMNOW_EXPERIMENTAL_PROJECT_DIRECTORY": str(ROOT),
            "SIMNOW_EXPERIMENTAL_DOCKER_BIN": str(docker_bin),
            "COMPOSE_PROJECT_NAME": "issue362-test",
        }
    )
    return environment


def test_experimental_launcher_exits_before_docker_without_target(tmp_path: Path) -> None:
    launcher = (ROOT / "deployments/simnow-experimental-run-once.sh").read_text(
        encoding="utf-8"
    )

    no_target = '[[ -f "$target_path" ]] || exit 0'
    docker = "/Applications/Docker.app/Contents/Resources/bin/docker"
    assert no_target in launcher
    assert launcher.index(no_target) < launcher.index(docker)
    assert '"$bundle_directory/$source_month.json"' in launcher
    assert "--expires-at \"$expires_at\"" in launcher
    assert "--execute" in launcher
    assert "--no-deps" in launcher
    assert "while " not in launcher
    assert "sleep " not in launcher
    assert "flock" not in launcher

    environment = _launcher_environment(
        tmp_path,
        target_path=tmp_path / "absent-target.json",
        docker_bin=tmp_path / "docker-must-not-run",
    )
    environment.pop("COMPOSE_PROJECT_NAME")
    result = subprocess.run(
        ["/bin/bash", str(ROOT / "deployments/simnow-experimental-run-once.sh")],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_experimental_launcher_invokes_one_existing_runner_with_selected_bundle(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    source_month = "2026-08"
    target.write_text(json.dumps({"source_month": source_month}), encoding="utf-8")
    monthly = tmp_path / "monthly"
    monthly.mkdir()
    (monthly / f"{source_month}.json").write_text("{}", encoding="utf-8")
    arguments = tmp_path / "docker-arguments.json"
    fake_docker = tmp_path / "fake-docker"
    fake_docker.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$@\" | /usr/bin/python3 -c "
        "'import json,sys; print(json.dumps(sys.stdin.read().split()))' "
        f"> {arguments}\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    result = subprocess.run(
        ["/bin/bash", str(ROOT / "deployments/simnow-experimental-run-once.sh")],
        env=_launcher_environment(
            tmp_path, target_path=target, docker_bin=fake_docker
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    invoked = json.loads(arguments.read_text(encoding="utf-8"))
    assert invoked.count("compose") == 1
    assert invoked[invoked.index("--project-name") + 1] == (
        "issue362-test-simnow-experimental"
    )
    assert str(ROOT / "deployments/docker-compose.final.yml") not in invoked
    assert invoked[invoked.index("run") : invoked.index("run") + 4] == [
        "run",
        "--rm",
        "--no-deps",
        "simnow-experimental-runner",
    ]
    assert "/run/simnow-experimental/target.json" in invoked
    assert f"/run/simnow-experimental/monthly/{source_month}.json" in invoked
    assert "--expires-at" in invoked
    expires_at = datetime.fromisoformat(
        invoked[invoked.index("--expires-at") + 1].replace("Z", "+00:00")
    )
    remaining = (expires_at - datetime.now(timezone.utc)).total_seconds()
    assert 240 <= remaining <= 300
    assert "--execute" in invoked


def test_experimental_compose_reuses_final_boundaries_without_a_new_stack() -> None:
    raw = (ROOT / "deployments/docker-compose.simnow-experimental.yml").read_text(
        encoding="utf-8"
    )
    compose = yaml.safe_load(raw)
    service = compose["services"]["simnow-experimental-runner"]

    assert set(compose) == {"services", "networks", "volumes"}
    assert service["restart"] == "no"
    assert "user" not in service
    assert service["networks"] == ["private-control", "control-custody"]
    assert "depends_on" not in service
    assert "build" not in service
    assert service["environment"]["PRODUCTION"] == "false"
    assert service["environment"]["LIVE_TRADING_AUTHORIZED"] == "false"
    assert service["environment"]["COUNTABLE_FORWARD"] == "false"
    assert service["environment"]["OFFICIAL_FORWARD_CLAIMED"] == "false"
    assert service["environment"]["SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED"] == (
        "${SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED:?required}"
    )
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "network_mode" not in service
    assert compose["networks"] == {
        "private-control": {
            "external": True,
            "name": "${SIMNOW_EXPERIMENTAL_ACTIVE_PROJECT:?required}_private-control",
        },
        "control-custody": {
            "external": True,
            "name": "${SIMNOW_EXPERIMENTAL_ACTIVE_PROJECT:?required}_control-custody",
        },
    }
    assert compose["volumes"] == {
        "market_data_state": {
            "external": True,
            "name": "${SIMNOW_EXPERIMENTAL_ACTIVE_PROJECT:?required}_market_data_state",
        },
        "market_projection": {
            "external": True,
            "name": "${SIMNOW_EXPERIMENTAL_ACTIVE_PROJECT:?required}_market_projection",
        },
    }


def test_experimental_launcher_and_launchd_do_not_override_image_runtime_identity() -> None:
    launcher = (ROOT / "deployments/simnow-experimental-run-once.sh").read_text(
        encoding="utf-8"
    )
    plist = (ROOT / "deployments/com.vnpy-web-bridge.simnow-experimental.plist").read_text(
        encoding="utf-8"
    )

    assert "SIMNOW_EXPERIMENTAL_UID" not in launcher
    assert "SIMNOW_EXPERIMENTAL_GID" not in launcher
    assert "SIMNOW_EXPERIMENTAL_UID" not in plist
    assert "SIMNOW_EXPERIMENTAL_GID" not in plist
    containerfile = (
        ROOT / "deployments/phase-b/Containerfile.simnow-experimental-runner"
    ).read_text(encoding="utf-8")
    assert "USER 65532:65532" in containerfile


def test_experimental_schedule_glue_stays_on_the_contract_only_lane() -> None:
    for path in (
        "deployments/com.vnpy-web-bridge.simnow-experimental.plist",
        "deployments/docker-compose.simnow-experimental.yml",
        "deployments/simnow-experimental-run-once.sh",
        "deployments/simnow-experimental-preflight.sh",
        "backend/tests/unit/test_simnow_experimental_schedule.py",
    ):
        result = classify([path])
        assert result["simnow_experimental_changed"] is True, path
        assert not any(
            value
            for key, value in result.items()
            if key != "simnow_experimental_changed"
        ), path
        assert classify_phase_a([path])["selected_units"] == [], path
        assert classify_phase_a([path])["release_blocked"] is False, path
        assert classify_phase_b([path])["selected_units"] == [], path
        assert classify_phase_b([path])["phase_b_gate_blocked"] is False, path
