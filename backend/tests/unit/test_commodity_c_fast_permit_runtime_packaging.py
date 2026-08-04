from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import yaml

from app.services.commodity_c_fast_permit_runtime_smoke import (
    FORBIDDEN_SIGNER_NAMES,
    OFFLINE_OPERATOR_TOOL_NAMES,
    RUNTIME_MODULE_NAMES,
    RUNTIME_SCHEMA_NAMES,
    validate_runtime_packaging,
)

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE_OVERLAY = (
    ROOT / "deployments/docker-compose.c-fast-simnow-permit.yml"
)
ENV_EXAMPLE = ROOT / "backend/.env.example"


def test_repository_permit_runtime_import_smoke_is_default_off() -> None:
    result = validate_runtime_packaging()

    assert result["status"] == (
        "C_FAST_SIMNOW_PERMIT_RUNTIME_PACKAGED_DEFAULT_OFF"
    )
    assert result["runtime_modules"] == list(RUNTIME_MODULE_NAMES)
    assert result["runtime_schemas"] == list(RUNTIME_SCHEMA_NAMES)
    assert result["offline_operator_tools"] == list(
        OFFLINE_OPERATOR_TOOL_NAMES
    )
    assert result["shakedown_enabled"] is False
    assert result["auto_dispatch_enabled"] is False
    assert result["execution_permit_enabled"] is False
    assert result["orders_sent"] == 0
    assert result["positions_modified"] == 0
    assert result["production_allowed"] is False


def test_production_dockerfile_packages_only_exact_verifier_closure() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    lines = text.splitlines()

    assert {
        line for line in lines if line.startswith("COPY scripts")
    } == {
        f"COPY scripts/{name} ./scripts/{name}"
        for name in (*RUNTIME_MODULE_NAMES, *OFFLINE_OPERATOR_TOOL_NAMES)
    }
    assert {
        line for line in lines if line.startswith("COPY docs/schemas")
    } == {
        f"COPY docs/schemas/{name} ./docs/schemas/{name}"
        for name in RUNTIME_SCHEMA_NAMES
    }
    for forbidden in FORBIDDEN_SIGNER_NAMES:
        assert forbidden not in text
    assert "COPY scripts ./scripts" not in text
    assert "COPY scripts/ ./scripts" not in text
    assert "COPY docs ./docs" not in text
    assert "COPY docs/ ./docs" not in text
    assert "PYTHONPATH=/app/backend:/app/scripts" in text
    assert (
        "python -m app.services.commodity_c_fast_permit_runtime_smoke"
        in text
    )


def _isolated_runtime_root(tmp_path: Path) -> Path:
    runtime_root = tmp_path / "image-root"
    scripts = runtime_root / "scripts"
    schemas = runtime_root / "docs" / "schemas"
    scripts.mkdir(parents=True)
    schemas.mkdir(parents=True)
    for name in RUNTIME_MODULE_NAMES:
        shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    for name in OFFLINE_OPERATOR_TOOL_NAMES:
        shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    for name in RUNTIME_SCHEMA_NAMES:
        shutil.copyfile(ROOT / "docs" / "schemas" / name, schemas / name)
    return runtime_root


def _run_isolated_image_smoke(runtime_root: Path) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "APP_ENV": "development",
        "PYTHONPATH": os.pathsep.join(
            (str(ROOT / "backend"), str(runtime_root / "scripts"))
        ),
    }
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "app.services.commodity_c_fast_permit_runtime_smoke",
        ],
        cwd=runtime_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_exact_isolated_image_closure_import_smoke(tmp_path: Path) -> None:
    result = _run_isolated_image_smoke(_isolated_runtime_root(tmp_path))

    assert result.returncode == 0, result.stderr
    assert "C_FAST_SIMNOW_PERMIT_RUNTIME_PACKAGED_DEFAULT_OFF" in result.stdout
    assert '"signers_packaged": false' in result.stdout
    assert '"orders_sent": 0' in result.stdout
    assert "commodity_c_fast_fee_statement_verify.py" in result.stdout


def test_isolated_image_smoke_rejects_standalone_signer(tmp_path: Path) -> None:
    runtime_root = _isolated_runtime_root(tmp_path)
    forbidden = FORBIDDEN_SIGNER_NAMES[0]
    shutil.copyfile(
        ROOT / "scripts" / forbidden,
        runtime_root / "scripts" / forbidden,
    )

    result = _run_isolated_image_smoke(runtime_root)

    assert result.returncode != 0
    assert "code outside the exact verifier closure" in result.stderr


def test_mount_overlay_is_explicit_read_only_and_keeps_authority_off() -> None:
    payload = yaml.safe_load(COMPOSE_OVERLAY.read_text(encoding="utf-8"))
    service = payload["services"]["web-bridge"]

    assert service["environment"] == {
        "COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_ENABLED": "false",
        "COMMODITY_C_FAST_SIMNOW_SHAKEDOWN_ENABLED": "false",
        "COMMODITY_C_FAST_SIMNOW_AUTO_DISPATCH_ENABLED": "false",
        "COMMODITY_C_FAST_SIMNOW_EXECUTION_PERMIT_ENABLED": "false",
    }
    volumes = service["volumes"]
    assert [volume["target"] for volume in volumes] == [
        "/run/c-fast-simnow/artifacts",
        "/run/c-fast-simnow/keyrings",
        "/run/c-fast-simnow/snapshot",
        "/run/c-fast-simnow/one-shot",
    ]
    assert [volume["read_only"] for volume in volumes] == [
        True,
        True,
        True,
        False,
    ]
    assert all(
        volume["type"] == "bind"
        and volume["bind"] == {"create_host_path": False}
        and ":?required_for_explicit_c_fast_simnow_mount}" in volume["source"]
        for volume in volumes
    )


def test_fee_keyring_settings_are_documented_and_share_read_only_mount() -> None:
    env_keys = {
        line.split("=", 1)[0]
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    assert {
        "COMMODITY_C_FAST_FEE_STATEMENT_TRUSTED_KEYRING_PATH",
        "COMMODITY_C_FAST_FEE_STATEMENT_EXPECTED_KEYRING_RAW_SHA256",
        "COMMODITY_C_FAST_FEE_STATEMENT_HISTORICAL_TRUST_PROFILES_JSON",
    } <= env_keys

    payload = yaml.safe_load(COMPOSE_OVERLAY.read_text(encoding="utf-8"))
    keyring_mount = next(
        volume
        for volume in payload["services"]["web-bridge"]["volumes"]
        if volume["target"] == "/run/c-fast-simnow/keyrings"
    )
    assert keyring_mount == {
        "type": "bind",
        "source": (
            "${COMMODITY_C_FAST_SIMNOW_KEYRINGS_HOST_DIR:"
            "?required_for_explicit_c_fast_simnow_mount}"
        ),
        "target": "/run/c-fast-simnow/keyrings",
        "read_only": True,
        "bind": {"create_host_path": False},
    }
