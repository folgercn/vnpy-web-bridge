from __future__ import annotations

import copy
import hashlib
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import research_warehouse.registry as registry_module
from research_warehouse.authority import (
    assert_research_source_boundary,
)
from research_warehouse.errors import RegistryError
from research_warehouse.policy import (
    render_endpoint,
    validate_redirect,
)
from research_warehouse.registry import load_registry

REGISTRY_PATH = (
    ROOT / "deployments/research-warehouse/source-registry-v1.json"
)
SCHEMA_PATH = (
    ROOT / "docs/schemas/research-warehouse-source-registry-v1.schema.json"
)


def payload() -> dict:
    return json.loads(REGISTRY_PATH.read_bytes())


def write_payload(tmp_path: Path, value: dict) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def write_payload_with_test_pin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: dict,
) -> Path:
    path = write_payload(tmp_path, value)
    monkeypatch.setattr(
        registry_module,
        "FROZEN_REGISTRY_RAW_SHA256",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    return path


def test_frozen_registry_passes_schema_and_strict_parser() -> None:
    value = payload()
    Draft202012Validator(json.loads(SCHEMA_PATH.read_bytes())).validate(value)

    registry = load_registry(REGISTRY_PATH)

    assert registry.registry_id == "shfe-ine-public-daily-v1"
    assert registry.published_at == "2026-07-29T00:00:00Z"
    assert len(registry.raw_sha256) == 64
    assert {source.exchange for source in registry.sources} == {"SHFE", "INE"}
    assert registry.authority.trading_authorized is False


def test_registry_raw_bytes_must_match_audited_pin(tmp_path: Path) -> None:
    changed_formatting = tmp_path / "registry.json"
    changed_formatting.write_text(
        json.dumps(payload(), sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(RegistryError, match="raw SHA256"):
        load_registry(changed_formatting)


def test_authority_policy_is_deeply_immutable() -> None:
    registry = load_registry(REGISTRY_PATH)

    with pytest.raises(FrozenInstanceError):
        registry.authority.trading_authorized = True
    assert registry.authority.execution_authorized is False


def test_exact_official_endpoints_are_rendered() -> None:
    registry = load_registry(REGISTRY_PATH)

    assert render_endpoint(
        registry.source("shfe-daily-market-data-v1").endpoint_template,
        "20260728",
    ) == (
        "https://www.shfe.com.cn/data/tradedata/future/"
        "dailydata/kx20260728.dat"
    )
    assert render_endpoint(
        registry.source("ine-daily-market-data-v1").endpoint_template,
        "20260728",
    ).startswith("https://www.ine.cn/")


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda value: value["authority"].update(
                {"trading_authorized": True}
            ),
            "Research-only",
        ),
        (
            lambda value: value["sources"][0].update(
                {"allowed_hosts": ["shfe.com.cn.evil.invalid"]}
            ),
            "official host",
        ),
        (
            lambda value: value["sources"][0].update(
                {
                    "endpoint_template": (
                        "http://www.shfe.com.cn/kx{yyyymmdd}.dat"
                    )
                }
            ),
            "HTTPS",
        ),
        (
            lambda value: value["sources"][0].update(
                {
                    "endpoint_template": (
                        "https://user:pass@www.shfe.com.cn/"
                        "kx{yyyymmdd}.dat"
                    )
                }
            ),
            "credentials",
        ),
        (
            lambda value: value["sources"][0].update(
                {"endpoint_template": "https://www.shfe.com.cn/static.dat"}
            ),
            "yyyymmdd",
        ),
        (
            lambda value: value.update(
                {"published_at": "2026-07-29T08:00:00+08:00"}
            ),
            "UTC",
        ),
        (
            lambda value: value["sources"][0].update(
                {"license_policy": "PUBLIC_DOMAIN"}
            ),
            "license policy",
        ),
    ],
)
def test_registry_mutations_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    value = copy.deepcopy(payload())
    mutate(value)

    with pytest.raises(RegistryError, match=match):
        load_registry(write_payload_with_test_pin(monkeypatch, tmp_path, value))


def test_unknown_fields_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    value = payload()
    value["sources"][0]["runtime_rpc"] = "tcp://192.168.100.187:2014"

    with pytest.raises(RegistryError, match="frozen schema"):
        load_registry(write_payload_with_test_pin(monkeypatch, tmp_path, value))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["sources"][0].update(
            {
                "endpoint_template": (
                    "https://www.shfe.com.cn/other/kx{yyyymmdd}.dat"
                )
            }
        ),
        lambda value: (
            value["sources"][0].update(
                {"source_id": "ine-daily-market-data-v1"}
            ),
            value["sources"][1].update(
                {"source_id": "shfe-daily-market-data-v1"}
            ),
        ),
        lambda value: value["sources"][0].update(
            {"required_row_fields": ["NOT_THE_AUDITED_SCHEMA"]}
        ),
        lambda value: value["sources"][0].update(
            {"media_type": "application/octet-stream"}
        ),
        lambda value: value["sources"][0].update(
            {"endpoint_schema_version": "unreviewed-v2"}
        ),
    ],
)
def test_semantic_contract_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutate,
) -> None:
    value = copy.deepcopy(payload())
    mutate(value)
    schema = Draft202012Validator(json.loads(SCHEMA_PATH.read_bytes()))

    assert not schema.is_valid(value)
    with pytest.raises(RegistryError, match="audited exact v1 contracts"):
        load_registry(write_payload_with_test_pin(monkeypatch, tmp_path, value))


def test_escaped_template_braces_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    value = copy.deepcopy(payload())
    value["sources"][0]["endpoint_template"] = (
        "https://www.shfe.com.cn/data/kx{{yyyymmdd}}.dat"
    )
    schema = Draft202012Validator(json.loads(SCHEMA_PATH.read_bytes()))

    assert not schema.is_valid(value)
    with pytest.raises(RegistryError, match="plain"):
        load_registry(write_payload_with_test_pin(monkeypatch, tmp_path, value))


def test_redirect_reapplies_exact_host_allowlist() -> None:
    assert validate_redirect(
        "https://www.shfe.com.cn/next",
        ("www.shfe.com.cn",),
    ).endswith("/next")

    with pytest.raises(RegistryError, match="not allowlisted"):
        validate_redirect(
            "https://shfe.com.cn.evil.invalid/next",
            ("www.shfe.com.cn",),
        )


@pytest.mark.parametrize("value", ["2026-07-28", "２０２６０７２８", "2026072x"])
def test_endpoint_date_is_strict(value: str) -> None:
    with pytest.raises(RegistryError, match="YYYYMMDD"):
        render_endpoint("https://www.shfe.com.cn/kx{yyyymmdd}.dat", value)


def test_registry_symlink_and_hardlink_are_rejected(tmp_path: Path) -> None:
    source = write_payload(tmp_path, payload())
    symlink = tmp_path / "registry-link.json"
    symlink.symlink_to(source)
    hardlink = tmp_path / "registry-hardlink.json"
    hardlink.hardlink_to(source)

    with pytest.raises(RegistryError, match="non-symlink"):
        load_registry(symlink)
    with pytest.raises(RegistryError, match="hardlink"):
        load_registry(source)


def test_research_package_has_no_execution_imports() -> None:
    assert_research_source_boundary(
        list((ROOT / "scripts/research_warehouse").rglob("*.py"))
    )


def test_boundary_rejects_execution_import(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text("from backend.app.services import TradeService\n")

    with pytest.raises(RegistryError, match="forbidden import"):
        assert_research_source_boundary([source])


@pytest.mark.parametrize(
    "source_text",
    [
        "from backend import app\n",
        "import backend\nvalue = backend.app\n",
        'import os\nvalue = os.environ.get("WEB_TRADE_ENABLED")\n',
        (
            "from os import getenv\n"
            'value = getenv("COMMODITY_C_FAST_SIMNOW_RPC_REQUEST_ADDRESS")\n'
        ),
        (
            "from os import environ as env\n"
            'value = env["COMMODITY_C_FAST_SIMNOW_RPC_SUBSCRIBE_ADDRESS"]\n'
        ),
    ],
)
def test_boundary_rejects_common_execution_bypasses(
    tmp_path: Path, source_text: str
) -> None:
    source = tmp_path / "bad_env.py"
    source.write_text(source_text, encoding="utf-8")

    with pytest.raises(RegistryError, match="forbidden"):
        assert_research_source_boundary([source])


def test_recursive_boundary_scan_catches_nested_module(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "safe.py").write_text("value = 1\n", encoding="utf-8")
    (nested / "bad.py").write_text("import questdb\n", encoding="utf-8")

    with pytest.raises(RegistryError, match="forbidden import questdb"):
        assert_research_source_boundary(list(tmp_path.rglob("*.py")))
