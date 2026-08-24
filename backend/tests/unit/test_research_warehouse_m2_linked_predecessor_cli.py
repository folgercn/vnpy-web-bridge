from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

linked_cli = importlib.import_module("research_warehouse.m2_linked_predecessor_cli")
RegistryError = importlib.import_module("research_warehouse.errors").RegistryError


class _Lock:
    def __enter__(self):
        return None

    def __exit__(self, *_args):
        return False


def _projection(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        runtime_input_raw_sha256="1" * 64,
        history_receipt_path=tmp_path / "history.json",
        history_receipt_raw_sha256="2" * 64,
        manifest_public_key_path=tmp_path / "manifest.pub",
        manifest_public_key_raw_sha256="3" * 64,
        business_public_key_raw_sha256="4" * 64,
        contract_registry_path=tmp_path / "contracts.json",
        contract_registry_raw_sha256="5" * 64,
    )


def test_non_root_fails_before_any_runtime_or_write_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def unexpected(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("non-root must not enter publication")

    monkeypatch.setattr(linked_cli, "_require_root", lambda: (_ for _ in ()).throw(RegistryError("root required")))
    monkeypatch.setattr(linked_cli, "load_isolation_policy", unexpected)
    assert linked_cli.main(["--continuous-config", str(tmp_path / "config.json")]) == 2
    assert called is False


def test_cli_replays_current_root_as_linked_catalog_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    projection = _projection(tmp_path)
    state = SimpleNamespace(
        raw_sha256="6" * 64,
        payload={"last_trade_day": "2026-08-21"},
    )
    runtime_input = SimpleNamespace(raw_sha256="1" * 64)
    context = SimpleNamespace(runtime_input=runtime_input)
    entry = SimpleNamespace(
        receipt_raw=b"receipt\n",
        artifact_raw=b"artifact\n",
        receipt={
            "receipt_id": "daily-roll-catalog-receipt-test",
            "sequence": 3,
            "official_day": "2026-08-21",
        },
        artifact={"artifact_id": "verified-daily-roll-test"},
    )
    captured: dict = {}

    monkeypatch.setattr(linked_cli, "_require_root", lambda: None)
    monkeypatch.setattr(
        linked_cli,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(uid=503, gid=503),
    )
    monkeypatch.setattr(linked_cli, "load_runtime_input", lambda *_a, **_k: runtime_input)
    monkeypatch.setattr(linked_cli, "operator_state_lock", lambda *_a, **_k: _Lock())
    monkeypatch.setattr(linked_cli, "load_operator_state", lambda _path: state)
    monkeypatch.setattr(linked_cli, "_load_projection_as_service", lambda **_k: projection)
    monkeypatch.setattr(linked_cli, "load_runtime_context_readonly", lambda _path: context)
    monkeypatch.setattr(linked_cli, "read_regular_strict", lambda *_a, **_k: b"registry")

    def publish(**kwargs):
        captured.update(kwargs)
        return entry

    monkeypatch.setattr(linked_cli, "publish_predecessor_artifact", publish)
    monkeypatch.setattr(
        linked_cli,
        "load_current_catalog_head",
        lambda _path: SimpleNamespace(receipt_raw=entry.receipt_raw, artifact_raw=entry.artifact_raw),
    )

    assert linked_cli.main(["--continuous-config", str(tmp_path / "config.json")]) == 0
    assert captured["official_day"] == "2026-08-21"
    assert captured["history_receipt_path"] == projection.history_receipt_path
    assert captured["contract_registry_raw"] == b"registry"
    assert captured["predecessor"].__class__.__name__ == "PredecessorContinuity"
    assert captured["pins"].operator_state_raw_sha256 == state.raw_sha256
    assert '"status":"LINKED_PUBLISHED"' in capsys.readouterr().out


def test_cli_rejects_runtime_root_drift_before_read_or_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _projection(tmp_path)
    state = SimpleNamespace(raw_sha256="6" * 64, payload={"last_trade_day": "2026-08-21"})
    runtime_input = SimpleNamespace(raw_sha256="1" * 64)
    called = False

    def unexpected(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("drift must stop before source reads")

    monkeypatch.setattr(linked_cli, "_require_root", lambda: None)
    monkeypatch.setattr(linked_cli, "load_isolation_policy", lambda _path: SimpleNamespace(uid=503, gid=503))
    monkeypatch.setattr(linked_cli, "load_runtime_input", lambda *_a, **_k: runtime_input)
    monkeypatch.setattr(linked_cli, "operator_state_lock", lambda *_a, **_k: _Lock())
    monkeypatch.setattr(linked_cli, "load_operator_state", lambda _path: state)
    monkeypatch.setattr(linked_cli, "_load_projection_as_service", lambda **_k: projection)
    monkeypatch.setattr(
        linked_cli,
        "load_runtime_context_readonly",
        lambda _path: SimpleNamespace(runtime_input=SimpleNamespace(raw_sha256="f" * 64)),
    )
    monkeypatch.setattr(linked_cli, "read_regular_strict", unexpected)
    assert linked_cli.main(["--continuous-config", str(tmp_path / "config.json")]) == 2
    assert called is False


def test_cli_has_no_execution_gateway_or_network_import_seam() -> None:
    tree = ast.parse(Path(linked_cli.__file__).read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    forbidden = ("app.", "gateway", "windows", "socket", "requests", "http")
    assert not any(
        item.lower().startswith(prefix) for item in imported for prefix in forbidden
    )
