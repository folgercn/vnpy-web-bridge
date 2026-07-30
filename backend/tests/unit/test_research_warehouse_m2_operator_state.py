from __future__ import annotations

import json
import plistlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import m2_operator_state
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_runtime_input import RuntimeInput


def _fake_root_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(m2_operator_state, "_require_root", lambda: None)
    monkeypatch.setattr(
        m2_operator_state,
        "require_root_managed",
        lambda _path: None,
    )

    def write(path: Path, raw: bytes, *, create_only: bool) -> None:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if create_only and path.exists():
            assert path.read_bytes() == raw
            return
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o444)

    monkeypatch.setattr(m2_operator_state, "_atomic_root_write", write)


def _manifest_result() -> dict:
    return {
        "batch_id": "batch-2026-07-30-" + "a" * 24,
        "batch_seal_sha256": "a" * 64,
        "commit_seal_sha256": "b" * 64,
        "committed_at": "2026-07-30T10:40:00.000000Z",
        "manifest_relative_path": (
            "manifests/2026-07-30/batch-2026-07-30-" + "a" * 24 + ".json"
        ),
        "manifest_raw_sha256": "c" * 64,
        "parent_batch_seal_sha256": None,
        "parent_commit_seal_sha256": None,
        "status": "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR",
        "trade_day": "2026-07-30",
    }


def test_root_state_records_content_addressed_ledger_and_backup_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_root_io(monkeypatch)
    state_path = tmp_path / "operator-state-v1.json"
    state = m2_operator_state.initialize_operator_state(state_path)
    committed = m2_operator_state.record_manifest_result(
        state,
        result=_manifest_result(),
    )

    assert committed.payload["manifest_sequence"] == 1
    assert committed.payload["manifest_genesis_seal_sha256"] == "a" * 64
    ledger_path = Path(committed.payload["commit_anchor_ledger_path"])
    assert ledger_path.name == (
        "commit-anchor-ledger-"
        + committed.payload["commit_anchor_ledger_raw_sha256"]
        + ".json"
    )
    assert json.loads(ledger_path.read_bytes())["entries"][0][
        "commit_seal_sha256"
    ] == "b" * 64

    runtime_path = tmp_path / "runtime-input-v1.json"
    runtime_payload = {
        "expected_backup_head_anchor_raw_sha256": "0" * 64,
        "authority": false_authority(),
    }
    runtime_path.write_bytes(canonical_json_line(runtime_payload))
    runtime_path.chmod(0o444)
    monkeypatch.setattr(
        m2_operator_state,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(payload={}),
    )

    def load_runtime(path: Path, *, policy) -> RuntimeInput:
        del policy
        raw = path.read_bytes()
        return RuntimeInput(
            path=path,
            raw_sha256=sha256(raw),
            payload=json.loads(raw),
        )

    monkeypatch.setattr(m2_operator_state, "load_runtime_input", load_runtime)
    backup = m2_operator_state.record_backup_result(
        committed,
        result={
            "anchor_id": "backup-" + "d" * 64,
            "anchor_raw_sha256": "d" * 64,
            "created_at": "2026-07-30T10:50:00.000000Z",
            "parent_anchor_raw_sha256": None,
            "sequence": 1,
            "status": "APPEND_ONLY_BACKUP_COMMITTED_AWAITING_ROOT_PIN",
        },
        runtime_input_path=runtime_path,
    )

    assert backup.payload["backup_sequence"] == 1
    assert backup.payload["backup_head_anchor_raw_sha256"] == "d" * 64
    assert json.loads(runtime_path.read_bytes())[
        "expected_backup_head_anchor_raw_sha256"
    ] == "d" * 64


def test_state_rejects_manifest_that_does_not_extend_root_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_root_io(monkeypatch)
    state = m2_operator_state.initialize_operator_state(
        tmp_path / "operator-state-v1.json"
    )
    result = _manifest_result()
    result["parent_batch_seal_sha256"] = "e" * 64

    with pytest.raises(
        m2_operator_state.RegistryError,
        match="does not extend root pin",
    ):
        m2_operator_state.record_manifest_result(state, result=result)


def test_layered_launchd_jobs_keep_signers_root_and_rebuild_service_only() -> None:
    directory = ROOT / "deployments/research-warehouse/m2"
    expected = {
        "manifest-signer": (None, 18, 40),
        "rebuild": ("vnpyresearch", 18, 50),
        "backup-signer": (None, 19, 10),
    }
    for role, (user, hour, minute) in expected.items():
        payload = plistlib.loads(
            (
                directory
                / f"com.vnpy.research-warehouse-{role}.plist"
            ).read_bytes()
        )
        assert payload.get("UserName") == user
        assert payload["ProgramArguments"] == [
            "/usr/local/libexec/vnpyresearch/release-lock-runner",
            role,
        ]
        assert payload["StartCalendarInterval"] == {
            "Hour": hour,
            "Minute": minute,
        }
        assert payload["Umask"] == 0o77
