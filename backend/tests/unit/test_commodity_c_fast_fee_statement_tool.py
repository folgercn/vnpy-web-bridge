from __future__ import annotations

import argparse
import importlib.util
import stat
import sys
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "commodity_c_fast_fee_statement_verify.py"
SPEC = importlib.util.spec_from_file_location("c_fast_fee_statement_tool", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class _Dumpable:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        assert mode == "json"
        return self.payload


def test_main_wires_offline_verifiers_and_create_only_canonical_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = (tmp_path / "fee-bound-v5.json").resolve()
    archive_target = (tmp_path / "archive-target.json").resolve()
    archive_target.write_text("{}", encoding="utf-8")
    archive_link = (tmp_path / "archive-link.json").resolve()
    archive_link.symlink_to(archive_target)
    args = argparse.Namespace(
        archive_facts=archive_link,
        archive_facts_raw_sha256="1" * 64,
        fee_statement=(tmp_path / "statement.json").resolve(),
        fee_statement_raw_sha256="2" * 64,
        fee_source_document=(tmp_path / "source.pdf").resolve(),
        output=output,
    )
    archive = _Dumpable({"schema_version": "settled-archive-test"})
    evidence = _Dumpable({"schema_version": "fee-evidence-test"})
    actual_payload = {
        "schema_version": "commodity_c_fast_actual_simnow_facts_v5",
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
    }
    settings = object()
    trust_context = object()
    calls: dict[str, Any] = {}

    monkeypatch.setattr(TOOL, "parse_args", lambda: args)
    monkeypatch.setattr(TOOL, "Settings", lambda: settings)

    def load_archive(**kwargs: Any) -> _Dumpable:
        calls["archive"] = kwargs
        return archive

    def load_fee(**kwargs: Any) -> tuple[_Dumpable, _Dumpable, object]:
        calls["fee"] = kwargs
        return archive, evidence, trust_context

    def build_actual(**kwargs: Any) -> _Dumpable:
        calls["actual"] = kwargs
        return _Dumpable(actual_payload)

    monkeypatch.setattr(TOOL, "load_settled_archive_replay_facts", load_archive)
    monkeypatch.setattr(
        TOOL,
        "load_and_verify_late_fee_correction_from_settings",
        load_fee,
    )
    monkeypatch.setattr(
        TOOL,
        "build_actual_simnow_fee_bound_source_facts",
        build_actual,
    )

    assert TOOL.main() == 0
    assert output.read_bytes() == TOOL.canonical_json_bytes(actual_payload)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert calls["archive"] == {
        "path": args.archive_facts,
        "expected_raw_sha256": "1" * 64,
    }
    assert calls["fee"]["settings"] is settings
    assert calls["fee"]["archive_replay"] is archive
    assert "verified_at_utc" not in calls["fee"]
    assert "trusted_keyring_path" not in calls["fee"]
    assert calls["actual"] == {
        "archive_replay": archive,
        "fee_binding": evidence.payload,
        "fee_binding_trust_context": trust_context,
    }

    with pytest.raises(FileExistsError):
        TOOL.main()


def test_create_only_output_never_follows_existing_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"original")
    output = tmp_path / "output.json"
    output.symlink_to(target)

    with pytest.raises(FileExistsError):
        TOOL._write_create_only(output, b"replacement")

    assert target.read_bytes() == b"original"


def test_lexical_absolute_rejects_relative_without_resolving() -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        TOOL._lexical_absolute(Path("relative.json"))


@pytest.mark.parametrize("kind", ["relative", "missing_parent"])
def test_create_only_output_rejects_unsafe_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    if kind == "relative":
        path = Path("relative-fee-evidence.json")
    else:
        path = (tmp_path / "missing" / "fee-evidence.json").resolve()
    with pytest.raises(ValueError, match="output must be absolute"):
        TOOL._write_create_only(path, b"{}")

    assert not path.exists()


@pytest.mark.parametrize(
    "forbidden",
    ["--verified-at-utc", "--fee-keyring", "--fee-keyring-raw-sha256"],
)
def test_cli_rejects_caller_controlled_trust_inputs(
    monkeypatch: pytest.MonkeyPatch,
    forbidden: str,
) -> None:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), forbidden, "attacker"])

    with pytest.raises(SystemExit):
        TOOL.parse_args()
