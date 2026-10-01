"""Entry-point regressions only; fixtures do not constitute Provider acceptance."""
import argparse
import hashlib
import json

import pytest

from scripts import issue502_trusted_runtime as runtime


class FakeTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def call_tool(self, operation, arguments, **kwargs):
        self.calls.append((operation, arguments, kwargs))
        return next(self.responses)


@pytest.mark.parametrize("run_id", ["", ".", "..", "a/b", "a\\b", " name", "name ", "a\0b"])
def test_unsafe_run_id(run_id):
    with pytest.raises(ValueError):
        runtime.validate_run_id(run_id)


def test_project_must_match_actual_checkout(tmp_path):
    project = {"project_id": "vnpy-id", "name": "vnpy", "cwd": str(tmp_path)}
    transport = FakeTransport([{"project": project}])
    assert runtime.require_project(transport, tmp_path, "vnpy-id") == project
    assert transport.calls[0][1] == {"cwd": str(tmp_path)}


@pytest.mark.parametrize("patch", [{"cwd": "/other"}, {"name": "gzgs"}, {"project_id": "other"}])
def test_project_mismatch_never_submits(tmp_path, patch):
    project = {"project_id": "vnpy-id", "name": "vnpy", "cwd": str(tmp_path), **patch}
    transport = FakeTransport([{"project": project}])
    with pytest.raises(RuntimeError):
        runtime.require_project(transport, tmp_path, "vnpy-id")
    assert [c[0] for c in transport.calls] == ["projects"]


def test_watch_preserves_job_and_cursor():
    transport = FakeTransport([
        {"status": "running", "resume": {"cursor": 7}},
        {"status": "completed"},
    ])
    runtime.wait_owned_job(transport, "existing-job")
    assert [c[0] for c in transport.calls] == ["watch", "watch"]
    assert [c[1]["cursor"] for c in transport.calls] == [0, 7]
    assert all(c[1]["job_id"] == "existing-job" for c in transport.calls)


def test_watch_timeout_is_uncertain_and_never_resubmits():
    transport = FakeTransport([{"status": "running", "resume": {"cursor": 2}}])
    with pytest.raises(runtime.ProviderError) as error:
        runtime.wait_owned_job(transport, "existing-job", max_updates=1)
    assert error.value.code == runtime.ProviderErrorCode.EXECUTION_UNCERTAIN
    assert [c[0] for c in transport.calls] == ["watch"]


@pytest.mark.parametrize("relative", [".", "nested"])
def test_output_cannot_mutate_source(tmp_path, relative):
    source = tmp_path / "source"
    args = argparse.Namespace(evidence_root=source, output_root=source / relative)
    with pytest.raises(ValueError, match="disjoint"):
        runtime.trusted_inputs(args, tmp_path / "checkout")
    assert not source.exists()


def test_source_verification_runs_before_any_output_write(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    raw = json.dumps({"source_days": [{"day": "2026-08-31"}]}).encode()
    (source / "snapshot-provenance.json").write_bytes(raw)
    (source / "rb-hc-2701-pit-screening-20260831-20260924.csv").write_text("private source")
    monkeypatch.setattr(runtime, "PROVENANCE_SHA256", hashlib.sha256(raw).hexdigest())
    output = tmp_path / "isolated-output"
    observed = []

    def verify(days, **kwargs):
        observed.append((days, kwargs))
        assert not output.exists()
        return {str(i): object() for i in range(19)}

    monkeypatch.setattr(runtime, "verify_shfe_settlement_days", verify)
    result = runtime.trusted_inputs(argparse.Namespace(evidence_root=source, output_root=output), tmp_path / "checkout")
    assert observed[0][1]["bundle_root"] == source / "pit-source-final-20260930"
    assert result["binding"]["official_rules_root"] == str(source / "pit-official-20260930")
    assert not output.exists()


def test_wrong_provenance_blocks_before_source_verifier(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "snapshot-provenance.json").write_text("{}")
    monkeypatch.setattr(runtime, "verify_shfe_settlement_days", lambda *a, **kw: pytest.fail("must not verify"))
    with pytest.raises(ValueError, match="SHA256"):
        runtime.trusted_inputs(argparse.Namespace(evidence_root=source, output_root=tmp_path / "output"), tmp_path / "checkout")


@pytest.mark.parametrize("round_number", [1, 2])
def test_preflight_cli_never_builds_provider_or_output(tmp_path, monkeypatch, round_number, capsys):
    import importlib
    import sys

    runner = importlib.import_module(f"scripts.run_stage2_universal_round{round_number}_real")
    output = tmp_path / "output"
    monkeypatch.setattr(runner, "trusted_inputs", lambda args, repo: {})
    monkeypatch.setattr(runner, "make_transport", lambda *args: pytest.fail("no Provider in offline preflight"))
    monkeypatch.setattr(sys, "argv", ["runner", "--run-id", "unique", "--evidence-root", str(tmp_path / "source"),
                                     "--output-root", str(output), "--mcp-command", '["installed-mcp", "--transport", "stdio"]', "--preflight-only"])
    runner.main()
    result = json.loads(capsys.readouterr().out)
    assert result["stage2_accepted"] is False
    assert result["provider_submissions"] == 0
    assert result["checkout"] == str(runner.REPO)
    assert not output.exists()


@pytest.mark.parametrize("command", ['"shell command"', '[]', '["agy-mcp"]', '["agy-mcp", "--transport", "sse"]'])
def test_mcp_command_cannot_start_implicit_network_transport(command):
    with pytest.raises(argparse.ArgumentTypeError):
        runtime.parse_mcp_command(command)



def test_historical_runs_cannot_resume_as_verified(tmp_path):
    inputs = {"binding": {"provenance_sha256": "reviewed"}}
    with pytest.raises(FileNotFoundError):
        runtime.bind_run_root(tmp_path, inputs, tmp_path, create=False)
    runtime.bind_run_root(tmp_path, inputs, tmp_path, create=True)
    runtime.bind_run_root(tmp_path, inputs, tmp_path, create=False)
    with pytest.raises(FileExistsError):
        runtime.bind_run_root(tmp_path, inputs, tmp_path, create=True)
    with pytest.raises(ValueError):
        runtime.bind_run_root(tmp_path, {"binding": {"provenance_sha256": "changed"}}, tmp_path, create=False)
