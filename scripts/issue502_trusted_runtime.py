"""Explicit isolated inputs for the existing Stage 2 round runners.

Source verification is offline and happens before constructing the Provider.
This module neither registers projects nor changes shared Desktop state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from research_lab.agent_control.errors import ProviderError, ProviderErrorCode
from research_lab.agent_control.transports.local_mcp import LocalMCPTransport
from research_lab.alpha_discovery.real_source_time import verify_shfe_settlement_days

PROVENANCE_SHA256 = "e3d6b6b74d8b6617455bcccf7d6eeed3e4f5fbfe8eca1216f40ad03006725354"


def validate_run_id(value: str) -> str:
    if not value or value != value.strip() or "/" in value or "\\" in value or value in {".", ".."} or "\0" in value:
        raise ValueError("run-id must be one nonempty directory name")
    return value


def parse_mcp_command(value: str) -> list[str]:
    try:
        command = json.loads(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("mcp-command must be a JSON argv array") from exc
    if (not isinstance(command, list) or not command
            or any(not isinstance(arg, str) or not arg for arg in command)
            or command[-2:] != ["--transport", "stdio"]):
        raise argparse.ArgumentTypeError("mcp-command must explicitly select --transport stdio")
    return command


def add_trusted_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--evidence-root", type=Path, required=True,
                        help="Read-only reviewed private source directory")
    parser.add_argument("--output-root", type=Path, required=True,
                        help="Isolated root for new runs; never the source directory")
    parser.add_argument("--preflight-only", action="store_true",
                        help="Verify reviewed sources offline, without Provider or scientific writes")
    parser.add_argument("--mcp-command", type=parse_mcp_command, required=True,
                        help="JSON argv for installed FastMCP, ending with --transport stdio")


def trusted_inputs(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    source = args.evidence_root.resolve()
    output = args.output_root.resolve()
    # Reject nesting in either direction, including symlink aliases.
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("Source and output roots must be disjoint")
    if source == repo.resolve() or source in repo.resolve().parents:
        raise ValueError("The private evidence root must not contain the checkout")
    provenance = source / "snapshot-provenance.json"
    raw = provenance.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA256:
        raise ValueError("Reviewed provenance SHA256 changed")
    days = json.loads(raw)["source_days"]
    bundle = source / "pit-source-final-20260930"
    rules = source / "pit-official-20260930"
    verified = verify_shfe_settlement_days(days, bundle_root=bundle, official_rules_root=rules)
    if len(verified) != 19:
        raise ValueError("Reviewed source must contain 19 verified trading days")
    base = source / "rb-hc-2701-pit-screening-20260831-20260924.csv"
    if not base.is_file():
        raise FileNotFoundError(base)
    return {"provenance": provenance, "base_csv": base, "output": output,
            "binding": {"provenance_path": str(provenance),
                        "provenance_sha256": PROVENANCE_SHA256,
                        "real_source_bundle_root": str(bundle),
                        "official_rules_root": str(rules)}}


def make_transport(command: list[str]) -> LocalMCPTransport:
    return LocalMCPTransport(command=command, connection_profile_ref="antigravity-local-desktop")


def require_project(transport: LocalMCPTransport, repo: Path, project_id: str) -> dict:
    response = transport.call_tool("projects", {"cwd": str(repo.resolve())})
    project = response.get("project") if isinstance(response, dict) else None
    if (not isinstance(project, dict) or project.get("project_id") != project_id
            or project.get("name") != "vnpy" or project.get("cwd") != str(repo.resolve())):
        raise RuntimeError("Actual isolated checkout is not registered to the exact vnpy project")
    return project


def wait_owned_job(transport: LocalMCPTransport, job_id: str, *, max_updates: int = 6) -> None:
    """Observe the same owned job; timeout never submits, cancels or retries it."""
    cursor = 0
    for _ in range(max_updates):
        response = transport.call_tool("watch", {"job_id": job_id, "cursor": cursor,
                                                  "timeout_seconds": 60}, timeout_seconds=70)
        if not isinstance(response, dict):
            raise RuntimeError("Invalid watch response; preserve the same job for recovery")
        resume = response.get("resume", {})
        cursor = resume.get("cursor", response.get("cursor", cursor))
        if response.get("status") in {"completed", "failed", "cancelled", "worker_lost"}:
            return
    raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN,
                        f"Job {job_id} is not terminal; recover this job without resubmission")


def bind_run_root(root: Path, inputs: dict[str, Any], repo: Path, *, create: bool) -> None:
    """Exclude historical pre-verification runs from resume and Round 2 inputs."""
    marker = root / "trusted-source-binding.json"
    expected = {"schema": "issue502.trusted-source-run.v1", "checkout": str(repo.resolve()),
                "binding": inputs["binding"]}
    if create:
        with marker.open("x", encoding="utf-8") as stream:
            json.dump(expected, stream, sort_keys=True, indent=2)
    elif json.loads(marker.read_text(encoding="utf-8")) != expected:
        raise ValueError("Existing run belongs to different source inputs or checkout")
