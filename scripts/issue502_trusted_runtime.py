"""Explicit isolated inputs for the existing Stage 2 round runners.

Source verification is offline and happens before constructing the Provider.
This module neither registers projects nor changes shared Desktop state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from research_lab.agent_control.contracts import _clean_for_canonical
from research_lab.agent_control.errors import ProviderError, ProviderErrorCode
from research_lab.agent_control.transports.local_mcp import LocalMCPTransport
from research_lab.alpha_discovery.real_source_time import verify_shfe_settlement_days
from research_lab.alpha_discovery.research_memory import ReadOnlyResearchMemoryReader
from scripts.issue502_feedback_lineage import verify_r1_scientific_lineage

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


def wait_owned_job(transport: LocalMCPTransport, job_id: str, *, max_updates: int = 6,
                   state_path: Path | None = None) -> None:
    """Keep a durable cursor even when a notification precedes a lost response."""
    cursor = 0
    if state_path is not None and state_path.exists():
        state = json.loads(state_path.read_text())
        if state.get("job_id") != job_id or type(state.get("cursor")) is not int or state["cursor"] < 0:
            raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN, "Invalid owned watch checkpoint")
        cursor = state["cursor"]

    def save_cursor(value: Any) -> None:
        nonlocal cursor
        if type(value) is not int or value < cursor:
            raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN, "Invalid/regressed watch cursor")
        cursor = value
        if state_path is not None:
            # Atomic replacement keeps the previous cursor intact on a failed write.
            write_json_atomic(state_path, {"job_id": job_id, "cursor": cursor})

    def notification(message: dict) -> None:
        data = message.get("params", {}).get("data")
        if isinstance(data, dict) and data.get("job_id") == job_id and "cursor" in data:
            save_cursor(data["cursor"])

    try:
        for _ in range(max_updates):
            response = transport.call_tool("watch", {"job_id": job_id, "cursor": cursor,
                                                      "timeout_seconds": 60}, timeout_seconds=70,
                                           on_notification=notification)
            if not isinstance(response, dict):
                raise ValueError("Invalid watch response")
            resume = response.get("resume", {})
            if not isinstance(resume, dict) or resume.get("job_id", job_id) != job_id:
                raise ValueError("Watch response belongs to another job")
            save_cursor(resume.get("cursor", response.get("cursor", cursor)))
            if response.get("status") in {"completed", "failed", "cancelled", "worker_lost"}:
                return
    except Exception as exc:
        raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN,
                            f"Observation unresolved for job {job_id} at cursor {cursor}") from exc
    raise ProviderError(ProviderErrorCode.EXECUTION_UNCERTAIN,
                        f"Job {job_id} is not terminal at cursor {cursor}; recover without resubmission")


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


def verify_r1_feedback_view(view: Any, persisted: dict, evidence: dict, store: Any, *,
                            memory_reader: Any = None) -> None:
    """Bind the next session to verified receipts and this R1's full controlled view."""
    observed = view.to_dict()
    expected = dict(persisted)
    observed.pop("generated_at", None)
    expected.pop("generated_at", None)
    if _clean_for_canonical(observed) != _clean_for_canonical(expected):
        raise ValueError("Memory View B differs from this completed R1 snapshot")
    summary = evidence["post_r1_memory_view"]
    for name, value in (("view_id", view.view_id), ("content_hash", view.view_content_hash),
                        ("total_entries", view.total_entries)):
        if summary.get(name) != value:
            raise ValueError("R1 evidence and controlled Memory View disagree")
    if evidence.get("round") != 1 or evidence.get("funnel", {}).get("requested") != 10:
        raise ValueError("Memory feedback must originate from this R1 ten-slot batch")
    slots = evidence.get("slots", [])
    if sorted(slot.get("ordinal", -1) for slot in slots) != list(range(1, 11)):
        raise ValueError("R1 per-slot provenance is incomplete")
    if any(slot.get("engineering_status") == "PROVIDER_UNCERTAIN" for slot in slots):
        raise ValueError("R1 contains unresolved Provider ownership")
    integrations = evidence.get("integrations", [])
    if not integrations:
        raise ValueError("R1 has no verified scientific integrations")
    verify_r1_scientific_lineage(
        evidence, memory_reader or ReadOnlyResearchMemoryReader(store.config.database_path), store
    )


def write_json_atomic(path: Path, payload: Any) -> None:
    """Keep the previous ownership record when an accepted-handle write fails."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
