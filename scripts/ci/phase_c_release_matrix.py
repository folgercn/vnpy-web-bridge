#!/usr/bin/env python3
"""Create the Issue #291 Phase C build-only release matrix.

This is deliberately a planner, not a deployer.  It joins the already
reviewed Phase A and Phase B dependency classifiers, preserves their
fail-closed behaviour, and emits the exact independent image units that CI
may build and smoke.  OCI digests are deliberately absent at planning time:
each selected unit must produce a separately schema-validated build receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CLASSIFIER_PATH = ROOT / "scripts/ci/classify_changes.py"
PLAN_SCHEMA_PATH = ROOT / "docs/schemas/issue-291-phase-c-release-matrix-v1.schema.json"
SOURCE_SHA = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")


def _load_classifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase_c_classifier", CLASSIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load classifier: {CLASSIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_classifier = _load_classifier()

# A shared proxy Containerfile is deliberately represented twice: request and
# publish are distinct runtime units and each receives its own smoke/receipt.
UNIT_METADATA: dict[tuple[str, str], dict[str, Any]] = {
    ("A", "frontend-edge"): {
        "containerfile": "frontend/Containerfile",
        "image_repository": "vnpy-web-bridge-frontend",
        "smoke_profile": "frontend",
    },
    ("A", "control-api"): {
        "containerfile": "deployments/phase-a/Containerfile.control-api",
        "image_repository": "vnpy-web-bridge-control-api",
        "smoke_profile": "control-api",
    },
    ("A", "execution-orchestrator"): {
        "containerfile": "deployments/phase-a/Containerfile.execution-orchestrator",
        "image_repository": "vnpy-web-bridge-execution",
        "smoke_profile": "execution-orchestrator",
    },
    ("A", "gateway-rpc-request-proxy"): {
        "containerfile": "deployments/phase-a/Containerfile.gateway-proxy",
        "image_repository": "vnpy-web-bridge-gateway-proxy",
        "smoke_profile": "gateway-request-proxy",
    },
    ("A", "gateway-rpc-publish-proxy"): {
        "containerfile": "deployments/phase-a/Containerfile.gateway-proxy",
        "image_repository": "vnpy-web-bridge-gateway-proxy",
        "smoke_profile": "gateway-publish-proxy",
    },
    ("B", "artifact-custody"): {
        "containerfile": "deployments/phase-b/Containerfile.artifact-custody",
        "image_repository": "vnpy-web-bridge-artifact-custody",
        "smoke_profile": "artifact-custody",
    },
    ("B", "c-fast-producer"): {
        "containerfile": "deployments/phase-b/Containerfile.c-fast-producer",
        "image_repository": "vnpy-web-bridge-c-fast-producer",
        "smoke_profile": "batch-producer",
    },
    ("B", "execution-quality-worker"): {
        "containerfile": "deployments/phase-b/Containerfile.execution-quality-worker",
        "image_repository": "vnpy-web-bridge-execution-quality-worker",
        "smoke_profile": "execution-quality-worker",
    },
    ("B", "map-producer"): {
        "containerfile": "deployments/phase-b/Containerfile.map-producer",
        "image_repository": "vnpy-web-bridge-map-producer",
        "smoke_profile": "batch-producer",
    },
    ("B", "market-data-worker"): {
        "containerfile": "deployments/phase-b/Containerfile.market-data-worker",
        "image_repository": "vnpy-web-bridge-market-data-worker",
        "smoke_profile": "market-data-worker",
    },
    ("B", "monitor-worker"): {
        "containerfile": "deployments/phase-b/Containerfile.monitor-worker",
        "image_repository": "vnpy-web-bridge-monitor-worker",
        "smoke_profile": "monitor-worker",
    },
    ("B", "signing-authority"): {
        "containerfile": "deployments/phase-b/Containerfile.signing-authority",
        "image_repository": "vnpy-web-bridge-signing-authority",
        "smoke_profile": "signing-authority",
    },
}

# Changes to the matrix/receipt contract are a shared release concern.  They
# must exercise every isolated image rather than silently relying on stale
# matrix behaviour.  This is intentionally narrow; arbitrary docs remain
# contract-only and unknown source paths still block.
PHASE_C_WORKFLOW_EXACT = (
    "backend/app/phase_c_custody.py",
    "backend/app/phase_c_execution.py",
    "deployments/phase-c/Containerfile.custody",
    "deployments/phase-c/Containerfile.execution",
    "deployments/phase-c/docker-compose.offline-e2e.yml",
    "backend/app/execution/final_runtime.py",
    "deployments/docker-compose.final.yml",
    "scripts/ci/final_runtime_compose_smoke.sh",
    "backend/tests/unit/test_issue291_final_execution.py",
    "backend/tests/unit/test_issue291_final_runtime_integration.py",
    "scripts/simnow_run_once.py",
)
PHASE_C_SHARED_EXACT = (
    "deployments/phase-b/Containerfile.artifact-custody",
    "scripts/ci/final_runtime_compose_smoke.sh",
)
PHASE_C_SHARED_PREFIXES = (
    "scripts/ci/phase_c_",
    "scripts/phase_c_faults/",
    "docs/architecture/issue-291-phase-c-release-",
    "docs/architecture/issue-291-phase-c-fault-",
    "docs/schemas/issue-291-phase-c-release-",
    "docs/schemas/issue-291-phase-c-image-",
    "docs/schemas/issue-291-phase-c-fault-",
    "shared/commodity_execution/",
    "scripts/phase_b_workers/",
    "deployments/final/",
)
PHASE_C_WORKFLOW_PREFIXES = (
    "backend/app/api/routes_phase_c_",
    "backend/app/phase_c/",
    "backend/tests/unit/test_issue291_phase_c_",
    "docs/architecture/issue-291-phase-c-workflow-",
    "docs/schemas/issue-291-phase-c-authorization-",
    "docs/schemas/issue-291-phase-c-signing-",
    "shared/phase_c_workflow/",
)
# These workers form the fresh-volume projection chain.  A selected producer
# or consumer must be verified with its real dependent services, while the
# independent matrix still handles all selected images separately.
PHASE_B_PROJECTION_UNITS = frozenset(
    {
        "artifact-custody",
        "market-data-worker",
        "execution-quality-worker",
        "monitor-worker",
    }
)


def _sha256_json(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _unit(
    phase: str, unit: str, verification_units: list[str], source_sha: str
) -> dict[str, Any]:
    metadata = UNIT_METADATA.get((phase, unit))
    if metadata is None:
        raise ValueError(f"unknown Phase {phase} matrix unit: {unit}")
    containerfile = str(metadata["containerfile"])
    repository = str(metadata["image_repository"])
    return {
        "phase": phase,
        "unit": unit,
        "containerfile": containerfile,
        "containerfile_exists": (ROOT / containerfile).is_file(),
        "image_repository": repository,
        "image_tag": f"issue-291-phase-c-{source_sha}-{unit}",
        "image_ref": f"{repository}:issue-291-phase-c-{source_sha}-{unit}",
        "smoke_profile": str(metadata["smoke_profile"]),
        "verification_units": sorted(set(verification_units)),
        "compose_file": (
            "deployments/docker-compose.phase-a.yml"
            if phase == "A"
            else "deployments/docker-compose.phase-b.yml"
        ),
        "immutable_oci_digest_required": True,
        "build_receipt_required": True,
        "rollback_identity": "build_receipt_pinned_oci_digest_only",
        "rollback_receipt_required": True,
        "deploy_allowed": False,
    }


def _phase_c_shared(paths: list[str]) -> bool:
    return any(
        path in PHASE_C_SHARED_EXACT or path.startswith(PHASE_C_SHARED_PREFIXES)
        for path in paths
    )


def _phase_c_workflow(paths: list[str]) -> bool:
    return any(
        path in PHASE_C_WORKFLOW_EXACT or path.startswith(PHASE_C_WORKFLOW_PREFIXES)
        for path in paths
    )


def _add_canonical_workflow_closure(
    phase_a: dict[str, Any], phase_b: dict[str, Any]
) -> None:
    """Select existing service owners; Phase C creates no deployment unit."""

    canonical_a = _classifier.classify_phase_a(
        ["backend/app/control_api.py", "backend/app/execution_orchestrator.py"]
    )
    canonical_b = _classifier.classify_phase_b(
        ["deployments/phase-b/Containerfile.artifact-custody"]
    )
    phase_a["selected_units"] = sorted(
        set(phase_a["selected_units"]) | set(canonical_a["selected_units"])
    )
    phase_a["dependency_closure"] = sorted(
        set(phase_a["dependency_closure"]) | set(canonical_a["dependency_closure"])
    )
    phase_a["verification_units"] = sorted(
        set(phase_a["verification_units"]) | set(canonical_a["verification_units"])
    )
    phase_b["selected_units"] = sorted(
        set(phase_b["selected_units"]) | set(canonical_b["selected_units"])
    )


def create_plan(
    paths: list[str],
    *,
    source_commit_sha: str,
    baseline_known: bool = True,
    force_all: bool = False,
) -> dict[str, Any]:
    """Return a schema-valid build-only Phase C plan for A+B closures."""

    source_commit_sha = source_commit_sha.strip().lower()
    if not SOURCE_SHA.fullmatch(source_commit_sha):
        raise ValueError("source_commit_sha must be a non-zero 40-character SHA")

    normalised = sorted({_classifier._normalise_change_path(path) for path in paths})
    changed_paths = [path for path in normalised if path]
    shared = force_all or _phase_c_shared(changed_paths)
    workflow = _phase_c_workflow(changed_paths)
    phase_a = _classifier.classify_phase_a(changed_paths, force_all=shared)
    phase_b = _classifier.classify_phase_b(changed_paths, force_all=shared)
    if workflow and not shared:
        _add_canonical_workflow_closure(phase_a, phase_b)

    blocked_reasons: list[dict[str, Any]] = []
    if not baseline_known:
        blocked_reasons.append(
            {
                "phase": "C",
                "path": "<baseline>",
                "code": "unknown_baseline",
                "rule_ids": [],
            }
        )
    if not changed_paths and not force_all:
        blocked_reasons.append(
            {
                "phase": "C",
                "path": "<empty>",
                "code": "empty_change_set",
                "rule_ids": [],
            }
        )
    for phase, result in (("A", phase_a), ("B", phase_b)):
        for reason in result["blocked_reasons"]:
            blocked_reasons.append({"phase": phase, **dict(reason)})

    units: list[dict[str, Any]] = []
    for unit in phase_a["dependency_closure"]:
        units.append(
            _unit(
                "A", str(unit), list(phase_a["verification_units"]), source_commit_sha
            )
        )
    for unit in phase_b["selected_units"]:
        units.append(_unit("B", str(unit), [], source_commit_sha))
    for item in units:
        if not item["containerfile_exists"]:
            blocked_reasons.append(
                {
                    "phase": item["phase"],
                    "path": item["containerfile"],
                    "code": "missing_containerfile",
                    "rule_ids": [],
                    "unit": item["unit"],
                }
            )

    phase_b_projection_required = bool(
        PHASE_B_PROJECTION_UNITS.intersection(phase_b["selected_units"])
    )

    decision = (
        "BLOCKED" if blocked_reasons else ("BUILD_ONLY" if units else "CONTRACT_ONLY")
    )
    plan_core = {
        "schema_version": "web_bridge_issue_291_phase_c_release_matrix_v1",
        "issue_number": 291,
        "phase": "C",
        "source_commit_sha": source_commit_sha,
        "changed_paths": changed_paths,
        "phase_a": {
            "selected_rule_ids": phase_a["selected_rule_ids"],
            "selected_units": phase_a["selected_units"],
            "dependency_closure": phase_a["dependency_closure"],
            "blocked": bool(phase_a["blocked_reasons"]),
        },
        "phase_b": {
            "selected_rule_ids": phase_b["selected_rule_ids"],
            "selected_units": phase_b["selected_units"],
            "blocked": bool(phase_b["blocked_reasons"]),
        },
        "phase_b_projection_required": phase_b_projection_required,
        "offline_e2e_required": shared or workflow,
        "decision": decision,
        "build_units": units,
        "blocked_reasons": blocked_reasons,
        "automatic_deploy_allowed": False,
        "manual_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "deployed": False,
        "accepted": False,
    }
    return {"plan_id": f"phase-c-{_sha256_json(plan_core)}", **plan_core}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths-file", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument(
        "--baseline-status", choices=("known", "unknown"), default="known"
    )
    parser.add_argument("--force-all", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--github-output")
    args = parser.parse_args(argv)
    plan = create_plan(
        Path(args.paths_file).read_text(encoding="utf-8").splitlines(),
        source_commit_sha=args.source_commit_sha,
        baseline_known=args.baseline_status == "known",
        force_all=args.force_all,
    )
    Draft202012Validator(
        json.loads(PLAN_SCHEMA_PATH.read_text(encoding="utf-8"))
    ).validate(plan)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.github_output:
        matrix = {"include": plan["build_units"]}
        with Path(args.github_output).open("a", encoding="utf-8") as stream:
            stream.write(
                f"build_required={'true' if plan['decision'] == 'BUILD_ONLY' else 'false'}\n"
            )
            stream.write(
                "build_matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n"
            )
            stream.write(
                f"phase_a_selected={'true' if plan['phase_a']['selected_units'] else 'false'}\n"
            )
            stream.write(
                f"phase_b_selected={'true' if plan['phase_b']['selected_units'] else 'false'}\n"
            )
            stream.write(
                "phase_b_projection_required="
                + ("true" if plan["phase_b_projection_required"] else "false")
                + "\n"
            )
            stream.write(
                "offline_e2e_required="
                + ("true" if plan["offline_e2e_required"] else "false")
                + "\n"
            )
    print(json.dumps(plan, sort_keys=True))
    return 1 if plan["decision"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
