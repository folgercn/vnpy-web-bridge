#!/usr/bin/env python3
"""Create a dependency-aware, non-deploying Issue #291 Phase A plan.

The planner consumes the independent Phase A classifier rather than the old
Issue #267 monolith guard.  It can therefore build one of the three primary
images in isolation, while shared typed contracts and the execution dependency
closure expand to every actual image consumer.
Every plan remains build/test-only: production, deployment and live trading
are explicit false values even when a path is classified as infrastructure or
execution-sensitive.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CLASSIFIER_PATH = ROOT / "scripts/ci/classify_changes.py"


def _load_classifier_dependency() -> ModuleType:
    """Load the sibling classifier without depending on cwd or PYTHONPATH."""

    spec = importlib.util.spec_from_file_location(
        "phase_a_change_classifier", CLASSIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Phase A classifier: {CLASSIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_classifier = _load_classifier_dependency()
PHASE_A_UNIT_METADATA = _classifier.PHASE_A_UNIT_METADATA
classify_phase_a = _classifier.classify_phase_a

PLAN_SCHEMA_PATH = ROOT / "docs/schemas/issue-291-phase-a-release-plan-v1.schema.json"
SOURCE_SHA = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
ROOT_DOCKERFILE_FORBIDDEN_MARKERS = (
    "frontend/dist",
    "frontend-build",
    "COPY --from=frontend",
    "npm ci",
    "npm run build",
)


def _static_contract_reasons(
    changed_paths: list[str], *, static_contents: Mapping[str, str] | None = None
) -> list[dict[str, Any]]:
    """Reject a root image that regresses into the frontend/monolith image."""

    if "Dockerfile" not in changed_paths:
        return []
    if static_contents is not None and "Dockerfile" in static_contents:
        content = static_contents["Dockerfile"]
    else:
        dockerfile = ROOT / "Dockerfile"
        if not dockerfile.is_file():
            return [
                {
                    "path": "Dockerfile",
                    "code": "static_contract_unavailable",
                    "rule_ids": ["phase-a-root-dockerfile"],
                }
            ]
        content = dockerfile.read_text(encoding="utf-8")
    markers = [
        marker for marker in ROOT_DOCKERFILE_FORBIDDEN_MARKERS if marker in content
    ]
    if not markers:
        return []
    return [
        {
            "path": "Dockerfile",
            "code": "static_contract_violation",
            "rule_ids": ["phase-a-root-dockerfile"],
            "markers": markers,
        }
    ]


def _unit_plan(unit: str) -> dict[str, Any]:
    metadata = PHASE_A_UNIT_METADATA[unit]
    build_file = str(metadata["build_file"])
    plan = {
        "unit": unit,
        "build_file": build_file,
        "build_file_exists": (ROOT / build_file).is_file(),
        "entrypoint": str(metadata["entrypoint"]),
        "verification_units": sorted(
            str(item) for item in metadata["verification_units"]
        ),
        "deploy_allowed": False,
    }
    if "command" in metadata:
        plan["command"] = str(metadata["command"])
    return plan


def create_plan(
    paths: list[str],
    *,
    source_commit_sha: str,
    baseline_known: bool = True,
    force_all: bool = False,
    static_contents: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a schema-valid plan, blocking on every unresolved dependency."""

    source_commit_sha = source_commit_sha.lower().strip()
    if not SOURCE_SHA.fullmatch(source_commit_sha):
        raise ValueError("source_commit_sha must be a non-zero 40-character SHA")

    classification = classify_phase_a(paths, force_all=force_all)
    changed_paths = list(
        classification.get("changed_paths", paths if not force_all else [])
    )
    blocked_reasons = [dict(item) for item in classification["blocked_reasons"]]
    if not baseline_known:
        blocked_reasons.insert(
            0,
            {"path": "<baseline>", "code": "unknown_baseline", "rule_ids": []},
        )
    if not changed_paths and not force_all:
        blocked_reasons.append(
            {"path": "<empty>", "code": "empty_change_set", "rule_ids": []}
        )

    blocked_reasons.extend(
        _static_contract_reasons(changed_paths, static_contents=static_contents)
    )

    selected_units = list(classification["selected_units"])
    closure_units = list(classification.get("dependency_closure", selected_units))
    units = [_unit_plan(unit) for unit in closure_units]
    for unit in units:
        if not unit["build_file_exists"]:
            blocked_reasons.append(
                {
                    "path": unit["build_file"],
                    "code": "missing_build_file",
                    "rule_ids": [],
                    "unit": unit["unit"],
                }
            )

    verification_units = {str(item) for item in classification["verification_units"]}
    for unit in units:
        verification_units.update(unit["verification_units"])
    if selected_units:
        verification_units.add("phase_a_contract")
    if "execution-orchestrator" in selected_units:
        verification_units.add("execution_safety_review")
    if "phase_a_compose_config" in verification_units:
        verification_units.add("compose_config")

    if blocked_reasons:
        decision = "BLOCKED"
    elif selected_units:
        decision = "BUILD_ONLY"
    else:
        decision = "CONTRACT_ONLY"

    # Do not infer a deployment/restart action from changed source.  A future
    # production release must be a separate reviewed contract and operator
    # authorization, not an extension of this CI evidence plan.
    return {
        "schema_version": "web_bridge_issue_291_phase_a_release_plan_v1",
        "issue_number": 291,
        "phase": "A",
        "source_commit_sha": source_commit_sha,
        "changed_paths": sorted(changed_paths),
        "candidate_rule_ids": sorted(classification["candidate_rule_ids"]),
        "selected_rule_ids": sorted(classification["selected_rule_ids"]),
        "decision": decision,
        "selected_units": selected_units,
        "dependency_closure": {
            "services": units,
            "shared_contract_changed": bool(classification["shared_contract_changed"]),
            "external_artifacts": sorted(
                str(item) for item in classification["external_artifacts"]
            ),
        },
        "external_artifacts": sorted(
            str(item) for item in classification["external_artifacts"]
        ),
        "build_units": units,
        "verification_units": sorted(verification_units),
        "deploy_units": [],
        "restart_units": [],
        "preserve_units": [],
        "execution_safety_required": bool(classification["execution_safety_required"]),
        "blocked_reasons": blocked_reasons,
        "manual_approval_required": bool(blocked_reasons),
        "automatic_deploy_allowed": False,
        "manual_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "deployed": False,
        "accepted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths-file", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument(
        "--baseline-status", choices=("known", "unknown"), default="known"
    )
    parser.add_argument("--force-all", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    paths = Path(args.paths_file).read_text(encoding="utf-8").splitlines()
    plan = create_plan(
        paths,
        source_commit_sha=args.source_commit_sha,
        baseline_known=args.baseline_status == "known",
        force_all=args.force_all,
    )
    schema = json.loads(PLAN_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(plan)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(plan, sort_keys=True))
    return 1 if plan["decision"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
