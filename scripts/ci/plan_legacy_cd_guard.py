#!/usr/bin/env python3
"""Produce an inert, fail-closed plan while legacy CD is frozen."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "docs/architecture/web-bridge-release-dependencies-v1.json"
SCHEMA_PATH = ROOT / "docs/schemas/web-bridge-legacy-cd-guard-plan-v1.schema.json"
SOURCE_SHA = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
PRESERVE_UNITS = ["postgres", "questdb", "web-bridge"]


def _specificity(rule: dict[str, Any], path: str) -> tuple[int, int] | None:
    match = rule["match"]
    candidates: list[tuple[int, int]] = []
    if path in match.get("exact", []):
        candidates.append((3, len(path)))
    candidates.extend(
        (2, len(pattern.replace("*", "")))
        for pattern in match.get("glob", [])
        if fnmatch.fnmatchcase(path, pattern)
    )
    candidates.extend(
        (1, len(prefix))
        for prefix in match.get("prefix", [])
        if path.startswith(prefix)
    )
    return max(candidates, default=None)


def _selected_rules(
    manifest: dict[str, Any], path: str
) -> list[dict[str, Any]]:
    scored = [
        (score, rule)
        for rule in manifest["path_rules"]
        if (score := _specificity(rule, path)) is not None
    ]
    if not scored:
        return []
    highest = max(score for score, _ in scored)
    return [rule for score, rule in scored if score == highest]


def create_plan(
    paths: list[str],
    *,
    source_commit_sha: str,
    manifest: dict[str, Any],
    baseline_known: bool = True,
) -> dict[str, Any]:
    if not SOURCE_SHA.fullmatch(source_commit_sha):
        raise ValueError("source_commit_sha must be a non-zero 40-character SHA")

    changed_paths = sorted({path.strip() for path in paths if path.strip()})
    selected_rule_ids: set[str] = set()
    build_units: set[str] = set()
    blockers: list[dict[str, str | None]] = []
    saw_build_only = False

    if not baseline_known:
        blockers.append(
            {"path": "<baseline>", "code": "unknown_baseline", "rule_id": None}
        )

    if not changed_paths:
        blockers.append(
            {"path": "<empty>", "code": "empty_change_set", "rule_id": None}
        )

    for path in changed_paths:
        selected = _selected_rules(manifest, path)
        if not selected:
            blockers.append(
                {"path": path, "code": "unknown_path", "rule_id": None}
            )
            continue
        if len(selected) != 1:
            blockers.append(
                {"path": path, "code": "ambiguous_rule", "rule_id": None}
            )
            continue

        rule = selected[0]
        rule_id = rule["id"]
        selected_rule_ids.add(rule_id)
        classification = rule["classification"]
        if classification == "infra_manual":
            intents = rule.get("pre_activation_build_units") or rule["build_units"]
            build_units.update(
                unit for unit in intents if not unit.startswith("closure_derived_")
            )
            blockers.append(
                {"path": path, "code": "infra_manual", "rule_id": rule_id}
            )
            continue
        if classification == "build_only":
            saw_build_only = True
            intents = rule.get("pre_activation_build_units") or rule["build_units"]
            unresolved = [
                unit for unit in intents if unit.startswith("closure_derived_")
            ]
            if unresolved:
                blockers.append(
                    {
                        "path": path,
                        "code": "unknown_dependency",
                        "rule_id": rule_id,
                    }
                )
                continue
            build_units.update(intents)

    if blockers:
        decision = "BLOCKED"
    elif saw_build_only:
        decision = "BUILD_ONLY"
    else:
        decision = "NO_DEPLOY"

    return {
        "schema_version": "web_bridge_legacy_cd_guard_plan_v1",
        "issue_number": 267,
        "source_commit_sha": source_commit_sha,
        "changed_paths": changed_paths,
        "selected_rule_ids": sorted(selected_rule_ids),
        "decision": decision,
        "build_units": sorted(build_units),
        "restart_units": [],
        "preserve_units": PRESERVE_UNITS,
        "blocked_reasons": blockers,
        "merge_gate_blocked": any(
            blocker["code"]
            in {"empty_change_set", "unknown_baseline", "unknown_path", "ambiguous_rule"}
            for blocker in blockers
        ),
        "automatic_deploy_allowed": False,
        "manual_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths-file", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument(
        "--baseline-status", choices=("known", "unknown"), default="known"
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    paths = Path(args.paths_file).read_text(encoding="utf-8").splitlines()
    plan = create_plan(
        paths,
        source_commit_sha=args.source_commit_sha.lower(),
        manifest=manifest,
        baseline_known=args.baseline_status == "known",
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(plan)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(plan, sort_keys=True))
    return 1 if plan["merge_gate_blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
