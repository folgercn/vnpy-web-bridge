"""Thin CLI for M2 Research Warehouse isolation verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import RegistryError
from .m2_deployment_assets import verify_deployment_assets
from .m2_isolation_audit import verify_isolation_evidence
from .m2_isolation_contracts import (
    IsolationPolicy,
    load_isolation_evidence,
    load_isolation_policy,
)
from .m2_release_artifacts import verify_release_artifacts
from .timeutil import parse_utc


def _verified_artifact_paths(
    policy: IsolationPolicy,
    release_root: Path,
    success_output: Path,
) -> tuple[Path, Path]:
    try:
        frozen_release = Path(policy.payload["release_root"]).resolve(strict=True)
        frozen_runtime = Path(policy.payload["runtime_root"]).resolve(strict=True)
        actual_release = release_root.resolve(strict=True)
        actual_output = success_output.resolve(strict=True)
    except OSError as exc:
        raise RegistryError("M2 artifact path is unavailable") from exc
    if (
        actual_release != frozen_release
        or not actual_output.is_relative_to(frozen_runtime)
    ):
        raise RegistryError("M2 artifact path is outside frozen deployment roots")
    return actual_release, actual_output


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--policy", type=Path, required=True)
    result.add_argument("--deployment-dir", type=Path, required=True)
    result.add_argument("--evidence", type=Path, required=True)
    result.add_argument("--expected-evidence-sha256", required=True)
    result.add_argument("--release-root", type=Path, required=True)
    result.add_argument("--release-tree-manifest", type=Path, required=True)
    result.add_argument(
        "--expected-release-tree-manifest-sha256",
        required=True,
    )
    result.add_argument("--success-output", type=Path, required=True)
    result.add_argument("--expected-success-output-sha256", required=True)
    result.add_argument("--now", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = load_isolation_policy(args.policy)
        evidence = load_isolation_evidence(
            args.evidence,
            expected_raw_sha256=args.expected_evidence_sha256,
        )
        identity = evidence.get("identity")
        if (
            not isinstance(identity, dict)
            or isinstance(identity.get("uid"), bool)
            or not isinstance(identity.get("uid"), int)
            or identity["uid"] <= 0
        ):
            raise RegistryError("M2 evidence identity is invalid")
        release_root, success_output = _verified_artifact_paths(
            policy,
            args.release_root,
            args.success_output,
        )
        assets = verify_deployment_assets(
            args.deployment_dir,
            policy=policy,
        )
        release_artifacts = verify_release_artifacts(
            policy=policy,
            release_root=release_root,
            manifest_path=args.release_tree_manifest,
            expected_manifest_raw_sha256=(
                args.expected_release_tree_manifest_sha256
            ),
            output_path=success_output,
            expected_output_raw_sha256=args.expected_success_output_sha256,
            output_owner_uid=identity["uid"],
        )
        result = verify_isolation_evidence(
            evidence,
            policy=policy,
            now=parse_utc(args.now, "M2 isolation verification now"),
            release_artifacts=release_artifacts,
        )
    except RegistryError as exc:
        print(f"M2 isolation verification failed closed: {exc}", file=sys.stderr)
        return 1
    result["deployment_assets"] = assets
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0
