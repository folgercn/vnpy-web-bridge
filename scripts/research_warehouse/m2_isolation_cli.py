"""Thin CLI for M2 Research Warehouse isolation verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import RegistryError
from .m2_verifier import verify_m2_isolation_files
from .timeutil import parse_utc


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
        result = verify_m2_isolation_files(
            policy_path=args.policy,
            deployment_directory=args.deployment_dir,
            evidence_path=args.evidence,
            expected_evidence_raw_sha256=args.expected_evidence_sha256,
            release_root=args.release_root,
            release_tree_manifest_path=args.release_tree_manifest,
            expected_release_tree_manifest_raw_sha256=(
                args.expected_release_tree_manifest_sha256
            ),
            success_output_path=args.success_output,
            expected_success_output_raw_sha256=(args.expected_success_output_sha256),
            now=parse_utc(args.now, "M2 isolation verification now"),
        )
    except RegistryError as exc:
        print(f"M2 isolation verification failed closed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0
