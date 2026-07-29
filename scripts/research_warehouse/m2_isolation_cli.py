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
    load_isolation_evidence,
    load_isolation_policy,
)
from .timeutil import parse_utc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--policy", type=Path, required=True)
    result.add_argument("--deployment-dir", type=Path, required=True)
    result.add_argument("--evidence", type=Path, required=True)
    result.add_argument("--expected-evidence-sha256", required=True)
    result.add_argument("--now", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = load_isolation_policy(args.policy)
        assets = verify_deployment_assets(
            args.deployment_dir,
            policy=policy,
        )
        evidence = load_isolation_evidence(
            args.evidence,
            expected_raw_sha256=args.expected_evidence_sha256,
        )
        result = verify_isolation_evidence(
            evidence,
            policy=policy,
            now=parse_utc(args.now, "M2 isolation verification now"),
        )
    except RegistryError as exc:
        print(f"M2 isolation verification failed closed: {exc}", file=sys.stderr)
        return 1
    result["deployment_assets"] = assets
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0
