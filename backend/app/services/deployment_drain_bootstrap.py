"""Create fresh deployment-drain custody in a frozen state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--confirm-offline-trading-disabled",
        action="store_true",
        help="confirm web-bridge is stopped and trading is disabled",
    )
    args = parser.parse_args()
    if not args.confirm_offline_trading_disabled:
        parser.error("--confirm-offline-trading-disabled is required")
    if not args.operator.strip() or not args.reason.strip():
        parser.error("non-empty --operator and --reason are required")

    try:
        service = DeploymentDrainService(
            args.state_root,
            runtime_instance_id="bootstrap-frozen-runtime",
            allow_initial_bootstrap=True,
            initial_bootstrap_state="RESTARTED_FROZEN",
            require_fresh_bootstrap=True,
        )
        status = service.status()
    except (DeploymentDrainError, OSError, ValueError) as exc:
        print(f"deployment-drain bootstrap blocked: {exc}", file=sys.stderr)
        return 2
    evidence = {
        "schema_version": "web_bridge_deployment_drain_bootstrap_v1",
        "state": status["state"],
        "drain_epoch": status["drain_epoch"],
        "execution_epoch": status["execution_epoch"],
        "operator": args.operator,
        "reason": args.reason,
        "production_allowed": False,
        "live_trading_authorized": False,
    }
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
