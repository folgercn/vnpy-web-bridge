"""Root-only publisher for one linked daily-roll predecessor catalog entry.

This is the continuation of the Genesis bridge: it reads the same protected
continuous-run configuration, replays the current signed Warehouse root, and
appends only the next linked no-authority artifact.  It has no Execution,
Gateway, Windows, RPC, broker, or network dependency.

Operational order is strict: sign one official day, append that exact current
root, then sign the next day.  For example, after a catalog head at day 19:
manifest-signer day 20 -> linked-publisher -> manifest-signer day 21 ->
linked-publisher.  A later current root cannot bridge an unappended day.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, sha256
from .daily_roll_predecessor_catalog import (
    ProtectedLinkedReplayInputs,
    load_current_catalog_head,
    publish_predecessor_artifact,
)
from .errors import RegistryError
from .m2_genesis_predecessor_cli import _load_projection_as_service, _require_root
from .m2_isolation_contracts import false_authority, load_isolation_policy
from .m2_operator_defaults import DEFAULT_OPERATOR_STATE
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT, load_runtime_input


class LinkedPublisherCliError(RegistryError):
    """The root-only linked publisher must fail closed."""


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    result.add_argument("--operator-state", type=Path, default=DEFAULT_OPERATOR_STATE)
    result.add_argument("--continuous-config", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _require_root()
        policy = load_isolation_policy(args.runtime_input.parent / "isolation-policy-v1.json")
        runtime_input = load_runtime_input(args.runtime_input, policy=policy)
        with operator_state_lock(args.operator_state, exclusive=False):
            state = load_operator_state(args.operator_state)
        projection = _load_projection_as_service(
            config_path=args.continuous_config,
            runtime_input_path=args.runtime_input,
            operator_state_path=args.operator_state,
            service_uid=policy.uid,
            service_gid=policy.gid,
        )
        if projection.runtime_input_raw_sha256 != runtime_input.raw_sha256:
            raise LinkedPublisherCliError("continuous config runtime input pin drifted")
        official_day = state.payload["last_trade_day"]
        if not isinstance(official_day, str):
            raise LinkedPublisherCliError("current root official day is invalid")
        entry = publish_predecessor_artifact(
            context=None,
            operator_state=state,
            history_receipt_path=None,
            pins=None,
            manifest_public_key_path=None,
            official_day=official_day,
            contract_registry_raw=None,
            expected_contract_registry_raw_sha256=None,
            protected_linked_inputs=ProtectedLinkedReplayInputs(
                history_receipt_path=projection.history_receipt_path,
                runtime_input_path=args.runtime_input,
                runtime_input_raw_sha256=runtime_input.raw_sha256,
                service_uid=policy.uid,
                service_gid=policy.gid,
                history_receipt_raw_sha256=projection.history_receipt_raw_sha256,
                manifest_public_key_path=projection.manifest_public_key_path,
                manifest_public_key_raw_sha256=(
                    projection.manifest_public_key_raw_sha256
                ),
                business_public_key_raw_sha256=(
                    projection.business_public_key_raw_sha256
                ),
                contract_registry_path=projection.contract_registry_path,
                contract_registry_raw_sha256=(
                    projection.contract_registry_raw_sha256
                ),
            ),
        )
        head = load_current_catalog_head(args.operator_state)
        if head.receipt_raw != entry.receipt_raw or head.artifact_raw != entry.artifact_raw:
            raise LinkedPublisherCliError("linked publication readback mismatches")
        output: dict[str, Any] = {
            "schema_version": "vnpy_research_m2_linked_publication_result_v1",
            "status": "LINKED_PUBLISHED",
            "receipt_id": entry.receipt["receipt_id"],
            "artifact_id": entry.artifact["artifact_id"],
            "sequence": entry.receipt["sequence"],
            "official_day": entry.receipt["official_day"],
            "receipt_raw_sha256": sha256(entry.receipt_raw),
            "artifact_raw_sha256": sha256(entry.artifact_raw),
            "authority": false_authority(),
        }
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
