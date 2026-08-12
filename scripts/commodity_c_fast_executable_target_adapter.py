"""Create one unsigned SIMNOW TargetPlan envelope from pinned offline inputs.

This is a file-only handoff.  It has no network client, signing key, custody
writer, or order mutation capability; the resulting envelope still requires
the existing offline signer and custody install flow.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _path in (_ROOT / "backend", _ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    build_executable_target_plan,
    peek_current_facts_to_snapshot,
)
from c_fast_producer.producer import (
    ProducerError,
    _create_only_atomic,
    _decode_json,
    _read_pinned_file,
)

from shared.trust_contracts.v1 import canonical_json_line


def _object_from_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = _decode_json(_read_pinned_file(path), label)
    except ProducerError as exc:
        raise ExecutableTargetAdapterError(f"{label} file is invalid") from exc
    if not isinstance(value, dict):  # pragma: no cover - strict decoder guarantees this
        raise ExecutableTargetAdapterError(f"{label} must be an object")
    return value


def _generated_at(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutableTargetAdapterError("generated_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutableTargetAdapterError("generated_at must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline MAP/C_FAST to unsigned SIMNOW TargetPlan handoff"
    )
    parser.add_argument("--map-candidate", required=True, type=Path)
    parser.add_argument("--c-fast-candidate", required=True, type=Path)
    parser.add_argument("--authority-receipt", required=True, type=Path)
    parser.add_argument("--authority-artifact", required=True, type=Path)
    parser.add_argument("--peek-current-facts", required=True, type=Path)
    parser.add_argument("--reconciliation-state", required=True, type=Path)
    parser.add_argument("--product", required=True)
    parser.add_argument("--account-scope", required=True)
    parser.add_argument(
        "--reduce-only-close",
        action="store_true",
        help="derive target=0 only to close one current C_FAST position",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generated-at")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        map_candidate = _object_from_file(args.map_candidate, "MAP candidate")
        c_fast_candidate = _object_from_file(args.c_fast_candidate, "C_FAST candidate")
        authority_receipt = _object_from_file(args.authority_receipt, "authority receipt")
        authority_artifact = _object_from_file(
            args.authority_artifact, "authority artifact"
        )
        peek_facts = _object_from_file(args.peek_current_facts, "peek current facts")
        reconciliation = _object_from_file(
            args.reconciliation_state, "reconciliation state"
        )
        if set(reconciliation) != {"state", "unknown_outcomes"}:
            raise ExecutableTargetAdapterError("reconciliation state fields are invalid")
        peek = peek_current_facts_to_snapshot(
            peek_facts, account_scope=args.account_scope
        )
        handoff = build_executable_target_plan(
            map_candidate=map_candidate,
            c_fast_candidate=c_fast_candidate,
            authority_receipt=authority_receipt,
            current_facts=peek.snapshot,
            reconciliation=reconciliation,
            product=args.product,
            account_scope=args.account_scope,
            environment="SIMNOW",
            gateway_name=peek.gateway_name,
            reduce_only_close=args.reduce_only_close,
        )
        envelope = handoff.artifact_envelope(
            generated_at=_generated_at(args.generated_at),
            authority_artifact=authority_artifact,
        )
        _create_only_atomic(args.output, canonical_json_line(envelope))
    except (ExecutableTargetAdapterError, ProducerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "artifact_id": envelope["artifact_id"],
                "plan_id": handoff.target_plan["plan_id"],
                "output": str(args.output),
                "private_key_access": False,
                "network_access": False,
                "order_mutation_access": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
