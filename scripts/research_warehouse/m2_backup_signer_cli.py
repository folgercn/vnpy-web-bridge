"""Privileged backup signer entrypoint with irreversible UID handoff."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .backup_custody import BackupPaths
from .backup_service import create_append_only_backup_with_private_key
from .canonical import canonical_json_line
from .commit_anchors import load_commit_anchor_ledger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .m2_isolation_contracts import load_isolation_policy
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import (
    BACKUP_SIGNER_KEY_ID,
    DEFAULT_BACKUP_PRIVATE_KEY,
    DEFAULT_MANIFEST_PUBLIC_KEY,
    DEFAULT_OPERATOR_STATE,
    release_binding,
)
from .m2_operator_state import (
    load_operator_state,
    operator_state_lock,
    record_backup_result,
)
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .m2_signer_handoff import run_with_preloaded_private_key
from .rebuild_binding import load_normalization_binding


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    result.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_BACKUP_PRIVATE_KEY,
    )
    result.add_argument(
        "--operator-state",
        type=Path,
        default=DEFAULT_OPERATOR_STATE,
    )
    result.add_argument("--signer-key-id", default=BACKUP_SIGNER_KEY_ID)
    result.add_argument(
        "--manifest-public-key",
        type=Path,
        default=DEFAULT_MANIFEST_PUBLIC_KEY,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = load_isolation_policy(
            args.runtime_input.parent / "isolation-policy-v1.json"
        )
        with operator_state_lock(args.operator_state, exclusive=True):
            state = load_operator_state(args.operator_state)
            if state.payload["manifest_sequence"] == 0:
                raise RegistryError("backup cannot run before a committed manifest")
            tool_commit, dependency_lock, dependency_lock_sha = release_binding()

            def sign(private_key):
                context = load_runtime_context(args.runtime_input)
                binding = load_normalization_binding(
                    tool_commit_sha=tool_commit,
                    dependency_lock_path=dependency_lock,
                    expected_dependency_lock_sha256=dependency_lock_sha,
                    registry_raw_sha256=context.registry.raw_sha256,
                )
                ledger = load_commit_anchor_ledger(
                    Path(state.payload["commit_anchor_ledger_path"]),
                    expected_raw_sha256=(
                        state.payload["commit_anchor_ledger_raw_sha256"]
                    ),
                    private=False,
                )
                clock = query_trusted_clock()
                anchor = create_append_only_backup_with_private_key(
                    source=context.paths,
                    source_derived=DerivedPaths.open(
                        context.runtime.root
                        / "derived"
                        / state.payload["manifest_head_seal_sha256"]
                    ),
                    backup=BackupPaths.open(
                        Path(context.policy.payload["backup_root"])
                    ),
                    public_key_path=args.manifest_public_key,
                    registry=context.registry,
                    expected_genesis_seal_sha256=state.payload[
                        "manifest_genesis_seal_sha256"
                    ],
                    expected_head_seal_sha256=state.payload[
                        "manifest_head_seal_sha256"
                    ],
                    expected_head_commit_seal_sha256=(
                        state.payload["manifest_head_commit_seal_sha256"]
                    ),
                    ledger=ledger,
                    binding=binding,
                    expected_parent_anchor_raw_sha256=state.payload[
                        "backup_head_anchor_raw_sha256"
                    ],
                    backup_signer_key_id=args.signer_key_id,
                    backup_private_key=private_key,
                    backup_public_key_path=Path(
                        context.runtime_input.payload["backup_public_key_path"]
                    ),
                    expected_backup_public_key_sha256=(
                        context.runtime_input.payload[
                            "expected_backup_public_key_sha256"
                        ]
                    ),
                    minimum_free_bytes_after=context.policy.payload[
                        "monitor_thresholds"
                    ]["disk_free_min_bytes"],
                    now=clock.trusted_now,
                )
                return {
                    "anchor_id": anchor.anchor_id,
                    "anchor_raw_sha256": anchor.raw_sha256,
                    "created_at": anchor.payload["created_at"],
                    "parent_anchor_raw_sha256": (
                        anchor.parent_anchor_raw_sha256
                    ),
                    "sequence": anchor.sequence,
                    "status": (
                        "APPEND_ONLY_BACKUP_COMMITTED_AWAITING_ROOT_PIN"
                    ),
                }

            output = run_with_preloaded_private_key(
                private_key_path=args.private_key,
                service_uid=policy.payload["service_uid"],
                service_gid=policy.payload["service_gid"],
                operation=sign,
            )
            record_backup_result(
                state,
                result=output,
                runtime_input_path=args.runtime_input,
            )
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
