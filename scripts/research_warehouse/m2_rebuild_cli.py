"""Keyless deterministic M2 rebuild stage bound to root operator pins."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .canonical import canonical_json_line
from .commit_anchors import load_commit_anchor_ledger
from .custody_paths import require_private_dir
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .file_integrity import fsync_dir
from .m2_operator_defaults import (
    DEFAULT_MANIFEST_PUBLIC_KEY,
    DEFAULT_OPERATOR_STATE,
    release_binding,
)
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .rebuild import rebuild_empty_catalog, verify_rebuilt_catalog
from .rebuild_binding import load_normalization_binding


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    result.add_argument(
        "--operator-state",
        type=Path,
        default=DEFAULT_OPERATOR_STATE,
    )
    result.add_argument(
        "--manifest-public-key",
        type=Path,
        default=DEFAULT_MANIFEST_PUBLIC_KEY,
    )
    return result


def _derived_root(runtime_root: Path, head_seal: str) -> Path:
    parent = runtime_root / "derived"
    created = False
    try:
        parent.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    require_private_dir(parent, "M2 derived generations root")
    if created:
        fsync_dir(parent)
        fsync_dir(runtime_root)
    return parent / head_seal


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        with operator_state_lock(args.operator_state, exclusive=False):
            context = load_runtime_context(args.runtime_input)
            state = load_operator_state(args.operator_state)
            if state.payload["manifest_sequence"] == 0:
                raise RegistryError("M2 rebuild requires a committed manifest")
            ledger = load_commit_anchor_ledger(
                Path(state.payload["commit_anchor_ledger_path"]),
                expected_raw_sha256=(
                    state.payload["commit_anchor_ledger_raw_sha256"]
                ),
                private=False,
            )
            tool_commit, dependency_lock, dependency_lock_sha = release_binding()
            binding = load_normalization_binding(
                tool_commit_sha=tool_commit,
                dependency_lock_path=dependency_lock,
                expected_dependency_lock_sha256=dependency_lock_sha,
                registry_raw_sha256=context.registry.raw_sha256,
            )
            derived_root = _derived_root(
                context.runtime.root,
                state.payload["manifest_head_seal_sha256"],
            )
            if derived_root.exists():
                result = verify_rebuilt_catalog(
                    evidence=context.paths,
                    derived=DerivedPaths.open(derived_root),
                    public_key_path=args.manifest_public_key,
                    registry=context.registry,
                    expected_genesis_seal_sha256=state.payload[
                        "manifest_genesis_seal_sha256"
                    ],
                    expected_head_seal_sha256=state.payload[
                        "manifest_head_seal_sha256"
                    ],
                    expected_head_commit_seal_sha256=state.payload[
                        "manifest_head_commit_seal_sha256"
                    ],
                    ledger=ledger,
                    binding=binding,
                )
            else:
                result = rebuild_empty_catalog(
                    evidence=context.paths,
                    derived_root=derived_root,
                    public_key_path=args.manifest_public_key,
                    registry=context.registry,
                    expected_genesis_seal_sha256=state.payload[
                        "manifest_genesis_seal_sha256"
                    ],
                    expected_head_seal_sha256=state.payload[
                        "manifest_head_seal_sha256"
                    ],
                    expected_head_commit_seal_sha256=state.payload[
                        "manifest_head_commit_seal_sha256"
                    ],
                    ledger=ledger,
                    binding=binding,
                )
            output = {
                **result,
                "derived_root": str(derived_root),
                "operator_state_raw_sha256": state.raw_sha256,
                "status": "M2_DERIVED_GENERATION_VALID",
            }
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
