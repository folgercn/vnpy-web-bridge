"""CLI for deterministic M2 Research release build and installation."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .canonical import canonical_json_line
from .errors import RegistryError
from .m2_release_builder import build_release_package
from .m2_release_bundle_contracts import (
    FROZEN_DEPENDENCY_LOCK_SHA256,
    LOGICAL_RELEASE_ROOT,
    load_dependency_lock,
)
from .m2_release_installer import (
    install_release_package,
    rollback_release,
    verify_release_package,
)

INSTALL_CONFIRMATION = "INSTALL_M2_RESEARCH_RELEASE_NOT_ACTIVATE"
ROLLBACK_CONFIRMATION = "ROLLBACK_M2_RESEARCH_RELEASE_NOT_ACTIVATE"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    verify_lock = commands.add_parser("verify-dependency-lock")
    verify_lock.add_argument("--dependency-lock", type=Path, required=True)
    build = commands.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--wheelhouse", type=Path, required=True)
    build.add_argument("--dependency-lock", type=Path, required=True)
    build.add_argument("--release-id", required=True)
    build.add_argument("--source-commit-sha", required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify-package")
    verify.add_argument("--package-root", type=Path, required=True)
    install = commands.add_parser("install")
    install.add_argument("--package-root", type=Path, required=True)
    install.add_argument("--installed-manifest", type=Path, required=True)
    install.add_argument("--confirm", required=True)
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--candidate", type=Path, required=True)
    rollback.add_argument("--confirm", required=True)
    return result


def _dependency_lock(path: Path):
    return load_dependency_lock(
        path,
        expected_raw_sha256=FROZEN_DEPENDENCY_LOCK_SHA256,
    )


def _require_root_confirmation(actual: str, expected: str) -> None:
    if os.geteuid() != 0 or actual != expected:
        raise RegistryError("M2 release root operation is not confirmed")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-dependency-lock":
            lock = _dependency_lock(args.dependency_lock)
            output = {
                "schema_version": "vnpy_research_m2_dependency_lock_result_v1",
                "status": "DEPENDENCY_LOCK_VERIFIED",
                "dependency_lock_raw_sha256": lock.raw_sha256,
                "dependency_count": len(lock.dependencies),
            }
        elif args.command == "build":
            output = build_release_package(
                source_root=args.source_root,
                package_root=args.output,
                wheelhouse=args.wheelhouse,
                dependency_lock=_dependency_lock(args.dependency_lock),
                release_id=args.release_id,
                source_commit_sha=args.source_commit_sha,
            )
        elif args.command == "verify-package":
            manifest = verify_release_package(args.package_root)
            output = {
                "schema_version": "vnpy_research_m2_release_verify_result_v1",
                "status": "RELEASE_PACKAGE_VERIFIED_NOT_INSTALLED",
                "release_id": manifest["release_id"],
                "tree_content_sha256": manifest["tree_content_sha256"],
                "authority": manifest["authority"],
            }
        elif args.command == "install":
            _require_root_confirmation(args.confirm, INSTALL_CONFIRMATION)
            output = install_release_package(
                package_root=args.package_root,
                active_root=Path(LOGICAL_RELEASE_ROOT),
                rollback_root=Path(
                    "/usr/local/libexec/vnpyresearch/release-rollbacks"
                ),
                release_lock_path=Path(
                    "/usr/local/libexec/vnpyresearch/release.lock"
                ),
                installed_manifest_path=args.installed_manifest,
            )
        else:
            _require_root_confirmation(args.confirm, ROLLBACK_CONFIRMATION)
            output = rollback_release(
                active_root=Path(LOGICAL_RELEASE_ROOT),
                rollback_root=Path(
                    "/usr/local/libexec/vnpyresearch/release-rollbacks"
                ),
                rollback_candidate=args.candidate,
                release_lock_path=Path(
                    "/usr/local/libexec/vnpyresearch/release.lock"
                ),
            )
    except RegistryError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
