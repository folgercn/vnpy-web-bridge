"""Build and verify an offline Research Warehouse M2 release bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .canonical import canonical_json_line
from .errors import RegistryError
from .m2_python_runtime import (
    create_python_runtime_manifest,
)
from .m2_python_runtime_archive import prepare_python_runtime
from .m2_release_builder import build_release_bundle
from .m2_release_contracts import (
    load_release_bundle_manifest,
    verify_release_bundle,
    write_create_only,
)
from .m2_release_install import install_release_bundle
from .m2_wheelhouse import create_wheelhouse_manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    wheelhouse = commands.add_parser("manifest-wheelhouse")
    wheelhouse.add_argument("--wheelhouse", type=Path, required=True)
    wheelhouse.add_argument("--output", type=Path, required=True)
    runtime = commands.add_parser("manifest-python-runtime")
    runtime.add_argument("--runtime-root", type=Path, required=True)
    runtime.add_argument("--output", type=Path, required=True)
    prepare_runtime = commands.add_parser("prepare-python-runtime")
    prepare_runtime.add_argument("--source-archive", type=Path, required=True)
    prepare_runtime.add_argument("--output-root", type=Path, required=True)
    build = commands.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--source-commit-sha", required=True)
    build.add_argument("--requirements", type=Path, required=True)
    build.add_argument("--wheelhouse", type=Path, required=True)
    build.add_argument("--wheelhouse-manifest", type=Path, required=True)
    build.add_argument("--expected-wheelhouse-manifest-sha256", required=True)
    build.add_argument("--python-runtime", type=Path, required=True)
    build.add_argument("--python-runtime-manifest", type=Path, required=True)
    build.add_argument("--expected-python-runtime-manifest-sha256", required=True)
    build.add_argument("--output-root", type=Path, required=True)
    build.add_argument("--bundle-manifest-output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--expected-manifest-sha256", required=True)
    install = commands.add_parser("install")
    install.add_argument("--staged-root", type=Path, required=True)
    install.add_argument("--manifest", type=Path, required=True)
    install.add_argument("--expected-manifest-sha256", required=True)
    install.add_argument(
        "--installed-tree-manifest-output",
        type=Path,
        required=True,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "manifest-wheelhouse":
            manifest = create_wheelhouse_manifest(args.wheelhouse)
            digest = write_create_only(args.output, manifest)
            output = {
                "schema_version": "vnpy_research_m2_wheelhouse_manifest_result_v1",
                "manifest_raw_sha256": digest,
                "wheel_count": len(manifest["wheels"]),
            }
        elif args.command == "prepare-python-runtime":
            prepare_python_runtime(args.source_archive, args.output_root)
            output = {
                "schema_version": (
                    "vnpy_research_m2_python_runtime_prepare_result_v1"
                ),
                "status": "M2_PYTHON_RUNTIME_PREPARED",
                "runtime_root": str(args.output_root),
            }
        elif args.command == "manifest-python-runtime":
            manifest = create_python_runtime_manifest(
                args.runtime_root,
            )
            digest = write_create_only(args.output, manifest)
            output = {
                "schema_version": (
                    "vnpy_research_m2_python_runtime_manifest_result_v1"
                ),
                "manifest_raw_sha256": digest,
                "entry_count": len(manifest["entries"]),
                "tree_content_sha256": manifest["tree_content_sha256"],
            }
        elif args.command == "build":
            manifest = build_release_bundle(
                source_root=args.source_root,
                source_commit_sha=args.source_commit_sha,
                requirements_path=args.requirements,
                wheelhouse=args.wheelhouse,
                wheelhouse_manifest_path=args.wheelhouse_manifest,
                expected_wheelhouse_manifest_raw_sha256=(
                    args.expected_wheelhouse_manifest_sha256
                ),
                python_runtime=args.python_runtime,
                python_runtime_manifest_path=args.python_runtime_manifest,
                expected_python_runtime_manifest_raw_sha256=(
                    args.expected_python_runtime_manifest_sha256
                ),
                output_root=args.output_root,
            )
            digest = write_create_only(args.bundle_manifest_output, manifest)
            output = {
                "schema_version": "vnpy_research_m2_release_build_result_v1",
                "bundle_manifest_raw_sha256": digest,
                "entry_count": len(manifest["entries"]),
                "tree_content_sha256": manifest["tree_content_sha256"],
            }
        elif args.command == "verify":
            manifest = load_release_bundle_manifest(
                args.manifest,
                expected_raw_sha256=args.expected_manifest_sha256,
            )
            verify_release_bundle(args.root, manifest)
            output = {
                "schema_version": "vnpy_research_m2_release_verify_result_v1",
                "status": "M2_RELEASE_BUNDLE_VERIFIED",
                "tree_content_sha256": manifest["tree_content_sha256"],
            }
        else:
            manifest = load_release_bundle_manifest(
                args.manifest,
                expected_raw_sha256=args.expected_manifest_sha256,
            )
            output = install_release_bundle(
                staged_root=args.staged_root,
                manifest=manifest,
                installed_manifest_output=args.installed_tree_manifest_output,
            )
    except RegistryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0
