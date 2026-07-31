#!/usr/bin/env python3
"""Create one deterministic, bounded C_FAST query-v4 source bundle."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from c_fast_t1.validate_query_v4_runtime import (
    ENTRYPOINT,
    EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256,
    EXPECTED_COPY_SOURCES,
)


ROOT = Path(__file__).resolve().parents[2]
DELEGATE_PATH = Path(__file__).with_name(
    "create_query_v3_source_bundle.py"
)
SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v4-source-manifest-v1.schema.json"
)
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.query-v4"
MANIFEST_ARCHIVE_PATH = "query-v4-source-manifest.json"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v4_source_manifest_v1"
RUNTIME_KIND = "c_fast_t1_query_v4"
MANIFEST_ID_PREFIX = "query-v4-source-manifest-v1-"
RUNTIME_LABEL = "io.vnpy-web-bridge.c-fast-t1.query-v4-runtime"


def _load_delegate() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_c_fast_t1_query_v4_source_bundle_delegate",
        DELEGATE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("query-v4 source bundle delegate is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SCHEMA_PATH = SCHEMA_PATH
    module.CONTAINERFILE_PATH = CONTAINERFILE_PATH
    module.MANIFEST_ARCHIVE_PATH = MANIFEST_ARCHIVE_PATH
    module.SCHEMA_VERSION = SCHEMA_VERSION
    module.RUNTIME_KIND = RUNTIME_KIND
    module.MANIFEST_ID_PREFIX = MANIFEST_ID_PREFIX
    module.ENTRYPOINT = list(ENTRYPOINT)
    module.RUNTIME_LABEL = RUNTIME_LABEL
    module.EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256 = (
        EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256
    )
    module.REQUIRED_COPY_SOURCES = frozenset(EXPECTED_COPY_SOURCES)
    return module


_delegate = _load_delegate()
SourceBundleError = _delegate.SourceBundleError
canonical_json = _delegate.canonical_json


def build_source_bundle(
    source_root: Path,
    commit_sha: str,
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Resolve exact Git blobs and return one canonical query-v4 bundle."""

    return _delegate.build_source_bundle(source_root, commit_sha)


def write_create_only(path: Path, raw: bytes) -> None:
    """Write one private create-only artifact."""

    _delegate._write_create_only(path, raw)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--bundle-output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        bundle_raw, manifest_raw, manifest = build_source_bundle(
            args.source_root,
            args.source_commit_sha,
        )
        write_create_only(args.bundle_output, bundle_raw)
        write_create_only(args.manifest_output, manifest_raw)
    except (SourceBundleError, OSError, ValueError) as exc:
        print(
            f"query-v4 source bundle creation failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"manifest_id={manifest['manifest_id']}")
    print(
        "source_bundle_archive_sha256="
        f"{_delegate._sha256(bundle_raw)}"
    )
    print("runtime_git_resolution_required=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
