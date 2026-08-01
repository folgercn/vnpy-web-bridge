#!/usr/bin/env python3
"""Create a deterministic bounded query-v5 code-only overlay source bundle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from c_fast_t1.validate_query_v5_runtime import (  # noqa: E402
    CONTAINERFILE_PATH,
    EXPECTED_COPY_SOURCES,
    inspect_containerfile,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v5-source-manifest-v1.schema.json"
)
DELEGATE_PATH = Path(__file__).with_name("create_query_v3_source_bundle.py")
MANIFEST_ARCHIVE_PATH = "query-v5-source-manifest.json"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v5_source_manifest_v1"
MANIFEST_ID_PREFIX = "query-v5-source-manifest-v1-"


def _load_delegate() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_query_v5_source_git_delegate", DELEGATE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("query-v5 source Git delegate is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_delegate = _load_delegate()
SourceBundleError = _delegate.SourceBundleError


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate(payload: dict[str, Any]) -> None:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceBundleError("query-v5 source schema is unavailable") from exc
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            payload
        ),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        raise SourceBundleError(
            "query-v5 source manifest is invalid: " + errors[0].message
        )


def build_source_bundle(
    source_root: Path, commit_sha: str
) -> tuple[bytes, bytes, dict[str, Any]]:
    exact_commit = _delegate._resolve_commit(source_root, commit_sha)
    container_raw, container_mode = _delegate._git_blob(
        source_root, exact_commit, CONTAINERFILE_PATH
    )
    instruction_sha256, copy_sources, _copies = inspect_containerfile(container_raw)
    if copy_sources != EXPECTED_COPY_SOURCES:
        raise SourceBundleError("query-v5 source closure drifted")
    paths = tuple(sorted({CONTAINERFILE_PATH, *copy_sources}))
    blobs: dict[str, tuple[bytes, int]] = {
        CONTAINERFILE_PATH: (container_raw, container_mode)
    }
    for path in paths:
        if path != CONTAINERFILE_PATH:
            blobs[path] = _delegate._git_blob(source_root, exact_commit, path)
    entries = [
        {
            "path": path,
            "sha256": _sha256(blobs[path][0]),
            "size": len(blobs[path][0]),
            "mode": blobs[path][1],
        }
        for path in paths
    ]
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": "",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "runtime_kind": "c_fast_t1_query_v5_code_only_overlay",
        "source_commit_sha": exact_commit,
        "containerfile_path": CONTAINERFILE_PATH,
        "containerfile_instruction_sha256": instruction_sha256,
        "entries": entries,
        "base_runtime_kind": "c_fast_t1_query_v4",
        "requires_exact_query_v4_base_content_attestation": True,
        "git_resolution_performed_by_producer": True,
        "runtime_git_resolution_required": False,
        "source_commit_lineage_independently_verified_by_runtime": False,
        "code_only_blocked": True,
        "sensitive_material_present": False,
        "authority_granted": False,
    }
    identity = {key: value for key, value in manifest.items() if key != "manifest_id"}
    manifest["manifest_id"] = MANIFEST_ID_PREFIX + _sha256(canonical_json(identity))
    _validate(manifest)
    manifest_raw = canonical_json(manifest)
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT
    ) as archive:
        members = [
            (MANIFEST_ARCHIVE_PATH, manifest_raw, 0o444),
            *[(path, blobs[path][0], blobs[path][1]) for path in paths],
        ]
        for path, raw, mode in members:
            member = tarfile.TarInfo(path)
            member.size = len(raw)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            member.type = tarfile.REGTYPE
            archive.addfile(member, io.BytesIO(raw))
    bundle_raw = output.getvalue()
    if len(bundle_raw) > 64 * 1024 * 1024:
        raise SourceBundleError("query-v5 source bundle is too large")
    return bundle_raw, manifest_raw, manifest


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
        bundle, manifest_raw, manifest = build_source_bundle(
            args.source_root, args.source_commit_sha
        )
        _delegate._write_create_only(args.bundle_output, bundle)
        _delegate._write_create_only(args.manifest_output, manifest_raw)
    except (OSError, SourceBundleError, ValueError) as exc:
        print(f"query-v5 source bundle creation failed: {exc}", file=sys.stderr)
        return 2
    print(f"manifest_id={manifest['manifest_id']}")
    print(f"source_bundle_archive_sha256={_sha256(bundle)}")
    print("runtime_execution_ready=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
