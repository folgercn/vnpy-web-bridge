#!/usr/bin/env python3
"""Create one deterministic, bounded C_FAST query-v3 source bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json"
)
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.query-v3"
MANIFEST_ARCHIVE_PATH = "query-v3-source-manifest.json"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v3_source_manifest_v1"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
RUNTIME_KIND = "c_fast_t1_query_v3"
MANIFEST_ID_PREFIX = "query-v3-source-manifest-v1-"
BASE_IMAGE = (
    "python:3.12-slim@"
    "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256 = (
    "6322dbef5346afbc74deadc1bf74cd521517ad3d34da4d241eb80c3f89d21db4"
)
ENTRYPOINT = [
    "/usr/local/bin/python3.12",
    "-I",
    "/opt/c-fast-t1/scripts/commodity_c_fast_t1_query_v3.py",
]
RUNTIME_LABEL = "io.vnpy-web-bridge.c-fast-t1.query-v3-runtime"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 128
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
ALLOWED_INSTRUCTIONS = frozenset(
    {"ARG", "COPY", "ENTRYPOINT", "ENV", "FROM", "LABEL", "RUN", "USER", "WORKDIR"}
)
REQUIRED_COPY_SOURCES = frozenset(
    {
        "scripts/commodity_c_fast_t1_query_v3.py",
        "scripts/commodity_c_fast_t1_query_child_v3.py",
        "scripts/commodity_c_fast_t1_one_shot.py",
        "scripts/commodity_c_fast_l1_l5_audit.py",
        "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-consume-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-child-started-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-terminal-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-v3-trusted-keys-v1.schema.json",
    }
)
FORBIDDEN_SOURCE_MARKERS = (
    "_sign_",
    "signer",
    "private",
    ".pem",
    ".key",
)


class SourceBundleError(RuntimeError):
    """Expected source resolution or deterministic bundle violation."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _git(
    source_root: Path,
    arguments: list[str],
    label: str,
    *,
    limit: int = MAX_FILE_BYTES,
) -> bytes:
    try:
        completed = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-c",
                "core.pager=cat",
                "-C",
                str(source_root),
                *arguments,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:
        raise SourceBundleError(f"cannot execute git for {label}") from exc
    if completed.returncode != 0:
        raise SourceBundleError(f"git cannot resolve {label}")
    if len(completed.stdout) > limit:
        raise SourceBundleError(f"{label} exceeds {limit} byte limit")
    return completed.stdout


def _resolve_commit(source_root: Path, commit_sha: str) -> str:
    if COMMIT_RE.fullmatch(commit_sha) is None:
        raise SourceBundleError(
            "source commit must be exactly 40 lowercase hexadecimal characters"
        )
    try:
        resolved = _git(
            source_root,
            ["rev-parse", f"{commit_sha}^{{commit}}"],
            "source commit",
        ).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise SourceBundleError("resolved source commit is not ASCII") from exc
    if resolved != commit_sha:
        raise SourceBundleError("source commit did not resolve exactly")
    return resolved


def _normalize_source_path(path: str) -> str:
    if (
        not path
        or "\x00" in path
        or "\\" in path
        or SAFE_PATH_RE.fullmatch(path) is None
    ):
        raise SourceBundleError("Containerfile COPY source path is invalid")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise SourceBundleError("Containerfile COPY source path is not normalized")
    normalized = "/".join(parsed.parts)
    if normalized != path:
        raise SourceBundleError("Containerfile COPY source path is not exact")
    if not (
        path.startswith("scripts/")
        or path.startswith("docs/schemas/")
    ):
        raise SourceBundleError("Containerfile COPY source is outside fixed roots")
    lowered = path.lower()
    if any(marker in lowered for marker in FORBIDDEN_SOURCE_MARKERS):
        raise SourceBundleError("Containerfile copies a signer or sensitive source")
    return normalized


def _logical_instructions(text: str) -> tuple[str, ...]:
    instructions: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if re.match(
            r"^#\s*(?:syntax|escape|check)\s*=",
            stripped,
            flags=re.IGNORECASE,
        ):
            raise SourceBundleError("Containerfile parser directives are forbidden")
        if not current and (not stripped or stripped.startswith("#")):
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        instructions.append(re.sub(r"\s+", " ", current))
        current = ""
    if current:
        raise SourceBundleError("Containerfile has an unterminated continuation")
    if not instructions:
        raise SourceBundleError("Containerfile is empty")
    return tuple(instructions)


def inspect_containerfile(raw: bytes) -> tuple[str, tuple[str, ...]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceBundleError("query-v3 Containerfile must be UTF-8") from exc
    instructions = _logical_instructions(text)
    keywords = tuple(item.split(maxsplit=1)[0].upper() for item in instructions)
    unsupported = sorted(set(keywords) - ALLOWED_INSTRUCTIONS)
    if unsupported:
        raise SourceBundleError(
            "Containerfile instruction is forbidden: " + ", ".join(unsupported)
        )
    if keywords.count("FROM") != 1 or instructions[0] != f"FROM {BASE_IMAGE}":
        raise SourceBundleError("query-v3 base image contract drifted")
    if keywords.count("ENTRYPOINT") != 1 or "CMD" in keywords:
        raise SourceBundleError("query-v3 requires one ENTRYPOINT and no CMD")
    if any(
        keyword == "RUN"
        and re.search(r"(^|\s)--mount(?:=|\s)", instruction) is not None
        for keyword, instruction in zip(keywords, instructions)
    ):
        raise SourceBundleError("Containerfile RUN --mount is forbidden")
    expected_entrypoint = "ENTRYPOINT " + json.dumps(
        ENTRYPOINT,
        ensure_ascii=False,
    )
    if instructions.count(expected_entrypoint) != 1:
        raise SourceBundleError("query-v3 isolated ENTRYPOINT drifted")
    required_fragments = (
        f'{RUNTIME_LABEL}="true"',
        'io.vnpy-web-bridge.c-fast-t1.authority-granted="false"',
        "USER 65532:65532",
        "chmod -R a-w /opt/c-fast-t1",
        "psycopg[binary]==3.2.3",
        "cryptography==48.0.0",
        "jsonschema==4.26.0",
        "referencing==0.37.0",
    )
    normalized_text = "\n".join(instructions)
    if any(normalized_text.count(fragment) != 1 for fragment in required_fragments):
        raise SourceBundleError("query-v3 Containerfile invariant drifted")
    copy_sources: list[str] = []
    for instruction, keyword in zip(instructions, keywords):
        if keyword != "COPY":
            continue
        parts = instruction.split()
        if len(parts) != 3:
            raise SourceBundleError("COPY must use exactly one source and one target")
        source = _normalize_source_path(parts[1])
        if parts[2] != f"./{source}":
            raise SourceBundleError("query-v3 COPY target drifted")
        if source in copy_sources:
            raise SourceBundleError("query-v3 COPY source is duplicated")
        copy_sources.append(source)
    if not REQUIRED_COPY_SOURCES.issubset(copy_sources):
        raise SourceBundleError("query-v3 required COPY closure is incomplete")
    if len(copy_sources) > MAX_ENTRIES - 2:
        raise SourceBundleError("query-v3 COPY closure is too large")
    instruction_sha256 = _sha256(normalized_text.encode("utf-8"))
    if instruction_sha256 != EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256:
        raise SourceBundleError(
            "query-v3 Containerfile normalized instruction sequence drifted"
        )
    return instruction_sha256, tuple(copy_sources)


def _git_blob(
    source_root: Path,
    commit_sha: str,
    relative_path: str,
) -> tuple[bytes, int]:
    tree_entry = _git(
        source_root,
        ["ls-tree", commit_sha, "--", relative_path],
        f"tree entry {commit_sha}:{relative_path}",
    )
    try:
        metadata, separator, path_raw = tree_entry.rstrip(b"\n").partition(b"\t")
        mode_text, object_type, _object_id = metadata.decode("ascii").split()
        stored_path = path_raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise SourceBundleError(
            f"source tree entry is malformed: {relative_path}"
        ) from exc
    if (
        separator != b"\t"
        or object_type != "blob"
        or mode_text not in {"100644", "100755"}
        or stored_path != relative_path
    ):
        raise SourceBundleError(
            f"source path must be one exact regular blob: {relative_path}"
        )
    raw = _git(
        source_root,
        ["show", f"{commit_sha}:{relative_path}"],
        f"source blob {commit_sha}:{relative_path}",
    )
    if b"\x00" in raw:
        raise SourceBundleError(f"source blob contains NUL: {relative_path}")
    return raw, 0o755 if mode_text == "100755" else 0o644


def _manifest_identity(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "manifest_id"}


def _validate_schema(payload: dict[str, Any]) -> None:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceBundleError("source manifest schema cannot be loaded") from exc
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        raise SourceBundleError(
            "source manifest schema validation failed: " + errors[0].message
        )


def build_source_bundle(
    source_root: Path,
    commit_sha: str,
) -> tuple[bytes, bytes, dict[str, Any]]:
    exact_commit = _resolve_commit(source_root, commit_sha)
    containerfile_raw, containerfile_mode = _git_blob(
        source_root,
        exact_commit,
        CONTAINERFILE_PATH,
    )
    instruction_sha256, copy_sources = inspect_containerfile(containerfile_raw)
    source_paths = tuple(sorted({CONTAINERFILE_PATH, *copy_sources}))
    blobs: dict[str, tuple[bytes, int]] = {
        CONTAINERFILE_PATH: (containerfile_raw, containerfile_mode)
    }
    for relative_path in source_paths:
        if relative_path == CONTAINERFILE_PATH:
            continue
        blobs[relative_path] = _git_blob(
            source_root,
            exact_commit,
            relative_path,
        )
    entries = [
        {
            "path": path,
            "sha256": _sha256(blobs[path][0]),
            "size": len(blobs[path][0]),
            "mode": blobs[path][1],
        }
        for path in source_paths
    ]
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": "",
        "candidate_id": CANDIDATE_ID,
        "runtime_kind": RUNTIME_KIND,
        "source_commit_sha": exact_commit,
        "containerfile_path": CONTAINERFILE_PATH,
        "containerfile_instruction_sha256": instruction_sha256,
        "entries": entries,
        "git_resolution_performed_by_producer": True,
        "runtime_git_resolution_required": False,
        "source_commit_lineage_independently_verified_by_runtime": False,
        "sensitive_material_present": False,
        "authority_granted": False,
    }
    manifest["manifest_id"] = (
        MANIFEST_ID_PREFIX
        + _sha256(canonical_json(_manifest_identity(manifest)))
    )
    _validate_schema(manifest)
    manifest_raw = canonical_json(manifest)

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        members = [
            (MANIFEST_ARCHIVE_PATH, manifest_raw, 0o444),
            *[(path, blobs[path][0], blobs[path][1]) for path in source_paths],
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
    if len(bundle_raw) > MAX_BUNDLE_BYTES:
        raise SourceBundleError("source bundle exceeds bounded archive size")
    return bundle_raw, manifest_raw, manifest


def _write_create_only(path: Path, raw: bytes, mode: int = 0o600) -> None:
    if not path.is_absolute():
        raise SourceBundleError("output path must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
        info = parent.lstat()
    except OSError as exc:
        raise SourceBundleError("output parent is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SourceBundleError("output parent must be a non-symlink directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent / path.name, flags, mode)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise SourceBundleError(f"cannot create output: {path}") from exc


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
        _write_create_only(args.bundle_output, bundle_raw)
        _write_create_only(args.manifest_output, manifest_raw)
    except (SourceBundleError, OSError, ValueError) as exc:
        print(f"query-v3 source bundle creation failed: {exc}", file=sys.stderr)
        return 2
    print(f"manifest_id={manifest['manifest_id']}")
    print(f"source_bundle_archive_sha256={_sha256(bundle_raw)}")
    print("runtime_git_resolution_required=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
