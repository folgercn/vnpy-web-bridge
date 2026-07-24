#!/usr/bin/env python3
"""Verify one OCI layout archive for the C_FAST T1 one-shot runtime."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
import gzip
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


SCHEMA_VERSION = "commodity_c_fast_t1_image_attestation_v1"
EVIDENCE_SCHEMA_VERSION = "commodity_c_fast_t1_external_image_evidence_v1"
STATUS = "EXTERNAL_OCI_ARTIFACT_CONTENT_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE"
MAX_INPUT_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_LAYER_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_LAYER_FILE_BYTES = 128 * 1024 * 1024
MAX_BLOBS = 512
ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-external-image-evidence-v1.schema.json"
)
ATTESTATION_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-image-attestation-v1.schema.json"
)
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.one-shot"
VERIFIER_SOURCE_PATH = "scripts/c_fast_t1/verify_image_attestation.py"
EVIDENCE_SCHEMA_SOURCE_PATH = (
    "docs/schemas/commodity-c-fast-t1-external-image-evidence-v1.schema.json"
)
ATTESTATION_SCHEMA_SOURCE_PATH = (
    "docs/schemas/commodity-c-fast-t1-image-attestation-v1.schema.json"
)
ENTRYPOINT = [
    "python",
    "-I",
    "/opt/c-fast-t1/scripts/commodity_c_fast_t1_one_shot.py",
]
EXPECTED_DEPENDENCIES = {
    "cryptography": "48.0.0",
    "jsonschema": "4.26.0",
    "psycopg[binary]": "3.2.3",
    "referencing": "0.37.0",
}
EXPECTED_INSTALLED_DEPENDENCIES = {
    "cryptography": "48.0.0",
    "jsonschema": "4.26.0",
    "psycopg": "3.2.3",
    "psycopg-binary": "3.2.3",
    "referencing": "0.37.0",
}
EXPECTED_LABELS = {
    "io.vnpy-web-bridge.c-fast-t1.authority-granted": "false",
    "io.vnpy-web-bridge.c-fast-t1.one-shot-runtime": "true",
    "org.opencontainers.image.title": ("vnpy-web-bridge C_FAST T1 one-shot runner"),
}
EXPECTED_COPY_SOURCES = (
    "scripts/commodity_c_fast_t1_one_shot.py",
    "scripts/commodity_c_fast_l1_l5_audit.py",
    "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
    "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-one-shot-release-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-consume-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-terminal-seal-v1.schema.json",
)
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
BLOB_PATH_RE = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
SENSITIVE_ENV_MARKERS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "PRIVATE_KEY",
    "DSN",
)
PRIVATE_KEY_CONTENT_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


class ImageAttestationError(RuntimeError):
    """An expected image evidence, OCI, or source-binding violation."""


@dataclass(frozen=True)
class FileSystemEntry:
    kind: str
    sha256: str | None = None
    size: int = 0
    link_target: str | None = None
    contains_private_key_marker: bool = False
    package_metadata: bytes | None = None


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ImageAttestationError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ImageAttestationError(f"non-finite JSON value is forbidden: {value}")


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        stat.S_IFMT(value.st_mode),
    )


def _read_fd_bounded(
    descriptor: int,
    label: str,
    limit: int,
) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > limit:
        raise ImageAttestationError(f"{label} exceeds {limit} byte limit")
    return raw


def _read_regular_file(
    path: Path,
    label: str,
    *,
    limit: int = MAX_INPUT_BYTES,
) -> bytes:
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode):
            raise ImageAttestationError(f"{label} must not be a symlink")
        if not stat.S_ISREG(before_path.st_mode):
            raise ImageAttestationError(f"{label} must be a regular file")
        if before_path.st_size > limit:
            raise ImageAttestationError(f"{label} exceeds {limit} byte limit")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            first = _read_fd_bounded(descriptor, label, limit)
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_fd_bounded(descriptor, label, limit)
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
    except ImageAttestationError:
        raise
    except OSError as exc:
        raise ImageAttestationError(f"cannot read {label}") from exc

    if (
        len(
            {
                _identity(before_path),
                _identity(opened),
                _identity(closed),
                _identity(after_path),
            }
        )
        != 1
        or first != second
        or len(first) != opened.st_size
    ):
        raise ImageAttestationError(f"{label} changed while being read")
    return first


def _parse_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except ImageAttestationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageAttestationError(f"{label} must be one UTF-8 JSON object") from exc
    if not isinstance(payload, dict):
        raise ImageAttestationError(f"{label} must be one UTF-8 JSON object")
    return payload


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, label)
    return _parse_json_bytes(raw, label), raw


def _validate_schema(
    payload: dict[str, Any],
    schema_path: Path,
    label: str,
) -> None:
    schema, _ = _load_json(schema_path, f"{label} schema")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise ImageAttestationError(f"{label} schema is invalid") from exc
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.absolute_path)
        raise ImageAttestationError(
            f"{label} schema validation failed at "
            f"{location or '<root>'}: {first.message}"
        )


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    return environment


def _git_command(source_root: Path, arguments: list[str]) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        "-c",
        "core.pager=cat",
        "-C",
        str(source_root),
        *arguments,
    ]


def _git_output(
    source_root: Path,
    arguments: list[str],
    label: str,
    *,
    limit: int = MAX_INPUT_BYTES,
) -> bytes:
    try:
        completed = subprocess.run(
            _git_command(source_root, arguments),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:
        raise ImageAttestationError(f"cannot execute git for {label}") from exc
    if completed.returncode != 0:
        raise ImageAttestationError(f"git cannot resolve {label}")
    if len(completed.stdout) > limit:
        raise ImageAttestationError(f"{label} exceeds {limit} byte limit")
    return completed.stdout


def _git_archive_sha256(source_root: Path, commit_sha: str) -> str:
    try:
        process = subprocess.Popen(
            _git_command(
                source_root,
                ["archive", "--format=tar", commit_sha],
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:
        raise ImageAttestationError("cannot execute git archive") from exc
    assert process.stdout is not None
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = process.stdout.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            process.kill()
            process.wait()
            raise ImageAttestationError(
                f"source archive exceeds {MAX_ARCHIVE_BYTES} byte limit"
            )
        digest.update(chunk)
    stderr = process.stderr.read() if process.stderr is not None else b""
    returncode = process.wait()
    if returncode != 0:
        raise ImageAttestationError(
            "git archive failed: " + stderr.decode("utf-8", errors="replace").strip()
        )
    return digest.hexdigest()


def _git_blob(
    source_root: Path,
    commit_sha: str,
    relative_path: str,
) -> bytes:
    tree_entry = _git_output(
        source_root,
        ["ls-tree", commit_sha, "--", relative_path],
        f"tree entry {commit_sha}:{relative_path}",
    )
    try:
        metadata, separator, path_bytes = tree_entry.rstrip(b"\n").partition(b"\t")
        mode, object_type, _object_id = metadata.decode("ascii").split()
        stored_path = path_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ImageAttestationError(
            f"source tree entry is malformed: {relative_path}"
        ) from exc
    if (
        separator != b"\t"
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or stored_path != relative_path
    ):
        raise ImageAttestationError(
            f"source path must be an exact regular blob: {relative_path}"
        )
    return _git_output(
        source_root,
        ["show", f"{commit_sha}:{relative_path}"],
        f"{commit_sha}:{relative_path}",
    )


def _parse_containerfile(raw: bytes) -> tuple[str, dict[str, str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ImageAttestationError("one-shot Containerfile must be UTF-8") from exc
    first_line = text.splitlines()[0] if text.splitlines() else ""
    prefix = "FROM python:3.12-slim@"
    if not first_line.startswith(prefix):
        raise ImageAttestationError("one-shot Containerfile base image is not frozen")
    base_digest = first_line.removeprefix(prefix)
    if OCI_DIGEST_RE.fullmatch(base_digest) is None:
        raise ImageAttestationError(
            "one-shot Containerfile base image digest is invalid"
        )

    copy_map: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("COPY "):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ImageAttestationError(
                "one-shot Containerfile COPY instruction is malformed"
            )
        source, target = parts[1:]
        if source in copy_map:
            raise ImageAttestationError(
                "one-shot Containerfile has duplicate COPY source"
            )
        copy_map[source] = target
    if tuple(copy_map) != EXPECTED_COPY_SOURCES:
        raise ImageAttestationError("one-shot Containerfile COPY allowlist drifted")
    for dependency, version in EXPECTED_DEPENDENCIES.items():
        if text.count(f'"{dependency}=={version}"') != 1:
            raise ImageAttestationError(f"dependency pin drifted: {dependency}")
    required_cleanup = (
        "find /opt/c-fast-t1 -type f \\( -name '*.pyc' -o -name '*.pyo' \\) -delete"
    )
    if text.count(required_cleanup) != 1:
        raise ImageAttestationError("one-shot Containerfile bytecode cleanup drifted")
    return base_digest, copy_map


def _image_path(target: str) -> str:
    normalized = target.removeprefix("./")
    return f"/opt/c-fast-t1/{normalized}"


def derive_source_facts(
    source_root: Path,
    commit_sha: str,
) -> dict[str, Any]:
    if COMMIT_RE.fullmatch(commit_sha) is None:
        raise ImageAttestationError(
            "expected source commit must be 40 lowercase hex characters"
        )
    resolved = (
        _git_output(
            source_root,
            ["rev-parse", f"{commit_sha}^{{commit}}"],
            "expected source commit",
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if resolved != commit_sha:
        raise ImageAttestationError("expected source commit did not resolve exactly")
    containerfile_raw = _git_blob(
        source_root,
        commit_sha,
        CONTAINERFILE_PATH,
    )
    base_digest, copy_map = _parse_containerfile(containerfile_raw)
    bundle_files: dict[str, str] = {}
    for source, target in copy_map.items():
        bundle_files[_image_path(target)] = hashlib.sha256(
            _git_blob(source_root, commit_sha, source)
        ).hexdigest()
    return {
        "source_archive_sha256": _git_archive_sha256(
            source_root,
            commit_sha,
        ),
        "containerfile_sha256": hashlib.sha256(containerfile_raw).hexdigest(),
        "base_image_digest": base_digest,
        "bundle_files": bundle_files,
        "verifier_sha256": hashlib.sha256(
            _git_blob(source_root, commit_sha, VERIFIER_SOURCE_PATH)
        ).hexdigest(),
        "evidence_schema_sha256": hashlib.sha256(
            _git_blob(
                source_root,
                commit_sha,
                EVIDENCE_SCHEMA_SOURCE_PATH,
            )
        ).hexdigest(),
        "attestation_schema_sha256": hashlib.sha256(
            _git_blob(
                source_root,
                commit_sha,
                ATTESTATION_SCHEMA_SOURCE_PATH,
            )
        ).hexdigest(),
    }


def _normalize_tar_path(name: str, label: str) -> str:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise ImageAttestationError(f"{label} has an invalid path")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name:
        return ""
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ImageAttestationError(f"{label} contains path traversal")
    normalized = "/".join(path.parts)
    if normalized != name:
        raise ImageAttestationError(f"{label} path is not normalized")
    return normalized


def _read_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    label: str,
    *,
    limit: int,
) -> bytes:
    if member.size < 0 or member.size > limit:
        raise ImageAttestationError(f"{label} exceeds {limit} byte limit")
    stream = archive.extractfile(member)
    if stream is None:
        raise ImageAttestationError(f"cannot read {label}")
    raw = stream.read(limit + 1)
    if len(raw) != member.size or len(raw) > limit:
        raise ImageAttestationError(f"{label} size does not match tar header")
    return raw


def _parse_oci_layout_archive(raw: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                name = _normalize_tar_path(member.name, "OCI layout archive")
                if name in seen:
                    raise ImageAttestationError(
                        f"OCI layout archive has duplicate path: {name}"
                    )
                seen.add(name)
                if member.issym() or member.islnk():
                    raise ImageAttestationError(
                        "OCI layout archive must not contain links"
                    )
                if member.isdir():
                    continue
                if not member.isreg() or not name:
                    raise ImageAttestationError(
                        "OCI layout archive contains a non-regular file"
                    )
                if name not in {"oci-layout", "index.json"}:
                    match = BLOB_PATH_RE.fullmatch(name)
                    if match is None:
                        raise ImageAttestationError(
                            f"OCI layout archive path is not allowed: {name}"
                        )
                    if len(files) >= MAX_BLOBS + 2:
                        raise ImageAttestationError(
                            "OCI layout archive contains too many blobs"
                        )
                limit = (
                    MAX_INPUT_BYTES
                    if name in {"oci-layout", "index.json"}
                    else MAX_ARCHIVE_BYTES
                )
                files[name] = _read_tar_member(
                    archive,
                    member,
                    name,
                    limit=limit,
                )
    except ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise ImageAttestationError(
            "OCI layout archive is not a valid plain tar"
        ) from exc
    if "oci-layout" not in files or "index.json" not in files:
        raise ImageAttestationError("OCI layout archive is missing layout metadata")
    layout = _parse_json_bytes(files["oci-layout"], "oci-layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ImageAttestationError("OCI image layout version is invalid")
    for name, content in files.items():
        match = BLOB_PATH_RE.fullmatch(name)
        if match is not None and hashlib.sha256(content).hexdigest() != match[1]:
            raise ImageAttestationError(f"OCI blob path digest mismatch: {name}")
    return files


def _require_exact_fields(
    payload: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    if set(payload) != expected:
        raise ImageAttestationError(f"{label} fields are invalid")


def _descriptor(
    payload: Any,
    label: str,
    *,
    media_types: set[str],
    platform: bool = False,
) -> tuple[str, int, str]:
    if not isinstance(payload, dict):
        raise ImageAttestationError(f"{label} must be an object")
    expected = {"mediaType", "digest", "size"}
    if platform:
        expected.add("platform")
    _require_exact_fields(payload, expected, label)
    media_type = payload["mediaType"]
    digest = payload["digest"]
    size = payload["size"]
    if media_type not in media_types:
        raise ImageAttestationError(f"{label} mediaType is invalid")
    if not isinstance(digest, str) or OCI_DIGEST_RE.fullmatch(digest) is None:
        raise ImageAttestationError(f"{label} digest is invalid")
    if type(size) is not int or size < 0 or size > MAX_ARCHIVE_BYTES:
        raise ImageAttestationError(f"{label} size is invalid")
    if platform and payload["platform"] != {
        "architecture": "amd64",
        "os": "linux",
    }:
        raise ImageAttestationError(f"{label} platform is invalid")
    return digest, size, media_type


def _descriptor_blob(
    files: dict[str, bytes],
    digest: str,
    size: int,
    label: str,
) -> bytes:
    path = "blobs/sha256/" + digest.removeprefix("sha256:")
    if path not in files:
        raise ImageAttestationError(f"{label} blob is missing")
    raw = files[path]
    if len(raw) != size:
        raise ImageAttestationError(f"{label} descriptor size mismatch")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        raise ImageAttestationError(f"{label} descriptor digest mismatch")
    return raw


def _decompress_layer(raw: bytes, media_type: str, label: str) -> bytes:
    if media_type == "application/vnd.oci.image.layer.v1.tar":
        if len(raw) > MAX_LAYER_UNPACKED_BYTES:
            raise ImageAttestationError(f"{label} is too large")
        return raw
    try:
        stream = gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LAYER_UNPACKED_BYTES:
                raise ImageAttestationError(f"{label} exceeds decompression limit")
            chunks.append(chunk)
        stream.close()
        return b"".join(chunks)
    except ImageAttestationError:
        raise
    except (EOFError, OSError) as exc:
        raise ImageAttestationError(f"{label} gzip stream is invalid") from exc


def _remove_path(
    filesystem: dict[str, FileSystemEntry],
    target: str,
    *,
    lower_paths: set[str] | None = None,
    created_paths: set[str] | None = None,
) -> None:
    prefix = target + "/"
    for path in list(filesystem):
        if target and path != target and not path.startswith(prefix):
            continue
        if (
            lower_paths is not None
            and path not in lower_paths
            or created_paths is not None
            and path in created_paths
        ):
            continue
        filesystem.pop(path, None)


def _apply_layer(
    filesystem: dict[str, FileSystemEntry],
    raw: bytes,
    label: str,
) -> None:
    lower_paths = set(filesystem)
    created_paths: set[str] = set()
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                name = _normalize_tar_path(member.name, label)
                if not name:
                    if member.isdir():
                        continue
                    raise ImageAttestationError(f"{label} contains an unnamed entry")
                if name in seen:
                    raise ImageAttestationError(
                        f"{label} contains duplicate path: {name}"
                    )
                seen.add(name)
                total += max(member.size, 0)
                if total > MAX_LAYER_UNPACKED_BYTES:
                    raise ImageAttestationError(f"{label} exceeds unpacked size limit")
                path = PurePosixPath(name)
                basename = path.name
                parent = "" if str(path.parent) == "." else str(path.parent)
                if basename.startswith(".wh."):
                    valid_whiteout = member.isreg() or (
                        member.ischr() and member.devmajor == 0 and member.devminor == 0
                    )
                    if not valid_whiteout:
                        raise ImageAttestationError(
                            f"{label} whiteout entry is invalid"
                        )
                    if basename == ".wh..wh..opq":
                        target = parent
                    else:
                        target_name = basename.removeprefix(".wh.")
                        if not target_name:
                            raise ImageAttestationError(
                                f"{label} whiteout target is invalid"
                            )
                        target = f"{parent}/{target_name}" if parent else target_name
                    _remove_path(
                        filesystem,
                        target,
                        lower_paths=lower_paths,
                        created_paths=created_paths,
                    )
                    continue
                if member.isdir():
                    filesystem.pop(name, None)
                    continue
                _remove_path(filesystem, name)
                if member.isreg():
                    content = _read_tar_member(
                        archive,
                        member,
                        f"{label}:{name}",
                        limit=MAX_LAYER_FILE_BYTES,
                    )
                    if (
                        name.endswith(".dist-info/METADATA")
                        and len(content) > MAX_INPUT_BYTES
                    ):
                        raise ImageAttestationError(
                            f"{label} package METADATA is too large"
                        )
                    filesystem[name] = FileSystemEntry(
                        kind="regular",
                        sha256=hashlib.sha256(content).hexdigest(),
                        size=len(content),
                        contains_private_key_marker=any(
                            marker in content for marker in PRIVATE_KEY_CONTENT_MARKERS
                        ),
                        package_metadata=(
                            content if name.endswith(".dist-info/METADATA") else None
                        ),
                    )
                elif member.issym() or member.islnk():
                    if "\x00" in member.linkname:
                        raise ImageAttestationError(f"{label} link target is invalid")
                    filesystem[name] = FileSystemEntry(
                        kind="symlink" if member.issym() else "hardlink",
                        link_target=member.linkname,
                    )
                else:
                    raise ImageAttestationError(
                        f"{label} contains unsupported special file: {name}"
                    )
                created_paths.add(name)
    except ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise ImageAttestationError(f"{label} is not a valid tar") from exc


def _environment_facts(config: dict[str, Any]) -> dict[str, str]:
    values = config.get("Env")
    if not isinstance(values, list):
        raise ImageAttestationError("OCI config Env must be an array")
    parsed: dict[str, str] = {}
    for item in values:
        if not isinstance(item, str) or "=" not in item or "\x00" in item:
            raise ImageAttestationError("OCI config Env entry is invalid")
        name, value = item.split("=", 1)
        if not name or name in parsed:
            raise ImageAttestationError(
                "OCI config Env contains an invalid or duplicate name"
            )
        upper_name = name.upper()
        if any(marker in upper_name for marker in SENSITIVE_ENV_MARKERS):
            raise ImageAttestationError(
                "OCI config contains a sensitive environment name"
            )
        if "postgresql://" in value.lower() or any(
            marker in value.encode() for marker in PRIVATE_KEY_CONTENT_MARKERS
        ):
            raise ImageAttestationError(
                "OCI config contains sensitive environment material"
            )
        parsed[name] = value
    expected = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }
    for name, value in expected.items():
        if parsed.get(name) != value:
            raise ImageAttestationError(f"OCI config environment drifted: {name}")
    return expected


def _runtime_scan(
    filesystem: dict[str, FileSystemEntry],
    expected_paths: set[str],
) -> tuple[dict[str, str], list[str], list[str], list[str]]:
    runtime_prefix = "opt/c-fast-t1/"
    actual_runtime_paths = {
        path for path in filesystem if path.startswith(runtime_prefix)
    }
    expected_relative = {path.removeprefix("/") for path in expected_paths}
    unexpected = sorted(actual_runtime_paths - expected_relative)
    bundle: dict[str, str] = {}
    for expected in sorted(expected_paths):
        relative = expected.removeprefix("/")
        entry = filesystem.get(relative)
        if entry is None or entry.kind != "regular" or entry.sha256 is None:
            raise ImageAttestationError(
                f"runtime bundle file is missing or non-regular: {expected}"
            )
        bundle[expected] = entry.sha256
    signer_paths: list[str] = []
    forbidden_paths: list[str] = []
    for path, entry in filesystem.items():
        lowered = path.lower()
        basename = PurePosixPath(lowered).name
        lowered_target = (entry.link_target or "").lower()
        if (
            "commodity_c_fast_t1_sign_release" in lowered
            or "signer" in lowered
            or "private_key" in lowered
            or "private_key" in lowered_target
            or "signer" in lowered_target
            or basename in {"id_rsa", "id_ed25519"}
            or entry.contains_private_key_marker
        ):
            signer_paths.append("/" + path)
        if not path.startswith(runtime_prefix):
            continue
        if "__pycache__" in PurePosixPath(path).parts or basename.endswith(
            (".pyc", ".pyo")
        ):
            forbidden_paths.append("/" + path)
    return (
        bundle,
        sorted(forbidden_paths),
        ["/" + path for path in unexpected],
        sorted(signer_paths),
    )


def _installed_dependency_versions(
    filesystem: dict[str, FileSystemEntry],
) -> dict[str, str]:
    installed: dict[str, str] = {}
    for path, entry in filesystem.items():
        if (
            not path.startswith("usr/local/lib/python")
            or not path.endswith(".dist-info/METADATA")
            or entry.package_metadata is None
        ):
            continue
        try:
            metadata = BytesParser(policy=policy.default).parsebytes(
                entry.package_metadata
            )
        except (TypeError, ValueError) as exc:
            raise ImageAttestationError(
                "installed dependency METADATA is invalid"
            ) from exc
        name = metadata.get("Name")
        version = metadata.get("Version")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or len(metadata.get_all("Name", [])) != 1
            or len(metadata.get_all("Version", [])) != 1
        ):
            raise ImageAttestationError("installed dependency METADATA is incomplete")
        normalized_name = name.strip().lower().replace("_", "-")
        normalized_version = version.strip()
        if normalized_name not in EXPECTED_INSTALLED_DEPENDENCIES:
            continue
        if normalized_name in installed:
            raise ImageAttestationError(
                f"installed dependency is duplicated: {normalized_name}"
            )
        installed[normalized_name] = normalized_version
    if installed != EXPECTED_INSTALLED_DEPENDENCIES:
        raise ImageAttestationError(
            "installed dependency versions do not match frozen runtime"
        )
    return installed


def derive_oci_facts(
    archive_path: Path,
    expected_source_commit_sha: str,
    expected_runtime_paths: set[str],
) -> dict[str, Any]:
    archive_raw = _read_regular_file(
        archive_path,
        "OCI layout archive",
        limit=MAX_ARCHIVE_BYTES,
    )
    files = _parse_oci_layout_archive(archive_raw)
    index = _parse_json_bytes(files["index.json"], "OCI index")
    allowed_index_fields = {"schemaVersion", "mediaType", "manifests"}
    _require_exact_fields(index, allowed_index_fields, "OCI index")
    if (
        index["schemaVersion"] != 2
        or index["mediaType"] != OCI_INDEX_MEDIA_TYPE
        or not isinstance(index["manifests"], list)
        or len(index["manifests"]) != 1
    ):
        raise ImageAttestationError("OCI index must contain one linux/amd64 manifest")
    manifest_digest, manifest_size, _ = _descriptor(
        index["manifests"][0],
        "OCI manifest descriptor",
        media_types={OCI_MANIFEST_MEDIA_TYPE},
        platform=True,
    )
    if manifest_size > MAX_INPUT_BYTES:
        raise ImageAttestationError("OCI manifest exceeds metadata limit")
    manifest_raw = _descriptor_blob(
        files,
        manifest_digest,
        manifest_size,
        "OCI manifest",
    )
    manifest = _parse_json_bytes(manifest_raw, "OCI manifest")
    _require_exact_fields(
        manifest,
        {"schemaVersion", "mediaType", "config", "layers"},
        "OCI manifest",
    )
    if (
        manifest["schemaVersion"] != 2
        or manifest["mediaType"] != OCI_MANIFEST_MEDIA_TYPE
        or not isinstance(manifest["layers"], list)
        or not manifest["layers"]
        or len(manifest["layers"]) > 256
    ):
        raise ImageAttestationError("OCI manifest is invalid")
    config_digest, config_size, _ = _descriptor(
        manifest["config"],
        "OCI config descriptor",
        media_types={OCI_CONFIG_MEDIA_TYPE},
    )
    if config_size > MAX_INPUT_BYTES:
        raise ImageAttestationError("OCI config exceeds metadata limit")
    config_raw = _descriptor_blob(
        files,
        config_digest,
        config_size,
        "OCI config",
    )
    config_document = _parse_json_bytes(config_raw, "OCI config")
    config = config_document.get("config")
    if not isinstance(config, dict):
        raise ImageAttestationError("OCI config.config must be an object")

    layer_digests: list[str] = []
    diff_ids: list[str] = []
    filesystem: dict[str, FileSystemEntry] = {}
    total_unpacked = 0
    referenced_blob_paths = {
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"),
        "blobs/sha256/" + config_digest.removeprefix("sha256:"),
    }
    for index_number, descriptor in enumerate(manifest["layers"]):
        digest, size, media_type = _descriptor(
            descriptor,
            f"OCI layer descriptor {index_number}",
            media_types=OCI_LAYER_MEDIA_TYPES,
        )
        compressed = _descriptor_blob(
            files,
            digest,
            size,
            f"OCI layer {index_number}",
        )
        uncompressed = _decompress_layer(
            compressed,
            media_type,
            f"OCI layer {index_number}",
        )
        total_unpacked += len(uncompressed)
        if total_unpacked > MAX_LAYER_UNPACKED_BYTES:
            raise ImageAttestationError("OCI layers exceed total unpacked size limit")
        layer_digests.append(digest)
        diff_ids.append("sha256:" + hashlib.sha256(uncompressed).hexdigest())
        _apply_layer(
            filesystem,
            uncompressed,
            f"OCI layer {index_number}",
        )
        referenced_blob_paths.add("blobs/sha256/" + digest.removeprefix("sha256:"))
    actual_blob_paths = {name for name in files if BLOB_PATH_RE.fullmatch(name)}
    if actual_blob_paths != referenced_blob_paths:
        raise ImageAttestationError("OCI layout contains missing or unreferenced blobs")

    rootfs = config_document.get("rootfs")
    if rootfs != {"type": "layers", "diff_ids": diff_ids}:
        raise ImageAttestationError("OCI config rootfs diff_ids do not match layers")
    labels = config.get("Labels")
    if labels != {
        **EXPECTED_LABELS,
        "org.opencontainers.image.revision": expected_source_commit_sha,
    }:
        raise ImageAttestationError("OCI labels do not match exact source")
    if config.get("User") != "65532:65532":
        raise ImageAttestationError("OCI user is not the frozen non-root user")
    if config.get("WorkingDir") != "/opt/c-fast-t1":
        raise ImageAttestationError("OCI working directory drifted")
    if config.get("Entrypoint") != ENTRYPOINT:
        raise ImageAttestationError("OCI entrypoint drifted")
    relevant_environment = _environment_facts(config)

    (
        bundle_files,
        forbidden_paths,
        unexpected_paths,
        signer_paths,
    ) = _runtime_scan(filesystem, expected_runtime_paths)
    installed_dependencies = _installed_dependency_versions(filesystem)
    return {
        "archive_sha256": hashlib.sha256(archive_raw).hexdigest(),
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "layer_digests": layer_digests,
        "config": {
            "user": config["User"],
            "working_dir": config["WorkingDir"],
            "entrypoint": config["Entrypoint"],
            "relevant_environment": relevant_environment,
            "labels": labels,
        },
        "bundle_files": bundle_files,
        "installed_dependencies": installed_dependencies,
        "forbidden_path_matches": forbidden_paths,
        "unexpected_bundle_paths": unexpected_paths,
        "signer_or_private_key_paths": signer_paths,
    }


def _require_exact(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise ImageAttestationError(f"{label} does not match verified content")


def verify_image_evidence(
    evidence_path: Path,
    oci_layout_archive_path: Path,
    source_root: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    evidence, evidence_raw = _load_json(
        evidence_path,
        "external image evidence",
    )
    _validate_schema(
        evidence,
        EVIDENCE_SCHEMA_PATH,
        "external image evidence",
    )
    source_facts = derive_source_facts(
        source_root,
        expected_source_commit_sha,
    )
    local_contract_files = {
        "verifier_sha256": Path(__file__).resolve(),
        "evidence_schema_sha256": EVIDENCE_SCHEMA_PATH,
        "attestation_schema_sha256": ATTESTATION_SCHEMA_PATH,
    }
    for field, path in local_contract_files.items():
        _require_exact(
            hashlib.sha256(_read_regular_file(path, field)).hexdigest(),
            source_facts[field],
            field,
        )
    oci_facts = derive_oci_facts(
        oci_layout_archive_path,
        expected_source_commit_sha,
        set(source_facts["bundle_files"]),
    )

    _require_exact(
        evidence["source_commit_sha"],
        expected_source_commit_sha,
        "source commit",
    )
    _require_exact(
        evidence["source_archive_sha256"],
        source_facts["source_archive_sha256"],
        "source archive digest",
    )
    build = evidence["build"]
    image = evidence["image"]
    _require_exact(
        build["containerfile_sha256"],
        source_facts["containerfile_sha256"],
        "Containerfile digest",
    )
    _require_exact(
        build["base_image_digest"],
        source_facts["base_image_digest"],
        "base image digest",
    )
    _require_exact(
        build["direct_dependencies"],
        EXPECTED_DEPENDENCIES,
        "direct dependencies",
    )
    _require_exact(
        image["export_sha256"],
        oci_facts["archive_sha256"],
        "OCI layout archive digest",
    )
    _require_exact(
        image["digest"],
        oci_facts["manifest_digest"],
        "OCI manifest digest",
    )
    _require_exact(
        image["id"],
        oci_facts["config_digest"],
        "OCI config digest/image ID",
    )
    _require_exact(
        image["rootfs_layer_digests"],
        oci_facts["layer_digests"],
        "OCI layer digests",
    )
    _require_exact(image["config"], oci_facts["config"], "OCI config")
    _require_exact(
        image["bundle_files"],
        oci_facts["bundle_files"],
        "runtime bundle hashes",
    )
    _require_exact(
        oci_facts["bundle_files"],
        source_facts["bundle_files"],
        "runtime bundle/source hashes",
    )
    for field in (
        "forbidden_path_matches",
        "unexpected_bundle_paths",
        "signer_or_private_key_paths",
    ):
        _require_exact(image[field], oci_facts[field], field)
        _require_exact(oci_facts[field], [], field)
    reference_digest = image["reference"].rsplit("@", maxsplit=1)[-1]
    _require_exact(
        reference_digest,
        oci_facts["manifest_digest"],
        "immutable image reference digest",
    )

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "source_commit_sha": expected_source_commit_sha,
        "source_archive_sha256": source_facts["source_archive_sha256"],
        "external_evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "evidence_captured_at": evidence["captured_at"],
        "containerfile_sha256": source_facts["containerfile_sha256"],
        "verifier_sha256": source_facts["verifier_sha256"],
        "evidence_schema_sha256": source_facts["evidence_schema_sha256"],
        "attestation_schema_sha256": source_facts["attestation_schema_sha256"],
        "base_image_digest": source_facts["base_image_digest"],
        "installed_dependencies": oci_facts["installed_dependencies"],
        "oci_layout_archive_sha256": oci_facts["archive_sha256"],
        "image_reference": image["reference"],
        "image_digest": oci_facts["manifest_digest"],
        "image_id": oci_facts["config_digest"],
        "rootfs_layer_digests": oci_facts["layer_digests"],
        "runtime_bundle_sha256": oci_facts["bundle_files"],
        "checks": {
            "exact_git_commit_resolved": True,
            "git_archive_digest_matched": True,
            "containerfile_digest_matched": True,
            "base_image_pin_present_in_exact_containerfile": True,
            "dependency_pins_present_in_exact_containerfile": True,
            "installed_dependency_versions_recomputed": True,
            "oci_archive_sha256_recomputed": True,
            "oci_manifest_digest_recomputed": True,
            "oci_config_digest_recomputed": True,
            "oci_layer_digests_recomputed": True,
            "immutable_image_reference_matched": True,
            "oci_revision_matched": True,
            "non_root_entrypoint_matched": True,
            "runtime_files_recomputed_from_layers": True,
            "forbidden_and_signer_paths_absent": True,
            "build_provenance_verified": False,
            "registry_provenance_verified": False,
        },
        "image_built_here": False,
        "cryptographic_approval_present": False,
        "sensitive_material_present": False,
        "authority_recovery_allowed": False,
        "receipt_replay_allowed": False,
        "t1_executed": False,
        "production_queried": False,
        "authority_granted": False,
        "network_authorized": False,
        "network_query_authorized": False,
        "readonly_production_query_authorized": False,
        "production_query_authorized": False,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "collection_authorized": False,
        "execution_quality_collection_authorized": False,
        "runtime_activation_authorized": False,
        "order_authorized": False,
        "order_submission_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "replacement_authorized": False,
        "production_authorized": False,
        "dynamic_selection_allowed": False,
        "automatic_promotion_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }
    _validate_schema(
        report,
        ATTESTATION_SCHEMA_PATH,
        "image attestation",
    )
    return report


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _write_create_only(path: Path, payload: dict[str, Any]) -> None:
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ImageAttestationError("cannot create image attestation output") from exc


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--oci-layout-archive",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=ROOT,
    )
    parser.add_argument(
        "--expected-source-commit-sha",
        required=True,
    )
    parser.add_argument("--json-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = verify_image_evidence(
            args.evidence.expanduser().resolve(),
            args.oci_layout_archive.expanduser().resolve(),
            args.source_root.expanduser().resolve(),
            args.expected_source_commit_sha,
        )
        if args.json_output is not None:
            _write_create_only(
                args.json_output.expanduser().resolve(),
                report,
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except (ImageAttestationError, OSError, UnicodeError) as exc:
        print(f"image attestation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
