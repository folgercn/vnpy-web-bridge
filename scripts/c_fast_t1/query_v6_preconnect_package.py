#!/usr/bin/env python3
"""Build, install and preflight the pinned query-v6 pre-connect runtime.

This module is deliberately offline.  It packages exact Git blobs plus the
local Python interpreter/dependency closure, and publishes an active pin
generation only after the package has been fully installed and revalidated.
It never reads a DSN, opens a socket, consumes a release or grants authority.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v6-preconnect-package-v1.schema.json"
)
PIN_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v6-executable-pin-set-v1.schema.json"
)
MANIFEST_ARCHIVE_PATH = "query-v6-preconnect-package-manifest.json"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v6_preconnect_package_v1"
PIN_SET_VERSION = "commodity_c_fast_t1_query_v6_executable_pin_set_v1"
ENTRYPOINT = "scripts/commodity_c_fast_t1_query_v6_preconnect_adapter.py"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
SOURCE_PATHS = (
    "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
    "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-child-launched-v6.schema.json",
    "docs/schemas/commodity-c-fast-t1-one-shot-query-executable-release-v6.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-consume-v6.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-v6-executable-pin-set-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-v6-executable-trusted-keys-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-v6-preconnect-package-v1.schema.json",
    "scripts/c_fast_t1/query_v6_preconnect_package.py",
    "scripts/commodity_c_fast_l1_l5_audit_v4.py",
    "scripts/commodity_c_fast_t1_query_v6_executable.py",
    "scripts/commodity_c_fast_t1_query_v6_executable_sign.py",
    "scripts/commodity_c_fast_t1_query_v6_runtime.py",
    ENTRYPOINT,
)
PIN_SOURCE_PATHS = {
    "executable_signer_sha256": "scripts/commodity_c_fast_t1_query_v6_executable_sign.py",
    "executable_verifier_sha256": "scripts/commodity_c_fast_t1_query_v6_executable.py",
    "executable_runner_sha256": "scripts/commodity_c_fast_t1_query_v6_runtime.py",
    "executable_release_schema_sha256": "docs/schemas/commodity-c-fast-t1-one-shot-query-executable-release-v6.schema.json",
    "executable_keyring_schema_sha256": "docs/schemas/commodity-c-fast-t1-query-v6-executable-trusted-keys-v1.schema.json",
    "consume_schema_sha256": "docs/schemas/commodity-c-fast-t1-query-consume-v6.schema.json",
    "terminal_schema_sha256": "docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json",
    "audit_evidence_schema_sha256": "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
    "legacy_audit_evidence_schema_sha256": "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
    "readonly_proof_schema_sha256": "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "child_launch_schema_sha256": "docs/schemas/commodity-c-fast-t1-query-child-launched-v6.schema.json",
    "adapter_package_schema_sha256": "docs/schemas/commodity-c-fast-t1-query-v6-preconnect-package-v1.schema.json",
    "adapter_package_builder_sha256": "scripts/c_fast_t1/query_v6_preconnect_package.py",
}
DEPENDENCY_NAMES = (
    "attrs",
    "cryptography",
    "jsonschema",
    "jsonschema-specifications",
    "psycopg",
    "psycopg-binary",
    "referencing",
    "rpds-py",
)


class QueryV6PackageError(RuntimeError):
    """The query-v6 package or active installation failed closed."""


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


def _validate(payload: dict[str, Any], schema_path: Path, label: str) -> None:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV6PackageError(f"{label} schema is unavailable") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        raise QueryV6PackageError(f"{label} is invalid: {errors[0].message}")


def _resolve_commit(source_root: Path, commit_sha: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"{commit_sha}^{{commit}}"],
        cwd=source_root,
        check=False,
        capture_output=True,
        text=True,
    )
    exact = result.stdout.strip()
    if (
        result.returncode
        or len(exact) != 40
        or any(c not in "0123456789abcdef" for c in exact)
    ):
        raise QueryV6PackageError("query-v6 package source commit is invalid")
    return exact


def _git_blob(source_root: Path, commit_sha: str, path: str) -> tuple[bytes, int]:
    tree = subprocess.run(
        ["git", "ls-tree", commit_sha, "--", path],
        cwd=source_root,
        check=False,
        capture_output=True,
        text=True,
    )
    fields = tree.stdout.strip().split()
    if tree.returncode or len(fields) < 4 or fields[1] != "blob":
        raise QueryV6PackageError(f"query-v6 package Git blob is absent: {path}")
    if fields[0] not in {"100644", "100755"}:
        raise QueryV6PackageError(f"query-v6 package Git mode is invalid: {path}")
    blob = subprocess.run(
        ["git", "show", f"{commit_sha}:{path}"],
        cwd=source_root,
        check=False,
        capture_output=True,
    )
    if blob.returncode or not blob.stdout:
        raise QueryV6PackageError(f"query-v6 package Git blob is unreadable: {path}")
    return blob.stdout, 0o555 if fields[0] == "100755" else 0o444


def _stable_runtime_file(
    path: Path,
    label: str,
    *,
    require_root_owned: bool,
    executable: bool = False,
) -> tuple[Path, bytes]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise QueryV6PackageError(f"{label} is unavailable") from exc
    _safe_ancestors(resolved.parent, require_root_owned=require_root_owned)
    try:
        path_before = resolved.lstat()
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(descriptor)
            raw = _read_bounded_descriptor(descriptor, MAX_ARCHIVE_BYTES)
            os.lseek(descriptor, 0, os.SEEK_SET)
            repeated = _read_bounded_descriptor(descriptor, MAX_ARCHIVE_BYTES)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = resolved.lstat()
    except OSError as exc:
        raise QueryV6PackageError(f"{label} is unavailable") from exc
    allowed = {0} if require_root_owned else {0, os.geteuid()}
    mode = stat.S_IMODE(path_before.st_mode)
    if (
        not stat.S_ISREG(path_before.st_mode)
        or path_before.st_nlink != 1
        or path_before.st_uid not in allowed
        or mode & 0o022
        or (executable and not mode & 0o111)
        or len(raw) > MAX_ARCHIVE_BYTES
        or raw != repeated
        or len(raw) != before.st_size
        or _stat_identity(path_before) != _stat_identity(before)
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(path_after)
    ):
        raise QueryV6PackageError(f"{label} custody is unsafe")
    return resolved, raw


def _interpreter_identity(
    python_executable: Path,
    *,
    require_root_owned: bool = True,
) -> tuple[str, str]:
    logical = Path(os.path.abspath(python_executable))
    _safe_ancestors(logical.parent, require_root_owned=require_root_owned)
    try:
        logical_before = logical.lstat()
    except OSError as exc:
        raise QueryV6PackageError("query-v6 Python interpreter is unavailable") from exc
    allowed = {0} if require_root_owned else {0, os.geteuid()}
    if (
        not (
            stat.S_ISREG(logical_before.st_mode) or stat.S_ISLNK(logical_before.st_mode)
        )
        or logical_before.st_uid not in allowed
        or logical_before.st_nlink != 1
    ):
        raise QueryV6PackageError("query-v6 Python interpreter custody is unsafe")
    resolved, raw = _stable_runtime_file(
        logical,
        "query-v6 Python interpreter",
        require_root_owned=require_root_owned,
        executable=True,
    )
    try:
        logical_after = logical.lstat()
    except OSError as exc:
        raise QueryV6PackageError("query-v6 Python interpreter is unavailable") from exc
    if _stat_identity(logical_before) != _stat_identity(logical_after):
        raise QueryV6PackageError("query-v6 Python interpreter changed while read")
    if not stat.S_ISLNK(logical_before.st_mode) and logical != resolved:
        raise QueryV6PackageError("query-v6 Python interpreter path is unsafe")
    if not raw:
        raise QueryV6PackageError("query-v6 Python interpreter custody is unsafe")
    return str(logical), _sha256(raw)


def dependency_closure(
    names: Iterable[str] = DEPENDENCY_NAMES,
    *,
    require_root_owned: bool = True,
) -> tuple[list[dict[str, str]], str]:
    records: list[dict[str, Any]] = []
    public: list[dict[str, str]] = []
    for name in sorted(names, key=str.casefold):
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise QueryV6PackageError(f"query-v6 dependency is absent: {name}") from exc
        normalized = distribution.metadata.get("Name", name)
        version = distribution.version
        distribution_root = Path(distribution.locate_file("")).resolve(strict=True)
        _safe_ancestors(
            distribution_root,
            require_root_owned=require_root_owned,
        )
        files: list[dict[str, Any]] = []
        for relative in sorted(distribution.files or (), key=lambda item: str(item)):
            path = Path(distribution.locate_file(relative))
            try:
                logical = Path(os.path.abspath(path))
                _safe_ancestors(
                    logical.parent,
                    require_root_owned=require_root_owned,
                )
                unresolved = logical.lstat()
                resolved = logical.resolve(strict=True)
                info = resolved.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
            except OSError as exc:
                raise QueryV6PackageError(
                    f"query-v6 dependency file is unavailable: {name}"
                ) from exc
            if not (
                stat.S_ISREG(unresolved.st_mode) or stat.S_ISLNK(unresolved.st_mode)
            ):
                continue
            allowed = {0} if require_root_owned else {0, os.geteuid()}
            if unresolved.st_uid not in allowed or unresolved.st_nlink != 1:
                raise QueryV6PackageError(
                    f"query-v6 dependency file custody is unsafe: {name}"
                )
            resolved, raw = _stable_runtime_file(
                logical,
                f"query-v6 dependency file: {name}",
                require_root_owned=require_root_owned,
            )
            files.append(
                {
                    "path": str(relative),
                    "absolute_path": str(resolved),
                    "size": len(raw),
                    "sha256": _sha256(raw),
                }
            )
        if not files:
            raise QueryV6PackageError(f"query-v6 dependency closure is empty: {name}")
        public.append({"name": normalized, "version": version})
        records.append({"name": normalized, "version": version, "files": files})
    return public, _sha256(canonical_json(records))


def build_package(
    source_root: Path,
    commit_sha: str,
    *,
    python_executable: Path = Path(sys.executable),
    require_root_owned_runtime: bool = True,
) -> tuple[bytes, bytes, dict[str, Any]]:
    exact_commit = _resolve_commit(source_root, commit_sha)
    blobs = {
        path: _git_blob(source_root, exact_commit, path)
        for path in sorted(SOURCE_PATHS)
    }
    python_path, python_sha256 = _interpreter_identity(
        python_executable,
        require_root_owned=require_root_owned_runtime,
    )
    try:
        running_python = os.path.abspath(sys.executable)
    except OSError as exc:
        raise QueryV6PackageError("query-v6 running Python is unavailable") from exc
    if python_path != running_python:
        raise QueryV6PackageError(
            "query-v6 package must be built by the exact pinned Python interpreter"
        )
    dependencies, closure_sha256 = dependency_closure(
        require_root_owned=require_root_owned_runtime
    )
    entries = [
        {
            "path": path,
            "sha256": _sha256(raw),
            "size": len(raw),
            "mode": mode,
        }
        for path, (raw, mode) in blobs.items()
    ]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "package_id": "PENDING_PACKAGE_ID",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "source_commit_sha": exact_commit,
        "entrypoint": ENTRYPOINT,
        "entries": entries,
        "python_executable_path": python_path,
        "python_executable_sha256": python_sha256,
        "python_dependencies": dependencies,
        "python_dependency_closure_sha256": closure_sha256,
        "deterministic_archive": True,
        "v6_only_preconnect_adapter": True,
        "legacy_authority_reused": False,
        "dsn_secret_included": False,
        "network_accessed": False,
        "authority_granted": False,
        "production_authorized": False,
    }
    identity = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = "query-v6-preconnect-" + _sha256(canonical_json(identity))
    _verify_package_manifest(payload)
    manifest_raw = canonical_json(payload)
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT
    ) as archive:
        members = [(MANIFEST_ARCHIVE_PATH, manifest_raw, 0o444)] + [
            (path, raw, mode) for path, (raw, mode) in blobs.items()
        ]
        for path, raw, mode in members:
            member = tarfile.TarInfo(path)
            member.size = len(raw)
            member.mode = mode
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = 0
            member.type = tarfile.REGTYPE
            archive.addfile(member, io.BytesIO(raw))
    archive_raw = output.getvalue()
    if len(archive_raw) > MAX_ARCHIVE_BYTES:
        raise QueryV6PackageError("query-v6 package archive is too large")
    return archive_raw, manifest_raw, payload


def _safe_ancestors(path: Path, *, require_root_owned: bool) -> None:
    if not path.is_absolute():
        raise QueryV6PackageError("query-v6 installation path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise QueryV6PackageError(
                "query-v6 installation ancestor is unavailable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise QueryV6PackageError("query-v6 installation ancestor is unsafe")
        allowed = {0} if require_root_owned else {0, os.geteuid()}
        sticky_test_parent = (
            not require_root_owned
            and info.st_uid == 0
            and bool(stat.S_IMODE(info.st_mode) & stat.S_ISVTX)
        )
        if not sticky_test_parent and (
            info.st_uid not in allowed or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise QueryV6PackageError("query-v6 installation ancestor is unsafe")


def _read_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV6PackageError(f"{label} is invalid") from exc
    if not isinstance(payload, dict):
        raise QueryV6PackageError(f"{label} must be an object")
    return raw, payload


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_bounded_descriptor(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_root_install_input(
    path: Path,
    label: str,
    *,
    require_root_owned: bool,
    limit: int = 8 * 1024 * 1024,
) -> bytes:
    _safe_ancestors(path.parent, require_root_owned=require_root_owned)
    try:
        path_before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(descriptor)
            raw = _read_bounded_descriptor(descriptor, limit)
            os.lseek(descriptor, 0, os.SEEK_SET)
            repeated = _read_bounded_descriptor(descriptor, limit)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise QueryV6PackageError(f"{label} is unavailable") from exc
    allowed = {0} if require_root_owned else {0, os.geteuid()}
    if (
        stat.S_ISLNK(path_before.st_mode)
        or not stat.S_ISREG(path_before.st_mode)
        or path_before.st_nlink != 1
        or path_before.st_uid not in allowed
        or stat.S_IMODE(path_before.st_mode) & 0o022
        or not raw
        or len(raw) > limit
        or len(raw) != before.st_size
        or raw != repeated
        or _stat_identity(path_before) != _stat_identity(before)
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(path_after)
    ):
        raise QueryV6PackageError(f"{label} custody is unsafe")
    return raw


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_package_manifest(
    payload: dict[str, Any], expected_manifest_sha256: str | None = None
) -> None:
    _validate(payload, PACKAGE_SCHEMA_PATH, "query-v6 package manifest")
    paths = [entry["path"] for entry in payload["entries"]]
    if paths != sorted(SOURCE_PATHS) or len(paths) != len(set(paths)):
        raise QueryV6PackageError("query-v6 package source closure mismatch")
    dependency_names = sorted(
        item["name"].casefold().replace("_", "-")
        for item in payload["python_dependencies"]
    )
    if dependency_names != sorted(DEPENDENCY_NAMES):
        raise QueryV6PackageError("query-v6 package dependency set mismatch")
    identity = {key: value for key, value in payload.items() if key != "package_id"}
    expected_id = "query-v6-preconnect-" + _sha256(canonical_json(identity))
    if payload["package_id"] != expected_id:
        raise QueryV6PackageError("query-v6 package identity mismatch")
    if expected_manifest_sha256 is not None and not hmac.compare_digest(
        _sha256(canonical_json(payload)), expected_manifest_sha256
    ):
        raise QueryV6PackageError("query-v6 package manifest binding mismatch")


def _archive_members(archive_raw: bytes, payload: dict[str, Any]) -> dict[str, bytes]:
    expected = {entry["path"]: entry for entry in payload["entries"]}
    expected[MANIFEST_ARCHIVE_PATH] = {
        "sha256": _sha256(canonical_json(payload)),
        "size": len(canonical_json(payload)),
        "mode": 0o444,
    }
    result: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
            for member in archive.getmembers():
                pure = PurePosixPath(member.name)
                if (
                    member.name not in expected
                    or member.name in result
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                    or not member.isreg()
                    or member.uid != 0
                    or member.gid != 0
                    or member.mtime != 0
                    or stat.S_IMODE(member.mode) != expected[member.name]["mode"]
                ):
                    raise QueryV6PackageError(
                        "query-v6 package archive member is unsafe"
                    )
                handle = archive.extractfile(member)
                raw = handle.read() if handle is not None else b""
                if (
                    len(raw) != expected[member.name]["size"]
                    or _sha256(raw) != expected[member.name]["sha256"]
                ):
                    raise QueryV6PackageError(
                        "query-v6 package archive member mismatch"
                    )
                result[member.name] = raw
    except (tarfile.TarError, OSError) as exc:
        raise QueryV6PackageError("query-v6 package archive is invalid") from exc
    if set(result) != set(expected):
        raise QueryV6PackageError("query-v6 package archive closure is incomplete")
    return result


def preflight_installed_runtime(
    package_manifest_path: Path,
    *,
    expected_manifest_sha256: str,
    expected_package_root_identity_sha256: str | None = None,
    expected_python_executable_sha256: str,
    expected_dependency_closure_sha256: str,
    require_root_owned: bool = True,
) -> dict[str, Any]:
    _safe_ancestors(package_manifest_path.parent, require_root_owned=require_root_owned)
    raw, payload = _read_json(
        package_manifest_path, "query-v6 installed package manifest"
    )
    _verify_package_manifest(payload, expected_manifest_sha256)
    if _sha256(canonical_json(payload)) != _sha256(raw):
        raise QueryV6PackageError(
            "query-v6 installed package manifest is not canonical"
        )
    package_root = package_manifest_path.parent
    try:
        root_info = package_root.lstat()
    except OSError as exc:
        raise QueryV6PackageError("query-v6 package root is unavailable") from exc
    for entry in payload["entries"]:
        path = package_root / entry["path"]
        try:
            unresolved = path.lstat()
            raw_entry = path.read_bytes()
        except OSError as exc:
            raise QueryV6PackageError(
                "query-v6 installed package entry is unavailable"
            ) from exc
        if (
            stat.S_ISLNK(unresolved.st_mode)
            or not stat.S_ISREG(unresolved.st_mode)
            or unresolved.st_nlink != 1
            or stat.S_IMODE(unresolved.st_mode) != entry["mode"]
            or (
                require_root_owned
                and (unresolved.st_uid != 0 or unresolved.st_gid != 0)
            )
            or len(raw_entry) != entry["size"]
            or _sha256(raw_entry) != entry["sha256"]
        ):
            raise QueryV6PackageError("query-v6 installed package entry mismatch")
    python_path, python_sha256 = _interpreter_identity(
        Path(payload["python_executable_path"]),
        require_root_owned=require_root_owned,
    )
    try:
        running_python = os.path.abspath(sys.executable)
    except OSError as exc:
        raise QueryV6PackageError("query-v6 running Python is unavailable") from exc
    if (
        python_path != payload["python_executable_path"]
        or python_path != running_python
        or python_sha256 != payload["python_executable_sha256"]
        or python_sha256 != expected_python_executable_sha256
    ):
        raise QueryV6PackageError("query-v6 Python interpreter binding mismatch")
    dependencies, closure = dependency_closure(
        (item["name"] for item in payload["python_dependencies"]),
        require_root_owned=require_root_owned,
    )
    if (
        dependencies != payload["python_dependencies"]
        or closure != payload["python_dependency_closure_sha256"]
        or closure != expected_dependency_closure_sha256
    ):
        raise QueryV6PackageError("query-v6 Python dependency closure mismatch")
    package_root_identity_sha256 = _sha256(
        canonical_json(
            {
                "absolute_path": str(package_root),
                "device": root_info.st_dev,
                "inode": root_info.st_ino,
                "owner_uid": root_info.st_uid,
                "owner_gid": root_info.st_gid,
                "mode": stat.S_IMODE(root_info.st_mode),
                "entries": payload["entries"],
            }
        )
    )
    if (
        expected_package_root_identity_sha256 is not None
        and package_root_identity_sha256 != expected_package_root_identity_sha256
    ):
        raise QueryV6PackageError("query-v6 package root identity mismatch")
    return {
        "package_id": payload["package_id"],
        "package_manifest_sha256": _sha256(canonical_json(payload)),
        "package_root_identity_sha256": package_root_identity_sha256,
        "entrypoint": str(package_root / payload["entrypoint"]),
        "python_executable_path": python_path,
        "python_executable_sha256": python_sha256,
        "python_dependency_closure_sha256": closure,
    }


def build_active_pin_payload(
    base_pin_manifest: Mapping[str, Any],
    package_payload: Mapping[str, Any],
    preflight: Mapping[str, str],
) -> dict[str, Any]:
    allowed_base_fields = {
        "generation_id",
        "executable_keyring_sha256",
        "questdb_build_sha256",
    }
    if set(base_pin_manifest) != allowed_base_fields:
        raise QueryV6PackageError("query-v6 base pins contain non-local fields")
    entry_hashes = {
        entry["path"]: entry["sha256"] for entry in package_payload["entries"]
    }
    try:
        pin_payload = {
            **base_pin_manifest,
            "schema_version": PIN_SET_VERSION,
            **{field: entry_hashes[path] for field, path in PIN_SOURCE_PATHS.items()},
            "execution_adapter_sha256": entry_hashes[ENTRYPOINT],
            "execution_adapter_absolute_path": preflight["entrypoint"],
            "adapter_package_manifest_absolute_path": preflight["manifest_path"],
            "adapter_package_manifest_sha256": preflight["package_manifest_sha256"],
            "adapter_package_root_identity_sha256": preflight[
                "package_root_identity_sha256"
            ],
            "python_executable_path": preflight["python_executable_path"],
            "python_executable_sha256": preflight["python_executable_sha256"],
            "python_dependency_closure_sha256": preflight[
                "python_dependency_closure_sha256"
            ],
        }
    except (KeyError, TypeError) as exc:
        raise QueryV6PackageError(
            "query-v6 installed pin closure is incomplete"
        ) from exc
    _validate(pin_payload, PIN_SCHEMA_PATH, "query-v6 active pin set")
    return pin_payload


def install_package(
    archive_path: Path,
    manifest_path: Path,
    install_root: Path,
    active_pin_root: Path,
    expected_manifest_sha256: str,
    expected_source_commit_sha: str,
    generation_id: str,
    executable_keyring_path: Path,
    questdb_build_identity_path: Path,
    *,
    require_root: bool = True,
) -> dict[str, Any]:
    if require_root and os.geteuid() != 0:
        raise QueryV6PackageError("query-v6 package installation requires root")
    require_root_owned = require_root
    for parent in {install_root.parent, active_pin_root.parent}:
        _safe_ancestors(parent, require_root_owned=require_root_owned)
    if install_root.exists() or active_pin_root.exists():
        raise QueryV6PackageError("query-v6 installation destinations must be absent")
    keyring_raw = _read_root_install_input(
        executable_keyring_path,
        "query-v6 executable keyring",
        require_root_owned=require_root_owned,
    )
    try:
        keyring = json.loads(keyring_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV6PackageError("query-v6 executable keyring is invalid") from exc
    if not isinstance(keyring, dict):
        raise QueryV6PackageError("query-v6 executable keyring must be an object")
    questdb_build_raw = _read_root_install_input(
        questdb_build_identity_path,
        "query-v6 QuestDB build identity",
        require_root_owned=require_root_owned,
    )
    try:
        questdb_build = questdb_build_raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise QueryV6PackageError("query-v6 QuestDB build identity is invalid") from exc
    if not questdb_build or "\n" in questdb_build or "\r" in questdb_build:
        raise QueryV6PackageError("query-v6 QuestDB build identity is invalid")
    base_pin_manifest = {
        "generation_id": generation_id,
        "executable_keyring_sha256": _sha256(canonical_json(keyring)),
        "questdb_build_sha256": _sha256(questdb_build.encode("utf-8")),
    }
    archive_raw = _read_root_install_input(
        archive_path,
        "query-v6 package archive",
        require_root_owned=require_root_owned,
        limit=MAX_ARCHIVE_BYTES,
    )
    manifest_raw = _read_root_install_input(
        manifest_path,
        "query-v6 package manifest",
        require_root_owned=require_root_owned,
    )
    try:
        payload = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV6PackageError("query-v6 package manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise QueryV6PackageError("query-v6 package manifest must be an object")
    if manifest_raw != canonical_json(payload):
        raise QueryV6PackageError("query-v6 package manifest must be canonical")
    if (
        len(expected_manifest_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_manifest_sha256)
        or not hmac.compare_digest(_sha256(manifest_raw), expected_manifest_sha256)
    ):
        raise QueryV6PackageError("query-v6 approved package manifest mismatch")
    if (
        len(expected_source_commit_sha) != 40
        or any(c not in "0123456789abcdef" for c in expected_source_commit_sha)
        or payload.get("source_commit_sha") != expected_source_commit_sha
    ):
        raise QueryV6PackageError("query-v6 approved source commit mismatch")
    _verify_package_manifest(payload, expected_manifest_sha256)
    members = _archive_members(archive_raw, payload)
    staging = Path(
        tempfile.mkdtemp(prefix=".query-v6-install-", dir=install_root.parent)
    )
    try:
        for name, raw in members.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with target.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            mode = (
                0o444
                if name == MANIFEST_ARCHIVE_PATH
                else next(
                    entry["mode"]
                    for entry in payload["entries"]
                    if entry["path"] == name
                )
            )
            target.chmod(mode)
        for directory in sorted(
            (path for path in staging.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        os.rename(staging, install_root)
        install_root.chmod(0o555)
        _fsync_directory(install_root.parent)
        package_manifest_installed = install_root / MANIFEST_ARCHIVE_PATH
        preflight = preflight_installed_runtime(
            package_manifest_installed,
            expected_manifest_sha256=_sha256(manifest_raw),
            expected_python_executable_sha256=payload["python_executable_sha256"],
            expected_dependency_closure_sha256=payload[
                "python_dependency_closure_sha256"
            ],
            require_root_owned=require_root_owned,
        )
        preflight = {**preflight, "manifest_path": str(package_manifest_installed)}
        pin_payload = build_active_pin_payload(base_pin_manifest, payload, preflight)
        active_pin_root.mkdir(mode=0o755)
        _fsync_directory(active_pin_root.parent)
        pin_path = active_pin_root / "pin-set.manifest.json"
        with pin_path.open("xb") as handle:
            handle.write(canonical_json(pin_payload))
            handle.flush()
            os.fsync(handle.fileno())
        pin_path.chmod(0o444)
        _fsync_directory(active_pin_root)
        return pin_payload
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--source-commit-sha", required=True)
    build.add_argument("--archive-output", type=Path, required=True)
    build.add_argument("--manifest-output", type=Path, required=True)
    install = sub.add_parser("install")
    install.add_argument("--archive", type=Path, required=True)
    install.add_argument("--manifest", type=Path, required=True)
    install.add_argument("--install-root", type=Path, required=True)
    install.add_argument("--active-pin-root", type=Path, required=True)
    install.add_argument("--expected-manifest-sha256", required=True)
    install.add_argument("--expected-source-commit-sha", required=True)
    install.add_argument("--generation-id", required=True)
    install.add_argument("--executable-keyring", type=Path, required=True)
    install.add_argument("--questdb-build-identity", type=Path, required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--package-manifest", type=Path, required=True)
    preflight.add_argument("--expected-manifest-sha256", required=True)
    preflight.add_argument("--expected-python-executable-sha256", required=True)
    preflight.add_argument("--expected-dependency-closure-sha256", required=True)
    return parser.parse_args()


def _write_create_only(path: Path, raw: bytes, mode: int = 0o444) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)


def main() -> int:
    args = parse_args()
    try:
        if args.command == "build":
            archive, manifest, payload = build_package(
                args.source_root, args.source_commit_sha
            )
            _write_create_only(args.archive_output, archive)
            _write_create_only(args.manifest_output, manifest)
            print(f"package_id={payload['package_id']}")
        elif args.command == "install":
            pins = install_package(
                args.archive,
                args.manifest,
                args.install_root,
                args.active_pin_root,
                args.expected_manifest_sha256,
                args.expected_source_commit_sha,
                args.generation_id,
                args.executable_keyring,
                args.questdb_build_identity,
            )
            print(f"pin_set_generation_id={pins['generation_id']}")
        else:
            report = preflight_installed_runtime(
                args.package_manifest,
                expected_manifest_sha256=args.expected_manifest_sha256,
                expected_python_executable_sha256=args.expected_python_executable_sha256,
                expected_dependency_closure_sha256=args.expected_dependency_closure_sha256,
            )
            print(json.dumps(report, sort_keys=True))
    except (OSError, QueryV6PackageError, ValueError) as exc:
        print(f"query-v6 package operation failed: {exc}", file=sys.stderr)
        return 2
    print("dsn_secret_read=false")
    print("network_accessed=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
