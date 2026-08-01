"""Isolated, independently pinned query-v5 code-only overlay launcher."""

from __future__ import annotations

import sys


RUNNING_AS_SCRIPT = __name__ == "__main__"


def _require_isolated_startup() -> None:
    flags = sys.flags
    if not (
        flags.isolated == 1
        and flags.no_site == 1
        and flags.no_user_site == 1
        and flags.ignore_environment == 1
        and flags.dont_write_bytecode == 1
    ):
        raise SystemExit(
            "query-v5 launcher requires a fixed interpreter with -I -S -s -E -B"
        )


if RUNNING_AS_SCRIPT:
    _require_isolated_startup()


import argparse  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path, PurePosixPath  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
from typing import Any  # noqa: E402


SCHEMA_VERSION = "commodity_c_fast_t1_query_v5_runtime_pin_set_v1"
STATUS = "QUERY_V5_OVERLAY_RUNTIME_IDENTITY_VERIFIED_CODE_ONLY_BLOCKED"
INSPECTION_STATUS = "QUERY_V5_OVERLAY_RUNTIME_IDENTITY_INSPECTED_NONAUTHORITY"
PIN_ROOT = Path("/run/c-fast-t1-query-v5-pins")
PIN_MANIFEST_PATH = PIN_ROOT / "pin-set.manifest.json"
SOURCE_ROOT = Path("/opt/c-fast-query-v5/release")
LAUNCHER_PATH = Path(__file__).resolve()
INTERPRETER_PATH = Path("/usr/local/bin/python3.12")
LOADED_EXECUTABLE_PATH = Path("/proc/self/exe")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_INTERPRETER_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 32
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GENERATION_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
EXPECTED_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "runtime_image_digest",
        "launcher_sha256",
        "python_executable_path",
        "python_executable_sha256",
        "source_root_path",
        "source_root_identity_sha256",
        "source_closure_manifest_sha256",
        "code_only_blocked",
        "authority_granted",
    }
)


class QueryV5LauncherError(RuntimeError):
    """The query-v5 code-only runtime identity failed closed."""


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


def _effective_access(path: Path, mode: int) -> bool:
    if os.access in os.supports_effective_ids:
        return os.access(path, mode, effective_ids=True)
    return os.access(path, mode)


def _identity(info: os.stat_result) -> tuple[int, ...]:
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


def _require_safe(
    path: Path,
    info: os.stat_result,
    label: str,
    *,
    regular: bool,
    require_root_owned: bool,
) -> None:
    expected_owners = {0} if require_root_owned else {0, os.geteuid()}
    if info.st_uid not in expected_owners:
        raise QueryV5LauncherError(f"{label} owner is unsafe")
    if info.st_mode & 0o022:
        raise QueryV5LauncherError(f"{label} is group/world writable")
    if regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise QueryV5LauncherError(f"{label} must be one regular hardlink-free file")
    if not regular and not stat.S_ISDIR(info.st_mode):
        raise QueryV5LauncherError(f"{label} must be a directory")
    if not regular and not _effective_access(path, os.R_OK | os.X_OK):
        raise QueryV5LauncherError(f"{label} is not enumerable by the runtime")
    if require_root_owned:
        if os.geteuid() == 0:
            raise QueryV5LauncherError("query-v5 runtime must execute as non-root")
        if _effective_access(path, os.W_OK):
            raise QueryV5LauncherError(f"{label} is writable by the runtime")


def _require_safe_ancestor_chain(
    path: Path,
    label: str,
    *,
    require_root_owned: bool,
) -> None:
    if not path.is_absolute():
        raise QueryV5LauncherError(f"{label} path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise QueryV5LauncherError(f"cannot inspect {label} ancestor") from exc
        if stat.S_ISLNK(info.st_mode):
            raise QueryV5LauncherError(f"{label} ancestor contains a symlink")
        _require_safe(
            current,
            info,
            f"{label} ancestor",
            regular=False,
            require_root_owned=require_root_owned,
        )


def _stable_read_with_identity(
    path: Path,
    label: str,
    *,
    limit: int,
    require_root_owned: bool,
) -> tuple[bytes, os.stat_result]:
    _require_safe_ancestor_chain(
        path.parent,
        label,
        require_root_owned=require_root_owned,
    )
    try:
        before_path = path.lstat()
        _require_safe(
            path,
            before_path,
            label,
            regular=True,
            require_root_owned=require_root_owned,
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            _require_safe(
                path,
                before,
                label,
                regular=True,
                require_root_owned=require_root_owned,
            )
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise QueryV5LauncherError(f"{label} exceeds its size limit")
                chunks.append(chunk)
            raw = b"".join(chunks)
            os.lseek(descriptor, 0, os.SEEK_SET)
            verification = b""
            while len(verification) < len(raw):
                chunk = os.read(
                    descriptor, min(64 * 1024, len(raw) - len(verification))
                )
                if not chunk:
                    break
                verification += chunk
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
    except OSError as exc:
        raise QueryV5LauncherError(f"cannot read {label}") from exc
    if (
        _identity(before_path) != _identity(before)
        or _identity(before) != _identity(after)
        or _identity(after) != _identity(after_path)
        or raw != verification
        or len(raw) != before.st_size
    ):
        raise QueryV5LauncherError(f"{label} changed while being read")
    return raw, after


def _stable_read(
    path: Path,
    label: str,
    *,
    limit: int,
    require_root_owned: bool,
) -> bytes:
    raw, _info = _stable_read_with_identity(
        path,
        label,
        limit=limit,
        require_root_owned=require_root_owned,
    )
    return raw


def _read_fd_twice(descriptor: int, label: str, *, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise QueryV5LauncherError(f"{label} exceeds its size limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    os.lseek(descriptor, 0, os.SEEK_SET)
    verification = b""
    while len(verification) < len(raw):
        chunk = os.read(
            descriptor,
            min(64 * 1024, len(raw) - len(verification)),
        )
        if not chunk:
            break
        verification += chunk
    if raw != verification:
        raise QueryV5LauncherError(f"{label} changed while being read")
    return raw


def _stable_loaded_executable(
    path: Path,
    *,
    injected: bool,
    require_root_owned: bool,
) -> tuple[bytes, os.stat_result]:
    if injected:
        return _stable_read_with_identity(
            path,
            "query-v5 loaded executable test input",
            limit=MAX_INTERPRETER_BYTES,
            require_root_owned=require_root_owned,
        )
    if path != LOADED_EXECUTABLE_PATH or sys.platform != "linux":
        raise QueryV5LauncherError(
            "production query-v5 runtime requires Linux /proc/self/exe"
        )
    try:
        before_link = os.readlink(path)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            _require_safe(
                path,
                before,
                "query-v5 loaded executable",
                regular=True,
                require_root_owned=require_root_owned,
            )
            raw = _read_fd_twice(
                descriptor,
                "query-v5 loaded executable",
                limit=MAX_INTERPRETER_BYTES,
            )
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_link = os.readlink(path)
    except OSError as exc:
        raise QueryV5LauncherError(
            "cannot read Linux query-v5 loaded executable"
        ) from exc
    if (
        before_link != after_link
        or _identity(before) != _identity(after)
        or len(raw) != before.st_size
    ):
        raise QueryV5LauncherError(
            "query-v5 loaded executable changed while being verified"
        )
    return raw, after


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise QueryV5LauncherError("pin manifest contains a duplicate key")
        output[key] = value
    return output


def _reject_constant(value: str) -> Any:
    raise QueryV5LauncherError(f"pin manifest contains invalid constant {value}")


def load_pin_manifest(
    path: Path = PIN_MANIFEST_PATH,
    *,
    require_root_owned: bool = True,
) -> tuple[bytes, dict[str, Any]]:
    raw = _stable_read(
        path,
        "query-v5 pin manifest",
        limit=MAX_MANIFEST_BYTES,
        require_root_owned=require_root_owned,
    )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV5LauncherError("query-v5 pin manifest is invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != EXPECTED_FIELDS:
        raise QueryV5LauncherError("query-v5 pin manifest fields are invalid")
    if raw != canonical_json(payload):
        raise QueryV5LauncherError("query-v5 pin manifest is not canonical JSON")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise QueryV5LauncherError("query-v5 pin manifest namespace is invalid")
    if GENERATION_RE.fullmatch(str(payload["generation_id"])) is None:
        raise QueryV5LauncherError("query-v5 pin generation is invalid")
    for field in (
        "launcher_sha256",
        "python_executable_sha256",
        "source_root_identity_sha256",
        "source_closure_manifest_sha256",
    ):
        if SHA256_RE.fullmatch(str(payload[field])) is None:
            raise QueryV5LauncherError(f"{field} is invalid")
    if OCI_DIGEST_RE.fullmatch(str(payload["runtime_image_digest"])) is None:
        raise QueryV5LauncherError("runtime_image_digest is invalid")
    if (
        payload["code_only_blocked"] is not True
        or payload["authority_granted"] is not False
    ):
        raise QueryV5LauncherError("query-v5 pin manifest attempts to grant authority")
    return raw, payload


def _relative(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise QueryV5LauncherError("source closure escaped its root") from exc
    parsed = PurePosixPath(relative)
    if not relative or parsed.is_absolute() or ".." in parsed.parts:
        raise QueryV5LauncherError("source closure path is invalid")
    return relative


def source_closure(
    root: Path = SOURCE_ROOT,
    *,
    require_root_owned: bool = True,
) -> tuple[str, str, dict[str, Any]]:
    _require_safe_ancestor_chain(
        root.parent,
        "query-v5 source root",
        require_root_owned=require_root_owned,
    )

    def scan_once() -> tuple[list[dict[str, Any]], os.stat_result]:
        try:
            root_info = root.lstat()
        except OSError as exc:
            raise QueryV5LauncherError("query-v5 source root is unavailable") from exc
        _require_safe(
            root,
            root_info,
            "query-v5 source root",
            regular=False,
            require_root_owned=require_root_owned,
        )
        directory_snapshots: dict[Path, tuple[int, ...]] = {root: _identity(root_info)}
        records: list[dict[str, Any]] = []
        count = 0

        def walk_error(error: OSError) -> None:
            raise QueryV5LauncherError(
                "cannot enumerate query-v5 source directory"
            ) from error

        for current, directories, files in os.walk(
            root,
            topdown=True,
            onerror=walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            try:
                current_info = current_path.lstat()
            except OSError as exc:
                raise QueryV5LauncherError(
                    "cannot stat query-v5 source directory"
                ) from exc
            _require_safe(
                current_path,
                current_info,
                "query-v5 source directory",
                regular=False,
                require_root_owned=require_root_owned,
            )
            directory_snapshots.setdefault(current_path, _identity(current_info))
            directories.sort()
            files.sort()
            for name in [*directories, *files]:
                count += 1
                if count > MAX_ENTRIES:
                    raise QueryV5LauncherError("query-v5 source closure is too large")
                path = current_path / name
                try:
                    info = path.lstat()
                except OSError as exc:
                    raise QueryV5LauncherError(
                        "cannot stat query-v5 source closure"
                    ) from exc
                if stat.S_ISLNK(info.st_mode):
                    raise QueryV5LauncherError(
                        "query-v5 source closure contains a symlink"
                    )
                relative = _relative(path, root)
                if stat.S_ISDIR(info.st_mode):
                    _require_safe(
                        path,
                        info,
                        f"query-v5 source directory {relative}",
                        regular=False,
                        require_root_owned=require_root_owned,
                    )
                    directory_snapshots[path] = _identity(info)
                    records.append(
                        {
                            "path": relative,
                            "kind": "directory",
                            "mode": stat.S_IMODE(info.st_mode),
                            "uid": info.st_uid,
                            "gid": info.st_gid,
                        }
                    )
                elif stat.S_ISREG(info.st_mode):
                    raw = _stable_read(
                        path,
                        f"query-v5 source file {relative}",
                        limit=MAX_FILE_BYTES,
                        require_root_owned=require_root_owned,
                    )
                    if name.endswith((".pyc", ".pyo")) or "__pycache__" in path.parts:
                        raise QueryV5LauncherError(
                            "query-v5 source closure contains bytecode"
                        )
                    records.append(
                        {
                            "path": relative,
                            "kind": "regular",
                            "sha256": _sha256(raw),
                            "size": len(raw),
                            "mode": stat.S_IMODE(info.st_mode),
                            "uid": info.st_uid,
                            "gid": info.st_gid,
                        }
                    )
                else:
                    raise QueryV5LauncherError(
                        "query-v5 source closure contains a special file"
                    )
            try:
                current_after = current_path.lstat()
            except OSError as exc:
                raise QueryV5LauncherError(
                    "query-v5 source directory disappeared during scan"
                ) from exc
            if _identity(current_info) != _identity(current_after):
                raise QueryV5LauncherError(
                    "query-v5 source directory changed during scan"
                )
        for path, expected_identity in directory_snapshots.items():
            try:
                actual_identity = _identity(path.lstat())
            except OSError as exc:
                raise QueryV5LauncherError(
                    "query-v5 source directory disappeared after scan"
                ) from exc
            if actual_identity != expected_identity:
                raise QueryV5LauncherError(
                    "query-v5 source closure changed after directory scan"
                )
        return records, root_info

    records, root_info = scan_once()
    verification_records, verification_root_info = scan_once()
    if records != verification_records or _identity(root_info) != _identity(
        verification_root_info
    ):
        raise QueryV5LauncherError(
            "query-v5 source closure changed between complete scans"
        )
    manifest = {
        "schema_version": "commodity_c_fast_t1_query_v5_source_closure_v1",
        "entries": records,
    }
    # Device/inode/timestamps are intentionally excluded: an OCI extraction
    # assigns them at deployment time. The stable identity is the exact path,
    # ownership/mode contract and byte closure.
    root_identity = {
        "schema_version": "commodity_c_fast_t1_query_v5_source_root_identity_v1",
        "path": str(root),
        "uid": root_info.st_uid,
        "gid": root_info.st_gid,
        "mode": stat.S_IMODE(root_info.st_mode),
        "source_closure_manifest_sha256": _sha256(canonical_json(manifest)),
    }
    return (
        _sha256(canonical_json(root_identity)),
        _sha256(canonical_json(manifest)),
        manifest,
    )


def _inspect_runtime_identity(
    runtime_image_digest: str,
    *,
    pin_manifest_path: Path = PIN_MANIFEST_PATH,
    launcher_path: Path = LAUNCHER_PATH,
    interpreter_path: Path = INTERPRETER_PATH,
    source_root: Path = SOURCE_ROOT,
    reported_executable_path: Path | None = None,
    loaded_executable_path: Path | None = None,
    require_root_owned: bool = True,
) -> dict[str, Any]:
    _raw, pins = load_pin_manifest(
        pin_manifest_path,
        require_root_owned=require_root_owned,
    )
    launcher_raw = _stable_read(
        launcher_path,
        "query-v5 launcher",
        limit=MAX_FILE_BYTES,
        require_root_owned=require_root_owned,
    )
    interpreter_raw, interpreter_info = _stable_read_with_identity(
        interpreter_path,
        "query-v5 Python interpreter",
        limit=MAX_INTERPRETER_BYTES,
        require_root_owned=require_root_owned,
    )
    reported = Path(
        sys.executable if reported_executable_path is None else reported_executable_path
    )
    loaded = (
        LOADED_EXECUTABLE_PATH
        if loaded_executable_path is None
        else loaded_executable_path
    )
    loaded_raw, loaded_info = _stable_loaded_executable(
        loaded,
        injected=loaded_executable_path is not None,
        require_root_owned=require_root_owned,
    )
    try:
        if reported.resolve(strict=True) != interpreter_path.resolve(strict=True):
            raise QueryV5LauncherError(
                "query-v5 reported executable is not the pinned interpreter"
            )
        if not os.path.samefile(reported, interpreter_path):
            raise QueryV5LauncherError("query-v5 reported interpreter identity changed")
        if not os.path.samefile(loaded, interpreter_path):
            raise QueryV5LauncherError(
                "query-v5 loaded executable is not the pinned interpreter"
            )
    except OSError as exc:
        raise QueryV5LauncherError(
            "cannot verify the running query-v5 interpreter"
        ) from exc
    if (
        not hmac.compare_digest(_sha256(loaded_raw), _sha256(interpreter_raw))
        or loaded_raw != interpreter_raw
        or _identity(loaded_info) != _identity(interpreter_info)
    ):
        raise QueryV5LauncherError(
            "query-v5 loaded executable bytes or identity changed"
        )
    root_identity, closure_sha256, closure = source_closure(
        source_root,
        require_root_owned=require_root_owned,
    )
    expected = {
        "runtime_image_digest": runtime_image_digest,
        "launcher_sha256": _sha256(launcher_raw),
        "python_executable_path": str(interpreter_path),
        "python_executable_sha256": _sha256(interpreter_raw),
        "source_root_path": str(source_root),
        "source_root_identity_sha256": root_identity,
        "source_closure_manifest_sha256": closure_sha256,
    }
    for field, value in expected.items():
        if not hmac.compare_digest(str(pins[field]), value):
            raise QueryV5LauncherError(f"query-v5 runtime pin changed: {field}")
    if (
        launcher_path.resolve()
        != (source_root / "scripts/commodity_c_fast_t1_query_v5_launcher.py").resolve()
    ):
        raise QueryV5LauncherError("query-v5 launcher escaped the pinned source root")
    interpreter_verification, interpreter_after = _stable_read_with_identity(
        interpreter_path,
        "query-v5 Python interpreter final verification",
        limit=MAX_INTERPRETER_BYTES,
        require_root_owned=require_root_owned,
    )
    loaded_verification, loaded_after = _stable_loaded_executable(
        loaded,
        injected=loaded_executable_path is not None,
        require_root_owned=require_root_owned,
    )
    if (
        interpreter_raw != interpreter_verification
        or loaded_raw != loaded_verification
        or _identity(interpreter_info) != _identity(interpreter_after)
        or _identity(loaded_info) != _identity(loaded_after)
    ):
        raise QueryV5LauncherError(
            "query-v5 interpreter or loaded executable changed after verification"
        )
    return {
        "schema_version": "commodity_c_fast_t1_query_v5_runtime_identity_v1",
        "status": INSPECTION_STATUS,
        "generation_id": pins["generation_id"],
        **expected,
        "loaded_executable_path": str(loaded),
        "loaded_executable_sha256": _sha256(loaded_raw),
        "source_closure_entries": len(closure["entries"]),
        "isolated_flags_verified": False,
        "code_only_blocked": True,
        "authority_granted": False,
    }


def verify_runtime_identity(
    runtime_image_digest: str,
) -> dict[str, Any]:
    _require_isolated_startup()
    inspected = _inspect_runtime_identity(
        runtime_image_digest,
        pin_manifest_path=PIN_MANIFEST_PATH,
        launcher_path=LAUNCHER_PATH,
        interpreter_path=INTERPRETER_PATH,
        source_root=SOURCE_ROOT,
        reported_executable_path=None,
        loaded_executable_path=None,
        require_root_owned=True,
    )
    return {
        **inspected,
        "status": STATUS,
        "isolated_flags_verified": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image-digest", required=True)
    parser.add_argument("--verify-code-only", action="store_true", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify_runtime_identity(args.runtime_image_digest)
        # Re-read every pin and source byte after deriving the result. There is
        # deliberately no import or child launch after this check in v1.
        verification = verify_runtime_identity(args.runtime_image_digest)
        if result != verification:
            raise QueryV5LauncherError(
                "query-v5 runtime identity changed after verification"
            )
    except (OSError, QueryV5LauncherError, ValueError) as exc:
        print(f"query-v5 code-only launcher blocked: {exc}", file=sys.stderr)
        return 2
    print(f"status={result['status']}")
    print("runtime_execution_ready=false")
    print("network_authorized=false")
    print("production_query_authorized=false")
    print("authority_granted=false")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
