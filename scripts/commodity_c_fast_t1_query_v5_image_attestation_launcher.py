"""Isolated query-v5 launcher whose runtime trust is established externally."""

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
            "query-v5 image attestation launcher requires a fixed interpreter "
            "with -I -S -s -E -B"
        )


if RUNNING_AS_SCRIPT:
    _require_isolated_startup()


# CPython loads path-backed codec modules before executing this file.  This
# bootstrap is therefore defense in depth only: it checks the remaining runtime
# closure before importing additional path-backed modules, but it must never be
# represented as an independently trusted phase-zero verification.  Consumers
# must establish the exact attestation image RepoDigest outside this process.
if RUNNING_AS_SCRIPT:
    import os as _bootstrap_os

    if getattr(getattr(_bootstrap_os, "__spec__", None), "origin", None) != "frozen":
        raise SystemExit("query-v5 attestation requires CPython 3.12 frozen os")
else:
    _bootstrap_os = None


BOOTSTRAP_PIN_PATH_TEXT = "/run/c-fast-t1-query-v5-image-attestation-pins/bootstrap.pin"
BOOTSTRAP_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v5_image_attestation_bootstrap_pin_v1"
)
BOOTSTRAP_FIELDS = (
    "schema_version",
    "generation_id",
    "runtime_image_digest",
    "launcher_path",
    "launcher_sha256",
    "python_executable_path",
    "python_executable_sha256",
    "python_runtime_root_path",
    "python_runtime_closure_sha256",
    "native_runtime_root_path",
    "native_runtime_closure_sha256",
    "source_root_path",
    "bootstrap_source_closure_sha256",
    "dependency_root_path",
    "bootstrap_dependency_closure_sha256",
)
_BOOTSTRAP_K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


def _bootstrap_sha256(raw):
    mask = 0xFFFFFFFF
    values = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    padded = raw + b"\x80"
    padded += b"\x00" * ((55 - len(raw)) % 64)
    padded += (len(raw) * 8).to_bytes(8, "big")
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        words = [
            int.from_bytes(block[index : index + 4], "big") for index in range(0, 64, 4)
        ]
        for index in range(16, 64):
            old = words[index - 15]
            s0 = (
                ((old >> 7) | (old << 25)) ^ ((old >> 18) | (old << 14)) ^ (old >> 3)
            ) & mask
            old = words[index - 2]
            s1 = (
                ((old >> 17) | (old << 15)) ^ ((old >> 19) | (old << 13)) ^ (old >> 10)
            ) & mask
            words.append((words[index - 16] + s0 + words[index - 7] + s1) & mask)
        a, b, c, d, e, f, g, h = values
        for index in range(64):
            s1 = (
                ((e >> 6) | (e << 26))
                ^ ((e >> 11) | (e << 21))
                ^ ((e >> 25) | (e << 7))
            ) & mask
            choice = (e & f) ^ ((~e) & g)
            first = (h + s1 + choice + _BOOTSTRAP_K[index] + words[index]) & mask
            s0 = (
                ((a >> 2) | (a << 30))
                ^ ((a >> 13) | (a << 19))
                ^ ((a >> 22) | (a << 10))
            ) & mask
            majority = (a & b) ^ (a & c) ^ (b & c)
            second = (s0 + majority) & mask
            h, g, f, e, d, c, b, a = (
                g,
                f,
                e,
                (d + first) & mask,
                c,
                b,
                a,
                (first + second) & mask,
            )
        values = [
            (left + right) & mask
            for left, right in zip(values, (a, b, c, d, e, f, g, h))
        ]
    return b"".join(value.to_bytes(4, "big") for value in values).hex()


def _bootstrap_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _bootstrap_safe(path, info, *, directory):
    mode = info.st_mode
    kind = mode & 0o170000
    if info.st_uid != 0 or mode & 0o022:
        raise SystemExit("query-v5 bootstrap closure is not root-owned immutable")
    if directory:
        if kind != 0o040000:
            raise SystemExit("query-v5 bootstrap closure directory is invalid")
        access = _bootstrap_os.R_OK | _bootstrap_os.X_OK
    else:
        if kind != 0o100000 or info.st_nlink != 1:
            raise SystemExit("query-v5 bootstrap closure file is invalid")
        access = _bootstrap_os.R_OK
    kwargs = (
        {"effective_ids": True}
        if _bootstrap_os.access in _bootstrap_os.supports_effective_ids
        else {}
    )
    if not _bootstrap_os.access(path, access, **kwargs):
        raise SystemExit("query-v5 bootstrap closure is inaccessible")
    if _bootstrap_os.access(path, _bootstrap_os.W_OK, **kwargs):
        raise SystemExit("query-v5 bootstrap closure is runtime writable")


def _bootstrap_read(path, label):
    before = _bootstrap_os.lstat(path)
    _bootstrap_safe(path, before, directory=False)
    flags = _bootstrap_os.O_RDONLY | getattr(_bootstrap_os, "O_CLOEXEC", 0)
    flags |= getattr(_bootstrap_os, "O_NOFOLLOW", 0)
    descriptor = _bootstrap_os.open(path, flags)
    try:
        opened = _bootstrap_os.fstat(descriptor)
        if _bootstrap_identity(before) != _bootstrap_identity(opened):
            raise SystemExit(label + " changed before bootstrap read")
        chunks = []
        size = 0
        while True:
            chunk = _bootstrap_os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 536870912:
                raise SystemExit(label + " exceeds bootstrap size limit")
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = _bootstrap_os.fstat(descriptor)
        path_after = _bootstrap_os.lstat(path)
        if (
            len(raw) != opened.st_size
            or _bootstrap_identity(opened) != _bootstrap_identity(after)
            or _bootstrap_identity(opened) != _bootstrap_identity(path_after)
        ):
            raise SystemExit(label + " changed during bootstrap read")
        return raw
    finally:
        _bootstrap_os.close(descriptor)


def _bootstrap_proc_read(path, label):
    descriptor = _bootstrap_os.open(
        path,
        _bootstrap_os.O_RDONLY | getattr(_bootstrap_os, "O_CLOEXEC", 0),
    )
    try:
        chunks = []
        size = 0
        while True:
            chunk = _bootstrap_os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 16777216:
                raise SystemExit(label + " exceeds bootstrap size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        _bootstrap_os.close(descriptor)


def _bootstrap_tree_digest(root, *, allow_symlinks=False):
    root = _bootstrap_os.path.realpath(root)
    records = []
    count = 0

    def visit(directory, relative):
        nonlocal count
        before = _bootstrap_os.lstat(directory)
        _bootstrap_safe(directory, before, directory=True)
        with _bootstrap_os.scandir(directory) as iterator:
            children = sorted(
                iterator, key=lambda entry: _bootstrap_os.fsencode(entry.name)
            )
        for child in children:
            count += 1
            if count > 200000:
                raise SystemExit("query-v5 bootstrap closure has too many entries")
            child_path = child.path
            child_relative = child.name if not relative else relative + "/" + child.name
            encoded_path = _bootstrap_os.fsencode(child_relative).hex()
            info = child.stat(follow_symlinks=False)
            kind = info.st_mode & 0o170000
            if kind == 0o040000:
                _bootstrap_safe(child_path, info, directory=True)
                records.append(
                    "d|%s|%d|%d|%o\n"
                    % (encoded_path, info.st_uid, info.st_gid, info.st_mode & 0o7777)
                )
                visit(child_path, child_relative)
            elif kind == 0o100000:
                raw = _bootstrap_read(child_path, "bootstrap closure file")
                records.append(
                    "f|%s|%d|%d|%o|%d|%s\n"
                    % (
                        encoded_path,
                        info.st_uid,
                        info.st_gid,
                        info.st_mode & 0o7777,
                        len(raw),
                        _bootstrap_sha256(raw),
                    )
                )
            elif kind == 0o120000 and allow_symlinks:
                if info.st_uid != 0:
                    raise SystemExit(
                        "query-v5 bootstrap closure symlink owner is unsafe"
                    )
                target = _bootstrap_os.readlink(child_path)
                resolved = _bootstrap_os.path.realpath(child_path)
                if not _bootstrap_under(resolved, root):
                    raise SystemExit(
                        "query-v5 bootstrap closure symlink escapes its root"
                    )
                records.append(
                    "l|%s|%d|%d|%s\n"
                    % (
                        encoded_path,
                        info.st_uid,
                        info.st_gid,
                        _bootstrap_os.fsencode(target).hex(),
                    )
                )
            else:
                raise SystemExit(
                    "query-v5 bootstrap closure contains link or special file"
                )
        after = _bootstrap_os.lstat(directory)
        if _bootstrap_identity(before) != _bootstrap_identity(after):
            raise SystemExit("query-v5 bootstrap closure changed during scan")

    visit(root, "")
    return _bootstrap_sha256("".join(records).encode("ascii"))


def _bootstrap_directory_chain(path):
    current = _bootstrap_os.path.realpath(path)
    while True:
        info = _bootstrap_os.lstat(current)
        _bootstrap_safe(current, info, directory=True)
        parent = _bootstrap_os.path.dirname(current)
        if parent == current:
            return
        current = parent


def _bootstrap_parse_pin(raw):
    expected_prefixes = [field.encode("ascii") + b"=" for field in BOOTSTRAP_FIELDS]
    lines = raw.splitlines(keepends=True)
    if len(lines) != len(BOOTSTRAP_FIELDS) or any(
        not line.endswith(b"\n") or not line.startswith(prefix)
        for line, prefix in zip(lines, expected_prefixes)
    ):
        raise SystemExit("query-v5 bootstrap pin is not canonical")
    values = {}
    for field, line, prefix in zip(BOOTSTRAP_FIELDS, lines, expected_prefixes):
        try:
            values[field] = line[len(prefix) : -1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise SystemExit("query-v5 bootstrap pin is not ASCII") from exc
    if values["schema_version"] != BOOTSTRAP_SCHEMA_VERSION:
        raise SystemExit("query-v5 bootstrap pin version mismatch")
    if not 8 <= len(values["generation_id"]) <= 128 or any(
        character
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
        for character in values["generation_id"]
    ):
        raise SystemExit("query-v5 bootstrap generation is invalid")
    digest_fields = [field for field in BOOTSTRAP_FIELDS if field.endswith("_sha256")]
    for field in digest_fields:
        value = values[field]
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise SystemExit("query-v5 bootstrap digest is invalid")
    image_digest = values["runtime_image_digest"]
    if (
        len(image_digest) != 71
        or not image_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in image_digest[7:])
    ):
        raise SystemExit("query-v5 bootstrap image digest is invalid")
    return values


def _bootstrap_under(path, root):
    path = _bootstrap_os.path.realpath(path)
    root = _bootstrap_os.path.realpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _bootstrap_verify():
    if _bootstrap_os.geteuid() == 0 or sys.version_info[:2] != (3, 12):
        raise SystemExit("query-v5 bootstrap requires non-root CPython 3.12")
    _bootstrap_directory_chain(_bootstrap_os.path.dirname(BOOTSTRAP_PIN_PATH_TEXT))
    pin_raw = _bootstrap_read(BOOTSTRAP_PIN_PATH_TEXT, "query-v5 bootstrap pin")
    pins = _bootstrap_parse_pin(pin_raw)
    paths = {
        field: pins[field] for field in BOOTSTRAP_FIELDS if field.endswith("_path")
    }
    for field, value in paths.items():
        if not value.startswith("/") or _bootstrap_os.path.realpath(value) != value:
            raise SystemExit("query-v5 bootstrap path is not canonical: " + field)
        _bootstrap_directory_chain(
            value if field.endswith("root_path") else _bootstrap_os.path.dirname(value)
        )
    if _bootstrap_os.path.realpath(__file__) != paths["launcher_path"]:
        raise SystemExit("query-v5 bootstrap launcher path escaped pin")
    if _bootstrap_os.path.realpath(sys.executable) != paths["python_executable_path"]:
        raise SystemExit("query-v5 bootstrap interpreter path escaped pin")
    if not _bootstrap_os.path.samefile(
        "/proc/self/exe", paths["python_executable_path"]
    ):
        raise SystemExit("query-v5 bootstrap did not load pinned interpreter")
    actual = {
        "launcher_sha256": _bootstrap_sha256(
            _bootstrap_read(paths["launcher_path"], "query-v5 bootstrap launcher")
        ),
        "python_executable_sha256": _bootstrap_sha256(
            _bootstrap_read(
                paths["python_executable_path"], "query-v5 bootstrap interpreter"
            )
        ),
        "python_runtime_closure_sha256": _bootstrap_tree_digest(
            paths["python_runtime_root_path"], allow_symlinks=True
        ),
        "native_runtime_closure_sha256": _bootstrap_tree_digest(
            paths["native_runtime_root_path"], allow_symlinks=True
        ),
        "bootstrap_source_closure_sha256": _bootstrap_tree_digest(
            paths["source_root_path"]
        ),
        "bootstrap_dependency_closure_sha256": _bootstrap_tree_digest(
            paths["dependency_root_path"]
        ),
    }
    if any(actual[field] != pins[field] for field in actual):
        raise SystemExit("query-v5 pre-import runtime closure pin mismatch")
    allowed_roots = (
        paths["python_runtime_root_path"],
        paths["native_runtime_root_path"],
        paths["source_root_path"],
        paths["dependency_root_path"],
    )
    for entry in sys.path:
        if entry and not any(_bootstrap_under(entry, root) for root in allowed_roots):
            raise SystemExit("query-v5 bootstrap sys.path escaped pinned roots")
    maps_raw = _bootstrap_proc_read(
        "/proc/self/maps", "query-v5 bootstrap process maps"
    )
    for line in maps_raw.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].startswith(b"/"):
            continue
        if fields[5].endswith(b" (deleted)"):
            raise SystemExit("query-v5 bootstrap mapped deleted native code")
        try:
            mapped = _bootstrap_os.fsdecode(fields[5])
        except UnicodeDecodeError as exc:
            raise SystemExit("query-v5 bootstrap mapped path is invalid") from exc
        if not any(_bootstrap_under(mapped, root) for root in allowed_roots):
            raise SystemExit("query-v5 bootstrap mapped code escaped pinned roots")
    return {
        **actual,
        "bootstrap_pin_sha256": _bootstrap_sha256(pin_raw),
        "generation_id": pins["generation_id"],
        "runtime_image_digest": pins["runtime_image_digest"],
        "python_runtime_root_path": paths["python_runtime_root_path"],
        "native_runtime_root_path": paths["native_runtime_root_path"],
        "source_root_path": paths["source_root_path"],
        "dependency_root_path": paths["dependency_root_path"],
        "pre_import_runtime_verified": False,
    }


_PYTHON_STARTUP_BOOTSTRAP_IDENTITY = _bootstrap_verify() if RUNNING_AS_SCRIPT else None


import hashlib  # noqa: E402
import hmac  # noqa: E402
import importlib.abc  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import stat  # noqa: E402
from types import ModuleType  # noqa: E402
from typing import Any, Callable  # noqa: E402

if _bootstrap_os is None:
    _bootstrap_os = os


PIN_ROOT = Path("/run/c-fast-t1-query-v5-image-attestation-pins")
PIN_MANIFEST_PATH = PIN_ROOT / "pin-set.manifest.json"
PIN_MANIFEST_VERSION = "commodity_c_fast_t1_query_v5_image_attestation_pin_set_v1"
TARGET_MODULE = "c_fast_t1.verify_query_v5_image_attestation"
TARGET_RELATIVE_PATH = Path("scripts/c_fast_t1/verify_query_v5_image_attestation.py")
LAUNCHER_RELATIVE_PATH = Path(
    "scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py"
)
LAUNCHER_PATH = Path(__file__).resolve()
LOADED_EXECUTABLE_PATH = Path("/proc/self/exe")
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 100_000
SOURCE_MANIFEST_VERSION = "commodity_c_fast_t1_query_v5_attestation_source_closure_v1"
DEPENDENCY_MANIFEST_VERSION = (
    "commodity_c_fast_t1_query_v5_attestation_dependency_closure_v1"
)
DIRECTORY_IDENTITY_VERSION = (
    "commodity_c_fast_t1_query_v5_attestation_directory_identity_v1"
)
FORBIDDEN_STARTUP_ENTRIES = frozenset(
    {
        "sitecustomize.py",
        "sitecustomize.pyc",
        "usercustomize.py",
        "usercustomize.pyc",
    }
)
PINNED_THIRD_PARTY_TOP_LEVEL = frozenset(
    {
        "attr",
        "attrs",
        "jsonschema",
        "jsonschema_specifications",
        "referencing",
        "rpds",
        "yaml",
    }
)
PIN_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "runtime_image_digest",
        "launcher_sha256",
        "verifier_sha256",
        "query_v4_verifier_sha256",
        "query_v4_delegate_sha256",
        "query_v5_validator_sha256",
        "query_v4_validator_sha256",
        "python_executable_path",
        "python_executable_sha256",
        "bootstrap_pin_sha256",
        "python_runtime_root_path",
        "python_runtime_closure_sha256",
        "native_runtime_root_path",
        "native_runtime_closure_sha256",
        "source_root_path",
        "source_root_identity_sha256",
        "source_closure_manifest_sha256",
        "bootstrap_source_closure_sha256",
        "dependency_root_path",
        "dependency_root_identity_sha256",
        "dependency_closure_manifest_sha256",
        "bootstrap_dependency_closure_sha256",
    }
)
LOCAL_MODULE_PATHS = {
    "verifier_sha256": TARGET_RELATIVE_PATH,
    "query_v4_verifier_sha256": Path(
        "scripts/c_fast_t1/verify_query_v4_image_attestation.py"
    ),
    "query_v4_delegate_sha256": Path(
        "scripts/c_fast_t1/verify_query_v3_image_attestation.py"
    ),
    "query_v5_validator_sha256": Path("scripts/c_fast_t1/validate_query_v5_runtime.py"),
    "query_v4_validator_sha256": Path("scripts/c_fast_t1/validate_query_v4_runtime.py"),
}


class QueryV5AttestationLauncherError(RuntimeError):
    """The pinned execution-closure self-check failed closed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_sha256(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise QueryV5AttestationLauncherError(f"{label} must be one lowercase SHA256")


def _validate_image_digest(value: Any) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise QueryV5AttestationLauncherError(
            "attestation runtime image digest must be an OCI RepoDigest"
        )
    _validate_sha256(value[7:], "attestation runtime image digest")


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


def _effective_access(path: Path, mode: int) -> bool:
    if os.access in os.supports_effective_ids:
        return os.access(path, mode, effective_ids=True)
    return os.access(path, mode)


def _require_safe(
    path: Path,
    info: os.stat_result,
    label: str,
    *,
    regular: bool,
    require_immutable: bool,
) -> None:
    expected_owners = {0} if require_immutable else {0, os.geteuid()}
    if info.st_uid not in expected_owners:
        raise QueryV5AttestationLauncherError(f"{label} owner is unsafe")
    mode = stat.S_IMODE(info.st_mode)
    private_sticky_directory = (
        not require_immutable
        and not regular
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and bool(mode & stat.S_ISVTX)
        and bool(mode & 0o002)
    )
    if mode & 0o022 and not private_sticky_directory:
        raise QueryV5AttestationLauncherError(f"{label} is group/world writable")
    if regular:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise QueryV5AttestationLauncherError(
                f"{label} must be one regular hardlink-free file"
            )
    elif not stat.S_ISDIR(info.st_mode):
        raise QueryV5AttestationLauncherError(f"{label} must be a directory")
    if not regular and not _effective_access(path, os.R_OK | os.X_OK):
        raise QueryV5AttestationLauncherError(
            f"{label} is not enumerable by the runtime"
        )
    if require_immutable:
        if os.geteuid() == 0:
            raise QueryV5AttestationLauncherError(
                "query-v5 attestation runtime must execute as non-root"
            )
        if _effective_access(path, os.W_OK):
            raise QueryV5AttestationLauncherError(f"{label} is writable by the runtime")


def _read_fd(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_FILE_BYTES:
            raise QueryV5AttestationLauncherError(f"{label} is too large")
        chunks.append(chunk)


def _stable_read(
    path: Path,
    label: str,
    *,
    require_immutable: bool,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise QueryV5AttestationLauncherError(f"{label} is a symlink")
        _require_safe(
            path,
            before,
            label,
            regular=True,
            require_immutable=require_immutable,
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise QueryV5AttestationLauncherError(f"{label} changed before read")
        first = _read_fd(descriptor, label)
        after_first = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd(descriptor, label)
        after_second = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            first != second
            or _identity(opened) != _identity(after_first)
            or _identity(opened) != _identity(after_second)
            or _identity(opened) != _identity(after_path)
            or len(first) != opened.st_size
        ):
            raise QueryV5AttestationLauncherError(f"{label} changed while being read")
        return first, opened
    except QueryV5AttestationLauncherError:
        raise
    except OSError as exc:
        raise QueryV5AttestationLauncherError(f"{label} cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _stable_loaded_executable(
    path: Path,
    *,
    injected: bool,
    require_immutable: bool,
) -> tuple[bytes, os.stat_result]:
    if injected:
        return _stable_read(
            path,
            "loaded executable test input",
            require_immutable=require_immutable,
        )
    if sys.platform != "linux" or path != LOADED_EXECUTABLE_PATH:
        raise QueryV5AttestationLauncherError(
            "production attestation runtime requires Linux /proc/self/exe"
        )
    descriptor = -1
    try:
        before_link = os.readlink(path)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        before = os.fstat(descriptor)
        _require_safe(
            path,
            before,
            "loaded Python executable",
            regular=True,
            require_immutable=require_immutable,
        )
        first = _read_fd(descriptor, "loaded Python executable")
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd(descriptor, "loaded Python executable")
        after = os.fstat(descriptor)
        after_link = os.readlink(path)
        if (
            before_link != after_link
            or first != second
            or _identity(before) != _identity(after)
            or len(first) != before.st_size
        ):
            raise QueryV5AttestationLauncherError(
                "loaded Python executable changed while being read"
            )
        return first, after
    except QueryV5AttestationLauncherError:
        raise
    except OSError as exc:
        raise QueryV5AttestationLauncherError(
            "loaded Python executable cannot be read safely"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _directory_records(
    path: Path,
    *,
    require_immutable: bool,
) -> list[dict[str, Any]]:
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise QueryV5AttestationLauncherError("runtime directory path is not canonical")
    records: list[dict[str, Any]] = []
    for current in reversed((path, *path.parents)):
        try:
            info = current.lstat()
        except OSError as exc:
            raise QueryV5AttestationLauncherError(
                "runtime directory chain cannot be inspected"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise QueryV5AttestationLauncherError(
                "runtime directory chain contains a symlink"
            )
        _require_safe(
            current,
            info,
            f"runtime directory {current}",
            regular=False,
            require_immutable=require_immutable,
        )
        records.append(
            {
                "path": str(current),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
                "type": stat.S_IFMT(info.st_mode),
            }
        )
    return records


def directory_identity_sha256(
    path: Path,
    *,
    require_immutable: bool = False,
) -> str:
    first = _directory_records(path, require_immutable=require_immutable)
    second = _directory_records(path, require_immutable=require_immutable)
    if first != second:
        raise QueryV5AttestationLauncherError("runtime directory identity changed")
    return _sha256(
        _canonical(
            {
                "schema_version": DIRECTORY_IDENTITY_VERSION,
                "resolved_path": str(path.resolve(strict=True)),
                "chain": first,
            }
        )
    )


RetainedEntry = tuple[bytes, Path, bool]


def _scan_tree(
    root: Path,
    *,
    manifest_version: str,
    require_immutable: bool,
    retain_python_under: Path | None = None,
    reject_startup_hooks: bool = False,
) -> tuple[str, dict[str, RetainedEntry]]:
    records: list[dict[str, Any]] = []
    retained: dict[str, RetainedEntry] = {}
    count = 0

    def visit(directory: Path, relative: Path) -> None:
        nonlocal count
        before = directory.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise QueryV5AttestationLauncherError("runtime tree directory is a symlink")
        _require_safe(
            directory,
            before,
            f"runtime directory {relative.as_posix()}",
            regular=False,
            require_immutable=require_immutable,
        )
        try:
            with os.scandir(directory) as iterator:
                children = sorted(
                    iterator,
                    key=lambda entry: os.fsencode(entry.name),
                )
        except OSError as exc:
            raise QueryV5AttestationLauncherError(
                "runtime tree cannot be enumerated"
            ) from exc
        for child in children:
            count += 1
            if count > MAX_ENTRIES:
                raise QueryV5AttestationLauncherError(
                    "runtime closure has too many entries"
                )
            child_path = Path(child.path)
            child_relative = relative / child.name
            info = child.stat(follow_symlinks=False)
            label = f"runtime entry {child_relative.as_posix()}"
            if stat.S_ISLNK(info.st_mode):
                raise QueryV5AttestationLauncherError(f"{label} symlink is forbidden")
            if stat.S_ISDIR(info.st_mode):
                _require_safe(
                    child_path,
                    info,
                    label,
                    regular=False,
                    require_immutable=require_immutable,
                )
                records.append(
                    {
                        "type": "directory",
                        "path": child_relative.as_posix(),
                        "uid": info.st_uid,
                        "gid": info.st_gid,
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                visit(child_path, child_relative)
            elif stat.S_ISREG(info.st_mode):
                if reject_startup_hooks and (
                    child.name in FORBIDDEN_STARTUP_ENTRIES
                    or child.name.endswith((".pth", ".egg-link"))
                ):
                    raise QueryV5AttestationLauncherError(
                        f"{label} startup hook is forbidden"
                    )
                raw, opened = _stable_read(
                    child_path,
                    label,
                    require_immutable=require_immutable,
                )
                records.append(
                    {
                        "type": "file",
                        "path": child_relative.as_posix(),
                        "uid": opened.st_uid,
                        "gid": opened.st_gid,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "size": len(raw),
                        "sha256": _sha256(raw),
                    }
                )
                if (
                    retain_python_under is not None
                    and child_path.suffix == ".py"
                    and child_path.is_relative_to(retain_python_under)
                ):
                    module_relative = child_path.relative_to(retain_python_under)
                    parts = list(module_relative.parts)
                    package = parts[-1] == "__init__.py"
                    if package:
                        parts.pop()
                    else:
                        parts[-1] = module_relative.stem
                    module_name = ".".join(parts)
                    if module_name:
                        retained[module_name] = (
                            raw,
                            child_path.resolve(strict=True),
                            package,
                        )
            else:
                raise QueryV5AttestationLauncherError(f"{label} file type is forbidden")
        after = directory.lstat()
        if _identity(before) != _identity(after):
            raise QueryV5AttestationLauncherError("runtime tree changed during scan")

    visit(root, Path("."))
    digest = _sha256(
        _canonical(
            {
                "schema_version": manifest_version,
                "root": str(root),
                "records": records,
            }
        )
    )
    return digest, retained


def scan_source_closure(
    root: Path,
    *,
    require_immutable: bool = False,
) -> tuple[str, dict[str, RetainedEntry]]:
    scripts = root / "scripts"
    first, retained = _scan_tree(
        root,
        manifest_version=SOURCE_MANIFEST_VERSION,
        require_immutable=require_immutable,
        retain_python_under=scripts,
        reject_startup_hooks=True,
    )
    second, second_retained = _scan_tree(
        root,
        manifest_version=SOURCE_MANIFEST_VERSION,
        require_immutable=require_immutable,
        retain_python_under=scripts,
        reject_startup_hooks=True,
    )
    if first != second or retained != second_retained:
        raise QueryV5AttestationLauncherError(
            "source closure changed during stable scan"
        )
    if TARGET_MODULE not in retained:
        raise QueryV5AttestationLauncherError(
            "query-v5 attestation verifier is absent from source closure"
        )
    return first, retained


def scan_dependency_closure(
    root: Path,
    *,
    require_immutable: bool = False,
) -> str:
    first, _ = _scan_tree(
        root,
        manifest_version=DEPENDENCY_MANIFEST_VERSION,
        require_immutable=require_immutable,
        reject_startup_hooks=True,
    )
    second, _ = _scan_tree(
        root,
        manifest_version=DEPENDENCY_MANIFEST_VERSION,
        require_immutable=require_immutable,
        reject_startup_hooks=True,
    )
    if first != second:
        raise QueryV5AttestationLauncherError(
            "dependency closure changed during stable scan"
        )
    return first


def _read_pin_manifest(
    path: Path,
    *,
    require_immutable: bool,
) -> tuple[dict[str, Any], str]:
    directory_identity_sha256(
        path.parent,
        require_immutable=require_immutable,
    )
    first, _ = _stable_read(
        path,
        "query-v5 attestation pin manifest",
        require_immutable=require_immutable,
    )
    try:
        manifest = json.loads(first)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV5AttestationLauncherError(
            "query-v5 attestation pin manifest is invalid JSON"
        ) from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != PIN_FIELDS
        or manifest.get("schema_version") != PIN_MANIFEST_VERSION
        or not isinstance(manifest.get("generation_id"), str)
        or not 8 <= len(manifest["generation_id"]) <= 128
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in manifest["generation_id"]
        )
    ):
        raise QueryV5AttestationLauncherError(
            "query-v5 attestation pin manifest fields are invalid"
        )
    if first != _canonical(manifest):
        raise QueryV5AttestationLauncherError(
            "query-v5 attestation pin manifest is not canonical JSON"
        )
    _validate_image_digest(manifest["runtime_image_digest"])
    for field in PIN_FIELDS:
        if field.endswith("_sha256"):
            _validate_sha256(manifest[field], field)
    for field in (
        "python_executable_path",
        "python_runtime_root_path",
        "native_runtime_root_path",
        "source_root_path",
        "dependency_root_path",
    ):
        value = manifest[field]
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or Path(value).resolve(strict=True) != Path(value)
        ):
            raise QueryV5AttestationLauncherError(
                f"{field} is not one canonical absolute path"
            )
    second, _ = _stable_read(
        path,
        "query-v5 attestation pin manifest",
        require_immutable=require_immutable,
    )
    if first != second:
        raise QueryV5AttestationLauncherError(
            "query-v5 attestation pin generation changed"
        )
    return manifest, _sha256(first)


def _path_sha256(path: Path) -> str:
    return _sha256(str(path).encode("utf-8"))


def _inspect_runtime(
    *,
    pin_manifest_path: Path = PIN_MANIFEST_PATH,
    launcher_path: Path = LAUNCHER_PATH,
    reported_executable_path: Path | None = None,
    loaded_executable_path: Path | None = None,
    require_immutable: bool = True,
) -> tuple[
    dict[str, Any],
    Callable[[], None],
    dict[str, RetainedEntry],
    Path,
    Path,
]:
    pins, pin_manifest_sha256 = _read_pin_manifest(
        pin_manifest_path,
        require_immutable=require_immutable,
    )
    python_path = Path(pins["python_executable_path"])
    source_root = Path(pins["source_root_path"])
    dependency_root = Path(pins["dependency_root_path"])
    expected_launcher = (source_root / LAUNCHER_RELATIVE_PATH).resolve(strict=True)
    if launcher_path.resolve(strict=True) != expected_launcher:
        raise QueryV5AttestationLauncherError(
            "running launcher escaped the pinned source closure"
        )
    reported = Path(
        sys.executable if reported_executable_path is None else reported_executable_path
    )
    loaded = (
        LOADED_EXECUTABLE_PATH
        if loaded_executable_path is None
        else loaded_executable_path
    )
    launcher_raw, _ = _stable_read(
        launcher_path,
        "query-v5 attestation launcher",
        require_immutable=require_immutable,
    )
    python_raw, python_info = _stable_read(
        python_path,
        "query-v5 attestation Python interpreter",
        require_immutable=require_immutable,
    )
    loaded_raw, loaded_info = _stable_loaded_executable(
        loaded,
        injected=loaded_executable_path is not None,
        require_immutable=require_immutable,
    )
    try:
        if reported.resolve(strict=True) != python_path.resolve(strict=True):
            raise QueryV5AttestationLauncherError(
                "reported Python executable is not the pinned interpreter"
            )
        if not os.path.samefile(reported, python_path):
            raise QueryV5AttestationLauncherError(
                "reported Python interpreter identity changed"
            )
        if not os.path.samefile(loaded, python_path):
            raise QueryV5AttestationLauncherError(
                "loaded executable is not the pinned interpreter"
            )
    except OSError as exc:
        raise QueryV5AttestationLauncherError(
            "cannot bind the running Python interpreter"
        ) from exc
    if python_raw != loaded_raw or _identity(python_info) != _identity(loaded_info):
        raise QueryV5AttestationLauncherError(
            "loaded executable bytes or identity changed"
        )
    source_identity = directory_identity_sha256(
        source_root,
        require_immutable=require_immutable,
    )
    dependency_identity = directory_identity_sha256(
        dependency_root,
        require_immutable=require_immutable,
    )
    source_manifest, retained = scan_source_closure(
        source_root,
        require_immutable=require_immutable,
    )
    dependency_manifest = scan_dependency_closure(
        dependency_root,
        require_immutable=require_immutable,
    )
    bootstrap = _PYTHON_STARTUP_BOOTSTRAP_IDENTITY
    if require_immutable:
        if bootstrap is None:
            raise QueryV5AttestationLauncherError(
                "query-v5 Python-startup bootstrap identity is unavailable"
            )
        bootstrap_expected = {
            "generation_id": pins["generation_id"],
            "runtime_image_digest": pins["runtime_image_digest"],
            "bootstrap_pin_sha256": pins["bootstrap_pin_sha256"],
            "launcher_sha256": pins["launcher_sha256"],
            "python_executable_sha256": pins["python_executable_sha256"],
            "python_runtime_root_path": pins["python_runtime_root_path"],
            "python_runtime_closure_sha256": pins["python_runtime_closure_sha256"],
            "native_runtime_root_path": pins["native_runtime_root_path"],
            "native_runtime_closure_sha256": pins["native_runtime_closure_sha256"],
            "source_root_path": pins["source_root_path"],
            "bootstrap_source_closure_sha256": pins["bootstrap_source_closure_sha256"],
            "dependency_root_path": pins["dependency_root_path"],
            "bootstrap_dependency_closure_sha256": pins[
                "bootstrap_dependency_closure_sha256"
            ],
            "pre_import_runtime_verified": False,
        }
        if bootstrap != bootstrap_expected:
            raise QueryV5AttestationLauncherError(
                "query-v5 bootstrap and phase-two pin generations differ"
            )
    local_hashes: dict[str, str] = {}
    for field, relative in LOCAL_MODULE_PATHS.items():
        module_path = (source_root / relative).resolve(strict=True)
        match = next(
            (raw for raw, path, _package in retained.values() if path == module_path),
            None,
        )
        if match is None:
            raise QueryV5AttestationLauncherError(
                f"pinned local module is absent: {relative.as_posix()}"
            )
        local_hashes[field] = _sha256(match)
    actual = {
        "launcher_sha256": _sha256(launcher_raw),
        **local_hashes,
        "python_executable_sha256": _sha256(python_raw),
        "source_root_identity_sha256": source_identity,
        "source_closure_manifest_sha256": source_manifest,
        "dependency_root_identity_sha256": dependency_identity,
        "dependency_closure_manifest_sha256": dependency_manifest,
    }
    if any(
        not hmac.compare_digest(str(pins[field]), value)
        for field, value in actual.items()
    ):
        raise QueryV5AttestationLauncherError(
            "query-v5 attestation runtime closure pin mismatch"
        )
    identity = {
        "runtime_image_digest": pins["runtime_image_digest"],
        "pin_manifest_sha256": pin_manifest_sha256,
        **actual,
        "loaded_executable_sha256": _sha256(loaded_raw),
        "python_executable_path_sha256": _path_sha256(python_path),
        "source_root_path_sha256": _path_sha256(source_root),
        "dependency_root_path_sha256": _path_sha256(dependency_root),
        "bootstrap_pin_sha256": pins["bootstrap_pin_sha256"],
        "python_runtime_root_path_sha256": _path_sha256(
            Path(pins["python_runtime_root_path"])
        ),
        "python_runtime_closure_sha256": pins["python_runtime_closure_sha256"],
        "native_runtime_root_path_sha256": _path_sha256(
            Path(pins["native_runtime_root_path"])
        ),
        "native_runtime_closure_sha256": pins["native_runtime_closure_sha256"],
        "bootstrap_source_closure_sha256": pins["bootstrap_source_closure_sha256"],
        "bootstrap_dependency_closure_sha256": pins[
            "bootstrap_dependency_closure_sha256"
        ],
        # CPython has already executed path-backed encodings modules before this
        # launcher can observe any flags or files.  These claims stay false until
        # a non-Python phase-zero trust root is introduced.
        "isolated_flags_verified": False,
        "pre_import_runtime_verified": False,
        "source_closure_retained": True,
        "immutable_runtime_verified": False,
        "external_runtime_identity_required": True,
    }
    snapshot_pins = dict(pins)

    def revalidate() -> None:
        current_pins, current_pin_sha256 = _read_pin_manifest(
            pin_manifest_path,
            require_immutable=require_immutable,
        )
        current_source, _ = scan_source_closure(
            source_root,
            require_immutable=require_immutable,
        )
        current_dependency = scan_dependency_closure(
            dependency_root,
            require_immutable=require_immutable,
        )
        current_launcher, _ = _stable_read(
            launcher_path,
            "query-v5 attestation launcher",
            require_immutable=require_immutable,
        )
        current_python, _ = _stable_read(
            python_path,
            "query-v5 attestation Python interpreter",
            require_immutable=require_immutable,
        )
        bootstrap_drifted = False
        if require_immutable:
            bootstrap_drifted = any(
                (
                    _bootstrap_tree_digest(
                        pins["python_runtime_root_path"],
                        allow_symlinks=True,
                    )
                    != pins["python_runtime_closure_sha256"],
                    _bootstrap_tree_digest(
                        pins["native_runtime_root_path"],
                        allow_symlinks=True,
                    )
                    != pins["native_runtime_closure_sha256"],
                    _bootstrap_tree_digest(pins["source_root_path"])
                    != pins["bootstrap_source_closure_sha256"],
                    _bootstrap_tree_digest(pins["dependency_root_path"])
                    != pins["bootstrap_dependency_closure_sha256"],
                )
            )
        if (
            current_pins != snapshot_pins
            or current_pin_sha256 != pin_manifest_sha256
            or current_source != source_manifest
            or current_dependency != dependency_manifest
            or _sha256(current_launcher) != actual["launcher_sha256"]
            or _sha256(current_python) != actual["python_executable_sha256"]
            or bootstrap_drifted
            or directory_identity_sha256(
                source_root,
                require_immutable=require_immutable,
            )
            != source_identity
            or directory_identity_sha256(
                dependency_root,
                require_immutable=require_immutable,
            )
            != dependency_identity
        ):
            raise QueryV5AttestationLauncherError(
                "query-v5 attestation runtime identity drifted"
            )

    return identity, revalidate, retained, source_root, dependency_root


class _RetainedLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, sources: dict[str, RetainedEntry], scripts_root: Path) -> None:
        self.sources = sources
        self.synthetic_packages: dict[str, Path] = {}
        for module_name in sources:
            parts = module_name.split(".")
            for length in range(1, len(parts)):
                package_name = ".".join(parts[:length])
                if package_name not in sources:
                    self.synthetic_packages[package_name] = scripts_root.joinpath(
                        *parts[:length]
                    )

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: ModuleType | None = None,
    ) -> Any:
        entry = self.sources.get(fullname)
        if entry is None:
            if fullname not in self.synthetic_packages:
                return None
            return importlib.util.spec_from_loader(
                fullname,
                self,
                origin=str(self.synthetic_packages[fullname]),
                is_package=True,
            )
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=str(entry[1]),
            is_package=entry[2],
        )

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        entry = self.sources.get(module.__name__)
        if entry is None:
            module.__path__ = [  # type: ignore[attr-defined]
                str(self.synthetic_packages[module.__name__])
            ]
            return
        raw, path, package = entry
        module.__file__ = str(path)
        if package:
            module.__path__ = [str(path.parent)]  # type: ignore[attr-defined]
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)


class _RetainedPathLoader(importlib.abc.Loader):
    def __init__(self, raw: bytes, path: Path) -> None:
        self.raw = raw
        self.path = path

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        module.__file__ = str(self.path)
        exec(
            compile(self.raw, str(self.path), "exec", dont_inherit=True),
            module.__dict__,
        )


def _load_retained_target(
    retained: dict[str, RetainedEntry],
    source_root: Path,
    dependency_root: Path,
) -> ModuleType:
    if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
        raise QueryV5AttestationLauncherError(
            "Python startup customization executed before attestation"
        )
    by_path = {path: (raw, path) for raw, path, _package in retained.values()}
    retained_loader = _RetainedLoader(retained, source_root / "scripts")
    original_spec_from_file_location = importlib.util.spec_from_file_location

    def retained_spec_from_file_location(
        name: str,
        location: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        try:
            path = Path(location).resolve(strict=True)
        except (OSError, TypeError, ValueError):
            return original_spec_from_file_location(
                name,
                location,
                *args,
                **kwargs,
            )
        entry = by_path.get(path)
        if entry is None:
            return original_spec_from_file_location(
                name,
                location,
                *args,
                **kwargs,
            )
        return importlib.util.spec_from_loader(
            name,
            _RetainedPathLoader(entry[0], path),
            origin=str(path),
        )

    filtered_path: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        resolved = Path(entry).resolve()
        if resolved in {LAUNCHER_PATH.parent, source_root / "scripts"}:
            continue
        if any(part in {"site-packages", "dist-packages"} for part in resolved.parts):
            continue
        filtered_path.append(entry)
    sys.path = filtered_path
    sys.path.append(str(dependency_root))
    sys.meta_path.insert(0, retained_loader)
    importlib.util.spec_from_file_location = retained_spec_from_file_location
    try:
        spec = importlib.util.find_spec(TARGET_MODULE)
        if spec is None or spec.loader is not retained_loader:
            raise QueryV5AttestationLauncherError(
                "query-v5 attestation verifier did not resolve from retained bytes"
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[TARGET_MODULE] = module
        spec.loader.exec_module(module)
    finally:
        importlib.util.spec_from_file_location = original_spec_from_file_location
    required_modules = {
        TARGET_MODULE,
        "c_fast_t1.verify_query_v4_image_attestation",
        "c_fast_t1.validate_query_v5_runtime",
        "c_fast_t1.validate_query_v4_runtime",
        "_c_fast_t1_query_v4_image_attestation_delegate",
    }
    if any(
        name not in sys.modules
        or not isinstance(
            getattr(sys.modules[name], "__loader__", None),
            (_RetainedLoader, _RetainedPathLoader),
        )
        for name in required_modules
    ):
        raise QueryV5AttestationLauncherError(
            "query-v5 local import closure escaped retained source bytes"
        )
    if "jsonschema" not in sys.modules or "yaml" not in sys.modules:
        raise QueryV5AttestationLauncherError(
            "query-v5 pinned dependencies were not loaded"
        )
    for name, imported in tuple(sys.modules.items()):
        location = getattr(imported, "__file__", None)
        if location is None:
            continue
        try:
            resolved = Path(location).resolve(strict=True)
        except (OSError, TypeError, ValueError) as exc:
            raise QueryV5AttestationLauncherError(
                f"loaded module path cannot be bound: {name}"
            ) from exc
        top_level = name.partition(".")[0]
        lives_in_site_packages = any(
            part in {"site-packages", "dist-packages"} for part in resolved.parts
        )
        if (
            top_level in PINNED_THIRD_PARTY_TOP_LEVEL or lives_in_site_packages
        ) and not resolved.is_relative_to(dependency_root):
            raise QueryV5AttestationLauncherError(
                f"query-v5 dependency import escaped the pinned closure: {name}"
            )
    return module


def main() -> int:
    try:
        identity, revalidate, retained, source_root, dependency_root = (
            _inspect_runtime()
        )
        module = _load_retained_target(
            retained,
            source_root,
            dependency_root,
        )
        module.install_runtime_identity_observation(
            module.QueryV5AttestationRuntimeIdentity(**identity),
            revalidate,
        )
        revalidate()
        return int(module.main())
    except (QueryV5AttestationLauncherError, OSError, ValueError) as exc:
        print(
            f"query-v5 image attestation launcher self-check failed: {exc}",
            file=sys.stderr,
        )
        return 2


if RUNNING_AS_SCRIPT:
    raise SystemExit(main())
