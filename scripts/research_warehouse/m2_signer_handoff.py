"""Root-key preload and irreversible service-identity signer handoff."""

from __future__ import annotations

import grp
import os
import pwd
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json_line, parse_json_strict
from .errors import RegistryError
from .file_integrity import write_all
from .signing import load_private_key

MAX_CHILD_RESULT_BYTES = 1024 * 1024


def _require_root() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RegistryError("M2 signer handoff must start as root")


def _require_service_identity(uid: int, gid: int) -> None:
    for value, label in ((uid, "UID"), (gid, "GID")):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RegistryError(f"M2 signer service {label} is invalid")


def _darwin_memberships(account: pwd.struct_passwd) -> set[int]:
    """Resolve the account's own non-privileged directory memberships."""
    values = set(os.getgrouplist(account.pw_name, account.pw_gid))
    values.add(account.pw_gid)
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
        raise RegistryError("M2 signer Darwin account memberships are invalid")
    for value in values:
        if value == 0:
            raise RegistryError("M2 signer Darwin membership is privileged")
        try:
            name = grp.getgrgid(value).gr_name.lower()
        except KeyError as exc:
            raise RegistryError("M2 signer Darwin membership is unresolved") from exc
        if name in {"root", "wheel", "admin"}:
            raise RegistryError("M2 signer Darwin membership is privileged")
    return values


def _drop_identity(uid: int, gid: int) -> None:
    if hasattr(os, "setresgid"):
        os.setresgid(gid, gid, gid)
    else:
        os.setgid(gid)
    if hasattr(os, "setresuid"):
        os.setresuid(uid, uid, uid)
    else:
        os.setuid(uid)


def _drop_privileges(uid: int, gid: int, *, key_path: Path) -> None:
    account = pwd.getpwuid(uid)
    if account.pw_uid != uid:
        raise RegistryError("M2 signer service account identity mismatch")
    if sys.platform == "darwin":
        expected_groups = _darwin_memberships(account)
        os.initgroups(account.pw_name, account.pw_gid)
    else:
        if account.pw_gid != gid:
            raise RegistryError("M2 signer service account identity mismatch")
        expected_groups = set(os.getgrouplist(account.pw_name, gid))
        os.initgroups(account.pw_name, gid)
    _drop_identity(uid, gid)
    observed_groups = set(os.getgroups())
    if (
        os.getuid() != uid
        or os.geteuid() != uid
        or os.getgid() != gid
        or os.getegid() != gid
        or (
            observed_groups != expected_groups
            if sys.platform != "darwin"
            else not observed_groups.issubset(expected_groups)
        )
    ):
        raise RegistryError("M2 signer privilege drop did not bind exact identity")
    if hasattr(os, "getresuid") and os.getresuid() != (uid, uid, uid):
        raise RegistryError("M2 signer retained a privileged saved UID")
    if hasattr(os, "getresgid") and os.getresgid() != (gid, gid, gid):
        raise RegistryError("M2 signer retained a privileged saved GID")
    try:
        descriptor = os.open(
            key_path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        pass
    else:
        os.close(descriptor)
        raise RegistryError("M2 signer key remains readable after privilege drop")
    os.umask(0o077)
    os.chdir("/")
    os.environ.clear()
    os.environ.update(
        {
            "HOME": "/Users/Shared/vnpy-research/home",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": "/Users/Shared/vnpy-research/runtime/tmp",
        }
    )


def _read_child_result(descriptor: int) -> bytes:
    chunks = []
    remaining = MAX_CHILD_RESULT_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > MAX_CHILD_RESULT_BYTES:
        raise RegistryError("M2 signer child result exceeds safety limit")
    return raw


def run_with_preloaded_private_key(
    *,
    private_key_path: Path,
    service_uid: int,
    service_gid: int,
    operation: Callable[[Ed25519PrivateKey], dict[str, Any]],
) -> dict[str, Any]:
    """Load a root-only key, fork, drop permanently, and run one signer stage."""
    _require_root()
    _require_service_identity(service_uid, service_gid)
    private_key = load_private_key(private_key_path)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        status = 0
        try:
            _drop_privileges(
                service_uid,
                service_gid,
                key_path=private_key_path,
            )
            result = operation(private_key)
            if not isinstance(result, dict):
                raise RegistryError("M2 signer operation returned a non-object")
            raw = canonical_json_line({"ok": True, "result": result})
        except (OSError, RegistryError, ValueError) as exc:
            status = 70
            raw = canonical_json_line(
                {
                    "error": str(exc),
                    "ok": False,
                }
            )
        try:
            write_all(write_fd, raw)
        finally:
            os.close(write_fd)
        os._exit(status)
    os.close(write_fd)
    try:
        raw = _read_child_result(read_fd)
    finally:
        os.close(read_fd)
    _pid, status = os.waitpid(child, 0)
    payload = parse_json_strict(raw, "M2 signer child result")
    if (
        not isinstance(payload, dict)
        or payload.get("ok") is not True
        or set(payload) != {"ok", "result"}
        or not os.WIFEXITED(status)
        or os.WEXITSTATUS(status) != 0
    ):
        detail = (
            payload.get("error")
            if isinstance(payload, dict) and isinstance(payload.get("error"), str)
            else "child failed without a valid error receipt"
        )
        raise RegistryError(f"M2 signer handoff failed: {detail}")
    result = payload["result"]
    if not isinstance(result, dict):
        raise RegistryError("M2 signer child result contract mismatch")
    return result
