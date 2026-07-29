#!/usr/bin/env python3
"""Fail-closed C_FAST T1 query bootstrap.

This process never opens the DSN.  It re-reads the fixed production pins and
then atomically replaces itself with the frozen readonly audit process.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
from typing import Any


PIN_ROOT = Path("/run/c-fast-t1-readiness-v3-pins")
PIN_NAMES = {
    "provenance_keyring_sha256": "provenance-keyring.sha256",
    "provenance_signing_tool_source_sha256": (
        "provenance-signing-tool-source.sha256"
    ),
    "provenance_signing_tool_source_commit_sha": (
        "provenance-signing-tool-source.commit"
    ),
    "t1_authority_keyring_sha256": "t1-authority-keyring.sha256",
    "query_v4": "query-v4-authority-keyring.sha256",
    "l3_authority_keyring_sha256": "l3-authority-keyring.sha256",
    "outcome_keyring_sha256": "outcome-keyring.sha256",
    "packet_custody_path": "packet-custody.path",
}
READINESS_PIN_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "provenance_keyring_sha256",
        "provenance_signing_tool_source_sha256",
        "provenance_signing_tool_source_commit_sha",
        "t1_authority_keyring_sha256",
        "l3_authority_keyring_sha256",
        "outcome_keyring_sha256",
        "packet_custody_path",
        "packet_custody_id",
        "packet_custody_identity_sha256",
        "packet_custody_directory_identity_sha256",
        "evidence_join_identity_sha256",
    }
)
READINESS_CUSTODY_IDENTITY_VERSION = (
    "commodity_c_fast_t1_readiness_v3_custody_identity_v1"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
ATTEMPT_ID_PATTERN = re.compile(r"^attempt-[0-9a-f]{64}$")
MAX_INVOCATION_BYTES = 64 * 1024
MAX_CUSTODY_JSON_BYTES = 1024 * 1024
LAUNCH_CAPABILITY_BYTES = 32
LAUNCH_CAPABILITY_FD_ENV = "BK_C_FAST_QUERY_V4_LAUNCH_CAPABILITY_FD"
LAUNCH_CAPABILITY_DOMAIN = (
    b"vnpy-web-bridge:c-fast-t1:query-v4:parent-launch-capability:v1"
)
LAUNCH_CAPABILITY_BINDING_DOMAIN = (
    b"vnpy-web-bridge:c-fast-t1:query-v4:launch-capability-binding:v1"
)
CONSUME_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "candidate_id",
        "release_id",
        "attempt_id",
        "release_raw_sha256",
        "release_canonical_sha256",
        "consumed_at",
        "readiness_packet_id",
        "readiness_packet_raw_sha256",
        "readiness_packet_canonical_sha256",
        "content_attestation_raw_sha256",
        "content_attestation_canonical_sha256",
        "provenance_raw_sha256",
        "provenance_canonical_sha256",
        "outcome_raw_sha256",
        "outcome_canonical_sha256",
        "manifest_raw_sha256",
        "manifest_canonical_sha256",
        "trusted_keyring_sha256",
        "custody_identity_sha256",
        "custody_path_sha256",
        "consume_precedes_final_revalidation",
        "query_started",
        "production_queried",
        "consume_is_authority",
        "replay_allowed",
    }
)
AUDIT_FLAGS = (
    "--manifest",
    "--start",
    "--end",
    "--dsn-file",
    "--expected-endpoint-identity-sha256",
    "--expected-manifest-sha256",
    "--json-output",
    "--csv-output",
    "--markdown-output",
    "--readonly-proof-output",
    "--pre-connect-query-gate",
    "--expected-pre-connect-gate-raw-sha256",
    "--expected-pre-connect-gate-canonical-sha256",
)
GATE_HASH_FLAGS = (
    "--expected-pre-connect-gate-raw-sha256",
    "--expected-pre-connect-gate-canonical-sha256",
)


class QueryChildError(RuntimeError):
    """Expected pre-network bootstrap failure."""


def unblock_control_signals() -> None:
    if (
        not hasattr(signal, "pthread_sigmask")
        or not hasattr(signal, "SIG_UNBLOCK")
    ):
        raise QueryChildError("query bootstrap requires POSIX signal unmasking")
    controlled = tuple(
        current
        for current in (
            getattr(signal, "SIGTERM", None),
            getattr(signal, "SIGHUP", None),
            getattr(signal, "SIGINT", None),
        )
        if current is not None
    )
    signal.pthread_sigmask(signal.SIG_UNBLOCK, controlled)


def _read_root_pin(path: Path, label: str) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise QueryChildError(f"{label} pin is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QueryChildError(f"{label} pin metadata is unsafe")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise QueryChildError(f"{label} pin cannot be read") from exc
    if len(raw) > 4096 or b"\x00" in raw:
        raise QueryChildError(f"{label} pin content is invalid")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise QueryChildError(f"{label} pin is not UTF-8") from exc
    if not value:
        raise QueryChildError(f"{label} pin is empty")
    return value


def verify_active_pins(
    expected: dict[str, str],
    *,
    pin_root: Path = PIN_ROOT,
) -> Path:
    if (
        ID_PATTERN.fullmatch(expected.get("pin_set_generation_id", ""))
        is None
        or SHA256_PATTERN.fullmatch(
            expected.get("pin_set_manifest_sha256", "")
        )
        is None
    ):
        raise QueryChildError("expected readiness-v3 pin generation is invalid")
    try:
        info = pin_root.lstat()
    except OSError as exc:
        raise QueryChildError("active pin root is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QueryChildError("active pin root metadata is unsafe")
    observed = {
        key: _read_root_pin(pin_root / name, key)
        for key, name in PIN_NAMES.items()
    }
    for key in (
        "provenance_keyring_sha256",
        "provenance_signing_tool_source_sha256",
        "t1_authority_keyring_sha256",
        "query_v4",
        "l3_authority_keyring_sha256",
        "outcome_keyring_sha256",
    ):
        if SHA256_PATTERN.fullmatch(expected[key]) is None:
            raise QueryChildError(f"expected {key} pin is invalid")
        if observed[key] != expected[key]:
            raise QueryChildError("active pins changed before query boundary")
    source_commit = expected["provenance_signing_tool_source_commit_sha"]
    if (
        COMMIT_PATTERN.fullmatch(source_commit) is None
        or observed["provenance_signing_tool_source_commit_sha"]
        != source_commit
    ):
        raise QueryChildError(
            "active provenance source commit changed before query boundary"
        )
    manifest_path = pin_root / "pin-set.manifest.json"
    manifest_raw = _read_root_pin(manifest_path, "pin-set manifest").encode(
        "utf-8"
    )
    try:
        manifest = _parse_json_object(
            manifest_raw,
            "pin-set manifest",
        )
        manifest_hash = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    except (QueryChildError, TypeError) as exc:
        raise QueryChildError("pin-set manifest JSON is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != READINESS_PIN_MANIFEST_FIELDS
        or manifest.get("schema_version")
        != "commodity_c_fast_t1_readiness_v3_pin_set_v1"
        or manifest.get("generation_id") != expected["pin_set_generation_id"]
        or manifest_hash != expected["pin_set_manifest_sha256"]
        or any(
            str(manifest.get(key)) != observed[key]
            for key in (
                "provenance_keyring_sha256",
                "provenance_signing_tool_source_sha256",
                "provenance_signing_tool_source_commit_sha",
                "t1_authority_keyring_sha256",
                "l3_authority_keyring_sha256",
                "outcome_keyring_sha256",
                "packet_custody_path",
            )
        )
        or manifest.get("packet_custody_id")
        != expected.get("packet_custody_id")
        or manifest.get("packet_custody_identity_sha256")
        != expected.get("packet_custody_identity_sha256")
        or manifest.get("packet_custody_directory_identity_sha256")
        != expected.get("packet_custody_directory_identity_sha256")
        or manifest.get("evidence_join_identity_sha256")
        != expected.get("evidence_join_identity_sha256")
    ):
        raise QueryChildError(
            "active readiness-v3 pin generation changed before query boundary"
        )
    return _verify_readiness_custody_facts(
        Path(observed["packet_custody_path"]),
        expected,
    )


def _reject_constant(value: str) -> None:
    raise QueryChildError(f"JSON constant {value!r} is forbidden")


def _read_invocation_bytes(path: Path, label: str) -> bytes:
    try:
        path_before = path.lstat()
        if (
            stat.S_ISLNK(path_before.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or stat.S_IMODE(path_before.st_mode) & 0o022
        ):
            raise QueryChildError(
                f"{label} must be a non-writable regular file"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            first = _read_fd_bounded(
                descriptor,
                label,
                limit=MAX_INVOCATION_BYTES,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_fd_bounded(
                descriptor,
                label,
                limit=MAX_INVOCATION_BYTES,
            )
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise QueryChildError(f"{label} is unavailable") from exc

    def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            stat.S_IFMT(info.st_mode),
            info.st_uid,
            stat.S_IMODE(info.st_mode),
        )

    if (
        identity(path_before) != identity(before)
        or identity(before) != identity(after)
        or identity(after) != identity(path_after)
        or first != second
        or len(first) != before.st_size
    ):
        raise QueryChildError(f"{label} changed while it was being read")
    return first


def _parse_invocation(raw: bytes, label: str) -> list[str]:
    try:
        value: Any = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryChildError(f"{label} JSON is invalid") from exc
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise QueryChildError(f"{label} must contain non-empty strings")
    return value


def _load_audit_invocation_with_raw(path: Path) -> tuple[bytes, list[str]]:
    raw = _read_invocation_bytes(path, "audit invocation")
    value = _parse_invocation(raw, "audit invocation")
    if len(value) != 3 + 2 * len(AUDIT_FLAGS) or value[1] != "-I":
        raise QueryChildError("audit invocation shape is invalid")
    if tuple(value[3::2]) != AUDIT_FLAGS:
        raise QueryChildError("audit invocation flags are not frozen")
    if Path(value[0]).resolve(strict=True) != Path(sys.executable).resolve(
        strict=True
    ):
        raise QueryChildError("audit invocation Python is not current")
    script = Path(value[2]).resolve(strict=True)
    if script.name != "commodity_c_fast_l1_l5_audit.py":
        raise QueryChildError("audit invocation script is not frozen")
    return raw, value


def load_audit_invocation(path: Path) -> list[str]:
    return _load_audit_invocation_with_raw(path)[1]


def _load_query_child_invocation_with_raw(
    path: Path,
) -> tuple[bytes, list[str]]:
    raw = _read_invocation_bytes(path, "query-child invocation")
    value = _parse_invocation(raw, "query-child invocation")
    if (
        len(value) < 5
        or len(value[3:]) % 2 != 0
        or value[1] != "-I"
        or Path(value[0]).resolve(strict=True)
        != Path(sys.executable).resolve(strict=True)
        or Path(value[2]).name
        != "commodity_c_fast_t1_query_child_v4.py"
    ):
        raise QueryChildError("query-child invocation shape is invalid")
    return raw, value


def child_environment() -> dict[str, str]:
    allowed = ("LANG", "LC_ALL", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE", "TZ")
    return {key: os.environ[key] for key in allowed if key in os.environ}


def verify_gate_binding(
    invocation: list[str],
    expected_raw_sha256: str,
    expected_canonical_sha256: str,
) -> dict[str, Any]:
    expected_suffix = [
        GATE_HASH_FLAGS[0],
        expected_raw_sha256,
        GATE_HASH_FLAGS[1],
        expected_canonical_sha256,
    ]
    if invocation[-len(expected_suffix) :] != expected_suffix:
        raise QueryChildError(
            "audit invocation gate expectations are not bootstrap-bound"
        )
    invocation_core = invocation[: -len(expected_suffix)]
    try:
        index = invocation.index("--pre-connect-query-gate")
        gate_path = Path(invocation[index + 1])
    except (ValueError, IndexError) as exc:
        raise QueryChildError("audit invocation lacks query gate") from exc
    try:
        info = gate_path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise QueryChildError("query gate metadata is unsafe")
        raw = gate_path.read_bytes()
        payload = json.loads(raw, parse_constant=_reject_constant)
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryChildError("query gate is invalid") from exc
    if (
        hashlib.sha256(raw).hexdigest() != expected_raw_sha256
        or hashlib.sha256(canonical).hexdigest()
        != expected_canonical_sha256
    ):
        raise QueryChildError("query gate binding changed before exec")
    if not isinstance(payload, dict):
        raise QueryChildError("query gate is invalid")
    core_raw = json.dumps(
        invocation_core,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if (
        payload.get("audit_invocation_core_raw_sha256")
        != hashlib.sha256(core_raw).hexdigest()
        or payload.get("audit_invocation_core_canonical_sha256")
        != hashlib.sha256(core_raw).hexdigest()
    ):
        raise QueryChildError("audit invocation core binding changed before exec")
    return payload


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise QueryChildError(f"{label} has duplicate keys")
            result[key] = value
        return result

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryChildError(f"{label} JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise QueryChildError(f"{label} must contain one JSON object")
    return payload


def _read_fd_bounded(
    descriptor: int,
    label: str,
    *,
    limit: int = MAX_CUSTODY_JSON_BYTES,
) -> bytes:
    chunks: list[bytes] = []
    observed = 0
    while True:
        chunk = os.read(descriptor, min(65536, limit + 1 - observed))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        observed += len(chunk)
        if observed > limit:
            raise QueryChildError(f"{label} is oversized")


def _open_pinned_custody(path: Path) -> tuple[int, Path]:
    try:
        resolved = path.resolve(strict=True)
        before = resolved.lstat()
    except OSError as exc:
        raise QueryChildError("pinned custody is unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise QueryChildError("pinned custody metadata is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
        opened = os.fstat(descriptor)
        after = resolved.lstat()
    except OSError as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise QueryChildError("pinned custody cannot be opened") from exc
    identities = {
        (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            stat.S_IFMT(current.st_mode),
        )
        for current in (before, opened, after)
    }
    if len(identities) != 1:
        os.close(descriptor)
        raise QueryChildError("pinned custody changed while opening")
    return descriptor, resolved


def _read_regular_file_at(
    custody_fd: int,
    name: str,
    label: str,
) -> bytes:
    if "/" in name or name in {"", ".", ".."}:
        raise QueryChildError(f"{label} filename is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=custody_fd)
        before = os.fstat(descriptor)
        first = _read_fd_bounded(descriptor, label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_bounded(descriptor, label)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise QueryChildError(f"{label} is unavailable") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or len(first) != before.st_size
        or first != second
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise QueryChildError(f"{label} metadata or bytes are unsafe")
    return first


def _read_readiness_custody_facts(
    path: Path,
) -> tuple[Path, str, str, str]:
    custody_fd, resolved = _open_pinned_custody(path)
    try:
        info = os.fstat(custody_fd)
        identity_raw = _read_regular_file_at(
            custody_fd,
            "custody-identity.json",
            "readiness-v3 custody identity",
        )
    finally:
        os.close(custody_fd)
    identity = _parse_json_object(
        identity_raw,
        "readiness-v3 custody identity",
    )
    if (
        set(identity) != {"schema_version", "custody_id"}
        or identity.get("schema_version")
        != READINESS_CUSTODY_IDENTITY_VERSION
        or not isinstance(identity.get("custody_id"), str)
        or ID_PATTERN.fullmatch(identity["custody_id"]) is None
    ):
        raise QueryChildError("readiness-v3 custody identity is invalid")
    directory_identity = {
        "resolved_path": str(resolved),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "mode": stat.S_IMODE(info.st_mode),
        "file_type": stat.S_IFMT(info.st_mode),
    }
    return (
        resolved,
        identity["custody_id"],
        hashlib.sha256(_canonical_json(identity)).hexdigest(),
        hashlib.sha256(_canonical_json(directory_identity)).hexdigest(),
    )


def _verify_readiness_custody_facts(
    path: Path,
    expected: dict[str, str],
) -> Path:
    (
        observed_custody,
        observed_custody_id,
        observed_custody_identity_sha256,
        observed_custody_directory_identity_sha256,
    ) = _read_readiness_custody_facts(path)
    try:
        expected_custody = Path(
            expected["packet_custody_path"]
        ).resolve(strict=True)
    except OSError as exc:
        raise QueryChildError("expected custody cannot be resolved") from exc
    if (
        observed_custody != expected_custody
        or observed_custody_id != expected.get("packet_custody_id")
        or not hmac.compare_digest(
            observed_custody_identity_sha256,
            expected.get("packet_custody_identity_sha256", ""),
        )
        or not hmac.compare_digest(
            observed_custody_directory_identity_sha256,
            expected.get("packet_custody_directory_identity_sha256", ""),
        )
        or SHA256_PATTERN.fullmatch(
            expected.get("evidence_join_identity_sha256", "")
        )
        is None
    ):
        raise QueryChildError("active custody changed before query boundary")
    return observed_custody


def _entry_exists_at(custody_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=custody_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise QueryChildError("custody entry cannot be inspected") from exc
    return True


def _launch_capability_sha256(capability: bytes) -> str:
    if len(capability) != LAUNCH_CAPABILITY_BYTES:
        raise QueryChildError("query launch capability length is invalid")
    return hashlib.sha256(
        LAUNCH_CAPABILITY_DOMAIN + b"\0" + capability
    ).hexdigest()


def _launch_marker_identity_payload(
    consume: dict[str, Any],
    *,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    query_child_invocation_raw_sha256: str,
    query_child_invocation_canonical_sha256: str,
    audit_child_invocation_raw_sha256: str,
    audit_child_invocation_canonical_sha256: str,
    pre_connect_gate_raw_sha256: str,
    pre_connect_gate_canonical_sha256: str,
    parent_launch_capability_sha256: str,
) -> dict[str, Any]:
    expected_hashes = (
        consume_raw_sha256,
        consume_canonical_sha256,
        query_child_invocation_raw_sha256,
        query_child_invocation_canonical_sha256,
        audit_child_invocation_raw_sha256,
        audit_child_invocation_canonical_sha256,
        pre_connect_gate_raw_sha256,
        pre_connect_gate_canonical_sha256,
        parent_launch_capability_sha256,
    )
    if any(
        SHA256_PATTERN.fullmatch(value) is None for value in expected_hashes
    ):
        raise QueryChildError("launch marker binding SHA256 is invalid")
    return {
        "schema_version": "commodity_c_fast_t1_query_child_started_v4",
        "purpose": "c_fast_t1_one_shot_child_launch_claim_before_network",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "release_id": consume["release_id"],
        "attempt_id": consume["attempt_id"],
        "release_raw_sha256": consume["release_raw_sha256"],
        "release_canonical_sha256": consume["release_canonical_sha256"],
        "consume_marker_raw_sha256": consume_raw_sha256,
        "consume_marker_canonical_sha256": consume_canonical_sha256,
        "readiness_packet_raw_sha256": consume[
            "readiness_packet_raw_sha256"
        ],
        "readiness_packet_canonical_sha256": consume[
            "readiness_packet_canonical_sha256"
        ],
        "manifest_raw_sha256": consume["manifest_raw_sha256"],
        "manifest_canonical_sha256": consume["manifest_canonical_sha256"],
        "trusted_keyring_sha256": consume["trusted_keyring_sha256"],
        "custody_identity_sha256": consume["custody_identity_sha256"],
        "custody_path_sha256": consume["custody_path_sha256"],
        "query_child_invocation_raw_sha256": (
            query_child_invocation_raw_sha256
        ),
        "query_child_invocation_canonical_sha256": (
            query_child_invocation_canonical_sha256
        ),
        "audit_child_invocation_raw_sha256": (
            audit_child_invocation_raw_sha256
        ),
        "audit_child_invocation_canonical_sha256": (
            audit_child_invocation_canonical_sha256
        ),
        "pre_connect_gate_raw_sha256": pre_connect_gate_raw_sha256,
        "pre_connect_gate_canonical_sha256": (
            pre_connect_gate_canonical_sha256
        ),
        "parent_launch_capability_sha256": (
            parent_launch_capability_sha256
        ),
        "launch_claim_precedes_network": True,
        "query_started": False,
        "production_queried": False,
        "launch_claim_is_authority": False,
        "replay_allowed": False,
    }


def _launch_capability_binding_sha256(
    capability: bytes,
    launch_marker_identity_sha256: str,
) -> str:
    if (
        len(capability) != LAUNCH_CAPABILITY_BYTES
        or SHA256_PATTERN.fullmatch(launch_marker_identity_sha256) is None
    ):
        raise QueryChildError("launch capability binding input is invalid")
    return hashlib.sha256(
        LAUNCH_CAPABILITY_BINDING_DOMAIN
        + b"\0"
        + capability
        + b"\0"
        + bytes.fromhex(launch_marker_identity_sha256)
    ).hexdigest()


def _launch_payload(
    consume: dict[str, Any],
    *,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    query_child_invocation_raw_sha256: str,
    query_child_invocation_canonical_sha256: str,
    audit_child_invocation_raw_sha256: str,
    audit_child_invocation_canonical_sha256: str,
    pre_connect_gate_raw_sha256: str,
    pre_connect_gate_canonical_sha256: str,
    launch_capability: bytes,
    parent_launch_capability_sha256: str,
) -> dict[str, Any]:
    observed_parent_sha256 = _launch_capability_sha256(launch_capability)
    if not hmac.compare_digest(
        observed_parent_sha256,
        parent_launch_capability_sha256,
    ):
        raise QueryChildError("parent launch capability binding changed")
    identity = _launch_marker_identity_payload(
        consume,
        consume_raw_sha256=consume_raw_sha256,
        consume_canonical_sha256=consume_canonical_sha256,
        query_child_invocation_raw_sha256=(
            query_child_invocation_raw_sha256
        ),
        query_child_invocation_canonical_sha256=(
            query_child_invocation_canonical_sha256
        ),
        audit_child_invocation_raw_sha256=(
            audit_child_invocation_raw_sha256
        ),
        audit_child_invocation_canonical_sha256=(
            audit_child_invocation_canonical_sha256
        ),
        pre_connect_gate_raw_sha256=pre_connect_gate_raw_sha256,
        pre_connect_gate_canonical_sha256=(
            pre_connect_gate_canonical_sha256
        ),
        parent_launch_capability_sha256=(
            parent_launch_capability_sha256
        ),
    )
    identity_sha256 = hashlib.sha256(_canonical_json(identity)).hexdigest()
    return {
        **identity,
        "launch_marker_identity_sha256": identity_sha256,
        "launch_capability_binding_sha256": (
            _launch_capability_binding_sha256(
                launch_capability,
                identity_sha256,
            )
        ),
    }


def _validate_consume(
    consume: dict[str, Any],
    *,
    release_id: str,
    attempt_id: str,
    release_raw_sha256: str,
    release_canonical_sha256: str,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    query_v4_keyring_sha256: str,
    custody: Path,
    custody_fd: int,
) -> None:
    if set(consume) != CONSUME_FIELDS:
        raise QueryChildError("consume marker fields are invalid")
    if (
        consume.get("schema_version")
        != "commodity_c_fast_t1_query_consume_v4"
        or consume.get("purpose")
        != "c_fast_t1_query_v4_consume_before_final_revalidation"
        or consume.get("candidate_id") != "C_FAST_CROSS_SECTION_NEUTRAL"
        or consume.get("release_id") != release_id
        or consume.get("attempt_id") != attempt_id
        or consume.get("release_raw_sha256") != release_raw_sha256
        or consume.get("release_canonical_sha256")
        != release_canonical_sha256
        or consume.get("trusted_keyring_sha256")
        != query_v4_keyring_sha256
        or consume.get("consume_precedes_final_revalidation") is not True
        or consume.get("query_started") is not False
        or consume.get("production_queried") is not False
        or consume.get("consume_is_authority") is not False
        or consume.get("replay_allowed") is not False
    ):
        raise QueryChildError("consume marker binding is invalid")
    for key, value in consume.items():
        if key.endswith("_sha256") and (
            not isinstance(value, str)
            or SHA256_PATTERN.fullmatch(value) is None
        ):
            raise QueryChildError("consume marker SHA256 is invalid")
    if (
        hashlib.sha256(str(custody).encode("utf-8")).hexdigest()
        != consume["custody_path_sha256"]
    ):
        raise QueryChildError("consume marker custody path binding is invalid")
    identity_raw = _read_regular_file_at(
        custody_fd,
        "custody-identity.json",
        "custody identity",
    )
    identity = _parse_json_object(identity_raw, "custody identity")
    if (
        set(identity) != {"schema_version", "custody_id"}
        or identity.get("schema_version")
        != READINESS_CUSTODY_IDENTITY_VERSION
        or not isinstance(identity.get("custody_id"), str)
        or ID_PATTERN.fullmatch(identity["custody_id"]) is None
        or hashlib.sha256(_canonical_json(identity)).hexdigest()
        != consume["custody_identity_sha256"]
    ):
        raise QueryChildError("consume marker custody identity binding is invalid")
def claim_query_child_launch(
    custody: Path,
    *,
    release_id: str,
    attempt_id: str,
    release_raw_sha256: str,
    release_canonical_sha256: str,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    query_v4_keyring_sha256: str,
    query_child_invocation_raw_sha256: str,
    query_child_invocation_canonical_sha256: str,
    audit_child_invocation_raw_sha256: str,
    audit_child_invocation_canonical_sha256: str,
    pre_connect_gate_raw_sha256: str,
    pre_connect_gate_canonical_sha256: str,
    launch_capability: bytes,
    parent_launch_capability_sha256: str,
) -> tuple[str, str]:
    if (
        ID_PATTERN.fullmatch(release_id) is None
        or ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is None
        or any(
            SHA256_PATTERN.fullmatch(value) is None
            for value in (
                release_raw_sha256,
                release_canonical_sha256,
                consume_raw_sha256,
                consume_canonical_sha256,
                query_v4_keyring_sha256,
                query_child_invocation_raw_sha256,
                query_child_invocation_canonical_sha256,
                audit_child_invocation_raw_sha256,
                audit_child_invocation_canonical_sha256,
                pre_connect_gate_raw_sha256,
                pre_connect_gate_canonical_sha256,
                parent_launch_capability_sha256,
            )
        )
    ):
        raise QueryChildError("launch claim expectations are invalid")
    custody_fd, resolved_custody = _open_pinned_custody(custody)
    consume_name = f"{attempt_id}.query-consumed-v4.json"
    launch_name = f"{attempt_id}.query-child-started-v4.json"
    terminal_name = f"{attempt_id}.query-terminal-v4.json"
    try:
        consume_raw = _read_regular_file_at(
            custody_fd,
            consume_name,
            "query consume marker",
        )
        consume = _parse_json_object(consume_raw, "query consume marker")
        observed_consume_raw_sha256 = hashlib.sha256(consume_raw).hexdigest()
        observed_consume_canonical_sha256 = hashlib.sha256(
            _canonical_json(consume)
        ).hexdigest()
        if (
            observed_consume_raw_sha256 != consume_raw_sha256
            or observed_consume_canonical_sha256
            != consume_canonical_sha256
        ):
            raise QueryChildError("consume marker exact binding changed")
        _validate_consume(
            consume,
            release_id=release_id,
            attempt_id=attempt_id,
            release_raw_sha256=release_raw_sha256,
            release_canonical_sha256=release_canonical_sha256,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            query_v4_keyring_sha256=query_v4_keyring_sha256,
            custody=resolved_custody,
            custody_fd=custody_fd,
        )
        if _entry_exists_at(custody_fd, terminal_name):
            raise QueryChildError("query terminal already exists")
        launch = _launch_payload(
            consume,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            query_child_invocation_raw_sha256=(
                query_child_invocation_raw_sha256
            ),
            query_child_invocation_canonical_sha256=(
                query_child_invocation_canonical_sha256
            ),
            audit_child_invocation_raw_sha256=(
                audit_child_invocation_raw_sha256
            ),
            audit_child_invocation_canonical_sha256=(
                audit_child_invocation_canonical_sha256
            ),
            pre_connect_gate_raw_sha256=pre_connect_gate_raw_sha256,
            pre_connect_gate_canonical_sha256=(
                pre_connect_gate_canonical_sha256
            ),
            launch_capability=launch_capability,
            parent_launch_capability_sha256=(
                parent_launch_capability_sha256
            ),
        )
        rendered = json.dumps(
            launch,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(
                launch_name,
                flags,
                0o600,
                dir_fd=custody_fd,
            )
        except FileExistsError as exc:
            raise QueryChildError("query child launch is already claimed") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.unlink(launch_name, dir_fd=custody_fd)
                os.fsync(custody_fd)
            except OSError:
                pass
            raise
        os.fsync(custody_fd)
        launch_raw = _read_regular_file_at(
            custody_fd,
            launch_name,
            "query child launch marker",
        )
        if launch_raw != rendered:
            raise QueryChildError("query child launch marker changed after claim")
        consume_after = _read_regular_file_at(
            custody_fd,
            consume_name,
            "query consume marker",
        )
        if consume_after != consume_raw:
            raise QueryChildError("consume marker changed after launch claim")
        if _entry_exists_at(custody_fd, terminal_name):
            raise QueryChildError("query terminal appeared before network")
        return (
            hashlib.sha256(launch_raw).hexdigest(),
            hashlib.sha256(_canonical_json(launch)).hexdigest(),
        )
    finally:
        os.close(custody_fd)


def _read_launch_capability_from_environment() -> bytes:
    descriptor_text = os.environ.pop(LAUNCH_CAPABILITY_FD_ENV, None)
    if (
        descriptor_text is None
        or not descriptor_text.isascii()
        or not descriptor_text.isdecimal()
        or len(descriptor_text) > 10
    ):
        raise QueryChildError("query launch capability is unavailable")
    descriptor = int(descriptor_text)
    if descriptor < 3:
        raise QueryChildError("query launch capability descriptor is invalid")
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISFIFO(info.st_mode):
            raise QueryChildError("query launch capability is not a pipe")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                LAUNCH_CAPABILITY_BYTES + 1 - observed,
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > LAUNCH_CAPABILITY_BYTES:
                raise QueryChildError("query launch capability is oversized")
    except OSError as exc:
        raise QueryChildError("query launch capability cannot be read") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    capability = b"".join(chunks)
    if len(capability) != LAUNCH_CAPABILITY_BYTES:
        raise QueryChildError("query launch capability length is invalid")
    return capability


def verify_query_child_launch_capability(
    custody: Path,
    *,
    release_id: str,
    attempt_id: str,
    release_raw_sha256: str,
    release_canonical_sha256: str,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    query_v4_keyring_sha256: str,
    query_child_invocation_path: Path,
    audit_child_invocation_raw_sha256: str,
    audit_child_invocation_canonical_sha256: str,
    pre_connect_gate_raw_sha256: str,
    pre_connect_gate_canonical_sha256: str,
    parent_launch_capability_sha256: str,
) -> tuple[str, str]:
    capability = _read_launch_capability_from_environment()
    if not hmac.compare_digest(
        _launch_capability_sha256(capability),
        parent_launch_capability_sha256,
    ):
        raise QueryChildError("parent launch capability binding changed")
    query_invocation_raw, query_invocation = (
        _load_query_child_invocation_with_raw(query_child_invocation_path)
    )
    custody_fd, resolved_custody = _open_pinned_custody(custody)
    consume_name = f"{attempt_id}.query-consumed-v4.json"
    launch_name = f"{attempt_id}.query-child-started-v4.json"
    terminal_name = f"{attempt_id}.query-terminal-v4.json"
    try:
        consume_raw = _read_regular_file_at(
            custody_fd,
            consume_name,
            "query consume marker",
        )
        consume = _parse_json_object(consume_raw, "query consume marker")
        observed_consume_raw_sha256 = hashlib.sha256(consume_raw).hexdigest()
        observed_consume_canonical_sha256 = hashlib.sha256(
            _canonical_json(consume)
        ).hexdigest()
        if (
            observed_consume_raw_sha256 != consume_raw_sha256
            or observed_consume_canonical_sha256
            != consume_canonical_sha256
        ):
            raise QueryChildError("consume marker exact binding changed")
        _validate_consume(
            consume,
            release_id=release_id,
            attempt_id=attempt_id,
            release_raw_sha256=release_raw_sha256,
            release_canonical_sha256=release_canonical_sha256,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            query_v4_keyring_sha256=query_v4_keyring_sha256,
            custody=resolved_custody,
            custody_fd=custody_fd,
        )
        if _entry_exists_at(custody_fd, terminal_name):
            raise QueryChildError("query terminal already exists")
        launch_raw = _read_regular_file_at(
            custody_fd,
            launch_name,
            "query child launch marker",
        )
        launch = _parse_json_object(
            launch_raw,
            "query child launch marker",
        )
        expected_launch = _launch_payload(
            consume,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            query_child_invocation_raw_sha256=hashlib.sha256(
                query_invocation_raw
            ).hexdigest(),
            query_child_invocation_canonical_sha256=hashlib.sha256(
                _canonical_json(query_invocation)
            ).hexdigest(),
            audit_child_invocation_raw_sha256=(
                audit_child_invocation_raw_sha256
            ),
            audit_child_invocation_canonical_sha256=(
                audit_child_invocation_canonical_sha256
            ),
            pre_connect_gate_raw_sha256=pre_connect_gate_raw_sha256,
            pre_connect_gate_canonical_sha256=(
                pre_connect_gate_canonical_sha256
            ),
            launch_capability=capability,
            parent_launch_capability_sha256=(
                parent_launch_capability_sha256
            ),
        )
        if launch != expected_launch:
            raise QueryChildError("query child launch marker binding is invalid")
        consume_after = _read_regular_file_at(
            custody_fd,
            consume_name,
            "query consume marker",
        )
        launch_after = _read_regular_file_at(
            custody_fd,
            launch_name,
            "query child launch marker",
        )
        if consume_after != consume_raw or launch_after != launch_raw:
            raise QueryChildError(
                "query launch custody markers changed before network"
            )
        if _entry_exists_at(custody_fd, terminal_name):
            raise QueryChildError("query terminal appeared before network")
        return (
            hashlib.sha256(launch_raw).hexdigest(),
            hashlib.sha256(_canonical_json(launch)).hexdigest(),
        )
    finally:
        os.close(custody_fd)


def _launch_capability_pipe(capability: bytes) -> int:
    if len(capability) != LAUNCH_CAPABILITY_BYTES:
        raise QueryChildError("query launch capability length is invalid")
    read_descriptor, write_descriptor = os.pipe()
    try:
        os.set_inheritable(read_descriptor, True)
        written = 0
        while written < len(capability):
            written += os.write(write_descriptor, capability[written:])
        os.close(write_descriptor)
        write_descriptor = -1
        return read_descriptor
    except BaseException:
        try:
            os.close(read_descriptor)
        except OSError:
            pass
        raise
    finally:
        if write_descriptor >= 0:
            try:
                os.close(write_descriptor)
            except OSError:
                pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-invocation", type=Path, required=True)
    parser.add_argument("--expected-pin-set-generation-id", required=True)
    parser.add_argument("--expected-pin-set-manifest-sha256", required=True)
    parser.add_argument("--expected-provenance-pin", required=True)
    parser.add_argument(
        "--expected-provenance-signing-tool-source-pin",
        required=True,
    )
    parser.add_argument(
        "--expected-provenance-signing-tool-source-commit",
        required=True,
    )
    parser.add_argument("--expected-t1-pin", required=True)
    parser.add_argument("--expected-query-v4-pin", required=True)
    parser.add_argument("--expected-l3-pin", required=True)
    parser.add_argument("--expected-outcome-pin", required=True)
    parser.add_argument("--expected-custody", required=True)
    parser.add_argument("--expected-custody-id", required=True)
    parser.add_argument("--expected-custody-identity-sha256", required=True)
    parser.add_argument(
        "--expected-custody-directory-identity-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-evidence-join-identity-sha256",
        required=True,
    )
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-attempt-id", required=True)
    parser.add_argument("--expected-release-raw-sha256", required=True)
    parser.add_argument("--expected-release-canonical-sha256", required=True)
    parser.add_argument("--expected-consume-raw-sha256", required=True)
    parser.add_argument("--expected-consume-canonical-sha256", required=True)
    parser.add_argument("--expected-gate-raw-sha256", required=True)
    parser.add_argument("--expected-gate-canonical-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        unblock_control_signals()
        launch_capability = _read_launch_capability_from_environment()
        audit_invocation_raw, invocation = _load_audit_invocation_with_raw(
            args.audit_invocation
        )
        gate = verify_gate_binding(
            invocation,
            args.expected_gate_raw_sha256,
            args.expected_gate_canonical_sha256,
        )
        expected_parent_capability_sha256 = gate.get(
            "parent_launch_capability_sha256"
        )
        if (
            not isinstance(expected_parent_capability_sha256, str)
            or SHA256_PATTERN.fullmatch(
                expected_parent_capability_sha256
            )
            is None
            or not hmac.compare_digest(
                _launch_capability_sha256(launch_capability),
                expected_parent_capability_sha256,
            )
        ):
            raise QueryChildError(
                "parent launch capability does not match the frozen gate"
            )
        try:
            query_invocation_path = Path(
                gate["query_child_invocation_path"]
            )
        except (KeyError, TypeError) as exc:
            raise QueryChildError(
                "gate query-child invocation binding is invalid"
            ) from exc
        query_invocation_raw, query_invocation = (
            _load_query_child_invocation_with_raw(query_invocation_path)
        )
        actual_query_invocation = [
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            str(Path(sys.argv[0]).resolve(strict=True)),
            *sys.argv[1:],
        ]
        if query_invocation != actual_query_invocation:
            raise QueryChildError(
                "frozen query-child invocation is not the active process"
            )
        custody = verify_active_pins(
            {
                "pin_set_generation_id": args.expected_pin_set_generation_id,
                "pin_set_manifest_sha256": (
                    args.expected_pin_set_manifest_sha256
                ),
                "provenance_keyring_sha256": args.expected_provenance_pin,
                "provenance_signing_tool_source_sha256": (
                    args.expected_provenance_signing_tool_source_pin
                ),
                "provenance_signing_tool_source_commit_sha": (
                    args.expected_provenance_signing_tool_source_commit
                ),
                "t1_authority_keyring_sha256": args.expected_t1_pin,
                "query_v4": args.expected_query_v4_pin,
                "l3_authority_keyring_sha256": args.expected_l3_pin,
                "outcome_keyring_sha256": args.expected_outcome_pin,
                "packet_custody_path": args.expected_custody,
                "packet_custody_id": args.expected_custody_id,
                "packet_custody_identity_sha256": (
                    args.expected_custody_identity_sha256
                ),
                "packet_custody_directory_identity_sha256": (
                    args.expected_custody_directory_identity_sha256
                ),
                "evidence_join_identity_sha256": (
                    args.expected_evidence_join_identity_sha256
                ),
            }
        )
        if (
            gate.get("release_raw_sha256")
            != args.expected_release_raw_sha256
            or gate.get("release_canonical_sha256")
            != args.expected_release_canonical_sha256
            or gate.get("packet_custody_id")
            != args.expected_custody_id
            or gate.get("packet_custody_identity_sha256")
            != args.expected_custody_identity_sha256
            or gate.get("packet_custody_directory_identity_sha256")
            != args.expected_custody_directory_identity_sha256
            or gate.get("evidence_join_identity_sha256")
            != args.expected_evidence_join_identity_sha256
        ):
            raise QueryChildError(
                "gate release/custody binding changed before claim"
            )
        claim_query_child_launch(
            custody,
            release_id=args.expected_release_id,
            attempt_id=args.expected_attempt_id,
            release_raw_sha256=args.expected_release_raw_sha256,
            release_canonical_sha256=args.expected_release_canonical_sha256,
            consume_raw_sha256=args.expected_consume_raw_sha256,
            consume_canonical_sha256=args.expected_consume_canonical_sha256,
            query_v4_keyring_sha256=args.expected_query_v4_pin,
            query_child_invocation_raw_sha256=hashlib.sha256(
                query_invocation_raw
            ).hexdigest(),
            query_child_invocation_canonical_sha256=hashlib.sha256(
                _canonical_json(query_invocation)
            ).hexdigest(),
            audit_child_invocation_raw_sha256=hashlib.sha256(
                audit_invocation_raw
            ).hexdigest(),
            audit_child_invocation_canonical_sha256=hashlib.sha256(
                _canonical_json(invocation)
            ).hexdigest(),
            pre_connect_gate_raw_sha256=args.expected_gate_raw_sha256,
            pre_connect_gate_canonical_sha256=(
                args.expected_gate_canonical_sha256
            ),
            launch_capability=launch_capability,
            parent_launch_capability_sha256=(
                expected_parent_capability_sha256
            ),
        )
        capability_descriptor = _launch_capability_pipe(launch_capability)
        environment = child_environment()
        environment[LAUNCH_CAPABILITY_FD_ENV] = str(capability_descriptor)
        try:
            os.execve(invocation[0], invocation, environment)
        finally:
            try:
                os.close(capability_descriptor)
            except OSError:
                pass
    except (OSError, QueryChildError) as exc:
        print(f"T1 query child blocked before network: {exc}", file=sys.stderr)
        return 78
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
