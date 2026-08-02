#!/usr/bin/env python3
"""Consume and terminalize one independently authorized query-v6 attempt.

No foundation-only release can enter this runner.  The CLI requires a distinct
executable release and an active root-pinned v6 execution adapter.  If that
deployment input is absent, verification stops before custody, DSN secret
access, consume, child launch, or network access.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping

from c_fast_t1 import query_v6_preconnect_package as preconnect_package
import commodity_c_fast_t1_query_v6_authority as foundation_v6
import commodity_c_fast_t1_query_v6_executable as executable
import commodity_c_fast_t1_query_v6_preconnect_adapter as preconnect_adapter
from commodity_c_fast_t1_one_shot import (
    ArtifactPaths,
    OneShotError,
    VerifiedRelease,
    canonical_json,
    child_environment,
    custody_entry_exists,
    open_custody_guard,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    validate_completed_outputs,
    validate_json_schema,
    validate_private_dsn_metadata,
    write_json_create_only_at,
)


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 64 * 1024 * 1024
RUNTIME_BLOCKER = "QUERY_V6_PINNED_PRECONNECT_ADAPTER_NOT_DEPLOYED"
PROCESS_GROUP_TERM_SECONDS = 2.0
PROCESS_GROUP_KILL_SECONDS = 2.0


class QueryV6RuntimeError(RuntimeError):
    """Expected fail-closed query-v6 runtime error."""


class QueryV6PrelaunchError(QueryV6RuntimeError):
    """A final package check failed before the adapter process existed."""


@dataclass(frozen=True)
class CompletedValidation:
    p0_pass: bool
    artifact_sha256: dict[str, str]
    readonly_preflight_canonical_sha256: str
    readonly_postflight_canonical_sha256: str


AdapterLauncher = Callable[..., subprocess.CompletedProcess[str]]
PackagePreflight = Callable[..., Mapping[str, Any]]
OutputValidator = Callable[
    [ArtifactPaths, executable.VerifiedExecutableRelease, int],
    CompletedValidation,
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QueryV6RuntimeError(f"{label} must include an explicit timezone")
    return value.astimezone(timezone.utc)


def _assert_same(
    expected: executable.VerifiedExecutableRelease,
    actual: executable.VerifiedExecutableRelease,
) -> None:
    if (
        expected.raw_sha256 != actual.raw_sha256
        or expected.canonical_sha256 != actual.canonical_sha256
        or expected.keyring_sha256 != actual.keyring_sha256
        or expected.payload != actual.payload
        or expected.foundation.raw_sha256 != actual.foundation.raw_sha256
        or expected.foundation.canonical_sha256 != actual.foundation.canonical_sha256
        or expected.pins != actual.pins
    ):
        raise QueryV6RuntimeError("query-v6 authority changed during execution")


def _verify_dsn_metadata(
    dsn_file: Path,
    verified: executable.VerifiedExecutableRelease,
) -> None:
    validate_private_dsn_metadata(dsn_file)
    attestation = verified.foundation.evidence.dsn_identity_attestation.payload
    try:
        resolved = dsn_file.resolve(strict=True)
        info = dsn_file.lstat()
    except OSError as exc:
        raise QueryV6RuntimeError("DSN file metadata is unavailable") from exc
    expected = {
        "dsn_file_absolute_path_sha256": _sha256(str(resolved).encode("utf-8")),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": info.st_nlink,
        "size_bytes": info.st_size,
    }
    if any(attestation.get(field) != value for field, value in expected.items()):
        raise QueryV6RuntimeError(
            "DSN file metadata does not match the secret-free attestation"
        )


def verify_query_manifest_file(
    manifest_path: Path,
    verified: executable.VerifiedExecutableRelease,
) -> None:
    try:
        info_before = manifest_path.lstat()
        raw_before = read_regular_file_strict(
            manifest_path,
            "query-v6 runtime query manifest",
            limit=MAX_BYTES,
        )
        payload = parse_json_bytes(raw_before, "query-v6 runtime query manifest")
        raw_after = read_regular_file_strict(
            manifest_path,
            "query-v6 runtime query manifest final re-read",
            limit=MAX_BYTES,
        )
        info_after = manifest_path.lstat()
    except (OSError, OneShotError) as exc:
        raise QueryV6RuntimeError(str(exc)) from exc
    if raw_before != raw_after or (
        info_before.st_dev,
        info_before.st_ino,
        info_before.st_size,
    ) != (info_after.st_dev, info_after.st_ino, info_after.st_size):
        raise QueryV6RuntimeError("query-v6 runtime query manifest changed while read")
    evidence = verified.foundation.evidence.query_manifest
    if (
        not hmac.compare_digest(_sha256(raw_before), evidence.raw_sha256)
        or not hmac.compare_digest(
            _sha256(canonical_json(payload)),
            evidence.canonical_sha256,
        )
        or payload != evidence.payload
    ):
        raise QueryV6RuntimeError(
            "runtime query manifest does not match verified foundation"
        )


def verify_execution_adapter(
    path: Path,
    verified: executable.VerifiedExecutableRelease,
    *,
    require_root_owned: bool = True,
) -> bytes:
    try:
        unresolved_info = path.lstat()
        resolved = path.resolve(strict=True)
        info_before = resolved.lstat()
        if (
            stat.S_ISLNK(unresolved_info.st_mode)
            or stat.S_ISLNK(info_before.st_mode)
            or not stat.S_ISREG(info_before.st_mode)
            or (
                require_root_owned
                and (info_before.st_uid != 0 or info_before.st_gid != 0)
            )
            or stat.S_IMODE(info_before.st_mode) & 0o022
        ):
            raise QueryV6RuntimeError("query-v6 execution adapter custody is unsafe")
        if require_root_owned:
            absolute = Path(os.path.abspath(path))
            if absolute != resolved:
                raise QueryV6RuntimeError(
                    "query-v6 execution adapter path contains a symlink"
                )
            current = resolved.parent
            while True:
                parent_info = current.lstat()
                if (
                    stat.S_ISLNK(parent_info.st_mode)
                    or not stat.S_ISDIR(parent_info.st_mode)
                    or parent_info.st_uid != 0
                    or parent_info.st_gid != 0
                    or stat.S_IMODE(parent_info.st_mode) & 0o022
                ):
                    raise QueryV6RuntimeError(
                        "query-v6 execution adapter parent custody is unsafe"
                    )
                if current.parent == current:
                    break
                current = current.parent
        raw_before = read_regular_file_strict(
            resolved,
            "query-v6 execution adapter",
            limit=MAX_BYTES,
        )
        raw_after = read_regular_file_strict(
            resolved,
            "query-v6 execution adapter final re-read",
            limit=MAX_BYTES,
        )
        info_after = resolved.lstat()
    except (OSError, OneShotError) as exc:
        raise QueryV6RuntimeError(str(exc)) from exc
    if raw_before != raw_after or (
        info_before.st_dev,
        info_before.st_ino,
        info_before.st_size,
    ) != (info_after.st_dev, info_after.st_ino, info_after.st_size):
        raise QueryV6RuntimeError("query-v6 execution adapter changed while read")
    _expected = str(verified.payload["execution"]["execution_adapter_sha256"])
    expected_path = Path(
        verified.payload["execution"]["execution_adapter_absolute_path"]
    )
    if resolved != expected_path:
        raise QueryV6RuntimeError("query-v6 execution adapter path binding mismatch")
    if not hmac.compare_digest(_sha256(raw_before), _expected):
        raise QueryV6RuntimeError("query-v6 execution adapter binding mismatch")
    return raw_before


def preflight_execution_package(
    verified: executable.VerifiedExecutableRelease,
    *,
    preflight: PackagePreflight = preconnect_package.preflight_installed_runtime,
    require_root_owned: bool = True,
) -> Mapping[str, Any]:
    execution = verified.payload["execution"]
    report = preflight(
        Path(execution["adapter_package_manifest_absolute_path"]),
        expected_manifest_sha256=execution["adapter_package_manifest_sha256"],
        expected_package_root_identity_sha256=execution[
            "adapter_package_root_identity_sha256"
        ],
        expected_python_executable_sha256=execution["python_executable_sha256"],
        expected_dependency_closure_sha256=execution[
            "python_dependency_closure_sha256"
        ],
        require_root_owned=require_root_owned,
    )
    expected = {
        "package_manifest_sha256": execution["adapter_package_manifest_sha256"],
        "package_root_identity_sha256": execution[
            "adapter_package_root_identity_sha256"
        ],
        "entrypoint": execution["execution_adapter_absolute_path"],
        "python_executable_path": execution["python_executable_path"],
        "python_executable_sha256": execution["python_executable_sha256"],
        "python_dependency_closure_sha256": execution[
            "python_dependency_closure_sha256"
        ],
    }
    if any(report.get(field) != value for field, value in expected.items()):
        raise QueryV6RuntimeError("query-v6 package preflight binding mismatch")
    return report


def _consume_payload(
    verified: executable.VerifiedExecutableRelease,
    consumed_at: datetime,
) -> dict[str, Any]:
    release = verified.payload
    foundation = release["foundation"]
    execution = release["execution"]
    return {
        "schema_version": "commodity_c_fast_t1_query_consume_v6",
        "purpose": "c_fast_t1_query_v6_consume_before_network",
        "candidate_id": executable.CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "consumed_at": _utc(consumed_at, "consume time").isoformat(),
        "executable_release_raw_sha256": verified.raw_sha256,
        "executable_release_canonical_sha256": verified.canonical_sha256,
        "executable_keyring_sha256": verified.keyring_sha256,
        "foundation_raw_sha256": foundation["raw_sha256"],
        "foundation_canonical_sha256": foundation["canonical_sha256"],
        "readiness_v4_raw_sha256": foundation["readiness_v4_raw_sha256"],
        "l3_outcome_raw_sha256": foundation["l3_outcome_raw_sha256"],
        "query_manifest_raw_sha256": foundation["query_manifest_raw_sha256"],
        "runtime_pin_manifest_sha256": foundation["runtime_pin_manifest_sha256"],
        "dsn_file_identity_attestation_raw_sha256": foundation[
            "dsn_file_identity_attestation_raw_sha256"
        ],
        "custody_identity_sha256": foundation["custody_identity_sha256"],
        "pin_set_generation_id": execution["pin_set_generation_id"],
        "pin_set_manifest_sha256": execution["pin_set_manifest_sha256"],
        "execution_adapter_sha256": execution["execution_adapter_sha256"],
        "consume_precedes_final_revalidation": True,
        "consume_precedes_dsn_secret_read": True,
        "consume_precedes_network": True,
        "query_started": False,
        "dsn_secret_read": False,
        "network_attempted": False,
        "production_query_attempted": False,
        "consume_is_authority": False,
        "database_mutation_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "replay_allowed": False,
    }


def _empty_hashes() -> dict[str, None]:
    return {
        "audit_json": None,
        "audit_csv": None,
        "audit_markdown": None,
        "readonly_proof": None,
    }


def _terminal_payload(
    verified: executable.VerifiedExecutableRelease,
    *,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    started_at: datetime,
    final_revalidation_at: datetime | None,
    ended_at: datetime,
    terminal_state: str,
    error_code: str | None,
    adapter_launch_attempted: bool,
    child_exit_code: int | None,
    child_signal: int | None,
    validation: CompletedValidation | None,
) -> dict[str, Any]:
    if ended_at < started_at or (
        final_revalidation_at is not None
        and not started_at <= final_revalidation_at <= ended_at
    ):
        raise QueryV6RuntimeError("query-v6 terminal timeline is invalid")
    completed = terminal_state in {"COMPLETED_PASS", "COMPLETED_BLOCKED"}
    incomplete = terminal_state in {"OUTCOME_UNKNOWN", "INTERRUPTED"}
    return {
        "schema_version": "commodity_c_fast_t1_query_terminal_v6",
        "purpose": "c_fast_t1_query_v6_readonly_terminal",
        "candidate_id": executable.CANDIDATE_ID,
        "release_id": verified.payload["release_id"],
        "attempt_id": verified.payload["attempt_id"],
        "terminal_state": terminal_state,
        "error_code": error_code,
        "started_at": started_at.isoformat(),
        "final_revalidation_at": (
            final_revalidation_at.isoformat()
            if final_revalidation_at is not None
            else None
        ),
        "ended_at": ended_at.isoformat(),
        "executable_release_raw_sha256": verified.raw_sha256,
        "executable_release_canonical_sha256": verified.canonical_sha256,
        "foundation_raw_sha256": verified.foundation.raw_sha256,
        "foundation_canonical_sha256": verified.foundation.canonical_sha256,
        "consume_marker_raw_sha256": consume_raw_sha256,
        "consume_marker_canonical_sha256": consume_canonical_sha256,
        "execution_adapter_sha256": verified.payload["execution"][
            "execution_adapter_sha256"
        ],
        "adapter_launch_attempted": adapter_launch_attempted,
        "child_exit_code": child_exit_code,
        "child_signal": child_signal,
        "production_query_attempted": completed or incomplete,
        "production_query_completed": (
            True if completed else (None if incomplete else False)
        ),
        "readonly_proof_verified": completed,
        "readonly_principal_verified": completed,
        "endpoint_verified": completed,
        "readonly_preflight_canonical_sha256": (
            validation.readonly_preflight_canonical_sha256
            if validation is not None
            else None
        ),
        "readonly_postflight_canonical_sha256": (
            validation.readonly_postflight_canonical_sha256
            if validation is not None
            else None
        ),
        "artifact_sha256": (
            validation.artifact_sha256 if validation is not None else _empty_hashes()
        ),
        "p0_pass": validation.p0_pass if validation is not None else None,
        "write_probe_attempted": False,
        "database_mutations_observed": 0 if completed else None,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "terminal_is_authority": False,
        "p0_acceptance_authorized": False,
        "database_mutation_authorized": False,
        "collection_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "replay_allowed": False,
    }


def _legacy_release(
    verified: executable.VerifiedExecutableRelease,
) -> VerifiedRelease:
    foundation = verified.payload["foundation"]
    manifest = verified.foundation.evidence.query_manifest.payload
    return VerifiedRelease(
        payload={
            "snapshot_id": foundation["snapshot_id"],
            "manifest_sha256": foundation["query_manifest_canonical_sha256"],
            "audit_window": foundation["audit_window"],
            "endpoint_identity_sha256": foundation["expected_endpoint_identity_sha256"],
            "questdb_build_sha256": verified.payload["execution"][
                "questdb_build_sha256"
            ],
        },
        release_sha256=verified.canonical_sha256,
        keyring_sha256=verified.keyring_sha256,
        manifest=manifest,
        bundle_files={
            "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json": (
                read_regular_file_strict(
                    executable.AUDIT_EVIDENCE_SCHEMA_PATH,
                    "query-v6 audit evidence v2 schema",
                )
            ),
            "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json": (
                read_regular_file_strict(
                    executable.LEGACY_AUDIT_EVIDENCE_SCHEMA_PATH,
                    "query-v6 audit evidence v1 schema",
                )
            ),
            "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json": (
                read_regular_file_strict(
                    executable.READONLY_PROOF_SCHEMA_PATH,
                    "query-v6 readonly proof schema",
                )
            ),
        },
    )


def validate_outputs(
    paths: ArtifactPaths,
    verified: executable.VerifiedExecutableRelease,
    child_exit_code: int,
) -> CompletedValidation:
    p0_pass, hashes = validate_completed_outputs(
        paths,
        _legacy_release(verified),
        child_exit_code,
    )
    proof_raw = read_regular_file_strict(
        paths.readonly_proof,
        "query-v6 readonly proof",
        limit=MAX_BYTES,
    )
    try:
        proof = parse_json_bytes(proof_raw, "query-v6 readonly proof")
        validate_json_schema(
            proof,
            executable.READONLY_PROOF_SCHEMA_PATH,
            "query-v6 readonly proof",
        )
    except OneShotError as exc:
        raise QueryV6RuntimeError(str(exc)) from exc
    principal_hash = _sha256(str(proof["preflight"]["principal"]).encode("utf-8"))
    if not hmac.compare_digest(
        principal_hash,
        str(verified.payload["foundation"]["expected_readonly_principal_sha256"]),
    ):
        raise QueryV6RuntimeError("readonly proof principal identity mismatch")
    return CompletedValidation(
        p0_pass=p0_pass,
        artifact_sha256=hashes,
        readonly_preflight_canonical_sha256=_sha256(canonical_json(proof["preflight"])),
        readonly_postflight_canonical_sha256=_sha256(
            canonical_json(proof["postflight"])
        ),
    )


def build_adapter_invocation(
    adapter_path: Path,
    dsn_file: Path,
    manifest_path: Path,
    paths: ArtifactPaths,
    verified: executable.VerifiedExecutableRelease,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    consume_marker_path: Path,
    launch_marker_path: Path,
) -> list[str]:
    foundation = verified.payload["foundation"]
    execution = verified.payload["execution"]
    return [
        execution["python_executable_path"],
        "-I",
        str(adapter_path),
        "--dsn-file",
        str(dsn_file.resolve(strict=True)),
        "--manifest",
        str(manifest_path.resolve(strict=True)),
        "--json-output",
        str(paths.audit_json),
        "--csv-output",
        str(paths.audit_csv),
        "--markdown-output",
        str(paths.audit_markdown),
        "--readonly-proof-output",
        str(paths.readonly_proof),
        "--consume-marker",
        str(consume_marker_path),
        "--launch-marker",
        str(launch_marker_path),
        "--package-manifest",
        execution["adapter_package_manifest_absolute_path"],
        "--expected-manifest-sha256",
        foundation["query_manifest_canonical_sha256"],
        "--expected-endpoint-identity-sha256",
        foundation["expected_endpoint_identity_sha256"],
        "--expected-readonly-principal-sha256",
        foundation["expected_readonly_principal_sha256"],
        "--expected-questdb-build-sha256",
        execution["questdb_build_sha256"],
        "--consume-raw-sha256",
        consume_raw_sha256,
        "--consume-canonical-sha256",
        consume_canonical_sha256,
        "--executable-release-raw-sha256",
        verified.raw_sha256,
        "--foundation-raw-sha256",
        verified.foundation.raw_sha256,
        "--pin-set-manifest-sha256",
        execution["pin_set_manifest_sha256"],
        "--execution-adapter-sha256",
        execution["execution_adapter_sha256"],
        "--adapter-package-manifest-sha256",
        execution["adapter_package_manifest_sha256"],
        "--adapter-package-root-identity-sha256",
        execution["adapter_package_root_identity_sha256"],
        "--python-executable-sha256",
        execution["python_executable_sha256"],
        "--python-dependency-closure-sha256",
        execution["python_dependency_closure_sha256"],
    ]


def run_adapter(
    invocation: list[str],
    *,
    cwd: Path,
    timeout: int,
    launch_capability: bytes | None = None,
    prelaunch_validator: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    if (
        threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "pthread_sigmask")
        or not hasattr(signal, "SIG_BLOCK")
        or not hasattr(signal, "SIG_SETMASK")
    ):
        raise QueryV6RuntimeError(
            "query-v6 adapter requires main-thread POSIX signal masking"
        )
    controlled_signals = tuple(
        current
        for current in (
            getattr(signal, "SIGTERM", None),
            getattr(signal, "SIGHUP", None),
            getattr(signal, "SIGINT", None),
        )
        if current is not None
    )
    previous_handlers: dict[signal.Signals, Any] = {}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, controlled_signals)
    process: subprocess.Popen[str] | None = None
    capability_read_fd: int | None = None
    capability_write_fd: int | None = None

    def interrupt_for_shutdown(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"query-v6 runner received signal {signum}")

    try:
        for current in controlled_signals:
            previous_handlers[current] = signal.getsignal(current)
            signal.signal(current, interrupt_for_shutdown)
        try:
            environment = child_environment()
            pass_fds: tuple[int, ...] = ()
            if launch_capability is not None:
                if len(launch_capability) != preconnect_adapter.CAPABILITY_BYTES:
                    raise QueryV6RuntimeError("query-v6 launch capability is invalid")
                capability_read_fd, capability_write_fd = os.pipe()
                os.set_inheritable(capability_read_fd, True)
                environment[preconnect_adapter.CAPABILITY_FD_ENV] = str(
                    capability_read_fd
                )
                pass_fds = (capability_read_fd,)
            if prelaunch_validator is not None:
                prelaunch_validator()
            process = subprocess.Popen(
                invocation,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                start_new_session=True,
                pass_fds=pass_fds,
            )
        except OSError as exc:
            raise QueryV6RuntimeError(
                "query-v6 execution adapter could not be created"
            ) from exc
        if capability_read_fd is not None:
            os.close(capability_read_fd)
            capability_read_fd = None
        if capability_write_fd is not None:
            try:
                written = os.write(capability_write_fd, launch_capability)
            except OSError as exc:
                if process is not None:
                    _terminate_adapter_process_group(process)
                raise QueryV6RuntimeError(
                    "query-v6 launch capability could not be delivered"
                ) from exc
            finally:
                os.close(capability_write_fd)
                capability_write_fd = None
            if written != len(launch_capability):
                if process is not None:
                    _terminate_adapter_process_group(process)
                raise QueryV6RuntimeError(
                    "query-v6 launch capability delivery was incomplete"
                )
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException as exc:
            if not _terminate_adapter_process_group(process):
                raise QueryV6RuntimeError(
                    "query-v6 adapter process-group cleanup could not be confirmed"
                ) from exc
            raise
        if _process_group_exists(process.pid):
            if not _terminate_adapter_process_group(process):
                raise QueryV6RuntimeError(
                    "query-v6 adapter descendant cleanup could not be confirmed"
                )
            raise QueryV6RuntimeError(
                "query-v6 adapter left a descendant process after exit"
            )
        return subprocess.CompletedProcess(
            invocation,
            process.returncode,
            stdout,
            stderr,
        )
    finally:
        for descriptor in (capability_read_fd, capability_write_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for current, previous in previous_handlers.items():
            signal.signal(current, previous)
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except BaseException:
            pass


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_process_group_exit(
    process_group_id: int,
    timeout: float,
    process: subprocess.Popen[str],
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(process_group_id):
            return True
        time.sleep(0.02)
    process.poll()
    return not _process_group_exists(process_group_id)


def _terminate_adapter_process_group(process: subprocess.Popen[str]) -> bool:
    process_group_id = process.pid
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        return False
    group_gone = _wait_process_group_exit(
        process_group_id,
        PROCESS_GROUP_TERM_SECONDS,
        process,
    )
    if not group_gone:
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        group_gone = _wait_process_group_exit(
            process_group_id,
            PROCESS_GROUP_KILL_SECONDS,
            process,
        )
    try:
        process.wait(timeout=PROCESS_GROUP_KILL_SECONDS)
    except subprocess.TimeoutExpired:
        return False
    return group_gone and not _process_group_exists(process_group_id)


def run_authorized_attempt(
    verified: executable.VerifiedExecutableRelease,
    release_path: Path,
    manifest_path: Path,
    dsn_file: Path,
    execution_adapter_path: Path,
    revalidator: Callable[[datetime], executable.VerifiedExecutableRelease],
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    adapter_launcher: AdapterLauncher = run_adapter,
    output_validator: OutputValidator = validate_outputs,
    package_preflight: PackagePreflight = (
        preconnect_package.preflight_installed_runtime
    ),
    require_root_owned_parent: bool = True,
    require_root_owned_adapter: bool = True,
) -> tuple[int, dict[str, Any]]:
    verify_query_manifest_file(manifest_path, verified)
    verify_execution_adapter(
        execution_adapter_path,
        verified,
        require_root_owned=require_root_owned_adapter,
    )
    preflight_execution_package(
        verified,
        preflight=package_preflight,
        require_root_owned=require_root_owned_adapter,
    )
    _verify_dsn_metadata(dsn_file, verified)
    custody = Path(verified.payload["foundation"]["custody_absolute_path"])
    try:
        if release_path.parent.resolve(strict=True) != custody.resolve(strict=True):
            raise QueryV6RuntimeError(
                "executable release is outside exact foundation custody"
            )
    except OSError as exc:
        raise QueryV6RuntimeError("query-v6 custody cannot be resolved") from exc
    guard = open_custody_guard(
        custody,
        require_root_owned_parent=require_root_owned_parent,
    )
    attempt_id = verified.payload["attempt_id"]
    consume_name = f"{attempt_id}.query-consumed-v6.json"
    launch_name = f"{attempt_id}.query-child-launched-v6.json"
    terminal_name = f"{attempt_id}.query-terminal-v6.json"
    attempt_dir = custody / attempt_id
    try:
        if custody_entry_exists(guard, consume_name):
            raise QueryV6RuntimeError("query-v6 executable release is already consumed")
        if custody_entry_exists(guard, terminal_name):
            raise QueryV6RuntimeError("query-v6 terminal exists without consume")
        if custody_entry_exists(guard, launch_name):
            raise QueryV6RuntimeError("query-v6 launch exists without consume")
        if custody_entry_exists(guard, attempt_id):
            raise QueryV6RuntimeError("query-v6 partial attempt directory exists")
        preconsume_at = _utc(clock(), "pre-consume time")
        preconsume = revalidator(preconsume_at)
        _assert_same(verified, preconsume)
        consumed_at = _utc(clock(), "consume time")
        if consumed_at < preconsume_at:
            raise QueryV6RuntimeError("query-v6 consume clock moved backwards")
        executable.validate_release_semantics(
            preconsume.payload,
            preconsume.foundation,
            preconsume.pins,
            now=consumed_at,
        )
        consume = _consume_payload(preconsume, consumed_at)
        consume_raw_sha256 = write_json_create_only_at(
            guard,
            consume_name,
            consume,
            executable.CONSUME_SCHEMA_PATH,
            "query-v6 consume",
        )
        consume_canonical_sha256 = _sha256(canonical_json(consume))
        final_at: datetime | None = None
        try:
            consume_raw = read_regular_file_at(
                guard,
                consume_name,
                "query-v6 consume exact reopen",
            )
            if _sha256(consume_raw) != consume_raw_sha256:
                raise QueryV6RuntimeError("query-v6 consume exact reopen failed")

            os.mkdir(attempt_id, mode=0o700, dir_fd=guard.descriptor)
            os.fsync(guard.descriptor)
            artifacts_dir = attempt_dir / "artifacts"
            artifacts_dir.mkdir(mode=0o700)
            paths = ArtifactPaths(
                audit_json=artifacts_dir / "audit.json",
                audit_csv=artifacts_dir / "audit.csv",
                audit_markdown=artifacts_dir / "audit.md",
                readonly_proof=artifacts_dir / "readonly-proof.json",
            )
            final_at = _utc(clock(), "final revalidation time")
            final = revalidator(final_at)
            _assert_same(preconsume, final)
            executable.validate_release_semantics(
                final.payload,
                final.foundation,
                final.pins,
                now=final_at,
            )
            invocation = build_adapter_invocation(
                execution_adapter_path.resolve(strict=True),
                dsn_file,
                manifest_path,
                paths,
                final,
                consume_raw_sha256,
                consume_canonical_sha256,
                custody / consume_name,
                custody / launch_name,
            )

            def final_prelaunch_check() -> None:
                try:
                    verify_query_manifest_file(manifest_path, final)
                    _verify_dsn_metadata(dsn_file, final)
                    verify_execution_adapter(
                        execution_adapter_path,
                        final,
                        require_root_owned=require_root_owned_adapter,
                    )
                    preflight_execution_package(
                        final,
                        preflight=package_preflight,
                        require_root_owned=require_root_owned_adapter,
                    )
                except Exception as exc:
                    raise QueryV6PrelaunchError(
                        "query-v6 final prelaunch validation failed"
                    ) from exc

            final_prelaunch_check()
            launch_capability = os.urandom(preconnect_adapter.CAPABILITY_BYTES)
            invocation_values = {
                "dsn_file": str(dsn_file.resolve(strict=True)),
                "manifest": str(manifest_path.resolve(strict=True)),
                "json_output": str(paths.audit_json),
                "csv_output": str(paths.audit_csv),
                "markdown_output": str(paths.audit_markdown),
                "readonly_proof_output": str(paths.readonly_proof),
                "consume_marker": str(custody / consume_name),
                "launch_marker": str(custody / launch_name),
                "package_manifest": final.payload["execution"][
                    "adapter_package_manifest_absolute_path"
                ],
                "expected_manifest_sha256": final.payload["foundation"][
                    "query_manifest_canonical_sha256"
                ],
                "expected_endpoint_identity_sha256": final.payload["foundation"][
                    "expected_endpoint_identity_sha256"
                ],
                "expected_readonly_principal_sha256": final.payload["foundation"][
                    "expected_readonly_principal_sha256"
                ],
                "expected_questdb_build_sha256": final.payload["execution"][
                    "questdb_build_sha256"
                ],
                "consume_raw_sha256": consume_raw_sha256,
                "consume_canonical_sha256": consume_canonical_sha256,
                "executable_release_raw_sha256": final.raw_sha256,
                "foundation_raw_sha256": final.foundation.raw_sha256,
                "pin_set_manifest_sha256": final.payload["execution"][
                    "pin_set_manifest_sha256"
                ],
                "execution_adapter_sha256": final.payload["execution"][
                    "execution_adapter_sha256"
                ],
                "adapter_package_manifest_sha256": final.payload["execution"][
                    "adapter_package_manifest_sha256"
                ],
                "adapter_package_root_identity_sha256": final.payload["execution"][
                    "adapter_package_root_identity_sha256"
                ],
                "python_executable_sha256": final.payload["execution"][
                    "python_executable_sha256"
                ],
                "python_dependency_closure_sha256": final.payload["execution"][
                    "python_dependency_closure_sha256"
                ],
            }
            launch = {
                "schema_version": preconnect_adapter.SCHEMA_VERSION,
                "purpose": preconnect_adapter.PURPOSE,
                "candidate_id": executable.CANDIDATE_ID,
                "release_id": final.payload["release_id"],
                "attempt_id": final.payload["attempt_id"],
                "claimed_at": final_at.isoformat(),
                "consume_marker_raw_sha256": consume_raw_sha256,
                "consume_marker_canonical_sha256": consume_canonical_sha256,
                "executable_release_raw_sha256": final.raw_sha256,
                "foundation_raw_sha256": final.foundation.raw_sha256,
                "pin_set_manifest_sha256": final.payload["execution"][
                    "pin_set_manifest_sha256"
                ],
                "execution_adapter_sha256": final.payload["execution"][
                    "execution_adapter_sha256"
                ],
                "adapter_package_manifest_sha256": final.payload["execution"][
                    "adapter_package_manifest_sha256"
                ],
                "adapter_package_root_identity_sha256": final.payload["execution"][
                    "adapter_package_root_identity_sha256"
                ],
                "python_executable_sha256": final.payload["execution"][
                    "python_executable_sha256"
                ],
                "python_dependency_closure_sha256": final.payload["execution"][
                    "python_dependency_closure_sha256"
                ],
                "invocation_binding_sha256": preconnect_adapter.invocation_binding_sha256(
                    invocation_values
                ),
                "launch_capability_sha256": preconnect_adapter.launch_capability_sha256(
                    launch_capability
                ),
                "consume_verified_before_claim": True,
                "final_revalidation_completed_before_claim": True,
                "launch_claimed": True,
                "dsn_secret_read": False,
                "network_attempted": False,
                "production_query_attempted": False,
                "launch_marker_is_authority": False,
                "database_mutation_authorized": False,
                "web_bridge_rpc_authorized": False,
                "order_authorized": False,
                "position_mutation_authorized": False,
                "dispatch_authorized": False,
                "trading_authorized": False,
                "production_authorized": False,
                "replay_allowed": False,
            }
            write_json_create_only_at(
                guard,
                launch_name,
                launch,
                executable.CHILD_LAUNCH_SCHEMA_PATH,
                "query-v6 child launch claim",
            )
        except Exception:
            ended_at = max(consumed_at, _utc(clock(), "terminal time"))
            terminal = _terminal_payload(
                verified,
                consume_raw_sha256=consume_raw_sha256,
                consume_canonical_sha256=consume_canonical_sha256,
                started_at=consumed_at,
                final_revalidation_at=None,
                ended_at=ended_at,
                terminal_state="FAILED_BEFORE_NETWORK",
                error_code="PRE_NETWORK_LAUNCH_BOUNDARY_FAILED",
                adapter_launch_attempted=False,
                child_exit_code=None,
                child_signal=None,
                validation=None,
            )
            write_json_create_only_at(
                guard,
                terminal_name,
                terminal,
                executable.TERMINAL_SCHEMA_PATH,
                "query-v6 terminal",
            )
            return 2, terminal
        result: subprocess.CompletedProcess[str] | None = None
        validation: CompletedValidation | None = None
        adapter_launch_attempted = True
        try:
            result = adapter_launcher(
                invocation,
                cwd=attempt_dir,
                timeout=verified.payload["execution"]["maximum_runtime_seconds"],
                launch_capability=launch_capability,
                prelaunch_validator=final_prelaunch_check,
            )
            if result.returncode not in {0, 1}:
                raise QueryV6RuntimeError("execution adapter outcome is unknown")
            validation = output_validator(paths, final, result.returncode)
            state = "COMPLETED_PASS" if validation.p0_pass else "COMPLETED_BLOCKED"
            exit_code = 0 if validation.p0_pass else 1
            error_code = None
        except QueryV6PrelaunchError:
            state = "FAILED_BEFORE_NETWORK"
            error_code = "PRE_NETWORK_LAUNCH_BOUNDARY_FAILED"
            exit_code = 2
            adapter_launch_attempted = False
        except subprocess.TimeoutExpired:
            state = "OUTCOME_UNKNOWN"
            error_code = "EXECUTION_ADAPTER_TIMEOUT"
            exit_code = 2
        except KeyboardInterrupt:
            state = "INTERRUPTED"
            error_code = "EXECUTION_ADAPTER_INTERRUPTED"
            exit_code = 130
        except Exception:
            state = "OUTCOME_UNKNOWN"
            error_code = "EXECUTION_ADAPTER_OUTCOME_UNKNOWN"
            exit_code = 2
        ended_at = max(final_at, _utc(clock(), "terminal time"))
        child_exit_code = (
            result.returncode
            if result is not None and 0 <= result.returncode <= 255
            else None
        )
        child_signal = (
            -result.returncode if result is not None and result.returncode < 0 else None
        )
        terminal = _terminal_payload(
            verified,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            started_at=consumed_at,
            final_revalidation_at=(final_at if adapter_launch_attempted else None),
            ended_at=ended_at,
            terminal_state=state,
            error_code=error_code,
            adapter_launch_attempted=adapter_launch_attempted,
            child_exit_code=child_exit_code,
            child_signal=child_signal,
            validation=validation,
        )
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            executable.TERMINAL_SCHEMA_PATH,
            "query-v6 terminal",
        )
        return exit_code, terminal
    except (FileExistsError, OneShotError) as exc:
        raise QueryV6RuntimeError(str(exc)) from exc
    finally:
        guard.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    executable._common_arguments(parser)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--execution-adapter", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.execution_adapter is None:
        print(f"query-v6 runtime blocked: {RUNTIME_BLOCKER}", file=sys.stderr)
        print("release_consumed=false", file=sys.stderr)
        print("dsn_secret_read=false", file=sys.stderr)
        print("network_attempted=false", file=sys.stderr)
        return 2

    def verify_at(at: datetime) -> executable.VerifiedExecutableRelease:
        foundation = executable.verify_foundation_from_args(args, now=at)
        pins = executable.read_active_pins(args.active_executable_pin_manifest)
        return executable.verify_release(
            args.signed_executable_release,
            args.executable_keyring,
            args.release_keyring,
            foundation,
            pins,
            now=at,
        )

    try:
        initial = verify_at(datetime.now(timezone.utc))
        return run_authorized_attempt(
            initial,
            args.signed_executable_release,
            args.manifest,
            args.dsn_file,
            args.execution_adapter,
            verify_at,
        )[0]
    except (
        OSError,
        OneShotError,
        foundation_v6.QueryV6AuthorityError,
        executable.QueryV6ExecutableError,
        QueryV6RuntimeError,
        ValueError,
    ) as exc:
        print(f"query-v6 runtime failed closed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
