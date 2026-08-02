#!/usr/bin/env python3
"""V6-only pre-connect adapter for one authorized readonly QuestDB audit.

The parent runtime burns the executable release and creates a launch claim
before this process exists.  This process accepts the corresponding opaque
capability through an inherited pipe, revalidates the exact consume/claim,
runtime package, interpreter and dependency closure, and only then opens the
DSN.  It never imports or verifies a legacy query-v3/v4/v5 release, consume
marker, launch gate or launch capability.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType
from typing import Any, Callable, Mapping


RUNNING_AS_SCRIPT = __name__ == "__main__"
CAPABILITY_BYTES = 32
CAPABILITY_FD_ENV = "BK_C_FAST_QUERY_V6_LAUNCH_CAPABILITY_FD"
CAPABILITY_DOMAIN = b"vnpy-web-bridge:c-fast-t1:query-v6:launch-capability:v1"
SCHEMA_VERSION = "commodity_c_fast_t1_query_child_launched_v6"
PURPOSE = "c_fast_t1_query_v6_one_shot_launch_claim"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_JSON_BYTES = 8 * 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ATTEMPT_RE = re.compile(r"^attempt-[0-9a-f]{64}$")


class QueryV6PreconnectError(RuntimeError):
    """Expected fail-closed v6 adapter error."""


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


def launch_capability_sha256(capability: bytes) -> str:
    if len(capability) != CAPABILITY_BYTES:
        raise QueryV6PreconnectError("query-v6 launch capability length is invalid")
    return _sha256(CAPABILITY_DOMAIN + capability)


def invocation_binding_payload(values: Mapping[str, str]) -> dict[str, str]:
    expected = {
        "dsn_file",
        "manifest",
        "json_output",
        "csv_output",
        "markdown_output",
        "readonly_proof_output",
        "consume_marker",
        "launch_marker",
        "package_manifest",
        "expected_manifest_sha256",
        "expected_endpoint_identity_sha256",
        "expected_readonly_principal_sha256",
        "expected_questdb_build_sha256",
        "consume_raw_sha256",
        "consume_canonical_sha256",
        "executable_release_raw_sha256",
        "foundation_raw_sha256",
        "pin_set_manifest_sha256",
        "execution_adapter_sha256",
        "adapter_package_manifest_sha256",
        "adapter_package_root_identity_sha256",
        "python_executable_sha256",
        "python_dependency_closure_sha256",
    }
    if set(values) != expected or any(
        not isinstance(value, str) or not value for value in values.values()
    ):
        raise QueryV6PreconnectError(
            "query-v6 adapter invocation binding is incomplete"
        )
    path_fields = {
        "dsn_file",
        "manifest",
        "json_output",
        "csv_output",
        "markdown_output",
        "readonly_proof_output",
        "consume_marker",
        "launch_marker",
        "package_manifest",
    }
    normalized = dict(values)
    for field in path_fields:
        path = Path(normalized[field])
        if not path.is_absolute():
            raise QueryV6PreconnectError(f"query-v6 adapter {field} must be absolute")
        normalized[field] = str(path)
    for field, value in normalized.items():
        if field not in path_fields and SHA_RE.fullmatch(value) is None:
            raise QueryV6PreconnectError(f"query-v6 adapter {field} is invalid")
    return normalized


def invocation_binding_sha256(values: Mapping[str, str]) -> str:
    return _sha256(canonical_json(invocation_binding_payload(values)))


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


def _require_ancestor_custody(path: Path, *, require_root_owned: bool) -> None:
    if not path.is_absolute():
        raise QueryV6PreconnectError("query-v6 custody path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise QueryV6PreconnectError(
                "query-v6 custody ancestor is unavailable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise QueryV6PreconnectError("query-v6 custody ancestor is unsafe")
        mode = stat.S_IMODE(info.st_mode)
        test_sticky = (
            not require_root_owned
            and info.st_uid == 0
            and bool(mode & stat.S_ISVTX)
            and bool(mode & 0o002)
        )
        if test_sticky:
            continue
        allowed_owners = {0} if require_root_owned else {0, os.geteuid()}
        if info.st_uid not in allowed_owners or mode & 0o022:
            raise QueryV6PreconnectError("query-v6 custody ancestor is unsafe")


def stable_read(
    path: Path,
    label: str,
    *,
    require_root_owned: bool = True,
    private: bool = False,
    limit: int = MAX_JSON_BYTES,
) -> bytes:
    _require_ancestor_custody(path.parent, require_root_owned=require_root_owned)
    try:
        path_before = path.lstat()
        if (
            stat.S_ISLNK(path_before.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_nlink != 1
            or path_before.st_size <= 0
            or path_before.st_size > limit
            or stat.S_IMODE(path_before.st_mode) & 0o022
            or (private and stat.S_IMODE(path_before.st_mode) & 0o077)
            or (
                require_root_owned
                and (path_before.st_uid != 0 or path_before.st_gid != 0)
            )
        ):
            raise QueryV6PreconnectError(f"{label} custody is unsafe")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(descriptor)
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            repeated = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise QueryV6PreconnectError(f"{label} is unavailable") from exc
    if (
        _identity(path_before) != _identity(before)
        or _identity(before) != _identity(after)
        or _identity(after) != _identity(path_after)
        or raw != repeated
        or len(raw) != before.st_size
        or len(raw) > limit
    ):
        raise QueryV6PreconnectError(f"{label} changed while read")
    return raw


def _parse_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise QueryV6PreconnectError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise QueryV6PreconnectError(f"{label} contains invalid constant {value}")

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV6PreconnectError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise QueryV6PreconnectError(f"{label} must contain one object")
    return payload


def read_launch_capability() -> bytes:
    raw_fd = os.environ.pop(CAPABILITY_FD_ENV, "")
    if not raw_fd.isdigit():
        raise QueryV6PreconnectError("query-v6 launch capability descriptor is absent")
    descriptor = int(raw_fd)
    try:
        chunks: list[bytes] = []
        remaining = CAPABILITY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        capability = b"".join(chunks)
        trailing = os.read(descriptor, 1)
    except OSError as exc:
        raise QueryV6PreconnectError(
            "query-v6 launch capability cannot be read"
        ) from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if len(capability) != CAPABILITY_BYTES or trailing:
        raise QueryV6PreconnectError("query-v6 launch capability is invalid")
    return capability


LAUNCH_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "candidate_id",
        "release_id",
        "attempt_id",
        "claimed_at",
        "consume_marker_raw_sha256",
        "consume_marker_canonical_sha256",
        "executable_release_raw_sha256",
        "foundation_raw_sha256",
        "pin_set_manifest_sha256",
        "execution_adapter_sha256",
        "adapter_package_manifest_sha256",
        "adapter_package_root_identity_sha256",
        "python_executable_sha256",
        "python_dependency_closure_sha256",
        "invocation_binding_sha256",
        "launch_capability_sha256",
        "consume_verified_before_claim",
        "final_revalidation_completed_before_claim",
        "launch_claimed",
        "dsn_secret_read",
        "network_attempted",
        "production_query_attempted",
        "launch_marker_is_authority",
        "database_mutation_authorized",
        "web_bridge_rpc_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "trading_authorized",
        "production_authorized",
        "replay_allowed",
    }
)


def verify_launch_claim(
    args: argparse.Namespace,
    capability: bytes,
    *,
    require_root_owned: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    consume_raw = stable_read(
        args.consume_marker,
        "query-v6 consume marker",
        require_root_owned=require_root_owned,
        private=True,
    )
    launch_raw = stable_read(
        args.launch_marker,
        "query-v6 launch marker",
        require_root_owned=require_root_owned,
        private=True,
    )
    consume = _parse_object(consume_raw, "query-v6 consume marker")
    launch = _parse_object(launch_raw, "query-v6 launch marker")
    if set(launch) != LAUNCH_FIELDS:
        raise QueryV6PreconnectError("query-v6 launch marker fields are invalid")
    values = _invocation_values(args)
    expected = {
        "schema_version": SCHEMA_VERSION,
        "purpose": PURPOSE,
        "candidate_id": CANDIDATE_ID,
        "attempt_id": consume.get("attempt_id"),
        "release_id": consume.get("release_id"),
        "consume_marker_raw_sha256": args.consume_raw_sha256,
        "consume_marker_canonical_sha256": args.consume_canonical_sha256,
        "executable_release_raw_sha256": args.executable_release_raw_sha256,
        "foundation_raw_sha256": args.foundation_raw_sha256,
        "pin_set_manifest_sha256": args.pin_set_manifest_sha256,
        "execution_adapter_sha256": args.execution_adapter_sha256,
        "adapter_package_manifest_sha256": args.adapter_package_manifest_sha256,
        "adapter_package_root_identity_sha256": (
            args.adapter_package_root_identity_sha256
        ),
        "python_executable_sha256": args.python_executable_sha256,
        "python_dependency_closure_sha256": args.python_dependency_closure_sha256,
        "invocation_binding_sha256": invocation_binding_sha256(values),
        "launch_capability_sha256": launch_capability_sha256(capability),
    }
    if any(launch.get(field) != value for field, value in expected.items()):
        raise QueryV6PreconnectError("query-v6 launch marker binding mismatch")
    if (
        ATTEMPT_RE.fullmatch(str(launch.get("attempt_id") or "")) is None
        or _sha256(consume_raw) != args.consume_raw_sha256
        or _sha256(canonical_json(consume)) != args.consume_canonical_sha256
        or any(
            launch.get(field) is not True
            for field in (
                "consume_verified_before_claim",
                "final_revalidation_completed_before_claim",
                "launch_claimed",
            )
        )
        or any(
            launch.get(field) is not False
            for field in (
                "dsn_secret_read",
                "network_attempted",
                "production_query_attempted",
                "launch_marker_is_authority",
                "database_mutation_authorized",
                "web_bridge_rpc_authorized",
                "order_authorized",
                "position_mutation_authorized",
                "dispatch_authorized",
                "trading_authorized",
                "production_authorized",
                "replay_allowed",
            )
        )
    ):
        raise QueryV6PreconnectError("query-v6 launch marker semantics are invalid")
    return consume, launch


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise QueryV6PreconnectError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _audit_module() -> ModuleType:
    return _load_module(
        Path(__file__).with_name("commodity_c_fast_l1_l5_audit_v4.py"),
        "_query_v6_frozen_audit_engine",
    )


def _package_module() -> ModuleType:
    return _load_module(
        Path(__file__).parent / "c_fast_t1/query_v6_preconnect_package.py",
        "_query_v6_preconnect_package",
    )


def _invocation_values(args: argparse.Namespace) -> dict[str, str]:
    return {
        field: str(getattr(args, field))
        for field in (
            "dsn_file",
            "manifest",
            "json_output",
            "csv_output",
            "markdown_output",
            "readonly_proof_output",
            "consume_marker",
            "launch_marker",
            "package_manifest",
            "expected_manifest_sha256",
            "expected_endpoint_identity_sha256",
            "expected_readonly_principal_sha256",
            "expected_questdb_build_sha256",
            "consume_raw_sha256",
            "consume_canonical_sha256",
            "executable_release_raw_sha256",
            "foundation_raw_sha256",
            "pin_set_manifest_sha256",
            "execution_adapter_sha256",
            "adapter_package_manifest_sha256",
            "adapter_package_root_identity_sha256",
            "python_executable_sha256",
            "python_dependency_closure_sha256",
        )
    }


def validate_output_paths(args: argparse.Namespace) -> None:
    inputs = {
        args.dsn_file,
        args.manifest,
        args.consume_marker,
        args.launch_marker,
        args.package_manifest,
    }
    outputs = {
        args.json_output,
        args.csv_output,
        args.markdown_output,
        args.readonly_proof_output,
    }
    if len(outputs) != 4 or inputs & outputs:
        raise QueryV6PreconnectError("query-v6 adapter path scope is invalid")
    if any(path.exists() or path.is_symlink() for path in outputs):
        raise QueryV6PreconnectError("query-v6 adapter outputs must be create-only")


def run(
    args: argparse.Namespace,
    *,
    capability: bytes,
    connector: Callable[[Path], Any] | None = None,
    audit_module: ModuleType | None = None,
    runtime_preflight: Callable[..., Any] | None = None,
    require_root_owned: bool = True,
) -> int:
    validate_output_paths(args)
    verify_launch_claim(args, capability, require_root_owned=require_root_owned)
    package = _package_module()
    preflight = runtime_preflight or package.preflight_installed_runtime
    preflight(
        args.package_manifest,
        expected_manifest_sha256=args.adapter_package_manifest_sha256,
        expected_package_root_identity_sha256=(
            args.adapter_package_root_identity_sha256
        ),
        expected_python_executable_sha256=args.python_executable_sha256,
        expected_dependency_closure_sha256=(args.python_dependency_closure_sha256),
        require_root_owned=require_root_owned,
    )
    audit = audit_module or _audit_module()
    manifest, contracts, sessions, windows = audit.load_manifest(args.manifest)
    if not hmac.compare_digest(
        audit.canonical_manifest_sha256(manifest),
        args.expected_manifest_sha256,
    ):
        raise QueryV6PreconnectError("query-v6 manifest binding mismatch")
    # This is the last v6-only boundary before the DSN secret is opened.
    verify_launch_claim(args, capability, require_root_owned=require_root_owned)
    preflight(
        args.package_manifest,
        expected_manifest_sha256=args.adapter_package_manifest_sha256,
        expected_package_root_identity_sha256=(
            args.adapter_package_root_identity_sha256
        ),
        expected_python_executable_sha256=args.python_executable_sha256,
        expected_dependency_closure_sha256=(args.python_dependency_closure_sha256),
        require_root_owned=require_root_owned,
    )
    connection_factory = connector or audit.connect_server_enforced_readonly
    conn = None
    try:
        conn = connection_factory(args.dsn_file)
        endpoint_hash = audit.connected_endpoint_identity_sha256(conn)
        if not hmac.compare_digest(
            endpoint_hash, args.expected_endpoint_identity_sha256
        ):
            raise QueryV6PreconnectError("query-v6 connected endpoint mismatch")
        before = audit.collect_readonly_proof_snapshot(conn)
        if not hmac.compare_digest(
            _sha256(before.principal.encode("utf-8")),
            args.expected_readonly_principal_sha256,
        ):
            raise QueryV6PreconnectError("query-v6 readonly principal mismatch")
        if not hmac.compare_digest(
            _sha256(before.questdb_build.encode("utf-8")),
            args.expected_questdb_build_sha256,
        ):
            raise QueryV6PreconnectError("query-v6 QuestDB build mismatch")
        evidence = audit.audit(conn, manifest, contracts, sessions, windows)
        after = audit.collect_readonly_proof_snapshot(conn)
        if before != after:
            raise QueryV6PreconnectError(
                "query-v6 readonly metadata changed during audit"
            )
        conn.close()
        conn = None
        audit.validate_json_schema(
            evidence, audit.EVIDENCE_SCHEMA_PATH, "query-v6 audit evidence"
        )
        evidence_text = json.dumps(
            evidence,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        if not evidence_text.endswith("\n"):
            evidence_text += "\n"
        proof = audit.build_readonly_proof(
            evidence,
            _sha256(evidence_text.encode("utf-8")),
            before,
            after,
            endpoint_hash,
        )
        audit.validate_json_schema(
            proof, audit.READONLY_PROOF_SCHEMA_PATH, "query-v6 readonly proof"
        )
        audit.write_text_atomic(args.json_output, evidence_text)
        audit.write_csv(args.csv_output, evidence)
        audit.write_text_atomic(args.markdown_output, audit.render_markdown(evidence))
        audit.write_text_atomic(
            args.readonly_proof_output,
            json.dumps(proof, ensure_ascii=False, indent=2, sort_keys=True),
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return 0 if evidence["summary"]["p0_pass"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in (
        "dsn-file",
        "manifest",
        "json-output",
        "csv-output",
        "markdown-output",
        "readonly-proof-output",
        "consume-marker",
        "launch-marker",
        "package-manifest",
    ):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    for flag in (
        "expected-manifest-sha256",
        "expected-endpoint-identity-sha256",
        "expected-readonly-principal-sha256",
        "expected-questdb-build-sha256",
        "consume-raw-sha256",
        "consume-canonical-sha256",
        "executable-release-raw-sha256",
        "foundation-raw-sha256",
        "pin-set-manifest-sha256",
        "execution-adapter-sha256",
        "adapter-package-manifest-sha256",
        "adapter-package-root-identity-sha256",
        "python-executable-sha256",
        "python-dependency-closure-sha256",
    ):
        parser.add_argument(f"--{flag}", required=True)
    return parser.parse_args()


def main() -> int:
    if not RUNNING_AS_SCRIPT or sys.flags.isolated != 1:
        print("query-v6 adapter requires isolated Python (-I)", file=sys.stderr)
        return 2
    try:
        capability = read_launch_capability()
        return run(parse_args(), capability=capability)
    except Exception as exc:
        print(f"query-v6 pre-connect adapter failed closed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
