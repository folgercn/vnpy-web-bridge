#!/usr/bin/env python3
"""CLI-only Phase B artifact custody entrypoint.

Custody is not a public HTTP service and has no control-plane secret.  Each
invocation opens the pinned root, claims a writer epoch, performs one bounded
operation, and exits.  A scheduler may invoke ``run`` for a readiness/audit
cycle; all artifact mutations remain in the same fenced writer implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from shared.artifact_custody import ArtifactCustody, CustodyError


def _schemas(directory: Path | None) -> dict[str, dict[str, Any]]:
    if directory is None:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for path in directory.rglob("*.schema.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        schema_id = payload.get("$id")
        if isinstance(schema_id, str) and schema_id:
            result[schema_id] = payload
            result[schema_id.rsplit("/", 1)[-1].removesuffix(".schema.json")] = payload
        properties = payload.get("properties")
        schema_version = (
            properties.get("schema_version", {}).get("const")
            if isinstance(properties, dict)
            and isinstance(properties.get("schema_version"), dict)
            else None
        )
        if isinstance(schema_version, str) and schema_version:
            result[schema_version] = payload
        result[path.name.removesuffix(".schema.json")] = payload
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phase-b-artifact-custody")
    parser.add_argument("--root", default=os.getenv("PHASE_B_CUSTODY_ROOT"))
    parser.add_argument(
        "--writer-id",
        default=os.getenv("PHASE_B_CUSTODY_WRITER_ID", "artifact-custody"),
    )
    parser.add_argument(
        "--writer-epoch", type=int, default=_writer_epoch_from_environment()
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=Path(os.getenv("PHASE_B_SCHEMA_DIR", "docs/schemas")),
    )
    parser.add_argument(
        "--projection-dir", default=os.getenv("PHASE_B_CUSTODY_PROJECTION_DIR")
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("version", "health", "ready", "audit", "run"):
        sub.add_parser(name)
    publish = sub.add_parser("publish")
    publish.add_argument("--artifact", required=True)
    publish.add_argument("--actor-id", required=True)
    publish.add_argument("--idempotency-key", required=True)
    publish.add_argument("--correlation-id", required=True)
    publish.add_argument("--expected-version", required=True, type=int)
    signed = sub.add_parser("publish-signed")
    signed.add_argument("--signed-artifact", required=True)
    signed.add_argument("--keyring", required=True)
    signed.add_argument("--expected-domain", required=True)
    signed.add_argument("--expected-key-purpose", required=True)
    signed.add_argument("--keyring-raw-sha256", required=True)
    signed.add_argument("--actor-id", required=True)
    signed.add_argument("--idempotency-key", required=True)
    signed.add_argument("--correlation-id", required=True)
    signed.add_argument("--expected-version", required=True, type=int)
    record = sub.add_parser("record")
    record.add_argument(
        "--receipt-type", required=True, choices=("install", "consume", "revoke")
    )
    record.add_argument("--artifact-id", required=True)
    record.add_argument("--actor-id", required=True)
    record.add_argument("--idempotency-key", required=True)
    record.add_argument("--correlation-id", required=True)
    record.add_argument("--expected-version", required=True, type=int)
    return parser


def _writer_epoch_from_environment() -> int | None:
    value = os.getenv("PHASE_B_CUSTODY_WRITER_EPOCH", "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _projection_payload(*, audit: dict[str, Any]) -> dict[str, Any]:
    """Build a typed, explicitly non-authoritative custody projection."""

    payload = {
        "health": {
            "service_id": "artifact-custody",
            "status": "healthy",
            "ready": True,
        },
        "readiness": {
            "service_id": "artifact-custody",
            "status": "ready",
            "ready": True,
        },
        "version": {
            "service_id": "artifact-custody",
            "contract_versions": ["phase_b_worker_contract_v1"],
            "version": "phase-b-artifact-custody-v1",
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "private_key_access": False,
            "trade_rpc_access": False,
            "account_access": False,
            "order_access": False,
        },
    }
    return {
        "schema_version": "phase-b-worker-projection-v1",
        "service_id": "artifact-custody",
        "generation": f"artifact-custody:{audit['version']}",
        "payload": payload,
        "payload_sha256": hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "projected_at_utc": _utc_now(),
        "production": False,
        "live": False,
        "countable_forward": False,
    }


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _publish_projection(directory: str | None, *, audit: dict[str, Any]) -> None:
    if not directory:
        return
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise CustodyError("CUSTODY_PROJECTION_DIRECTORY_INVALID")
    os.chmod(root, 0o700)
    target = root / "artifact-custody.json"
    temporary = root / f".artifact-custody.{uuid.uuid4().hex}.tmp"
    raw = (
        json.dumps(
            _projection_payload(audit=audit), sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode("utf-8")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise CustodyError("CUSTODY_PROJECTION_WRITE_FAILED")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, target)
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _load_json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CustodyError("CUSTODY_REQUEST_INVALID") from exc
    if not isinstance(value, dict):
        raise CustodyError("CUSTODY_REQUEST_INVALID")
    return value


def _ready(root: str | None) -> dict[str, Any]:
    if not root:
        raise CustodyError("CUSTODY_ROOT_REQUIRED")
    path = Path(root)
    try:
        info = path.lstat()
    except OSError as exc:
        raise CustodyError("CUSTODY_ROOT_UNAVAILABLE") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise CustodyError("CUSTODY_ROOT_NOT_READY")
    return {
        "service": "artifact-custody",
        "version": "phase-b-artifact-custody-v1",
        "status": "ready",
        "private_key_access": False,
        "trade_rpc_access": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "version":
        print("phase-b-artifact-custody-v1")
        return 0
    if args.command == "health":
        print(
            json.dumps(
                {
                    "service": "artifact-custody",
                    "version": "phase-b-artifact-custody-v1",
                    "status": "ok",
                    "private_key_access": False,
                    "trade_rpc_access": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if args.command == "ready":
        try:
            print(json.dumps(_ready(args.root), sort_keys=True, separators=(",", ":")))
            return 0
        except CustodyError as exc:
            print(exc.code, file=sys.stderr)
            return 2
    if not args.root:
        print("CUSTODY_ROOT_REQUIRED", file=sys.stderr)
        return 2
    try:
        if (
            args.command in {"audit", "run", "publish", "publish-signed", "record"}
            and args.writer_epoch is None
        ):
            raise CustodyError("CUSTODY_WRITER_EPOCH_REQUIRED")
        registry = _schemas(args.schema_dir)
        if (
            args.command in {"audit", "run", "publish", "publish-signed", "record"}
            and not registry
        ):
            raise CustodyError("CUSTODY_SCHEMA_REGISTRY_REQUIRED")
        with ArtifactCustody(
            args.root,
            writer_id=args.writer_id,
            writer_epoch=args.writer_epoch,
            schema_registry=registry,
        ) as custody:
            if args.command in {"ready", "audit"}:
                payload = {
                    "service": "artifact-custody",
                    "version": "phase-b-artifact-custody-v1",
                    "status": "ready",
                    **custody.audit(),
                }
            elif args.command == "run":
                payload = {
                    "service": "artifact-custody",
                    "version": "phase-b-artifact-custody-v1",
                    "status": "ready",
                    **custody.audit(),
                }
                _publish_projection(args.projection_dir, audit=custody.audit())
                print(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    flush=True,
                )
                stop = False

                def _stop(*_signals: object) -> None:
                    nonlocal stop
                    stop = True

                signal.signal(signal.SIGTERM, _stop)
                signal.signal(signal.SIGINT, _stop)
                while not stop:
                    _publish_projection(args.projection_dir, audit=custody.audit())
                    time.sleep(1.0)
                return 0
            elif args.command == "publish":
                payload = custody.publish(
                    _load_json(args.artifact),
                    actor_id=args.actor_id,
                    idempotency_key=args.idempotency_key,
                    correlation_id=args.correlation_id,
                    expected_version=args.expected_version,
                )
            elif args.command == "publish-signed":
                payload = custody.publish_signed(
                    _load_json(args.signed_artifact),
                    keyring_path=args.keyring,
                    expected_domain=args.expected_domain,
                    expected_key_purpose=args.expected_key_purpose,
                    expected_keyring_raw_sha256=args.keyring_raw_sha256,
                    actor_id=args.actor_id,
                    idempotency_key=args.idempotency_key,
                    correlation_id=args.correlation_id,
                    expected_version=args.expected_version,
                )
            else:
                payload = custody.record(
                    args.receipt_type,
                    args.artifact_id,
                    actor_id=args.actor_id,
                    idempotency_key=args.idempotency_key,
                    correlation_id=args.correlation_id,
                    expected_version=args.expected_version,
                )
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except (CustodyError, OSError, ValueError) as exc:
        print(getattr(exc, "code", "CUSTODY_FAILED"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
