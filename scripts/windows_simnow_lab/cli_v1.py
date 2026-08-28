"""Minimal M2 client for the Issue #462 Windows SIMNOW_LAB RPCs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - import compatibility for Windows CI
    fcntl = None  # type: ignore[assignment]

from scripts import simnow_experimental_materialize_target as source_target

TARGET_SCHEMA, STRATEGY_ID = "simnow_lab_target_v1", "STATIC_CORE_EQUAL"
RPC_APPLY, RPC_GET = "simnow_lab_apply_target_v1", "simnow_lab_get_run_v1"
PRODUCT_EXCHANGES = {
    "ag": "SHFE", "al": "SHFE", "au": "SHFE", "bu": "SHFE", "cu": "SHFE",
    "rb": "SHFE", "ru": "SHFE", "sc": "INE", "sp": "SHFE", "zn": "SHFE",
}
PRODUCTS = tuple(PRODUCT_EXCHANGES)
DEFAULT_REQUEST_ADDRESS = os.environ.get("VNPY_RPC_REQ_ADDRESS", "tcp://192.168.100.187:2014")
DEFAULT_PUBLISH_ADDRESS = os.environ.get("VNPY_RPC_PUB_ADDRESS", "tcp://192.168.100.187:4102")


class SimNowLabCliError(ValueError):
    """Stable rejection for local target input or RPC setup."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _target_id(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("target_id", None)
    return hashlib.sha256(canonical_json(body)).hexdigest()


def _source_rows(value: Any) -> list[Mapping[str, Any]]:
    try:
        source = source_target.validate_target(value)
    except source_target.ExperimentalTargetError as exc:
        raise SimNowLabCliError("SOURCE_TARGET_INVALID") from exc
    rows = {row["product"]: row for row in source["targets"]}
    return [rows[product] for product in PRODUCTS]


def materialize_lab_target(source: Any) -> dict[str, Any]:
    """Convert only the current exact route shape; quantities stay untouched."""

    rows = _source_rows(source)
    target: dict[str, Any] = {
        "schema_version": TARGET_SCHEMA,
        "strategy_id": STRATEGY_ID,
        "generated_at": source["generated_at"],
        "targets": [
            {
                "product": row["product"],
                "vt_symbol": f"{row['exact_contract'].split('.', 1)[1]}.{row['exact_contract'].split('.', 1)[0]}",
                "quantity": row["quantity"],
            }
            for row in rows
        ],
    }
    target["target_id"] = _target_id(target)
    return target


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SimNowLabCliError("JSON_READ_FAILED") from exc


def read_lab_target(path: Path) -> dict[str, Any]:
    value = read_json(path)
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "strategy_id", "generated_at", "target_id", "targets",
    }:
        raise SimNowLabCliError("LAB_TARGET_INVALID")
    if value.get("schema_version") != TARGET_SCHEMA or value.get("strategy_id") != STRATEGY_ID:
        raise SimNowLabCliError("LAB_TARGET_INVALID")
    if value.get("target_id") != _target_id(value):
        raise SimNowLabCliError("LAB_TARGET_ID_INVALID")
    return value


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@contextmanager
def one_shot_lock(path: Path):
    """Take a non-blocking per-target lock for the launchd one-shot."""

    if fcntl is None:
        raise SimNowLabCliError("LAB_LOCK_UNAVAILABLE")

    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SimNowLabCliError("LAB_ALREADY_RUNNING") from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def create_rpc_client() -> Any:
    try:
        from vnpy.rpc import RpcClient
    except ImportError as exc:  # pragma: no cover - deployment dependency
        raise SimNowLabCliError("VNPY_RPC_CLIENT_UNAVAILABLE") from exc
    return RpcClient()


def rpc_call(*, method: str, args: tuple[Any, ...], request_address: str, publish_address: str, timeout_ms: int) -> Any:
    client = create_rpc_client()
    client.start(request_address, publish_address)
    try:
        remote = getattr(client, method)
        return remote(*args, timeout=timeout_ms)
    finally:
        client.stop()
        client.join()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Issue #462 SIMNOW_LAB M2 target client")
    commands = parser.add_subparsers(dest="command", required=True)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("--input", required=True, type=Path)
    materialize.add_argument("--output", required=True, type=Path)
    for command in (commands.add_parser("apply"), commands.add_parser("get-run"), commands.add_parser("current")):
        command.add_argument("--request-address", default=DEFAULT_REQUEST_ADDRESS)
        command.add_argument("--publish-address", default=DEFAULT_PUBLISH_ADDRESS)
        command.add_argument("--timeout-ms", type=int, default=30_000)
    one_shot = commands.add_parser("run-once")
    one_shot.add_argument("--input", required=True, type=Path)
    one_shot.add_argument("--output", required=True, type=Path)
    one_shot.add_argument("--request-address", default=DEFAULT_REQUEST_ADDRESS)
    one_shot.add_argument("--publish-address", default=DEFAULT_PUBLISH_ADDRESS)
    one_shot.add_argument("--timeout-ms", type=int, default=30_000)
    apply = commands.choices["apply"]
    apply.add_argument("--target", required=True, type=Path)
    commands.choices["get-run"].add_argument("--run-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "materialize":
            target = materialize_lab_target(read_json(args.input))
            write_json_atomic(args.output, target)
            result: Any = {"status": "MATERIALIZED", "target_id": target["target_id"]}
        elif args.command == "run-once":
            with one_shot_lock(args.output):
                source = read_json(args.input)
                target = materialize_lab_target(source)
                write_json_atomic(args.output, target)
                current = rpc_call(
                    method=RPC_GET,
                    args=("CURRENT",),
                    request_address=args.request_address,
                    publish_address=args.publish_address,
                    timeout_ms=args.timeout_ms,
                )
                if not isinstance(current, Mapping):
                    raise SimNowLabCliError("CURRENT_INVALID")
                active_count = current.get("active_order_count")
                if type(active_count) is not int or active_count < 0:
                    raise SimNowLabCliError("CURRENT_INVALID")
                if active_count > 0:
                    raise SimNowLabCliError("ACTIVE_ORDERS_PRESENT")
                applied = rpc_call(
                    method=RPC_APPLY,
                    args=(target,),
                    request_address=args.request_address,
                    publish_address=args.publish_address,
                    timeout_ms=args.timeout_ms,
                )
                if not isinstance(applied, Mapping):
                    raise SimNowLabCliError("APPLY_RESULT_INVALID")
                run = applied.get("run")
                run_id = run.get("run_id") if isinstance(run, Mapping) else None
                if not isinstance(run_id, str):
                    raise SimNowLabCliError("RUN_ID_MISSING")
                result = rpc_call(
                    method=RPC_GET,
                    args=(run_id,),
                    request_address=args.request_address,
                    publish_address=args.publish_address,
                    timeout_ms=args.timeout_ms,
                )
                if not isinstance(result, Mapping) or not isinstance(result.get("run"), Mapping):
                    raise SimNowLabCliError("RUN_RESULT_INVALID")
                orders = result.get("orders")
                if not isinstance(orders, list):
                    raise SimNowLabCliError("RUN_RESULT_INVALID")
                if any(
                    isinstance(order, Mapping)
                    and order.get("status") in {"CREATED", "SUBMITTED", "UNKNOWN"}
                    for order in orders
                ):
                    raise SimNowLabCliError("RUN_STOP_ACTIVE_OR_UNKNOWN_ORDER")
                status = result["run"].get("status")
                if status in {"DONE", "NOOP"}:
                    pass
                elif status in {"UNKNOWN", "PARTIAL"} or result["run"].get("error") in {
                    "UNKNOWN_ORDER_PRESENT",
                    "ACTIVE_ORDERS_PRESENT",
                }:
                    raise SimNowLabCliError(f"RUN_STOP_{status or 'UNKNOWN'}")
                else:
                    raise SimNowLabCliError(f"RUN_FAILED_{status or 'UNKNOWN'}")
        elif args.command == "apply":
            target = read_lab_target(args.target)
            result = rpc_call(method=RPC_APPLY, args=(target,), request_address=args.request_address, publish_address=args.publish_address, timeout_ms=args.timeout_ms)
        elif args.command == "get-run":
            result = rpc_call(method=RPC_GET, args=(args.run_id,), request_address=args.request_address, publish_address=args.publish_address, timeout_ms=args.timeout_ms)
        else:
            result = rpc_call(method=RPC_GET, args=("CURRENT",), request_address=args.request_address, publish_address=args.publish_address, timeout_ms=args.timeout_ms)
    except (SimNowLabCliError, OSError, ValueError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
