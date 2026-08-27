"""Minimal M2 client for the Issue #462 Windows SIMNOW_LAB RPCs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

TARGET_SCHEMA = "simnow_lab_target_v1"
SOURCE_SCHEMA = "simnow-experimental-target-v1"
STRATEGY_ID = "STATIC_CORE_EQUAL"
RPC_APPLY = "simnow_lab_apply_target_v1"
RPC_GET = "simnow_lab_get_run_v1"
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
    if not isinstance(value, Mapping):
        raise SimNowLabCliError("SOURCE_TARGET_INVALID")
    if value.get("schema_version") != SOURCE_SCHEMA or value.get("strategy_id") != STRATEGY_ID:
        raise SimNowLabCliError("SOURCE_TARGET_IDENTITY_INVALID")
    if any(value.get(field) is not False for field in (
        "production", "live_trading_authorized", "countable_forward", "official_forward_claimed",
    )):
        raise SimNowLabCliError("SOURCE_TARGET_LANE_INVALID")
    generated_at = value.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
        raise SimNowLabCliError("SOURCE_TARGET_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(generated_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SimNowLabCliError("SOURCE_TARGET_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SimNowLabCliError("SOURCE_TARGET_TIME_INVALID")
    rows = value.get("targets")
    if not isinstance(rows, list) or len(rows) != len(PRODUCTS):
        raise SimNowLabCliError("SOURCE_TARGET_ROWS_INVALID")
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"product", "exact_contract", "quantity"}:
            raise SimNowLabCliError("SOURCE_TARGET_ROW_INVALID")
        product, exact_contract, quantity = row.get("product"), row.get("exact_contract"), row.get("quantity")
        exchange = PRODUCT_EXCHANGES.get(product) if isinstance(product, str) else None
        prefix = f"{exchange}.{product}" if exchange is not None else ""
        if (
            exchange is None
            or product in result
            or not isinstance(exact_contract, str)
            or not exact_contract.startswith(prefix)
            or not exact_contract[len(prefix):].isdigit()
            or isinstance(quantity, bool)
            or not isinstance(quantity, int)
        ):
            raise SimNowLabCliError("SOURCE_TARGET_ROW_INVALID")
        result[product] = row
    if tuple(result) != PRODUCTS:
        raise SimNowLabCliError("SOURCE_TARGET_PRODUCTS_INVALID")
    return [result[product] for product in PRODUCTS]


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
