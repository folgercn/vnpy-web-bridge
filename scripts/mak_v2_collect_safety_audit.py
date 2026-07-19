from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


AUDIT_PATH = "/api/mak-v2/testnet-observer/safety-audit"
LATEST_PATH = "/api/mak-v2/testnet-observer/safety-audit/latest"
HISTORY_PATH = "/api/mak-v2/testnet-observer/safety-audits"
RESULT_JSON = "mak_v2_safety_audit.json"
CHECKS_CSV = "mak_v2_safety_audit_checks.csv"
ACCOUNTS_CSV = "mak_v2_safety_audit_accounts.csv"
CONTRACTS_CSV = "mak_v2_safety_audit_contracts.csv"
LATEST_JSON = "mak_v2_safety_audit_latest.json"
HISTORY_JSON = "mak_v2_safety_audit_history.json"
HISTORY_CSV = "mak_v2_safety_audit_history.csv"


class AuditCollectionError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect read-only MAK v2 safety-audit evidence from a deployed vnpy-web-bridge backend.",
    )
    parser.add_argument("--base-url", required=True, help="Backend base URL, for example https://bridge.example.com")
    parser.add_argument(
        "--token-env",
        default="VNPY_WEB_BRIDGE_TOKEN",
        help="Environment variable that contains an admin bearer token. The token is never read from CLI args.",
    )
    parser.add_argument("--output-dir", required=True, help="Directory where JSON and CSV artifacts will be written.")
    parser.add_argument("--probe-rpc", action="store_true", help="Ask the backend audit endpoint to probe RPC status.")
    parser.add_argument(
        "--collect-rpc-snapshot",
        action="store_true",
        help="Ask the backend audit endpoint to collect read-only account/contract/position snapshots.",
    )
    parser.add_argument(
        "--require-rpc-connected",
        action="store_true",
        help="Treat RPC disconnected status and snapshot errors as FAIL in the backend audit result.",
    )
    parser.add_argument(
        "--contract",
        action="append",
        default=[],
        help="Expected exact GFEX contract, repeatable. Example: --contract GFEX.ps2609 --contract GFEX.lc2609",
    )
    parser.add_argument(
        "--collect-latest",
        action="store_true",
        help="After POST audit, GET the read-only latest safety-audit endpoint and write a JSON artifact.",
    )
    parser.add_argument(
        "--collect-history",
        action="store_true",
        help="After POST audit, GET the read-only safety-audit history endpoint and write JSON/CSV artifacts.",
    )
    parser.add_argument(
        "--history-limit",
        type=_positive_int,
        default=200,
        help="Maximum history rows to request when --collect-history is set. Default: 200.",
    )
    return parser


def build_endpoint(base_url: str, path: str = AUDIT_PATH) -> str:
    cleaned = base_url.rstrip("/")
    if cleaned.endswith("/api"):
        return f"{cleaned}{path.removeprefix('/api')}"
    return f"{cleaned}{path}"


def build_history_endpoint(base_url: str, limit: int) -> str:
    return f"{build_endpoint(base_url, HISTORY_PATH)}?{urlencode({'limit': limit})}"


def post_safety_audit(endpoint: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = request_api_data(endpoint, token, method="POST", payload=payload)
    if not isinstance(data, dict):
        raise AuditCollectionError("response data was not an object")
    return data


def get_api_data(endpoint: str, token: str) -> Any:
    return request_api_data(endpoint, token, method="GET")


def request_api_data(endpoint: str, token: str, *, method: str, payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    request = Request(
        endpoint,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=60) as response:
            raw_body = response.read()
    except HTTPError as exc:
        message = _response_error_message(exc)
        raise AuditCollectionError(f"HTTP {exc.code}: {message}") from exc
    except URLError as exc:
        raise AuditCollectionError(f"request failed: {_safe_error_text(str(exc.reason))}") from exc

    try:
        decoded = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditCollectionError("response was not valid JSON") from exc

    if not isinstance(decoded, dict):
        raise AuditCollectionError("response JSON was not an object")
    if decoded.get("ok") is not True:
        error = decoded.get("error") if isinstance(decoded.get("error"), dict) else {}
        code = _safe_error_text(str(error.get("code") or "API_ERROR"))
        message = _safe_error_text(str(error.get("message") or "request failed"))
        raise AuditCollectionError(f"{code}: {message}")
    data = decoded.get("data")
    return data


def write_artifacts(result: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / RESULT_JSON).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(output_dir / CHECKS_CSV, ["name", "status", "observed_json"], _check_rows(result))
    snapshot = result.get("snapshot") if isinstance(result.get("snapshot"), dict) else {}
    accounts = snapshot.get("accounts") if isinstance(snapshot.get("accounts"), list) else []
    contracts = snapshot.get("gfex_contracts") if isinstance(snapshot.get("gfex_contracts"), list) else []
    _write_csv(
        output_dir / ACCOUNTS_CSV,
        ["account_hash", "account_tail", "gateway_name", "balance", "available"],
        _dict_rows(accounts, ["account_hash", "account_tail", "gateway_name", "balance", "available"]),
    )
    _write_csv(
        output_dir / CONTRACTS_CSV,
        ["vt_symbol", "symbol", "exchange", "pricetick", "size", "gateway_name"],
        _dict_rows(contracts, ["vt_symbol", "symbol", "exchange", "pricetick", "size", "gateway_name"]),
    )


def write_latest_artifact(latest: Any, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / LATEST_JSON, latest)


def write_history_artifacts(history: Any, output_dir: Path) -> None:
    if not isinstance(history, list):
        raise AuditCollectionError("history response data was not a list")
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / HISTORY_JSON, history)
    _write_csv(
        output_dir / HISTORY_CSV,
        [
            "row",
            "audit_time_utc",
            "mode",
            "overall",
            "single_order_smoke_allowed",
            "failed_checks",
            "watched_checks",
            "rpc_connected",
            "observer_enabled",
            "manual_approval",
            "testnet_mode",
        ],
        _history_rows(history),
    )


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _check_rows(result: dict[str, Any]) -> list[dict[str, str]]:
    checks = result.get("checks")
    if not isinstance(checks, list):
        return []
    rows: list[dict[str, str]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        rows.append(
            {
                "name": str(check.get("name") or ""),
                "status": str(check.get("status") or ""),
                "observed_json": json.dumps(check.get("observed"), ensure_ascii=False, sort_keys=True),
            }
        )
    return rows


def _dict_rows(values: list[Any], fieldnames: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        rows.append({field: value.get(field, "") for field in fieldnames})
    return rows


def _history_rows(history: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(history, start=1):
        if not isinstance(item, dict):
            continue
        checks = item.get("checks") if isinstance(item.get("checks"), list) else []
        failed = [str(check.get("name") or "") for check in checks if isinstance(check, dict) and check.get("status") == "FAIL"]
        watched = [str(check.get("name") or "") for check in checks if isinstance(check, dict) and check.get("status") == "WATCH"]
        rpc = item.get("rpc") if isinstance(item.get("rpc"), dict) else {}
        observer = item.get("observer") if isinstance(item.get("observer"), dict) else {}
        rows.append(
            {
                "row": index,
                "audit_time_utc": item.get("audit_time_utc", ""),
                "mode": item.get("mode", ""),
                "overall": item.get("overall", ""),
                "single_order_smoke_allowed": item.get("single_order_smoke_allowed", ""),
                "failed_checks": ",".join(name for name in failed if name),
                "watched_checks": ",".join(name for name in watched if name),
                "rpc_connected": rpc.get("connected", ""),
                "observer_enabled": observer.get("enabled", ""),
                "manual_approval": observer.get("manual_approval", ""),
                "testnet_mode": observer.get("testnet_mode", ""),
            }
        )
    return rows


def _response_error_message(exc: HTTPError) -> str:
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except Exception:
        return _safe_error_text(str(exc.reason))
    if isinstance(payload, dict):
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        if error:
            code = str(error.get("code") or "HTTP_ERROR")
            message = str(error.get("message") or exc.reason)
            return _safe_error_text(f"{code}: {message}")
    return _safe_error_text(str(exc.reason))


def _safe_error_text(value: str) -> str:
    return value.replace("\n", " ")[:240]


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def main() -> int:
    args = build_parser().parse_args()
    token = os.getenv(args.token_env)
    if not token:
        print(f"error: token environment variable {args.token_env!r} is not set", file=sys.stderr)
        return 2

    payload = {
        "probe_rpc": bool(args.probe_rpc),
        "collect_rpc_snapshot": bool(args.collect_rpc_snapshot),
        "require_rpc_connected": bool(args.require_rpc_connected),
        "expected_exact_contracts": list(args.contract),
    }

    try:
        result = post_safety_audit(build_endpoint(args.base_url), token, payload)
        output_dir = Path(args.output_dir)
        write_artifacts(result, output_dir)
        if args.collect_latest:
            latest = get_api_data(build_endpoint(args.base_url, LATEST_PATH), token)
            write_latest_artifact(latest, output_dir)
        if args.collect_history:
            history = get_api_data(build_history_endpoint(args.base_url, args.history_limit), token)
            write_history_artifacts(history, output_dir)
    except AuditCollectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: failed to write artifacts: {_safe_error_text(str(exc))}", file=sys.stderr)
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if result.get("overall") != "PASS":
        print(f"error: safety audit overall={result.get('overall')!r}; artifacts were written", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
