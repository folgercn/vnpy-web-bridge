from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any
from zoneinfo import ZoneInfo


class AuditService:
    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path or Path("logs/audit.log")
        self._lock = Lock()

    def record(
        self,
        *,
        action: str,
        request: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        operator: str = "anonymous",
        source_ip: str | None = None,
    ) -> None:
        payload = {
            "ts": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="milliseconds"),
            "operator": operator,
            "action": action,
            "request": self._sanitize(request or {}),
            "result": self._sanitize(result or {}),
            "error": error,
            "source_ip": source_ip,
        }
        line = json.dumps(payload, ensure_ascii=False, default=str)
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as file:
                file.write(f"{line}\n")

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "***" if self._is_sensitive_key(key) else self._sanitize(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._sanitize(item) for item in value]
        return value

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.lower()
        return any(part in normalized for part in ("password", "passwd", "auth", "token", "secret"))


audit_service = AuditService()
