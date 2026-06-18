from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


class AlertStateStore:
    def __init__(self, state_path: str | Path, events_path: str | Path | None = None) -> None:
        self.state_path = Path(state_path)
        self.events_path = Path(events_path) if events_path else self.state_path.with_name("events.jsonl")
        self._lock = Lock()

    def load(self) -> dict[str, Any]:
        with self._lock:
            if not self.state_path.exists():
                return self._empty_state()
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return self._empty_state()
            return self._normalize(data)

    def save(self, state: dict[str, Any]) -> None:
        payload = self._normalize(state)
        payload["updated_at"] = _utc_now()
        with self._lock:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.state_path.with_suffix(f"{self.state_path.suffix}.tmp")
            tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp_path, self.state_path)

    def append_event(self, event: dict[str, Any]) -> None:
        payload = {"timestamp": _utc_now(), **event}
        line = json.dumps(payload, ensure_ascii=False, default=str)
        with self._lock:
            self.events_path.parent.mkdir(parents=True, exist_ok=True)
            with self.events_path.open("a", encoding="utf-8") as file:
                file.write(f"{line}\n")

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self.load())

    def _normalize(self, data: dict[str, Any]) -> dict[str, Any]:
        return {
            "version": 1,
            "incidents": dict(data.get("incidents") or {}),
            "silences": dict(data.get("silences") or {}),
            "deliveries": dict(data.get("deliveries") or {}),
            "updated_at": data.get("updated_at"),
        }

    def _empty_state(self) -> dict[str, Any]:
        return {"version": 1, "incidents": {}, "silences": {}, "deliveries": {}, "updated_at": None}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
