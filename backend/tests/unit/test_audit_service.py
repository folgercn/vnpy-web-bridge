from __future__ import annotations

import json

from app.services.audit_service import AuditService


def test_audit_service_writes_sanitized_json_line(tmp_path) -> None:
    log_path = tmp_path / "audit.log"
    service = AuditService(log_path)

    service.record(
        action="order_request",
        request={"symbol": "rb2610", "auth_token": "secret"},
        result={"ok": True},
        source_ip="127.0.0.1",
    )

    line = log_path.read_text(encoding="utf-8").strip()
    payload = json.loads(line)
    assert payload["action"] == "order_request"
    assert payload["request"]["auth_token"] == "***"
    assert payload["source_ip"] == "127.0.0.1"
