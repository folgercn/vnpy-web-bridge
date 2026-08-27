from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts", Path(__file__).parent):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from test_issue362_simnow_continuous_run_once import (  # noqa: E402
    _production_backend_without_clients,
    runner,
)


@pytest.mark.parametrize(
    ("has_intent", "expected_error"),
    [
        (False, "start was rejected before broker mutation"),
        (True, "start outcome is unknown; query only"),
    ],
)
def test_explicit_start_rejection_requires_zero_work_boundary(
    tmp_path: Path, has_intent: bool, expected_error: str
) -> None:
    backend = _production_backend_without_clients(tmp_path, enabled=True)
    plan_id = "continuous-open-plan-rejected-0001"
    plan_hash = "a" * 64
    previewed = {
        "state_version": 7,
        "lifecycle": "READY",
        "plan": {
            "state": "PREVIEWED",
            "plan_id": f"preview-{plan_hash[:16]}",
            "plan_hash": plan_hash,
        },
        "authority": {
            "state": "ENABLED",
            "artifact_id": plan_id,
            "artifact_hash": plan_hash,
            "expires_at": "2099-01-01T00:00:00Z",
        },
        "leader": {"held": False},
        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
        "broker": {"active_order_count": 0},
        "send_intents": ([{"state": "TERMINAL"}] if has_intent else []),
        "safe_to_restart": False,
    }

    class Execution:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.token = SimpleNamespace(epoch=5, fencing_token=8)

        async def status(self):
            self.calls.append("status")
            return SimpleNamespace(as_dict=lambda: previewed)

        async def acquire_leader(self, _owner_id):
            self.calls.append("acquire")
            return self.token

        async def renew_leader(self, token):
            assert token is self.token
            self.calls.append("renew")
            return token

        async def submit(self, _command):
            self.calls.append("start")
            raise runner.ExecutionRejectedError("start rejected", status_code=409)

        async def receipt(self, _key, *, actor):
            assert actor["principal"] == "control-api"
            self.calls.append("receipt")
            return None

        async def release_leader(self, token):
            assert token is self.token
            self.calls.append("release")

    execution = Execution()
    backend.execution = execution
    recovery = {
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "phase": "OPEN",
        "custody_idempotency_key": "b" * 64,
        "start_quote_proof_state": "READY",
        "expected_after_position_hash": "c" * 64,
        "receipt_id": "receipt-rejected-0001",
        "receipt_sha256": "e" * 64,
        "artifact_id": plan_id,
        "artifact_sha256": "d" * 64,
        "expires_at": "2099-01-01T00:00:00Z",
    }

    with pytest.raises(runner.ContinuousRunError, match=expected_error):
        asyncio.run(backend._drive_installed_plan(recovery))

    assert execution.calls.count("start") == 1
    assert execution.calls.count("receipt") == 1
    assert execution.calls[-1] == "release"
