from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

from scripts.phase_c_faults import run_fault_acceptance

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = ROOT / "docs" / "schemas"
SCENARIO_SCHEMA = json.loads(
    (SCHEMA_DIR / "issue-291-phase-c-fault-scenario-v1.schema.json").read_text()
)
BUNDLE_SCHEMA = json.loads(
    (SCHEMA_DIR / "issue-291-phase-c-fault-evidence-bundle-v1.schema.json").read_text()
)


def _validator() -> Draft202012Validator:
    resolver = RefResolver(
        base_uri=f"{SCHEMA_DIR.as_uri()}/",
        referrer=BUNDLE_SCHEMA,
        store={SCENARIO_SCHEMA["$id"]: SCENARIO_SCHEMA},
    )
    return Draft202012Validator(BUNDLE_SCHEMA, resolver=resolver)


def test_phase_c_fault_schemas_are_strict_draft202012_contracts() -> None:
    Draft202012Validator.check_schema(SCENARIO_SCHEMA)
    Draft202012Validator.check_schema(BUNDLE_SCHEMA)
    assert BUNDLE_SCHEMA["properties"]["production"] == {"const": False}
    assert BUNDLE_SCHEMA["properties"]["live"] == {"const": False}
    assert BUNDLE_SCHEMA["properties"]["countable_forward"] == {"const": False}


def test_phase_c_fault_harness_is_offline_deterministic_and_covers_required_faults(
    tmp_path: Path,
) -> None:
    bundle = run_fault_acceptance(tmp_path)
    assert list(_validator().iter_errors(bundle)) == []
    assert bundle["execution_mode"] == "offline_deterministic"
    assert bundle["production"] is False
    assert bundle["live"] is False
    assert bundle["countable_forward"] is False
    assert {item["case_id"] for item in bundle["scenarios"]} == {
        "double_leader_pause_expiry_partition_rejoin",
        "stale_token_send_cancel_final_fence",
        "rpc_timeout_unknown_same_intent_no_replay",
        "crash_before_after_gateway_and_restart_reconcile",
        "delayed_duplicate_callback_idempotent",
        "custody_tamper_replay_toctou_receipts",
    }
    assert all(item["status"] == "passed" for item in bundle["scenarios"])
