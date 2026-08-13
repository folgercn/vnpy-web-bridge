from __future__ import annotations

import base64
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from app.execution import ExecutionOrchestrator, InMemoryExecutionRepository
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    peek_current_facts_to_snapshot,
)
from app.execution.final_runtime import (
    FinalExecutionRuntime,
    InMemoryTargetPlanRepository,
)
from app.execution.gateway import InMemoryGateway
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
)
from c_fast_producer.producer import (
    MAP_ACCEPTANCE_KEY_PURPOSE,
    MAP_ACCEPTANCE_KEY_VERSION,
    MAP_ACCEPTANCE_PRODUCER_ID,
    MAP_ACCEPTANCE_PRODUCER_VERSION,
    MAP_ACCEPTANCE_SCHEMA_REF,
    MAP_ACCEPTANCE_TRUST_DOMAIN,
    produce_c_fast_candidate,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from map.producer import build_approved_source_fixture, produce_map_candidate

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.artifact_custody.v1 import ArtifactCustody
from shared.commodity_execution import TARGET_PLAN_SCHEMA_VERSION, TargetPlan
from shared.trust_contracts.v1 import (
    build_signed_artifact,
    build_signing_request,
    canonical_json_line,
    sha256_bytes,
    signing_bytes,
)

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend/tests/unit"))

from commodity_c_fast_executable_target_adapter import (
    _reduce_only_peek_current_facts_to_snapshot,
    build_parser,
)
from commodity_c_fast_executable_target_adapter import (
    main as adapter_main,
)
from test_commodity_c_fast_pure_producer_kernel import source_view
from test_issue291_executable_target_adapter import authority, candidates

SCOPE = "account:simnow-cli"
FALSE_AUTHORITY_FIELDS = {
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "simnow_execution_authorized",
    "runtime_activation_authorized",
    "network_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "production_authorized",
    "automatic_promotion_authorized",
    "production_allowed",
    "live_allowed",
    "countable_forward",
    "authority_granted",
    "signing_requested",
    "custody_published",
}


def _signed(artifact: dict, *, private: Ed25519PrivateKey, request_id: str) -> dict:
    request = build_signing_request(
        artifact,
        domain="runtime_authorization",
        key_id="runtime-adapter-key",
        key_version="v1",
        request_id=request_id,
        requested_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    unsigned = {
        "schema_version": "web-bridge-signed-artifact-v1",
        "request_id": request["request_id"],
        "domain": request["domain"],
        "signer_key_id": request["key_id"],
        "signer_key_version": request["key_version"],
        "requested_at": request["requested_at"],
        "expires_at": request["expires_at"],
        "artifact": request["artifact"],
    }
    return build_signed_artifact(
        request,
        signature_base64=base64.b64encode(
            private.sign(signing_bytes(unsigned))
        ).decode(),
    )


def _map_acceptance(map_result) -> tuple[dict, dict]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    keyring = {
        "schema_version": "web-bridge-trust-keyring-v1",
        "domain": MAP_ACCEPTANCE_TRUST_DOMAIN,
        "key_version": MAP_ACCEPTANCE_KEY_VERSION,
        "keys": [
            {
                "key_id": "map-acceptance-cli",
                "domain": MAP_ACCEPTANCE_TRUST_DOMAIN,
                "purpose": MAP_ACCEPTANCE_KEY_PURPOSE,
                "public_key_base64": base64.b64encode(public).decode(),
                "status": "active",
            }
        ],
    }
    artifact = new_artifact_envelope(
        artifact_type="map-acceptance",
        trust_domain=MAP_ACCEPTANCE_TRUST_DOMAIN,
        producer_id=MAP_ACCEPTANCE_PRODUCER_ID,
        producer_version=MAP_ACCEPTANCE_PRODUCER_VERSION,
        schema_ref=MAP_ACCEPTANCE_SCHEMA_REF,
        payload={
            "decision": "approved",
            "map_candidate_id": map_result.payload["candidate_id"],
            "map_candidate_sha256": map_result.artifact_sha256,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        generated_at="2020-01-01T00:00:00Z",
        scope={"candidate_id": map_result.payload["candidate_id"]},
        predecessor_refs=[],
        lineage=[map_result.artifact_sha256],
    )
    request = build_signing_request(
        artifact,
        domain=MAP_ACCEPTANCE_TRUST_DOMAIN,
        key_id="map-acceptance-cli",
        key_version=MAP_ACCEPTANCE_KEY_VERSION,
        request_id="map-acceptance-cli-request",
        requested_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    unsigned = {
        "schema_version": "web-bridge-signed-artifact-v1",
        "request_id": request["request_id"],
        "domain": request["domain"],
        "signer_key_id": request["key_id"],
        "signer_key_version": request["key_version"],
        "requested_at": request["requested_at"],
        "expires_at": request["expires_at"],
        "artifact": request["artifact"],
    }
    return (
        build_signed_artifact(
            request,
            signature_base64=base64.b64encode(
                private.sign(signing_bytes(unsigned))
            ).decode(),
        ),
        keyring,
    )


def _write(path: Path, value: dict | bytes) -> None:
    path.write_bytes(value if isinstance(value, bytes) else canonical_json_line(value))


def _peek(positions: dict) -> dict:
    return {
        "schema_version": "windows_execution_current_facts_v1",
        "position_query_complete": True,
        "account": {
            "CTP.simnow-cli": {
                "accountid": "simnow-cli",
                "gateway_name": "CTP",
            }
        },
        "positions": positions,
        "active_orders": {},
        "gateway": {
            "gateway_name": "CTP",
            "account_scope": SCOPE,
            "environment": "simnow",
            "connected": True,
        },
        "execution": {"orders": {}},
        "admission": {
            "account_scope": SCOPE,
            "environment": "simnow",
            "durable_state_version": 1,
            "durable_state_hash": "a" * 64,
            "snapshot_generation": 1,
            "fence": {
                "active": False,
                "current_epoch": 0,
                "current_fencing_token": 0,
                "high_water_epoch": 0,
                "high_water_fencing_token": 0,
            },
            "receipt_intents": [],
        },
    }


@pytest.mark.parametrize(
    "account,connected",
    [
        ({}, False),
        ({"CTP.simnow-cli": {"accountid": "simnow-cli", "gateway_name": "CTP"}}, False),
        ({}, True),
    ],
    ids=["empty-account", "connected-false", "account-connected-mismatch"],
)
def test_peek_current_facts_requires_live_ctp_account(
    account: dict, connected: bool
) -> None:
    facts = _peek({})
    facts["account"] = account
    facts["gateway"]["connected"] = connected

    with pytest.raises(ExecutableTargetAdapterError):
        peek_current_facts_to_snapshot(facts, account_scope=SCOPE)


def test_peek_default_mode_rejects_terminal_execution_order() -> None:
    facts = _peek({})
    facts["execution"]["orders"] = {"CTP.terminal": {"status": "ALLTRADED"}}

    with pytest.raises(ExecutableTargetAdapterError, match="execution orders"):
        peek_current_facts_to_snapshot(facts, account_scope=SCOPE)


def test_public_peek_cannot_enable_terminal_execution_order_bypass() -> None:
    facts = _peek({})
    facts["execution"]["orders"] = {
        "CTP.terminal": {"status": "ALLTRADED", "symbol": "ru2609"}
    }

    with pytest.raises(TypeError, match="allow_terminal_execution_orders"):
        peek_current_facts_to_snapshot(
            facts,
            account_scope=SCOPE,
            allow_terminal_execution_orders=True,
        )


@pytest.mark.parametrize(
    "status",
    ("SUBMITTING", "SUBMITTED", "NOTTRADED", "PARTTRADED", "UNKNOWN", None),
)
def test_reduce_only_cli_preprocessor_rejects_nonterminal_execution_order(
    status: str | None,
) -> None:
    facts = _peek({})
    row = {} if status is None else {"status": status}
    facts["execution"]["orders"] = {"CTP.nonterminal": row}

    with pytest.raises(ExecutableTargetAdapterError, match="not explicitly terminal"):
        _reduce_only_peek_current_facts_to_snapshot(
            facts,
            account_scope=SCOPE,
        )


def test_cli_exposes_explicit_reduce_only_close_flag() -> None:
    args = build_parser().parse_args(
        [
            "--map-candidate",
            "map.json",
            "--c-fast-candidate",
            "cfast.json",
            "--authority-receipt",
            "receipt.json",
            "--authority-artifact",
            "artifact.json",
            "--peek-current-facts",
            "peek.json",
            "--reconciliation-state",
            "reconcile.json",
            "--product",
            "ru",
            "--account-scope",
            SCOPE,
            "--reduce-only-close",
            "--reduce-only-close-limit-price",
            "17100",
            "--output",
            "target.json",
        ]
    )

    assert args.reduce_only_close is True
    assert args.reduce_only_close_limit_price == 17100.0


def test_cli_reduce_only_close_writes_one_opposite_close_target(tmp_path: Path) -> None:
    map_candidate, c_fast_candidate = candidates(
        target_quantity=-1,
        product="ru",
        exact_contract="SHFE.ru2609",
    )
    scope = {
        "account_scope": SCOPE,
        "environment": "SIMNOW",
        "gateway_name": "CTP",
    }
    authority_artifact = new_artifact_envelope(
        artifact_type="runtime-authorization",
        trust_domain="runtime_authorization",
        producer_id="runtime-authority-fixture",
        producer_version="v1",
        schema_ref="phase-c-runtime-authorization-v1",
        payload={
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        generated_at="2020-01-01T00:00:00Z",
        scope=scope,
        predecessor_refs=[],
        lineage=[],
    )
    authority_receipt = authority(scope=scope)
    authority_receipt["artifact_id"] = authority_artifact["artifact_id"]
    authority_receipt["artifact_sha256"] = authority_artifact["raw_sha256"]
    map_path, c_fast_path = tmp_path / "map.json", tmp_path / "cfast.json"
    receipt_path = tmp_path / "authority-receipt.json"
    artifact_path = tmp_path / "authority-artifact.json"
    peek_path = tmp_path / "peek.json"
    reconciliation_path = tmp_path / "reconcile.json"
    output_path = tmp_path / "target.json"
    _write(map_path, map_candidate)
    _write(c_fast_path, c_fast_candidate)
    _write(receipt_path, authority_receipt)
    _write(artifact_path, authority_artifact)
    peek_facts = _peek(
        {
            "RU2609.SHFE.SHORT": {
                "gateway_name": "CTP",
                "symbol": "RU2609",
                "exchange": "SHFE",
                "direction": "SHORT",
                "volume": 1,
                "yd_volume": 0,
            }
        }
    )
    peek_facts["execution"]["orders"] = {"CTP.historical": {"status": "ALLTRADED"}}
    _write(peek_path, peek_facts)
    _write(reconciliation_path, {"state": "RECONCILED", "unknown_outcomes": 0})

    assert (
        adapter_main(
            [
                "--map-candidate",
                str(map_path),
                "--c-fast-candidate",
                str(c_fast_path),
                "--authority-receipt",
                str(receipt_path),
                "--authority-artifact",
                str(artifact_path),
                "--peek-current-facts",
                str(peek_path),
                "--reconciliation-state",
                str(reconciliation_path),
                "--product",
                "ru",
                "--account-scope",
                SCOPE,
                "--reduce-only-close",
                "--reduce-only-close-limit-price",
                "3500",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    order = json.loads(output_path.read_text(encoding="utf-8"))["payload"]["orders"][0]
    assert order == {
        "symbol": "ru2609",
        "exchange": "SHFE",
        "direction": "LONG",
        "type": "LIMIT",
        "volume": 1,
        "price": 3500.0,
        "offset": "CLOSETODAY",
        "reference": order["reference"],
        "gateway_name": "CTP",
    }


def test_real_producer_cli_signing_custody_and_final_preview_are_mutation_free(
    tmp_path: Path,
) -> None:
    source = build_approved_source_fixture(source_view())
    map_result = produce_map_candidate(source)
    acceptance, acceptance_keyring = _map_acceptance(map_result)
    c_fast_result = produce_c_fast_candidate(
        map_result.raw,
        source,
        map_acceptance=acceptance,
        map_acceptance_keyring=acceptance_keyring,
    )
    assert {
        key
        for key in map_result.payload
        if key.endswith("_authorized")
        or key
        in {
            "production_allowed",
            "live_allowed",
            "countable_forward",
            "authority_granted",
            "signing_requested",
            "custody_published",
        }
    } == FALSE_AUTHORITY_FIELDS
    assert {
        key
        for key in c_fast_result.payload
        if key.endswith("_authorized")
        or key
        in {
            "production_allowed",
            "live_allowed",
            "countable_forward",
            "authority_granted",
            "signing_requested",
            "custody_published",
        }
    } == FALSE_AUTHORITY_FIELDS

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    keyring = {
        "schema_version": "web-bridge-trust-keyring-v1",
        "domain": "runtime_authorization",
        "key_version": "v1",
        "keys": [
            {
                "key_id": "runtime-adapter-key",
                "domain": "runtime_authorization",
                "purpose": "phase-c-runtime-authorization",
                "public_key_base64": base64.b64encode(public).decode(),
                "status": "active",
            }
        ],
    }
    keyring_path = tmp_path / "runtime-keyring.json"
    _write(keyring_path, keyring)
    keyring_sha = sha256_bytes(keyring_path.read_bytes())
    authority_artifact = new_artifact_envelope(
        artifact_type="runtime-authorization",
        trust_domain="runtime_authorization",
        producer_id="runtime-authority-fixture",
        producer_version="v1",
        schema_ref="phase-c-runtime-authorization-v1",
        payload={
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        generated_at="2020-01-01T00:00:00Z",
        scope={
            "account_scope": SCOPE,
            "environment": "SIMNOW",
            "gateway_name": "CTP",
        },
        predecessor_refs=[],
        lineage=[],
    )
    authority_signed = _signed(
        authority_artifact, private=private, request_id="runtime-authority-request"
    )
    custody_root = tmp_path / "custody"
    custody_service = ArtifactCustodyService(
        CustodySettings(
            root=custody_root,
            writer_id="artifact-custody",
            writer_epoch=1,
            secret="control-secret",
            allowed_principals=frozenset({"control-api"}),
            policies={
                "runtime_authorization": CustodyPolicy(
                    keyring_path=str(keyring_path),
                    keyring_raw_sha256=keyring_sha,
                    key_purpose="phase-c-runtime-authorization",
                )
            },
            execution_read_secret="execution-read-secret",
        )
    )
    with ArtifactCustody(
        custody_root,
        writer_id="artifact-custody",
        writer_epoch=1,
        schema_registry={
            "phase-c-runtime-authorization-v1": lambda value: None,
            TARGET_PLAN_SCHEMA_VERSION: lambda value: TargetPlan.from_mapping(value),
        },
    ) as custody:
        authority_publish = custody.publish_signed(
            authority_signed,
            keyring_path=keyring_path,
            expected_domain="runtime_authorization",
            expected_key_purpose="phase-c-runtime-authorization",
            expected_keyring_raw_sha256=keyring_sha,
            actor_id="offline-fixture",
            idempotency_key="authority-publish-0001",
            correlation_id="authority-correlation-0001",
            expected_version=0,
        )
        authority_install = custody.record(
            "install",
            authority_publish["artifact_id"],
            actor_id="offline-fixture",
            idempotency_key="authority-install-0001",
            correlation_id="authority-correlation-0001",
            expected_version=1,
        )
    authority_receipt_dto = custody_service.receipt(authority_install["receipt_id"])
    assert authority_receipt_dto is not None
    authority_receipt = authority_receipt_dto.model_dump(mode="json")
    target = next(
        row for row in c_fast_result.payload["targets"] if row["product"] == "rb"
    )
    target_quantity = int(target["target_quantity"])
    exchange, symbol = target["exact_contract"].split(".", 1)
    exchange, symbol = exchange.upper(), symbol.upper()
    if target_quantity > 0:
        position = {
            f"{symbol}.{exchange}.LONG": {
                "gateway_name": "CTP",
                "symbol": symbol,
                "exchange": exchange,
                "direction": "LONG",
                "volume": target_quantity - 1,
            }
        }
    else:
        position = {
            f"{symbol}.{exchange}.SHORT": {
                "gateway_name": "CTP",
                "symbol": symbol,
                "exchange": exchange,
                "direction": "SHORT",
                "volume": abs(target_quantity) + 1,
            }
        }
    if exchange in {"INE", "SHFE"}:
        next(iter(position.values()))["yd_volume"] = 0
    map_path, c_fast_path = tmp_path / "map.json", tmp_path / "cfast.json"
    receipt_path = tmp_path / "authority-receipt.json"
    authority_artifact_path = tmp_path / "authority-artifact.json"
    peek_path = tmp_path / "peek.json"
    reconciliation_path, output_path = (
        tmp_path / "reconcile.json",
        tmp_path / "target.json",
    )
    _write(map_path, map_result.raw)
    _write(c_fast_path, c_fast_result.raw)
    _write(receipt_path, authority_receipt)
    _write(authority_artifact_path, authority_artifact)
    _write(peek_path, _peek(position))
    _write(reconciliation_path, {"state": "RECONCILED", "unknown_outcomes": 0})
    assert (
        adapter_main(
            [
                "--map-candidate",
                str(map_path),
                "--c-fast-candidate",
                str(c_fast_path),
                "--authority-receipt",
                str(receipt_path),
                "--authority-artifact",
                str(authority_artifact_path),
                "--peek-current-facts",
                str(peek_path),
                "--reconciliation-state",
                str(reconciliation_path),
                "--product",
                "rb",
                "--account-scope",
                SCOPE,
                "--output",
                str(output_path),
                "--generated-at",
                "2030-01-01T00:00:00Z",
            ]
        )
        == 0
    )
    envelope = json.loads(output_path.read_text(encoding="utf-8"))
    target_signed = _signed(envelope, private=private, request_id="target-plan-request")
    with ArtifactCustody(
        custody_root,
        writer_id="artifact-custody",
        writer_epoch=1,
        schema_registry={
            "phase-c-runtime-authorization-v1": lambda value: None,
            TARGET_PLAN_SCHEMA_VERSION: lambda value: TargetPlan.from_mapping(value),
        },
    ) as custody:
        published = custody.publish_signed(
            target_signed,
            keyring_path=keyring_path,
            expected_domain="runtime_authorization",
            expected_key_purpose="phase-c-runtime-authorization",
            expected_keyring_raw_sha256=keyring_sha,
            actor_id="offline-fixture",
            idempotency_key="target-publish-0001",
            correlation_id="target-correlation-0001",
            expected_version=2,
        )
        installed = custody.record(
            "install",
            published["artifact_id"],
            actor_id="offline-fixture",
            idempotency_key="target-install-0001",
            correlation_id="target-correlation-0001",
            expected_version=3,
        )
    target_receipt_dto = custody_service.receipt(installed["receipt_id"])
    assert target_receipt_dto is not None
    target_receipt = target_receipt_dto.model_dump(mode="json")
    target_artifact = custody_service.artifact_for_execution(
        target_receipt["artifact_id"]
    )
    assert target_artifact is not None
    assert target_receipt["artifact_sha256"] == envelope["raw_sha256"]
    assert target_artifact["artifact_raw_sha256"] == sha256_bytes(
        canonical_json_line(envelope)
    )

    class CustodyRead:
        def receipt(self, receipt_id: str):
            receipt = custody_service.receipt(receipt_id)
            return None if receipt is None else receipt.model_dump(mode="json")

        def artifact(self, artifact_id: str):
            return custody_service.artifact_for_execution(artifact_id)

        def probe(self):
            return None

    gateway = InMemoryGateway(account_scope=SCOPE, environment="SIMNOW")
    core = ExecutionOrchestrator(
        InMemoryExecutionRepository(scope=SCOPE),
        gateway,
        scope=SCOPE,
        environment="SIMNOW",
        test_mode=True,
    )
    runtime = FinalExecutionRuntime(
        core,
        plans=InMemoryTargetPlanRepository(),
        custody=CustodyRead(),
        allowed_scope=authority_receipt["scope"],
        allow_simnow_execution=False,
    )
    assert (
        runtime.preview_from_custody(target_receipt["receipt_id"]).plan_hash
        == envelope["payload"]["plan_hash"]
    )
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []


@pytest.mark.parametrize(
    ("candidate_name", "field"),
    [
        ("map", "control_authorized"),
        ("c_fast", "control_authorized"),
        ("map", "signing_requested"),
        ("c_fast", "signing_requested"),
        ("map", "custody_published"),
        ("c_fast", "custody_published"),
    ],
)
def test_real_producer_authority_tampering_fails_closed(
    tmp_path: Path, candidate_name: str, field: str
) -> None:
    source = build_approved_source_fixture(source_view())
    map_result = produce_map_candidate(source)
    acceptance, acceptance_keyring = _map_acceptance(map_result)
    c_fast_result = produce_c_fast_candidate(
        map_result.raw,
        source,
        map_acceptance=acceptance,
        map_acceptance_keyring=acceptance_keyring,
    )
    assert map_result.payload[field] is False
    assert c_fast_result.payload[field] is False
    map_candidate = deepcopy(map_result.payload)
    c_fast_candidate = deepcopy(c_fast_result.payload)
    if candidate_name == "map":
        map_candidate[field] = True
    else:
        c_fast_candidate[field] = True
    map_path = tmp_path / "map.json"
    c_fast_path = tmp_path / "cfast.json"
    receipt_path = tmp_path / "authority.json"
    authority_artifact_path = tmp_path / "authority-artifact.json"
    peek_path = tmp_path / "peek.json"
    reconciliation_path = tmp_path / "reconcile.json"
    output_path = tmp_path / "target.json"
    _write(map_path, map_candidate)
    _write(c_fast_path, c_fast_candidate)
    _write(receipt_path, {})
    _write(authority_artifact_path, {})
    _write(peek_path, {})
    _write(reconciliation_path, {"state": "RECONCILED", "unknown_outcomes": 0})
    assert (
        adapter_main(
            [
                "--map-candidate",
                str(map_path),
                "--c-fast-candidate",
                str(c_fast_path),
                "--authority-receipt",
                str(receipt_path),
                "--authority-artifact",
                str(authority_artifact_path),
                "--peek-current-facts",
                str(peek_path),
                "--reconciliation-state",
                str(reconciliation_path),
                "--product",
                "rb",
                "--account-scope",
                SCOPE,
                "--output",
                str(output_path),
            ]
        )
        == 2
    )
    assert not output_path.exists()


def test_cli_keyless_simnow_needs_no_authority_files(tmp_path: Path) -> None:
    map_candidate, c_fast_candidate = candidates()
    map_path, c_fast_path = tmp_path / "map.json", tmp_path / "cfast.json"
    peek_path = tmp_path / "peek.json"
    reconciliation_path = tmp_path / "reconcile.json"
    output_path = tmp_path / "keyless-target.json"
    _write(map_path, map_candidate)
    _write(c_fast_path, c_fast_candidate)
    peek_facts = _peek({})
    peek_facts["gateway"]["account_scope"] = "account:windows"
    peek_facts["admission"]["account_scope"] = "account:windows"
    _write(peek_path, peek_facts)
    _write(reconciliation_path, {"state": "RECONCILED", "unknown_outcomes": 0})

    assert adapter_main(
        [
            "--map-candidate", str(map_path),
            "--c-fast-candidate", str(c_fast_path),
            "--peek-current-facts", str(peek_path),
            "--reconciliation-state", str(reconciliation_path),
            "--product", "rb",
            "--account-scope", "account:windows",
            "--trusted-keyless-simnow",
            "--expires-at", "2099-01-01T00:00:00Z",
            "--generated-at", "2030-01-01T00:00:00Z",
            "--output", str(output_path),
        ]
    ) == 0
    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    assert artifact["schema_ref"] == "web-bridge-simnow-keyless-target-plan-v1"
    assert "signer_key_id" not in artifact["payload"]
