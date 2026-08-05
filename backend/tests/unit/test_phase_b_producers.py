from __future__ import annotations

import ast
import base64
import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from c_fast_producer.producer import (
    CFAST_CANDIDATE_SCHEMA,
    produce_c_fast_candidate,
    verify_c_fast_candidate,
)
from c_fast_producer.producer import ProducerError as CFastProducerError
from map.producer import (
    MAP_CANDIDATE_SCHEMA,
    approved_source_envelope,
    produce_map_candidate,
    verify_map_candidate,
)
from map.producer import (
    ProducerError as MapProducerError,
)
from test_commodity_c_fast_pure_producer_kernel import source_view

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.trust_contracts.v1 import (
    SIGNED_ARTIFACT_SCHEMA_VERSION,
    build_signed_artifact,
    build_signing_request,
    signing_bytes,
)


def _envelope() -> dict:
    return approved_source_envelope(source_view())


def _map_acceptance(map_result) -> tuple[dict, dict]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "schema_version": "web-bridge-trust-keyring-v1",
        "domain": "map_acceptance",
        "key_version": "v1",
        "keys": [{
            "key_id": "map-acceptance-test",
            "domain": "map_acceptance",
            "purpose": "unit-test-only",
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "status": "active",
        }],
    }
    artifact = new_artifact_envelope(
        artifact_type="map-acceptance",
        trust_domain="map_acceptance",
        producer_id="map-acceptance-reviewer",
        producer_version="review-v1",
        schema_ref="map-acceptance-v1",
        payload={
            "decision": "approved",
            "map_candidate_id": map_result.payload["candidate_id"],
            "map_candidate_sha256": map_result.artifact_sha256,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        generated_at="2026-08-05T06:00:00Z",
        scope={"candidate_id": map_result.payload["candidate_id"]},
        predecessor_refs=[],
        lineage=[map_result.artifact_sha256],
    )
    request = build_signing_request(
        artifact,
        domain="map_acceptance",
        key_id="map-acceptance-test",
        key_version="v1",
        request_id="map-acceptance-request-1",
        requested_at="2026-08-05T06:00:00Z",
        expires_at="2026-08-05T07:00:00Z",
    )
    unsigned = {
        "schema_version": SIGNED_ARTIFACT_SCHEMA_VERSION,
        "request_id": request["request_id"],
        "domain": request["domain"],
        "signer_key_id": request["key_id"],
        "signer_key_version": request["key_version"],
        "requested_at": request["requested_at"],
        "expires_at": request["expires_at"],
        "artifact": request["artifact"],
    }
    signature = base64.b64encode(private.sign(signing_bytes(unsigned))).decode("ascii")
    return build_signed_artifact(request, signature_base64=signature), keyring


def test_map_and_c_fast_are_deterministic_and_canonical() -> None:
    source = _envelope()
    first = produce_map_candidate(source)
    second = produce_map_candidate(json.loads(json.dumps(source)))
    assert first.raw == second.raw
    assert first.raw == json.dumps(first.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert first.payload["schema_version"] == MAP_CANDIDATE_SCHEMA
    assert first.payload["production_allowed"] is False
    assert verify_map_candidate(first.raw, source_input=source).raw == first.raw
    approval, keyring = _map_acceptance(first)

    c_first = produce_c_fast_candidate(first.raw, source, map_acceptance=approval, map_acceptance_keyring=keyring)
    c_second = produce_c_fast_candidate(first.raw, source, map_acceptance=approval, map_acceptance_keyring=keyring)
    assert c_first.raw == c_second.raw
    assert c_first.raw == json.dumps(c_first.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert c_first.payload["schema_version"] == CFAST_CANDIDATE_SCHEMA
    assert c_first.payload["predecessor"]["artifact_sha256"] == hashlib.sha256(first.raw).hexdigest()
    assert verify_c_fast_candidate(c_first.raw, map_candidate_input=first.raw, source_input=source, map_acceptance=approval, map_acceptance_keyring=keyring).raw == c_first.raw


def test_approval_tamper_map_tamper_and_replay_fail_closed() -> None:
    source = _envelope()
    unapproved = deepcopy(source)
    unapproved["approval"]["custody_verified"] = False
    with pytest.raises(MapProducerError, match="approval"):
        produce_map_candidate(unapproved)

    map_result = produce_map_candidate(source)
    approval, keyring = _map_acceptance(map_result)
    tampered_map = json.loads(map_result.raw)
    tampered_map["signals"][0]["source_target_weight"] += 0.01
    with pytest.raises(CFastProducerError, match="acceptance"):
        produce_c_fast_candidate(tampered_map, source, map_acceptance=approval, map_acceptance_keyring=keyring)

    with pytest.raises(CFastProducerError, match="replay"):
        produce_c_fast_candidate(
            map_result.raw,
            source,
            map_acceptance=approval,
            map_acceptance_keyring=keyring,
            rejected_predecessor_sha256=[map_result.artifact_sha256],
        )


def test_source_and_predecessor_hashes_are_explicit() -> None:
    source = _envelope()
    map_result = produce_map_candidate(source)
    approval, keyring = _map_acceptance(map_result)
    with pytest.raises(CFastProducerError, match="predecessor hash"):
        produce_c_fast_candidate(
            map_result.raw,
            source,
            map_acceptance=approval,
            map_acceptance_keyring=keyring,
            expected_map_sha256="0" * 64,
        )
    wrong_source = deepcopy(source)
    wrong_source["source_view"]["source_view_id"] = "different-source-20260803"
    # The envelope's source hash is now stale and must not be silently repaired.
    with pytest.raises(CFastProducerError, match="source canonical hash"):
        produce_c_fast_candidate(map_result.raw, wrong_source, map_acceptance=approval, map_acceptance_keyring=keyring)


def test_candidate_schemas_validate_golden_outputs() -> None:
    source = _envelope()
    map_result = produce_map_candidate(source)
    approval, keyring = _map_acceptance(map_result)
    c_result = produce_c_fast_candidate(map_result.raw, source, map_acceptance=approval, map_acceptance_keyring=keyring)
    map_schema = json.loads((ROOT / "shared/artifact-contracts/map/commodity-map-signal-candidate-v1.schema.json").read_text())
    c_schema = json.loads((ROOT / "shared/artifact-contracts/c-fast/commodity-c-fast-target-candidate-v1.schema.json").read_text())
    assert list(Draft202012Validator(map_schema).iter_errors(map_result.payload)) == []
    assert list(Draft202012Validator(c_schema).iter_errors(c_result.payload)) == []


def test_producer_import_closure_is_stdlib_and_pure() -> None:
    forbidden_import_roots = {
        "backend",
        "fastapi",
        "httpx",
        "psycopg",
        "questdb",
        "pyzmq",
        "vnpy",
        "socket",
        "requests",
    }
    for relative in ("scripts/map/producer.py", "scripts/c_fast_producer/producer.py"):
        tree = ast.parse((ROOT / relative).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [item.name.split(".", 1)[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".", 1)[0]]
            else:
                continue
            assert not forbidden_import_roots.intersection(names), (relative, names)
        text = (ROOT / relative).read_text()
        for forbidden in ("TradeService", "send_order", "cancel_order", "execute_order"):
            assert forbidden not in text
