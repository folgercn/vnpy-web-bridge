from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_pure_producer_kernel as cfast  # noqa: E402
import commodity_static_core_equal_formula_v1 as formula  # noqa: E402
import commodity_static_core_equal_pure_producer as producer  # noqa: E402
from test_commodity_c_fast_pure_producer_kernel import (  # noqa: E402
    source_view as c_fast_source_view,
)


def source_view() -> dict:
    source = c_fast_source_view()
    source.update(
        {
            "schema_version": producer.SOURCE_SCHEMA_VERSION,
            "purpose": producer.SOURCE_PURPOSE,
            "status": producer.SOURCE_STATUS,
            "source_view_id": "static-core-equal-source-20260803-a01",
        }
    )
    for product_index, product in enumerate(source["products"]):
        for day_index, daily in enumerate(product["daily"]):
            for contract_index, contract in enumerate(daily["contracts"]):
                settlement = float(contract["settlement"])
                direction = 1 if product_index < 5 else -1
                intraday_shift = direction * 0.0002 * (
                    1 + (day_index + contract_index) % 3
                )
                raw_open = settlement / (1.0 + intraday_shift)
                contract.update(
                    {
                        "open": raw_open,
                        "high": max(raw_open, settlement) * 1.0001,
                        "low": min(raw_open, settlement) * 0.9999,
                    }
                )
    return source


def test_golden_composite_is_deterministic_complete_and_non_authoritative() -> None:
    first = producer.produce_research_artifacts(source_view())
    second = producer.produce_research_artifacts(
        producer.canonical_json(source_view())
    )

    assert first.status == producer.STATUS
    assert first.source_view_canonical_sha256 == (
        second.source_view_canonical_sha256
    )
    assert first.artifacts == second.artifacts
    assert first.producer_projection == second.producer_projection
    assert tuple(first.artifacts) == producer.ARTIFACT_ROLES
    assert len(set(first.artifacts.values())) == len(producer.ARTIFACT_ROLES)

    for role, raw in first.artifacts.items():
        payload = json.loads(raw)
        assert raw == producer.canonical_json(payload)
        assert payload["artifact_role"] == role
        assert payload["status"] == producer.STATUS
        assert payload["research_evidence_only"] is True
        assert payload["producer_code_identity"] == {
            "c_fast_kernel_code_sha256": producer.C_KERNEL_CODE_SHA256,
            "d_formula_code_sha256": producer.D_FORMULA_CODE_SHA256,
        }
        for field in producer.FALSE_AUTHORITY_FIELDS:
            assert payload[field] is False

    freeze = json.loads(first.artifacts["freeze_contract"])
    assert freeze["candidate_weights"] == {"C": 0.5, "D": 0.5}
    assert freeze["D_candidate_id"] == "D_DONCHIAN20_EXIT10_NEUTRAL"
    assert freeze["D_algorithm_id"] == (
        "DONCHIAN20_EXIT10_ROLL_SAFE_NEUTRAL_V1"
    )
    assert freeze["guardband_v2"] == {
        "product": 0.12,
        "sector": 0.27,
        "gross": 0.8,
        "target_net": 0.0,
        "policy": "SHRINK_ONLY_PRODUCT_SECTOR_GROSS_THEN_NET_ZERO",
    }
    assert freeze["allocator"]["virtual_nav_cny"] == 20_000_000
    assert freeze["allocator"]["algorithm"] == (
        "FINITE_NEIGHBOURHOOD_BEAM_V1"
    )

    signals = json.loads(first.artifacts["signal_evidence"])
    assert [row["product"] for row in signals["D_signals"]] == list(
        cfast.PRODUCTS
    )
    assert {row["state"] for row in signals["D_signals"]} == {-1, 1}

    target = json.loads(first.artifacts["target_evidence"])
    assert [row["product"] for row in target["targets"]] == list(
        cfast.PRODUCTS
    )
    assert abs(
        sum(row["source_target_weight"] for row in target["targets"])
    ) < 1e-10
    assert abs(
        sum(row["buffered_target_weight"] for row in target["targets"])
    ) < 1e-10
    for row in target["targets"]:
        assert row["raw_combined_weight"] == pytest.approx(
            row["C_raw_contribution"] + row["D_raw_contribution"]
        )

    golden = {
        role: hashlib.sha256(raw).hexdigest()
        for role, raw in first.artifacts.items()
    }
    assert golden == {
        "freeze_contract": (
                "7530ef1534ed0868f5bf94287a10436eb52bc8498782ceff456f5f3b311767f2"
        ),
        "research_manifest": (
                "01d1ea4142fc52ca6f350224cf456747ddbebf7b124858a96562b680daa3ce00"
        ),
        "signal_evidence": (
                "6cca34723524e0028167051ecb4a13cb581d7480f5df7d92a4a48cee33da88b4"
        ),
        "target_evidence": (
                "0209c819e264e614e7bca1a404d8dfa398afd6d0f55a298ce0ec7b6b7d3a0e47"
        ),
        "allocation_evidence": (
                "309a7f34499209226d2f61e7fef180a5e3486ab57f04fb7078a5451026b12839"
        ),
        "daily_roll_evidence": (
                "3187f13740d38bf75f66c9ff246dbbc6c923fc13d65a938ed2ad4ab57f8ec31e"
        ),
        "reference_price_evidence": (
                "26ec39bff458ef1e252f8aa0cfa1a3054ed2bbab40a619e2005ce790a4bc3176"
        ),
        "calendar_authority": (
                "aadddf8075f53cd574242d567d213def14ef88e7435c8bf02a81e52d67bd9520"
        ),
        "contract_spec_evidence": (
                "e6fe4d50cea36be1fae4659fcfea45384b9d88fbc6118521b0921e03211279e3"
        ),
    }


def test_missing_and_tampered_source_fail_closed() -> None:
    missing = source_view()
    del missing["products"][0]["daily"][0]["contracts"][0]["high"]
    with pytest.raises(cfast.ProducerKernelError, match="field set"):
        producer.produce_research_artifacts(missing)

    invalid_range = source_view()
    contract = invalid_range["products"][0]["daily"][0]["contracts"][0]
    contract["low"] = contract["high"] * 2
    with pytest.raises(cfast.ProducerKernelError, match="OHLC range"):
        producer.produce_research_artifacts(invalid_range)

    future = source_view()
    future["products"][0]["daily"][-1]["official_day"] = future[
        "execution_day"
    ]
    with pytest.raises(cfast.ProducerKernelError, match="future data"):
        producer.produce_research_artifacts(future)


def test_source_schema_primitive_types_fail_closed_before_normalization() -> None:
    numeric_source_id = source_view()
    numeric_source_id["source_view_id"] = 12345678
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="source_view_id must be one JSON string",
    ):
        producer.produce_research_artifacts(numeric_source_id)

    string_open = source_view()
    contract = string_open["products"][0]["daily"][0]["contracts"][0]
    contract["open"] = str(contract["open"])
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match=r"contracts\[0\]\.open must be one finite JSON number",
    ):
        producer.produce_research_artifacts(string_open)

    string_open_interest = source_view()
    contract = string_open_interest["products"][0]["daily"][0]["contracts"][0]
    contract["open_interest"] = str(contract["open_interest"])
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match=r"contracts\[0\]\.open_interest must be one finite JSON number",
    ):
        producer.produce_research_artifacts(string_open_interest)

    boolean_settlement = source_view()
    contract = boolean_settlement["products"][0]["daily"][0]["contracts"][0]
    contract["settlement"] = True
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match=r"contracts\[0\]\.settlement must be one finite JSON number",
    ):
        producer.produce_research_artifacts(boolean_settlement)


def test_missing_or_tampered_output_fails_independent_verification() -> None:
    result = producer.produce_research_artifacts(source_view())

    missing_artifacts = dict(result.artifacts)
    missing_artifacts.pop("target_evidence")
    missing = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=missing_artifacts,
        producer_projection=result.producer_projection,
    )
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="missing or reordered",
    ):
        producer.verify_research_artifacts(missing)

    target = json.loads(result.artifacts["target_evidence"])
    target["targets"][0]["buffered_target_weight"] += 0.001
    tampered_artifacts = dict(result.artifacts)
    tampered_artifacts["target_evidence"] = producer.canonical_json(target)
    tampered_projection = dict(result.producer_projection)
    tampered_projection["artifact_digests"] = [
        {"role": role, "sha256": hashlib.sha256(raw).hexdigest()}
        for role, raw in tampered_artifacts.items()
    ]
    tampered = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=tampered_artifacts,
        producer_projection=tampered_projection,
    )
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="guardband v2 target mismatch",
    ):
        producer.verify_research_artifacts(tampered)


@pytest.mark.parametrize("sleeve", ["C", "D"])
def test_signal_risk_score_is_bound_to_formula_and_target_sleeve(
    sleeve: str,
) -> None:
    result = producer.produce_research_artifacts(source_view())
    signal = json.loads(result.artifacts["signal_evidence"])
    signal[f"{sleeve}_signals"][0]["raw_risk_score"] += 0.125

    tampered_artifacts = dict(result.artifacts)
    tampered_artifacts["signal_evidence"] = producer.canonical_json(signal)
    tampered_projection = dict(result.producer_projection)
    tampered_projection["artifact_digests"] = [
        {"role": role, "sha256": hashlib.sha256(raw).hexdigest()}
        for role, raw in tampered_artifacts.items()
    ]
    tampered = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=tampered_artifacts,
        producer_projection=tampered_projection,
    )

    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match=rf"{sleeve} signal formula mismatch",
    ):
        producer.verify_research_artifacts(tampered)


@pytest.mark.parametrize(
    ("role", "mutate"),
    [
        (
            "signal_evidence",
            lambda payload: payload["D_signals"].append(None),
        ),
        (
            "target_evidence",
            lambda payload: payload["targets"][0].pop(
                "C_source_target_weight"
            ),
        ),
        (
            "target_evidence",
            lambda payload: payload["targets"][0].pop("exact_contract"),
        ),
        (
            "target_evidence",
            lambda payload: payload["targets"][0].__setitem__(
                "C_source_target_weight", "not-a-number"
            ),
        ),
        (
            "signal_evidence",
            lambda payload: payload["C_signals"][0].__setitem__(
                "source_score", True
            ),
        ),
        (
            "target_evidence",
            lambda payload: payload["targets"][0].__setitem__(
                "target_quantity", False
            ),
        ),
    ],
)
def test_malformed_artifact_fields_use_controlled_fail_closed_error(
    role: str,
    mutate: object,
) -> None:
    result = producer.produce_research_artifacts(source_view())
    payload = json.loads(result.artifacts[role])
    mutate(payload)  # type: ignore[operator]

    tampered_artifacts = dict(result.artifacts)
    tampered_artifacts[role] = producer.canonical_json(payload)
    tampered_projection = dict(result.producer_projection)
    tampered_projection["artifact_digests"] = [
        {"role": item, "sha256": hashlib.sha256(raw).hexdigest()}
        for item, raw in tampered_artifacts.items()
    ]
    tampered = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=tampered_artifacts,
        producer_projection=tampered_projection,
    )

    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match=(
            "producer artifact field validation failed"
            "|must be one finite JSON number"
            "|must be one JSON integer"
        ),
    ):
        producer.verify_research_artifacts(tampered)


@pytest.mark.parametrize(
    "malicious_contract",
    ["EVIL.CONTRACT", "SHFE.ag2712"],
)
def test_coordinated_exact_contract_cross_splice_fails_closed(
    malicious_contract: str,
) -> None:
    result = producer.produce_research_artifacts(source_view())
    tampered_artifacts = dict(result.artifacts)
    signal = json.loads(tampered_artifacts["signal_evidence"])
    target = json.loads(tampered_artifacts["target_evidence"])
    reference = json.loads(tampered_artifacts["reference_price_evidence"])
    spec = json.loads(tampered_artifacts["contract_spec_evidence"])
    daily_roll = json.loads(tampered_artifacts["daily_roll_evidence"])

    signal["C_signals"][0]["pit_main_exact_contract"] = malicious_contract
    signal["D_signals"][0]["pit_main_exact_contract"] = malicious_contract
    target["targets"][0]["exact_contract"] = malicious_contract
    reference["rows"][0]["exact_contract"] = malicious_contract
    spec["rows"][0]["exact_contract"] = malicious_contract
    daily_roll["D_rows"][0]["source_day_state"][
        "pit_main_exact_contract"
    ] = malicious_contract
    for role, payload in (
        ("signal_evidence", signal),
        ("target_evidence", target),
        ("reference_price_evidence", reference),
        ("contract_spec_evidence", spec),
        ("daily_roll_evidence", daily_roll),
    ):
        tampered_artifacts[role] = producer.canonical_json(payload)

    tampered_projection = dict(result.producer_projection)
    tampered_projection["artifact_digests"] = [
        {"role": role, "sha256": hashlib.sha256(raw).hexdigest()}
        for role, raw in tampered_artifacts.items()
    ]
    tampered = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=tampered_artifacts,
        producer_projection=tampered_projection,
    )

    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match=(
            "producer artifact field validation failed"
            "|outside the frozen exact contract"
            "|exact-contract/reference/spec/roll binding mismatch"
        ),
    ):
        producer.verify_research_artifacts(tampered)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("guardband_v2", "target_net"), False),
        (("allocator", "net_error_penalty"), True),
        (("allocator", "integer_limits_strict", "gross"), True),
    ],
)
def test_freeze_numeric_literals_reject_boolean_equivalents(
    path: tuple[str, ...],
    value: bool,
) -> None:
    result = producer.produce_research_artifacts(source_view())
    freeze = json.loads(result.artifacts["freeze_contract"])
    target = freeze
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    tampered_artifacts = dict(result.artifacts)
    tampered_artifacts["freeze_contract"] = producer.canonical_json(freeze)
    tampered_projection = dict(result.producer_projection)
    tampered_projection["artifact_digests"] = [
        {"role": role, "sha256": hashlib.sha256(raw).hexdigest()}
        for role, raw in tampered_artifacts.items()
    ]
    tampered = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=tampered_artifacts,
        producer_projection=tampered_projection,
    )

    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="freeze contract literal mismatch|freeze allocator literal mismatch",
    ):
        producer.verify_research_artifacts(tampered)


@pytest.mark.parametrize(
    ("role", "mutate"),
    [
        (
            "research_manifest",
            lambda payload: payload.__setitem__(
                "real_artifact_claimed", True
            ),
        ),
        (
            "research_manifest",
            lambda payload: payload.__setitem__(
                "acceptance_authority_claimed", True
            ),
        ),
        (
            "research_manifest",
            lambda payload: payload.__setitem__(
                "execution_permit_claimed", True
            ),
        ),
        (
            "target_evidence",
            lambda payload: payload["candidate_weights"].__setitem__(
                "C", True
            ),
        ),
        (
            "freeze_contract",
            lambda payload: payload["D_exact_contract"].__setitem__(
                "entry", "tampered"
            ),
        ),
        (
            "calendar_authority",
            lambda payload: payload.__setitem__(
                "execution_is_immediate_next_official_day", False
            ),
        ),
        (
            "signal_evidence",
            lambda payload: payload.__setitem__(
                "C_signal_evidence_sha256", "0" * 64
            ),
        ),
    ],
)
def test_every_artifact_role_is_bound_to_fresh_source_replay(
    role: str,
    mutate: object,
) -> None:
    result = producer.produce_research_artifacts(source_view())
    payload = json.loads(result.artifacts[role])
    mutate(payload)  # type: ignore[operator]

    tampered_artifacts = dict(result.artifacts)
    tampered_artifacts[role] = producer.canonical_json(payload)
    tampered_projection = dict(result.producer_projection)
    tampered_projection["artifact_digests"] = [
        {"role": item, "sha256": hashlib.sha256(raw).hexdigest()}
        for item, raw in tampered_artifacts.items()
    ]
    tampered = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=result.source_view_canonical,
        artifacts=tampered_artifacts,
        producer_projection=tampered_projection,
    )

    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="producer artifacts do not match fresh source replay",
    ):
        producer.verify_research_artifacts(tampered)


def test_canonical_source_bytes_and_hash_cannot_be_rebound_without_replay() -> None:
    result = producer.produce_research_artifacts(source_view())
    changed_source = json.loads(result.source_view_canonical)
    contract = changed_source["products"][0]["daily"][0]["contracts"][0]
    contract["open"] = (
        float(contract["open"]) + float(contract["settlement"])
    ) / 2
    changed_source_raw = producer.canonical_json(changed_source)
    changed_source_hash = hashlib.sha256(changed_source_raw).hexdigest()

    hash_only = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=result.source_view_canonical_sha256,
        source_view_canonical=changed_source_raw,
        artifacts=result.artifacts,
        producer_projection=result.producer_projection,
    )
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="canonical source view identity mismatch",
    ):
        producer.verify_research_artifacts(hash_only)

    rebound_artifacts: dict[str, bytes] = {}
    for role, raw in result.artifacts.items():
        payload = json.loads(raw)
        payload["source_view_canonical_sha256"] = changed_source_hash
        rebound_artifacts[role] = producer.canonical_json(payload)
    rebound_projection = dict(result.producer_projection)
    rebound_projection["source_view_canonical_sha256"] = changed_source_hash
    rebound_projection["artifact_digests"] = [
        {"role": role, "sha256": hashlib.sha256(raw).hexdigest()}
        for role, raw in rebound_artifacts.items()
    ]
    rebound = producer.ProducerResult(
        status=result.status,
        source_view_canonical_sha256=changed_source_hash,
        source_view_canonical=changed_source_raw,
        artifacts=rebound_artifacts,
        producer_projection=rebound_projection,
    )
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="producer artifacts do not match fresh source replay",
    ):
        producer.verify_research_artifacts(rebound)


def test_code_identity_tamper_fails_before_source_calculation(monkeypatch) -> None:
    monkeypatch.setattr(producer, "D_FORMULA_CODE_SHA256", "0" * 64)
    with pytest.raises(
        producer.StaticCoreEqualProducerError,
        match="code identity mismatch",
    ):
        producer.produce_research_artifacts(source_view())


def test_guardband_boundary_is_shrink_only_and_net_zero() -> None:
    source = {product: 0.0 for product in cfast.PRODUCTS}
    source.update(
        {
            "ag": 0.20,
            "au": 0.15,
            "al": -0.20,
            "cu": -0.15,
        }
    )
    buffered = cfast._buffer_weights(source)

    assert buffered["ag"] == pytest.approx(0.12)
    assert buffered["au"] == pytest.approx(0.12)
    assert buffered["al"] == pytest.approx(-0.12)
    assert buffered["cu"] == pytest.approx(-0.12)
    assert sum(buffered.values()) == pytest.approx(0.0, abs=1e-12)
    assert sum(abs(value) for value in buffered.values()) <= 0.8
    assert all(
        abs(buffered[product]) <= abs(source[product]) + 1e-12
        for product in cfast.PRODUCTS
    )


def test_no_feasible_product_nonzero_path_returns_explicit_safe_zero() -> None:
    target = {product: 0.0 for product in cfast.PRODUCTS}
    target["ag"] = 0.12
    target["al"] = -0.12
    unit_weights = {product: 0.15 for product in cfast.PRODUCTS}

    result = formula.allocate_with_safe_zero_status(target, unit_weights)

    assert result.allocation_status == (
        "NO_FEASIBLE_PRODUCT_NONZERO_SAFE_ZERO"
    )
    assert result.nonzero_product_candidate_available is False
    assert set(result.allocation.quantities.values()) == {0}
    assert result.allocation.gross == 0.0
    assert result.allocation.residual_net == 0.0


def test_d_roll_uses_old_main_on_switch_day_and_new_main_afterward() -> None:
    source = source_view()
    roll_index = 80
    for product in source["products"]:
        for daily in product["daily"][roll_index:]:
            daily["contracts"][0]["open_interest"] = 700.0
            daily["contracts"][1]["open_interest"] = 1100.0
        exchange = product["exchange"]
        code = product["product"]
        new_main = f"{exchange}.{code}2701"
        product["execution_reference"]["exact_contract"] = new_main
        product["contract_spec"]["exact_contract"] = new_main

    result = producer.produce_research_artifacts(source)
    roll = json.loads(result.artifacts["daily_roll_evidence"])

    assert [row["product"] for row in roll["D_rows"]] == list(cfast.PRODUCTS)
    for row in roll["D_rows"]:
        assert row["roll_event_count"] == 1
        event = row["roll_events"][0]
        product = row["product"]
        exchange = cfast.PRODUCT_SPECS[product]["exchange"]
        assert event["old_comparable_exact_contract"] == (
            f"{exchange}.{product}2612"
        )
        assert event["new_pit_main_exact_contract"] == (
            f"{exchange}.{product}2701"
        )


def test_schema_is_strict_and_fixture_valid() -> None:
    schema_path = (
        ROOT
        / "docs/schemas/"
        "commodity-static-core-equal-pit-ohlc-source-view-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(source_view())
    assert schema["x-vnpy-resource-limits"] == {
        "max_raw_bytes": cfast.MAX_SOURCE_VIEW_RAW_BYTES,
        "max_official_days": cfast.MAX_OFFICIAL_DAYS,
        "max_source_bindings": cfast.MAX_SOURCE_BINDINGS,
        "max_daily_rows_per_product": cfast.MAX_DAILY_ROWS_PER_PRODUCT,
        "max_contracts_per_product_day": (
            cfast.MAX_CONTRACTS_PER_PRODUCT_DAY
        ),
        "max_total_contract_rows": cfast.MAX_TOTAL_CONTRACT_ROWS,
    }

    def assert_strict(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            for value in node.values():
                assert_strict(value)
        elif isinstance(node, list):
            for value in node:
                assert_strict(value)

    assert_strict(schema)


def test_import_boundary_excludes_execution_runtime_and_data_connectors() -> None:
    paths = (
        ROOT / "scripts/commodity_static_core_equal_formula_v1.py",
        ROOT / "scripts/commodity_static_core_equal_pure_producer.py",
    )
    imported: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

    forbidden = {
        "backend",
        "backend.app",
        "requests",
        "httpx",
        "socket",
        "questdb",
        "vnpy",
        "sqlalchemy",
        "pymongo",
    }
    assert not any(
        module == item or module.startswith(f"{item}.")
        for module in imported
        for item in forbidden
    )
    for path in paths:
        source = path.read_text(encoding="utf-8")
        for forbidden_symbol in (
            "TradeService",
            "send_order",
            "cancel_order",
            "execute_order",
            "Gateway",
        ):
            assert forbidden_symbol not in source


def test_result_shape_cannot_be_mutated_into_execution_contract() -> None:
    result = producer.produce_research_artifacts(source_view())
    assert set(result.__dataclass_fields__) == {
        "status",
        "source_view_canonical_sha256",
        "source_view_canonical",
        "artifacts",
        "producer_projection",
    }
    assert hashlib.sha256(result.source_view_canonical).hexdigest() == (
        result.source_view_canonical_sha256
    )
    assert not hasattr(result, "unsigned_bundle_draft")
    forbidden_projection_fields = {
        "schema_version",
        "signer_key_id",
        "execution_day",
        "targets",
        "exact_contract",
        "target_quantity",
        *producer.FALSE_AUTHORITY_FIELDS,
    }
    assert forbidden_projection_fields.isdisjoint(result.producer_projection)
