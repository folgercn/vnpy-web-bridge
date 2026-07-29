from __future__ import annotations

import ast
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator
import pytest

from app.core.commodity_strategy_identity import (
    COMMODITY_FROZEN_SECTOR_MAP_V1,
    COMMODITY_FROZEN_SECTOR_MAP_V1_ID,
)

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_pure_producer_kernel as producer  # noqa: E402


EXECUTION_DAY = date(2026, 8, 3)
SOURCE_DAY = date(2026, 7, 31)
FOLLOWING_DAY = date(2026, 8, 4)
GENERATED_AT = "2026-08-03T02:00:00+00:00"
PRICES = {
    "ag": 8000.0,
    "al": 20000.0,
    "au": 500.0,
    "bu": 3800.0,
    "cu": 80000.0,
    "rb": 3600.0,
    "ru": 15000.0,
    "sc": 600.0,
    "sp": 6200.0,
    "zn": 24000.0,
}


def test_pure_producer_uses_frozen_cross_plane_sector_map_identity() -> None:
    assert producer.SECTOR_MAP_ID == COMMODITY_FROZEN_SECTOR_MAP_V1_ID
    assert producer.SECTOR_MAP == dict(COMMODITY_FROZEN_SECTOR_MAP_V1)


def _sha(character: str) -> str:
    return hashlib.sha256(character.encode()).hexdigest()


def _weekdays_ending(end: date, count: int) -> list[date]:
    days: list[date] = []
    current = end
    while len(days) < count:
        if current.weekday() < 5:
            days.append(current)
        current -= timedelta(days=1)
    return sorted(days)


def _binding(
    binding_id: str,
    source_class: str,
    scope: str,
    query_start: date,
    query_end: date,
    marker: str,
    *,
    cutoff_at: str,
    generated_at: str,
) -> dict:
    return {
        "binding_id": binding_id,
        "source_class": source_class,
        "scope": scope,
        "source_identity": f"official-{source_class.lower()}-{scope.lower()}",
        "query_start": query_start.isoformat(),
        "query_end": query_end.isoformat(),
        "cutoff_at": cutoff_at,
        "generated_at": generated_at,
        "raw_sha256": _sha(marker),
        "lineage_sha256": _sha(chr(ord(marker) + 1)),
        "claimed_receipt_sha256": _sha(chr(ord(marker) + 2)),
    }


def source_view() -> dict:
    history = _weekdays_ending(SOURCE_DAY, 127)
    official_days = history + [EXECUTION_DAY, FOLLOWING_DAY]
    bindings = [
        _binding(
            "market-shfe-20260731",
            "MARKET_DAILY",
            "SHFE",
            history[0],
            SOURCE_DAY,
            "1",
            cutoff_at="2026-07-31T10:00:00+00:00",
            generated_at="2026-07-31T10:01:00+00:00",
        ),
        _binding(
            "market-ine-20260731",
            "MARKET_DAILY",
            "INE",
            history[0],
            SOURCE_DAY,
            "4",
            cutoff_at="2026-07-31T10:00:00+00:00",
            generated_at="2026-07-31T10:01:00+00:00",
        ),
        _binding(
            "calendar-shfe-ine-v1",
            "CALENDAR",
            "SHFE_INE",
            history[0],
            date(2026, 12, 31),
            "7",
            cutoff_at="2026-07-31T10:00:00+00:00",
            generated_at="2026-07-31T10:01:00+00:00",
        ),
        _binding(
            "reference-shfe-20260803",
            "REFERENCE_OPEN",
            "SHFE",
            EXECUTION_DAY,
            EXECUTION_DAY,
            "a",
            cutoff_at="2026-08-03T01:31:00+00:00",
            generated_at="2026-08-03T01:32:00+00:00",
        ),
        _binding(
            "reference-ine-20260803",
            "REFERENCE_OPEN",
            "INE",
            EXECUTION_DAY,
            EXECUTION_DAY,
            "d",
            cutoff_at="2026-08-03T01:31:00+00:00",
            generated_at="2026-08-03T01:32:00+00:00",
        ),
        _binding(
            "contract-spec-shfe-v1",
            "CONTRACT_SPEC",
            "SHFE",
            EXECUTION_DAY,
            EXECUTION_DAY,
            "g",
            cutoff_at="2026-07-31T10:00:00+00:00",
            generated_at="2026-07-31T10:01:00+00:00",
        ),
        _binding(
            "contract-spec-ine-v1",
            "CONTRACT_SPEC",
            "INE",
            EXECUTION_DAY,
            EXECUTION_DAY,
            "j",
            cutoff_at="2026-07-31T10:00:00+00:00",
            generated_at="2026-07-31T10:01:00+00:00",
        ),
    ]
    products: list[dict] = []
    for product_index, product in enumerate(producer.PRODUCTS):
        spec = producer.PRODUCT_SPECS[product]
        exchange = spec["exchange"]
        market_binding = (
            "market-ine-20260731"
            if exchange == "INE"
            else "market-shfe-20260731"
        )
        reference_binding = (
            "reference-ine-20260803"
            if exchange == "INE"
            else "reference-shfe-20260803"
        )
        spec_binding = (
            "contract-spec-ine-v1"
            if exchange == "INE"
            else "contract-spec-shfe-v1"
        )
        direction = 1 if product_index < 5 else -1
        level = PRICES[product] * 0.9
        daily: list[dict] = []
        for day_index, official_day in enumerate(history):
            noise = 0.00035 * (
                ((day_index * (product_index + 3)) % 11) - 5
            ) / 5
            level *= pow(2.718281828459045, direction * 0.001 + noise)
            exact_contract = f"{exchange}.{product}2612"
            daily.append(
                {
                    "official_day": official_day.isoformat(),
                    "source_binding_id": market_binding,
                    "contracts": [
                        {
                            "exact_contract": exact_contract,
                            "delivery_yyyymm": 202612,
                            "settlement": level,
                            "open_interest": 1000.0,
                        },
                        {
                            "exact_contract": f"{exchange}.{product}2701",
                            "delivery_yyyymm": 202701,
                            "settlement": level * 1.01,
                            "open_interest": 900.0,
                        },
                        {
                            "exact_contract": f"{exchange}.{product}2702",
                            "delivery_yyyymm": 202702,
                            "settlement": level * 1.02,
                            "open_interest": 800.0,
                        },
                    ],
                }
            )
        exact_contract = f"{exchange}.{product}2612"
        products.append(
            {
                "product": product,
                "exchange": exchange,
                "daily": daily,
                "execution_reference": {
                    "source_binding_id": reference_binding,
                    "exact_contract": exact_contract,
                    "official_open": PRICES[product],
                    "observed_at": "2026-08-03T01:30:00+00:00",
                    "raw_sha256": hashlib.sha256(
                        f"reference-{product}".encode()
                    ).hexdigest(),
                },
                "contract_spec": {
                    "source_binding_id": spec_binding,
                    "exact_contract": exact_contract,
                    "official_last_trading_day": "2026-12-15",
                    "multiplier": spec["multiplier"],
                    "price_tick": spec["price_tick"],
                    "raw_sha256": hashlib.sha256(
                        f"spec-{product}".encode()
                    ).hexdigest(),
                },
            }
        )
    return {
        "schema_version": producer.SOURCE_SCHEMA_VERSION,
        "purpose": producer.SOURCE_PURPOSE,
        "status": producer.SOURCE_STATUS,
        "source_view_id": "c-fast-pit-source-20260803-a01",
        "claimed_receipt_sha256": _sha("f"),
        "generated_at": GENERATED_AT,
        "cutoff_at": "2026-08-03T01:45:00+00:00",
        "research_as_of_official_day": SOURCE_DAY.isoformat(),
        "execution_day": EXECUTION_DAY.isoformat(),
        "official_days": [item.isoformat() for item in official_days],
        "source_bindings": bindings,
        "products": products,
    }


def test_golden_pure_kernel_is_deterministic_and_non_authoritative() -> None:
    first = producer.produce_research_artifacts(source_view())
    second = producer.produce_research_artifacts(
        producer.canonical_json(source_view())
    )

    assert first.status == producer.STATUS
    assert first.source_view_canonical_sha256 == second.source_view_canonical_sha256
    assert first.artifacts == second.artifacts
    assert first.producer_projection == second.producer_projection
    assert tuple(first.artifacts) == producer.ARTIFACT_ROLES
    assert len(set(first.artifacts.values())) == 9
    assert all(first.artifacts.values())
    for role, raw in first.artifacts.items():
        payload = json.loads(raw)
        assert raw == producer.canonical_json(payload)
        assert payload["artifact_role"] == role
        assert payload["status"] == producer.STATUS
        assert payload["research_evidence_only"] is True
        assert payload["source_receipt_signature_verified"] is False
        assert payload["source_receipt_keyring_verified"] is False
        assert payload["source_custody_verified"] is False
        assert payload["sealed_export_verified"] is False
        for field in producer.FALSE_AUTHORITY_FIELDS:
            assert payload[field] is False
    projection = first.producer_projection
    assert projection["projection_type"] == "producer_projection_v1"
    assert projection["artifact_roles"] == list(producer.ARTIFACT_ROLES)
    assert projection["artifact_digests"] == [
        {"role": role, "sha256": hashlib.sha256(raw).hexdigest()}
        for role, raw in first.artifacts.items()
    ]
    allocation = json.loads(first.artifacts["allocation_evidence"])
    assert max(
        abs(value) for value in allocation["raw_quantities"].values()
    ) <= producer.MAX_ABS_TARGET_QUANTITY

    golden = {
        role: hashlib.sha256(raw).hexdigest()
        for role, raw in first.artifacts.items()
    }
    assert golden == {
        "freeze_contract": (
            "b92421bfa7145b14ae63b5ba9fcfeb2b83a38588dfb8a5a845682788152c5696"
        ),
        "research_manifest": (
            "d84932bd76097b4b517e5b1e566277c5a853e5faa3a97b123f8b34b05f4c5992"
        ),
        "signal_evidence": (
            "d827c91d5b32ab4782ea6a8b6bf0ee19db799f010589c29824b45393e2c1c67a"
        ),
        "target_evidence": (
            "d1c009579a99cca21f7ea8f3f798c8e57360e66630a2dd5fee462a5c31fcff3c"
        ),
        "allocation_evidence": (
            "2333f2741774209663b0f5a0147d95f8fbb9223bd34d656bf0805dd0968793a9"
        ),
        "daily_roll_evidence": (
            "7f98e6b765301b95382e04456fc04832977b682da0dc35f21efb7e745bc97553"
        ),
        "reference_price_evidence": (
            "c959482b6694a338bba7e16deff32b0b85fffd7f928970a173d446b35a49efe3"
        ),
        "calendar_authority": (
            "5014090c2a17536d025ff0357c1e6b96d0d523ae8eaa59a0e0cd1bd298da3ed0"
        ),
        "contract_spec_evidence": (
            "7914bbe8337f430ab6e79b19ee2e9f2a721f88c0104ed3c57459323adf944f55"
        ),
    }


def test_result_has_no_bundle_draft_or_three_field_mutation_bypass() -> None:
    result = producer.produce_research_artifacts(source_view())
    assert not hasattr(result, "unsigned_bundle_draft")
    assert set(result.__dataclass_fields__) == {
        "status",
        "source_view_canonical_sha256",
        "artifacts",
        "producer_projection",
    }

    forbidden_projection_fields = {
        "schema_version",
        "research_source_class",
        "signer_key_id",
        "generated_at",
        "not_before",
        "expires_at",
        "execution_day",
        "targets",
        "exact_contract",
        "target_quantity",
        *producer.FALSE_AUTHORITY_FIELDS,
    }

    def assert_projection_separated(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden_projection_fields.isdisjoint(value)
            assert not any(
                key.endswith("_authorized") or key.endswith("_authority")
                for key in value
            )
            for item in value.values():
                assert_projection_separated(item)
        elif isinstance(value, list):
            for item in value:
                assert_projection_separated(item)
        elif isinstance(value, str):
            assert value != "NON_COUNTABLE_SIMNOW_EXERCISE_ONLY"

    assert_projection_separated(result.producer_projection)

    mutated = dict(result.producer_projection)
    mutated.update(
        {
            "template_state": "READY_FOR_HUMAN_SIGNATURE",
            "research_source_class": "SEALED_EXTERNAL_C_FAST_EVIDENCE",
            "research_bundle_fact_frozen": True,
        }
    )
    assert "schema_version" not in mutated
    assert "targets" not in mutated
    assert "signer_key_id" not in mutated


def test_module_has_no_pr160_projection_or_prepare_dependency() -> None:
    path = ROOT / "scripts/commodity_c_fast_pure_producer_kernel.py"
    source = path.read_text(encoding="utf-8")
    assert "commodity_c_fast_simnow_research_bundle_v1" not in source
    assert "commodity_c_fast_simnow_research_bundle" not in source
    assert "prepare_unsigned_bundle" not in source
    assert "_build_unsigned_bundle_draft" not in source


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value.__setitem__("unexpected", True),
            "field set mismatch",
        ),
        (
            lambda value: value["products"].pop(),
            "exact frozen ten products",
        ),
        (
            lambda value: value["products"][0]["daily"][-1].__setitem__(
                "official_day",
                EXECUTION_DAY.isoformat(),
            ),
            "future data",
        ),
        (
            lambda value: value["products"][0]["execution_reference"].__setitem__(
                "exact_contract",
                "SHFE.ag2701",
            ),
            "splice",
        ),
        (
            lambda value: value["products"][0]["daily"][-1]["contracts"].pop(),
            "at least three",
        ),
        (
            lambda value: value["source_bindings"][0].__setitem__(
                "query_end",
                EXECUTION_DAY.isoformat(),
            ),
            "future dates",
        ),
    ],
)
def test_source_view_failures_are_closed(mutate, message: str) -> None:
    source = source_view()
    mutate(source)
    with pytest.raises(producer.ProducerKernelError, match=message):
        producer.produce_research_artifacts(source)


def test_zero_volatility_and_dte_boundary_fail_closed() -> None:
    constant = source_view()
    for daily in constant["products"][0]["daily"]:
        for contract in daily["contracts"]:
            contract["settlement"] = PRICES["ag"]
    with pytest.raises(producer.ProducerKernelError, match="vol60"):
        producer.produce_research_artifacts(constant)

    unsafe = source_view()
    unsafe["products"][0]["contract_spec"][
        "official_last_trading_day"
    ] = "2026-08-13"
    with pytest.raises(producer.ProducerKernelError, match="DTE safety"):
        producer.produce_research_artifacts(unsafe)


def test_source_raw_bytes_limit_precedes_decode() -> None:
    oversized_invalid_json = b"{" + b"x" * producer.MAX_SOURCE_VIEW_RAW_BYTES
    with pytest.raises(
        producer.ProducerKernelError,
        match="raw bytes exceeds",
    ):
        producer.produce_research_artifacts(oversized_invalid_json)


def test_source_collection_limits_precede_row_validation() -> None:
    too_many_days = source_view()
    too_many_days["official_days"] = [None] * (
        producer.MAX_OFFICIAL_DAYS + 1
    )
    with pytest.raises(
        producer.ProducerKernelError,
        match="official_days exceeds",
    ):
        producer.produce_research_artifacts(too_many_days)

    too_many_contracts = source_view()
    too_many_contracts["products"][0]["daily"][0]["contracts"] = [None] * (
        producer.MAX_CONTRACTS_PER_PRODUCT_DAY + 1
    )
    with pytest.raises(
        producer.ProducerKernelError,
        match="per-day resource limit",
    ):
        producer.produce_research_artifacts(too_many_contracts)

    too_many_total_rows = source_view()
    rows_per_day = (
        producer.MAX_TOTAL_CONTRACT_ROWS
        // (
            len(producer.PRODUCTS)
            * len(too_many_total_rows["products"][0]["daily"])
        )
        + 1
    )
    assert rows_per_day <= producer.MAX_CONTRACTS_PER_PRODUCT_DAY
    template_rows = too_many_total_rows["products"][0]["daily"][0][
        "contracts"
    ]
    for product in too_many_total_rows["products"]:
        for daily in product["daily"]:
            daily["contracts"] = [
                template_rows[index % len(template_rows)]
                for index in range(rows_per_day)
            ]
    with pytest.raises(
        producer.ProducerKernelError,
        match="total contract-row resource limit",
    ):
        producer.produce_research_artifacts(too_many_total_rows)


def test_allocator_raw_lot_cap_fails_instead_of_zeroing_target() -> None:
    target = {product: 0.0 for product in producer.PRODUCTS}
    target["ag"] = 0.06
    unit_weights = {product: 0.001 for product in producer.PRODUCTS}
    unit_weights["ag"] = 0.0001

    with pytest.raises(
        producer.ProducerKernelError,
        match="refuse silent clipping/zeroing",
    ):
        producer._joint_integer_allocate(target, unit_weights)


def test_source_schema_is_strict_and_fixture_valid() -> None:
    schema_path = (
        ROOT
        / "docs/schemas/commodity-c-fast-pit-frozen-source-view-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(source_view())
    assert schema["x-vnpy-resource-limits"] == {
        "max_raw_bytes": producer.MAX_SOURCE_VIEW_RAW_BYTES,
        "max_official_days": producer.MAX_OFFICIAL_DAYS,
        "max_source_bindings": producer.MAX_SOURCE_BINDINGS,
        "max_daily_rows_per_product": producer.MAX_DAILY_ROWS_PER_PRODUCT,
        "max_contracts_per_product_day": (
            producer.MAX_CONTRACTS_PER_PRODUCT_DAY
        ),
        "max_total_contract_rows": producer.MAX_TOTAL_CONTRACT_ROWS,
    }
    assert (
        schema["properties"]["official_days"]["maxItems"]
        == producer.MAX_OFFICIAL_DAYS
    )
    assert (
        schema["$defs"]["daily"]["properties"]["contracts"]["maxItems"]
        == producer.MAX_CONTRACTS_PER_PRODUCT_DAY
    )
    assert (
        schema["$defs"]["product"]["properties"]["daily"]["maxItems"]
        == producer.MAX_DAILY_ROWS_PER_PRODUCT
    )

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


def test_kernel_import_boundary_excludes_runtime_and_data_connectors() -> None:
    path = ROOT / "scripts/commodity_c_fast_pure_producer_kernel.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
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
