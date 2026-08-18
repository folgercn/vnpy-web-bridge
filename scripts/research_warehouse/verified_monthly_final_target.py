"""Root-pinned, read-only replay of one monthly STATIC_CORE_EQUAL final target.

The public reader accepts paths plus expected immutable pins, never a caller-
built baseline, thermostat snapshot, catalog proof, final-target dataclass, or
claimed lineage hash.  It reloads the current catalog head, current operator
state, complete manifest chain and exact Warehouse daily bytes, then invokes
the existing STATIC_CORE_EQUAL and relative-vol thermostat producers.

The result is source evidence only.  It creates no event, performs no install,
custody, scheduler, launcher, broker, RPC, Execution or order operation, and
all authority remains false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import commodity_c_fast_pure_producer_kernel as frozen
import commodity_relative_vol_snapshot_producer as thermostat_producer
import commodity_static_core_equal_pure_producer as static_producer

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .daily_roll_predecessor_catalog import (
    CurrentCatalogHeadProof,
    _load_catalog,
    catalog_root,
    load_current_catalog_head,
)
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority
from .m2_operator_state import (
    OperatorState,
    load_operator_state,
    operator_state_lock,
)
from .m2_runtime_input import require_sha
from .m2_runtime_loader import RuntimeContext, load_runtime_context_readonly
from .pit_source_view import (
    SourcePins,
    _official_month_boundary,
    build_source_view,
    validate_business_key,
    verify_built_source_view,
    verify_root_pins,
)
from .static_core_baseline import (
    PLACEHOLDER_SIGNATURE,
    BuiltBaseline,
    build_historical_baseline,
    verified_static_baseline_daily_sources,
    verify_built_baseline,
)

EXECUTION_LANE = "simnow_shakedown"
FINAL_TARGET_SCHEMA_VERSION = "commodity_static_core_equal_final_target_projection_v1"
MAX_CONTRACT_REGISTRY_RAW_BYTES = 1024 * 1024
MAX_FINAL_TARGET_RAW_BYTES = 4 * 1024 * 1024


class VerifiedMonthlyFinalTargetError(RegistryError):
    """The current Warehouse root cannot prove one monthly final target."""


@dataclass(frozen=True, slots=True)
class VerifiedMonthlyFinalTarget:
    """Canonical no-authority target bytes and independently rebuilt lineage."""

    source_month: str
    execution_day: str
    static_core_equal_sha256: str
    position_manager_sha256: str
    final_target_sha256: str
    baseline_batch_raw_sha256: str
    quantity_vector: tuple[tuple[str, int], ...]
    quantity_vector_sha256: str
    monthly_exact_contract_map: tuple[tuple[str, str], ...]
    monthly_exact_contract_map_sha256: str
    final_target_raw: bytes
    final_target_raw_sha256: str
    current_catalog_receipt_raw_sha256: str
    current_catalog_artifact_raw_sha256: str
    operator_state_raw_sha256: str
    authority: dict[str, bool]

    @property
    def lineage_hashes(self) -> tuple[str, str, str]:
        return (
            self.static_core_equal_sha256,
            self.position_manager_sha256,
            self.final_target_sha256,
        )

    def to_structural_selector_candidate(self):
        """Project into #371's permanently non-event-ready input type.

        The conversion intentionally drops this result's current-root proof:
        the structural selector cannot promote any Python value to custody or
        event readiness.  A later installer must call this replay again and
        independently bind its result to completion facts.
        """

        from .continuous_event_selector import MonthlyFinalTargetCandidate

        return MonthlyFinalTargetCandidate(
            final_target_raw=self.final_target_raw,
            static_core_equal_sha256=self.static_core_equal_sha256,
            position_manager_sha256=self.position_manager_sha256,
            baseline_batch_raw_sha256=self.baseline_batch_raw_sha256,
        )


def _root_pins(state: OperatorState) -> dict[str, str]:
    payload = state.payload
    return {
        "operator_state_raw_sha256": state.raw_sha256,
        "manifest_genesis_seal_sha256": payload["manifest_genesis_seal_sha256"],
        "manifest_head_seal_sha256": payload["manifest_head_seal_sha256"],
        "manifest_head_commit_seal_sha256": payload["manifest_head_commit_seal_sha256"],
        "commit_anchor_ledger_raw_sha256": payload["commit_anchor_ledger_raw_sha256"],
    }


def _require_catalog_matches_locked_root(
    proof: CurrentCatalogHeadProof,
    state: OperatorState,
) -> None:
    payload = state.payload
    if (
        proof.operator_state_raw_sha256 != state.raw_sha256
        or proof.operator_manifest_sequence != payload["manifest_sequence"]
        or proof.manifest_genesis_seal_sha256 != payload["manifest_genesis_seal_sha256"]
        or proof.manifest_head_seal_sha256 != payload["manifest_head_seal_sha256"]
        or proof.manifest_head_commit_seal_sha256
        != payload["manifest_head_commit_seal_sha256"]
        or proof.commit_anchor_ledger_raw_sha256
        != payload["commit_anchor_ledger_raw_sha256"]
        or proof.last_trade_day != payload["last_trade_day"]
        or proof.authority != false_authority()
    ):
        raise VerifiedMonthlyFinalTargetError(
            "monthly replay catalog proof is cross-spliced from another root"
        )


def _catalog_monthly_signer_pins(
    *,
    operator_state_path: Path,
    proof: CurrentCatalogHeadProof,
) -> tuple[str, str, str, str]:
    """Recover the original signed monthly trust anchor from the full chain."""

    loaded = _load_catalog(catalog_root(operator_state_path))
    head = loaded.head
    if (
        not loaded.entries
        or head is None
        or sha256(head.receipt_raw) != proof.receipt_raw_sha256
        or sha256(head.artifact_raw) != proof.artifact_raw_sha256
    ):
        raise VerifiedMonthlyFinalTargetError(
            "monthly catalog chain changed after current-head verification"
        )
    continuity = (
        loaded.entries[0].artifact.get("verified_lineage", {}).get("continuity")
    )
    if (
        not isinstance(continuity, dict)
        or continuity.get("mode") != "GENESIS_STATIC_CORE_EQUAL"
    ):
        raise VerifiedMonthlyFinalTargetError(
            "monthly catalog lacks its signed Genesis trust anchor"
        )
    public_key_sha256 = require_sha(
        continuity.get("baseline_public_key_sha256"),
        "catalog Genesis monthly public key",
    )
    baseline_raw_sha256 = require_sha(
        continuity.get("baseline_batch_raw_sha256"),
        "catalog Genesis monthly baseline",
    )
    signer_key_id = continuity.get("baseline_signer_key_id")
    source_month = continuity.get("baseline_source_month")
    if (
        not isinstance(signer_key_id, str)
        or not signer_key_id
        or not isinstance(source_month, str)
        or len(source_month) != 7
    ):
        raise VerifiedMonthlyFinalTargetError(
            "monthly catalog Genesis signer identity is invalid"
        )
    return public_key_sha256, signer_key_id, source_month, baseline_raw_sha256


def _verify_baseline_bindings(
    built: BuiltBaseline,
    *,
    context: RuntimeContext,
    state: OperatorState,
    source_month: str,
    history_receipt_raw_sha256: str,
    contract_registry_raw_sha256: str,
    expected_signer_key_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    verify_built_baseline(built)
    evidence = parse_json_strict(built.evidence_raw, "monthly baseline evidence")
    batch = parse_json_strict(built.unsigned_batch_raw, "monthly baseline batch")
    expected_operator = _root_pins(state)
    pins = evidence.get("pins") if isinstance(evidence, dict) else None
    if (
        not isinstance(evidence, dict)
        or not isinstance(batch, dict)
        or canonical_json(batch) != built.unsigned_batch_raw
        or batch.get("signature") != PLACEHOLDER_SIGNATURE
        or batch.get("source_month") != source_month
        or batch.get("execution_lane") != EXECUTION_LANE
        or batch.get("signer_key_id") != expected_signer_key_id
        or evidence.get("source_month") != source_month
        or evidence.get("execution_lane") != EXECUTION_LANE
        or evidence.get("authority") != false_authority()
        or not isinstance(pins, dict)
        or pins.get("history_receipt_raw_sha256") != history_receipt_raw_sha256
        or pins.get("calendar_raw_sha256") != context.calendar.raw_sha256
        or pins.get("calendar_anchor_raw_sha256") != context.availability.raw_sha256
        or pins.get("warehouse_registry_raw_sha256") != context.registry.raw_sha256
        or pins.get("contract_registry_raw_sha256") != contract_registry_raw_sha256
        or pins.get("operator_pins") != expected_operator
        or pins.get("source_month") != source_month
    ):
        raise VerifiedMonthlyFinalTargetError(
            "monthly baseline replay is not bound to the locked Warehouse root"
        )
    return evidence, batch


def _target_rows(value: object, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(frozen.PRODUCTS):
        raise VerifiedMonthlyFinalTargetError(f"{label} is not the frozen ten products")
    result: dict[str, dict[str, Any]] = {}
    for index, product in enumerate(frozen.PRODUCTS):
        row = value[index]
        if not isinstance(row, dict) or row.get("product") != product:
            raise VerifiedMonthlyFinalTargetError(f"{label} is incomplete or reordered")
        result[product] = row
    return result


def _final_projection(
    *,
    target_evidence: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    static_rows = _target_rows(target_evidence.get("targets"), "monthly static target")
    thermostat_rows = _target_rows(snapshot.get("targets"), "monthly thermostat target")
    if (
        target_evidence.get("scheduler_id") != "STATIC_CORE_EQUAL"
        or target_evidence.get("candidate_weights") != {"C": 0.5, "D": 0.5}
        or snapshot.get("schema_version") != thermostat_producer.SNAPSHOT_SCHEMA_VERSION
        or snapshot.get("position_manager_id")
        != thermostat_producer.POSITION_MANAGER_ID
        or snapshot.get("sector_map_id") != thermostat_producer.SECTOR_MAP_ID
        or snapshot.get("baseline_scheduler_id") != "STATIC_CORE_EQUAL"
        or snapshot.get("execution_lane") != EXECUTION_LANE
        or snapshot.get("countable_forward") is not False
        or snapshot.get("authority_granted") is not False
        or snapshot.get("dispatch_allowed") is not False
        or snapshot.get("execution_day") != target_evidence.get("execution_day")
    ):
        raise VerifiedMonthlyFinalTargetError(
            "monthly producer identities are inconsistent"
        )
    rows: list[dict[str, Any]] = []
    for product in frozen.PRODUCTS:
        static = static_rows[product]
        managed = thermostat_rows[product]
        baseline_binding = {
            "product": product,
            "exact_contract": managed.get("exact_contract"),
            "target_quantity": managed.get("baseline_target_quantity"),
            "source_target_weight": managed.get("baseline_source_target_weight"),
            "buffered_target_weight": managed.get("baseline_buffered_target_weight"),
            "reference_open_price": managed.get("reference_open_price"),
            "multiplier": managed.get("multiplier"),
            "price_tick": managed.get("price_tick"),
        }
        static_binding = {
            key: static.get(key)
            for key in (
                "product",
                "exact_contract",
                "target_quantity",
                "source_target_weight",
                "buffered_target_weight",
                "reference_open_price",
                "multiplier",
                "price_tick",
            )
        }
        quantity = managed.get("shadow_target_quantity")
        if (
            canonical_json(baseline_binding) != canonical_json(static_binding)
            or isinstance(quantity, bool)
            or not isinstance(quantity, int)
        ):
            raise VerifiedMonthlyFinalTargetError(
                f"monthly thermostat baseline cross-splice for {product}"
            )
        rows.append(
            {
                "product": product,
                "sector": frozen.SECTOR_MAP[product],
                "exact_contract": managed["exact_contract"],
                "target_quantity": quantity,
                "reference_open_price": managed["reference_open_price"],
                "multiplier": managed["multiplier"],
                "price_tick": managed["price_tick"],
            }
        )
    return {
        "schema_version": FINAL_TARGET_SCHEMA_VERSION,
        "strategy_id": "STATIC_CORE_EQUAL",
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "execution_lane": EXECUTION_LANE,
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "c_sleeve_id": frozen.CANDIDATE_ID,
        "c_map_rule_id": frozen.FROZEN_RULE_ID,
        "d_sleeve_id": "D_DONCHIAN20_EXIT10_NEUTRAL",
        "sector_map_id": frozen.SECTOR_MAP_ID,
        "position_manager_id": thermostat_producer.POSITION_MANAGER_ID,
        "source_month": snapshot["source_month"],
        "execution_day": snapshot["execution_day"],
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "targets": rows,
    }


def _quantity_vector_sha(vector: tuple[tuple[str, int], ...]) -> str:
    return sha256(
        canonical_json(
            [
                {"product": product, "target_quantity": quantity}
                for product, quantity in vector
            ]
        )
    )


def _contract_map_sha(value: tuple[tuple[str, str], ...]) -> str:
    return sha256(
        canonical_json(
            [
                {"product": product, "exact_contract": exact_contract}
                for product, exact_contract in value
            ]
        )
    )


def replay_verified_monthly_final_target(
    *,
    runtime_input_path: Path,
    expected_runtime_input_raw_sha256: str,
    operator_state_path: Path,
    expected_operator_state_raw_sha256: str,
    history_receipt_path: Path,
    expected_history_receipt_raw_sha256: str,
    manifest_public_key_path: Path,
    expected_manifest_public_key_raw_sha256: str,
    signed_baseline_batch_path: Path,
    business_public_key_path: Path,
    expected_business_public_key_raw_sha256: str,
    expected_business_signer_key_id: str,
    contract_registry_path: Path,
    expected_contract_registry_raw_sha256: str,
    source_month: str,
) -> VerifiedMonthlyFinalTarget:
    """Independently replay one monthly economic target from current custody.

    The current catalog proof is loaded internally and re-bound to the
    operator state while one shared lock covers manifest verification, exact
    raw loading and both pure-producer replays.  Missing historical bytes,
    incomplete normal-run supplemental receipts, a source-month timing gap or
    any root drift fails closed.
    """

    try:
        expected_runtime = require_sha(
            expected_runtime_input_raw_sha256, "monthly runtime input"
        )
        expected_operator = require_sha(
            expected_operator_state_raw_sha256, "monthly operator state"
        )
        expected_history = require_sha(
            expected_history_receipt_raw_sha256, "monthly history receipt"
        )
        expected_manifest_key = require_sha(
            expected_manifest_public_key_raw_sha256, "monthly manifest public key"
        )
        expected_business_key = require_sha(
            expected_business_public_key_raw_sha256,
            "monthly business public key",
        )
        expected_contract_registry = require_sha(
            expected_contract_registry_raw_sha256, "monthly contract registry"
        )
        context = load_runtime_context_readonly(Path(runtime_input_path))
        if context.runtime_input.raw_sha256 != expected_runtime:
            raise VerifiedMonthlyFinalTargetError(
                "monthly runtime input root pin changed"
            )
        _research_day, execution_day, _cutoff_day = _official_month_boundary(
            context.calendar,
            source_month=source_month,
        )
        contract_registry_raw = read_regular_strict(
            Path(contract_registry_path),
            "monthly static-core contract registry",
            limit=MAX_CONTRACT_REGISTRY_RAW_BYTES,
        )
        if sha256(contract_registry_raw) != expected_contract_registry:
            raise VerifiedMonthlyFinalTargetError(
                "monthly contract registry root pin changed"
            )
        signed_baseline_raw = read_regular_strict(
            Path(signed_baseline_batch_path),
            "signed monthly baseline batch",
            limit=MAX_FINAL_TARGET_RAW_BYTES,
        )
        signed_baseline = parse_json_strict(
            signed_baseline_raw,
            "signed monthly baseline batch",
        )
        if (
            not isinstance(signed_baseline, dict)
            or canonical_json(signed_baseline) != signed_baseline_raw
        ):
            raise VerifiedMonthlyFinalTargetError(
                "signed monthly baseline batch is not canonical"
            )
        business_key = validate_business_key(
            Path(business_public_key_path),
            expected_raw_sha256=expected_business_key,
        )
        catalog = load_current_catalog_head(Path(operator_state_path))
        with operator_state_lock(Path(operator_state_path), exclusive=False):
            state = load_operator_state(Path(operator_state_path))
            if state.raw_sha256 != expected_operator:
                raise VerifiedMonthlyFinalTargetError(
                    "monthly operator state root pin changed"
                )
            _require_catalog_matches_locked_root(catalog, state)
            (
                catalog_business_key,
                catalog_signer_key_id,
                catalog_genesis_source_month,
                catalog_genesis_baseline_raw_sha256,
            ) = _catalog_monthly_signer_pins(
                operator_state_path=Path(operator_state_path),
                proof=catalog,
            )
            if (
                expected_business_key != catalog_business_key
                or expected_business_signer_key_id != catalog_signer_key_id
                or (
                    source_month == catalog_genesis_source_month
                    and sha256(signed_baseline_raw)
                    != catalog_genesis_baseline_raw_sha256
                )
            ):
                raise VerifiedMonthlyFinalTargetError(
                    "signed monthly baseline is not bound to the catalog trust anchor"
                )
            if date.fromisoformat(catalog.last_trade_day) < execution_day:
                raise VerifiedMonthlyFinalTargetError(
                    "monthly execution day is not sealed in the current catalog root"
                )
            pins = SourcePins(
                history_receipt_raw_sha256=expected_history,
                operator_state_raw_sha256=expected_operator,
                manifest_public_key_raw_sha256=expected_manifest_key,
                baseline_public_key_raw_sha256=expected_business_key,
            )
            history, chain = verify_root_pins(
                context=context,
                operator_state=state,
                history_receipt_path=Path(history_receipt_path),
                pins=pins,
                manifest_public_key_path=Path(manifest_public_key_path),
            )
            sources = verified_static_baseline_daily_sources(
                context=context,
                history=history,
                chain=chain,
                source_month=source_month,
            )
            baseline = build_historical_baseline(
                calendar=context.calendar,
                calendar_anchor_raw_sha256=context.availability.raw_sha256,
                warehouse_registry_raw_sha256=context.registry.raw_sha256,
                history_receipt=history,
                history_receipt_raw_sha256=expected_history,
                operator_pins=_root_pins(state),
                daily_source_raw=sources.daily_raw,
                contract_registry_raw=contract_registry_raw,
                source_month=source_month,
                signer_key_id=expected_business_signer_key_id,
                execution_lane=EXECUTION_LANE,
                supplemental_daily_receipts=sources.supplemental_daily_receipts,
            )
            _evidence, baseline_batch = _verify_baseline_bindings(
                baseline,
                context=context,
                state=state,
                source_month=source_month,
                history_receipt_raw_sha256=expected_history,
                contract_registry_raw_sha256=expected_contract_registry,
                expected_signer_key_id=expected_business_signer_key_id,
            )
            if (
                canonical_json({**signed_baseline, "signature": PLACEHOLDER_SIGNATURE})
                != baseline.unsigned_batch_raw
            ):
                raise VerifiedMonthlyFinalTargetError(
                    "signed monthly baseline does not match root replay"
                )
            thermostat_source = build_source_view(
                calendar=context.calendar,
                calendar_anchor=context.availability,
                history_receipt=history,
                history_receipt_sha256=expected_history,
                operator_state=state,
                daily_source_raw=sources.daily_raw,
                baseline_batch=signed_baseline,
                business_public_key=business_key,
                expected_business_signer_key_id=expected_business_signer_key_id,
                source_month=source_month,
                previous_snapshot=None,
            )
            verify_built_source_view(
                thermostat_source.source_view_raw,
                thermostat_source.receipt_raw,
                expected_receipt_raw_sha256=sha256(thermostat_source.receipt_raw),
            )

            static_result = static_producer.produce_research_artifacts(
                baseline.source_view_raw
            )
            thermostat_result = thermostat_producer.produce_snapshot(
                thermostat_source.source_view_raw
            )
            target_evidence = parse_json_strict(
                static_result.artifacts["target_evidence"],
                "monthly STATIC_CORE_EQUAL target evidence",
            )
            snapshot = parse_json_strict(
                thermostat_result.snapshot_draft,
                "monthly thermostat snapshot",
            )
            if not isinstance(target_evidence, dict) or not isinstance(snapshot, dict):
                raise VerifiedMonthlyFinalTargetError(
                    "monthly producer output is not an object"
                )
            projection = _final_projection(
                target_evidence=target_evidence,
                snapshot=snapshot,
            )
            final_raw = canonical_json_line(projection)
            if not final_raw or len(final_raw) > MAX_FINAL_TARGET_RAW_BYTES:
                raise VerifiedMonthlyFinalTargetError(
                    "monthly final target resource limit exceeded"
                )
            quantity_vector = tuple(
                (row["product"], row["target_quantity"])
                for row in projection["targets"]
            )
            monthly_contracts = tuple(
                (product, target_evidence["targets"][index]["exact_contract"])
                for index, product in enumerate(frozen.PRODUCTS)
            )
            static_sha = sha256(canonical_json(static_result.producer_projection))
            position_sha = thermostat_result.snapshot_draft_sha256
            final_sha = sha256(canonical_json(projection))
            return VerifiedMonthlyFinalTarget(
                source_month=source_month,
                execution_day=execution_day.isoformat(),
                static_core_equal_sha256=static_sha,
                position_manager_sha256=position_sha,
                final_target_sha256=final_sha,
                baseline_batch_raw_sha256=sha256(signed_baseline_raw),
                quantity_vector=quantity_vector,
                quantity_vector_sha256=_quantity_vector_sha(quantity_vector),
                monthly_exact_contract_map=monthly_contracts,
                monthly_exact_contract_map_sha256=_contract_map_sha(monthly_contracts),
                final_target_raw=final_raw,
                final_target_raw_sha256=sha256(final_raw),
                current_catalog_receipt_raw_sha256=catalog.receipt_raw_sha256,
                current_catalog_artifact_raw_sha256=catalog.artifact_raw_sha256,
                operator_state_raw_sha256=state.raw_sha256,
                authority=false_authority(),
            )
    except VerifiedMonthlyFinalTargetError:
        raise
    except (KeyError, OSError, TypeError, ValueError, RegistryError) as exc:
        raise VerifiedMonthlyFinalTargetError(
            "monthly final target replay failed closed"
        ) from exc
