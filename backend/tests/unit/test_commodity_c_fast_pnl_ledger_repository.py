from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

import app.services.commodity_c_fast_pnl_ledger_repository as repository_module
from app.schemas.commodity_c_fast_pnl_ledger import sha256_json
from app.schemas.commodity_c_fast_pnl_ledger_repository import (
    CommodityCFastPnlLedgerRepositoryExportDTO,
)
from app.services.commodity_c_fast_pnl_ledger_repository import (
    CFastPnlLedgerRepositoryError,
    CommodityCFastPnlLedgerRepository,
    canonical_json_line,
    reload_and_verify_repository_export,
)
from test_commodity_c_fast_pnl_ledger import (
    LEDGER_ID,
    build,
    source_inputs,
)


def _second_entry(first, *, actual_state: str = "none"):
    payloads = source_inputs(
        valuation_day="2026-09-03",
        as_of_at_utc="2026-09-03T08:02:00Z",
        actual_state=actual_state,
    )
    return build(
        sequence=2,
        previous=first.entry_hash,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:03:00Z",
        payloads=payloads,
    )


def assert_repository_error(
    code: str,
    function,
    *args,
    **kwargs,
) -> None:
    with pytest.raises(CFastPnlLedgerRepositoryError) as exc_info:
        function(*args, **kwargs)
    assert exc_info.value.code == code


def _rehash_export(payload: dict) -> None:
    payload["export_sha256"] = sha256_json(
        {key: value for key, value in payload.items() if key != "export_sha256"}
    )


def test_append_reopen_audit_and_exports_are_deterministic(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    first = build()
    second = _second_entry(first)

    first_result = repository.append(first.model_dump(mode="json"))
    second_result = repository.append(second.model_dump(mode="json"))
    expected_json = repository.export_json_bytes()
    expected_report = repository.render_audit_report_zh()

    reopened = CommodityCFastPnlLedgerRepository.open(
        tmp_path,
        LEDGER_ID,
    )
    assert first_result.status == "CREATED"
    assert second_result.status == "CREATED"
    assert reopened.entries() == (first, second)
    assert reopened.audit().entry_count == 2
    assert reopened.export_json_bytes() == expected_json
    assert reopened.render_audit_report_zh() == expected_report
    assert reload_and_verify_repository_export(expected_json) == (reopened.export())
    assert expected_json.endswith(b"\n")
    assert "不可变账本审计报告" in expected_report
    assert "NOT_PROVIDED_STRUCTURE_ONLY" in expected_report
    assert "Actual 金额固定为 `null/UNVERIFIED`" in expected_report


def test_append_is_create_only_and_idempotent(tmp_path: Path) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    entry = build()
    repository.append(entry.model_dump(mode="json"))
    path = next((tmp_path / LEDGER_ID / "entries").glob("*.json"))
    before = (path.read_bytes(), path.stat().st_mtime_ns)

    result = repository.append(entry.model_dump(mode="json"))

    assert result.status == "ALREADY_PRESENT"
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert len(tuple(path.parent.glob("*.json"))) == 1


def test_reopen_recovers_pending_before_and_after_final_link(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    first = build()
    repository.append(first.model_dump(mode="json"))
    second = _second_entry(first)
    entries_path = tmp_path / LEDGER_ID / "entries"
    second_pending = entries_path / (
        f".pending-{second.entry_sequence:010d}-{second.entry_hash}.json"
    )
    second_pending.write_bytes(canonical_json_line(second.model_dump(mode="json")))
    second_pending.chmod(0o600)

    recovered = CommodityCFastPnlLedgerRepository.open(
        tmp_path,
        LEDGER_ID,
    )
    assert recovered.entries() == (first, second)
    assert not second_pending.exists()

    first_pending = entries_path / (
        f".pending-{first.entry_sequence:010d}-{first.entry_hash}.json"
    )
    first_pending.write_bytes(canonical_json_line(first.model_dump(mode="json")))
    first_pending.chmod(0o600)

    recovered_again = CommodityCFastPnlLedgerRepository.open(
        tmp_path,
        LEDGER_ID,
    )
    assert recovered_again.entries() == (first, second)
    assert not first_pending.exists()


def test_tampered_entry_and_wrong_predecessor_fail_closed(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    first = build()
    repository.append(first.model_dump(mode="json"))
    source = source_inputs(
        valuation_day="2026-09-03",
        as_of_at_utc="2026-09-03T08:02:00Z",
    )
    wrong = build(
        sequence=2,
        previous="f" * 64,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:03:00Z",
        payloads=source,
    )
    assert_repository_error(
        "REPOSITORY_APPEND_PREDECESSOR_INVALID",
        repository.append,
        wrong.model_dump(mode="json"),
    )
    assert repository.entries() == (first,)

    path = next((tmp_path / LEDGER_ID / "entries").glob("*.json"))
    path.write_bytes(path.read_bytes() + b"\n")
    assert_repository_error(
        "REPOSITORY_ENTRY_NOT_CANONICAL",
        CommodityCFastPnlLedgerRepository.open,
        tmp_path,
        LEDGER_ID,
    )


def test_multiple_pending_unknown_artifact_and_symlink_fail_closed(
    tmp_path: Path,
) -> None:
    CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    entries_path = tmp_path / LEDGER_ID / "entries"
    for suffix in ("0" * 64, "1" * 64):
        pending = entries_path / f".pending-0000000001-{suffix}.json"
        pending.write_text("{}\n", encoding="utf-8")
        pending.chmod(0o600)
    assert_repository_error(
        "REPOSITORY_MULTIPLE_PENDING_FILES",
        CommodityCFastPnlLedgerRepository.open,
        tmp_path,
        LEDGER_ID,
    )

    for pending in entries_path.iterdir():
        pending.unlink()
    unknown = entries_path / "mutable-index.json"
    unknown.write_text("{}\n", encoding="utf-8")
    assert_repository_error(
        "REPOSITORY_UNKNOWN_ENTRY_ARTIFACT",
        CommodityCFastPnlLedgerRepository.open,
        tmp_path,
        LEDGER_ID,
    )
    unknown.unlink()

    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    link = entries_path / ("0000000001-" + "f" * 64 + ".json")
    link.symlink_to(target)
    assert_repository_error(
        "REPOSITORY_ENTRY_READ_FAILED",
        CommodityCFastPnlLedgerRepository.open,
        tmp_path,
        LEDGER_ID,
    )


def test_export_declares_strict_adapters_and_actual_null_boundary(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    source = source_inputs(actual_state="complete")
    entry = build(payloads=source)
    repository.append(entry.model_dump(mode="json"))

    exported = repository.export()

    assert [adapter.adapter_id for adapter in exported.source_adapters] == [
        "cfast-theoretical-target-marks-v1",
        "cfast-fee-and-stress-v2",
        "cfast-book-walk-fill-bounds-v1",
        "cfast-simnow-not-provided-v1",
        "cfast-simnow-archive-reference-v3",
    ]
    actual = exported.entries[0].actual_simnow_calibration_pnl
    assert actual.actual_state == "FACTS_BOUND"
    assert actual.gross_execution_pnl_cny is None
    assert actual.adverse_slippage_cny is None
    assert actual.actual_fees_cny is None
    assert actual.actual_net_pnl_cny is None
    assert exported.external_genesis_anchor_state == ("NOT_PROVIDED_STRUCTURE_ONLY")
    assert exported.external_tip_anchor_state == ("NOT_PROVIDED_STRUCTURE_ONLY")
    assert exported.authority_granted is False
    assert exported.dispatch_allowed is False

    duplicated = exported.model_dump(mode="json")
    duplicated["source_adapters"][4] = duplicated["source_adapters"][3]
    _rehash_export(duplicated)
    with pytest.raises(ValidationError):
        CommodityCFastPnlLedgerRepositoryExportDTO.model_validate(duplicated)
    assert_repository_error(
        "REPOSITORY_EXPORT_DTO_INVALID",
        reload_and_verify_repository_export,
        duplicated,
    )


def test_export_verifier_rejects_cross_splice_and_fake_audit(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    first = build(payloads=source_inputs(actual_state="complete"))
    second = _second_entry(first)
    repository.append(first.model_dump(mode="json"))
    repository.append(second.model_dump(mode="json"))
    cross_spliced = repository.export().model_dump(mode="json")
    second_payload = cross_spliced["entries"][1]
    second_payload["previous_entry_hash"] = "f" * 64
    second_payload["entry_hash"] = sha256_json(
        {key: value for key, value in second_payload.items() if key != "entry_hash"}
    )
    ordered_hashes = [entry["entry_hash"] for entry in cross_spliced["entries"]]
    cross_spliced["chain_tip_entry_hash"] = ordered_hashes[-1]
    cross_spliced["ordered_entry_hashes_sha256"] = sha256_json(ordered_hashes)
    cross_spliced["audit"]["chain_tip_entry_hash"] = ordered_hashes[-1]
    cross_spliced["audit"]["ordered_entry_hashes_sha256"] = sha256_json(ordered_hashes)
    _rehash_export(cross_spliced)

    CommodityCFastPnlLedgerRepositoryExportDTO.model_validate(cross_spliced)
    assert_repository_error(
        ("REPOSITORY_EXPORT_CHAIN_INVALID:LEDGER_PREDECESSOR_MISMATCH"),
        reload_and_verify_repository_export,
        cross_spliced,
    )

    fake_audit = repository.export().model_dump(mode="json")
    assert fake_audit["audit"]["actual_fact_entry_count"] == 1
    fake_audit["audit"]["actual_fact_entry_count"] = 0
    _rehash_export(fake_audit)
    CommodityCFastPnlLedgerRepositoryExportDTO.model_validate(fake_audit)
    assert_repository_error(
        "REPOSITORY_EXPORT_FRESH_AUDIT_MISMATCH",
        reload_and_verify_repository_export,
        fake_audit,
    )


def test_export_verifier_rejects_adapter_remap_and_noncanonical_raw(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    repository.append(build().model_dump(mode="json"))
    remapped = repository.export().model_dump(mode="json")
    first = remapped["source_adapters"][0]
    first.update(
        {
            "source_schema_version": (
                "commodity_c_fast_fee_adjusted_pnl_source_facts_v2"
            ),
            "source_kind": "FEE_AND_STRESS_ASSUMPTIONS",
            "verification_rule": (
                "FRESH_REPLAY_RATE_TIMES_TURNOVER_OR_EXPLICIT_UNBOUND"
            ),
            "amount_authority": (
                "DERIVED_WHEN_ALL_FEE_COMPONENTS_BOUND_OTHERWISE_NULL"
            ),
        }
    )
    _rehash_export(remapped)

    CommodityCFastPnlLedgerRepositoryExportDTO.model_validate(remapped)
    assert_repository_error(
        "REPOSITORY_EXPORT_SOURCE_ADAPTER_MISMATCH",
        reload_and_verify_repository_export,
        remapped,
    )
    assert_repository_error(
        "REPOSITORY_EXPORT_NOT_CANONICAL",
        reload_and_verify_repository_export,
        repository.export_json_bytes() + b"\n",
    )


def test_path_replacement_during_fd_read_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    repository.append(build().model_dump(mode="json"))
    entries_path = tmp_path / LEDGER_ID / "entries"
    entry_path = next(entries_path.glob("*.json"))
    displaced_path = tmp_path / "displaced-entry.json"
    replacement_path = tmp_path / "replacement-entry.json"
    replacement_path.write_bytes(entry_path.read_bytes())
    replacement_path.chmod(0o600)
    original_fstat = repository_module.os.fstat
    calls = 0

    def replacing_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        observed = original_fstat(descriptor)
        if calls == 2:
            entry_path.rename(displaced_path)
            replacement_path.rename(entry_path)
        return observed

    monkeypatch.setattr(repository_module.os, "fstat", replacing_fstat)

    assert_repository_error(
        "REPOSITORY_ENTRY_CHANGED_DURING_READ",
        repository.entries,
    )


def test_group_or_world_writable_custody_is_rejected(
    tmp_path: Path,
) -> None:
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        LEDGER_ID,
    )
    entries_path = tmp_path / LEDGER_ID / "entries"
    entries_path.chmod(0o777)
    try:
        assert_repository_error(
            "REPOSITORY_DIRECTORY_CUSTODY_INVALID",
            repository.entries,
        )
    finally:
        entries_path.chmod(0o700)


def test_repository_module_has_no_runtime_or_execution_capability() -> None:
    root = Path(__file__).resolve().parents[2]
    paths = (
        root / "app/schemas/commodity_c_fast_pnl_ledger_repository.py",
        root / "app/services/commodity_c_fast_pnl_ledger_repository.py",
    )
    forbidden_modules = {
        "app.api",
        "app.core.config",
        "app.services.commodity_simnow",
        "app.services.trade_service",
        "app.services.vnpy_rpc_service",
        "app.services.tick_persistence",
        "app.stores",
        "questdb",
        "vnpy",
        "zmq",
    }
    forbidden_names = {
        "Settings",
        "TradeService",
        "VnpyRpcService",
        "send_order",
        "cancel_order",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                names.update(alias.name for alias in node.names)
        assert not any(
            module == forbidden or module.startswith(f"{forbidden}.")
            for module in imported
            for forbidden in forbidden_modules
        )
        assert not (names & forbidden_names)
