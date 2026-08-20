# ruff: noqa: E402

from __future__ import annotations

import asyncio
from dataclasses import replace
import importlib.util
import inspect
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.phase_c.adapters import UnknownOutcomeError
from app.phase_c.models import TrustedKeylessContinuousEventUploadDTO
from research_warehouse.continuous_event_selector import BuiltContinuousEventSelection
from scripts.ci.classify_changes import classify_phase_a, classify_phase_b
from test_issue362_continuous_event_custody import (
    HEAD_NONCE,
    _artifact,
    _publish_only,
    _reenvelope,
    _rehash_structural_candidate,
    _service,
    _upload,
)


def _load_runner():
    path = ROOT / "scripts" / "simnow_continuous_run_once.py"
    spec = importlib.util.spec_from_file_location("simnow_continuous_run_once", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


def _metadata(
    path: Path,
    *,
    kind: int,
    mode: int,
    uid: int = 0,
    nlink: int | None = None,
    size: int | None = None,
    inode_delta: int = 0,
):
    actual = path.lstat()
    return SimpleNamespace(
        st_dev=actual.st_dev,
        st_ino=actual.st_ino + inode_delta,
        st_uid=uid,
        st_gid=actual.st_gid,
        st_mode=kind | mode,
        st_nlink=actual.st_nlink if nlink is None else nlink,
        st_size=actual.st_size if size is None else size,
    )


def _install_root_private_metadata(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    *,
    file_kind: int = stat.S_IFREG,
    file_mode: int = 0o600,
    parent_mode: int = 0o700,
    nlink: int = 1,
    size: int | None = None,
    change_second_fstat: bool = False,
    change_named_recheck: bool = False,
) -> None:
    original_lstat = Path.lstat
    original_fstat = os.fstat
    file_info = _metadata(
        path,
        kind=file_kind,
        mode=file_mode,
        nlink=nlink,
        size=size,
    )
    parent_info = _metadata(path.parent, kind=stat.S_IFDIR, mode=parent_mode)
    path_reads = 0
    fstat_reads = 0

    def lstat(candidate: Path):
        nonlocal path_reads
        candidate = Path(candidate)
        if candidate == path:
            path_reads += 1
            if change_named_recheck and path_reads > 1:
                return SimpleNamespace(
                    **{
                        **vars(file_info),
                        "st_ino": file_info.st_ino + 1,
                    }
                )
            return file_info
        if candidate == path.parent:
            return parent_info
        return original_lstat(candidate)

    def fstat(descriptor: int):
        nonlocal fstat_reads
        fstat_reads += 1
        if change_second_fstat and fstat_reads > 1:
            return SimpleNamespace(
                **{
                    **vars(file_info),
                    "st_ino": file_info.st_ino + 1,
                }
            )
        # The helper is installed only while the runner opens this one file.
        # Keep the real call reachable so invalid descriptors still fail.
        original_fstat(descriptor)
        return file_info

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "fstat", fstat)


def _config_value(tmp_path: Path) -> dict:
    return {
        "schema_version": runner.CONFIG_SCHEMA,
        "run_lock_path": str(tmp_path / "runner.lock"),
        "warehouse_runtime_input_path": str(tmp_path / "runtime.json"),
        "warehouse_runtime_input_raw_sha256": "1" * 64,
        "warehouse_operator_state_path": str(tmp_path / "operator.json"),
        "warehouse_history_receipt_path": str(tmp_path / "history.json"),
        "warehouse_history_receipt_raw_sha256": "2" * 64,
        "warehouse_manifest_public_key_path": str(tmp_path / "manifest.pub"),
        "warehouse_manifest_public_key_raw_sha256": "3" * 64,
        "warehouse_signed_baseline_batch_path": str(tmp_path / "baseline.json"),
        "warehouse_business_public_key_path": str(tmp_path / "business.pub"),
        "warehouse_business_public_key_raw_sha256": "4" * 64,
        "warehouse_business_signer_key_id": "warehouse-signer-test-0001",
        "warehouse_contract_registry_path": str(tmp_path / "contracts.json"),
        "warehouse_contract_registry_raw_sha256": "5" * 64,
        "phase_c_custody_url": "http://phase-c-custody.invalid",
        "phase_c_execution_url": "http://phase-c-execution.invalid",
        "phase_c_custody_shared_secret": "custody-secret-test-0001",
        "phase_c_execution_shared_secret": "execution-read-secret-test-0001",
        "execution_url": "http://execution.invalid",
        "execution_shared_secret": "execution-control-secret-test-0001",
        "leader_owner_id": "continuous-runner-test-0001",
        "principal": "control-api",
        "operator": "simnow-continuous-runner",
        "authority": runner.false_authority(),
    }


def _selection(event_id: str | None) -> BuiltContinuousEventSelection:
    return BuiltContinuousEventSelection(
        selection_raw=b"{}\n",
        selection_id="continuous-selection-test-0001",
        selection_sha256="1" * 64,
        candidate_set_sha256="2" * 64,
        event_candidate_raw=b"{}\n" if event_id else None,
        event_candidate_id=event_id,
        selected_trigger_kind="MONTHLY_REBALANCE" if event_id else None,
    )


class FakeBackend:
    def __init__(
        self,
        *,
        service,
        roots: list[str] | None = None,
        selected_artifact: dict | None = None,
        plan_ready: bool = True,
        resolution=None,
        facts: dict | None = None,
    ) -> None:
        self.service = service
        self.roots = list(roots or ["root-a", "root-a"])
        self.selected_artifact = selected_artifact
        self.plan_ready = plan_ready
        self.resolution = resolution
        self.facts = facts
        self.calls: list[str] = []
        self.recoveries: dict[str, dict] = {}
        self.completions: dict[str, dict] = {}
        self.head_override = None
        self.raise_publish_unknown = False
        self.raise_continue_unknown = False

    def event_head(self):
        self.calls.append("head")
        return self.head_override or self.service.continuous_event_head(
            request_nonce=HEAD_NONCE
        )

    def warehouse(self, _head):
        self.calls.append("warehouse")
        root = self.roots.pop(0) if len(self.roots) > 1 else self.roots[0]
        if self.resolution is not None:
            return replace(self.resolution, root_fingerprint=root)
        event_id = (
            self.selected_artifact["payload"]["event_id"]
            if self.selected_artifact is not None
            else None
        )
        return runner._WarehouseResolution(
            root_fingerprint=root,
            catalog=None,
            planner=None,
            selection=_selection(event_id),
        )

    async def recovery(self, key: str):
        self.calls.append(f"recovery:{key}")
        return dict(
            self.recoveries.get(
                key,
                {
                    "schema_version": "web_bridge_execution_target_plan_recovery_v1",
                    "state": "BEFORE_CUSTODY",
                    "custody_idempotency_key": key,
                },
            )
        )

    async def completion(self, plan_id: str):
        self.calls.append(f"completion:{plan_id}")
        value = self.completions.get(plan_id)
        return dict(value) if value is not None else None

    async def account_facts(self):
        self.calls.append("facts")
        return self.facts or {"observed_at": "2026-08-20T00:00:00Z"}

    def custody_version(self):
        self.calls.append("custody-version")
        return self.service.continuous_event_head(
            request_nonce=HEAD_NONCE
        ).observed_custody_version

    def continue_event(self, head):
        self.calls.append("continue-event")
        publication = head.publication
        current = head.current_event
        assert publication is not None and current is not None
        self.service.install_published_trusted_keyless_continuous_event(
            runner.TrustedKeylessContinuousEventInstallContinuationDTO(
                idempotency_key=current.idempotency_key,
                correlation_id=publication.correlation_id,
                publish_receipt_id=publication.publish_receipt_id,
                publish_receipt_sha256=publication.publish_receipt_sha256,
                publish_expected_custody_version=(
                    publication.publish_expected_custody_version
                ),
                publish_resulting_custody_version=(
                    publication.publish_resulting_custody_version
                ),
                artifact=current.artifact,
            ),
            principal="control-api",
        )
        if self.raise_continue_unknown:
            raise UnknownOutcomeError("lost continuation response")

    def publish_event(self, artifact: dict, *, version: int):
        self.calls.append(f"publish:{version}")
        event_id = artifact["payload"]["event_id"]
        self.service.publish_trusted_keyless_continuous_event(
            TrustedKeylessContinuousEventUploadDTO(
                idempotency_key=event_id,
                expected_custody_version=version,
                correlation_id="continuous-runner-test-0001",
                artifact=artifact,
            ),
            principal="control-api",
        )
        if self.raise_publish_unknown:
            raise UnknownOutcomeError("lost publication response")

    def plan_adapter_ready(self):
        self.calls.append("plan-ready")
        return self.plan_ready

    async def advance_installed_event(self, *, event, phase_keys):
        self.calls.append("advance")
        return {
            "state": "FAKE_E2E_COMPLETE",
            "event_id": event["payload"]["event_id"],
            "close_key": phase_keys["CLOSE"],
            "open_key": phase_keys["OPEN"],
        }


def _installed_service(tmp_path: Path, artifact: dict | None = None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    service = _service(tmp_path)
    value = artifact or _artifact()
    service.publish_trusted_keyless_continuous_event(
        _upload(value), principal="control-api"
    )
    return service, value


def _recovery(key: str, phase: str, *, plan: str) -> dict:
    return {
        "schema_version": "web_bridge_execution_target_plan_recovery_v3",
        "state": "INSTALLED",
        "custody_idempotency_key": key,
        "phase": phase,
        "plan_id": plan,
        "plan_hash": "3" * 64,
        "expected_after_position_hash": "4" * 64,
        "lineage": {
            "static_core_equal_sha256": "5" * 64,
            "position_manager_sha256": "6" * 64,
            "final_target_sha256": "7" * 64,
        },
        "execution_run_id": "execution-run-test-0001",
        "creation_quote_proof_sha256": "8" * 64,
        "start_quote_proof_sha256": "9" * 64,
    }


def _completion(recovery: dict) -> dict:
    return {
        "plan_id": recovery["plan_id"],
        "plan_hash": recovery["plan_hash"],
        "phase": recovery["phase"],
        "expected_after_position_hash": recovery["expected_after_position_hash"],
        "target_position_hash": recovery["expected_after_position_hash"],
        "lineage": recovery["lineage"],
        "execution_run_id": recovery["execution_run_id"],
        "creation_quote_proof_sha256": recovery["creation_quote_proof_sha256"],
        "start_quote_proof_sha256": recovery["start_quote_proof_sha256"],
    }


def _ownership(disposition):
    return SimpleNamespace(
        disposition=disposition,
        reason_code=SimpleNamespace(value="TEST_OWNERSHIP_REASON"),
    )


def _resolution_from_artifact(artifact: dict):
    payload = artifact["payload"]
    monthly = payload["monthly"]
    daily = payload["daily"]
    source_event_raw = payload["source_event_raw"].encode()
    selection_raw = payload["selection_raw"].encode()
    source_event = json.loads(source_event_raw)
    planner = SimpleNamespace(
        final_target=SimpleNamespace(
            final_target_raw=monthly["final_target_raw"].encode(),
            final_target_raw_sha256=monthly["final_target_raw_sha256"],
            final_target_sha256=monthly["final_target_sha256"],
            static_core_equal_sha256=monthly["static_core_equal_sha256"],
            position_manager_sha256=monthly["position_manager_sha256"],
            baseline_batch_raw_sha256=monthly["baseline_batch_raw_sha256"],
            source_month=monthly["source_month"],
            execution_day=monthly["execution_day"],
            quantity_vector_sha256=monthly["quantity_vector_sha256"],
            monthly_exact_contract_map_sha256=monthly[
                "monthly_exact_contract_map_sha256"
            ],
        )
    )
    catalog_raw = runner._canonical_line(
        {
            "artifact_id": daily["artifact_id"],
            "official_day": daily["official_day"],
            "execution_day": daily["execution_day"],
            "verified_lineage": {"continuity": {"mode": daily["continuity_mode"]}},
        }
    )
    catalog = SimpleNamespace(
        artifact_raw=catalog_raw,
        artifact_raw_sha256=daily["artifact_raw_sha256"],
        receipt_raw_sha256=daily["catalog_receipt_raw_sha256"],
        operator_state_raw_sha256=daily["operator_state_raw_sha256"],
        operator_manifest_sequence=daily["operator_manifest_sequence"],
        manifest_genesis_seal_sha256=daily["manifest_genesis_seal_sha256"],
        manifest_head_seal_sha256=daily["manifest_head_seal_sha256"],
        manifest_head_commit_seal_sha256=daily["manifest_head_commit_seal_sha256"],
        commit_anchor_ledger_raw_sha256=daily["commit_anchor_ledger_raw_sha256"],
        last_trade_day=daily["catalog_last_trade_day"],
    )
    selection = BuiltContinuousEventSelection(
        selection_raw=selection_raw,
        selection_id=payload["selection_id"],
        selection_sha256=payload["selection_sha256"],
        candidate_set_sha256=source_event["candidate_set_sha256"],
        event_candidate_raw=source_event_raw,
        event_candidate_id=payload["event_id"],
        selected_trigger_kind=payload["trigger_kind"],
    )
    return runner._WarehouseResolution("root-real", catalog, planner, selection)


def _terminal_from_event(prior_head, next_artifact: dict):
    predecessor = next_artifact["payload"]["predecessor"]
    completion = json.loads(predecessor["completion_raw"])
    recovery = {
        "schema_version": "web_bridge_execution_target_plan_recovery_v1",
        "state": "INSTALLED",
        "custody_idempotency_key": runner._phase_key(
            prior_head.current_event.idempotency_key, completion["phase"]
        ),
        "phase": completion["phase"],
        "plan_id": completion["plan_id"],
        "plan_hash": completion["plan_hash"],
        "expected_after_position_hash": completion["expected_after_position_hash"],
        "lineage": completion["lineage"],
    }
    return runner._TerminalCompletion(recovery, completion)


def test_public_seam_is_config_path_only_and_cli_has_no_dynamic_inputs():
    assert list(inspect.signature(runner.run_once).parameters) == ["config_path"]
    parser = runner.build_parser()
    assert {action.dest for action in parser._actions} == {"help", "config"}
    forbidden = {
        "monthly",
        "daily",
        "facts",
        "completion",
        "source_month",
        "source_day",
        "custody_version",
        "clock",
        "client",
    }
    assert forbidden.isdisjoint(inspect.signature(runner.run_once).parameters)
    assert forbidden.isdisjoint(runner._CONFIG_FIELDS)
    assert {
        "warehouse_runtime_input_raw_sha256",
        "warehouse_history_receipt_raw_sha256",
    }.issubset(runner._CONFIG_FIELDS)


@pytest.mark.parametrize(
    "path",
    [
        "scripts/simnow_continuous_run_once.py",
        "backend/tests/unit/test_issue362_simnow_continuous_run_once.py",
    ],
)
def test_runner_is_phase_a_contract_only_and_not_phase_b_packaged(path: str):
    phase_a = classify_phase_a([path])
    assert phase_a["release_blocked"] is False
    assert phase_a["selected_rule_ids"] == [
        "phase-a-preserved-issue362-continuous-runner-foundation"
    ]
    assert phase_a["selected_units"] == []
    assert phase_a["dependency_closure"] == []
    phase_b = classify_phase_b([path])
    assert phase_b["phase_b_changed"] is False
    assert phase_b["selected_units"] == []


def test_phase_keys_are_domain_separated_stable_and_not_caller_selected():
    event_id = "continuous-event-test-0001"
    close = runner._phase_key(event_id, "CLOSE")
    assert close == runner._phase_key(event_id, "CLOSE")
    assert len(close) == 64
    assert close != runner._phase_key(event_id, "OPEN")
    assert close != runner._phase_key("continuous-event-test-0002", "CLOSE")
    with pytest.raises(runner.ContinuousRunError):
        runner._phase_key(event_id, "OTHER")


def test_config_requires_canonical_root_private_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "continuous-runner.json"
    value = _config_value(tmp_path)
    config.write_bytes(runner._canonical_line(value))
    config.chmod(0o600)
    tmp_path.chmod(0o700)
    _install_root_private_metadata(monkeypatch, config)

    loaded = runner._load_config(config)

    assert loaded.raw == value


@pytest.mark.parametrize(
    ("file_kind", "file_mode", "parent_mode", "nlink", "size"),
    [
        (stat.S_IFREG, 0o644, 0o700, 1, None),
        (stat.S_IFREG, 0o600, 0o755, 1, None),
        (stat.S_IFLNK, 0o600, 0o700, 1, None),
        (stat.S_IFREG, 0o600, 0o700, 2, None),
        (stat.S_IFREG, 0o600, 0o700, 1, 64 * 1024 + 1),
    ],
)
def test_config_rejects_unsafe_metadata_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_kind: int,
    file_mode: int,
    parent_mode: int,
    nlink: int,
    size: int | None,
):
    config = tmp_path / "continuous-runner.json"
    config.write_bytes(runner._canonical_line(_config_value(tmp_path)))
    _install_root_private_metadata(
        monkeypatch,
        config,
        file_kind=file_kind,
        file_mode=file_mode,
        parent_mode=parent_mode,
        nlink=nlink,
        size=size,
    )

    with pytest.raises(runner.ContinuousRunError, match="root-owned 0700/0600"):
        runner._load_config(config)


@pytest.mark.parametrize("invalid_kind", ["unknown-field", "noncanonical"])
def test_config_rejects_unknown_or_noncanonical_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_kind: str,
):
    config = tmp_path / "continuous-runner.json"
    value = _config_value(tmp_path)
    if invalid_kind == "unknown-field":
        value["source_month"] = "2026-08"
        raw = runner._canonical_line(value)
    else:
        raw = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    config.write_bytes(raw)
    _install_root_private_metadata(monkeypatch, config)

    with pytest.raises(runner.ContinuousRunError, match="contract mismatch"):
        runner._load_config(config)


@pytest.mark.parametrize("drift", ["descriptor", "named-path"])
def test_config_rejects_read_time_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
):
    config = tmp_path / "continuous-runner.json"
    config.write_bytes(runner._canonical_line(_config_value(tmp_path)))
    _install_root_private_metadata(
        monkeypatch,
        config,
        change_second_fstat=drift == "descriptor",
        change_named_recheck=drift == "named-path",
    )

    with pytest.raises(runner.ContinuousRunError, match="changed while reading"):
        runner._load_config(config)


def test_nonblocking_flock_reports_busy_without_creating_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    lock = tmp_path / "runner.lock"
    lock.write_bytes(b"lock\n")
    lock.chmod(0o600)
    tmp_path.chmod(0o700)
    _install_root_private_metadata(monkeypatch, lock)
    with runner._one_process(lock):
        with pytest.raises(runner.ContinuousRunBusy):
            with runner._one_process(lock):
                pass
    assert lock.read_bytes() == b"lock\n"


@pytest.mark.parametrize(
    ("file_kind", "file_mode", "parent_mode", "nlink"),
    [
        (stat.S_IFREG, 0o644, 0o700, 1),
        (stat.S_IFREG, 0o600, 0o755, 1),
        (stat.S_IFLNK, 0o600, 0o700, 1),
        (stat.S_IFREG, 0o600, 0o700, 2),
    ],
)
def test_lock_rejects_unsafe_existing_file_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_kind: int,
    file_mode: int,
    parent_mode: int,
    nlink: int,
):
    lock = tmp_path / "runner.lock"
    lock.write_bytes(b"lock\n")
    before = lock.read_bytes()
    _install_root_private_metadata(
        monkeypatch,
        lock,
        file_kind=file_kind,
        file_mode=file_mode,
        parent_mode=parent_mode,
        nlink=nlink,
    )

    with pytest.raises(runner.ContinuousRunError, match="lock is unsafe"):
        with runner._one_process(lock):
            pass

    assert lock.read_bytes() == before


def test_lock_rejects_named_path_replacement_after_flock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    lock = tmp_path / "runner.lock"
    lock.write_bytes(b"lock\n")
    before = lock.read_bytes()
    _install_root_private_metadata(
        monkeypatch,
        lock,
        change_named_recheck=True,
    )

    with pytest.raises(runner.ContinuousRunError, match="lock changed"):
        with runner._one_process(lock):
            pass

    assert lock.read_bytes() == before


def test_no_event_double_reads_roots_and_is_full_domain_zero_write(tmp_path: Path):
    backend = FakeBackend(service=_service(tmp_path))

    result = asyncio.run(runner._run_locked(backend))

    assert result == {
        "status": "NO_EVENT",
        "custody_mutated": False,
        "leader_mutated": False,
        "execution_mutated": False,
        "gateway_mutated": False,
    }
    assert backend.calls == ["head", "warehouse", "warehouse", "head"]


def test_no_event_warehouse_or_event_head_drift_fails_before_any_mutation(
    tmp_path: Path,
):
    root_drift = FakeBackend(service=_service(tmp_path / "root"), roots=["r0", "r1"])
    with pytest.raises(runner.ContinuousRunError, match="roots drifted"):
        asyncio.run(runner._run_locked(root_drift))
    assert not any(call.startswith("publish") for call in root_drift.calls)

    (tmp_path / "head").mkdir()
    service = _service(tmp_path / "head")
    head_drift = FakeBackend(service=service, selected_artifact=None)
    first = service.continuous_event_head(request_nonce=HEAD_NONCE)
    count = 0

    def drifting_head():
        nonlocal count
        count += 1
        if count == 1:
            return first
        artifact = _artifact(suffix="8")
        service.publish_trusted_keyless_continuous_event(
            _upload(artifact), principal="control-api"
        )
        return service.continuous_event_head(request_nonce=HEAD_NONCE)

    head_drift.event_head = drifting_head
    with pytest.raises(runner.ContinuousRunError, match="roots drifted"):
        asyncio.run(runner._run_locked(head_drift))


@pytest.mark.parametrize("unknown", [False, True])
def test_published_event_uses_install_only_continuation_even_after_response_loss(
    tmp_path: Path, unknown: bool
):
    artifact = _artifact()
    service = _service(tmp_path)
    _publish_only(service, artifact)
    backend = FakeBackend(service=service)
    backend.raise_continue_unknown = unknown

    result = asyncio.run(runner._run_locked(backend))

    assert result["status"] == "EVENT_STORED_CONTINUATION"
    assert backend.calls == ["head", "continue-event", "head"]
    assert service.continuous_event_head(request_nonce=HEAD_NONCE).state == "INSTALLED"


def test_foreign_recovery_and_completion_fail_before_facts_or_mutations(tmp_path: Path):
    service, prior = _installed_service(tmp_path)
    next_artifact = _artifact(suffix="2")
    backend = FakeBackend(service=service, selected_artifact=next_artifact)
    close_key = runner._phase_key(prior["payload"]["event_id"], "CLOSE")
    backend.recoveries[close_key] = {
        "state": "INSTALLED",
        "custody_idempotency_key": "f" * 64,
        "phase": "CLOSE",
    }
    with pytest.raises(runner.ContinuousRunError, match="foreign target-plan"):
        asyncio.run(runner._run_locked(backend))
    assert "facts" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)

    backend = FakeBackend(service=service, selected_artifact=next_artifact)
    recovery = _recovery(close_key, "CLOSE", plan="close-plan-test-0001")
    backend.recoveries[close_key] = recovery
    completion = _completion(recovery)
    completion["plan_hash"] = "f" * 64
    backend.completions[recovery["plan_id"]] = completion
    with pytest.raises(runner.ContinuousRunError, match="foreign execution"):
        asyncio.run(runner._run_locked(backend))
    assert "facts" not in backend.calls


def test_active_or_missing_prior_phase_is_query_only_full_domain_zero_write(
    tmp_path: Path,
):
    service, prior = _installed_service(tmp_path)
    backend = FakeBackend(service=service, selected_artifact=_artifact(suffix="2"))
    close_key = runner._phase_key(prior["payload"]["event_id"], "CLOSE")
    backend.recoveries[close_key] = _recovery(
        close_key, "CLOSE", plan="close-plan-active-0001"
    )

    result = asyncio.run(runner._run_locked(backend))

    assert result["status"] == "PRIOR_EVENT_NOT_TERMINAL"
    assert result["reason"] == "CLOSE_ACTIVE_OR_NOT_STARTED"
    assert result["custody_mutated"] is False
    assert result["leader_mutated"] is False
    assert result["execution_mutated"] is False
    assert result["gateway_mutated"] is False
    assert "facts" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)


def test_installed_active_is_queried_before_no_candidate_can_report_no_event(
    tmp_path: Path,
):
    service, prior = _installed_service(tmp_path)
    backend = FakeBackend(service=service, selected_artifact=None)
    close_key = runner._phase_key(prior["payload"]["event_id"], "CLOSE")
    backend.recoveries[close_key] = _recovery(
        close_key, "CLOSE", plan="close-plan-no-candidate-active-0001"
    )

    result = asyncio.run(runner._run_locked(backend))

    assert result["status"] == "PRIOR_EVENT_NOT_TERMINAL"
    assert result["reason"] == "CLOSE_ACTIVE_OR_NOT_STARTED"
    assert any(call.startswith("recovery:") for call in backend.calls)
    assert "facts" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)


@pytest.mark.parametrize("foreign_field", ["target", "lineage"])
def test_no_candidate_rejects_terminal_completion_foreign_to_installed_head(
    tmp_path: Path, foreign_field: str
):
    service, prior = _installed_service(tmp_path)
    backend = FakeBackend(service=service, selected_artifact=None)
    event_id = prior["payload"]["event_id"]
    close_key = runner._phase_key(event_id, "CLOSE")
    recovery = _recovery(close_key, "CLOSE", plan="close-plan-foreign-head-0001")
    recovery["expected_after_position_hash"] = prior["payload"]["desired_target"][
        "target_position_hash"
    ]
    recovery["lineage"] = {
        field: prior["payload"]["monthly"][field]
        for field in (
            "static_core_equal_sha256",
            "position_manager_sha256",
            "final_target_sha256",
        )
    }
    completion = _completion(recovery)
    if foreign_field == "target":
        recovery["expected_after_position_hash"] = "f" * 64
        completion["expected_after_position_hash"] = "f" * 64
        completion["target_position_hash"] = "f" * 64
    else:
        recovery["lineage"]["final_target_sha256"] = "f" * 64
        completion["lineage"]["final_target_sha256"] = "f" * 64
    backend.recoveries[close_key] = recovery
    backend.completions[recovery["plan_id"]] = completion

    with pytest.raises(runner.ContinuousRunError, match="installed event root"):
        asyncio.run(runner._run_locked(backend))

    assert "facts" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)


def test_unknown_prior_recovery_is_not_misclassified_as_terminal(tmp_path: Path):
    service, prior = _installed_service(tmp_path)
    backend = FakeBackend(service=service, selected_artifact=_artifact(suffix="2"))
    close_key = runner._phase_key(prior["payload"]["event_id"], "CLOSE")
    backend.recoveries[close_key] = {
        "state": "UNKNOWN",
        "custody_idempotency_key": close_key,
        "phase": "CLOSE",
    }

    with pytest.raises(runner.ContinuousRunError, match="recovery state"):
        asyncio.run(runner._run_locked(backend))
    assert "facts" not in backend.calls
    assert "advance" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)


def test_terminal_resolution_prefers_exact_open_after_close():
    class TerminalBackend:
        def __init__(self):
            self.recoveries = {}
            self.completions = {}

        async def recovery(self, key):
            return self.recoveries[key]

        async def completion(self, plan_id):
            return self.completions[plan_id]

    event_id = "continuous-event-close-open-0001"
    backend = TerminalBackend()
    for phase in ("CLOSE", "OPEN"):
        key = runner._phase_key(event_id, phase)
        recovery = _recovery(key, phase, plan=f"{phase.lower()}-plan-test-0001")
        backend.recoveries[key] = recovery
        backend.completions[recovery["plan_id"]] = _completion(recovery)

    terminal, keys, active = asyncio.run(
        runner._terminal_completion(backend, event_id=event_id)
    )

    assert terminal is not None
    assert terminal.completion["phase"] == "OPEN"
    assert keys["CLOSE"] != keys["OPEN"]
    assert active is None


def test_open_completion_rejects_unfinished_close_recovery():
    class TerminalBackend:
        def __init__(self):
            self.recoveries = {}
            self.completions = {}

        async def recovery(self, key):
            return self.recoveries[key]

        async def completion(self, plan_id):
            return self.completions.get(plan_id)

    event_id = "continuous-event-open-conflict-0001"
    backend = TerminalBackend()
    close_key = runner._phase_key(event_id, "CLOSE")
    open_key = runner._phase_key(event_id, "OPEN")
    backend.recoveries[close_key] = _recovery(
        close_key, "CLOSE", plan="close-plan-unfinished-0001"
    )
    opened = _recovery(open_key, "OPEN", plan="open-plan-complete-0001")
    backend.recoveries[open_key] = opened
    backend.completions[opened["plan_id"]] = _completion(opened)

    with pytest.raises(runner.ContinuousRunError, match="unfinished CLOSE"):
        asyncio.run(runner._terminal_completion(backend, event_id=event_id))


def test_close_completion_is_not_terminal_while_open_is_active():
    class TerminalBackend:
        def __init__(self):
            self.recoveries = {}
            self.completions = {}

        async def recovery(self, key):
            return self.recoveries[key]

        async def completion(self, plan_id):
            return self.completions.get(plan_id)

    event_id = "continuous-event-close-active-open-0001"
    backend = TerminalBackend()
    close_key = runner._phase_key(event_id, "CLOSE")
    open_key = runner._phase_key(event_id, "OPEN")
    close = _recovery(close_key, "CLOSE", plan="close-plan-complete-0001")
    opened = _recovery(open_key, "OPEN", plan="open-plan-active-0001")
    backend.recoveries = {close_key: close, open_key: opened}
    backend.completions[close["plan_id"]] = _completion(close)

    terminal, _keys, reason = asyncio.run(
        runner._terminal_completion(backend, event_id=event_id)
    )

    assert terminal is None
    assert reason == "OPEN_ACTIVE_OR_NOT_STARTED"


def test_private_assembler_closes_genesis_monthly_with_real_validator():
    artifact = _artifact()
    resolved = _resolution_from_artifact(artifact)
    facts = json.loads(artifact["payload"]["account_facts"]["account_facts_raw"])
    head = runner.ContinuousEventHeadDTO.sealed(
        custody_secret="assembler-genesis-secret",
        state="NO_EVENT",
        request_nonce=HEAD_NONCE,
        observed_custody_version=0,
    )

    assembled = runner._assemble_verified_event(
        resolved=resolved,
        facts=facts,
        predecessor_head=head,
        predecessor=None,
    )
    repeated = runner._assemble_verified_event(
        resolved=resolved,
        facts=facts,
        predecessor_head=head,
        predecessor=None,
    )

    assert repeated == assembled
    assert (
        runner.event_contract.validate_simnow_continuous_event_v1(assembled["payload"])[
            "event_id"
        ]
        == artifact["payload"]["event_id"]
    )
    assert assembled["payload"]["predecessor"]["mode"] == "GENESIS_FLAT"
    assert set(assembled["payload"]["authority"].values()) == {False}
    classified = runner._classify_ownership(
        resolved=resolved,
        facts=facts,
        predecessor_head=head,
        predecessor=None,
    )
    assert classified.disposition is runner.FullAccountOwnershipDisposition.NEW_TARGET


def test_private_assembler_closes_prior_open_to_next_monthly(tmp_path: Path):
    service, prior = _installed_service(tmp_path / "prior-monthly")
    prior_head = service.continuous_event_head(request_nonce=HEAD_NONCE)
    next_artifact = _artifact(completion_phase="OPEN", suffix="2")
    resolved = _resolution_from_artifact(next_artifact)
    facts = json.loads(next_artifact["payload"]["account_facts"]["account_facts_raw"])
    terminal = _terminal_from_event(prior_head, next_artifact)

    assembled = runner._assemble_verified_event(
        resolved=resolved,
        facts=facts,
        predecessor_head=prior_head,
        predecessor=terminal,
    )

    payload = runner.event_contract.validate_simnow_continuous_event_v1(
        assembled["payload"]
    )
    assert payload["predecessor"]["terminal_target_id"] == prior["payload"]["event_id"]
    assert payload["predecessor"]["completion_phase"] == "OPEN"
    assert runner._classify_ownership(
        resolved=resolved,
        facts=facts,
        predecessor_head=prior_head,
        predecessor=terminal,
    ).disposition in {
        runner.FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED,
        runner.FullAccountOwnershipDisposition.ALREADY_SATISFIED,
    }


def test_private_assembler_closes_roll_and_rejects_foreign_roots(tmp_path: Path):
    service, prior = _installed_service(tmp_path / "prior-roll")
    prior_head = service.continuous_event_head(request_nonce=HEAD_NONCE)
    closed_prior = _artifact(completion_phase="CLOSE", suffix="2")
    terminal = _terminal_from_event(prior_head, closed_prior)
    facts = json.loads(closed_prior["payload"]["account_facts"]["account_facts_raw"])
    roll = _artifact(
        trigger="ROLL_ONLY",
        suffix="3",
        official_day="2026-08-04",
        execution_day="2026-08-05",
        monthly_execution_day="2026-07-31",
        previous_contract_month="09",
        previous_ag_contract_month="10",
        current_contract_month="11",
    )
    candidate = json.loads(roll["payload"]["source_event_raw"])["candidate"]
    candidate["predecessor_terminal_target_id"] = (
        prior_head.current_event.idempotency_key
    )
    candidate["predecessor_terminal_target_raw_sha256"] = (
        prior_head.current_event.artifact_raw_sha256
    )
    _rehash_structural_candidate(roll["payload"], candidate)
    roll = _reenvelope(roll["payload"])
    resolved = _resolution_from_artifact(roll)

    assembled = runner._assemble_verified_event(
        resolved=resolved,
        facts=facts,
        predecessor_head=prior_head,
        predecessor=terminal,
    )
    assert (
        runner.event_contract.validate_simnow_continuous_event_v1(assembled["payload"])[
            "trigger_kind"
        ]
        == "ROLL_ONLY"
    )
    assert (
        runner._classify_prior_close_ownership(
            facts=facts,
            predecessor_head=prior_head,
            predecessor=terminal,
        ).disposition
        is runner.FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED
    )

    foreign_catalog = SimpleNamespace(
        **{
            **vars(resolved.catalog),
            "artifact_raw_sha256": "a" * 64,
        }
    )
    with pytest.raises(
        runner.event_contract.ContinuousEventContractError,
        match="daily/catalog binding",
    ):
        runner._assemble_verified_event(
            resolved=replace(resolved, catalog=foreign_catalog),
            facts=facts,
            predecessor_head=prior_head,
            predecessor=terminal,
        )

    foreign_completion = json.loads(json.dumps(terminal.completion))
    foreign_completion["lineage"]["final_target_sha256"] = "f" * 64
    foreign_recovery = json.loads(json.dumps(terminal.recovery))
    foreign_recovery["lineage"]["final_target_sha256"] = "f" * 64
    with pytest.raises(runner.ContinuousRunError, match="installed event root"):
        runner._assemble_verified_event(
            resolved=resolved,
            facts=facts,
            predecessor_head=prior_head,
            predecessor=runner._TerminalCompletion(
                foreign_recovery, foreign_completion
            ),
        )


def test_prior_close_terminal_creates_distinct_next_monthly_event(tmp_path: Path):
    service, prior = _installed_service(tmp_path)
    prior_head = service.continuous_event_head(request_nonce=HEAD_NONCE)
    closed_prior = _artifact(completion_phase="CLOSE", suffix="2")
    terminal = _terminal_from_event(prior_head, closed_prior)
    facts = json.loads(closed_prior["payload"]["account_facts"]["account_facts_raw"])
    next_artifact = _artifact(
        suffix="3",
        source_month="2026-08",
        official_day="2026-08-31",
        execution_day="2026-09-01",
        monthly_contract_month="10",
        previous_contract_month="09",
        previous_ag_contract_month="10",
        current_contract_month="11",
    )
    resolved = _resolution_from_artifact(next_artifact)
    closed = runner._classify_prior_close_ownership(
        facts=facts,
        predecessor_head=prior_head,
        predecessor=terminal,
    )
    assert (
        closed.disposition
        is runner.FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED
    )
    assert closed.reason_code.value == "CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED"
    assert (
        next_artifact["payload"]["monthly"]["final_target_sha256"]
        != prior["payload"]["monthly"]["final_target_sha256"]
    )

    backend = FakeBackend(
        service=service,
        selected_artifact=next_artifact,
        resolution=resolved,
        facts=facts,
    )
    backend.recoveries[terminal.recovery["custody_idempotency_key"]] = terminal.recovery
    backend.completions[terminal.recovery["plan_id"]] = terminal.completion

    result = asyncio.run(runner._run_locked(backend))

    next_event_id = next_artifact["payload"]["event_id"]
    assert next_event_id != prior["payload"]["event_id"]
    assert result["status"] == "EVENT_INSTALLED"
    assert result["event_id"] == next_event_id
    assert result["phase_keys"]["OPEN"] == runner._phase_key(next_event_id, "OPEN")
    assert result["phase_keys"]["OPEN"] != runner._phase_key(
        prior["payload"]["event_id"], "OPEN"
    )


def test_prior_close_terminal_creates_distinct_roll_event(tmp_path: Path):
    service, prior = _installed_service(tmp_path)
    prior_head = service.continuous_event_head(request_nonce=HEAD_NONCE)
    closed_prior = _artifact(completion_phase="CLOSE", suffix="2")
    terminal = _terminal_from_event(prior_head, closed_prior)
    facts = json.loads(closed_prior["payload"]["account_facts"]["account_facts_raw"])
    roll = _artifact(
        trigger="ROLL_ONLY",
        suffix="3",
        official_day="2026-08-04",
        execution_day="2026-08-05",
        monthly_execution_day="2026-07-31",
        previous_contract_month="09",
        previous_ag_contract_month="10",
        current_contract_month="11",
    )
    candidate = json.loads(roll["payload"]["source_event_raw"])["candidate"]
    candidate["predecessor_terminal_target_id"] = (
        prior_head.current_event.idempotency_key
    )
    candidate["predecessor_terminal_target_raw_sha256"] = (
        prior_head.current_event.artifact_raw_sha256
    )
    _rehash_structural_candidate(roll["payload"], candidate)
    roll = _reenvelope(roll["payload"])
    resolved = _resolution_from_artifact(roll)
    backend = FakeBackend(
        service=service,
        selected_artifact=roll,
        resolution=resolved,
        facts=facts,
    )
    backend.recoveries[terminal.recovery["custody_idempotency_key"]] = terminal.recovery
    backend.completions[terminal.recovery["plan_id"]] = terminal.completion

    result = asyncio.run(runner._run_locked(backend))

    roll_event_id = roll["payload"]["event_id"]
    assert result["status"] == "EVENT_INSTALLED"
    assert result["event_id"] == roll_event_id
    assert result["phase_keys"]["CLOSE"] == runner._phase_key(roll_event_id, "CLOSE")
    assert result["phase_keys"]["OPEN"] != runner._phase_key(
        prior["payload"]["event_id"], "OPEN"
    )


def test_repeated_same_event_after_exact_close_is_noop_zero_write(tmp_path: Path):
    service, prior = _installed_service(tmp_path)
    prior_head = service.continuous_event_head(request_nonce=HEAD_NONCE)
    closed_prior = _artifact(completion_phase="CLOSE", suffix="2")
    terminal = _terminal_from_event(prior_head, closed_prior)
    facts = json.loads(closed_prior["payload"]["account_facts"]["account_facts_raw"])
    backend = FakeBackend(
        service=service,
        selected_artifact=prior,
        resolution=_resolution_from_artifact(prior),
        facts=facts,
    )
    backend.recoveries[terminal.recovery["custody_idempotency_key"]] = terminal.recovery
    backend.completions[terminal.recovery["plan_id"]] = terminal.completion

    result = asyncio.run(runner._run_locked(backend))

    assert result == {
        "status": "NOOP",
        "reason": "PRIOR_CLOSE_EVENT_ALREADY_TERMINAL",
        "custody_mutated": False,
        "leader_mutated": False,
        "execution_mutated": False,
        "gateway_mutated": False,
    }
    assert "custody-version" not in backend.calls
    assert "plan-ready" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)


@pytest.mark.parametrize("response_lost", [False, True])
def test_fake_e2e_publish_install_response_loss_and_phase_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response_lost: bool
):
    artifact = _artifact()
    backend = FakeBackend(
        service=_service(tmp_path), selected_artifact=artifact, plan_ready=True
    )
    backend.raise_publish_unknown = response_lost
    monkeypatch.setattr(runner, "_assemble_verified_event", lambda **_: artifact)
    monkeypatch.setattr(
        runner,
        "_classify_ownership",
        lambda **_: _ownership(runner.FullAccountOwnershipDisposition.NEW_TARGET),
    )

    result = asyncio.run(runner._run_locked(backend))

    assert result["status"] == "EVENT_INSTALLED"
    assert result["lifecycle"]["state"] == "FAKE_E2E_COMPLETE"
    assert backend.calls.count("facts") == 1
    assert backend.calls.count("custody-version") == 1
    assert backend.calls.count("advance") == 1
    assert backend.calls.index("facts") < backend.calls.index("custody-version")
    assert backend.calls.index("custody-version") < next(
        index for index, call in enumerate(backend.calls) if call.startswith("publish")
    )


def test_production_plan_adapter_blocker_stops_before_all_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    artifact = _artifact()
    backend = FakeBackend(
        service=_service(tmp_path), selected_artifact=artifact, plan_ready=False
    )
    monkeypatch.setattr(runner, "_assemble_verified_event", lambda **_: artifact)
    monkeypatch.setattr(
        runner,
        "_classify_ownership",
        lambda **_: _ownership(runner.FullAccountOwnershipDisposition.NEW_TARGET),
    )

    result = asyncio.run(runner._run_locked(backend))

    assert result["status"] == "STOP"
    assert result["reason"] == "INSTALLED_EVENT_PLAN_ADAPTER_UNAVAILABLE"
    assert result["custody_mutated"] is False
    assert result["leader_mutated"] is False
    assert result["execution_mutated"] is False
    assert result["gateway_mutated"] is False
    assert "custody-version" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)


def test_noop_ownership_is_full_domain_zero_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    artifact = _artifact()
    backend = FakeBackend(
        service=_service(tmp_path), selected_artifact=artifact, plan_ready=True
    )
    monkeypatch.setattr(
        runner,
        "_classify_ownership",
        lambda **_: _ownership(
            runner.FullAccountOwnershipDisposition.ALREADY_SATISFIED
        ),
    )

    result = asyncio.run(runner._run_locked(backend))

    assert result["status"] == "NOOP"
    assert result["custody_mutated"] is False
    assert result["leader_mutated"] is False
    assert result["execution_mutated"] is False
    assert result["gateway_mutated"] is False
    assert "custody-version" not in backend.calls
    assert "plan-ready" not in backend.calls
    assert not any(call.startswith("publish") for call in backend.calls)
