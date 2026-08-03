from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.services.commodity_c_fast_execution_quality_evidence_export import (
    build_execution_quality_evidence_export,
)
from app.services.commodity_c_fast_execution_quality_questdb_readonly import (
    CFastExecutionQualityQuestDBReadonlyError,
    CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter,
)
from app.services.commodity_c_fast_execution_quality_readonly_repository import (
    CommodityCFastExecutionQualityReadonlyRepository,
)


ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
CONTRACT = "SHFE.cu2612"
FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}
_BUNDLE_NAMES = (
    "foundation_release",
    "foundation_keyring",
    "executable_release",
    "executable_keyring",
    "active_pin_set",
    "manifest",
    "consume_marker",
    "launch_marker",
    "terminal",
    "audit_json",
    "audit_csv",
    "audit_markdown",
    "readonly_proof",
    "external_custody_identity",
)


def _load_test_helpers(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SIDECAR = _load_test_helpers(
    "questdb_readonly_sidecar_helpers",
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _endpoint_sha256() -> str:
    return _sha256(_canonical({"dbname": "qdb", "host": "questdb", "port": 8812}))


def _readonly_snapshot() -> dict[str, object]:
    return {
        "questdb_build": "test-build",
        "readonly_user_enabled": True,
        "principal_matches_readonly_user": True,
        "principal_differs_admin": True,
        "global_pgwire_readonly": False,
        "instance_readonly": False,
        "configuration_sources": {
            "pg.readonly.password": "env",
            "pg.readonly.user": "env",
            "pg.readonly.user.enabled": "env",
            "pg.security.readonly": "default",
            "pg.user": "env",
            "readonly": "default",
        },
    }


def _write_minimal_p0(path: Path) -> bytes:
    proof = {
        "endpoint_identity_sha256": _endpoint_sha256(),
        "preflight": _readonly_snapshot(),
        "postflight": _readonly_snapshot(),
        "write_probe_attempted": False,
        "database_mutations": 0,
    }
    proof_raw = _canonical(proof) + b"\n"
    filler_raw = _canonical({"fixture": "p0"}) + b"\n"
    digests = {name: _sha256(name.encode("utf-8")) for name in _BUNDLE_NAMES}
    canonical_digests = {
        name: (None if name in {"audit_csv", "audit_markdown"} else value)
        for name, value in digests.items()
    }
    sizes = {name: 1 for name in _BUNDLE_NAMES}
    archived_at = NOW - timedelta(minutes=1)
    payload = {
        "schema_version": "commodity_c_fast_execution_quality_p0_acceptance_v6_v1",
        "artifact_role": "signed_p0_acceptance",
        "purpose": "c_fast_query_v6_exact_terminal_p0_acceptance",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "generation_id": "questdb-readonly-test-generation-v1",
        "snapshot_id": "questdb-readonly-test-snapshot-v1",
        "issued_at_utc": NOW.isoformat(),
        "valid_until_utc": (NOW + timedelta(minutes=5)).isoformat(),
        "exact_contracts": [CONTRACT],
        "signer_key_id": "questdb-readonly-test-signer",
        "signature": "A" * 88,
        "terminal_exact_json_base64": base64.b64encode(filler_raw).decode(),
        "terminal_raw_sha256": "1" * 64,
        "terminal_canonical_sha256": "2" * 64,
        "readonly_proof_exact_json_base64": base64.b64encode(proof_raw).decode(),
        "readonly_proof_raw_sha256": _sha256(proof_raw),
        "readonly_proof_canonical_sha256": _sha256(_canonical(proof)),
        "audit_exact_json_base64": base64.b64encode(filler_raw).decode(),
        "audit_raw_sha256": "3" * 64,
        "audit_canonical_sha256": "4" * 64,
        "manifest_exact_json_base64": base64.b64encode(filler_raw).decode(),
        "executable_release_raw_sha256": "5" * 64,
        "executable_release_canonical_sha256": "6" * 64,
        "foundation_raw_sha256": "7" * 64,
        "foundation_canonical_sha256": "8" * 64,
        "execution_adapter_sha256": "9" * 64,
        "bundle_raw_sha256": digests,
        "bundle_canonical_sha256": canonical_digests,
        "bundle_size_bytes": sizes,
        "bundle_index_sha256": "a" * 64,
        "external_archive": {
            "custody_id": "questdb-readonly-test-custody",
            "asserted_archive_type": "ASSERTED_APPEND_ONLY",
            "archive_locator_sha256": "b" * 64,
            "custody_identity_raw_sha256": "c" * 64,
            "custody_identity_canonical_sha256": "d" * 64,
            "archived_bundle_index_sha256": "a" * 64,
            "archived_at_utc": archived_at.isoformat(),
            "independent_custody_asserted": True,
            "immutability_asserted": True,
            "verification_state": "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED",
        },
        "consumed_at_utc": (NOW - timedelta(minutes=5)).isoformat(),
        "started_at_utc": (NOW - timedelta(minutes=5)).isoformat(),
        "final_revalidation_at_utc": (NOW - timedelta(minutes=4)).isoformat(),
        "launch_claimed_at_utc": (NOW - timedelta(minutes=3)).isoformat(),
        "ended_at_utc": (NOW - timedelta(minutes=2)).isoformat(),
        "archived_at_utc": archived_at.isoformat(),
        "p0_accepted": True,
        "exact_terminal_replayed": True,
        "exact_readonly_proof_replayed": True,
        "exact_audit_replayed": True,
        "signer_type": "human",
        "reviewer_role": "independent test reviewer",
        "human_signature": "Reviewed exact test evidence",
        **FALSE_AUTHORITY,
    }
    raw = _canonical(payload) + b"\n"
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _revalidation(p0_raw: bytes) -> CFastExecutionQualityRuntimeRevalidationDTO:
    core = {
        "schema_version": "commodity_c_fast_execution_quality_runtime_revalidation_v1",
        "trigger": "startup",
        "revalidated_at_utc": NOW.isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (NOW + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
        "exact_contracts": [CONTRACT],
        "signed_p0_acceptance_sha256": _sha256(p0_raw),
        "collection_admission_sha256": "2" * 64,
        "execution_policy_sha256": "3" * 64,
        "signed_snapshot_sha256": "4" * 64,
        "virtual_intent_plan_sha256": "5" * 64,
        "contract_spec_set_sha256": "6" * 64,
        "custody_binding_sha256": "7" * 64,
        "verified_signer_domains": {
            "signed_p0_acceptance": ["8" * 64],
            "collection_admission": ["9" * 64],
            "execution_policy": ["a" * 64],
            "signed_snapshot": ["b" * 64],
            "virtual_intent_plan": ["c" * 64],
            "contract_spec_set": ["d" * 64],
            "custody_binding": ["e" * 64],
        },
        "p0_acceptance_state": "VERIFIED",
        "collection_admission_state": "VERIFIED",
        "execution_policy_state": "VERIFIED",
        "signed_snapshot_state": "VERIFIED",
        "virtual_intent_plan_state": "VERIFIED",
        "contract_spec_state": "VERIFIED",
        "custody_state": "VERIFIED",
        **FALSE_AUTHORITY,
    }
    return CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
        {**core, "receipt_sha256": _sha256(_canonical(core))}
    )


class _Rows:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self._rows)


class _ReadonlyConnection:
    def __init__(self, *, principal: str = "readonly") -> None:
        self.info = SimpleNamespace(host="questdb", port=8812, dbname="qdb")
        self.principal = principal
        self.queries: list[str] = []
        self.closed = False

    def execute(self, query: str) -> _Rows:
        self.queries.append(query)
        if query == "SELECT current_user(), build()":
            return _Rows([(self.principal, "test-build")])
        values = {
            "pg.readonly.password": ("masked", "env", True),
            "pg.readonly.user": ("readonly", "env", False),
            "pg.readonly.user.enabled": ("true", "env", False),
            "pg.security.readonly": ("false", "default", False),
            "pg.user": ("admin", "env", False),
            "readonly": ("false", "default", False),
        }
        return _Rows(
            [
                (key, "", value, source, sensitive, "")
                for key, (value, source, sensitive) in values.items()
            ]
        )

    def close(self) -> None:
        self.closed = True


def _fixture(tmp_path: Path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = SIDECAR.sidecar(source_root)
    SIDECAR.register(source)
    repository = CommodityCFastExecutionQualityReadonlyRepository(source)
    repository_status = repository.recover()
    exported = build_execution_quality_evidence_export(source)
    p0_path = tmp_path / "signed-p0.json"
    receipt = _revalidation(_write_minimal_p0(p0_path))
    dsn_path = tmp_path / "questdb-readonly.dsn"
    dsn_path.write_text("postgresql://readonly:test-secret@questdb:8812/qdb\n")
    dsn_path.chmod(0o600)
    return receipt, repository_status, exported, p0_path, dsn_path


def test_exact_readonly_source_and_journal_export_checkpoint_survive_restart(
    tmp_path: Path,
) -> None:
    receipt, repository_status, exported, p0_path, dsn_path = _fixture(tmp_path)
    connections: list[_ReadonlyConnection] = []

    def connect(dsn: str) -> _ReadonlyConnection:
        assert dsn.startswith("postgresql://readonly:")
        connection = _ReadonlyConnection()
        connections.append(connection)
        return connection

    adapter = CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter(
        dsn_path=dsn_path,
        signed_p0_path=p0_path,
        expected_dsn_owner_uid=os.geteuid(),
        expected_p0_owner_uid=os.geteuid(),
        connection_factory=connect,
        clock=lambda: NOW,
    )

    first = adapter.verify(
        revalidation_receipt=receipt,
        repository_status=repository_status,
        evidence_export=exported,
    )
    duplicate = adapter.verify(
        revalidation_receipt=receipt,
        repository_status=repository_status,
        evidence_export=exported,
    )
    adapter.stop()
    restarted = adapter.verify(
        revalidation_receipt=receipt,
        repository_status=repository_status,
        evidence_export=exported,
    )

    assert first == duplicate == restarted
    assert all(connection.closed for connection in connections)
    assert all(len(connection.queries) == 4 for connection in connections)
    assert restarted.journal_export_join_verified is True
    assert restarted.query_v6_terminal_join_verified is True
    assert adapter.status()["server_enforced_readonly_verified"] is True
    assert "test-secret" not in json.dumps(adapter.status(), sort_keys=True)
    assert adapter.status()["orders_sent"] == 0
    assert adapter.status()["positions_modified"] == 0


def test_only_writer_dsn_never_falls_back_when_private_path_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt, repository_status, exported, p0_path, dsn_path = _fixture(tmp_path)
    dsn_path.unlink()
    monkeypatch.setenv(
        "QUESTDB_PG_DSN",
        "postgresql://admin:writer-secret@questdb:8812/qdb",
    )
    calls = 0

    def forbidden_connect(_: str):
        nonlocal calls
        calls += 1
        raise AssertionError("writer fallback must not connect")

    adapter = CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter(
        dsn_path=dsn_path,
        signed_p0_path=p0_path,
        expected_dsn_owner_uid=os.geteuid(),
        expected_p0_owner_uid=os.geteuid(),
        connection_factory=forbidden_connect,
        clock=lambda: NOW,
    )

    with pytest.raises(
        CFastExecutionQualityQuestDBReadonlyError,
        match="QUESTDB_READONLY_DSN_CUSTODY_INVALID",
    ):
        adapter.verify(
            revalidation_receipt=receipt,
            repository_status=repository_status,
            evidence_export=exported,
        )

    assert calls == 0
    assert adapter.status()["blocked_fail_closed"] is True
    assert "writer-secret" not in json.dumps(adapter.status(), sort_keys=True)


def test_writer_principal_and_checkpoint_drift_fail_closed_before_capability(
    tmp_path: Path,
) -> None:
    receipt, repository_status, exported, p0_path, dsn_path = _fixture(tmp_path)
    connections: list[_ReadonlyConnection] = []

    def writer_connect(_: str) -> _ReadonlyConnection:
        connection = _ReadonlyConnection(principal="admin")
        connections.append(connection)
        return connection

    adapter = CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter(
        dsn_path=dsn_path,
        signed_p0_path=p0_path,
        expected_dsn_owner_uid=os.geteuid(),
        expected_p0_owner_uid=os.geteuid(),
        connection_factory=writer_connect,
        clock=lambda: NOW,
    )
    with pytest.raises(
        CFastExecutionQualityQuestDBReadonlyError,
        match="QUESTDB_READONLY_SERVER_ENFORCEMENT_INVALID",
    ):
        adapter.verify(
            revalidation_receipt=receipt,
            repository_status=repository_status,
            evidence_export=exported,
        )
    assert connections[0].closed is True
    assert adapter.status()["server_enforced_readonly_verified"] is False

    connect_calls = 0

    def should_not_connect(_: str):
        nonlocal connect_calls
        connect_calls += 1
        raise AssertionError("journal drift must fail before connecting")

    drifted_adapter = CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter(
        dsn_path=dsn_path,
        signed_p0_path=p0_path,
        expected_dsn_owner_uid=os.geteuid(),
        expected_p0_owner_uid=os.geteuid(),
        connection_factory=should_not_connect,
        clock=lambda: NOW,
    )
    with pytest.raises(
        CFastExecutionQualityQuestDBReadonlyError,
        match="QUESTDB_READONLY_JOURNAL_EXPORT_JOIN_MISMATCH",
    ):
        drifted_adapter.verify(
            revalidation_receipt=receipt,
            repository_status={
                **repository_status,
                "source_journal_tip_record_hash": "f" * 64,
            },
            evidence_export=exported,
        )
    assert connect_calls == 0
    assert drifted_adapter.status()["blocked_fail_closed"] is True
