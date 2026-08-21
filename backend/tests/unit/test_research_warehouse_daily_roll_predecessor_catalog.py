# ruff: noqa: E402

from __future__ import annotations

import json
import os
import stat
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import research_warehouse.daily_roll_predecessor_catalog as catalog
import research_warehouse.m2_runtime_loader as runtime_loader
import research_warehouse.verified_daily_pit_main_roll_source as verified_roll
from research_warehouse import pit_source_view
from research_warehouse.canonical import canonical_json_line, sha256
from test_research_warehouse_verified_daily_pit_main_roll_source import (
    _kwargs,
    _state,
    _verified_input,
)


def _root_harness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state_holder: dict[str, object],
) -> None:
    @contextmanager
    def unlocked(*_args, **_kwargs):
        yield

    def prepare(path: Path) -> None:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)

    def create_only(path: Path, raw: bytes, *, create_only: bool = False) -> None:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if create_only and path.exists():
            raise catalog.DailyRollPredecessorCatalogError("test create-only collision")
        path.write_bytes(raw)
        path.chmod(0o444)

    def root_link_info(path: Path) -> SimpleNamespace:
        info = path.lstat()
        return SimpleNamespace(
            st_uid=0,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
        )

    def verified_retry_root(**values):
        state = values["operator_state"]
        verified = state_holder["inputs"][state.payload["last_trade_day"]]
        manifest = dict(verified.manifest)
        manifest["revisions"] = [
            {**row, "observation_ids": [row["observation_id"]]}
            for row in verified.manifest["revisions"]
        ]
        return (
            manifest,
            verified.manifest_raw_sha256,
            verified.commit_receipt_raw_sha256,
        )

    monkeypatch.setattr(catalog, "_require_root", lambda: None)
    monkeypatch.setattr(catalog, "_prepare_public_root_directory", prepare)
    monkeypatch.setattr(catalog, "_require_root_parent", lambda _path: None)
    monkeypatch.setattr(catalog, "require_root_managed", lambda _path: None)
    monkeypatch.setattr(catalog, "_validate_root_file_fd", lambda _fd: None)
    monkeypatch.setattr(catalog, "_validate_recovery_root_file_fd", lambda _fd: None)
    monkeypatch.setattr(catalog, "_validate_unpublished_partial_fd", lambda _fd: None)
    monkeypatch.setattr(catalog, "_recovery_link_info", root_link_info)
    monkeypatch.setattr(catalog, "_verified_retry_root", verified_retry_root)
    monkeypatch.setattr(catalog, "operator_state_lock", unlocked)
    monkeypatch.setattr(
        catalog,
        "load_operator_state",
        lambda _path: state_holder["state"],
    )
    monkeypatch.setattr(catalog, "_atomic_root_write", create_only)


def _genesis_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict, dict[str, verified_roll._VerifiedDailyInput], dict[str, object]]:
    kwargs, inputs, _private = _kwargs(monkeypatch, tmp_path)
    state = replace(kwargs["operator_state"], path=tmp_path / "operator-state.json")
    kwargs["operator_state"] = state
    holder: dict[str, object] = {"state": state, "inputs": inputs}
    _root_harness(monkeypatch, tmp_path, holder)
    return kwargs, inputs, holder


def _protected_inputs(tmp_path: Path, *, runtime_sha: str = "0" * 64) -> catalog.ProtectedGenesisReplayInputs:
    """Only root-held identities cross into the protected child replay."""

    return catalog.ProtectedGenesisReplayInputs(
        history_receipt_path=tmp_path / "history.json",
        runtime_input_path=tmp_path / "runtime.json",
        runtime_input_raw_sha256=runtime_sha,
        service_uid=503,
        service_gid=503,
        history_receipt_raw_sha256="1" * 64,
        manifest_public_key_path=tmp_path / "manifest.pub",
        manifest_public_key_raw_sha256="2" * 64,
        signed_baseline_batch_path=tmp_path / "baseline.json",
        business_public_key_path=tmp_path / "business.pub",
        business_public_key_raw_sha256="3" * 64,
        business_signer_key_id="research-signer-test-0001",
        contract_registry_path=tmp_path / "contracts.json",
        contract_registry_raw_sha256="4" * 64,
        source_month="2026-06",
    )


def test_protected_genesis_retry_reuses_exact_existing_catalog_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    monkeypatch.setattr(
        catalog,
        "_build_protected_genesis_as_service",
        lambda **_values: built,
    )
    monkeypatch.setattr(
        catalog,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(uid=503, gid=503),
    )
    monkeypatch.setattr(
        catalog,
        "load_runtime_input",
        lambda _path, **_kwargs: SimpleNamespace(raw_sha256="0" * 64),
    )
    protected = _protected_inputs(tmp_path)
    request = {
        "context": kwargs["context"],
        "operator_state": kwargs["operator_state"],
        "history_receipt_path": None,
        "pins": None,
        "manifest_public_key_path": None,
        "official_day": kwargs["official_day"],
        "contract_registry_raw": None,
        "expected_contract_registry_raw_sha256": None,
        "protected_genesis_inputs": protected,
    }
    first = catalog.publish_predecessor_artifact(**request)
    second = catalog.publish_predecessor_artifact(**request)
    assert second == first


def test_protected_genesis_rejects_root_drift_after_shared_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)

    def replay_then_drift(**_values):
        holder["state"] = replace(
            kwargs["operator_state"],
            raw_sha256="f" * 64,
        )
        return built

    monkeypatch.setattr(catalog, "_build_protected_genesis_as_service", replay_then_drift)
    monkeypatch.setattr(
        catalog,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(uid=503, gid=503),
    )
    monkeypatch.setattr(
        catalog,
        "load_runtime_input",
        lambda _path, **_kwargs: SimpleNamespace(raw_sha256="0" * 64),
    )
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="changed before publication",
    ):
        catalog.publish_predecessor_artifact(
            context=None,
            operator_state=kwargs["operator_state"],
            history_receipt_path=None,
            pins=None,
            manifest_public_key_path=None,
            official_day=kwargs["official_day"],
            contract_registry_raw=None,
            expected_contract_registry_raw_sha256=None,
            protected_genesis_inputs=_protected_inputs(tmp_path),
        )


def test_protected_genesis_final_publication_rechecks_runtime_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The parent rejects input drift while holding its final exclusive lock."""

    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    monkeypatch.setattr(
        catalog,
        "_build_protected_genesis_as_service",
        lambda **_values: built,
    )
    monkeypatch.setattr(
        catalog,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(uid=503, gid=503),
    )
    monkeypatch.setattr(
        catalog,
        "load_runtime_input",
        lambda _path, **_kwargs: SimpleNamespace(raw_sha256="f" * 64),
    )
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="protected publication runtime root drifted",
    ):
        catalog.publish_predecessor_artifact(
            context=None,
            operator_state=kwargs["operator_state"],
            history_receipt_path=None,
            pins=None,
            manifest_public_key_path=None,
            official_day=kwargs["official_day"],
            contract_registry_raw=None,
            expected_contract_registry_raw_sha256=None,
            protected_genesis_inputs=_protected_inputs(tmp_path),
        )


def test_protected_genesis_rejects_nonempty_catalog_before_child_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A fresh Genesis may not be created beside a prior catalog entry."""

    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipts = root / "receipts"
    receipts.mkdir(parents=True)
    (receipts / "2026-06-30.json").write_bytes(b"prior")
    monkeypatch.setattr(
        catalog,
        "_build_protected_genesis_as_service",
        lambda **_values: pytest.fail("non-empty Genesis reached protected replay"),
    )
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="cannot append Genesis to a non-empty catalog",
    ):
        catalog.publish_predecessor_artifact(
            context=None,
            operator_state=kwargs["operator_state"],
            history_receipt_path=None,
            pins=None,
            manifest_public_key_path=None,
            official_day=kwargs["official_day"],
            contract_registry_raw=None,
            expected_contract_registry_raw_sha256=None,
            protected_genesis_inputs=_protected_inputs(tmp_path),
        )


def test_protected_genesis_replays_in_child_then_publishes_sequence_one(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise the real forked protected replay and the real v3 builder.

    The test identity harness deliberately leaves the test process unprivileged;
    the production drop primitive is covered separately.  It lets the forked
    child traverse the same bounded proof pipe, strict proof validation, and
    create-only root publication without a caller-supplied built artifact.
    """

    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    context = kwargs["context"]
    context.policy.uid = 503
    context.policy.gid = 503
    genesis = kwargs["genesis"]
    registry_raw = kwargs["contract_registry_raw"]
    protected = replace(
        _protected_inputs(
            tmp_path,
            runtime_sha=context.runtime_input.raw_sha256,
        ),
        history_receipt_raw_sha256=kwargs["pins"].history_receipt_raw_sha256,
        manifest_public_key_raw_sha256=(
            kwargs["pins"].manifest_public_key_raw_sha256
        ),
        contract_registry_raw_sha256=sha256(registry_raw),
        signed_baseline_batch_path=tmp_path / "signed-baseline.json",
        business_public_key_path=genesis.business_public_key_path,
        business_public_key_raw_sha256=kwargs["pins"].baseline_public_key_raw_sha256,
        business_signer_key_id=genesis.expected_business_signer_key_id,
    )
    private_evidence_raws = {
        protected.history_receipt_path: b"history-private-proof",
        protected.contract_registry_path: registry_raw,
        protected.signed_baseline_batch_path: genesis.signed_baseline_batch_raw,
        protected.business_public_key_path: b"business-key-private-proof",
    }
    original_strict_read = catalog.read_regular_strict
    original_lstat = Path.lstat
    original_fstat = catalog.os.fstat
    private_parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=503)
    private_file = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_uid=503,
        st_nlink=1,
    )
    private_parents = {path.parent for path in private_evidence_raws}
    private_trace = tmp_path / "protected-private-evidence-trace.txt"
    private_acl_trace = tmp_path / "protected-private-evidence-acl-trace.txt"

    monkeypatch.setattr(catalog, "_drop_to_protected_replay_identity", lambda **_v: None)
    monkeypatch.setattr(
        catalog,
        "_prepare_protected_replay_identity_context",
        lambda **_values: catalog._ProtectedReplayIdentityContext(
            platform="linux",
            directory_memberships=frozenset({20}),
            write_protected_paths=(),
        ),
    )
    monkeypatch.setattr(
        runtime_loader,
        "load_runtime_context_readonly",
        lambda _path: context,
    )
    def strict_read(path, *args, **read_kwargs):
        protected_raw = private_evidence_raws.get(Path(path))
        if protected_raw is not None:
            assert read_kwargs["private"] is True
            read_kwargs["descriptor_validator"](991)
            return protected_raw
        return original_strict_read(path, *args, **read_kwargs)

    def lstat(path: Path):
        if path in private_parents:
            return private_parent
        return original_lstat(path)

    def fstat(descriptor: int):
        if descriptor == 991:
            return private_file
        return original_fstat(descriptor)

    real_private_read = catalog._read_private_protected_evidence

    def traced_private_read(path, *args, **read_kwargs):
        raw = real_private_read(path, *args, **read_kwargs)
        with private_trace.open("a", encoding="utf-8") as handle:
            handle.write(f"{path}\n")
        return raw

    def require_acl_free(path: Path, _label: str) -> None:
        with private_acl_trace.open("a", encoding="utf-8") as handle:
            handle.write(f"{path}\n")

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(catalog.os, "fstat", fstat)
    monkeypatch.setattr(
        catalog,
        "require_acl_free_path",
        require_acl_free,
    )
    monkeypatch.setattr(catalog, "read_regular_strict", strict_read)
    monkeypatch.setattr(catalog, "_read_private_protected_evidence", traced_private_read)
    monkeypatch.setattr(
        pit_source_view,
        "verify_root_pins",
        lambda **_values: ({"history": "root-verified"}, [{"chain": "root-verified"}]),
    )
    monkeypatch.setattr(
        verified_roll,
        "_root_replayed_genesis_baseline",
        lambda **_values: genesis.built_baseline,
    )
    monkeypatch.setattr(
        catalog,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(uid=503, gid=503),
    )
    monkeypatch.setattr(
        catalog,
        "load_runtime_input",
        lambda _path, **_kwargs: SimpleNamespace(
            raw_sha256=context.runtime_input.raw_sha256
        ),
    )
    # Exercise the protected builder inputs once in-process too, so a failure
    # remains diagnostic on platforms where child stdio is intentionally closed.
    in_process = verified_roll.build_verified_daily_pit_main_roll_source(
        context=context,
        operator_state=kwargs["operator_state"],
        history_receipt_path=protected.history_receipt_path,
        pins=pit_source_view.SourcePins(
            history_receipt_raw_sha256=protected.history_receipt_raw_sha256,
            operator_state_raw_sha256=kwargs["operator_state"].raw_sha256,
            manifest_public_key_raw_sha256=(
                protected.manifest_public_key_raw_sha256
            ),
            baseline_public_key_raw_sha256=(
                protected.business_public_key_raw_sha256
            ),
        ),
        manifest_public_key_path=protected.manifest_public_key_path,
        official_day=kwargs["official_day"],
        contract_registry_raw=registry_raw,
        expected_contract_registry_raw_sha256=sha256(registry_raw),
        genesis=verified_roll.GenesisContinuity(
            source_month=protected.source_month,
            built_baseline=genesis.built_baseline,
            signed_baseline_batch_raw=genesis.signed_baseline_batch_raw,
            business_public_key_path=protected.business_public_key_path,
            expected_business_signer_key_id=protected.business_signer_key_id,
        ),
    )
    assert in_process.artifact_raw
    request = {
        "context": None,
        "operator_state": kwargs["operator_state"],
        "history_receipt_path": None,
        "pins": None,
        "manifest_public_key_path": None,
        "official_day": kwargs["official_day"],
        "contract_registry_raw": None,
        "expected_contract_registry_raw_sha256": None,
        "protected_genesis_inputs": protected,
    }
    read_proof = catalog._read_protected_replay_payload

    def proof_then_manifest_drift(**values):
        raw = read_proof(**values)
        holder["state"] = replace(
            kwargs["operator_state"],
            payload={
                **kwargs["operator_state"].payload,
                "manifest_head_seal_sha256": "f" * 64,
            },
        )
        return raw

    monkeypatch.setattr(catalog, "_read_protected_replay_payload", proof_then_manifest_drift)
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="changed before publication",
    ):
        catalog.publish_predecessor_artifact(**request)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert not list((root / "artifacts").iterdir())
    assert not list((root / "receipts").iterdir())

    holder["state"] = kwargs["operator_state"]
    monkeypatch.setattr(catalog, "_read_protected_replay_payload", read_proof)
    first = catalog.publish_predecessor_artifact(**request)
    head = catalog.load_current_catalog_head(kwargs["operator_state"].path)
    assert first.receipt["sequence"] == 1
    assert first.receipt["previous_receipt_raw_sha256"] is None
    assert first.receipt["previous_artifact_id"] is None
    assert head.artifact_raw == first.artifact_raw
    assert head.receipt_raw == first.receipt_raw
    assert first.artifact["verified_lineage"]["continuity"]["mode"] == (
        "GENESIS_STATIC_CORE_EQUAL"
    )
    assert first.artifact["mains"] == json.loads(in_process.artifact_raw)["mains"]
    assert catalog.publish_predecessor_artifact(**request) == first
    traced_paths = {
        Path(value)
        for value in private_trace.read_text(encoding="utf-8").splitlines()
        if value
    }
    assert traced_paths == set(private_evidence_raws)
    # Each strict helper call checks the private parent both before and after
    # its stable file read.  The trace is child-written because the bounded
    # proof pipe intentionally carries only canonical Genesis proof bytes.
    assert {
        Path(value)
        for value in private_acl_trace.read_text(encoding="utf-8").splitlines()
        if value
    } == private_parents

def _linked_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict, dict, dict[str, object], catalog.CatalogEntry, catalog.CatalogEntry]:
    kwargs, inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    genesis_entry = catalog.publish_predecessor_artifact(**kwargs)
    head = "9" * 64
    commit = "a" * 64
    state = _state("2026-07-02", head, commit, sequence=2)
    state = replace(state, path=kwargs["operator_state"].path)
    holder["state"] = state
    current = _verified_input(
        "2026-07-02",
        head_seal=head,
        head_commit=commit,
        parent_seal=genesis_entry.artifact["verified_lineage"]["manifest"][
            "batch_seal_sha256"
        ],
        parent_commit=genesis_entry.artifact["verified_lineage"]["manifest"][
            "commit_seal_sha256"
        ],
        expected_genesis_baseline=None,
    )
    current = replace(current, predecessor_entry=genesis_entry)
    inputs["2026-07-02"] = current
    kwargs.update(
        operator_state=state,
        official_day="2026-07-02",
        genesis=None,
        predecessor=verified_roll.PredecessorContinuity(),
    )
    linked_entry = catalog.publish_predecessor_artifact(**kwargs)
    return kwargs, inputs, holder, genesis_entry, linked_entry


def _replace_catalog_artifact(
    root: Path,
    entry: catalog.CatalogEntry,
    artifact: dict,
) -> catalog.CatalogEntry:
    artifact["artifact_id"] = verified_roll._artifact_id(artifact)
    artifact_raw = canonical_json_line(artifact)
    old_artifact_path = root / entry.receipt["artifact_relative_path"]
    new_artifact_path = root / catalog._artifact_relative_path(artifact["artifact_id"])
    old_artifact_path.unlink()
    new_artifact_path.write_bytes(artifact_raw)
    new_artifact_path.chmod(0o444)
    receipt = dict(entry.receipt)
    receipt.update(
        artifact_id=artifact["artifact_id"],
        artifact_raw_sha256=sha256(artifact_raw),
        artifact_raw_bytes=len(artifact_raw),
        artifact_relative_path=catalog._artifact_relative_path(artifact["artifact_id"]),
    )
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_raw = canonical_json_line(receipt)
    receipt_path = root / "receipts" / f"{receipt['official_day']}.json"
    receipt_path.chmod(0o644)
    receipt_path.write_bytes(receipt_raw)
    receipt_path.chmod(0o444)
    return catalog.CatalogEntry(receipt_raw, receipt, artifact_raw, artifact)


def test_publication_replays_builder_and_is_create_only_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)

    first = catalog.publish_predecessor_artifact(**kwargs)
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("same-day retry rebuilt the artifact"),
    )
    second = catalog.publish_predecessor_artifact(**kwargs)

    assert second == first
    assert first.receipt["sequence"] == 1
    assert first.receipt["previous_receipt_raw_sha256"] is None
    assert first.receipt["artifact_raw_sha256"] == sha256(first.artifact_raw)
    assert first.receipt["artifact_id"] == first.artifact["artifact_id"]
    assert first.receipt["authority"] == first.artifact["authority"]
    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert sorted(path.name for path in (root / "receipts").iterdir()) == [
        "2026-07-01.json"
    ]
    assert sorted(path.name for path in (root / "artifacts").iterdir()) == [
        f"{first.artifact['artifact_id']}.json"
    ]


def test_publication_cannot_accept_forged_structural_raw_with_current_labels(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    forged = json.loads(built.artifact_raw)
    forged["verified_lineage"]["runtime"]["runtime_input_raw_sha256"] = "f" * 64
    forged["artifact_id"] = verified_roll._artifact_id(forged)
    forged_raw = canonical_json_line(forged)
    # The forgery is structurally coherent and retains all current operator
    # labels, but no public catalog API accepts caller-selected raw bytes.
    verified_roll.validate_structural_daily_pit_main_roll_source(forged_raw)

    with pytest.raises(TypeError, match="artifact_raw"):
        catalog.publish_predecessor_artifact(
            operator_state=kwargs["operator_state"],
            artifact_raw=forged_raw,
        )

    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert not root.exists()


def test_protected_genesis_parent_guards_root_managed_paths_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Child write isolation covers root custody, not its own private evidence."""

    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    protected = replace(
        _protected_inputs(tmp_path),
        history_receipt_path=tmp_path / "history" / "history.json",
        signed_baseline_batch_path=tmp_path / "baseline" / "baseline.json",
        business_public_key_path=tmp_path / "business" / "business.pub",
        contract_registry_path=tmp_path / "registry" / "contracts.json",
    )
    captured: dict[str, object] = {}

    def capture_context(**values):
        captured.update(values)
        raise RuntimeError("stop before fork")

    monkeypatch.setattr(
        catalog, "_prepare_protected_replay_identity_context", capture_context
    )
    with pytest.raises(RuntimeError, match="stop before fork"):
        catalog._build_protected_genesis_as_service_locked(
            operator_state=kwargs["operator_state"],
            official_day=kwargs["official_day"],
            inputs=protected,
        )

    paths = captured["write_protected_paths"]
    assert protected.history_receipt_path.parent not in paths
    assert protected.signed_baseline_batch_path.parent not in paths
    assert protected.business_public_key_path.parent not in paths
    assert protected.contract_registry_path.parent not in paths
    assert protected.history_receipt_path not in paths
    assert protected.signed_baseline_batch_path not in paths
    assert catalog.DEFAULT_MANIFEST_PRIVATE_KEY.parent in paths
    assert catalog.DEFAULT_BACKUP_PRIVATE_KEY.parent in paths
    assert catalog.DEFAULT_CALENDAR_PRIVATE_KEY.parent in paths


def _private_evidence_stat(*, mode: int, uid: int = 503) -> SimpleNamespace:
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=1)


def test_private_evidence_admission_allows_owner_write_but_enforces_private_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """0600/0700 owner evidence is intentionally writable by UID503."""

    path = Path("/protected/evidence/baseline.json")
    parent = _private_evidence_stat(mode=stat.S_IFDIR | 0o700)
    descriptor = _private_evidence_stat(mode=stat.S_IFREG | 0o600)
    acl_paths: list[Path] = []
    captured: dict[str, object] = {}

    monkeypatch.setattr(Path, "lstat", lambda _self: parent)
    monkeypatch.setattr(
        catalog,
        "require_acl_free_path",
        lambda candidate, _label: acl_paths.append(candidate),
    )
    monkeypatch.setattr(catalog.os, "access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(catalog.os, "fstat", lambda _descriptor: descriptor)

    def strict_read(_path, _label, **kwargs):
        captured.update(kwargs)
        kwargs["descriptor_validator"](7)
        return b"evidence"

    monkeypatch.setattr(catalog, "read_regular_strict", strict_read)
    assert catalog._read_private_protected_evidence(
        path,
        "private evidence",
        uid=503,
        limit=1024,
    ) == b"evidence"
    assert captured["private"] is True
    assert acl_paths == [path.parent, path.parent]


@pytest.mark.parametrize(
    ("parent_mode", "file_mode", "file_uid"),
    [
        (0o700, 0o600, 502),
        (0o700, 0o620, 503),
        (0o770, 0o600, 503),
    ],
)
def test_private_evidence_rejects_nonowner_or_group_write_custody(
    parent_mode: int,
    file_mode: int,
    file_uid: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("/protected/evidence/baseline.json")
    parent = _private_evidence_stat(mode=stat.S_IFDIR | parent_mode)
    descriptor = _private_evidence_stat(
        mode=stat.S_IFREG | file_mode,
        uid=file_uid,
    )
    monkeypatch.setattr(Path, "lstat", lambda _self: parent)
    monkeypatch.setattr(catalog, "require_acl_free_path", lambda *_args: None)
    monkeypatch.setattr(catalog.os, "fstat", lambda _descriptor: descriptor)

    def strict_read(_path, _label, **kwargs):
        kwargs["descriptor_validator"](7)
        return b"evidence"

    monkeypatch.setattr(catalog, "read_regular_strict", strict_read)
    with pytest.raises(catalog.DailyRollPredecessorCatalogError):
        catalog._read_private_protected_evidence(
            path,
            "private evidence",
            uid=503,
            limit=1024,
        )


def test_private_evidence_rejects_acl_granted_write_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("/protected/evidence/baseline.json")
    parent = _private_evidence_stat(mode=stat.S_IFDIR | 0o700)
    monkeypatch.setattr(Path, "lstat", lambda _self: parent)
    monkeypatch.setattr(
        catalog,
        "require_acl_free_path",
        lambda *_args: (_ for _ in ()).throw(
            catalog.RegistryError("extended ACL grants write")
        ),
    )
    with pytest.raises(catalog.RegistryError, match="extended ACL grants write"):
        catalog._read_private_protected_evidence(
            path,
            "private evidence",
            uid=503,
            limit=1024,
        )


def test_catalog_load_rejects_receipt_artifact_hash_tamper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    entry = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipt_path = root / "receipts" / "2026-07-01.json"
    receipt = json.loads(entry.receipt_raw)
    receipt["artifact_raw_sha256"] = "f" * 64
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_path.chmod(0o644)
    receipt_path.write_bytes(canonical_json_line(receipt))
    receipt_path.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="receipt/artifact binding mismatch",
    ):
        catalog._load_catalog(root)


def test_catalog_load_rejects_non_contiguous_sequence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    entry = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipt_path = root / "receipts" / "2026-07-01.json"
    receipt = json.loads(entry.receipt_raw)
    receipt["sequence"] = 2
    receipt["previous_receipt_raw_sha256"] = "e" * 64
    receipt["previous_artifact_id"] = "verified-daily-roll-" + "d" * 64
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_path.chmod(0o644)
    receipt_path.write_bytes(canonical_json_line(receipt))
    receipt_path.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="sequence is not contiguous",
    ):
        catalog._load_catalog(root)


def test_same_day_different_root_replayed_result_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    kwargs["context"] = SimpleNamespace(
        **{
            **vars(kwargs["context"]),
            "runtime_input": SimpleNamespace(raw_sha256="f" * 64),
        }
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="retry inputs do not match stored artifact",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_same_day_retry_rejects_forged_genesis_caller_bundle_before_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    kwargs["genesis"] = replace(kwargs["genesis"], source_month="2026-05")
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("forged retry reached the builder"),
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="retry input verification failed",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_publication_rejects_operator_root_change_after_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    original = verified_roll.build_verified_daily_pit_main_roll_source

    def build_then_rotate(**values):
        built = original(**values)
        state = values["operator_state"]
        holder["state"] = replace(state, raw_sha256="f" * 64)
        return built

    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        build_then_rotate,
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="operator state changed before publication",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    root = catalog.catalog_root(kwargs["operator_state"].path)
    assert not list((root / "artifacts").iterdir())
    assert not list((root / "receipts").iterdir())


def test_exact_orphan_artifact_is_recovered_but_conflict_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    artifact_path = root / catalog._artifact_relative_path(built.artifact_id)
    artifact_path.write_bytes(built.artifact_raw)
    artifact_path.chmod(0o444)

    recovered = catalog.publish_predecessor_artifact(**kwargs)
    assert recovered.artifact_raw == built.artifact_raw

    receipt_path = root / "receipts" / "2026-07-01.json"
    receipt_path.unlink()
    artifact_path.chmod(0o644)
    artifact_path.write_bytes(b"{}\n")
    artifact_path.chmod(0o444)
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="orphan artifact conflicts",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_artifact_link_before_unlink_crash_is_strictly_recovered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    target.write_bytes(built.artifact_raw)
    target.chmod(0o444)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    os.link(target, partial)
    assert target.stat().st_nlink == 2
    original = verified_roll.build_verified_daily_pit_main_roll_source

    def build_after_recovery(**values):
        assert not partial.exists()
        assert not target.exists()
        return original(**values)

    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        build_after_recovery,
    )

    entry = catalog.publish_predecessor_artifact(**kwargs)

    assert entry.artifact_raw == built.artifact_raw
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_receipt_link_before_unlink_crash_is_strictly_recovered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    first = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    target = root / "receipts" / "2026-07-01.json"
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    os.link(target, partial)
    assert target.stat().st_nlink == 2
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("receipt-commit retry rebuilt the artifact"),
    )

    recovered = catalog.publish_predecessor_artifact(**kwargs)

    assert recovered == first
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_complete_artifact_before_link_partial_is_validated_and_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(built.artifact_raw)
    partial.chmod(0o444)
    assert not target.exists()
    original = verified_roll.build_verified_daily_pit_main_roll_source

    def build_after_recovery(**values):
        assert not partial.exists()
        assert not target.exists()
        return original(**values)

    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        build_after_recovery,
    )

    entry = catalog.publish_predecessor_artifact(**kwargs)

    assert entry.artifact_raw == built.artifact_raw
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_complete_receipt_before_link_partial_is_validated_and_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    first = catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    target = root / "receipts" / "2026-07-01.json"
    target.unlink()
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(first.receipt_raw)
    partial.chmod(0o444)

    recovered = catalog.publish_predecessor_artifact(**kwargs)

    assert recovered == first
    assert not partial.exists()
    assert target.stat().st_nlink == 1


def test_incomplete_private_before_link_partial_is_safely_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(b'{"interrupted":')
    partial.chmod(0o600)

    recovered = catalog.publish_predecessor_artifact(**kwargs)

    assert recovered.artifact_raw == built.artifact_raw
    assert not partial.exists()


@pytest.mark.parametrize("directory", ["artifacts", "receipts"])
def test_invalid_completed_before_link_partial_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    directory: str,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    if directory == "artifacts":
        target = root / catalog._artifact_relative_path(built.artifact_id)
    else:
        target = root / "receipts" / "2026-07-01.json"
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(b"{}\n")
    partial.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="completed unpublished partial is invalid",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    assert partial.exists()
    assert not target.exists()


def test_conflicting_separate_partial_inode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    target.write_bytes(built.artifact_raw)
    target.chmod(0o444)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    partial.write_bytes(built.artifact_raw)
    partial.chmod(0o444)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="recovery link identity mismatch",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    assert partial.exists()
    assert not (root / "receipts" / "2026-07-01.json").exists()


def test_recovery_rejects_target_with_more_than_one_partial_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    catalog._prepare_catalog(root)
    target = root / catalog._artifact_relative_path(built.artifact_id)
    target.write_bytes(built.artifact_raw)
    target.chmod(0o444)
    partial = target.with_name(f".{target.name}-abcdefgh.partial")
    extra = target.with_name(f"{target.name}.extra-link")
    os.link(target, partial)
    os.link(target, extra)
    assert target.stat().st_nlink == 3

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="recovery link identity mismatch",
    ):
        catalog.publish_predecessor_artifact(**kwargs)

    assert partial.exists()
    assert extra.exists()


def test_linked_day_uses_catalog_head_and_extends_receipt_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    genesis_entry = catalog.publish_predecessor_artifact(**kwargs)

    head = "9" * 64
    commit = "a" * 64
    state = _state("2026-07-02", head, commit, sequence=2)
    state = replace(state, path=kwargs["operator_state"].path)
    holder["state"] = state
    current = _verified_input(
        "2026-07-02",
        head_seal=head,
        head_commit=commit,
        parent_seal=genesis_entry.artifact["verified_lineage"]["manifest"][
            "batch_seal_sha256"
        ],
        parent_commit=genesis_entry.artifact["verified_lineage"]["manifest"][
            "commit_seal_sha256"
        ],
        expected_genesis_baseline=None,
    )
    loaded = catalog._load_linked_predecessor_locked(
        operator_state=state,
        current_official_day=verified_roll._day("2026-07-02", "test day"),
        current_execution_day=verified_roll._day("2026-07-03", "test day"),
        current_manifest=current.manifest,
        runtime_input_raw_sha256=kwargs["context"].runtime_input.raw_sha256,
        calendar_raw_sha256=kwargs["context"].calendar.raw_sha256,
        calendar_availability_anchor_raw_sha256=kwargs[
            "context"
        ].availability.raw_sha256,
        isolation_policy_raw_sha256=kwargs["context"].policy.raw_sha256,
        warehouse_registry_raw_sha256=kwargs["context"].registry.raw_sha256,
        contract_registry_raw_sha256=kwargs["expected_contract_registry_raw_sha256"],
    )
    assert loaded == genesis_entry
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="predecessor/current-root continuity mismatch",
    ):
        catalog._load_linked_predecessor_locked(
            operator_state=state,
            current_official_day=verified_roll._day("2026-07-02", "test day"),
            current_execution_day=verified_roll._day("2026-07-03", "test day"),
            current_manifest=current.manifest,
            runtime_input_raw_sha256="f" * 64,
            calendar_raw_sha256=kwargs["context"].calendar.raw_sha256,
            calendar_availability_anchor_raw_sha256=kwargs[
                "context"
            ].availability.raw_sha256,
            isolation_policy_raw_sha256=kwargs["context"].policy.raw_sha256,
            warehouse_registry_raw_sha256=kwargs["context"].registry.raw_sha256,
            contract_registry_raw_sha256=kwargs[
                "expected_contract_registry_raw_sha256"
            ],
        )
    inputs["2026-07-02"] = replace(current, predecessor_entry=loaded)
    kwargs.update(
        operator_state=state,
        official_day="2026-07-02",
        genesis=None,
        predecessor=verified_roll.PredecessorContinuity(),
    )

    linked = catalog.publish_predecessor_artifact(**kwargs)

    assert linked.receipt["sequence"] == 2
    assert linked.receipt["previous_receipt_raw_sha256"] == sha256(
        genesis_entry.receipt_raw
    )
    assert (
        linked.receipt["previous_artifact_id"] == genesis_entry.artifact["artifact_id"]
    )
    assert linked.artifact["verified_lineage"]["continuity"]["mode"] == (
        "LINKED_ROOT_CATALOG"
    )
    assert (
        linked.artifact["verified_lineage"]["continuity"]["predecessor_artifact_id"]
        == genesis_entry.artifact["artifact_id"]
    )


def test_catalog_rejects_nonfirst_genesis_cross_branch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, genesis_entry, linked_entry = _linked_setup(
        monkeypatch, tmp_path
    )
    root = catalog.catalog_root(kwargs["operator_state"].path)
    artifact = json.loads(linked_entry.artifact_raw)
    forged_continuity = dict(genesis_entry.artifact["verified_lineage"]["continuity"])
    forged_continuity["baseline_execution_day"] = artifact["official_day"]
    forged_continuity["predecessor_exact_contract_map_sha256"] = artifact[
        "verified_lineage"
    ]["continuity"]["predecessor_exact_contract_map_sha256"]
    artifact["verified_lineage"]["continuity"] = forged_continuity
    forged = _replace_catalog_artifact(root, linked_entry, artifact)
    verified_roll.validate_structural_daily_pit_main_roll_source(forged.artifact_raw)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="non-first artifact is not linked continuity",
    ):
        catalog._load_catalog(root)


def test_linked_same_day_retry_returns_existing_before_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, _genesis_entry, linked_entry = _linked_setup(
        monkeypatch, tmp_path
    )
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("linked same-day retry rebuilt the artifact"),
    )

    assert catalog.publish_predecessor_artifact(**kwargs) == linked_entry


def test_catalog_rejects_linked_continuity_spliced_from_another_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, _genesis_entry, linked_entry = _linked_setup(
        monkeypatch, tmp_path
    )
    root = catalog.catalog_root(kwargs["operator_state"].path)
    artifact = json.loads(linked_entry.artifact_raw)
    artifact["verified_lineage"]["continuity"]["catalog_receipt_id"] = (
        "daily-roll-catalog-receipt-" + "f" * 64
    )
    forged = _replace_catalog_artifact(root, linked_entry, artifact)
    verified_roll.validate_structural_daily_pit_main_roll_source(forged.artifact_raw)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="linked artifact/predecessor binding mismatch",
    ):
        catalog._load_catalog(root)


def test_publisher_rejects_appending_genesis_before_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    kwargs["official_day"] = "2026-07-02"
    monkeypatch.setattr(
        verified_roll,
        "build_verified_daily_pit_main_roll_source",
        lambda **_values: pytest.fail("non-empty Genesis reached the builder"),
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="cannot append Genesis to a non-empty catalog",
    ):
        catalog.publish_predecessor_artifact(**kwargs)


def test_linked_load_rejects_current_manifest_cross_splice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    state = _state("2026-07-02", "9" * 64, "a" * 64, sequence=2)
    state = replace(state, path=kwargs["operator_state"].path)
    holder["state"] = state
    current = _verified_input(
        "2026-07-02",
        head_seal="9" * 64,
        head_commit="a" * 64,
        parent_seal="f" * 64,
        parent_commit="e" * 64,
        expected_genesis_baseline=None,
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="predecessor/current-root continuity mismatch",
    ):
        catalog._load_linked_predecessor_locked(
            operator_state=state,
            current_official_day=verified_roll._day("2026-07-02", "test day"),
            current_execution_day=verified_roll._day("2026-07-03", "test day"),
            current_manifest=current.manifest,
            runtime_input_raw_sha256=kwargs["context"].runtime_input.raw_sha256,
            calendar_raw_sha256=kwargs["context"].calendar.raw_sha256,
            calendar_availability_anchor_raw_sha256=kwargs[
                "context"
            ].availability.raw_sha256,
            isolation_policy_raw_sha256=kwargs["context"].policy.raw_sha256,
            warehouse_registry_raw_sha256=kwargs["context"].registry.raw_sha256,
            contract_registry_raw_sha256=kwargs[
                "expected_contract_registry_raw_sha256"
            ],
        )


@pytest.mark.parametrize(
    ("uid", "mode", "nlink"),
    [
        (501, stat.S_IFREG | 0o444, 1),
        (0, stat.S_IFREG | 0o644, 1),
        (0, stat.S_IFREG | 0o444, 2),
        (0, stat.S_IFLNK | 0o444, 1),
    ],
)
def test_root_catalog_file_descriptor_contract_is_strict(
    monkeypatch: pytest.MonkeyPatch,
    uid: int,
    mode: int,
    nlink: int,
) -> None:
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _descriptor: SimpleNamespace(
            st_uid=uid,
            st_mode=mode,
            st_nlink=nlink,
        ),
    )
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="not immutable root custody",
    ):
        catalog._validate_root_file_fd(7)


@pytest.mark.parametrize(
    "relative",
    ["/artifacts/x.json", "../x.json", "artifacts/../x.json", "other/x.json"],
)
def test_catalog_artifact_path_rejects_escape(tmp_path: Path, relative: str) -> None:
    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="artifact path is unsafe",
    ):
        catalog._artifact_path(tmp_path, relative)


def _catalog_tree_snapshot(root: Path) -> dict[str, tuple[int, int, int, bytes]]:
    snapshot = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        raw = path.read_bytes() if stat.S_ISREG(info.st_mode) else b""
        snapshot[str(path.relative_to(root))] = (
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
            info.st_size,
            raw,
        )
    return snapshot


def test_current_head_proof_is_restart_stable_shared_locked_and_zero_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder, genesis, linked = _linked_setup(monkeypatch, tmp_path)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    before = _catalog_tree_snapshot(root)
    lock_modes: list[bool] = []
    load_count = 0
    lock_held = False
    load_catalog = catalog._load_catalog

    @contextmanager
    def shared_lock(_path: Path, *, exclusive: bool):
        nonlocal lock_held
        lock_modes.append(exclusive)
        lock_held = True
        try:
            yield
        finally:
            lock_held = False

    def reload_state(_path: Path):
        nonlocal load_count
        assert lock_held is True
        load_count += 1
        return replace(holder["state"])

    def load_catalog_while_locked(*args, **kwargs):
        assert lock_held is True
        return load_catalog(*args, **kwargs)

    def unexpected_write(*_args, **_kwargs):
        pytest.fail("read-only current-head proof attempted a catalog write")

    monkeypatch.setattr(catalog, "operator_state_lock", shared_lock)
    monkeypatch.setattr(catalog, "load_operator_state", reload_state)
    monkeypatch.setattr(catalog, "_load_catalog", load_catalog_while_locked)
    monkeypatch.setattr(catalog, "_prepare_catalog", unexpected_write)
    monkeypatch.setattr(catalog, "_recover_catalog_partial", unexpected_write)
    monkeypatch.setattr(catalog, "_atomic_root_write", unexpected_write)

    first = catalog.load_current_catalog_head(kwargs["operator_state"].path)
    second = catalog.load_current_catalog_head(kwargs["operator_state"].path)

    assert first == second
    assert load_count == 2
    assert lock_modes == [False, False]
    assert first.receipt_raw == linked.receipt_raw
    assert first.receipt_raw_sha256 == sha256(linked.receipt_raw)
    assert first.artifact_raw == linked.artifact_raw
    assert first.artifact_raw_sha256 == sha256(linked.artifact_raw)
    assert first.operator_state_raw_sha256 == holder["state"].raw_sha256
    assert first.operator_manifest_sequence == 2
    assert (
        first.manifest_genesis_seal_sha256
        == holder["state"].payload["manifest_genesis_seal_sha256"]
    )
    assert (
        first.manifest_head_seal_sha256
        == holder["state"].payload["manifest_head_seal_sha256"]
    )
    assert (
        first.manifest_head_commit_seal_sha256
        == holder["state"].payload["manifest_head_commit_seal_sha256"]
    )
    assert (
        first.commit_anchor_ledger_raw_sha256
        == holder["state"].payload["commit_anchor_ledger_raw_sha256"]
    )
    assert first.last_trade_day == "2026-07-02"
    assert first.authority == linked.receipt["authority"]
    assert set(first.authority.values()) == {False}
    assert _catalog_tree_snapshot(root) == before

    schema_path = (
        ROOT
        / "deployments/research-warehouse/daily-roll-predecessor-catalog-receipt-v1.schema.json"
    )
    schema = json.loads(schema_path.read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(json.loads(genesis.receipt_raw))
    validator.validate(json.loads(first.receipt_raw))
    forged_authority = json.loads(first.receipt_raw)
    forged_authority["authority"]["order_authorized"] = True
    assert validator.is_valid(forged_authority) is False


def test_current_head_proof_rejects_current_root_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    holder["state"] = replace(holder["state"], raw_sha256="f" * 64)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="not bound to current root",
    ):
        catalog.load_current_catalog_head(kwargs["operator_state"].path)


def test_current_head_proof_rejects_old_head_after_root_advance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    holder["state"] = replace(
        _state("2026-07-02", "9" * 64, "a" * 64, sequence=2),
        path=kwargs["operator_state"].path,
    )

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="not bound to current root",
    ):
        catalog.load_current_catalog_head(kwargs["operator_state"].path)


def test_current_head_proof_rejects_tamper_anywhere_in_catalog_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder, genesis, _linked = _linked_setup(monkeypatch, tmp_path)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    genesis_path = root / "receipts" / "2026-07-01.json"
    tampered = dict(genesis.receipt)
    tampered["operator_state_raw_sha256"] = "f" * 64
    tampered["receipt_id"] = catalog._receipt_id(tampered)
    genesis_path.chmod(0o644)
    genesis_path.write_bytes(canonical_json_line(tampered))
    genesis_path.chmod(0o444)

    with pytest.raises(catalog.DailyRollPredecessorCatalogError):
        catalog.load_current_catalog_head(kwargs["operator_state"].path)


def test_current_head_proof_rejects_symlinked_receipt_without_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipt_path = root / "receipts" / "2026-07-01.json"
    external = tmp_path / "external-receipt.json"
    external.write_bytes(receipt_path.read_bytes())
    external.chmod(0o444)
    receipt_path.unlink()
    receipt_path.symlink_to(external)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="current catalog head verification failed",
    ):
        catalog.load_current_catalog_head(kwargs["operator_state"].path)

    assert receipt_path.is_symlink()


def test_current_head_proof_rejects_multi_link_catalog_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    receipt_path = root / "receipts" / "2026-07-01.json"
    os.link(receipt_path, tmp_path / "extra-receipt-link.json")

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="current catalog head verification failed",
    ):
        catalog.load_current_catalog_head(kwargs["operator_state"].path)


def test_current_head_proof_rejects_empty_catalog_without_creating_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    root = catalog.catalog_root(kwargs["operator_state"].path)
    (root / "artifacts").mkdir(parents=True)
    (root / "receipts").mkdir()
    before = _catalog_tree_snapshot(root)

    with pytest.raises(
        catalog.DailyRollPredecessorCatalogError,
        match="catalog is empty",
    ):
        catalog.load_current_catalog_head(kwargs["operator_state"].path)

    assert _catalog_tree_snapshot(root) == before
