from __future__ import annotations

import ast
import base64
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_pure_producer_kernel as producer
import commodity_c_fast_simnow_research_bundle as bundle
import research_warehouse.sealed_export_custody as custody
from research_warehouse.canonical import (
    canonical_json_line,
    sha256,
)
from research_warehouse.errors import RegistryError
from research_warehouse.sealed_export import (
    create_sealed_export,
    verify_sealed_export,
)
from research_warehouse.sealed_export_contracts import (
    KEYRING_SCHEMA,
    SIGNING_PURPOSE,
)
from research_warehouse.signing import public_key_sha256
from research_warehouse.timeutil import format_utc

SCHEMA_ROOT = ROOT / "deployments/research-warehouse"
MANIFEST_SCHEMA = SCHEMA_ROOT / "sealed-source-export-v1.schema.json"
RECEIPT_SCHEMA = SCHEMA_ROOT / "sealed-source-export-receipt-v1.schema.json"
KEYRING_SCHEMA_PATH = SCHEMA_ROOT / "sealed-source-export-keyring-v1.schema.json"
UTC = timezone.utc


def _producer_fixture_module():
    path = ROOT / "backend/tests/unit/test_commodity_c_fast_pure_producer_kernel.py"
    spec = importlib.util.spec_from_file_location("producer_fixture_171", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_file(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def export_inputs(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    fixture = _producer_fixture_module()
    source = fixture.source_view()
    produced = producer.produce_research_artifacts(source)
    source_view_path = _private_file(
        tmp_path / "source-view.json",
        producer.canonical_json(source),
    )
    source_root = tmp_path / "producer-artifacts"
    source_root.mkdir(mode=0o700)
    artifact_paths = {
        role: _private_file(source_root / f"{role}.json", raw)
        for role, raw in produced.artifacts.items()
    }
    lineage = {
        "registry_raw_sha256": "1" * 64,
        "calendar_raw_sha256": "2" * 64,
        "calendar_anchor_sha256": "3" * 64,
        "commit_anchor_ledger_sha256": "4" * 64,
        "manifest_genesis_seal_sha256": "5" * 64,
        "manifest_head_seal_sha256": "6" * 64,
        "manifest_head_commit_seal_sha256": "7" * 64,
        "pit_cutoff_at": format_utc(
            datetime.fromisoformat(source["cutoff_at"]),
            "test PIT cutoff",
        ),
        "research_as_of_official_day": source[
            "research_as_of_official_day"
        ],
        "execution_day": source["execution_day"],
        "source_view_canonical_sha256": (
            produced.source_view_canonical_sha256
        ),
    }
    lineage_raw = canonical_json_line(lineage)
    lineage_path = _private_file(tmp_path / "lineage.json", lineage_raw)
    private = Ed25519PrivateKey.generate()
    private_path = _private_file(
        tmp_path / "export-private.key",
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    keyring = {
        "schema_version": KEYRING_SCHEMA,
        "keyring_id": "sealed-export-test-v1",
        "purpose": SIGNING_PURPOSE,
        "keys": [
            {
                "key_id": "sealed-export-key-v1",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(public_raw).decode(),
                "public_key_sha256": public_key_sha256(private.public_key()),
                "enabled": True,
            }
        ],
    }
    keyring_raw = canonical_json_line(keyring)
    keyring_path = _private_file(tmp_path / "keyring.json", keyring_raw)
    export_root = tmp_path / "exports"
    export_root.mkdir(mode=0o700)
    return {
        "artifact_paths": artifact_paths,
        "source_view_path": source_view_path,
        "lineage": lineage,
        "lineage_path": lineage_path,
        "lineage_raw": lineage_raw,
        "private_path": private_path,
        "keyring_path": keyring_path,
        "keyring_raw": keyring_raw,
        "export_root": export_root,
        "produced": produced,
    }


def create_export(tmp_path: Path):
    values = export_inputs(tmp_path)
    verified = create_sealed_export(
        artifact_paths=values["artifact_paths"],
        source_view_path=values["source_view_path"],
        lineage_path=values["lineage_path"],
        expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
        keyring_path=values["keyring_path"],
        expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
        signer_key_id="sealed-export-key-v1",
        private_key_path=values["private_path"],
        export_root=values["export_root"],
        now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
    )
    return values, verified


def test_create_verify_and_schema_contracts(tmp_path: Path) -> None:
    values, verified = create_export(tmp_path)
    assert verified.artifact_raw == values["produced"].artifacts
    assert set(verified.lineage) == {
        "registry_raw_sha256",
        "calendar_raw_sha256",
        "calendar_anchor_sha256",
        "commit_anchor_ledger_sha256",
        "manifest_genesis_seal_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
        "pit_cutoff_at",
        "research_as_of_official_day",
        "execution_day",
        "source_view_canonical_sha256",
    }
    keyring_schema = json.loads(KEYRING_SCHEMA_PATH.read_bytes())
    manifest_schema = json.loads(MANIFEST_SCHEMA.read_bytes())
    receipt_schema = json.loads(RECEIPT_SCHEMA.read_bytes())
    for schema in (keyring_schema, manifest_schema, receipt_schema):
        Draft202012Validator.check_schema(schema)
    Draft202012Validator(keyring_schema).validate(
        json.loads(values["keyring_raw"])
    )
    Draft202012Validator(
        manifest_schema,
        format_checker=FormatChecker(),
    ).validate(
        json.loads(
            (verified.output / "sealed-export-manifest.json").read_bytes()
        )
    )
    Draft202012Validator(
        receipt_schema,
        format_checker=FormatChecker(),
    ).validate(
        json.loads(
            (verified.output / "sealed-export-receipt.json").read_bytes()
        )
    )
    assert bundle.artifact_bindings(verified.artifact_raw) == {
        role: {
            "bytes": len(raw),
            "raw_sha256": sha256(raw),
        }
        for role, raw in verified.artifact_raw.items()
    }


def test_create_only_and_late_source_revision_do_not_rewrite_export(
    tmp_path: Path,
) -> None:
    values, verified = create_export(tmp_path)
    original = dict(verified.artifact_raw)
    target = values["artifact_paths"]["signal_evidence"]
    target.write_bytes(b'{"late":"revision"}')
    target.chmod(0o600)
    repeated = verify_sealed_export(
        output=verified.output,
        keyring_path=values["keyring_path"],
        expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
        expected_receipt_raw_sha256=verified.receipt_raw_sha256,
    )
    assert repeated.artifact_raw == original
    with pytest.raises(RegistryError, match="overwrite forbidden"):
        create_sealed_export(
            artifact_paths={
                **values["artifact_paths"],
                "signal_evidence": verified.output / "signal_evidence.json",
            },
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )


def test_tamper_splice_and_unpinned_receipt_fail_closed(tmp_path: Path) -> None:
    values, verified = create_export(tmp_path)
    target = verified.output / "target_evidence.json"
    target.write_bytes(b'{"tampered":true}')
    target.chmod(0o600)
    with pytest.raises(RegistryError):
        verify_sealed_export(
            output=verified.output,
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            expected_receipt_raw_sha256=verified.receipt_raw_sha256,
        )
    with pytest.raises(RegistryError, match="receipt hash mismatch"):
        verify_sealed_export(
            output=verified.output,
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            expected_receipt_raw_sha256="f" * 64,
        )


def test_pinned_but_invalid_receipt_signature_fails_closed(
    tmp_path: Path,
) -> None:
    values, verified = create_export(tmp_path)
    path = verified.output / "sealed-export-receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt["signature"] = base64.b64encode(bytes(64)).decode()
    raw = canonical_json_line(receipt)
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(RegistryError, match="signature"):
        verify_sealed_export(
            output=verified.output,
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            expected_receipt_raw_sha256=sha256(raw),
        )


def test_source_splice_and_future_lineage_fail_before_signing(tmp_path: Path) -> None:
    values = export_inputs(tmp_path)
    signal = values["artifact_paths"]["signal_evidence"]
    payload = json.loads(signal.read_bytes())
    payload["source_view_canonical_sha256"] = "f" * 64
    signal.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    signal.chmod(0o600)
    with pytest.raises(RegistryError, match="common lineage mismatch"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    values = export_inputs(tmp_path / "future")
    lineage = dict(values["lineage"])
    lineage["pit_cutoff_at"] = "2026-08-03T01:46:00.000000Z"
    raw = canonical_json_line(lineage)
    _private_file(values["lineage_path"], raw)
    with pytest.raises(RegistryError, match="PIT/date lineage mismatch"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(raw),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )


def test_missing_duplicate_inode_symlink_and_wrong_signer_fail_closed(
    tmp_path: Path,
) -> None:
    values = export_inputs(tmp_path)
    missing = dict(values["artifact_paths"])
    missing.pop("signal_evidence")
    with pytest.raises(RegistryError, match="role order/set"):
        create_sealed_export(
            artifact_paths=missing,
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    duplicate = dict(values["artifact_paths"])
    duplicate["signal_evidence"] = duplicate["freeze_contract"]
    with pytest.raises(RegistryError, match="distinct inodes"):
        create_sealed_export(
            artifact_paths=duplicate,
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    symlink = tmp_path / "lineage-link.json"
    symlink.symlink_to(values["lineage_path"])
    with pytest.raises(RegistryError, match="symlink-free"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=symlink,
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    wrong = Ed25519PrivateKey.generate()
    wrong_path = _private_file(
        tmp_path / "wrong.key",
        wrong.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
    )
    with pytest.raises(RegistryError, match="private key is not trusted"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=wrong_path,
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )


def test_consistent_artifact_forgery_fails_exact_producer_replay(
    tmp_path: Path,
) -> None:
    values = export_inputs(tmp_path)
    forged_contract = "SHFE.ag9999"
    row_fields = {
        "target_evidence": ("targets", "exact_contract"),
        "signal_evidence": ("signals", "pit_main_exact_contract"),
        "daily_roll_evidence": ("rows", "pit_main_exact_contract"),
        "reference_price_evidence": ("rows", "exact_contract"),
        "contract_spec_evidence": ("rows", "exact_contract"),
    }
    for role, (rows_field, contract_field) in row_fields.items():
        path = values["artifact_paths"][role]
        payload = json.loads(path.read_bytes())
        row = next(item for item in payload[rows_field] if item["product"] == "ag")
        row[contract_field] = forged_contract
        if role == "target_evidence":
            row["target_quantity"] = "not-an-integer"
        _private_file(
            path,
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
        )
    allocation = values["artifact_paths"]["allocation_evidence"]
    payload = json.loads(allocation.read_bytes())
    payload["quantities"]["ag"] = "not-an-integer"
    _private_file(
        allocation,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )
    with pytest.raises(RegistryError, match="exact #163 replay"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )


def test_root_and_output_directory_replacement_races_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = export_inputs(tmp_path / "root-race")
    original_open_bound = custody._open_bound_directory
    raced = False

    def replace_root(path, label, *, expected_identity=None):
        nonlocal raced
        if label == "sealed export root" and not raced:
            raced = True
            displaced = path.with_name(path.name + "-displaced")
            path.rename(displaced)
            path.mkdir(mode=0o700)
        return original_open_bound(
            path,
            label,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(custody, "_open_bound_directory", replace_root)
    with pytest.raises(RegistryError, match="changed while being opened"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    assert not list(values["export_root"].glob("*/sealed-export-receipt.json"))

    monkeypatch.setattr(custody, "_open_bound_directory", original_open_bound)
    values = export_inputs(tmp_path / "output-race")
    original_os_open = custody.os.open
    output_raced = False

    def replace_output(path, flags, *args, **kwargs):
        nonlocal output_raced
        if (
            not output_raced
            and isinstance(path, str)
            and path.startswith("sealed-export-")
            and flags & getattr(custody.os, "O_DIRECTORY", 0)
        ):
            output_raced = True
            output = values["export_root"] / path
            output.rename(values["export_root"] / "displaced-output")
            output.mkdir(mode=0o700)
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(custody.os, "open", replace_output)
    with pytest.raises(RegistryError, match="changed while being opened"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    assert not list(values["export_root"].glob("*/sealed-export-receipt.json"))


def test_source_inode_reuse_after_precheck_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = export_inputs(tmp_path)
    original_os_open = custody.os.open
    freeze = values["artifact_paths"]["freeze_contract"]
    signal = values["artifact_paths"]["signal_evidence"]
    raced = False

    def reuse_first_inode(path, flags, *args, **kwargs):
        nonlocal raced
        if not raced and Path(path) == signal:
            raced = True
            signal.rename(signal.with_suffix(".displaced"))
            freeze.rename(signal)
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(custody.os, "open", reuse_first_inode)
    with pytest.raises(RegistryError, match="changed while being opened"):
        create_sealed_export(
            artifact_paths=values["artifact_paths"],
            source_view_path=values["source_view_path"],
            lineage_path=values["lineage_path"],
            expected_lineage_raw_sha256=sha256(values["lineage_raw"]),
            keyring_path=values["keyring_path"],
            expected_keyring_raw_sha256=sha256(values["keyring_raw"]),
            signer_key_id="sealed-export-key-v1",
            private_key_path=values["private_path"],
            export_root=values["export_root"],
            now=datetime(2026, 8, 3, 2, 5, tzinfo=UTC),
        )
    assert not list(values["export_root"].glob("*/sealed-export-receipt.json"))


def test_consumer_layer_has_no_warehouse_db_or_execution_imports() -> None:
    paths = [
        ROOT / "scripts/research_warehouse/sealed_export.py",
        ROOT / "scripts/research_warehouse/sealed_export_contracts.py",
        ROOT / "scripts/research_warehouse/sealed_export_crypto.py",
        ROOT / "scripts/research_warehouse/sealed_export_custody.py",
    ]
    forbidden = {
        "duckdb",
        "sqlalchemy",
        "app",
        "vnpy",
        "rpc",
        "trade_service",
        "settings",
    }
    for path in paths:
        tree = ast.parse(path.read_text())
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden)
