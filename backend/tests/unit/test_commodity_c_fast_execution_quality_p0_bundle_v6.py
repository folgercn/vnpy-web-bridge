from __future__ import annotations

import base64
from dataclasses import replace
from datetime import timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_execution_quality_p0_bundle_v6 as subject  # noqa: E402
import commodity_c_fast_execution_quality_sign_runtime_artifact as signer  # noqa: E402
import commodity_c_fast_t1_query_v6_authority as authority  # noqa: E402
import commodity_c_fast_t1_query_v6_executable as executable  # noqa: E402
import commodity_c_fast_t1_query_v6_executable_sign as executable_signer  # noqa: E402
import commodity_c_fast_t1_query_v6_runtime as runtime  # noqa: E402
import commodity_c_fast_t1_query_v6_sign as foundation_signer  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AUTH = _load(
    "p0_bundle_v6_authority_helpers",
    ROOT / "backend/tests/unit/test_commodity_c_fast_t1_query_v6_authority.py",
)
EXEC = _load(
    "p0_bundle_v6_executable_helpers",
    ROOT / "backend/tests/unit/test_commodity_c_fast_t1_query_v6_executable_runtime.py",
)
PRODUCTION = _load(
    "p0_bundle_v6_production_helpers",
    ROOT
    / "backend/tests/unit/"
    "test_commodity_c_fast_execution_quality_production_verifier.py",
)


def _write_production_json(
    path: Path,
    payload: dict,
    schema: Path,
    label: str,
) -> bytes:
    PRODUCTION.ONE_SHOT.write_json_create_only(path, payload, schema, label)
    path.chmod(0o600)
    return path.read_bytes()


def _bundle_fixture(tmp_path: Path) -> tuple[subject.P0BundleV6Paths, dict]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    _, production_paths, _ = PRODUCTION.generation(evidence_root)
    p0 = json.loads(production_paths["signed_p0_acceptance"].read_text())
    audit = json.loads(
        base64.b64decode(p0["audit_exact_json_base64"], validate=True)
    )
    proof = json.loads(
        base64.b64decode(p0["readonly_proof_exact_json_base64"], validate=True)
    )
    terminal = json.loads(
        base64.b64decode(p0["terminal_exact_json_base64"], validate=True)
    )
    manifest_payload = json.loads((evidence_root / "manifest.json").read_text())

    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir(mode=0o700)
    manifest_path = bundle_root / "manifest.json"
    manifest_raw = _write_production_json(
        manifest_path,
        manifest_payload,
        authority.QUERY_MANIFEST_SCHEMA_PATH,
        "query-v6 P0 manifest",
    )
    manifest_artifact = authority.JsonArtifact(
        payload=manifest_payload,
        raw_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        canonical_sha256=hashlib.sha256(
            authority.canonical_json(manifest_payload)
        ).hexdigest(),
    )

    now = PRODUCTION.NOW
    authority_key = Ed25519PrivateKey.generate()
    authority_keyring = AUTH._keyring(authority_key)
    provenance = AUTH._provenance()
    base_evidence = AUTH._evidence()
    readiness_payload = {
        **base_evidence.readiness.payload,
        "generated_at": (now - timedelta(minutes=3)).isoformat(),
        "expires_at": (now + timedelta(minutes=20)).isoformat(),
    }
    readiness = authority.JsonArtifact(
        payload=readiness_payload,
        raw_sha256=hashlib.sha256(b"exact readiness raw").hexdigest(),
        canonical_sha256=hashlib.sha256(
            authority.canonical_json(readiness_payload)
        ).hexdigest(),
    )
    foundation_evidence = replace(
        base_evidence,
        readiness=readiness,
        query_manifest=manifest_artifact,
    )
    foundation_draft = AUTH._draft()
    foundation_draft.update(
        {
            "issued_at": (now - timedelta(minutes=3)).isoformat(),
            "not_before": (now - timedelta(minutes=2, seconds=59)).isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
        }
    )
    authority_keyring_hash = hashlib.sha256(
        authority.canonical_json(authority_keyring)
    ).hexdigest()
    foundation_payload = foundation_signer.sign_release(
        foundation_draft,
        authority_keyring,
        provenance,
        frozenset({AUTH._sha(b"different-provenance-key")}),
        foundation_evidence,
        authority_key,
        expected_keyring_sha256=authority_keyring_hash,
        now=now,
    )
    foundation_path = bundle_root / "foundation.json"
    foundation_keyring_path = bundle_root / "foundation-keyring.json"
    _write_production_json(
        foundation_keyring_path,
        authority_keyring,
        authority.KEYRING_SCHEMA_PATH,
        "query-v6 foundation keyring",
    )
    _write_production_json(
        foundation_path,
        foundation_payload,
        authority.RELEASE_SCHEMA_PATH,
        "query-v6 foundation release",
    )
    verified_foundation = authority.verify_release(
        foundation_path,
        foundation_keyring_path,
        provenance,
        frozenset({AUTH._sha(b"different-provenance-key")}),
        foundation_evidence,
        expected_release_keyring_sha256=authority_keyring_hash,
        now=now,
    )

    executable_key = Ed25519PrivateKey.generate()
    executable_keyring = EXEC._keyring(executable_key, executable=True)
    pins = EXEC._pins(executable_keyring, b"pinned adapter bytes")
    executable_draft = EXEC._draft()
    executable_draft.update(
        {
            "issued_at": (now - timedelta(minutes=2, seconds=55)).isoformat(),
            "not_before": (now - timedelta(minutes=2, seconds=54)).isoformat(),
            "expires_at": (now + timedelta(minutes=1)).isoformat(),
        }
    )
    executable_payload = executable_signer.sign_release(
        executable_draft,
        executable_keyring,
        foundation_keyring_path,
        verified_foundation,
        pins,
        executable_key,
        now=now,
    )
    executable_path = bundle_root / "executable.json"
    executable_keyring_path = bundle_root / "executable-keyring.json"
    pin_path = bundle_root / "pin-set.json"
    _write_production_json(
        executable_keyring_path,
        executable_keyring,
        executable.KEYRING_SCHEMA_PATH,
        "query-v6 executable keyring",
    )
    _write_production_json(
        pin_path,
        pins.payload,
        executable.PIN_SET_SCHEMA_PATH,
        "query-v6 active pin set",
    )
    _write_production_json(
        executable_path,
        executable_payload,
        executable.RELEASE_SCHEMA_PATH,
        "query-v6 executable release",
    )
    verified_executable = executable.verify_release(
        executable_path,
        executable_keyring_path,
        foundation_keyring_path,
        verified_foundation,
        pins,
        now=now,
    )

    consumed_at = now - timedelta(minutes=2, seconds=50)
    consume = runtime._consume_payload(verified_executable, consumed_at)
    consume_path = bundle_root / "consume.json"
    consume_raw = _write_production_json(
        consume_path,
        consume,
        executable.CONSUME_SCHEMA_PATH,
        "query-v6 consume",
    )
    consume_raw_sha = hashlib.sha256(consume_raw).hexdigest()
    consume_canonical_sha = hashlib.sha256(runtime.canonical_json(consume)).hexdigest()
    launch = {
        "schema_version": "commodity_c_fast_t1_query_child_launched_v6",
        "purpose": "c_fast_t1_query_v6_one_shot_launch_claim",
        "candidate_id": executable.CANDIDATE_ID,
        "release_id": executable_payload["release_id"],
        "attempt_id": executable_payload["attempt_id"],
        "claimed_at": (now - timedelta(minutes=2, seconds=35)).isoformat(),
        "consume_marker_raw_sha256": consume_raw_sha,
        "consume_marker_canonical_sha256": consume_canonical_sha,
        "executable_release_raw_sha256": verified_executable.raw_sha256,
        "foundation_raw_sha256": verified_foundation.raw_sha256,
        "pin_set_manifest_sha256": pins.canonical_sha256,
        "execution_adapter_sha256": pins.execution_adapter_sha256,
        "adapter_package_manifest_sha256": "1" * 64,
        "adapter_package_root_identity_sha256": "2" * 64,
        "python_executable_sha256": "3" * 64,
        "python_dependency_closure_sha256": "4" * 64,
        "invocation_binding_sha256": "5" * 64,
        "launch_capability_sha256": "6" * 64,
        "consume_verified_before_claim": True,
        "final_revalidation_completed_before_claim": True,
        "launch_claimed": True,
        "dsn_secret_read": False,
        "network_attempted": False,
        "production_query_attempted": False,
        "launch_marker_is_authority": False,
        "database_mutation_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "replay_allowed": False,
    }
    launch_path = bundle_root / "launch.json"
    launch_path.write_text(
        json.dumps(launch, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    launch_path.chmod(0o600)

    audit_path = bundle_root / "audit.json"
    proof_path = bundle_root / "readonly-proof.json"
    audit_raw = _write_production_json(
        audit_path,
        audit,
        executable.AUDIT_EVIDENCE_SCHEMA_PATH,
        "query-v6 audit",
    )
    proof["audit_evidence_sha256"] = hashlib.sha256(audit_raw).hexdigest()
    proof_path_raw = _write_production_json(
        proof_path,
        proof,
        executable.READONLY_PROOF_SCHEMA_PATH,
        "query-v6 readonly proof",
    )
    csv_path = bundle_root / "audit.csv"
    markdown_path = bundle_root / "audit.md"
    csv_path.write_bytes(b"product,classification\nag,L5_USABLE\n")
    markdown_path.write_bytes(b"# exact query-v6 audit\n")
    csv_path.chmod(0o600)
    markdown_path.chmod(0o600)

    terminal.update(
        {
            "release_id": executable_payload["release_id"],
            "attempt_id": executable_payload["attempt_id"],
            "started_at": consumed_at.isoformat(),
            "final_revalidation_at": (
                now - timedelta(minutes=2, seconds=40)
            ).isoformat(),
            "ended_at": (now - timedelta(minutes=1, seconds=50)).isoformat(),
            "executable_release_raw_sha256": verified_executable.raw_sha256,
            "executable_release_canonical_sha256": (
                verified_executable.canonical_sha256
            ),
            "foundation_raw_sha256": verified_foundation.raw_sha256,
            "foundation_canonical_sha256": verified_foundation.canonical_sha256,
            "consume_marker_raw_sha256": consume_raw_sha,
            "consume_marker_canonical_sha256": consume_canonical_sha,
            "execution_adapter_sha256": pins.execution_adapter_sha256,
            "artifact_sha256": {
                "audit_json": hashlib.sha256(audit_raw).hexdigest(),
                "audit_csv": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
                "audit_markdown": hashlib.sha256(
                    markdown_path.read_bytes()
                ).hexdigest(),
                "readonly_proof": hashlib.sha256(proof_path_raw).hexdigest(),
            },
        }
    )
    terminal_path = bundle_root / "terminal.json"
    _write_production_json(
        terminal_path,
        terminal,
        executable.TERMINAL_SCHEMA_PATH,
        "query-v6 terminal",
    )
    external_identity = {
        "schema_version": "commodity_c_fast_p0_external_custody_identity_v1",
        "custody_id": "query-v6-external-custody-v1",
        "asserted_archive_type": "ASSERTED_APPEND_ONLY",
        "archive_locator_sha256": "9" * 64,
        "independent_from_t1_runner": True,
        "immutability_asserted": True,
    }
    external_path = bundle_root / "external-custody.json"
    external_path.write_text(
        json.dumps(external_identity, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    external_path.chmod(0o600)
    paths = subject.P0BundleV6Paths(
        foundation_release=foundation_path,
        foundation_keyring=foundation_keyring_path,
        executable_release=executable_path,
        executable_keyring=executable_keyring_path,
        active_pin_set=pin_path,
        manifest=manifest_path,
        consume_marker=consume_path,
        launch_marker=launch_path,
        terminal=terminal_path,
        audit_json=audit_path,
        audit_csv=csv_path,
        audit_markdown=markdown_path,
        readonly_proof=proof_path,
        external_custody_identity=external_path,
    )
    return paths, {"now": now, "terminal": terminal}


def test_builder_replays_full_bundle_and_writes_unsigned_pretty_draft(
    tmp_path: Path,
) -> None:
    paths, fixture = _bundle_fixture(tmp_path)
    now = fixture["now"]
    draft = subject.build_unsigned_p0_draft(
        paths,
        generation_id=None,
        issued_at=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=5),
        archived_at=now - timedelta(minutes=1, seconds=30),
        signer_key_id="signed-p0-acceptance-key-v1",
        reviewer_role="independent query-v6 P0 reviewer",
        human_signature="reviewed exact query-v6 bundle and external custody",
    )
    output_root = tmp_path / "output"
    output_root.mkdir(mode=0o700)
    output = output_root / "unsigned-p0.json"

    subject.write_unsigned_p0_draft(output, draft)

    assert "signature" not in draft
    assert draft["bundle_raw_sha256"]["terminal"] == hashlib.sha256(
        paths.terminal.read_bytes()
    ).hexdigest()
    assert output.read_text().startswith("{\n")
    assert output.read_text().endswith("\n")
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        subject.write_unsigned_p0_draft(output, draft)


def test_bundle_splice_is_rejected_before_draft(tmp_path: Path) -> None:
    paths, fixture = _bundle_fixture(tmp_path)
    terminal = json.loads(paths.terminal.read_text())
    terminal["consume_marker_raw_sha256"] = "f" * 64
    paths.terminal.unlink()
    _write_production_json(
        paths.terminal,
        terminal,
        executable.TERMINAL_SCHEMA_PATH,
        "tampered query-v6 terminal",
    )

    with pytest.raises(subject.P0BundleV6Error, match="terminal consume raw"):
        subject.build_unsigned_p0_draft(
            paths,
            generation_id="query-v6-p0-tamper-test",
            issued_at=fixture["now"] - timedelta(minutes=1),
            valid_until=fixture["now"] + timedelta(minutes=5),
            archived_at=fixture["now"] - timedelta(minutes=1, seconds=30),
            signer_key_id="signed-p0-acceptance-key-v1",
            reviewer_role="independent reviewer",
            human_signature="reviewed exact evidence",
        )


def test_whole_bundle_second_read_detects_cross_file_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _ = _bundle_fixture(tmp_path)
    original = subject._read_bundle_once
    calls = 0

    def drifting_read(bundle_paths: subject.P0BundleV6Paths) -> dict[str, bytes]:
        nonlocal calls
        calls += 1
        observed = original(bundle_paths)
        if calls == 2:
            observed = {**observed, "audit_csv": observed["audit_csv"] + b"drift"}
        return observed

    monkeypatch.setattr(subject, "_read_bundle_once", drifting_read)

    with pytest.raises(subject.P0BundleV6Error, match="changed during stable re-read"):
        subject.load_exact_bundle(paths)


def test_release_signature_tamper_is_rejected(tmp_path: Path) -> None:
    paths, fixture = _bundle_fixture(tmp_path)
    release = json.loads(paths.foundation_release.read_text())
    release["human_signature"] = "tampered after foundation signature"
    paths.foundation_release.unlink()
    _write_production_json(
        paths.foundation_release,
        release,
        authority.RELEASE_SCHEMA_PATH,
        "tampered query-v6 foundation release",
    )

    with pytest.raises(subject.P0BundleV6Error, match="signature is invalid"):
        subject.build_unsigned_p0_draft(
            paths,
            generation_id="query-v6-p0-signature-tamper",
            issued_at=fixture["now"] - timedelta(minutes=1),
            valid_until=fixture["now"] + timedelta(minutes=5),
            archived_at=fixture["now"] - timedelta(minutes=1, seconds=30),
            signer_key_id="signed-p0-acceptance-key-v1",
            reviewer_role="independent reviewer",
            human_signature="reviewed exact evidence",
        )


def _write_private_canonical_json(path: Path, payload: dict) -> bytes:
    raw = subject.canonical_json(payload) + b"\n"
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _p0_signer_fixture(root: Path):
    paths, fixture = _bundle_fixture(root)
    now = fixture["now"]
    private = Ed25519PrivateKey.generate()
    key_id = "signed-p0-acceptance-key-v1"
    draft = subject.build_unsigned_p0_draft(
        paths,
        generation_id=None,
        issued_at=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=5),
        archived_at=now - timedelta(minutes=1, seconds=30),
        signer_key_id=key_id,
        reviewer_role="independent query-v6 P0 reviewer",
        human_signature="reviewed exact query-v6 bundle and external custody",
    )
    draft_path = root / "unsigned-p0.json"
    _write_private_canonical_json(draft_path, draft)
    keyring = {
        "schema_version": (
            "commodity_c_fast_execution_quality_role_trusted_keys_v1"
        ),
        "artifact_role": "signed_p0_acceptance",
        "trusted_keys": [
            {
                "key_id": key_id,
                "purpose": (
                    "c_fast_execution_quality_query_v6_p0_acceptance_signer"
                ),
                "public_key_base64": base64.b64encode(
                    private.public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                ).decode(),
            }
        ],
    }
    keyring_path = root / "p0-keyring.json"
    keyring_raw = _write_private_canonical_json(keyring_path, keyring)
    private_path = root / "p0-private.key"
    private_path.write_bytes(
        base64.b64encode(
            private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        + b"\n"
    )
    private_path.chmod(0o600)
    args = SimpleNamespace(
        input=draft_path,
        output=root / "signed-p0.json",
        private_key_file=private_path,
        role_keyring=keyring_path,
        expected_role_keyring_raw_sha256=hashlib.sha256(keyring_raw).hexdigest(),
        **{
            role: getattr(paths, role)
            for role in signer.P0_QUERY_V6_BUNDLE_FILE_ORDER
        },
    )
    return paths, draft, args


def _replace_draft(root: Path, args: SimpleNamespace, draft: dict) -> None:
    args.input.unlink()
    _write_private_canonical_json(root / "unsigned-p0.json", draft)


def _bundle_index_sha256(draft: dict) -> str:
    index = {
        "schema_version": (
            "commodity_c_fast_execution_quality_p0_bundle_index_v6_v1"
        ),
        "files": [
            {
                "name": role,
                "size_bytes": draft["bundle_size_bytes"][role],
                "raw_sha256": draft["bundle_raw_sha256"][role],
                "canonical_sha256": draft["bundle_canonical_sha256"][role],
            }
            for role in signer.P0_QUERY_V6_BUNDLE_FILE_ORDER
        ],
    }
    return hashlib.sha256(subject.canonical_json(index)).hexdigest()


def test_p0_signer_reconstructs_all_exact_bundle_roles_before_key_access(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, _draft, args = _p0_signer_fixture(secure_tmp_path)
    monkeypatch.setattr(signer, "parse_args", lambda: args)

    assert signer.main() == 0
    assert json.loads(args.output.read_text())["artifact_role"] == (
        "signed_p0_acceptance"
    )


def test_p0_signer_rejects_self_consistent_unembedded_bundle_replacement(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _paths, draft, args = _p0_signer_fixture(secure_tmp_path)
    attacker_raw = subject.canonical_json({"attacker": "foundation-keyring"}) + b"\n"
    role = "foundation_keyring"
    draft["bundle_raw_sha256"][role] = hashlib.sha256(attacker_raw).hexdigest()
    draft["bundle_canonical_sha256"][role] = hashlib.sha256(
        subject.canonical_json({"attacker": "foundation-keyring"})
    ).hexdigest()
    draft["bundle_size_bytes"][role] = len(attacker_raw)
    draft["bundle_index_sha256"] = _bundle_index_sha256(draft)
    draft["external_archive"]["archived_bundle_index_sha256"] = draft[
        "bundle_index_sha256"
    ]
    _replace_draft(secure_tmp_path, args, draft)
    key_opened = False

    def reject_key_access(_path: Path):
        nonlocal key_opened
        key_opened = True
        raise AssertionError("private key must remain unopened")

    monkeypatch.setattr(signer, "load_private_key", reject_key_access)
    monkeypatch.setattr(signer, "parse_args", lambda: args)

    assert signer.main() == 2
    assert key_opened is False
    assert "does not exactly match reconstructed" in capsys.readouterr().err
    assert not args.output.exists()


def test_p0_signer_rejects_exact_original_tamper_before_key_access(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _draft, args = _p0_signer_fixture(secure_tmp_path)
    paths.audit_csv.write_bytes(paths.audit_csv.read_bytes() + b"tamper\n")
    key_opened = False

    def reject_key_access(_path: Path):
        nonlocal key_opened
        key_opened = True
        raise AssertionError("private key must remain unopened")

    monkeypatch.setattr(signer, "load_private_key", reject_key_access)
    monkeypatch.setattr(signer, "parse_args", lambda: args)

    assert signer.main() == 2
    assert key_opened is False
    assert not args.output.exists()


def test_p0_signer_cli_rejects_missing_bundle_paths_before_key_access(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _paths, _draft, args = _p0_signer_fixture(secure_tmp_path)
    args.audit_markdown = None
    key_opened = False

    def reject_key_access(_path: Path):
        nonlocal key_opened
        key_opened = True
        raise AssertionError("private key must remain unopened")

    monkeypatch.setattr(signer, "load_private_key", reject_key_access)
    monkeypatch.setattr(signer, "parse_args", lambda: args)

    assert signer.main() == 2
    assert key_opened is False
    assert "requires all exact query-v6 bundle paths" in capsys.readouterr().err
    assert not args.output.exists()
