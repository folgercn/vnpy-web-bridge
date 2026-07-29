from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import commodity_c_fast_t1_query_child_v4 as child
import commodity_c_fast_t1_query_v4 as query
import commodity_c_fast_l1_l5_audit_v4 as audit
import commodity_c_fast_t1_readiness_v3 as readiness_module
from commodity_c_fast_t1_readiness_v3 import VerifiedReadinessPacket


ROOT = Path(__file__).resolve().parents[3]


def _readiness(schema_version: str) -> VerifiedReadinessPacket:
    return VerifiedReadinessPacket(
        payload={
            "schema_version": schema_version,
            "status": "READY_FOR_QUERY_RELEASE_V4_HUMAN_SIGNATURE_ONLY",
            "ready_for_query_release_v4_human_signature_only": True,
            "requirements": {
                "requires_query_release_v4": True,
                "query_release_v3_accepted": False,
                "readiness_v2_accepted": False,
            },
        },
        raw_sha256="a" * 64,
        canonical_sha256="b" * 64,
    )


def _minimal_release() -> dict[str, object]:
    return {
        "schema_version": query.RELEASE_SCHEMA_VERSION,
        "purpose": query.RELEASE_PURPOSE,
        "candidate_id": query.CANDIDATE_ID,
    }


def _semantic_readiness(
    custody_identity_sha256: str,
) -> VerifiedReadinessPacket:
    return VerifiedReadinessPacket(
        payload={
            "schema_version": "commodity_c_fast_t1_readiness_v3",
            "status": "READY_FOR_QUERY_RELEASE_V4_HUMAN_SIGNATURE_ONLY",
            "ready_for_query_release_v4_human_signature_only": True,
            "requirements": {
                "requires_query_release_v4": True,
                "query_release_v3_accepted": False,
                "readiness_v2_accepted": False,
            },
            "generated_at": "2026-07-29T03:58:00+00:00",
            "expires_at": "2026-07-29T04:10:00+00:00",
            "packet_custody_identity_sha256": custody_identity_sha256,
        },
        raw_sha256="a" * 64,
        canonical_sha256="b" * 64,
    )


def _semantic_release(custody_identity_sha256: str) -> dict[str, object]:
    release_id = "query-v4-custody-contract-test"
    payload: dict[str, object] = {
        "schema_version": query.RELEASE_SCHEMA_VERSION,
        "purpose": query.RELEASE_PURPOSE,
        "candidate_id": query.CANDIDATE_ID,
        "release_id": release_id,
        "attempt_id": query.release_attempt_id(release_id),
        "human_signature": "human-reviewed-custody-contract",
        "reviewer_role": "release-reviewer",
        "issued_at": "2026-07-29T03:59:00+00:00",
        "not_before": "2026-07-29T03:59:00+00:00",
        "expires_at": "2026-07-29T04:05:00+00:00",
        "minimum_launch_margin_seconds": 1,
        "readiness": {},
        "custody_identity_sha256": custody_identity_sha256,
    }
    payload.update({field: True for field in query.TRUE_AUTHORITY_FIELDS})
    payload.update({field: False for field in query.FALSE_AUTHORITY_FIELDS})
    return payload


def _consume_for_identity(
    custody: Path,
    identity: dict[str, str],
) -> dict[str, object]:
    consume: dict[str, object] = {
        field: "a" * 64 if field.endswith("_sha256") else "value"
        for field in child.CONSUME_FIELDS
    }
    consume.update(
        {
            "schema_version": "commodity_c_fast_t1_query_consume_v4",
            "purpose": "c_fast_t1_query_v4_consume_before_final_revalidation",
            "candidate_id": query.CANDIDATE_ID,
            "release_id": "release-v4-test",
            "attempt_id": "attempt-" + "a" * 64,
            "release_raw_sha256": "b" * 64,
            "release_canonical_sha256": "c" * 64,
            "trusted_keyring_sha256": "d" * 64,
            "custody_identity_sha256": hashlib.sha256(
                child._canonical_json(identity)
            ).hexdigest(),
            "custody_path_sha256": hashlib.sha256(
                str(custody).encode("utf-8")
            ).hexdigest(),
            "consume_precedes_final_revalidation": True,
            "query_started": False,
            "production_queried": False,
            "consume_is_authority": False,
            "replay_allowed": False,
        }
    )
    return consume


def test_release_semantics_rejects_readiness_v2_before_authority_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(query, "validate_json_schema", lambda *_args: None)

    with pytest.raises(
        query.QueryV4Error,
        match="requires exact readiness-v3 without downgrade",
    ):
        query.validate_release_semantics(
            _minimal_release(),
            _readiness("commodity_c_fast_t1_readiness_v2"),
            now=datetime.now(timezone.utc),
        )


def test_release_semantics_rejects_release_v3_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(query, "validate_json_schema", lambda *_args: None)
    release = _minimal_release()
    release["schema_version"] = (
        "commodity_c_fast_t1_one_shot_query_release_v3"
    )

    with pytest.raises(query.QueryV4Error, match="identity is invalid"):
        query.validate_release_semantics(
            release,
            _readiness("commodity_c_fast_t1_readiness_v3"),
            now=datetime.now(timezone.utc),
        )


def test_release_custody_identity_must_equal_readiness_v3_packet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(query, "validate_json_schema", lambda *_args: None)
    monkeypatch.setattr(query, "_readiness_binding", lambda _packet: {})

    with pytest.raises(
        query.QueryV4Error,
        match="does not match readiness-v3",
    ):
        query.validate_release_semantics(
            _semantic_release("c" * 64),
            _semantic_readiness("d" * 64),
            now=datetime(2026, 7, 29, 4, 0, tzinfo=timezone.utc),
        )

    query.validate_release_semantics(
        _semantic_release("d" * 64),
        _semantic_readiness("d" * 64),
        now=datetime(2026, 7, 29, 4, 0, tzinfo=timezone.utc),
    )


def test_parent_custody_identity_accepts_only_readiness_v3_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = {
        "schema_version": query.READINESS_CUSTODY_IDENTITY_VERSION,
        "custody_id": "custody-v3-happy",
    }
    monkeypatch.setattr(
        query,
        "read_regular_file_at",
        lambda *_args: query.canonical_json(identity),
    )
    query._validate_readiness_v3_custody_identity(
        object(),
        query._hash(query.canonical_json(identity)),
    )

    legacy = {
        "schema_version": "commodity_c_fast_t1_custody_identity_v1",
        "custody_id": "custody-v3-happy",
    }
    monkeypatch.setattr(
        query,
        "read_regular_file_at",
        lambda *_args: query.canonical_json(legacy),
    )
    with pytest.raises(
        query.QueryV4Error,
        match="readiness-v3 custody identity",
    ):
        query._validate_readiness_v3_custody_identity(
            object(),
            query._hash(query.canonical_json(legacy)),
        )


def test_child_consume_identity_uses_same_readiness_v3_contract(
    tmp_path: Path,
) -> None:
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    custody = custody.resolve()
    identity = {
        "schema_version": child.READINESS_CUSTODY_IDENTITY_VERSION,
        "custody_id": "custody-v3-happy",
    }
    identity_path = custody / "custody-identity.json"
    identity_path.write_bytes(child._canonical_json(identity))
    identity_path.chmod(0o600)
    consume = _consume_for_identity(custody, identity)
    custody_fd = os.open(
        custody,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        child._validate_consume(
            consume,
            release_id="release-v4-test",
            attempt_id="attempt-" + "a" * 64,
            release_raw_sha256="b" * 64,
            release_canonical_sha256="c" * 64,
            consume_raw_sha256="e" * 64,
            consume_canonical_sha256="f" * 64,
            query_v4_keyring_sha256="d" * 64,
            custody=custody,
            custody_fd=custody_fd,
        )
        legacy = {
            "schema_version": "commodity_c_fast_t1_custody_identity_v1",
            "custody_id": "custody-v3-happy",
        }
        identity_path.write_bytes(child._canonical_json(legacy))
        legacy_consume = _consume_for_identity(custody, legacy)
        with pytest.raises(
            child.QueryChildError,
            match="custody identity binding is invalid",
        ):
            child._validate_consume(
                legacy_consume,
                release_id="release-v4-test",
                attempt_id="attempt-" + "a" * 64,
                release_raw_sha256="b" * 64,
                release_canonical_sha256="c" * 64,
                consume_raw_sha256="e" * 64,
                consume_canonical_sha256="f" * 64,
                query_v4_keyring_sha256="d" * 64,
                custody=custody,
                custody_fd=custody_fd,
            )
    finally:
        os.close(custody_fd)


def test_consume_v4_rejects_consume_v3_before_custody_access(
    tmp_path: Path,
) -> None:
    consume = {field: "x" for field in child.CONSUME_FIELDS}
    consume.update(
        {
            "schema_version": "commodity_c_fast_t1_query_consume_v3",
            "purpose": "c_fast_t1_query_v4_consume_before_final_revalidation",
            "candidate_id": query.CANDIDATE_ID,
            "release_id": "release-v4-test",
            "attempt_id": "attempt-" + "a" * 64,
            "release_raw_sha256": "a" * 64,
            "release_canonical_sha256": "b" * 64,
            "trusted_keyring_sha256": "c" * 64,
            "consume_precedes_final_revalidation": True,
            "query_started": False,
            "production_queried": False,
            "consume_is_authority": False,
            "replay_allowed": False,
        }
    )

    with pytest.raises(child.QueryChildError, match="binding is invalid"):
        child._validate_consume(
            consume,
            release_id="release-v4-test",
            attempt_id="attempt-" + "a" * 64,
            release_raw_sha256="a" * 64,
            release_canonical_sha256="b" * 64,
            consume_raw_sha256="d" * 64,
            consume_canonical_sha256="e" * 64,
            query_v4_keyring_sha256="c" * 64,
            custody=tmp_path,
            custody_fd=-1,
        )


def test_v4_contract_schemas_pin_v4_and_readiness_v3() -> None:
    release_schema = json.loads(
        (
            ROOT
            / "docs/schemas/"
            "commodity-c-fast-t1-one-shot-query-release-v4.schema.json"
        ).read_text()
    )
    consume_schema = json.loads(
        (
            ROOT
            / "docs/schemas/"
            "commodity-c-fast-t1-query-consume-v4.schema.json"
        ).read_text()
    )
    assert release_schema["properties"]["schema_version"]["const"].endswith(
        "_v4"
    )
    assert release_schema["properties"]["issue_number"]["const"] == 139
    assert (
        release_schema["properties"]["readiness"]["properties"]["packet_id"][
            "pattern"
        ]
        == "^readiness-v3-[0-9a-f]{64}$"
    )
    assert (
        consume_schema["properties"]["readiness_packet_id"]["pattern"]
        == "^readiness-v3-[0-9a-f]{64}$"
    )


def test_v4_runtime_sources_have_no_downgrade_imports() -> None:
    sources = (
        ROOT / "scripts/commodity_c_fast_t1_query_v4.py",
        ROOT / "scripts/commodity_c_fast_t1_query_v4_sign_release.py",
        ROOT / "scripts/commodity_c_fast_t1_query_child_v4.py",
        ROOT / "scripts/commodity_c_fast_l1_l5_audit_v4.py",
    )
    combined = "\n".join(path.read_text() for path in sources)
    assert "from commodity_c_fast_t1_readiness_v2 import" not in combined
    assert "from commodity_c_fast_t1_release_v2_foundation import" not in combined
    assert "from commodity_c_fast_t1_build_registry_provenance import" not in combined
    assert "/run/c-fast-t1-readiness-v2-pins" not in combined


def test_audit_cli_cannot_omit_pre_connect_gate_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected = False

    def forbidden_connect(_path: Path) -> object:
        nonlocal connected
        connected = True
        raise AssertionError("connection must not be attempted")

    monkeypatch.setattr(audit, "connect_server_enforced_readonly", forbidden_connect)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(ROOT / "scripts/commodity_c_fast_l1_l5_audit_v4.py"),
            "--manifest",
            "/missing/manifest.json",
            "--dsn-file",
            "/missing/read-only.dsn",
            "--expected-endpoint-identity-sha256",
            "a" * 64,
            "--expected-manifest-sha256",
            "b" * 64,
        ],
    )

    with pytest.raises(SystemExit) as caught:
        audit.main()

    assert caught.value.code == 2
    assert connected is False


def test_same_path_custody_directory_replacement_fails_identity_gate(
    tmp_path: Path,
) -> None:
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    identity = {
        "schema_version": child.READINESS_CUSTODY_IDENTITY_VERSION,
        "custody_id": "custody-v3-test",
    }
    identity_path = custody / "custody-identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")
    identity_path.chmod(0o600)
    (
        _old_path,
        custody_id,
        custody_identity_sha256,
        custody_directory_identity_sha256,
    ) = child._read_readiness_custody_facts(custody)
    custody.rename(tmp_path / "custody-old")
    custody.mkdir(mode=0o700)
    identity_path = custody / "custody-identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")
    identity_path.chmod(0o600)

    with pytest.raises(
        child.QueryChildError,
        match="active custody changed",
    ):
        child._verify_readiness_custody_facts(
            custody,
            {
                "packet_custody_path": str(custody),
                "packet_custody_id": custody_id,
                "packet_custody_identity_sha256": custody_identity_sha256,
                "packet_custody_directory_identity_sha256": (
                    custody_directory_identity_sha256
                ),
                "evidence_join_identity_sha256": "f" * 64,
            },
        )


def test_malformed_child_launch_marker_is_detected_as_corrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(query, "custody_entry_exists", lambda *_args: True)
    monkeypatch.setattr(
        query,
        "read_regular_file_at",
        lambda *_args: b'{"schema_version":',
    )

    with pytest.raises(query.QueryV4Error):
        query._read_child_launch_marker(
            object(),
            "child-started.json",
            {},
            consume_raw_sha256="a" * 64,
            consume_canonical_sha256="b" * 64,
            query_child_invocation_raw_sha256="c" * 64,
            query_child_invocation_canonical_sha256="d" * 64,
            audit_child_invocation_raw_sha256="e" * 64,
            audit_child_invocation_canonical_sha256="f" * 64,
            pre_connect_gate_raw_sha256="1" * 64,
            pre_connect_gate_canonical_sha256="2" * 64,
            launch_capability=b"x" * child.LAUNCH_CAPABILITY_BYTES,
            parent_launch_capability_sha256=(
                child._launch_capability_sha256(
                    b"x" * child.LAUNCH_CAPABILITY_BYTES
                )
            ),
        )

    terminal_schema = json.loads(
        (
            ROOT
            / "docs/schemas/"
            "commodity-c-fast-t1-query-terminal-v4.schema.json"
        ).read_text()
    )
    assert (
        "CORRUPT_CHILD_LAUNCH_MARKER_OUTCOME_UNKNOWN"
        in terminal_schema["properties"]["terminal_state"]["enum"]
    )


def _put_capability_in_environment(
    monkeypatch: pytest.MonkeyPatch,
    capability: bytes,
) -> None:
    descriptor = child._launch_capability_pipe(capability)
    monkeypatch.setenv(child.LAUNCH_CAPABILITY_FD_ENV, str(descriptor))


def test_direct_bootstrap_without_parent_fd_blocks_before_launch_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv(child.LAUNCH_CAPABILITY_FD_ENV, raising=False)
    monkeypatch.setattr(child, "unblock_control_signals", lambda: None)
    monkeypatch.setattr(
        child,
        "parse_args",
        lambda: SimpleNamespace(audit_invocation=tmp_path / "unused"),
    )
    monkeypatch.setattr(
        child,
        "claim_query_child_launch",
        lambda *_args, **_kwargs: pytest.fail(
            "launch marker must not be written without the parent FD"
        ),
    )
    monkeypatch.setattr(
        child.os,
        "execve",
        lambda *_args, **_kwargs: pytest.fail(
            "audit/DSN process must not start without the parent FD"
        ),
    )

    assert child.main() == 78


def test_bootstrap_rejects_wrong_parent_fd_before_launch_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = b"a" * child.LAUNCH_CAPABILITY_BYTES
    wrong = b"b" * child.LAUNCH_CAPABILITY_BYTES
    _put_capability_in_environment(monkeypatch, wrong)
    monkeypatch.setattr(child, "unblock_control_signals", lambda: None)
    monkeypatch.setattr(
        child,
        "parse_args",
        lambda: SimpleNamespace(
            audit_invocation=tmp_path / "audit-invocation.json",
            expected_gate_raw_sha256="c" * 64,
            expected_gate_canonical_sha256="d" * 64,
        ),
    )
    monkeypatch.setattr(
        child,
        "_load_audit_invocation_with_raw",
        lambda _path: (b"[]", ["/python", "-I", "/audit"]),
    )
    monkeypatch.setattr(
        child,
        "verify_gate_binding",
        lambda *_args: {
            "parent_launch_capability_sha256": (
                child._launch_capability_sha256(expected)
            ),
            "query_child_invocation_path": str(tmp_path / "unused"),
        },
    )
    monkeypatch.setattr(
        child,
        "claim_query_child_launch",
        lambda *_args, **_kwargs: pytest.fail(
            "wrong parent FD must fail before marker creation"
        ),
    )
    monkeypatch.setattr(
        child.os,
        "execve",
        lambda *_args, **_kwargs: pytest.fail(
            "wrong parent FD must fail before audit/DSN"
        ),
    )

    assert child.main() == 78


def test_parent_capability_fd_is_one_shot_and_cannot_be_replayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = b"r" * child.LAUNCH_CAPABILITY_BYTES
    _put_capability_in_environment(monkeypatch, capability)

    assert child._read_launch_capability_from_environment() == capability
    with pytest.raises(
        child.QueryChildError,
        match="capability is unavailable",
    ):
        child._read_launch_capability_from_environment()


def test_launch_binding_rejects_gate_hash_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    custody = (tmp_path / "custody").resolve()
    custody.mkdir(mode=0o700)
    identity = {
        "schema_version": child.READINESS_CUSTODY_IDENTITY_VERSION,
        "custody_id": "custody-v3-binding-test",
    }
    identity_path = custody / "custody-identity.json"
    identity_path.write_bytes(child._canonical_json(identity))
    identity_path.chmod(0o600)
    consume = _consume_for_identity(custody, identity)
    consume_raw = child._canonical_json(consume)
    consume_raw_sha256 = hashlib.sha256(consume_raw).hexdigest()
    consume_canonical_sha256 = hashlib.sha256(
        child._canonical_json(consume)
    ).hexdigest()
    consume_path = (
        custody / f"{consume['attempt_id']}.query-consumed-v4.json"
    )
    consume_path.write_bytes(consume_raw)
    consume_path.chmod(0o600)
    query_invocation = [
        str(Path(sys.executable).resolve(strict=True)),
        "-I",
        str(Path(child.__file__).resolve(strict=True)),
        "--frozen",
        "value",
    ]
    query_invocation_path = tmp_path / "query-child-invocation.json"
    query_invocation_raw = child._canonical_json(query_invocation)
    query_invocation_path.write_bytes(query_invocation_raw)
    query_invocation_path.chmod(0o600)
    capability = b"c" * child.LAUNCH_CAPABILITY_BYTES
    parent_capability_sha256 = child._launch_capability_sha256(capability)
    hashes = {
        "query_child_invocation_raw_sha256": hashlib.sha256(
            query_invocation_raw
        ).hexdigest(),
        "query_child_invocation_canonical_sha256": hashlib.sha256(
            child._canonical_json(query_invocation)
        ).hexdigest(),
        "audit_child_invocation_raw_sha256": "d" * 64,
        "audit_child_invocation_canonical_sha256": "e" * 64,
        "pre_connect_gate_raw_sha256": "f" * 64,
        "pre_connect_gate_canonical_sha256": "1" * 64,
    }
    child.claim_query_child_launch(
        custody,
        release_id=str(consume["release_id"]),
        attempt_id=str(consume["attempt_id"]),
        release_raw_sha256=str(consume["release_raw_sha256"]),
        release_canonical_sha256=str(
            consume["release_canonical_sha256"]
        ),
        consume_raw_sha256=consume_raw_sha256,
        consume_canonical_sha256=consume_canonical_sha256,
        query_v4_keyring_sha256=str(consume["trusted_keyring_sha256"]),
        launch_capability=capability,
        parent_launch_capability_sha256=parent_capability_sha256,
        **hashes,
    )
    _put_capability_in_environment(monkeypatch, capability)

    with pytest.raises(
        child.QueryChildError,
        match="launch marker binding is invalid",
    ):
        child.verify_query_child_launch_capability(
            custody,
            release_id=str(consume["release_id"]),
            attempt_id=str(consume["attempt_id"]),
            release_raw_sha256=str(consume["release_raw_sha256"]),
            release_canonical_sha256=str(
                consume["release_canonical_sha256"]
            ),
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            query_v4_keyring_sha256=str(
                consume["trusted_keyring_sha256"]
            ),
            query_child_invocation_path=query_invocation_path,
            audit_child_invocation_raw_sha256=(
                hashes["audit_child_invocation_raw_sha256"]
            ),
            audit_child_invocation_canonical_sha256=(
                hashes["audit_child_invocation_canonical_sha256"]
            ),
            pre_connect_gate_raw_sha256="2" * 64,
            pre_connect_gate_canonical_sha256=(
                hashes["pre_connect_gate_canonical_sha256"]
            ),
            parent_launch_capability_sha256=parent_capability_sha256,
        )


def test_parent_runner_inherits_exact_capability_fd(tmp_path: Path) -> None:
    capability = b"p" * child.LAUNCH_CAPABILITY_BYTES
    code = (
        "import os;"
        f"fd=int(os.environ[{child.LAUNCH_CAPABILITY_FD_ENV!r}]);"
        "print(os.read(fd, 33).hex())"
    )

    result = query.run_query_child(
        [sys.executable, "-I", "-c", code],
        cwd=tmp_path,
        timeout=5,
        launch_capability=capability,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == capability.hex()


def _signed_audit_authority_inputs(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "schema_version": (
            "commodity_c_fast_t1_query_v4_trusted_keys_v1"
        ),
        "keys": [
            {
                "key_id": "query-v4-forged-release-test",
                "purpose": audit.QUERY_V4_KEY_PURPOSE,
                "public_key_base64": base64.b64encode(public_raw).decode(
                    "ascii"
                ),
            }
        ],
    }
    keyring_raw = child._canonical_json(keyring)
    keyring_path = tmp_path / "attacker-keyring.json"
    keyring_path.write_bytes(keyring_raw)
    keyring_path.chmod(0o600)
    keyring_sha256 = hashlib.sha256(keyring_raw).hexdigest()
    readiness = {
        "packet_id": "readiness-v3-" + "a" * 64,
        "generated_at": "2026-07-29T04:00:00+00:00",
        "expires_at": "2026-07-29T04:10:00+00:00",
        "packet_custody_identity_sha256": "b" * 64,
        "pin_root_path_sha256": "c" * 64,
        "source_namespaces": {"source": "exact"},
        "digest_namespaces": {"digest": "sha256"},
        "t1_runtime": {
            "content_attestation_raw_sha256": "d" * 64,
            "content_attestation_canonical_sha256": "e" * 64,
        },
        "build_registry_provenance": {
            "signed_provenance_raw_sha256": "f" * 64,
            "signed_provenance_canonical_sha256": "1" * 64,
            "signer_public_key_sha256": "2" * 64,
        },
        "readonly_deployment_outcome": {
            "signed_outcome_raw_sha256": "3" * 64,
            "signed_outcome_canonical_sha256": "4" * 64,
            "signer_public_key_sha256": "5" * 64,
        },
    }
    gate: dict[str, object] = {
        "query_v4_keyring_path": str(keyring_path),
        "query_v4_keyring_raw_sha256": keyring_sha256,
        "query_v4_keyring_canonical_sha256": keyring_sha256,
        "query_v4_authority_keyring_sha256": keyring_sha256,
        "readiness_raw_sha256": "6" * 64,
        "readiness_canonical_sha256": "7" * 64,
        "packet_custody_identity_sha256": "b" * 64,
    }
    release_id = "query-v4-signed-audit-test"
    release_readiness = {
        "packet_id": readiness["packet_id"],
        "packet_raw_sha256": gate["readiness_raw_sha256"],
        "packet_canonical_sha256": gate[
            "readiness_canonical_sha256"
        ],
        "generated_at": readiness["generated_at"],
        "expires_at": readiness["expires_at"],
        "content_attestation_raw_sha256": "d" * 64,
        "content_attestation_canonical_sha256": "e" * 64,
        "provenance_raw_sha256": "f" * 64,
        "provenance_canonical_sha256": "1" * 64,
        "provenance_signer_public_key_sha256": "2" * 64,
        "outcome_raw_sha256": "3" * 64,
        "outcome_canonical_sha256": "4" * 64,
        "outcome_signer_public_key_sha256": "5" * 64,
    }
    source_bundle_index = {
        "readiness_packet_raw_sha256": gate["readiness_raw_sha256"],
        "readiness_packet_canonical_sha256": gate[
            "readiness_canonical_sha256"
        ],
        "t1_runtime": readiness["t1_runtime"],
        "build_registry_provenance": readiness[
            "build_registry_provenance"
        ],
        "readonly_deployment_outcome": readiness[
            "readonly_deployment_outcome"
        ],
    }
    release: dict[str, object] = {
        "release_schema_sha256": hashlib.sha256(
            audit.QUERY_V4_RELEASE_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "query_keyring_schema_sha256": hashlib.sha256(
            audit.QUERY_V4_KEYRING_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "readiness_schema_sha256": hashlib.sha256(
            audit.QUERY_V4_READINESS_SCHEMA_PATH.read_bytes()
        ).hexdigest(),
        "trusted_keyring_sha256": keyring_sha256,
        "signer_key_id": "query-v4-forged-release-test",
        "readiness": release_readiness,
        "release_id": release_id,
        "attempt_id": "attempt-"
        + hashlib.sha256(release_id.encode("utf-8")).hexdigest(),
        "custody_identity_sha256": "b" * 64,
        "pin_root_path_sha256": "c" * 64,
        "readiness_source_bundle_index_sha256": hashlib.sha256(
            child._canonical_json(source_bundle_index)
        ).hexdigest(),
        "namespaces": {"source": "exact", "digest": "sha256"},
        "human_signature": "human-approved-query-v4",
        "reviewer_role": "release-reviewer",
    }
    release["signature"] = base64.b64encode(
        private_key.sign(child._canonical_json(release))
    ).decode("ascii")
    return gate, release, readiness


def test_audit_independently_verifies_signed_release_and_readiness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    gate, release, readiness = _signed_audit_authority_inputs(tmp_path)
    monkeypatch.setattr(
        audit,
        "validate_json_schema",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        audit,
        "_read_query_gate_root_pin",
        lambda *_args, **_kwargs: gate[
            "query_v4_authority_keyring_sha256"
        ],
    )

    audit._verify_query_v4_signed_release(gate, release, readiness)


def test_attacker_fd_and_forged_gate_cannot_bypass_signed_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = b"a" * child.LAUNCH_CAPABILITY_BYTES
    _put_capability_in_environment(monkeypatch, capability)
    gate, release, readiness = _signed_audit_authority_inputs(tmp_path)
    monkeypatch.setattr(
        audit,
        "validate_json_schema",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        audit,
        "_read_query_gate_root_pin",
        lambda *_args, **_kwargs: "9" * 64,
    )
    monkeypatch.setattr(
        audit,
        "_verify_query_v4_launch_capability",
        lambda *_args, **_kwargs: pytest.fail(
            "attacker FD must not be consumed before signature verification"
        ),
    )

    with pytest.raises(
        audit.AuditError,
        match="does not match the active pin",
    ):
        audit._verify_query_v4_authority_and_launch(
            gate,
            release,
            readiness,
            tmp_path,
            now=datetime(2026, 7, 29, 4, 1, tzinfo=timezone.utc),
            audit_child_invocation_raw_sha256="b" * 64,
            audit_child_invocation_canonical_sha256="c" * 64,
            pre_connect_gate_raw_sha256="d" * 64,
            pre_connect_gate_canonical_sha256="e" * 64,
        )

    assert child.LAUNCH_CAPABILITY_FD_ENV in os.environ
    assert child._read_launch_capability_from_environment() == capability


def test_audit_rejects_invalid_ed25519_release_signature(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    gate, release, readiness = _signed_audit_authority_inputs(tmp_path)
    release["signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
    monkeypatch.setattr(
        audit,
        "validate_json_schema",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        audit,
        "_read_query_gate_root_pin",
        lambda *_args, **_kwargs: gate[
            "query_v4_authority_keyring_sha256"
        ],
    )

    with pytest.raises(
        audit.AuditError,
        match="Ed25519 signature is invalid",
    ):
        audit._verify_query_v4_signed_release(gate, release, readiness)


def test_audit_runs_full_readiness_v3_reverification_before_launch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = {
        key: (
            f"/exact/{key}.json"
            if key in audit.QUERY_V4_READINESS_PATH_INPUTS
            else f"exact-{key}"
        )
        for key in (
            audit.QUERY_V4_READINESS_PATH_INPUTS
            | audit.QUERY_V4_READINESS_SCALAR_INPUTS
        )
    }
    gate = {
        "readiness_verification_inputs": values,
        "source_readiness_path": str(tmp_path / "readiness-v3.json"),
        "readiness_raw_sha256": "a" * 64,
        "readiness_canonical_sha256": "b" * 64,
        "pin_set_generation_id": "pin-generation-test",
        "pin_set_manifest_sha256": "c" * 64,
        "pin_root_identity_sha256": "d" * 64,
        "provenance_keyring_sha256": "e" * 64,
        "provenance_signing_tool_source_sha256": "f" * 64,
        "provenance_signing_tool_source_commit_sha": "1" * 40,
        "t1_authority_keyring_sha256": "2" * 64,
        "l3_authority_keyring_sha256": "3" * 64,
        "outcome_keyring_sha256": "4" * 64,
        "packet_custody_path": str(tmp_path),
        "packet_custody_id": "custody-full-readiness",
        "packet_custody_identity_sha256": "5" * 64,
        "packet_custody_directory_identity_sha256": "6" * 64,
        "evidence_join_identity_sha256": "7" * 64,
    }
    readiness = {"schema_version": "commodity_c_fast_t1_readiness_v3"}
    readiness_source = Path(
        readiness_module.__file__
    ).resolve(strict=True)
    release = {
        "readiness_verifier_sha256": hashlib.sha256(
            readiness_source.read_bytes()
        ).hexdigest()
    }
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        audit,
        "_read_query_gate_regular_bytes",
        lambda path, *_args, **_kwargs: Path(path).read_bytes(),
    )
    monkeypatch.setattr(
        readiness_module,
        "inputs_from_args",
        lambda namespace: observed.setdefault("inputs", namespace),
    )

    def verify(
        inputs: object,
        pins: object,
        packet_path: Path,
        *,
        now: datetime,
        require_root_owned_parent: bool,
    ) -> SimpleNamespace:
        observed.update(
            {
                "verified_inputs": inputs,
                "pins": pins,
                "packet_path": packet_path,
                "now": now,
                "require_root_owned_parent": require_root_owned_parent,
            }
        )
        return SimpleNamespace(
            payload=readiness,
            raw_sha256="a" * 64,
            canonical_sha256="b" * 64,
        )

    monkeypatch.setattr(
        readiness_module,
        "verify_existing_readiness_packet",
        verify,
    )
    now = datetime(2026, 7, 29, 4, 1, tzinfo=timezone.utc)

    audit._verify_query_v4_full_readiness(
        gate,
        release,
        readiness,
        now=now,
    )

    assert observed["packet_path"] == tmp_path / "readiness-v3.json"
    assert observed["now"] == now
    assert observed["require_root_owned_parent"] is True
    namespace = observed["inputs"]
    assert isinstance(namespace.external_image_evidence, Path)
