from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/commodity_c_fast_t1_one_shot.py"
MODULE = runpy.run_path(
    str(SCRIPT),
    run_name="commodity_c_fast_t1_one_shot",
)
sys.path.insert(0, str(ROOT / "scripts"))
SIGNER_MODULE = runpy.run_path(
    str(ROOT / "scripts/commodity_c_fast_t1_sign_release.py"),
    run_name="commodity_c_fast_t1_sign_release",
)
NOW = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
SOURCE_COMMIT = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
ENDPOINT_SHA256 = "c" * 64
QUESTDB_BUILD = "Build Information: QuestDB 9.4.3"


def write_json(path: Path, payload: dict, *, mode: int = 0o600) -> Path:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, allow_nan=False),
        encoding="utf-8",
    )
    path.chmod(mode)
    return path


def manifest_payload() -> dict:
    products = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
    exchanges = {
        "ag": "SHFE",
        "al": "SHFE",
        "au": "SHFE",
        "bu": "SHFE",
        "cu": "SHFE",
        "rb": "SHFE",
        "ru": "SHFE",
        "sc": "INE",
        "sp": "SHFE",
        "zn": "SHFE",
    }
    return {
        "schema_version": "commodity_c_fast_l1_l5_audit_manifest_v2",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_id": "c-fast-p0-test-a01",
        "audit_window": {
            "start": "2026-08-31T12:00:00+00:00",
            "end_exclusive": "2026-09-01T08:00:00+00:00",
            "trading_day": "20260901",
        },
        "session_windows": {
            "night_open": {
                "start": "2026-08-31T13:00:00+00:00",
                "end_exclusive": "2026-08-31T13:02:05+00:00",
            },
            "night_session": {
                "start": "2026-08-31T13:10:00+00:00",
                "end_exclusive": "2026-08-31T13:20:00+00:00",
            },
            "day_open": {
                "start": "2026-09-01T01:00:00+00:00",
                "end_exclusive": "2026-09-01T01:02:05+00:00",
            },
            "day_session": {
                "start": "2026-09-01T01:10:00+00:00",
                "end_exclusive": "2026-09-01T01:20:00+00:00",
            },
        },
        "targets": [
            {
                "product": product,
                "exact_contract": f"{exchanges[product]}.{product}2609",
                "previous_exact_contract": None,
                "roll_expected": False,
            }
            for product in products
        ],
        "execution_windows": [],
    }


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def signed_inputs(
    tmp_path: Path,
    *,
    purpose: str = "t1_audit_release_signer",
    release_overrides: dict | None = None,
) -> tuple[argparse.Namespace, dict]:
    private_key = Ed25519PrivateKey.generate()
    keyring = {
        "schema_version": "commodity_c_fast_t1_trusted_keys_v1",
        "keys": [
            {
                "key_id": "t1-release-key-a01",
                "purpose": purpose,
                "public_key_base64": public_key_base64(private_key),
            }
        ],
    }
    keyring_path = write_json(tmp_path / "keyring.json", keyring)
    custody_identity = {
        "schema_version": "commodity_c_fast_t1_custody_identity_v1",
        "custody_id": "c-fast-t1-custody-a01",
    }
    custody_dir = tmp_path / "custody"
    custody_dir.mkdir(mode=0o700)
    write_json(custody_dir / "custody-identity.json", custody_identity)
    manifest = manifest_payload()
    manifest_path = write_json(tmp_path / "manifest.json", manifest)
    release_id = "c-fast-t1-release-a01"
    release = {
        "schema_version": "commodity_c_fast_t1_one_shot_release_v1",
        "purpose": "c_fast_l1_l5_t1_readonly_audit",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "issue_number": 114,
        "release_id": release_id,
        "attempt_id": MODULE["release_attempt_id"](release_id),
        "issued_at": (NOW - timedelta(minutes=2)).isoformat(),
        "not_before": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "signer_key_id": "t1-release-key-a01",
        "signer_type": "human",
        "reviewer_role": "T1 release reviewer",
        "human_signature": "Approved for one readonly T1 audit.",
        "trusted_keyring_sha256": hashlib.sha256(
            MODULE["canonical_json"](keyring)
        ).hexdigest(),
        "custody_identity_sha256": hashlib.sha256(
            MODULE["canonical_json"](custody_identity)
        ).hexdigest(),
        "custody_path_sha256": MODULE["custody_path_sha256"](
            custody_dir
        ),
        "source_commit_sha": SOURCE_COMMIT,
        "runtime_image_digest": IMAGE_DIGEST,
        "runner_sha256": MODULE["sha256_regular_file"](
            SCRIPT, "runner"
        ),
        "audit_script_sha256": MODULE["sha256_regular_file"](
            MODULE["AUDIT_SCRIPT_PATH"], "audit"
        ),
        "manifest_schema_sha256": MODULE["sha256_regular_file"](
            MODULE["MANIFEST_SCHEMA_PATH"], "manifest schema"
        ),
        "evidence_schema_sha256": MODULE["sha256_regular_file"](
            MODULE["EVIDENCE_SCHEMA_PATH"], "evidence schema"
        ),
        "legacy_evidence_schema_sha256": MODULE["sha256_regular_file"](
            MODULE["LEGACY_EVIDENCE_SCHEMA_PATH"],
            "legacy evidence schema",
        ),
        "readonly_proof_schema_sha256": MODULE["sha256_regular_file"](
            MODULE["READONLY_PROOF_SCHEMA_PATH"], "proof schema"
        ),
        "snapshot_id": manifest["snapshot_id"],
        "manifest_sha256": hashlib.sha256(
            MODULE["canonical_json"](manifest)
        ).hexdigest(),
        "audit_window": manifest["audit_window"],
        "endpoint_identity_sha256": ENDPOINT_SHA256,
        "questdb_build_sha256": hashlib.sha256(
            QUESTDB_BUILD.encode("utf-8")
        ).hexdigest(),
        "connect_timeout_seconds": 10,
        "statement_timeout_ms": 60_000,
        "max_rows_per_contract": 500_000,
        "max_runtime_seconds": 300,
        "network_authorized": True,
        "readonly_production_query_authorized": True,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "deployment_mutation_authorized": False,
    }
    if release_overrides:
        release.update(release_overrides)
    release["signature"] = base64.b64encode(
        private_key.sign(MODULE["canonical_json"](release))
    ).decode("ascii")
    release_path = write_json(tmp_path / "release.json", release)
    dsn_path = tmp_path / "readonly.dsn"
    dsn_path.write_text(
        "postgresql://reader:secret@questdb:8812/qdb",
        encoding="utf-8",
    )
    dsn_path.chmod(0o600)
    args = argparse.Namespace(
        release=release_path,
        trusted_keyring=keyring_path,
        manifest=manifest_path,
        dsn_file=dsn_path,
        custody_dir=custody_dir,
        source_commit_sha=SOURCE_COMMIT,
        runtime_image_digest=IMAGE_DIGEST,
        pinned_keyring_sha256=release["trusted_keyring_sha256"],
        pinned_custody_path=custody_dir,
    )
    return args, release


def verify(args: argparse.Namespace):
    return MODULE["verify_release"](
        args.release,
        args.trusted_keyring,
        args.manifest,
        source_commit_sha=SOURCE_COMMIT,
        runtime_image_digest=IMAGE_DIGEST,
        pinned_keyring_sha256=args.pinned_keyring_sha256,
        now=NOW,
    )


def execute(args: argparse.Namespace, **kwargs):
    return MODULE["execute_once"](
        args,
        pinned_keyring_sha256=args.pinned_keyring_sha256,
        pinned_custody_path=args.pinned_custody_path,
        **kwargs,
    )


def test_release_verification_binds_signature_purpose_and_runtime(
    tmp_path: Path,
) -> None:
    args, release = signed_inputs(tmp_path)

    verified = verify(args)

    assert verified.payload == release
    assert verified.release_sha256 == hashlib.sha256(
        MODULE["canonical_json"](release)
    ).hexdigest()


@pytest.mark.parametrize(
    ("purpose", "overrides", "message"),
    [
        ("research_snapshot_signer", None, "purpose"),
        (
            "t1_audit_release_signer",
            {"human_signature": "PENDING_REVIEW"},
            "human_signature",
        ),
        (
            "t1_audit_release_signer",
            {"database_mutation_authorized": True},
            "schema validation",
        ),
        (
            "t1_audit_release_signer",
            {"attempt_id": "attempt-" + "f" * 64},
            "attempt_id",
        ),
    ],
)
def test_release_verification_fails_closed(
    tmp_path: Path,
    purpose: str,
    overrides: dict | None,
    message: str,
) -> None:
    args, _ = signed_inputs(
        tmp_path,
        purpose=purpose,
        release_overrides=overrides,
    )
    with pytest.raises(MODULE["OneShotError"], match=message):
        verify(args)


def test_strict_json_rejects_duplicate_key_nonfinite_and_symlink(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"a":NaN}', encoding="utf-8")
    symlink = tmp_path / "link.json"
    symlink.symlink_to(duplicate)

    with pytest.raises(MODULE["OneShotError"], match="duplicate JSON key"):
        MODULE["load_json_strict"](duplicate, "duplicate")
    with pytest.raises(MODULE["OneShotError"], match="non-finite"):
        MODULE["load_json_strict"](nonfinite, "nonfinite")
    with pytest.raises(MODULE["OneShotError"], match="symlink"):
        MODULE["load_json_strict"](symlink, "symlink")


def test_consume_is_fsynced_before_child_and_release_cannot_replay(
    tmp_path: Path,
) -> None:
    args, release = signed_inputs(tmp_path)
    calls = 0
    def runner(argv, **kwargs):
        nonlocal calls
        calls += 1
        consume = args.custody_dir / (
            f"{release['attempt_id']}.consumed.json"
        )
        assert consume.exists()
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert "--expected-endpoint-identity-sha256" in argv
        assert "--expected-manifest-sha256" in argv
        assert "verified-bundle" in argv[2]
        for flag, content in (
            ("--json-output", b"json"),
            ("--csv-output", b"csv"),
            ("--markdown-output", b"markdown"),
            ("--readonly-proof-output", b"proof"),
        ):
            Path(argv[argv.index(flag) + 1]).write_bytes(content)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def validator(paths, verified, returncode):
        assert returncode == 0
        assert verified.payload == release
        hashes = MODULE["artifact_hashes"](paths)
        assert all(value is not None for value in hashes.values())
        return True, {key: str(value) for key, value in hashes.items()}

    exit_code, terminal = execute(
        args,
        runner=runner,
        output_validator=validator,
        now=NOW,
    )

    assert exit_code == 0
    assert terminal["terminal_state"] == "SUCCEEDED_P0_PASS"
    assert terminal["proof_verified"] is True
    assert calls == 1

    replay_code, replay_terminal = execute(
        args,
        runner=runner,
        output_validator=validator,
        now=NOW,
    )
    assert replay_code == 2
    assert replay_terminal == terminal
    assert calls == 1

    terminal_path = args.custody_dir / (
        f"{release['attempt_id']}.terminal.json"
    )
    original_terminal_raw = terminal_path.read_bytes()
    tampered_terminal = dict(terminal)
    tampered_terminal["child_exit_code"] = 2
    tampered_terminal["p0_pass"] = None
    tampered_terminal["proof_verified"] = False
    write_json(terminal_path, tampered_terminal)
    with pytest.raises(MODULE["OneShotError"], match="schema validation"):
        execute(
            args,
            runner=runner,
            output_validator=validator,
            now=NOW,
        )
    terminal_path.write_bytes(original_terminal_raw)
    terminal_path.chmod(0o600)

    consume_path = args.custody_dir / (
        f"{release['attempt_id']}.consumed.json"
    )
    original_consume_raw = consume_path.read_bytes()
    consume_payload = json.loads(original_consume_raw)
    consume_path.write_text(
        json.dumps(consume_payload, indent=4),
        encoding="utf-8",
    )
    consume_path.chmod(0o600)
    with pytest.raises(MODULE["OneShotError"], match="exact consume"):
        execute(
            args,
            runner=runner,
            output_validator=validator,
            now=NOW,
        )
    consume_path.write_bytes(original_consume_raw)
    consume_path.chmod(0o600)

    terminal_path.unlink()
    with pytest.raises(
        MODULE["OneShotError"],
        match="CONSUMED_WITHOUT_TERMINAL",
    ):
        execute(
            args,
            runner=runner,
            output_validator=validator,
            now=NOW,
        )
    assert calls == 1


def test_attacker_controlled_keyring_cannot_replace_deployment_trust_root(
    tmp_path: Path,
) -> None:
    honest_root = tmp_path / "honest"
    attacker_root = tmp_path / "attacker"
    honest_root.mkdir()
    attacker_root.mkdir()
    honest_args, _ = signed_inputs(honest_root)
    attacker_args, _ = signed_inputs(attacker_root)

    with pytest.raises(
        MODULE["OneShotError"],
        match="independent deployment pin",
    ):
        MODULE["verify_release"](
            attacker_args.release,
            attacker_args.trusted_keyring,
            attacker_args.manifest,
            source_commit_sha=SOURCE_COMMIT,
            runtime_image_digest=IMAGE_DIGEST,
            pinned_keyring_sha256=honest_args.pinned_keyring_sha256,
            now=NOW,
        )


def test_runtime_pin_file_must_be_root_owned_and_not_cli_environment(
    tmp_path: Path,
) -> None:
    user_owned_pin = tmp_path / "trusted-keyring.sha256"
    user_owned_pin.write_text("a" * 64 + "\n", encoding="utf-8")
    user_owned_pin.chmod(0o444)

    with pytest.raises(MODULE["OneShotError"], match="root-owned"):
        MODULE["read_root_owned_deployment_pin"](
            user_owned_pin,
            "test pin",
        )


def test_copied_custody_identity_cannot_replay_at_another_path(
    tmp_path: Path,
) -> None:
    args, _ = signed_inputs(tmp_path)
    copied = tmp_path / "copied-custody"
    copied.mkdir(mode=0o700)
    copied_identity = (
        args.custody_dir / "custody-identity.json"
    ).read_bytes()
    identity_path = copied / "custody-identity.json"
    identity_path.write_bytes(copied_identity)
    identity_path.chmod(0o600)
    copied_args = argparse.Namespace(**vars(args))
    copied_args.custody_dir = copied
    calls = 0

    def runner(argv, **kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(MODULE["OneShotError"], match="deployment pin"):
        execute(copied_args, runner=runner, now=NOW)
    assert calls == 0


def test_child_uses_staged_manifest_and_verified_bundle(
    tmp_path: Path,
) -> None:
    args, release = signed_inputs(tmp_path)

    def runner(argv, **kwargs):
        staged_script = Path(argv[2])
        bundle_root = staged_script.parents[1]
        attempt_dir = bundle_root.parent
        assert attempt_dir.stat().st_mode & 0o777 == 0o500
        with pytest.raises(PermissionError):
            bundle_root.rename(attempt_dir / "replacement-bundle")
        original = json.loads(args.manifest.read_text(encoding="utf-8"))
        original["snapshot_id"] = "attacker-replaced-snapshot"
        args.manifest.write_text(json.dumps(original), encoding="utf-8")
        manifest_path = Path(argv[argv.index("--manifest") + 1])
        staged = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert staged["snapshot_id"] == release["snapshot_id"]
        assert (
            argv[argv.index("--expected-manifest-sha256") + 1]
            == release["manifest_sha256"]
        )
        assert kwargs["cwd"] == manifest_path.parents[1]
        return subprocess.CompletedProcess(argv, 2, "", "expected failure")

    exit_code, terminal = execute(args, runner=runner, now=NOW)
    assert exit_code == 2
    assert terminal["terminal_state"] == "FAILED_CHILD"


def test_complete_p0_blocker_is_not_reported_as_child_failure(
    tmp_path: Path,
) -> None:
    args, _ = signed_inputs(tmp_path)
    fake_hashes = {
        "audit_json": "1" * 64,
        "audit_csv": "2" * 64,
        "audit_markdown": "3" * 64,
        "readonly_proof": "4" * 64,
    }

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "")

    def validator(paths, verified, returncode):
        assert returncode == 1
        return False, fake_hashes

    exit_code, terminal = execute(
        args,
        runner=runner,
        output_validator=validator,
        now=NOW,
    )
    assert exit_code == 1
    assert terminal["terminal_state"] == "COMPLETED_P0_BLOCKED"
    assert terminal["p0_pass"] is False
    assert terminal["proof_verified"] is True


def test_child_failure_is_sealed_and_never_looks_successful(
    tmp_path: Path,
) -> None:
    args, _ = signed_inputs(tmp_path)

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 2, "", "failed")

    exit_code, terminal = execute(
        args,
        runner=runner,
        now=NOW,
    )

    assert exit_code == 2
    assert terminal["terminal_state"] == "FAILED_CHILD"
    assert terminal["p0_pass"] is None
    assert terminal["proof_verified"] is False
    assert terminal["database_mutations"] == 0
    assert terminal["orders_sent"] == 0


def test_timeout_is_sealed_and_release_is_burned(tmp_path: Path) -> None:
    args, _ = signed_inputs(tmp_path)

    def runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    exit_code, terminal = execute(
        args,
        runner=runner,
        now=NOW,
    )

    assert exit_code == 2
    assert terminal["terminal_state"] == "TIMED_OUT"
    assert terminal["p0_pass"] is None
    assert terminal["proof_verified"] is False


def test_signer_generates_attempt_id_and_create_only_output(
    tmp_path: Path,
) -> None:
    _, signed = signed_inputs(tmp_path)
    draft = {
        key: value
        for key, value in signed.items()
        if key not in {"attempt_id", "signature"}
    }
    private_key = Ed25519PrivateKey.generate()

    result = SIGNER_MODULE["sign_release"](
        draft,
        private_key,
        now=NOW,
    )

    assert result["attempt_id"] == MODULE["release_attempt_id"](
        result["release_id"]
    )
    private_key.public_key().verify(
        base64.b64decode(result["signature"], validate=True),
        MODULE["canonical_json"](
            MODULE["unsigned_release_payload"](result)
        ),
    )
    output = tmp_path / "signed-output.json"
    SIGNER_MODULE["write_private_json_create_only"](output, result)
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        SIGNER_MODULE["write_private_json_create_only"](output, result)


def test_output_validation_cross_binds_endpoint_build_and_exact_json_hash(
    tmp_path: Path,
) -> None:
    args, release = signed_inputs(tmp_path)
    verified = verify(args)
    evidence = {
        "snapshot_id": release["snapshot_id"],
        "manifest_sha256": release["manifest_sha256"],
        "audit_window": release["audit_window"],
        "read_only": True,
        "database_mutations": 0,
        "summary": {"p0_pass": True},
    }
    proof = {
        "snapshot_id": release["snapshot_id"],
        "manifest_sha256": release["manifest_sha256"],
        "endpoint_identity_sha256": ENDPOINT_SHA256,
        "endpoint_binding_verified": True,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "preflight": {"questdb_build": QUESTDB_BUILD},
        "postflight": {"questdb_build": QUESTDB_BUILD},
    }
    paths = MODULE["ArtifactPaths"](
        audit_json=write_json(tmp_path / "audit.json", evidence),
        audit_csv=tmp_path / "audit.csv",
        audit_markdown=tmp_path / "audit.md",
        readonly_proof=tmp_path / "proof.json",
    )
    paths.audit_csv.write_text("header\n", encoding="utf-8")
    paths.audit_markdown.write_text("# report\n", encoding="utf-8")
    proof["audit_evidence_sha256"] = hashlib.sha256(
        paths.audit_json.read_bytes()
    ).hexdigest()
    write_json(paths.readonly_proof, proof)

    original_validate = MODULE["validate_completed_outputs"].__globals__[
        "validate_json_schema_bytes"
    ]
    MODULE["validate_completed_outputs"].__globals__[
        "validate_json_schema_bytes"
    ] = lambda *args, **kwargs: None
    try:
        p0_pass, hashes = MODULE["validate_completed_outputs"](
            paths,
            verified,
            0,
        )
        assert p0_pass is True
        assert hashes["audit_json"] == proof["audit_evidence_sha256"]

        proof["endpoint_identity_sha256"] = "d" * 64
        write_json(paths.readonly_proof, proof)
        with pytest.raises(MODULE["OneShotError"], match="endpoint"):
            MODULE["validate_completed_outputs"](paths, verified, 0)
    finally:
        MODULE["validate_completed_outputs"].__globals__[
            "validate_json_schema_bytes"
        ] = original_validate
