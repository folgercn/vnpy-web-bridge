from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from jsonschema import Draft202012Validator

from backend.tests.unit import test_issue267_windows_fence_foundation_schemas as fixture
from backend.tests.unit.test_windows_rpc_durable_fence_bundle_v1 import (
    CONFIG_RAW,
    KEYRING_CANONICAL_PATH,
    STORE_BINDING,
)
from backend.tests.unit.test_windows_rpc_durable_fence_manifest_v1 import _target_policy
from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.installer_trust_anchor_v1 import (
    canonical_public_keyring_v1,
)
from scripts.windows_fence_foundation.manifest_v1 import (
    EXPECTED_BINDING_FIELDS,
    verify_install_manifest_v1,
)
from scripts.windows_fence_foundation.offline_sign_cli_v1 import run as sign_run
from scripts.windows_fence_foundation.offline_signing_v1 import (
    OfflineSigningError,
    consume_replay_token_create_only_v1,
    verify_public_artifact_v1,
)
from scripts.windows_fence_foundation.release_bundle_v1 import (
    CHAIN_ORDER,
    verify_signing_closure_chain_v1,
)
from scripts.windows_fence_foundation.release_input_builder_cli_v1 import (
    main as release_input_main,
)
from scripts.windows_fence_foundation.release_input_builder_cli_v1 import (
    verify_release_build_audit_v1,
)
from scripts.windows_fence_foundation.release_input_builder_v1 import (
    _require_clean_approved_worktree,
    _thaw,
)
from scripts.windows_fence_foundation.trust_pins_v1 import (
    MANIFEST_KEY_DOMAIN,
    OBSERVER_KEY_DOMAIN,
    RESTART_KEY_DOMAIN,
)

ROOT = Path(__file__).resolve().parents[3]


def _raw(artifact: dict[str, object]) -> bytes:
    return artifact["raw"]  # type: ignore[return-value]


def _value(artifact: dict[str, object]) -> dict[str, object]:
    return fixture._artifact_value(artifact)  # type: ignore[no-any-return]


def _sha(artifact: dict[str, object]) -> str:
    return hashlib.sha256(_raw(artifact)).hexdigest()


def _attestation(value: dict[str, object]) -> dict[str, object]:
    private = fixture._test_private_key(OBSERVER_KEY_DOMAIN)
    public = fixture._public_key_raw(private)
    value = dict(value)
    value.pop("attestation_id", None)
    value.pop("attestation_core_sha256", None)
    value.pop("signature", None)
    value["attester_public_key_sha256"] = hashlib.sha256(public).hexdigest()
    core = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    value["attestation_core_sha256"] = core
    value["attestation_id"] = "windows-fence-foundation-attestation-" + core
    signature = private.sign(
        value["signature_domain_separator"].encode()
        + b"\x00"
        + canonical_json_bytes(value)
    )
    value["signature"] = base64.b64encode(signature).decode("ascii")
    return {"raw": canonical_json_bytes(value)}


def _keyring(tmp_path: Path) -> bytes:
    facts = {
        "path_sha256": hashlib.sha256(str(tmp_path).encode()).hexdigest(),
        "volume_serial": "A1B2C3D4",
        "volume_identity_sha256": "b" * 64,
        "file_identity": "A1B2C3D4:0000000000000001",
        "owner_sid_sha256": hashlib.sha256(b"test-owner").hexdigest(),
        "acl_sddl_sha256": hashlib.sha256(b"test-acl").hexdigest(),
        "unsafe_write_principals": [],
        "write_principal_sid_sha256s": [hashlib.sha256(b"test-writer").hexdigest()],
        "regular_file": False,
        "directory": True,
        "reparse_point": False,
        "parent_chain_reparse_free": True,
        "hardlink_count": 1,
        "alternate_data_streams": False,
        "dacl_protected": True,
        "inherited_ace_count": 0,
    }

    def pin(domain: str) -> dict[str, str]:
        key = fixture._test_private_key(domain)
        raw = fixture._public_key_raw(key)
        role, key_id = fixture.TEST_SIGNING_IDENTITIES[domain]
        return {
            "key_domain": domain,
            "role": role,
            "key_id": key_id,
            "public_key_b64": base64.b64encode(raw).decode("ascii"),
            "public_key_sha256": hashlib.sha256(raw).hexdigest(),
        }

    return canonical_json_bytes(
        {
            "schema_version": "windows_rpc_durable_fence_trust_keyring_v1",
            "purpose": "pin_windows_fence_public_verification_keys_and_nonce_root",
            "manifest": pin(MANIFEST_KEY_DOMAIN),
            "observer": pin(OBSERVER_KEY_DOMAIN),
            "restart": pin(RESTART_KEY_DOMAIN),
            "nonce_registry_root_facts": facts,
            "nonce_registry_owner_sid": "test-owner",
            "nonce_registry_acl_sddl": "test-acl",
        }
    )


def _chain_artifacts(tmp_path: Path) -> tuple[dict[str, bytes], bytes]:
    """Build a full all-public simulator chain with three independent keys."""
    artifacts: dict[str, dict[str, object]] = {}
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700, exist_ok=True)
    preflight = fixture._preflight()
    preflight.update(
        challenge_expires_at_utc="2026-08-05T00:00:50Z",
        snapshot_served_at_utc="2026-08-05T00:00:19Z",
        observed_at_utc="2026-08-05T00:00:20Z",
    )
    artifacts["zero_preflight"] = fixture._artifact("preflight", preflight)

    manifest = fixture._manifest()
    manifest.update(
        preflight_receipt_id=_value(artifacts["zero_preflight"])["receipt_id"],
        preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
    )
    artifacts["manifest"] = fixture._artifact("manifest", manifest)
    state = fixture._state()
    state.update(
        preflight_receipt_id=_value(artifacts["zero_preflight"])["receipt_id"],
        install_manifest_id=_value(artifacts["manifest"])["manifest_id"],
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
    )
    artifacts["fence_state"] = fixture._artifact("state", state)

    def event(
        sequence: int, event_type: str, attempt_state: str, observed_at: str
    ) -> None:
        value = fixture._event()
        value.update(
            event_sequence=sequence,
            event_type=event_type,
            attempt_state=attempt_state,
            observed_at_utc=observed_at,
            install_manifest_raw_sha256=_sha(artifacts["manifest"]),
            preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
            fence_state_raw_sha256=_sha(artifacts["fence_state"]),
        )
        if sequence == 1:
            value.update(previous_event_id=None, previous_event_raw_sha256=None)
        else:
            prior = artifacts[
                f"event_{sequence - 1}_"
                + {
                    2: "prepared",
                    3: "published",
                    4: "reserved",
                    5: "transition",
                    6: "dispatched",
                    7: "started",
                }[sequence]
            ]
            value.update(
                previous_event_id=_value(prior)["event_id"],
                previous_event_raw_sha256=_sha(prior),
            )
        if sequence >= 2:
            value["publish_receipt_raw_sha256"] = _sha(artifacts["publish_receipt"])
        if sequence >= 3:
            value.update(
                restart_authorization_raw_sha256=_sha(
                    artifacts["restart_authorization"]
                ),
                restart_dispatch_nonce_sha256=_value(
                    artifacts["restart_authorization"]
                )["dispatch_nonce_sha256"],
                service_control_operation_id=_value(artifacts["restart_authorization"])[
                    "service_control_operation_id"
                ],
            )
        if sequence >= 4:
            value["service_config_transition_receipt_raw_sha256"] = _sha(
                artifacts["transition_receipt"]
            )
        if sequence >= 5:
            value["scm_dispatch_evidence_raw_sha256"] = _sha(
                artifacts["scm_dispatch_evidence"]
            )
        if sequence >= 6:
            value["startup_receipt_raw_sha256"] = _sha(artifacts["startup_receipt"])
        if sequence == 7:
            value["foundation_attestation_raw_sha256"] = _sha(artifacts["attestation"])
        name = {
            1: "event_1_prepared",
            2: "event_2_published",
            3: "event_3_reserved",
            4: "event_4_transition",
            5: "event_5_dispatched",
            6: "event_6_started",
            7: "event_7_verified",
        }[sequence]
        artifacts[name] = fixture._artifact("install_event", value)

    event(1, "INSTALL_PREPARED", "PREPARED_FROZEN", "2026-08-05T00:00:05Z")
    publish = fixture._publish_receipt()
    publish.update(
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
    )
    artifacts["publish_receipt"] = fixture._artifact("publish", publish)
    event(2, "FILES_PUBLISHED", "FILES_READY_FROZEN", "2026-08-05T00:00:11Z")
    restart = fixture._restart_authorization()
    restart.update(
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
        publish_receipt_raw_sha256=_sha(artifacts["publish_receipt"]),
        install_event_head_raw_sha256=_sha(artifacts["event_2_published"]),
        issued_at_utc="2026-08-05T00:00:22Z",
        not_before_utc="2026-08-05T00:00:22Z",
        expires_at_utc="2026-08-05T00:01:00Z",
    )
    artifacts["restart_authorization"] = fixture._artifact(
        "restart_authorization", restart
    )
    event(
        3,
        "RESTART_DISPATCH_RESERVED",
        "RESTART_DISPATCH_RESERVED_FROZEN",
        "2026-08-05T00:00:23Z",
    )
    transition = fixture._service_config_transition_receipt()
    transition.update(
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
        publish_receipt_raw_sha256=_sha(artifacts["publish_receipt"]),
        restart_authorization_raw_sha256=_sha(artifacts["restart_authorization"]),
        reservation_event_id=_value(artifacts["event_3_reserved"])["event_id"],
        reservation_event_raw_sha256=_sha(artifacts["event_3_reserved"]),
        restart_dispatch_nonce_sha256=_value(artifacts["restart_authorization"])[
            "dispatch_nonce_sha256"
        ],
    )
    artifacts["transition_receipt"] = fixture._artifact(
        "service_config_transition_receipt", transition
    )
    event(
        4,
        "SERVICE_CONFIG_TRANSITION_VERIFIED",
        "SERVICE_CONFIG_READY_FROZEN",
        "2026-08-05T00:00:34Z",
    )
    scm = fixture._scm_dispatch_evidence()
    scm.update(
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        restart_authorization_raw_sha256=_sha(artifacts["restart_authorization"]),
        reservation_event_raw_sha256=_sha(artifacts["event_3_reserved"]),
        service_config_transition_receipt_raw_sha256=_sha(
            artifacts["transition_receipt"]
        ),
        restart_dispatch_nonce_sha256=_value(artifacts["restart_authorization"])[
            "dispatch_nonce_sha256"
        ],
    )
    artifacts["scm_dispatch_evidence"] = fixture._artifact("scm_dispatch_evidence", scm)
    event(5, "RESTART_DISPATCHED", "RESTART_UNKNOWN_FROZEN", "2026-08-05T00:00:37Z")
    startup = fixture._startup_receipt()
    startup.update(
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        restart_authorization_raw_sha256=_sha(artifacts["restart_authorization"]),
        service_config_transition_receipt_raw_sha256=_sha(
            artifacts["transition_receipt"]
        ),
        scm_dispatch_evidence_raw_sha256=_sha(artifacts["scm_dispatch_evidence"]),
        restart_dispatched_event_id=_value(artifacts["event_5_dispatched"])["event_id"],
        restart_dispatched_event_raw_sha256=_sha(artifacts["event_5_dispatched"]),
        restart_dispatch_nonce_sha256=_value(artifacts["restart_authorization"])[
            "dispatch_nonce_sha256"
        ],
    )
    artifacts["startup_receipt"] = fixture._artifact("startup_receipt", startup)
    event(6, "START_OBSERVED", "STARTED_FROZEN", "2026-08-05T00:00:37Z")
    attestation = fixture._attestation()
    attestation.update(
        install_manifest_raw_sha256=_sha(artifacts["manifest"]),
        preflight_receipt_raw_sha256=_sha(artifacts["zero_preflight"]),
        fence_state_raw_sha256=_sha(artifacts["fence_state"]),
        publish_receipt_raw_sha256=_sha(artifacts["publish_receipt"]),
        service_config_transition_receipt_raw_sha256=_sha(
            artifacts["transition_receipt"]
        ),
        start_observed_event_id=_value(artifacts["event_6_started"])["event_id"],
        start_observed_event_raw_sha256=_sha(artifacts["event_6_started"]),
        restart_authorization_raw_sha256=_sha(artifacts["restart_authorization"]),
        startup_receipt_raw_sha256=_sha(artifacts["startup_receipt"]),
        restart_dispatch_nonce_sha256=_value(artifacts["restart_authorization"])[
            "dispatch_nonce_sha256"
        ],
    )
    artifacts["attestation"] = _attestation(attestation)
    event(7, "FOUNDATION_VERIFIED", "VERIFIED_FROZEN", "2026-08-05T00:01:02Z")

    for name, kind, token, signed in (
        (
            "preflight_challenge_reservation",
            "preflight_challenge",
            _value(artifacts["zero_preflight"])["challenge_nonce_sha256"],
            "zero_preflight",
        ),
        (
            "preflight_replay_guard_reservation",
            "preflight_replay_guard",
            hashlib.sha256(
                str(_value(artifacts["zero_preflight"])["replay_guard_id"]).encode()
            ).hexdigest(),
            "zero_preflight",
        ),
        (
            "manifest_attempt_nonce_reservation",
            "manifest_attempt_nonce",
            _value(artifacts["manifest"])["attempt_nonce_sha256"],
            "manifest",
        ),
        (
            "manifest_install_attempt_reservation",
            "manifest_install_attempt",
            hashlib.sha256(
                str(_value(artifacts["manifest"])["install_attempt_id"]).encode()
            ).hexdigest(),
            "manifest",
        ),
        (
            "restart_dispatch_reservation",
            "restart_dispatch",
            _value(artifacts["restart_authorization"])["dispatch_nonce_sha256"],
            "restart_authorization",
        ),
        (
            "restart_authorization_reservation",
            "restart_authorization",
            hashlib.sha256(
                str(
                    _value(artifacts["restart_authorization"])["authorization_id"]
                ).encode()
            ).hexdigest(),
            "restart_authorization",
        ),
    ):
        artifacts[name] = {
            "raw": consume_replay_token_create_only_v1(
                ledger,
                token_sha256=str(token),
                reservation_kind=kind,
                artifact=_value(artifacts[signed]),
            )
        }
    return {name: _raw(artifacts[name]) for name in CHAIN_ORDER}, _keyring(tmp_path)


def test_three_key_full_closure_and_reservation_tamper_rejections(
    tmp_path: Path,
) -> None:
    artifacts, keyring = _chain_artifacts(tmp_path)
    closure = verify_signing_closure_chain_v1(
        artifacts,
        public_keyring_raw=keyring,
        now=datetime(2026, 8, 5, 0, 0, 40, tzinfo=timezone.utc),
    )
    assert closure["chain_order"] == list(CHAIN_ORDER)
    assert set(closure["artifact_raw_sha256"]) == set(CHAIN_ORDER)
    with pytest.raises(OfflineSigningError, match="OUTPUT_EXISTS"):
        _chain_artifacts(tmp_path)
    tampered = dict(artifacts)
    receipt = json.loads(tampered["restart_dispatch_reservation"])
    receipt["token_sha256"] = "0" * 64
    tampered["restart_dispatch_reservation"] = canonical_json_bytes(receipt)
    with pytest.raises(OfflineSigningError, match="RESERVATION_BINDING_MISMATCH"):
        verify_signing_closure_chain_v1(
            tampered,
            public_keyring_raw=keyring,
            now=datetime(2026, 8, 5, 0, 0, 40, tzinfo=timezone.utc),
        )


def test_release_source_requires_exact_clean_non_submodule_git_worktree(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "unit@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "unit"], check=True)
    (repo / "REVISION").write_text("unit\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "REVISION"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "unit"], check=True)
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _require_clean_approved_worktree(repo, head)
    for mutation, approved in (
        ("untracked", head),
        ("dirty", head),
        ("wrong", "0" * 40),
    ):
        if mutation == "untracked":
            (repo / "new").write_text("x", encoding="utf-8")
        elif mutation == "dirty":
            (repo / "REVISION").write_text("changed\n", encoding="utf-8")
        with pytest.raises(
            OfflineSigningError, match="RELEASE_SOURCE_REVISION_OR_CLEANLINESS_INVALID"
        ):
            _require_clean_approved_worktree(repo, approved)
        subprocess.run(["git", "-C", str(repo), "clean", "-fdq"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "checkout", "-q", "--", "REVISION"], check=True
        )
    assert _thaw({"value": (1, {"nested": (2,)})}) == {"value": [1, {"nested": [2]}]}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit_repository(repo: Path, filename: str = "REVISION") -> str:
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "unit@example.invalid")
    _git(repo, "config", "user.name", "unit")
    (repo / filename).write_text("unit\n", encoding="utf-8")
    _git(repo, "add", filename)
    _git(repo, "commit", "-qm", "unit")
    return _git(repo, "rev-parse", "HEAD")


def test_release_source_rejects_a_real_git_submodule(tmp_path: Path) -> None:
    child = tmp_path / "child"
    child_head = _commit_repository(child)
    parent = tmp_path / "parent"
    _commit_repository(parent)
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "-C",
            str(parent),
            "submodule",
            "add",
            "-q",
            str(child),
            "source",
        ],
        check=True,
    )
    _git(parent, "commit", "-qm", "add source submodule")
    with pytest.raises(OfflineSigningError, match="RELEASE_SOURCE_WORKTREE_REQUIRED"):
        _require_clean_approved_worktree(parent / "source", child_head)


def _release_source_repository(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "release-source"
    shutil.copytree(ROOT / "scripts", source / "scripts")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    _git(source, "config", "user.email", "unit@example.invalid")
    _git(source, "config", "user.name", "unit")
    _git(source, "add", "scripts")
    _git(source, "commit", "-qm", "release source")
    return source, _git(source, "rev-parse", "HEAD")


def _manifest_attempt_inputs(value: dict[str, object]) -> dict[str, object]:
    return {
        field: value[field]
        for field in (
            "attempt_nonce_sha256",
            "bundle_sha256",
            "service_name",
            "store_path_sha256",
            "store_volume_serial",
            "store_volume_identity_sha256",
            "expected_account_sha256",
            "gateway_name",
            "gateway_scope_sha256",
        )
    }


@pytest.mark.skipif(
    os.name == "nt",
    reason="positive FD signing requires Unix/macOS fcntl read-only-FD proof",
)
def test_release_input_build_fd_sign_and_receipt_tamper_rejection(
    tmp_path: Path,
) -> None:
    source, source_sha = _release_source_repository(tmp_path)
    keyring_raw = _keyring(tmp_path)
    pins = canonical_public_keyring_v1(
        keyring_raw, hashlib.sha256(keyring_raw).hexdigest()
    )
    preflight = fixture._preflight()
    preflight.update(
        challenge_expires_at_utc="2026-08-05T00:00:50Z",
        snapshot_served_at_utc="2026-08-05T00:00:19Z",
        observed_at_utc="2026-08-05T00:00:20Z",
    )
    preflight_raw = _raw(fixture._artifact("preflight", preflight))
    release_input = {
        "source_root": str(source),
        "inputs": {
            "approved_source_sha256": source_sha,
            "config_raw": base64.b64encode(CONFIG_RAW).decode("ascii"),
            "store_binding": STORE_BINDING,
            "keyring_raw": base64.b64encode(keyring_raw).decode("ascii"),
            "keyring_path": str(KEYRING_CANONICAL_PATH),
            "target_policy": _target_policy(),
            "preinstall_image_path": {
                "application_path": r"C:\\veighna_studio\\pythonservice.exe",
                "arguments": ["--legacy-rpc"],
            },
            "preinstall_python_class": "legacy_rpc.LegacyService",
            "preinstall_python_path": r"C:\\veighna_studio",
            "preinstall_start_type": "DISABLED",
            "preinstall_failure_actions": [],
            "preinstall_recovery_actions": [],
            "attempt_nonce_sha256": hashlib.sha256(b"release-input-nonce").hexdigest(),
            "issued_at_utc": "2026-08-05T00:00:20Z",
            "expires_at_utc": "2026-08-05T00:00:50Z",
            "trusted_clock_id": "unit.release.clock.v1",
            "preflight_raw": base64.b64encode(preflight_raw).decode("ascii"),
        },
    }
    input_path = tmp_path / "release-input.json"
    bundle_path = tmp_path / "bundle.zip"
    index_path = tmp_path / "bundle-index.json"
    draft_path = tmp_path / "manifest-draft.json"
    audit_path = tmp_path / "release-build.audit.json"
    input_path.write_bytes(canonical_json_bytes(release_input))
    assert (
        release_input_main(
            [
                "--release-input",
                str(input_path),
                "--bundle-output",
                str(bundle_path),
                "--index-output",
                str(index_path),
                "--manifest-output",
                str(draft_path),
                "--audit-output",
                str(audit_path),
                "--now-utc",
                "2026-08-05T00:00:20Z",
            ]
        )
        == 0
    )
    artifacts = {
        "bundle": bundle_path.read_bytes(),
        "index": index_path.read_bytes(),
        "manifest": draft_path.read_bytes(),
    }
    audit_raw = audit_path.read_bytes()
    audit_schema = json.loads(
        (
            ROOT / "docs/schemas/windows-fence-release-build-audit-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(audit_schema).validate(json.loads(audit_raw))
    assert verify_release_build_audit_v1(audit_raw, artifacts=artifacts)["artifacts"]

    keyring_path = tmp_path / "keyring.json"
    preflight_path = tmp_path / "preflight.json"
    keyring_path.write_bytes(keyring_raw)
    preflight_path.write_bytes(preflight_raw)
    private = fixture._test_private_key(MANIFEST_KEY_DOMAIN)
    key_path = tmp_path / "manifest-key"
    key_path.write_bytes(
        base64.b64encode(
            private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
    )
    key_path.chmod(0o400)
    key_fd = os.open(key_path, os.O_RDONLY)
    signed_path = tmp_path / "manifest.json"
    ledger_path = tmp_path / "ledger"
    ledger_path.mkdir(mode=0o700)
    try:
        assert (
            sign_run(
                "manifest",
                [
                    "--draft",
                    str(draft_path),
                    "--output",
                    str(signed_path),
                    "--audit-output",
                    str(tmp_path / "manifest-sign.audit.json"),
                    "--public-keyring",
                    str(keyring_path),
                    "--private-key-fd",
                    str(key_fd),
                    "--preflight-receipt",
                    str(preflight_path),
                    "--now-utc",
                    "2026-08-05T00:00:20Z",
                    "--replay-ledger-dir",
                    str(ledger_path),
                ],
            )
            == 0
        )
    finally:
        os.close(key_fd)
    signed_raw = signed_path.read_bytes()
    signed_value = json.loads(signed_raw)
    assert verify_public_artifact_v1(signed_raw, pin=pins.manifest).raw_sha256 == (
        hashlib.sha256(signed_raw).hexdigest()
    )
    verified = verify_install_manifest_v1(
        signed_raw,
        trust_pins=pins,
        expected_bindings={
            field: signed_value[field] for field in EXPECTED_BINDING_FIELDS
        },
        install_attempt_inputs=_manifest_attempt_inputs(signed_value),
        now=datetime(2026, 8, 5, 0, 0, 20, tzinfo=timezone.utc),
    )
    assert verified["bundle_sha256"] == hashlib.sha256(artifacts["bundle"]).hexdigest()

    for artifact, artifact_raw in artifacts.items():
        for field, replacement in (
            ("raw_sha256", "0" * 64),
            ("size_bytes", 1),
        ):
            tampered = json.loads(audit_raw)
            tampered["artifacts"][artifact][field] = replacement
            tampered["aggregate_raw_sha256"] = hashlib.sha256(
                canonical_json_bytes(tampered["artifacts"])
            ).hexdigest()
            with pytest.raises(
                OfflineSigningError, match="RELEASE_BUILD_AUDIT_ARTIFACT_MISMATCH"
            ):
                verify_release_build_audit_v1(
                    canonical_json_bytes(tampered), artifacts=artifacts
                )
        for altered in (
            b"\x00" + artifact_raw[1:],
            artifact_raw + b"\x00",
        ):
            tampered_artifacts = dict(artifacts)
            tampered_artifacts[artifact] = altered
            with pytest.raises(
                OfflineSigningError, match="RELEASE_BUILD_AUDIT_ARTIFACT_MISMATCH"
            ):
                verify_release_build_audit_v1(audit_raw, artifacts=tampered_artifacts)
