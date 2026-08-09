from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.tests.unit import test_issue267_windows_fence_foundation_schemas as fixture
from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.offline_signing_v1 import (
    OfflineSigningError,
    consume_replay_token_create_only_v1,
)
from scripts.windows_fence_foundation.release_bundle_v1 import (
    CHAIN_ORDER,
    verify_signing_closure_chain_v1,
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
