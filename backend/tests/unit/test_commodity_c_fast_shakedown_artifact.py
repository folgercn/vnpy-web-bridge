from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.core.config import Settings
from app.services.commodity_c_fast_shadow import (
    CommodityCFastShadowService,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from test_commodity_c_fast_shadow import contract_loader, unsigned_payload

SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "scripts"
    / "commodity_c_fast_shakedown_artifact.py"
)
SPEC = importlib.util.spec_from_file_location("cfast_shakedown_artifact", SCRIPT)
assert SPEC and SPEC.loader
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)

NOW = datetime(2026, 9, 1, 2, tzinfo=timezone.utc)
ACCOUNT_HASH = "9" * 64


def key_entry(key: Ed25519PrivateKey, purpose: str) -> dict[str, str]:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "public_key_base64": base64.b64encode(raw).decode(),
        "purpose": purpose,
    }


def research_bundle() -> dict:
    # Synthetic test fixture only; producer assertion tests must never be
    # reused as runtime Research evidence.
    snapshot = unsigned_payload(
        snapshot_id="c-fast-shakedown-20260901",
        source_month="2026-09",
        source_day="2026-09-01",
        execution_day="2026-09-01",
        input_cutoff="2026-09-01T00:30:00Z",
    )
    snapshot["snapshot_created_at_utc"] = "2026-09-01T01:02:00Z"
    snapshot["research_observed_at_utc"] = "2026-09-01T01:01:30Z"
    for key in ARTIFACT.PROTECTED_SNAPSHOT_KEYS:
        snapshot.pop(key, None)
    for key in (
        "snapshot_producer_status",
        "producer_sha256",
        "input_bundle_sha256",
    ):
        snapshot["research_bindings"].pop(key, None)
    return {
        "schema_version": "commodity_c_fast_simnow_research_input_v1",
        "human_confirmed": True,
        "reviewer_assertion":
        "REAL_RESEARCH_INPUT_NOT_FIXTURE_NOT_EXECUTION_DERIVED",
        "evidence": [
            {
                "name": "research-manifest.json",
                "kind": "research_manifest",
                "sha256": "c" * 64,
            },
            {
                "name": "allocation.json",
                "kind": "allocation",
                "sha256": "a" * 64,
            },
            {
                "name": "daily-roll.json",
                "kind": "daily_roll",
                "sha256": "b" * 64,
            },
            {
                "name": "official-open.json",
                "kind": "reference_price",
                "sha256": "f" * 64,
            },
        ],
        "snapshot": snapshot,
    }


def signed_artifact(
    research_key: Ed25519PrivateKey,
    control_key: Ed25519PrivateKey,
) -> dict:
    core = ARTIFACT.produce(research_bundle())
    research = ARTIFACT.sign_research(core, research_key)
    return ARTIFACT.issue_permit(
        research,
        research_public_key=research_key.public_key(),
        control_private_key=control_key,
        acceptance_id="cfast-accept-20260901a",
        permit_id="cfast-permit-20260901a",
        account_sha256=ACCOUNT_HASH,
        accepted_at="2026-09-01T01:03:00Z",
        expires_at="2026-09-01T03:00:00Z",
        max_selected_products=1,
        control_signer_key_id="c-fast-control-1",
    )


def service(
    tmp_path: Path,
    payload: dict,
    research_key: Ed25519PrivateKey,
    control_key: Ed25519PrivateKey,
    *,
    now: datetime = NOW,
) -> CommodityCFastShadowService:
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps(payload), encoding="utf-8")
    settings = Settings(
        commodity_simnow_enabled=True,
        commodity_c_fast_shadow_enabled=True,
        commodity_c_fast_shadow_snapshot_path=str(snapshot),
        commodity_c_fast_shadow_state_path=str(tmp_path / "state.json"),
        commodity_c_fast_shadow_evidence_path=str(tmp_path / "evidence.jsonl"),
        commodity_c_fast_simnow_shakedown_enabled=True,
        commodity_c_fast_simnow_account_hashes=ACCOUNT_HASH,
        commodity_c_fast_shadow_trusted_public_keys_json=json.dumps(
            {
                "c-fast-research-1": key_entry(
                    research_key, "research_snapshot_signer"
                ),
                "c-fast-control-1": key_entry(
                    control_key, "simnow_shakedown_control_signer"
                ),
            }
        ),
    )
    return CommodityCFastShadowService(
        settings=settings,
        contract_loader=contract_loader,
        clock=lambda: now,
    )


def test_produce_sign_permit_reload_and_runtime_read(
    tmp_path: Path,
) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = signed_artifact(research_key, control_key)
    instance = service(tmp_path, payload, research_key, control_key)

    result = instance.reload(operator="admin", role="admin", source_ip=None)
    snapshot, snapshot_hash = instance.accepted_snapshot_for_control()

    assert result["valid"] is True
    assert result["execution_lane"] == "simnow_shakedown"
    assert snapshot.account_sha256 == ACCOUNT_HASH
    assert snapshot.max_selected_products == 1
    assert snapshot.max_child_order_lots == 0
    assert snapshot_hash == result["snapshot_hash"]


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda value: value["targets"][0].update(
                {"target_quantity": value["targets"][0]["target_quantity"] + 1}
            ),
            "SHAKEDOWN_SIGNATURE_INVALID",
        ),
        (
            lambda value: value.update({"account_sha256": "8" * 64}),
            "SHAKEDOWN_SIGNATURE_INVALID",
        ),
        (
            lambda value: value.update({"signature": base64.b64encode(bytes(64)).decode()}),
            "SHAKEDOWN_SIGNATURE_INVALID",
        ),
    ],
)
def test_tamper_fails_closed(tmp_path: Path, mutator, error: str) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = copy.deepcopy(signed_artifact(research_key, control_key))
    mutator(payload)
    result = service(tmp_path, payload, research_key, control_key).reload(
        operator="admin", role="admin", source_ip=None
    )
    assert result["valid"] is False
    assert result["error_code"] == error


def test_expired_permit_and_wrong_allowlist_fail_closed(tmp_path: Path) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = signed_artifact(research_key, control_key)
    expired = service(
        tmp_path,
        payload,
        research_key,
        control_key,
        now=datetime(2026, 9, 1, 4, tzinfo=timezone.utc),
    ).reload(operator="admin", role="admin", source_ip=None)
    assert expired["error_code"] == "EXECUTION_PERMIT_EXPIRED"


def test_same_day_successor_is_replay_rejected(tmp_path: Path) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    first = signed_artifact(research_key, control_key)
    instance = service(tmp_path, first, research_key, control_key)
    accepted = instance.reload(operator="admin", role="admin", source_ip=None)
    assert accepted["valid"] is True

    bundle = research_bundle()
    bundle["snapshot"]["snapshot_id"] = "c-fast-shakedown-20260901-replay"
    bundle["snapshot"]["previous_snapshot_hash"] = accepted["snapshot_hash"]
    for row in bundle["snapshot"]["targets"]:
        row["previous_exact_contract"] = row["exact_contract"]
        row["previous_target_quantity"] = row["target_quantity"]
    core = ARTIFACT.produce(bundle)
    research = ARTIFACT.sign_research(core, research_key)
    replay = ARTIFACT.issue_permit(
        research,
        research_public_key=research_key.public_key(),
        control_private_key=control_key,
        acceptance_id="cfast-accept-20260901b",
        permit_id="cfast-permit-20260901b",
        account_sha256=ACCOUNT_HASH,
        accepted_at="2026-09-01T01:04:00Z",
        expires_at="2026-09-01T03:00:00Z",
        max_selected_products=1,
        control_signer_key_id="c-fast-control-1",
    )
    snapshot_path = Path(
        instance.settings.commodity_c_fast_shadow_snapshot_path
    )
    snapshot_path.write_text(json.dumps(replay), encoding="utf-8")
    rejected = instance.reload(operator="admin", role="admin", source_ip=None)

    assert rejected["error_code"] == "SNAPSHOT_STALE_OR_REPLAYED"


def test_research_and_control_must_use_distinct_keys(
    tmp_path: Path,
) -> None:
    shared_key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="must be distinct"):
        signed_artifact(shared_key, shared_key)

    trusted = json.dumps(
        {
            "c-fast-research-1": key_entry(
                shared_key, "research_snapshot_signer"
            ),
            "c-fast-control-1": key_entry(
                shared_key, "simnow_shakedown_control_signer"
            ),
        }
    )
    with pytest.raises(ValidationError, match="must be distinct"):
        Settings(
            app_env="production",
            jwt_secret_key="x" * 32,
            commodity_c_fast_shadow_enabled=True,
            commodity_c_fast_shadow_snapshot_path=str(
                tmp_path / "config-snapshot.json"
            ),
            commodity_c_fast_shadow_state_path=str(
                tmp_path / "config-state.json"
            ),
            commodity_c_fast_shadow_evidence_path=str(
                tmp_path / "config-evidence.jsonl"
            ),
            commodity_c_fast_shadow_trusted_public_keys_json=trusted,
        )

    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    payload = signed_artifact(research_key, control_key)
    instance = service(
        tmp_path, payload, research_key, control_key
    )
    instance.settings = instance.settings.model_copy(
        update={
            "commodity_c_fast_shadow_trusted_public_keys_json": trusted,
        }
    )
    rejected = instance.reload(
        operator="admin", role="admin", source_ip=None
    )
    assert rejected["error_code"] == (
        "RESEARCH_CONTROL_SIGNERS_NOT_DISTINCT"
    )


def test_successor_previous_targets_must_match_accepted_state(
    tmp_path: Path,
) -> None:
    research_key = Ed25519PrivateKey.generate()
    control_key = Ed25519PrivateKey.generate()
    first = signed_artifact(research_key, control_key)
    instance = service(tmp_path, first, research_key, control_key)
    accepted = instance.reload(
        operator="admin", role="admin", source_ip=None
    )
    assert accepted["valid"] is True

    bundle = research_bundle()
    bundle["snapshot"]["snapshot_id"] = "c-fast-shakedown-20260902-next"
    bundle["snapshot"]["execution_day"] = "2026-09-02"
    bundle["snapshot"]["source_official_day"] = "2026-09-02"
    bundle["snapshot"]["snapshot_created_at_utc"] = (
        "2026-09-02T01:02:00Z"
    )
    bundle["snapshot"]["research_observed_at_utc"] = (
        "2026-09-02T01:01:30Z"
    )
    bundle["snapshot"]["input_cutoff_at_utc"] = "2026-09-02T01:00:00Z"
    bundle["snapshot"]["previous_snapshot_hash"] = accepted[
        "snapshot_hash"
    ]
    for row in bundle["snapshot"]["targets"]:
        row["previous_exact_contract"] = row["exact_contract"]
        row["previous_target_quantity"] = row["target_quantity"]
        row["reference_price_observed_at_utc"] = (
            "2026-09-02T01:01:00Z"
        )
        row["pit_main_dte"] -= 1
        row["pit_main_following_official_day"] = "2026-09-03"
        row["pit_main_following_dte"] -= 1
    bundle["snapshot"]["targets"][0]["previous_target_quantity"] += 1
    core = ARTIFACT.produce(bundle)
    research = ARTIFACT.sign_research(core, research_key)
    successor = ARTIFACT.issue_permit(
        research,
        research_public_key=research_key.public_key(),
        control_private_key=control_key,
        acceptance_id="cfast-accept-20260902a",
        permit_id="cfast-permit-20260902a",
        account_sha256=ACCOUNT_HASH,
        accepted_at="2026-09-02T01:03:00Z",
        expires_at="2026-09-02T03:00:00Z",
        max_selected_products=1,
        control_signer_key_id="c-fast-control-1",
    )
    Path(
        instance.settings.commodity_c_fast_shadow_snapshot_path
    ).write_text(json.dumps(successor), encoding="utf-8")
    instance._clock = lambda: datetime(
        2026, 9, 2, 2, tzinfo=timezone.utc
    )

    rejected = instance.reload(
        operator="admin", role="admin", source_ip=None
    )

    assert (
        rejected["error_code"]
        == "PREVIOUS_TARGET_CONTINUITY_MISMATCH"
    )


def test_producer_rejects_missing_evidence_and_owned_fields() -> None:
    missing = research_bundle()
    missing["evidence"] = []
    with pytest.raises(ValueError, match="evidence"):
        ARTIFACT.produce(missing)
    controlled = research_bundle()
    controlled["snapshot"]["account_sha256"] = ACCOUNT_HASH
    with pytest.raises(ValueError, match="producer/control-owned"):
        ARTIFACT.produce(controlled)


@pytest.mark.parametrize(
    "kind",
    sorted(ARTIFACT.REQUIRED_EVIDENCE_KINDS),
)
def test_producer_requires_exact_unique_evidence_kinds(kind: str) -> None:
    missing = research_bundle()
    missing["evidence"] = [
        row for row in missing["evidence"] if row["kind"] != kind
    ]
    with pytest.raises(ValueError, match="exact and unique"):
        ARTIFACT.produce(missing)

    duplicate = research_bundle()
    duplicate["evidence"].append(copy.deepcopy(duplicate["evidence"][0]))
    duplicate["evidence"][-1]["name"] = "duplicate.json"
    with pytest.raises(ValueError, match="exact and unique"):
        ARTIFACT.produce(duplicate)


@pytest.mark.parametrize(
    "kind",
    ["research_manifest", "allocation", "daily_roll"],
)
def test_producer_binds_research_evidence_hashes(kind: str) -> None:
    bundle = research_bundle()
    next(
        row for row in bundle["evidence"] if row["kind"] == kind
    )["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not match bindings"):
        ARTIFACT.produce(bundle)


def test_producer_binds_reference_price_to_every_target() -> None:
    bundle = research_bundle()
    bundle["snapshot"]["targets"][0][
        "reference_price_source_sha256"
    ] = "0" * 64
    with pytest.raises(ValueError, match="does not bind every target"):
        ARTIFACT.produce(bundle)


def test_installer_is_create_only(tmp_path: Path) -> None:
    target = tmp_path / "installed.json"
    ARTIFACT.write_private_create(target, b"first")
    with pytest.raises(FileExistsError):
        ARTIFACT.write_private_create(target, b"replacement")
    assert target.read_bytes() == b"first"
    assert target.stat().st_mode & 0o077 == 0


def test_snapshot_bundle_install_is_atomic_private_and_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    canonical = b'{"schema_version":"test_snapshot_v1","value":1}'
    real_fsync = os.fsync
    fsync_kinds: list[str] = []
    rename_observations: list[tuple[bool, set[str]]] = []

    def recording_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        fsync_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(fd)

    real_rename = ARTIFACT.atomic_rename_no_replace

    def recording_rename(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        try:
            os.stat(
                target_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            target_exists = True
        except FileNotFoundError:
            target_exists = False
        source_fd = os.open(
            source_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            source_names = set(os.listdir(source_fd))
        finally:
            os.close(source_fd)
        rename_observations.append(
            (target_exists, source_names)
        )
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(ARTIFACT.os, "fsync", recording_fsync)
    monkeypatch.setattr(
        ARTIFACT, "atomic_rename_no_replace", recording_rename
    )

    digest = ARTIFACT.install_snapshot_bundle(destination, canonical)

    assert digest == hashlib.sha256(canonical).hexdigest()
    assert ARTIFACT.validate_snapshot_installation(destination) == digest
    assert rename_observations == [
        (
            False,
            {
                ARTIFACT.INSTALL_SNAPSHOT_NAME,
                ARTIFACT.INSTALL_CHECKSUM_NAME,
            },
        )
    ]
    assert fsync_kinds.count("file") == 2
    assert fsync_kinds.count("directory") == 2
    assert destination.stat().st_mode & 0o077 == 0
    for child in destination.iterdir():
        assert child.stat().st_mode & 0o077 == 0


def test_snapshot_bundle_replay_is_create_only(tmp_path: Path) -> None:
    destination = tmp_path / "c-fast-snapshot"
    canonical = b'{"schema_version":"test_snapshot_v1","value":1}'
    ARTIFACT.install_snapshot_bundle(destination, canonical)

    with pytest.raises(FileExistsError, match="already exists"):
        ARTIFACT.install_snapshot_bundle(destination, canonical)

    assert (
        ARTIFACT.validate_snapshot_installation(destination)
        == hashlib.sha256(canonical).hexdigest()
    )


def test_legacy_single_file_destination_is_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "snapshot.json"
    destination.write_bytes(b"legacy-single-file")

    with pytest.raises(
        ARTIFACT.SnapshotInstallInvalidError,
        match="must be a directory",
    ):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert destination.read_bytes() == b"legacy-single-file"


def test_interrupted_publish_never_exposes_half_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "c-fast-snapshot"

    def fail_before_publish(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        del parent_fd, source_name, target_name
        raise OSError("simulated crash before atomic rename")

    monkeypatch.setattr(
        ARTIFACT, "atomic_rename_no_replace", fail_before_publish
    )

    with pytest.raises(OSError, match="simulated crash"):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert not destination.exists()
    assert not list(tmp_path.glob(".c-fast-snapshot.staging-*"))


def test_committed_rename_lost_response_never_deletes_published_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    canonical = b'{"value":1}'
    real_rename = ARTIFACT.atomic_rename_no_replace

    def publish_then_lose_response(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        real_rename(parent_fd, source_name, target_name)
        raise OSError("simulated lost response after committed rename")

    monkeypatch.setattr(
        ARTIFACT,
        "atomic_rename_no_replace",
        publish_then_lose_response,
    )

    with pytest.raises(OSError, match="simulated lost response"):
        ARTIFACT.install_snapshot_bundle(destination, canonical)

    assert ARTIFACT.validate_snapshot_installation(
        destination
    ) == hashlib.sha256(canonical).hexdigest()
    assert set(row.name for row in destination.iterdir()) == {
        ARTIFACT.INSTALL_SNAPSHOT_NAME,
        ARTIFACT.INSTALL_CHECKSUM_NAME,
    }
    assert not list(tmp_path.glob(".c-fast-snapshot.staging-*"))


def test_unsupported_no_replace_platform_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    monkeypatch.setattr(ARTIFACT.sys, "platform", "unsupported")

    with pytest.raises(OSError) as exc_info:
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert exc_info.value.errno == ARTIFACT.errno.ENOTSUP
    assert not destination.exists()
    assert not list(tmp_path.glob(".c-fast-snapshot.staging-*"))


def test_orphaned_crash_staging_is_never_treated_as_installed(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    orphan = tmp_path / ".c-fast-snapshot.staging-crashed"
    orphan.mkdir(mode=0o700)
    (orphan / ARTIFACT.INSTALL_SNAPSHOT_NAME).write_bytes(b'{"partial":true}\n')

    digest = ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert orphan.exists()
    assert ARTIFACT.validate_snapshot_installation(destination) == digest


def test_atomic_publish_race_never_replaces_new_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    real_rename = ARTIFACT.atomic_rename_no_replace

    def create_racing_destination(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(
        ARTIFACT,
        "atomic_rename_no_replace",
        create_racing_destination,
    )

    with pytest.raises(FileExistsError):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert destination.is_dir()
    assert not list(destination.iterdir())
    assert not list(tmp_path.glob(".c-fast-snapshot.staging-*"))


def test_validator_rejects_destination_replaced_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    retired = tmp_path / "retired-snapshot"
    ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')
    real_entry_lstat = ARTIFACT._entry_lstat
    swapped = False

    def swap_before_path_identity_check(
        parent_fd: int,
        name: str,
    ) -> os.stat_result:
        nonlocal swapped
        if name == destination.name and not swapped:
            swapped = True
            os.rename(
                destination.name,
                retired.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
        return real_entry_lstat(parent_fd, name)

    monkeypatch.setattr(
        ARTIFACT, "_entry_lstat", swap_before_path_identity_check
    )

    with pytest.raises(
        ARTIFACT.SnapshotInstallInvalidError,
        match="changed during validation",
    ):
        ARTIFACT.validate_snapshot_installation(destination)


def test_missing_parent_fails_closed_without_implicit_creation(
    tmp_path: Path,
) -> None:
    missing_parent = tmp_path / "missing" / "nested"
    destination = missing_parent / "c-fast-snapshot"

    with pytest.raises(
        ARTIFACT.SnapshotInstallInvalidError,
        match="parent must pre-exist",
    ):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert not missing_parent.exists()


@pytest.mark.parametrize("parent_kind", ["insecure", "symlink", "wrong_owner"])
def test_untrusted_parent_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    parent_kind: str,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    parent = real_parent
    if parent_kind == "insecure":
        real_parent.chmod(0o755)
    elif parent_kind == "symlink":
        parent = tmp_path / "linked-parent"
        parent.symlink_to(real_parent, target_is_directory=True)
    else:
        real_uid = os.geteuid()
        monkeypatch.setattr(
            ARTIFACT.os,
            "geteuid",
            lambda: real_uid + 1,
        )
    destination = parent / "c-fast-snapshot"

    with pytest.raises(
        ARTIFACT.SnapshotInstallInvalidError,
        match="private|owner-controlled",
    ):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert not destination.exists()
    assert not list(real_parent.glob(".c-fast-snapshot.staging-*"))


def test_parent_swap_during_publish_fails_closed_on_pinned_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "private-parent"
    retired_parent = tmp_path / "retired-parent"
    parent.mkdir(mode=0o700)
    destination = parent / "c-fast-snapshot"
    real_rename = ARTIFACT.atomic_rename_no_replace

    def swap_parent_then_publish(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        parent.rename(retired_parent)
        parent.mkdir(mode=0o700)
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(
        ARTIFACT,
        "atomic_rename_no_replace",
        swap_parent_then_publish,
    )

    with pytest.raises(
        ARTIFACT.SnapshotInstallInvalidError,
        match="parent path changed",
    ):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert not destination.exists()
    retired_destination = retired_parent / destination.name
    assert retired_destination.is_dir()
    assert ARTIFACT.validate_snapshot_installation(
        retired_destination
    ) == hashlib.sha256(b'{"value":1}').hexdigest()
    assert not list(parent.glob(".c-fast-snapshot.staging-*"))


def test_half_installed_destination_fails_closed_and_is_not_repaired(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    destination.mkdir(mode=0o700)
    snapshot = destination / ARTIFACT.INSTALL_SNAPSHOT_NAME
    snapshot.write_bytes(b'{"value":1}\n')
    snapshot.chmod(0o600)

    with pytest.raises(
        ARTIFACT.SnapshotInstallInvalidError,
        match="files are not exact",
    ):
        ARTIFACT.install_snapshot_bundle(destination, b'{"value":1}')

    assert snapshot.read_bytes() == b'{"value":1}\n'
    assert not (destination / ARTIFACT.INSTALL_CHECKSUM_NAME).exists()


@pytest.mark.parametrize("tampered_name", ["snapshot.json", "snapshot.json.sha256"])
def test_tampered_installation_fails_closed_without_overwrite(
    tmp_path: Path,
    tampered_name: str,
) -> None:
    destination = tmp_path / "c-fast-snapshot"
    canonical = b'{"value":1}'
    ARTIFACT.install_snapshot_bundle(destination, canonical)
    tampered = destination / tampered_name
    tampered.write_bytes(
        b'{"value":2}\n'
        if tampered_name == "snapshot.json"
        else b"0" * 64 + b"\n"
    )

    with pytest.raises(ARTIFACT.SnapshotInstallInvalidError):
        ARTIFACT.validate_snapshot_installation(destination)
    with pytest.raises(ARTIFACT.SnapshotInstallInvalidError):
        ARTIFACT.install_snapshot_bundle(destination, canonical)

    assert tampered.read_bytes() != (
        canonical + b"\n"
        if tampered_name == "snapshot.json"
        else hashlib.sha256(canonical).hexdigest().encode() + b"\n"
    )
