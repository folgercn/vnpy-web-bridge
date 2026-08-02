from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_query_v5_release as query_v5  # noqa: E402
import commodity_c_fast_t1_query_v6_authority as foundation_v6  # noqa: E402
import commodity_c_fast_t1_query_v6_executable as subject  # noqa: E402
import commodity_c_fast_t1_query_v6_executable_sign as signer  # noqa: E402
import commodity_c_fast_t1_query_v6_runtime as runtime  # noqa: E402


NOW = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
H = "1" * 64
IMAGE_DIGEST = "sha256:" + "4" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_private(path: Path, payload: dict[str, Any]) -> Path:
    path.write_bytes(subject.canonical_json(payload) + b"\n")
    path.chmod(0o600)
    return path


def _keyring(
    private_key: Ed25519PrivateKey,
    *,
    executable: bool,
) -> dict[str, Any]:
    return {
        "schema_version": (
            subject.KEYRING_VERSION
            if executable
            else foundation_v6.KEYRING_VERSION
        ),
        "keys": [
            {
                "key_id": (
                    "query-v6-executable-test-key-0001"
                    if executable
                    else "query-v6-foundation-test-key-0001"
                ),
                "purpose": (
                    subject.KEY_PURPOSE
                    if executable
                    else foundation_v6.KEY_PURPOSE
                ),
                "public_key_base64": base64.b64encode(
                    private_key.public_key().public_bytes_raw()
                ).decode("ascii"),
            }
        ],
    }


def _artifact(payload: dict[str, Any], label: str) -> foundation_v6.JsonArtifact:
    return foundation_v6.JsonArtifact(
        payload=payload,
        raw_sha256=_sha(f"raw:{label}".encode()),
        canonical_sha256=_sha(f"canonical:{label}".encode()),
    )


def _manifest_payload() -> dict[str, Any]:
    return {
        "snapshot_id": "snapshot-query-v6-exec-0001",
        "audit_window": {
            "start": "2026-08-01T00:00:00+00:00",
            "end_exclusive": "2026-08-03T00:00:00+00:00",
            "trading_day": "20260802",
        },
    }


def _manifest_raw() -> bytes:
    return subject.canonical_json(_manifest_payload()) + b"\n"


def _foundation(
    custody: Path,
    dsn_file: Path,
    foundation_signer: Ed25519PrivateKey,
) -> foundation_v6.VerifiedAuthorityFoundation:
    dsn_info = dsn_file.lstat()
    dsn = {
        "schema_version": foundation_v6.DSN_IDENTITY_VERSION,
        "attestation_id": "dsn-executable-test-0001",
        "observed_at": (NOW - timedelta(minutes=2)).isoformat(),
        "dsn_file_absolute_path_sha256": _sha(
            str(dsn_file.resolve()).encode()
        ),
        "device": dsn_info.st_dev,
        "inode": dsn_info.st_ino,
        "owner_uid": dsn_info.st_uid,
        "owner_gid": dsn_info.st_gid,
        "mode": dsn_info.st_mode & 0o777,
        "link_count": dsn_info.st_nlink,
        "size_bytes": dsn_info.st_size,
        "expected_readonly_principal_sha256": _sha(b"readonly_user"),
        "expected_endpoint_identity_sha256": "8" * 64,
        "dsn_secret_included": False,
        "dsn_content_hash_included": False,
        "dsn_secret_read": False,
        "network_accessed": False,
        "authority_granted": False,
    }
    dsn["dsn_file_identity_sha256"] = foundation_v6.dsn_identity_sha256(dsn)
    manifest = foundation_v6.JsonArtifact(
        payload=_manifest_payload(),
        raw_sha256=_sha(_manifest_raw()),
        canonical_sha256=_sha(subject.canonical_json(_manifest_payload())),
    )
    readiness = _artifact({}, "readiness")
    l3 = _artifact({}, "l3")
    runtime_pins = _artifact({}, "runtime-pins")
    evidence = foundation_v6.AuthorityEvidence(
        readiness=readiness,
        l3_outcome=l3,
        query_manifest=manifest,
        runtime_pin_manifest=runtime_pins,
        dsn_identity_attestation=_artifact(dsn, "dsn"),
        verified_domain_public_key_hashes=frozenset({_sha(b"upstream-key")}),
    )
    provenance = query_v5.VerifiedProvenance(
        payload={
            "issued_at": (NOW - timedelta(minutes=4)).isoformat(),
            "runtime_source_commit_sha": "a" * 40,
            "image_reference": f"registry.invalid/query-v5@{IMAGE_DIGEST}",
            "image_digest": IMAGE_DIGEST,
            "image_id": "sha256:" + "5" * 64,
            "trusted_keyring_sha256": "6" * 64,
        },
        raw_sha256="a" * 64,
        canonical_sha256="b" * 64,
        signer_public_key_sha256=_sha(b"provenance-key"),
        composition_raw_sha256="c" * 64,
        composition_canonical_sha256="d" * 64,
    )
    foundation_keyring = _keyring(foundation_signer, executable=False)
    payload = {
        "release_id": "foundation-release-test-0001",
        "attempt_id": foundation_v6.release_attempt_id(
            "foundation-release-test-0001"
        ),
        "issued_at": (NOW - timedelta(minutes=3)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=8)).isoformat(),
        "signer_key_id": foundation_keyring["keys"][0]["key_id"],
        "trusted_keyring_sha256": _sha(
            foundation_v6.canonical_json(foundation_keyring)
        ),
        "authority_state": foundation_v6.AUTHORITY_STATE,
        "provenance_raw_sha256": provenance.raw_sha256,
        "provenance_canonical_sha256": provenance.canonical_sha256,
        "composition_attestation_raw_sha256": provenance.composition_raw_sha256,
        "composition_attestation_canonical_sha256": (
            provenance.composition_canonical_sha256
        ),
        "readiness_v4_raw_sha256": readiness.raw_sha256,
        "readiness_v4_canonical_sha256": readiness.canonical_sha256,
        "l3_outcome_raw_sha256": l3.raw_sha256,
        "l3_outcome_canonical_sha256": l3.canonical_sha256,
        "query_manifest_raw_sha256": manifest.raw_sha256,
        "query_manifest_canonical_sha256": manifest.canonical_sha256,
        "runtime_source_commit_sha": provenance.payload[
            "runtime_source_commit_sha"
        ],
        "runtime_image_reference": provenance.payload["image_reference"],
        "runtime_image_digest": provenance.payload["image_digest"],
        "runtime_image_id": provenance.payload["image_id"],
        "runtime_pin_generation_id": "runtime-pin-generation-test-0001",
        "runtime_pin_manifest_sha256": runtime_pins.raw_sha256,
        "runtime_identity_sha256": runtime_pins.canonical_sha256,
        "custody_absolute_path": str(custody.resolve()),
        "custody_path_sha256": _sha(str(custody.resolve()).encode()),
        "custody_id": "query-v6-custody-test-0001",
        "custody_identity_sha256": "9" * 64,
        "custody_directory_identity_sha256": "e" * 64,
        "dsn_file_identity_attestation_raw_sha256": (
            evidence.dsn_identity_attestation.raw_sha256
        ),
        "dsn_file_identity_attestation_canonical_sha256": (
            evidence.dsn_identity_attestation.canonical_sha256
        ),
        "dsn_file_identity_sha256": dsn["dsn_file_identity_sha256"],
        "expected_readonly_principal_sha256": dsn[
            "expected_readonly_principal_sha256"
        ],
        "expected_endpoint_identity_sha256": dsn[
            "expected_endpoint_identity_sha256"
        ],
        "query_child_sha256": "f" * 64,
        "audit_script_sha256": "0" * 64,
        "readonly_proof_schema_sha256": "1" * 64,
    }
    return foundation_v6.VerifiedAuthorityFoundation(
        payload=payload,
        raw_sha256="2" * 64,
        canonical_sha256="3" * 64,
        signer_public_key_sha256=_sha(
            foundation_signer.public_key().public_bytes_raw()
        ),
        evidence=evidence,
        provenance=provenance,
    )


def _pins(executable_keyring: dict[str, Any], adapter_raw: bytes) -> subject.ExecutablePins:
    payload = {
        "schema_version": subject.PIN_SET_VERSION,
        "generation_id": "query-v6-executable-pins-test-0001",
        "executable_keyring_sha256": _sha(subject.canonical_json(executable_keyring)),
        **subject.source_and_schema_hashes(),
        "execution_adapter_sha256": _sha(adapter_raw),
        "questdb_build_sha256": _sha(b"questdb-build-test"),
    }
    return subject.ExecutablePins(
        payload=payload,
        canonical_sha256=_sha(subject.canonical_json(payload)),
    )


def _draft() -> dict[str, Any]:
    payload = json.loads(
        (
            ROOT
            / "docs/operations/c-fast-t1-query-v6-executable-release.template.json"
        ).read_text(encoding="utf-8")
    )
    payload.update(
        {
            "release_id": "query-v6-executable-test-0001",
            "issued_at": (NOW - timedelta(seconds=20)).isoformat(),
            "not_before": (NOW - timedelta(seconds=10)).isoformat(),
            "expires_at": (NOW + timedelta(minutes=4)).isoformat(),
            "signer_key_id": "query-v6-executable-test-key-0001",
            "reviewer_role": "human-risk-reviewer",
            "human_signature": "approve one exact readonly query test",
        }
    )
    return payload


def _fixture(tmp_path: Path) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    dsn_file = tmp_path / "dsn"
    dsn_file.write_text("postgresql://readonly:test@localhost:8812/qdb", encoding="utf-8")
    dsn_file.chmod(0o600)
    adapter_raw = b"#!/usr/bin/env python3\n# pinned test adapter\n"
    adapter_path = tmp_path / "adapter.py"
    adapter_path.write_bytes(adapter_raw)
    adapter_path.chmod(0o500)
    foundation_signer = Ed25519PrivateKey.generate()
    foundation_keyring = _keyring(foundation_signer, executable=False)
    foundation_keyring_path = _write_private(
        tmp_path / "foundation-keyring.json",
        foundation_keyring,
    )
    foundation = _foundation(custody, dsn_file, foundation_signer)
    executable_signer = Ed25519PrivateKey.generate()
    executable_keyring = _keyring(executable_signer, executable=True)
    pins = _pins(executable_keyring, adapter_raw)
    signed = signer.sign_release(
        _draft(),
        executable_keyring,
        foundation_keyring_path,
        foundation,
        pins,
        executable_signer,
        now=NOW,
    )
    release_path = _write_private(custody / "executable-release.json", signed)
    executable_keyring_path = _write_private(
        tmp_path / "executable-keyring.json", executable_keyring
    )
    verified = subject.verify_release(
        release_path,
        executable_keyring_path,
        foundation_keyring_path,
        foundation,
        pins,
        now=NOW,
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(_manifest_raw())
    return {
        "custody": custody,
        "dsn_file": dsn_file,
        "adapter_path": adapter_path,
        "adapter_raw": adapter_raw,
        "foundation": foundation,
        "foundation_keyring_path": foundation_keyring_path,
        "executable_keyring": executable_keyring,
        "executable_signer": executable_signer,
        "executable_keyring_path": executable_keyring_path,
        "pins": pins,
        "signed": signed,
        "release_path": release_path,
        "verified": verified,
        "manifest_path": manifest_path,
    }


def _successful_validation() -> runtime.CompletedValidation:
    return runtime.CompletedValidation(
        p0_pass=True,
        artifact_sha256={
            "audit_json": "a" * 64,
            "audit_csv": "b" * 64,
            "audit_markdown": "c" * 64,
            "readonly_proof": "d" * 64,
        },
        readonly_preflight_canonical_sha256="e" * 64,
        readonly_postflight_canonical_sha256="e" * 64,
    )


def _pid_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    status = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return bool(status) and not status.startswith("Z")


def _assert_pid_exits(pid: int) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and _pid_is_live(pid):
        time.sleep(0.02)
    assert not _pid_is_live(pid)


def _forking_adapter(tmp_path: Path) -> tuple[list[str], Path, Path]:
    script = tmp_path / "forking-adapter.py"
    child_pid = tmp_path / "child.pid"
    parent_pid = tmp_path / "parent.pid"
    script.write_text(
        """import os
from pathlib import Path
import sys
import time

child = os.fork()
if child == 0:
    Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
    while True:
        time.sleep(1)
Path(sys.argv[2]).write_text(str(os.getpid()), encoding="utf-8")
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    invocation = [
        sys.executable,
        "-I",
        str(script),
        str(child_pid),
        str(parent_pid),
    ]
    return invocation, child_pid, parent_pid


def test_distinct_executable_signature_is_required_and_narrow(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    payload = values["verified"].payload
    assert all(payload[field] is True for field in subject.TRUE_AUTHORITY_FIELDS)
    assert all(payload[field] is False for field in subject.FALSE_AUTHORITY_FIELDS)
    assert payload["foundation_is_authority"] is False
    assert payload["production_authorized"] is False

    tampered = copy.deepcopy(payload)
    tampered["foundation"]["readiness_v4_raw_sha256"] = "0" * 64
    tampered["signature"] = base64.b64encode(
        values["executable_signer"].sign(
            subject.canonical_json(subject.unsigned_payload(tampered))
        )
    ).decode("ascii")
    _write_private(values["release_path"], tampered)
    with pytest.raises(subject.QueryV6ExecutableError):
        subject.verify_release(
            values["release_path"],
            values["executable_keyring_path"],
            values["foundation_keyring_path"],
            values["foundation"],
            values["pins"],
            now=NOW,
        )


def test_executable_key_cannot_reuse_foundation_domain(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    custody.mkdir()
    dsn = tmp_path / "dsn"
    dsn.write_text("secret", encoding="utf-8")
    dsn.chmod(0o600)
    shared = Ed25519PrivateKey.generate()
    foundation = _foundation(custody, dsn, shared)
    foundation_keyring_path = _write_private(
        tmp_path / "foundation-keyring.json",
        _keyring(shared, executable=False),
    )
    executable_keyring = _keyring(shared, executable=True)
    pins = _pins(executable_keyring, b"adapter")
    with pytest.raises(subject.QueryV6ExecutableError, match="domains overlap"):
        signer.prepare_release(
            _draft(),
            executable_keyring,
            foundation_keyring_path,
            foundation,
            pins,
            now=NOW,
        )


def test_consume_precedes_adapter_launch_and_replay_is_closed(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    launches: list[list[str]] = []

    def launch(invocation: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        consume_path = values["custody"] / (
            values["verified"].payload["attempt_id"] + ".query-consumed-v6.json"
        )
        assert consume_path.exists()
        launches.append(invocation)
        return subprocess.CompletedProcess(invocation, 0, "", "")

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        lambda _at: values["verified"],
        clock=lambda: NOW,
        adapter_launcher=launch,
        output_validator=lambda *_args: _successful_validation(),
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 0
    assert terminal["terminal_state"] == "COMPLETED_PASS"
    assert terminal["web_bridge_rpc_calls"] == 0
    assert terminal["orders_sent"] == 0
    assert terminal["positions_modified"] == 0
    assert len(launches) == 1
    assert Path(launches[0][2]) == values["adapter_path"].resolve(strict=True)
    assert "query-v6-execution-adapter.py" not in launches[0][2]

    with pytest.raises(runtime.QueryV6RuntimeError, match="already consumed"):
        runtime.run_authorized_attempt(
            values["verified"],
            values["release_path"],
            values["manifest_path"],
            values["dsn_file"],
            values["adapter_path"],
            lambda _at: values["verified"],
            clock=lambda: NOW,
            adapter_launcher=launch,
            output_validator=lambda *_args: _successful_validation(),
            require_root_owned_parent=False,
            require_root_owned_adapter=False,
        )
    assert len(launches) == 1


def test_staged_archive_tamper_never_changes_executed_adapter(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    revalidations = 0
    launches: list[list[str]] = []

    def tamper_staged_archive(
        _at: datetime,
    ) -> subject.VerifiedExecutableRelease:
        nonlocal revalidations
        revalidations += 1
        if revalidations == 2:
            staged = (
                values["custody"]
                / values["verified"].payload["attempt_id"]
                / "query-v6-execution-adapter.py"
            )
            staged.chmod(0o700)
            staged.write_text("tampered archival copy", encoding="utf-8")
        return values["verified"]

    def launch(
        invocation: list[str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        launches.append(invocation)
        return subprocess.CompletedProcess(invocation, 0, "", "")

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        tamper_staged_archive,
        clock=lambda: NOW,
        adapter_launcher=launch,
        output_validator=lambda *_args: _successful_validation(),
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 0
    assert terminal["terminal_state"] == "COMPLETED_PASS"
    assert len(launches) == 1
    assert Path(launches[0][2]) == values["adapter_path"].resolve(strict=True)


@pytest.mark.parametrize("drift_target", ["adapter", "dsn"])
def test_final_adapter_or_dsn_drift_blocks_launch(
    tmp_path: Path,
    drift_target: str,
) -> None:
    values = _fixture(tmp_path)
    revalidations = 0
    launches = 0

    def drift_at_final_boundary(
        _at: datetime,
    ) -> subject.VerifiedExecutableRelease:
        nonlocal revalidations
        revalidations += 1
        if revalidations == 2 and drift_target == "adapter":
            values["adapter_path"].chmod(0o700)
            values["adapter_path"].write_text("tampered root adapter", encoding="utf-8")
            values["adapter_path"].chmod(0o500)
        if revalidations == 2 and drift_target == "dsn":
            values["dsn_file"].write_text("changed-dsn-size", encoding="utf-8")
        return values["verified"]

    def launch(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal launches
        launches += 1
        return subprocess.CompletedProcess([], 0, "", "")

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        drift_at_final_boundary,
        clock=lambda: NOW,
        adapter_launcher=launch,
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 2
    assert terminal["terminal_state"] == "FAILED_BEFORE_NETWORK"
    assert terminal["adapter_launch_attempted"] is False
    assert terminal["production_query_attempted"] is False
    assert launches == 0


def test_wrong_runtime_manifest_blocks_before_consume(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    values["manifest_path"].write_text('{"wrong":true}\n', encoding="utf-8")
    launches = 0

    def launch(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal launches
        launches += 1
        return subprocess.CompletedProcess([], 0, "", "")

    with pytest.raises(runtime.QueryV6RuntimeError, match="verified foundation"):
        runtime.run_authorized_attempt(
            values["verified"],
            values["release_path"],
            values["manifest_path"],
            values["dsn_file"],
            values["adapter_path"],
            lambda _at: values["verified"],
            clock=lambda: NOW,
            adapter_launcher=launch,
            require_root_owned_parent=False,
            require_root_owned_adapter=False,
        )
    assert launches == 0
    assert not list(values["custody"].glob("*.query-consumed-v6.json"))


def test_final_tamper_fails_before_network_and_writes_terminal(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    calls = 0
    launches = 0

    def revalidate(_at: datetime) -> subject.VerifiedExecutableRelease:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise subject.QueryV6ExecutableError("simulated final tamper")
        return values["verified"]

    def launch(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal launches
        launches += 1
        return subprocess.CompletedProcess([], 0, "", "")

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        revalidate,
        clock=lambda: NOW,
        adapter_launcher=launch,
        output_validator=lambda *_args: _successful_validation(),
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 2
    assert terminal["terminal_state"] == "FAILED_BEFORE_NETWORK"
    assert terminal["production_query_attempted"] is False
    assert launches == 0


def test_launch_boundary_failure_after_consume_is_terminalized(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    launches = 0
    revalidations = 0

    def remove_manifest_before_launch(
        _at: datetime,
    ) -> subject.VerifiedExecutableRelease:
        nonlocal revalidations
        revalidations += 1
        if revalidations == 2:
            values["manifest_path"].unlink()
        return values["verified"]

    def launch(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal launches
        launches += 1
        return subprocess.CompletedProcess([], 0, "", "")

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        remove_manifest_before_launch,
        clock=lambda: NOW,
        adapter_launcher=launch,
        output_validator=lambda *_args: _successful_validation(),
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 2
    assert terminal["terminal_state"] == "FAILED_BEFORE_NETWORK"
    assert terminal["error_code"] == "PRE_NETWORK_LAUNCH_BOUNDARY_FAILED"
    assert terminal["adapter_launch_attempted"] is False
    assert terminal["production_query_attempted"] is False
    assert launches == 0


def test_timeout_is_terminal_outcome_unknown_and_never_replays(tmp_path: Path) -> None:
    values = _fixture(tmp_path)

    def timeout(invocation: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(invocation, 600)

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        lambda _at: values["verified"],
        clock=lambda: NOW,
        adapter_launcher=timeout,
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 2
    assert terminal["terminal_state"] == "OUTCOME_UNKNOWN"
    assert terminal["production_query_attempted"] is True
    assert terminal["production_query_completed"] is None


def test_run_adapter_timeout_kills_forked_process_group(tmp_path: Path) -> None:
    invocation, child_pid_path, parent_pid_path = _forking_adapter(tmp_path)
    with pytest.raises(subprocess.TimeoutExpired):
        runtime.run_adapter(invocation, cwd=tmp_path, timeout=1)
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    parent_pid = int(parent_pid_path.read_text(encoding="utf-8"))
    _assert_pid_exits(parent_pid)
    _assert_pid_exits(child_pid)


def test_run_adapter_interrupt_kills_forked_process_group(tmp_path: Path) -> None:
    invocation, child_pid_path, parent_pid_path = _forking_adapter(tmp_path)

    def interrupt_when_started() -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if child_pid_path.exists() and parent_pid_path.exists():
                os.kill(os.getpid(), signal.SIGINT)
                return
            time.sleep(0.01)

    interrupter = threading.Thread(target=interrupt_when_started)
    interrupter.start()
    with pytest.raises(KeyboardInterrupt):
        runtime.run_adapter(invocation, cwd=tmp_path, timeout=30)
    interrupter.join(timeout=2)
    assert not interrupter.is_alive()
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    parent_pid = int(parent_pid_path.read_text(encoding="utf-8"))
    _assert_pid_exits(parent_pid)
    _assert_pid_exits(child_pid)


def test_interrupt_terminalizes_and_prevents_replay(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    launches = 0

    def interrupt(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal launches
        launches += 1
        raise KeyboardInterrupt("test interrupt")

    code, terminal = runtime.run_authorized_attempt(
        values["verified"],
        values["release_path"],
        values["manifest_path"],
        values["dsn_file"],
        values["adapter_path"],
        lambda _at: values["verified"],
        clock=lambda: NOW,
        adapter_launcher=interrupt,
        require_root_owned_parent=False,
        require_root_owned_adapter=False,
    )
    assert code == 130
    assert terminal["terminal_state"] == "INTERRUPTED"
    assert terminal["production_query_completed"] is None
    assert launches == 1
    with pytest.raises(runtime.QueryV6RuntimeError, match="already consumed"):
        runtime.run_authorized_attempt(
            values["verified"],
            values["release_path"],
            values["manifest_path"],
            values["dsn_file"],
            values["adapter_path"],
            lambda _at: values["verified"],
            clock=lambda: NOW,
            adapter_launcher=interrupt,
            require_root_owned_parent=False,
            require_root_owned_adapter=False,
        )
    assert launches == 1


def test_adapter_tamper_and_partial_state_block_before_launch(tmp_path: Path) -> None:
    values = _fixture(tmp_path)
    values["adapter_path"].chmod(0o700)
    values["adapter_path"].write_text("tampered", encoding="utf-8")
    values["adapter_path"].chmod(0o500)
    launches = 0

    def launch(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal launches
        launches += 1
        return subprocess.CompletedProcess([], 0, "", "")

    with pytest.raises(runtime.QueryV6RuntimeError, match="adapter binding"):
        runtime.run_authorized_attempt(
            values["verified"],
            values["release_path"],
            values["manifest_path"],
            values["dsn_file"],
            values["adapter_path"],
            lambda _at: values["verified"],
            clock=lambda: NOW,
            adapter_launcher=launch,
            require_root_owned_parent=False,
            require_root_owned_adapter=False,
        )
    assert launches == 0
    assert not list(values["custody"].glob("*.query-consumed-v6.json"))

    values = _fixture(tmp_path / "partial")
    (values["custody"] / values["verified"].payload["attempt_id"]).mkdir()
    with pytest.raises(runtime.QueryV6RuntimeError, match="partial attempt"):
        runtime.run_authorized_attempt(
            values["verified"],
            values["release_path"],
            values["manifest_path"],
            values["dsn_file"],
            values["adapter_path"],
            lambda _at: values["verified"],
            clock=lambda: NOW,
            adapter_launcher=launch,
            require_root_owned_parent=False,
            require_root_owned_adapter=False,
        )
    assert launches == 0


def test_default_cli_has_explicit_preconsume_runtime_blocker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        runtime,
        "parse_args",
        lambda: SimpleNamespace(execution_adapter=None),
    )
    assert runtime.main() == 2
    error = capsys.readouterr().err
    assert runtime.RUNTIME_BLOCKER in error
    assert "release_consumed=false" in error
    assert "network_attempted=false" in error
