from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.services.deployment_drain import DeploymentDrainService
from app.services.deployment_reconciliation_custody import (
    DeploymentReconciliationCustodyError,
    DeploymentReconciliationCustodyRepository,
)

NOW = datetime(2026, 8, 6, tzinfo=timezone.utc)


def _repository(root: Path) -> DeploymentReconciliationCustodyRepository:
    def clock() -> datetime:
        return NOW

    bootstrap = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="bootstrap-frozen-runtime",
        allow_initial_bootstrap=True,
        initial_bootstrap_state="RESTARTED_FROZEN",
    )
    bootstrap.status()
    current = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="c2b-online-runtime",
        allow_initial_bootstrap=True,
    )
    current.status()
    return DeploymentReconciliationCustodyRepository(root)


def _assert_code(expected: str, operation) -> None:
    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        operation()
    assert caught.value.code == expected


def test_store_creates_owner_only_directory_and_exact_idempotent_file(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "custody")
    basename = "intent-" + "1" * 64 + ".json"

    with repository.locked() as session:
        first = session.write_intent(basename, {"z": 2, "a": 1})
        path = repository.root / first.relative_path
        first_inode = path.stat().st_ino
        second = session.write_intent(basename, {"a": 1, "z": 2})
        readback = session.read_intent(basename)
        session.snapshot(captured_at=NOW)

    assert first == second == readback
    assert first.raw == b'{"a":1,"z":2}\n'
    assert path.stat().st_ino == first_inode
    assert path.stat().st_nlink == 1
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    ("writer", "directory"),
    [
        ("write_intent", "reconciliation-intents"),
        ("write_blob", "reconciliation-blobs"),
        ("write_head", "reconciliation-heads"),
    ],
)
def test_all_reserved_roles_are_narrow_and_readable(
    tmp_path: Path, writer: str, directory: str
) -> None:
    repository = _repository(tmp_path / writer)
    basename = "artifact-" + "2" * 64 + ".json"
    reader = writer.replace("write_", "read_")

    with repository.locked() as session:
        stored = getattr(session, writer)(basename, {"role": directory})
        observed = getattr(session, reader)(basename)

    assert stored == observed
    assert stored.relative_path == f"{directory}/{basename}"


def test_store_rejects_create_only_collision(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "collision")
    basename = "head-" + "3" * 64 + ".json"

    with repository.locked() as session:
        session.write_head(basename, {"generation": 1})
        _assert_code(
            "CUSTODY_OUTPUT_COLLISION",
            lambda: session.write_head(basename, {"generation": 2}),
        )


def test_store_rejects_symlinked_output_directory(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "directory-symlink")
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (repository.root / "reconciliation-intents").symlink_to(
        outside, target_is_directory=True
    )

    with repository.locked() as session:
        _assert_code(
            "CUSTODY_OUTPUT_DIRECTORY_RACE",
            lambda: session.write_intent("intent.json", {"safe": True}),
        )
    assert list(outside.iterdir()) == []


def test_store_rejects_insecure_output_directory_mode(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "directory-mode")
    directory = repository.root / "reconciliation-blobs"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)

    with repository.locked() as session:
        _assert_code(
            "CUSTODY_DIRECTORY_INSECURE",
            lambda: session.write_blob("blob.json", {"safe": True}),
        )


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode"])
def test_store_rejects_insecure_existing_output_file(
    tmp_path: Path, kind: str
) -> None:
    repository = _repository(tmp_path / kind)
    directory = repository.root / "reconciliation-blobs"
    directory.mkdir(mode=0o700)
    final = directory / "blob.json"
    source = tmp_path / f"{kind}-source.json"
    source.write_bytes(b'{"safe":true}\n')
    source.chmod(0o600)
    if kind == "symlink":
        final.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, final)
    else:
        final.write_bytes(source.read_bytes())
        final.chmod(0o644)

    with repository.locked() as session:
        expected = (
            "CUSTODY_FILE_OPEN_FAILED"
            if kind == "symlink"
            else "CUSTODY_FILE_INSECURE"
        )
        _assert_code(expected, lambda: session.read_blob("blob.json"))


def test_closed_session_and_cross_thread_use_are_rejected(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "liveness")
    errors: list[str] = []

    with repository.locked() as session:
        def cross_thread() -> None:
            try:
                session.write_intent("thread.json", {"safe": True})
            except DeploymentReconciliationCustodyError as exc:
                errors.append(exc.code)

        thread = threading.Thread(target=cross_thread)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert errors == ["CUSTODY_SESSION_THREAD_MISMATCH"]
    _assert_code(
        "CUSTODY_SESSION_CLOSED",
        lambda: session.write_intent("closed.json", {"safe": True}),
    )
    _assert_code("CUSTODY_SESSION_CLOSED", lambda: session.read_intent("closed.json"))


def test_fsync_failure_never_publishes_success(tmp_path: Path, monkeypatch) -> None:
    repository = _repository(tmp_path / "fsync")
    with repository.locked() as session:
        session.write_blob("seed.json", {"seed": True})
        original_fsync = os.fsync

        def fail_fsync(fd: int) -> None:
            del fd
            raise OSError("injected fsync failure")

        monkeypatch.setattr(os, "fsync", fail_fsync)
        _assert_code(
            "CUSTODY_OUTPUT_FSYNC_FAILED",
            lambda: session.write_blob("failed.json", {"safe": True}),
        )
        monkeypatch.setattr(os, "fsync", original_fsync)

    assert not (repository.root / "reconciliation-blobs" / "failed.json").exists()


def test_secure_readback_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path / "readback")
    with repository.locked() as session:
        session.write_head("seed.json", {"seed": True})
        original = session._read_output_raw
        changed = False

        def mutate_before_read(directory_fd: int, basename: str) -> bytes:
            nonlocal changed
            if basename == "changed.json" and not changed:
                changed = True
                path = repository.root / "reconciliation-heads" / basename
                path.write_bytes(b'{"changed":true}\n')
                path.chmod(0o600)
            return original(directory_fd, basename)

        monkeypatch.setattr(session, "_read_output_raw", mutate_before_read)
        _assert_code(
            "CUSTODY_OUTPUT_READBACK_MISMATCH",
            lambda: session.write_head("changed.json", {"expected": True}),
        )
    assert changed is True
