"""Issue #362: the runner's planner replay is strictly read-only.

This is deliberately an integration sentinel rather than another matrix of
tamper cases.  It runs the catalog-anchored signed monthly planner fixture
through the field-gate input boundary while the real read-only manifest,
commit-receipt and observation readers are also invoked from that closure.
Every writer primitive is poisoned for the duration.
"""

from __future__ import annotations

import builtins
import io
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.execution.executable_target_adapter import (
    build_full_portfolio_quote_requests,
)
from research_warehouse import filesystem, manifests, observations, publication
from research_warehouse import verified_monthly_final_target as monthly
from research_warehouse.manifests import verify_manifest_chain_readonly
from research_warehouse.observations import load_observations_readonly
from test_issue353_static_core_keyless import _snapshot
from test_research_warehouse_acquisition import (
    T1,
    T2,
    acquire,
    commit_seal,
    official_raw,
    registry,
    seal,
    signing_keys,
    trusted_commit_ledger,
    warehouse,
)
from test_research_warehouse_verified_monthly_final_target import (
    _install_root_mocks,
)

_WRITE_OPEN_FLAGS = (
    os.O_CREAT
    | os.O_RDWR
    | os.O_WRONLY
    | os.O_APPEND
    | os.O_TRUNC
    | os.O_EXCL
)


def _tree_identity(root: Path) -> tuple[tuple[str, int, int, int], ...]:
    return tuple(
        sorted(
            (
                str(path.relative_to(root)),
                path.lstat().st_ino,
                path.lstat().st_mode,
                path.lstat().st_size,
            )
            for path in root.rglob("*")
        )
    )


def _forbid_mutation(name: str):
    def blocked(*_args, **_kwargs):
        raise AssertionError(f"read-only planner replay attempted {name}")

    return blocked


def _install_mutation_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail every filesystem write path while allowing regular read/flock."""

    original_os_open = os.open
    original_builtin_open = builtins.open
    original_io_open = io.open

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & _WRITE_OPEN_FLAGS:
            raise AssertionError(
                "read-only planner replay attempted writable os.open: "
                f"{path!s}"
            )
        return original_os_open(path, flags, *args, **kwargs)

    def guarded_open(original, file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise AssertionError(
                "read-only planner replay attempted writable open: "
                f"{file!s}"
            )
        return original(file, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_os_open)
    monkeypatch.setattr(
        builtins,
        "open",
        lambda file, mode="r", *args, **kwargs: guarded_open(
            original_builtin_open, file, mode, *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        io,
        "open",
        lambda file, mode="r", *args, **kwargs: guarded_open(
            original_io_open, file, mode, *args, **kwargs
        ),
    )
    for name in (
        "write",
        "pwrite",
        "mkdir",
        "makedirs",
        "rename",
        "replace",
        "unlink",
        "remove",
        "rmdir",
        "removedirs",
        "chmod",
        "chown",
        "fsync",
        "truncate",
        "link",
        "symlink",
    ):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _forbid_mutation(f"os.{name}"))
    for name in (
        "touch",
        "mkdir",
        "rename",
        "replace",
        "unlink",
        "chmod",
        "chown",
        "write_bytes",
        "write_text",
    ):
        if hasattr(Path, name):
            monkeypatch.setattr(Path, name, _forbid_mutation(f"Path.{name}"))

    # A writer helper in the runner closure is a failure even if its current
    # implementation happens not to reach a low-level write in this fixture.
    for module, names in (
        (
            manifests,
            (
                "custody_lock",
                "_recover_manifest_publications",
                "verify_manifest_chain",
            ),
        ),
        (
            observations,
            ("custody_lock", "recover_atomic_publishes", "load_observations"),
        ),
        (
            filesystem,
            ("create_only_bytes", "custody_lock", "recover_atomic_publishes"),
        ),
        (publication, ("create_only_bytes", "recover_atomic_publishes")),
    ):
        for name in names:
            if hasattr(module, name):
                monkeypatch.setattr(module, name, _forbid_mutation(f"{module.__name__}.{name}"))


def test_runner_monthly_planner_replay_closure_is_mutation_free_before_field_gate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise the runner's catalog Genesis planner bundle with real readers.

    The compact fixture uses a genuine sealed Warehouse observation/manifest
    and commit receipt.  The larger historical daily matrix remains the
    existing signed baseline fixture, so this sentinel reaches the same
    planner/quote-request boundary without constructing a second full history
    acquisition framework.
    """

    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    paths = warehouse(custody_root)
    private_key, public_key = signing_keys(tmp_path / "keys")
    acquired = acquire(paths, official_raw(), T1)
    _manifest_path, manifest = seal(paths, private_key, T2, None)
    manifest_seal = manifest["batch_seal_sha256"]
    manifest_commit_seal = commit_seal(paths, manifest_seal)
    before = _tree_identity(paths.root)

    planner_root = tmp_path / "planner"
    planner_root.mkdir(mode=0o700)
    kwargs, _state = _install_root_mocks(monkeypatch, planner_root)
    fixture_verify_root_pins = monthly.verify_root_pins
    fixture_daily_sources = monthly.verified_static_baseline_daily_sources

    def readonly_root_pins(**fields):
        assert fields["readonly_manifest_verifier"] is True
        chain = verify_manifest_chain_readonly(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=manifest_seal,
            expected_head_seal_sha256=manifest_seal,
            expected_head_commit_seal_sha256=manifest_commit_seal,
            offline=True,
        )
        trusted_commit_ledger(paths).require_chain(chain)
        return fixture_verify_root_pins(**fields)

    def readonly_daily_sources(**fields):
        assert fields["readonly_observation_loader"] is True
        loaded = load_observations_readonly(
            paths,
            registry(),
            source_id="shfe-daily-market-data-v1",
            trade_day="2026-07-28",
        )
        assert [row["observation_id"] for row in loaded] == [acquired.observation_id]
        return fixture_daily_sources(**fields)

    monkeypatch.setattr(monthly, "verify_root_pins", readonly_root_pins)
    monkeypatch.setattr(
        monthly,
        "verified_static_baseline_daily_sources",
        readonly_daily_sources,
    )
    _install_mutation_sentinel(monkeypatch)

    bundle = monthly.replay_verified_monthly_planner_bundle(**kwargs)
    requirements = build_full_portfolio_quote_requests(
        static_core_equal_projection=bundle.static_core_equal_projection,
        static_core_equal_freeze_contract=bundle.static_core_equal_freeze_contract,
        static_core_equal_target_evidence=bundle.static_core_equal_target_evidence,
        position_manager_snapshot=bundle.position_manager_snapshot,
        position_manager_sha256=bundle.position_manager_sha256,
        current_facts=_snapshot({}),
        reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
        run_id="issue362-readonly-closure-sentinel",
        event_generated_at="2030-01-01T00:00:00Z",
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        target_plan_version=3,
    )

    assert requirements.phase == "OPEN"
    assert len(requirements.requirements) == 10
    assert set(bundle.authority.values()) == {False}
    assert _tree_identity(paths.root) == before
