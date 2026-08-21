# ruff: noqa: E402

from __future__ import annotations

import ast
import grp
import json
import os
import pwd
import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import m2_genesis_predecessor_cli as genesis_cli
from research_warehouse.canonical import canonical_json_line
from research_warehouse.daily_roll_predecessor_catalog import (
    DailyRollPredecessorCatalogError,
    ProtectedGenesisReplayInputs,
    _close_child_inherited_descriptors,
    _drop_to_protected_replay_identity,
    _read_protected_replay_payload,
    _require_exact_service_identity,
    publish_predecessor_artifact,
)
from research_warehouse.errors import RegistryError
from research_warehouse.m2_isolation_contracts import false_authority


def _config_value(tmp_path: Path) -> dict:
    return {
        "schema_version": "web-bridge-simnow-continuous-run-once-config-v1",
        "authority": false_authority(),
        "warehouse_runtime_input_raw_sha256": "1" * 64,
        "warehouse_history_receipt_path": str(tmp_path / "history.json"),
        "warehouse_history_receipt_raw_sha256": "2" * 64,
        "warehouse_manifest_public_key_path": str(tmp_path / "manifest.pub"),
        "warehouse_manifest_public_key_raw_sha256": "3" * 64,
        "warehouse_signed_baseline_batch_path": str(tmp_path / "baseline.json"),
        "warehouse_business_public_key_path": str(tmp_path / "business.pub"),
        "warehouse_business_public_key_raw_sha256": "4" * 64,
        "warehouse_business_signer_key_id": "research-signer-test-0001",
        "warehouse_contract_registry_path": str(tmp_path / "contracts.json"),
        "warehouse_contract_registry_raw_sha256": "5" * 64,
        "bootstrap_source_month": "2026-08",
        "bootstrap_execution_month": "2026-08",
        "bootstrap_static_core_equal_sha256": "6" * 64,
        "bootstrap_position_manager_sha256": "7" * 64,
        "bootstrap_final_target_sha256": "8" * 64,
    }


def test_non_root_fails_before_any_root_or_write_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def unexpected(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("non-root must not enter publication")

    monkeypatch.setattr(genesis_cli.os, "getuid", lambda: 501)
    monkeypatch.setattr(genesis_cli.os, "geteuid", lambda: 501)
    monkeypatch.setattr(genesis_cli, "load_isolation_policy", unexpected)
    assert (
        genesis_cli.main(["--continuous-config", str(tmp_path / "config.json")])
        == 2
    )
    assert called is False


def test_projection_accepts_only_protected_genesis_facts(tmp_path: Path) -> None:
    projection = genesis_cli._projection_from_config(
        canonical_json_line(_config_value(tmp_path))
    )
    raw = genesis_cli._projection_payload(projection)
    assert b"target_quantity" not in raw
    assert b"exact_contract_map" not in raw
    assert b"artifact_raw" not in raw
    restored = genesis_cli._projection_from_payload(raw)
    assert restored == projection


def test_projection_rejects_noncanonical_schema_and_hash_tamper(tmp_path: Path) -> None:
    raw = genesis_cli._projection_payload(
        genesis_cli._projection_from_config(canonical_json_line(_config_value(tmp_path)))
    )
    value = json.loads(raw)
    for candidate in (
        b"{ }\n",
        canonical_json_line({**value, "schema_version": "forged"}),
        canonical_json_line({**value, "runtime_input_raw_sha256": "not-a-hash"}),
    ):
        with pytest.raises(RegistryError):
            genesis_cli._projection_from_payload(candidate)


def test_protected_replay_rejects_mixed_caller_inputs_before_catalog_write(
    tmp_path: Path,
) -> None:
    protected = ProtectedGenesisReplayInputs(
        history_receipt_path=tmp_path / "history.json",
        runtime_input_path=tmp_path / "runtime.json",
        runtime_input_raw_sha256="0" * 64,
        service_uid=503,
        service_gid=503,
        history_receipt_raw_sha256="1" * 64,
        manifest_public_key_path=tmp_path / "manifest.pub",
        manifest_public_key_raw_sha256="2" * 64,
        signed_baseline_batch_path=tmp_path / "baseline.json",
        business_public_key_path=tmp_path / "business.pub",
        business_public_key_raw_sha256="3" * 64,
        business_signer_key_id="research-signer-test-0001",
        contract_registry_path=tmp_path / "contracts.json",
        contract_registry_raw_sha256="4" * 64,
        source_month="2026-08",
    )
    with pytest.raises(DailyRollPredecessorCatalogError, match="mixed with caller"):
        publish_predecessor_artifact(
            context=SimpleNamespace(),
            operator_state=SimpleNamespace(),
            history_receipt_path=tmp_path / "forbidden.json",
            pins=None,
            manifest_public_key_path=None,
            official_day="2026-08-21",
            contract_registry_raw=None,
            expected_contract_registry_raw_sha256=None,
            protected_genesis_inputs=protected,
        )
    assert not (tmp_path / "daily-roll-predecessor-catalog-v1").exists()


def test_protected_replay_identity_is_fixed_to_research_service() -> None:
    assert _require_exact_service_identity(503, 503) == (503, 503)
    with pytest.raises(DailyRollPredecessorCatalogError, match="identity is invalid"):
        _require_exact_service_identity(503, 20)


def test_protected_child_drop_binds_saved_identity_groups_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    identity = {"uid": 0, "gid": 0, "groups": [0, 80]}
    account = pwd.struct_passwd(
        ("vnpyresearch", "*", 503, 20, "", "/var/empty", "/usr/bin/false")
    )
    group = grp.struct_group(("vnpyresearch", "*", 503, []))
    monkeypatch.setattr(catalog.pwd, "getpwuid", lambda _uid: account)
    monkeypatch.setattr(catalog.grp, "getgrgid", lambda _gid: group)
    monkeypatch.setattr(
        catalog.os,
        "setgroups",
        lambda groups: identity.update(groups=groups),
    )
    monkeypatch.setattr(catalog.os, "setgid", lambda gid: identity.update(gid=gid))
    monkeypatch.setattr(catalog.os, "setuid", lambda uid: identity.update(uid=uid))
    for name, value in (
        ("getuid", lambda: identity["uid"]),
        ("geteuid", lambda: identity["uid"]),
        ("getgid", lambda: identity["gid"]),
        ("getegid", lambda: identity["gid"]),
        ("getgroups", lambda: identity["groups"]),
    ):
        monkeypatch.setattr(catalog.os, name, value)
    if hasattr(os, "getresuid"):
        monkeypatch.setattr(
            catalog.os,
            "setresuid",
            lambda uid, _effective, _saved: identity.update(uid=uid),
        )
        monkeypatch.setattr(catalog.os, "getresuid", lambda: (503, 503, 503))
    if hasattr(os, "getresgid"):
        monkeypatch.setattr(
            catalog.os,
            "setresgid",
            lambda gid, _effective, _saved: identity.update(gid=gid),
        )
        monkeypatch.setattr(catalog.os, "getresgid", lambda: (503, 503, 503))
    monkeypatch.setattr(catalog.os, "chdir", lambda _path: None)
    monkeypatch.setattr(catalog.os, "umask", lambda _mode: 0o022)
    monkeypatch.setenv("HTTPS_PROXY", "forbidden")

    _drop_to_protected_replay_identity(uid=503, gid=503)

    assert identity == {"uid": 503, "gid": 503, "groups": [503]}
    assert "HTTPS_PROXY" not in os.environ
    assert os.environ["HOME"] == "/Users/Shared/vnpy-research/home"


@pytest.mark.parametrize("primary_gid", [20, 503])
def test_protected_child_drop_accepts_expected_account_with_independent_primary_gid(
    primary_gid: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    identity = {"uid": 0, "gid": 0, "groups": [0]}
    account = pwd.struct_passwd(
        ("vnpyresearch", "*", 503, primary_gid, "", "/var/empty", "/usr/bin/false")
    )
    group = grp.struct_group(("vnpyresearch", "*", 503, []))
    monkeypatch.setattr(catalog.pwd, "getpwuid", lambda _uid: account)
    monkeypatch.setattr(catalog.grp, "getgrgid", lambda _gid: group)
    monkeypatch.setattr(
        catalog.os,
        "setgroups",
        lambda groups: identity.update(groups=groups),
    )
    monkeypatch.setattr(
        catalog.os,
        "setresgid",
        lambda *_values: identity.update(gid=503),
        raising=False,
    )
    monkeypatch.setattr(
        catalog.os,
        "setresuid",
        lambda *_values: identity.update(uid=503),
        raising=False,
    )
    monkeypatch.setattr(catalog.os, "getuid", lambda: identity["uid"])
    monkeypatch.setattr(catalog.os, "geteuid", lambda: identity["uid"])
    monkeypatch.setattr(catalog.os, "getgid", lambda: identity["gid"])
    monkeypatch.setattr(catalog.os, "getegid", lambda: identity["gid"])
    monkeypatch.setattr(catalog.os, "getgroups", lambda: identity["groups"])
    monkeypatch.setattr(
        catalog.os,
        "getresuid",
        lambda: (503, 503, 503),
        raising=False,
    )
    monkeypatch.setattr(
        catalog.os,
        "getresgid",
        lambda: (503, 503, 503),
        raising=False,
    )
    monkeypatch.setattr(catalog.os, "chdir", lambda _path: None)
    monkeypatch.setattr(catalog.os, "umask", lambda _mode: 0o022)

    _drop_to_protected_replay_identity(uid=503, gid=503)

    assert identity == {"uid": 503, "gid": 503, "groups": [503]}


def test_protected_child_drop_rejects_unexpected_account_or_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    group = grp.struct_group(("vnpyresearch", "*", 503, []))
    monkeypatch.setattr(catalog.grp, "getgrgid", lambda _gid: group)
    monkeypatch.setattr(
        catalog.os,
        "setgroups",
        lambda _groups: pytest.fail("zero drop"),
    )
    monkeypatch.setattr(
        catalog.pwd,
        "getpwuid",
        lambda _uid: pwd.struct_passwd(
            ("vnpyresearch", "*", 502, 20, "", "/var/empty", "/usr/bin/false")
        ),
    )
    with pytest.raises(
        DailyRollPredecessorCatalogError,
        match="account identity mismatch",
    ):
        _drop_to_protected_replay_identity(uid=503, gid=503)
    monkeypatch.setattr(
        catalog.pwd,
        "getpwuid",
        lambda _uid: pwd.struct_passwd(
            ("wrong-research", "*", 503, 20, "", "/var/empty", "/usr/bin/false")
        ),
    )
    with pytest.raises(
        DailyRollPredecessorCatalogError,
        match="account identity mismatch",
    ):
        _drop_to_protected_replay_identity(uid=503, gid=503)
    monkeypatch.setattr(
        catalog.pwd,
        "getpwuid",
        lambda _uid: pwd.struct_passwd(
            ("vnpyresearch", "*", 503, 20, "", "/var/empty", "/usr/bin/false")
        ),
    )
    monkeypatch.setattr(
        catalog.grp,
        "getgrgid",
        lambda _gid: grp.struct_group(("wrong-research", "*", 503, [])),
    )
    with pytest.raises(
        DailyRollPredecessorCatalogError,
        match="group identity mismatch",
    ):
        _drop_to_protected_replay_identity(uid=503, gid=503)
    with pytest.raises(DailyRollPredecessorCatalogError, match="identity is invalid"):
        _drop_to_protected_replay_identity(uid=502, gid=503)
    with pytest.raises(DailyRollPredecessorCatalogError, match="identity is invalid"):
        _drop_to_protected_replay_identity(uid=503, gid=20)


def test_protected_child_drop_rejects_missing_account_or_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    monkeypatch.setattr(
        catalog.os,
        "setgroups",
        lambda _groups: pytest.fail("zero drop"),
    )
    monkeypatch.setattr(
        catalog.pwd,
        "getpwuid",
        lambda _uid: (_ for _ in ()).throw(KeyError("missing account")),
    )
    with pytest.raises(DailyRollPredecessorCatalogError, match="account is missing"):
        _drop_to_protected_replay_identity(uid=503, gid=503)
    monkeypatch.setattr(
        catalog.pwd,
        "getpwuid",
        lambda _uid: pwd.struct_passwd(
            ("vnpyresearch", "*", 503, 20, "", "/var/empty", "/usr/bin/false")
        ),
    )
    monkeypatch.setattr(
        catalog.grp,
        "getgrgid",
        lambda _gid: (_ for _ in ()).throw(KeyError("missing group")),
    )
    with pytest.raises(DailyRollPredecessorCatalogError, match="group is missing"):
        _drop_to_protected_replay_identity(uid=503, gid=503)


@pytest.mark.parametrize(
    ("groups", "resuid", "resgid"),
    [
        ([503, 20], (503, 503, 503), (503, 503, 503)),
        ([503, 503], (503, 503, 503), (503, 503, 503)),
        ([503], (503, 503, 0), (503, 503, 503)),
        ([503], (503, 503, 503), (503, 503, 0)),
    ],
)
def test_protected_child_drop_rejects_nonexact_final_identity(
    groups: list[int],
    resuid: tuple[int, int, int],
    resgid: tuple[int, int, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    identity = {"uid": 503, "gid": 503, "groups": groups}
    account = pwd.struct_passwd(
        ("vnpyresearch", "*", 503, 20, "", "/var/empty", "/usr/bin/false")
    )
    group = grp.struct_group(("vnpyresearch", "*", 503, []))
    monkeypatch.setattr(catalog.pwd, "getpwuid", lambda _uid: account)
    monkeypatch.setattr(catalog.grp, "getgrgid", lambda _gid: group)
    monkeypatch.setattr(catalog.os, "setgroups", lambda _groups: None)
    monkeypatch.setattr(catalog.os, "setresgid", lambda *_values: None, raising=False)
    monkeypatch.setattr(catalog.os, "setresuid", lambda *_values: None, raising=False)
    monkeypatch.setattr(catalog.os, "getuid", lambda: identity["uid"])
    monkeypatch.setattr(catalog.os, "geteuid", lambda: identity["uid"])
    monkeypatch.setattr(catalog.os, "getgid", lambda: identity["gid"])
    monkeypatch.setattr(catalog.os, "getegid", lambda: identity["gid"])
    monkeypatch.setattr(catalog.os, "getgroups", lambda: identity["groups"])
    monkeypatch.setattr(catalog.os, "getresuid", lambda: resuid, raising=False)
    monkeypatch.setattr(catalog.os, "getresgid", lambda: resgid, raising=False)
    monkeypatch.setattr(catalog.os, "chdir", lambda _path: None)
    monkeypatch.setattr(catalog.os, "umask", lambda _mode: 0o022)

    with pytest.raises(DailyRollPredecessorCatalogError):
        _drop_to_protected_replay_identity(uid=503, gid=503)


def test_protected_child_closes_inherited_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    calls: list[tuple] = []
    monkeypatch.setattr(catalog.os, "open", lambda *_args: 5)
    monkeypatch.setattr(
        catalog.os,
        "dup2",
        lambda source, target, **_kwargs: calls.append(("dup2", source, target)),
    )
    monkeypatch.setattr(catalog.os, "close", lambda fd: calls.append(("close", fd)))
    monkeypatch.setattr(
        catalog.os,
        "closerange",
        lambda start, stop: calls.append(("closerange", start, stop)),
    )
    assert _close_child_inherited_descriptors(result_fd=4) == 3
    assert ("dup2", 4, 3) in calls
    assert ("closerange", 4, 1 << 20) in calls


def test_protected_pipe_rejects_eof_signal_and_oversize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from research_warehouse import daily_roll_predecessor_catalog as catalog

    def child_result(writer) -> None:
        reader, writer_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            writer(writer_fd)
            os.close(writer_fd)
            os._exit(0)
        os.close(writer_fd)
        try:
            with pytest.raises(DailyRollPredecessorCatalogError):
                _read_protected_replay_payload(descriptor=reader, child=child)
        finally:
            os.close(reader)

    child_result(lambda _fd: None)
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        os.kill(os.getpid(), signal.SIGTERM)
        os._exit(99)
    os.close(writer)
    try:
        with pytest.raises(DailyRollPredecessorCatalogError):
            _read_protected_replay_payload(descriptor=reader, child=child)
    finally:
        os.close(reader)
    monkeypatch.setattr(catalog, "_PROTECTED_REPLAY_MAX_BYTES", 8)
    child_result(lambda fd: os.write(fd, b"x" * 9))


def test_cli_calls_existing_publisher_with_private_replay_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = genesis_cli._projection_from_config(
        canonical_json_line(_config_value(tmp_path))
    )
    state = SimpleNamespace(payload={"last_trade_day": "2026-08-21"})
    context = SimpleNamespace(
        raw_sha256="1" * 64,
    )
    entry = SimpleNamespace(
        receipt_raw=b"receipt\n",
        artifact_raw=b"artifact\n",
        receipt={
            "receipt_id": "daily-roll-catalog-receipt-test",
            "sequence": 1,
            "official_day": "2026-08-21",
        },
        artifact={"artifact_id": "verified-daily-roll-test"},
    )
    captured: dict = {}

    class _Lock:
        def __enter__(self):
            return None

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(genesis_cli, "_require_root", lambda: None)
    monkeypatch.setattr(
        genesis_cli,
        "load_isolation_policy",
        lambda _path: SimpleNamespace(uid=503, gid=503),
    )
    monkeypatch.setattr(
        genesis_cli,
        "load_runtime_input",
        lambda _path, **_kwargs: context,
    )
    monkeypatch.setattr(genesis_cli, "operator_state_lock", lambda *_a, **_k: _Lock())
    monkeypatch.setattr(genesis_cli, "load_operator_state", lambda _path: state)
    monkeypatch.setattr(
        genesis_cli,
        "_load_projection_as_service",
        lambda **_kwargs: projection,
    )

    def publish(**kwargs):
        captured.update(kwargs)
        return entry

    monkeypatch.setattr(genesis_cli, "publish_predecessor_artifact", publish)
    monkeypatch.setattr(
        genesis_cli,
        "load_current_catalog_head",
        lambda _path: SimpleNamespace(
            receipt_raw=entry.receipt_raw,
            artifact_raw=entry.artifact_raw,
        ),
    )
    assert genesis_cli.main(["--continuous-config", str(tmp_path / "config.json")]) == 0
    assert captured["history_receipt_path"] is None
    assert captured["contract_registry_raw"] is None
    protected = captured["protected_genesis_inputs"]
    assert protected.source_month == "2026-08"
    assert protected.history_receipt_path == projection.history_receipt_path


def test_cli_has_no_execution_gateway_or_network_import_seam() -> None:
    source = Path(genesis_cli.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    forbidden = ("app.", "gateway", "windows", "socket", "requests", "http")
    assert not any(
        item.lower().startswith(prefix) for item in imported for prefix in forbidden
    )
