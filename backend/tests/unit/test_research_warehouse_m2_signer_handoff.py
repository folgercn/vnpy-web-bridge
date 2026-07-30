from __future__ import annotations

import ast
import os
import pwd
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import m2_signer_handoff
from research_warehouse.errors import RegistryError


def test_privilege_drop_is_exact_binds_groups_and_cannot_reopen_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    identity = {"uid": 0, "gid": 0, "groups": [0, 80]}
    account = pwd.struct_passwd(
        ("vnpyresearch", "*", 503, 503, "", "/var/empty", "/usr/bin/false")
    )

    monkeypatch.setattr(
        m2_signer_handoff.pwd,
        "getpwuid",
        lambda uid: account if uid == 503 else pytest.fail("unexpected UID"),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "getgrouplist",
        lambda username, gid: (
            [gid, 12, 61, 100]
            if username == "vnpyresearch"
            else pytest.fail("unexpected user")
        ),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "initgroups",
        lambda username, gid: identity.update(groups=[gid, 12, 61, 100]),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "setgid",
        lambda gid: identity.update(gid=gid),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "setuid",
        lambda uid: identity.update(uid=uid),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "getuid",
        lambda: identity["uid"],
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "geteuid",
        lambda: identity["uid"],
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "getgid",
        lambda: identity["gid"],
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "getegid",
        lambda: identity["gid"],
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "getgroups",
        lambda: identity["groups"],
    )
    if hasattr(os, "getresuid"):
        monkeypatch.setattr(
            m2_signer_handoff.os,
            "getresuid",
            lambda: (identity["uid"],) * 3,
        )
    if hasattr(os, "getresgid"):
        monkeypatch.setattr(
            m2_signer_handoff.os,
            "getresgid",
            lambda: (identity["gid"],) * 3,
        )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError()),
    )
    monkeypatch.setattr(m2_signer_handoff.os, "chdir", lambda _path: None)
    monkeypatch.setattr(m2_signer_handoff.os, "umask", lambda _mask: 0o022)
    monkeypatch.setenv("HTTPS_PROXY", "secret-proxy")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")

    m2_signer_handoff._drop_privileges(
        503,
        503,
        key_path=tmp_path / "root-private.raw",
    )

    assert identity == {"uid": 503, "gid": 503, "groups": [503, 12, 61, 100]}
    assert "HTTPS_PROXY" not in os.environ
    assert "DOCKER_HOST" not in os.environ
    assert os.environ["HOME"] == "/Users/Shared/vnpy-research/home"


def test_handoff_rejects_non_root_before_loading_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(m2_signer_handoff.os, "getuid", lambda: 501)
    monkeypatch.setattr(m2_signer_handoff.os, "geteuid", lambda: 501)
    monkeypatch.setattr(
        m2_signer_handoff,
        "load_private_key",
        lambda _path: pytest.fail("non-root path loaded signer key"),
    )

    with pytest.raises(RegistryError, match="must start as root"):
        m2_signer_handoff.run_with_preloaded_private_key(
            private_key_path=tmp_path / "private.raw",
            service_uid=503,
            service_gid=503,
            operation=lambda _key: {},
        )


def test_collector_import_graph_has_no_signer_or_private_key_path() -> None:
    for relative in (
        "scripts/research_warehouse/m2_scheduler_cli.py",
        "scripts/research_warehouse/m2_daily_scheduler.py",
    ):
        source = (ROOT / relative).read_text()
        imports = {
            node.module
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom)
        }
        assert ".m2_signer_handoff" not in imports
        assert ".m2_manifest_signer_cli" not in imports
        assert "load_private_key" not in source
