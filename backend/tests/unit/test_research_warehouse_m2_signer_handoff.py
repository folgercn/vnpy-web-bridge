from __future__ import annotations

import ast
import os
import pwd
import sys
from pathlib import Path
from types import SimpleNamespace

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
    monkeypatch.setattr(m2_signer_handoff.sys, "platform", "linux")
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


def _install_darwin_drop(
    monkeypatch: pytest.MonkeyPatch,
    *,
    observed_groups: list[int] | None = None,
    directory_groups: list[int] | None = None,
    group_names: dict[int, str] | None = None,
    final_gid: int = 503,
    saved_uid: tuple[int, int, int] = (503, 503, 503),
    saved_gid: tuple[int, int, int] = (503, 503, 503),
) -> dict[str, object]:
    groups = directory_groups or [20, 12, 61, 100]
    identity: dict[str, object] = {"uid": 0, "gid": 0, "groups": [0]}
    account = pwd.struct_passwd(
        ("vnpyresearch", "*", 503, 20, "", "/var/empty", "/usr/bin/false")
    )
    names = group_names or {20: "staff", 12: "everyone", 61: "localaccounts", 100: "users"}
    monkeypatch.setattr(m2_signer_handoff.sys, "platform", "darwin")
    monkeypatch.setattr(m2_signer_handoff.pwd, "getpwuid", lambda _uid: account)
    monkeypatch.setattr(
        m2_signer_handoff.os, "getgrouplist", lambda _name, gid: [gid, *groups]
    )
    monkeypatch.setattr(
        m2_signer_handoff.grp,
        "getgrgid",
        lambda gid: SimpleNamespace(gr_name=names[gid]),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "initgroups",
        lambda _name, _gid: identity.update(groups=observed_groups or groups),
    )
    monkeypatch.setattr(
        m2_signer_handoff.os, "setgid", lambda _gid: identity.update(gid=final_gid)
    )
    monkeypatch.setattr(
        m2_signer_handoff.os, "setuid", lambda uid: identity.update(uid=uid)
    )
    monkeypatch.setattr(m2_signer_handoff.os, "getuid", lambda: identity["uid"])
    monkeypatch.setattr(m2_signer_handoff.os, "geteuid", lambda: identity["uid"])
    monkeypatch.setattr(m2_signer_handoff.os, "getgid", lambda: identity["gid"])
    monkeypatch.setattr(m2_signer_handoff.os, "getegid", lambda: identity["gid"])
    monkeypatch.setattr(m2_signer_handoff.os, "getgroups", lambda: identity["groups"])
    monkeypatch.setattr(m2_signer_handoff.os, "getresuid", lambda: saved_uid, raising=False)
    monkeypatch.setattr(m2_signer_handoff.os, "getresgid", lambda: saved_gid, raising=False)
    monkeypatch.setattr(
        m2_signer_handoff.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError()),
    )
    monkeypatch.setattr(m2_signer_handoff.os, "chdir", lambda _path: None)
    monkeypatch.setattr(m2_signer_handoff.os, "umask", lambda _mask: 0o022)
    return identity


def test_darwin_primary_gid_is_not_effective_signer_gid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    identity = _install_darwin_drop(monkeypatch)
    m2_signer_handoff._drop_privileges(503, 503, key_path=tmp_path / "key")
    assert identity["uid"] == 503
    assert identity["gid"] == 503
    assert set(identity["groups"]) == {20, 12, 61, 100}


def test_darwin_nonprivileged_membership_subset_and_order_are_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_darwin_drop(monkeypatch, observed_groups=[100, 12, 20])
    m2_signer_handoff._drop_privileges(503, 503, key_path=tmp_path / "key")


@pytest.mark.parametrize(
    ("observed_groups", "directory_groups", "group_names", "message"),
    [
        ([999], [20, 12], {20: "staff", 12: "everyone"}, "exact identity"),
        ([0], [0, 20], {0: "root", 20: "staff"}, "privileged"),
        ([80], [80, 20], {80: "admin", 20: "staff"}, "privileged"),
    ],
)
def test_darwin_untrusted_or_privileged_groups_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    observed_groups: list[int],
    directory_groups: list[int],
    group_names: dict[int, str],
    message: str,
) -> None:
    _install_darwin_drop(
        monkeypatch,
        observed_groups=observed_groups,
        directory_groups=directory_groups,
        group_names=group_names,
    )
    with pytest.raises(RegistryError, match=message):
        m2_signer_handoff._drop_privileges(503, 503, key_path=tmp_path / "key")


@pytest.mark.parametrize(
    ("final_gid", "saved_uid", "saved_gid", "message"),
    [
        (20, (503, 503, 503), (503, 503, 503), "exact identity"),
        (503, (0, 503, 503), (503, 503, 503), "saved UID"),
        (503, (503, 503, 503), (503, 0, 503), "saved GID"),
    ],
)
def test_darwin_effective_and_saved_identity_remain_exact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    final_gid: int,
    saved_uid: tuple[int, int, int],
    saved_gid: tuple[int, int, int],
    message: str,
) -> None:
    _install_darwin_drop(
        monkeypatch,
        final_gid=final_gid,
        saved_uid=saved_uid,
        saved_gid=saved_gid,
    )
    with pytest.raises(RegistryError, match=message):
        m2_signer_handoff._drop_privileges(503, 503, key_path=tmp_path / "key")


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
