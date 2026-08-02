from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_query_v6_preconnect_adapter as subject  # noqa: E402
import commodity_c_fast_t1_query_v6_runtime as runtime  # noqa: E402


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_private(path: Path, payload: dict[str, Any]) -> bytes:
    rendered = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    path.write_bytes(rendered)
    path.chmod(0o600)
    return rendered


def _fixture(tmp_path: Path) -> tuple[SimpleNamespace, bytes]:
    capability = b"c" * subject.CAPABILITY_BYTES
    attempt_id = "attempt-" + "a" * 64
    release_id = "query-v6-release-test-0001"
    consume_path = tmp_path / "consume.json"
    consume = {"attempt_id": attempt_id, "release_id": release_id}
    consume_raw = _write_private(consume_path, consume)
    paths = {
        name: (tmp_path / name)
        for name in (
            "dsn_file",
            "manifest",
            "json_output",
            "csv_output",
            "markdown_output",
            "readonly_proof_output",
            "launch_marker",
            "package_manifest",
        )
    }
    paths["dsn_file"].write_text("never-opened-test-dsn", encoding="utf-8")
    paths["dsn_file"].chmod(0o600)
    paths["manifest"].write_text("{}", encoding="utf-8")
    dsn_info = paths["dsn_file"].lstat()
    args = SimpleNamespace(
        **paths,
        consume_marker=consume_path,
        expected_manifest_sha256=_sha(b"manifest"),
        expected_endpoint_identity_sha256=_sha(b"endpoint"),
        expected_readonly_principal_sha256=_sha(b"readonly"),
        expected_questdb_build_sha256=_sha(b"questdb"),
        expected_dsn_file_identity_sha256=_sha(b"dsn-identity"),
        expected_dsn_device=dsn_info.st_dev,
        expected_dsn_inode=dsn_info.st_ino,
        expected_dsn_owner_uid=dsn_info.st_uid,
        expected_dsn_owner_gid=dsn_info.st_gid,
        expected_dsn_mode=dsn_info.st_mode & 0o777,
        expected_dsn_link_count=dsn_info.st_nlink,
        expected_dsn_size_bytes=dsn_info.st_size,
        consume_raw_sha256=_sha(consume_raw),
        consume_canonical_sha256=_sha(subject.canonical_json(consume)),
        executable_release_raw_sha256="1" * 64,
        foundation_raw_sha256="2" * 64,
        pin_set_manifest_sha256="3" * 64,
        execution_adapter_sha256="4" * 64,
        adapter_package_manifest_sha256="5" * 64,
        adapter_package_root_identity_sha256="6" * 64,
        python_executable_sha256="7" * 64,
        python_dependency_closure_sha256="8" * 64,
    )
    launch = {
        "schema_version": subject.SCHEMA_VERSION,
        "purpose": subject.PURPOSE,
        "candidate_id": subject.CANDIDATE_ID,
        "release_id": release_id,
        "attempt_id": attempt_id,
        "claimed_at": "2026-08-02T12:00:00+00:00",
        "consume_marker_raw_sha256": args.consume_raw_sha256,
        "consume_marker_canonical_sha256": args.consume_canonical_sha256,
        "executable_release_raw_sha256": args.executable_release_raw_sha256,
        "foundation_raw_sha256": args.foundation_raw_sha256,
        "pin_set_manifest_sha256": args.pin_set_manifest_sha256,
        "execution_adapter_sha256": args.execution_adapter_sha256,
        "adapter_package_manifest_sha256": args.adapter_package_manifest_sha256,
        "adapter_package_root_identity_sha256": args.adapter_package_root_identity_sha256,
        "python_executable_sha256": args.python_executable_sha256,
        "python_dependency_closure_sha256": args.python_dependency_closure_sha256,
        "invocation_binding_sha256": subject.invocation_binding_sha256(
            subject._invocation_values(args)
        ),
        "launch_capability_sha256": subject.launch_capability_sha256(capability),
        "consume_verified_before_claim": True,
        "final_revalidation_completed_before_claim": True,
        "launch_claimed": True,
        "dsn_secret_read": False,
        "network_attempted": False,
        "production_query_attempted": False,
        "launch_marker_is_authority": False,
        "database_mutation_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "replay_allowed": False,
    }
    _write_private(paths["launch_marker"], launch)
    return args, capability


def _open_dsn(args: SimpleNamespace) -> int:
    return os.open(
        args.dsn_file,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )


class _Connection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _audit(
    args: SimpleNamespace,
    *,
    endpoint: str = "endpoint",
    principal: str = "readonly",
    build: str = "questdb",
    drift: bool = False,
) -> SimpleNamespace:
    snapshots = [
        SimpleNamespace(principal=principal, questdb_build=build, marker="before"),
        SimpleNamespace(
            principal=principal,
            questdb_build=build,
            marker="after" if drift else "before",
        ),
    ]

    def write(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    return SimpleNamespace(
        EVIDENCE_SCHEMA_PATH=Path("evidence.schema.json"),
        READONLY_PROOF_SCHEMA_PATH=Path("proof.schema.json"),
        load_manifest=lambda _path: ({"manifest": True}, [], [], []),
        canonical_manifest_sha256=lambda _manifest: args.expected_manifest_sha256,
        connected_endpoint_identity_sha256=lambda _conn: _sha(endpoint.encode()),
        collect_readonly_proof_snapshot=lambda _conn: snapshots.pop(0),
        audit=lambda *_values: {"summary": {"p0_pass": True}},
        validate_json_schema=lambda *_values: None,
        build_readonly_proof=lambda *_values: {"proof": True},
        write_text_atomic=write,
        write_csv=lambda path, _evidence: write(path, "csv\n"),
        render_markdown=lambda _evidence: "# pass\n",
    )


def test_v6_claim_and_fake_connection_complete_once(tmp_path: Path) -> None:
    args, capability = _fixture(tmp_path)
    connection = _Connection()
    preflights: list[Path] = []
    assert (
        subject.run(
            args,
            capability=capability,
            dsn_descriptor=_open_dsn(args),
            connector=lambda _path: connection,
            audit_module=_audit(args),
            runtime_preflight=lambda path, **_kwargs: preflights.append(path),
            require_root_owned=False,
        )
        == 0
    )
    assert connection.closed is True
    assert len(preflights) == 2
    assert all(
        path.exists()
        for path in (
            args.json_output,
            args.csv_output,
            args.markdown_output,
            args.readonly_proof_output,
        )
    )


@pytest.mark.parametrize(
    ("kind", "expected"),
    (
        ("endpoint", "connected endpoint mismatch"),
        ("principal", "readonly principal mismatch"),
        ("build", "QuestDB build mismatch"),
        ("drift", "readonly metadata changed"),
    ),
)
def test_identity_and_pre_post_drift_fail_closed(
    tmp_path: Path, kind: str, expected: str
) -> None:
    args, capability = _fixture(tmp_path)
    audit = _audit(
        args,
        endpoint="wrong" if kind == "endpoint" else "endpoint",
        principal="wrong" if kind == "principal" else "readonly",
        build="wrong" if kind == "build" else "questdb",
        drift=kind == "drift",
    )
    with pytest.raises(subject.QueryV6PreconnectError, match=expected):
        subject.run(
            args,
            capability=capability,
            dsn_descriptor=_open_dsn(args),
            connector=lambda _path: _Connection(),
            audit_module=audit,
            runtime_preflight=lambda *_args, **_kwargs: None,
            require_root_owned=False,
        )


def test_capability_or_launch_claim_tamper_blocks_before_connector(
    tmp_path: Path,
) -> None:
    args, capability = _fixture(tmp_path)
    launches = 0

    def connector(_path: Path) -> _Connection:
        nonlocal launches
        launches += 1
        return _Connection()

    with pytest.raises(subject.QueryV6PreconnectError, match="launch marker binding"):
        subject.run(
            args,
            capability=b"x" * len(capability),
            dsn_descriptor=_open_dsn(args),
            connector=connector,
            audit_module=_audit(args),
            runtime_preflight=lambda *_args, **_kwargs: None,
            require_root_owned=False,
        )
    assert launches == 0


def test_package_root_identity_argument_is_inside_exact_invocation_binding(
    tmp_path: Path,
) -> None:
    args, capability = _fixture(tmp_path)
    original = subject._invocation_values(args)
    args.adapter_package_root_identity_sha256 = "f" * 64
    changed = subject._invocation_values(args)
    assert set(original) == set(changed)
    assert subject.invocation_binding_sha256(original) != (
        subject.invocation_binding_sha256(changed)
    )
    with pytest.raises(subject.QueryV6PreconnectError, match="launch marker binding"):
        subject.verify_launch_claim(args, capability, require_root_owned=False)


def test_adapter_cannot_start_standalone_without_inherited_capability() -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(Path(subject.__file__).resolve()), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert result.stderr.strip().endswith("PRECONNECT_BOUNDARY_FAILED")


def test_runner_delivers_capability_only_through_inherited_pipe(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import os\n"
        f"fd=int(os.environ.pop('{subject.CAPABILITY_FD_ENV}'))\n"
        f"dsn_fd=int(os.environ.pop('{subject.DSN_FD_ENV}'))\n"
        "value=os.read(fd, 64)\n"
        "assert os.read(dsn_fd, 64) == b'test-dsn'\n"
        "os.close(fd)\n"
        "os.close(dsn_fd)\n"
        "print(value.hex())\n",
        encoding="utf-8",
    )
    dsn_file = tmp_path / "dsn"
    dsn_file.write_bytes(b"test-dsn")
    dsn_file.chmod(0o600)
    dsn_descriptor = os.open(dsn_file, os.O_RDONLY)
    capability = b"q" * subject.CAPABILITY_BYTES
    try:
        result = runtime.run_adapter(
            [sys.executable, "-I", str(probe)],
            cwd=tmp_path,
            timeout=10,
            launch_capability=capability,
            dsn_descriptor=dsn_descriptor,
        )
    finally:
        os.close(dsn_descriptor)
    assert result.returncode == 0
    assert result.stdout.strip() == capability.hex()
    assert subject.CAPABILITY_FD_ENV not in result.stdout
    assert subject.DSN_FD_ENV not in result.stdout


def test_atomic_dsn_path_replacement_never_reaches_connector(
    tmp_path: Path,
) -> None:
    args, capability = _fixture(tmp_path)
    descriptor = _open_dsn(args)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(
        b"replacement-secret".ljust(args.expected_dsn_size_bytes, b"x")
    )
    replacement.chmod(0o600)
    os.replace(replacement, args.dsn_file)
    connector_calls = 0

    def connector(_dsn: str) -> _Connection:
        nonlocal connector_calls
        connector_calls += 1
        return _Connection()

    with pytest.raises(subject.QueryV6PreconnectError, match="identity mismatch"):
        subject.run(
            args,
            capability=capability,
            dsn_descriptor=descriptor,
            connector=connector,
            audit_module=_audit(args),
            runtime_preflight=lambda *_args, **_kwargs: None,
            require_root_owned=False,
        )
    assert connector_calls == 0


@pytest.mark.parametrize(
    "failure",
    (
        subject.QueryV6PreconnectError(
            "postgresql://readonly:SUPERSECRET@localhost:8812/qdb"
        ),
        RuntimeError("postgresql://readonly:SUPERSECRET@localhost:8812/qdb"),
    ),
)
def test_main_never_prints_secret_bearing_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: Exception,
) -> None:
    dsn_file = tmp_path / "dsn"
    dsn_file.write_text("SUPERSECRET", encoding="utf-8")
    descriptor = os.open(dsn_file, os.O_RDONLY)
    monkeypatch.setattr(subject, "RUNNING_AS_SCRIPT", True)
    monkeypatch.setattr(subject.sys, "flags", SimpleNamespace(isolated=1))
    monkeypatch.setattr(subject, "take_dsn_descriptor", lambda: descriptor)
    monkeypatch.setattr(
        subject, "read_launch_capability", lambda: (_ for _ in ()).throw(failure)
    )

    assert subject.main() == 2
    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "SUPERSECRET" not in rendered
    assert "postgresql://" not in rendered
    assert captured.out == ""
