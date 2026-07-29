from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from c_fast_t1.validate_query_v4_runtime import (
    QueryV4PackagingError,
    validate_containerfile,
    validate_runtime_template,
)


ROOT = Path(__file__).resolve().parents[3]
RUNTIME_PYTHON = next(
    (
        candidate
        for candidate in (
            ROOT / ".venv/bin/python",
            ROOT / "venv/bin/python",
            Path(sys.executable),
        )
        if candidate.is_file()
    ),
)
CONTAINERFILE = ROOT / "scripts/c_fast_t1/Containerfile.query-v4"
TEMPLATE = (
    ROOT / "docs/operations/c-fast-t1-query-v4-runtime.template.yml"
)


def test_query_v4_packaging_closure_is_valid_but_not_authority() -> None:
    container = validate_containerfile(CONTAINERFILE)
    runtime = validate_runtime_template(TEMPLATE)

    assert container["runtime_source_count"] == 9
    assert container["authority_granted"] is False
    assert runtime["runtime_execution_ready"] is False
    assert runtime["production_query_authorized"] is False
    assert runtime["trading_authorized"] is False


def test_parent_child_and_audit_reach_help_in_real_subprocesses() -> None:
    scripts = ROOT / "scripts"
    parent = scripts / "commodity_c_fast_t1_query_v4.py"
    child = scripts / "commodity_c_fast_t1_query_child_v4.py"
    audit = scripts / "commodity_c_fast_l1_l5_audit_v4.py"
    parent_bootstrap = (
        "import runpy,site;"
        f"site.addsitedir({str(scripts)!r});"
        f"runpy.run_path({str(parent)!r},run_name='__main__')"
    )
    commands = (
        (
            [str(RUNTIME_PYTHON), "-I", "-c", parent_bootstrap, "--help"],
            "--query-release",
        ),
        (
            [str(RUNTIME_PYTHON), "-I", str(child), "--help"],
            "--audit-invocation",
        ),
        (
            [str(RUNTIME_PYTHON), "-I", str(audit), "--help"],
            "--pre-connect-query-gate",
        ),
    )
    for command, expected_flag in commands:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=20,
        )
        assert completed.returncode == 0, completed.stderr
        assert expected_flag in completed.stdout


def test_python_isolated_mode_ignores_poison_pythonpath() -> None:
    poison = "/INVALID_POISON_MUST_BE_IGNORED_BY_PYTHON_ISOLATED_MODE"
    completed = subprocess.run(
        [
            str(RUNTIME_PYTHON),
            "-I",
            "-c",
            f"import sys;assert {poison!r} not in sys.path",
        ],
        env={**os.environ, "PYTHONPATH": poison},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr


def test_containerfile_rejects_readiness_v2_downgrade(
    tmp_path: Path,
) -> None:
    drifted = tmp_path / "Containerfile.query-v4"
    drifted.write_text(
        CONTAINERFILE.read_text().replace(
            "commodity_c_fast_t1_readiness_v3.py",
            "commodity_c_fast_t1_readiness_v2.py",
        )
    )

    with pytest.raises(QueryV4PackagingError):
        validate_containerfile(drifted)


def test_containerfile_rejects_legacy_verifier_copy(
    tmp_path: Path,
) -> None:
    drifted = tmp_path / "Containerfile.query-v4"
    drifted.write_text(
        CONTAINERFILE.read_text().replace(
            "scripts/c_fast_t1/verify_query_v3_image_attestation.py",
            "scripts/c_fast_t1/verify_image_attestation.py",
        )
    )

    with pytest.raises(QueryV4PackagingError):
        validate_containerfile(drifted)


def test_runtime_template_rejects_rpc_authority(
    tmp_path: Path,
) -> None:
    payload = json.loads(TEMPLATE.read_text())
    payload["services"]["c-fast-t1-query-v4"]["environment"][
        "C_FAST_T1_WEB_BRIDGE_RPC_AUTHORIZED"
    ] = "true"
    drifted = tmp_path / "runtime.json"
    drifted.write_text(json.dumps(payload))

    with pytest.raises(
        QueryV4PackagingError,
        match="runtime service environment drifted",
    ):
        validate_runtime_template(drifted)


def test_runtime_template_rejects_readiness_pin_file_splice(
    tmp_path: Path,
) -> None:
    payload = json.loads(TEMPLATE.read_text())
    payload["services"]["c-fast-t1-query-v4"]["volumes"][0]["target"] = (
        "/run/c-fast-t1-readiness-v3-pins/provenance-keyring.sha256"
    )
    drifted = tmp_path / "runtime.json"
    drifted.write_text(json.dumps(payload))

    with pytest.raises(
        QueryV4PackagingError,
        match="mount targets drifted",
    ):
        validate_runtime_template(drifted)
