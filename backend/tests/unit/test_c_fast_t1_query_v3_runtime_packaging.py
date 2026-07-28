from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest


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
SCRIPT_PATH = ROOT / "scripts/c_fast_t1/validate_query_v3_runtime.py"
CONTAINERFILE_PATH = ROOT / "scripts/c_fast_t1/Containerfile.query-v3"
TEMPLATE_PATH = (
    ROOT / "docs/operations/c-fast-t1-query-v3-runtime.template.yml"
)

spec = importlib.util.spec_from_file_location(
    "c_fast_t1_validate_query_v3_runtime",
    SCRIPT_PATH,
)
assert spec is not None and spec.loader is not None
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


def _copy_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    containerfile = tmp_path / "Containerfile.query-v3"
    template = tmp_path / "runtime.template.yml"
    shutil.copyfile(CONTAINERFILE_PATH, containerfile)
    shutil.copyfile(TEMPLATE_PATH, template)
    return containerfile, template


def _load_template(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_template(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _service(payload: dict) -> dict:
    return payload["services"]["c-fast-t1-query-v3"]


def test_repository_query_v3_packaging_is_valid_but_runtime_blocked() -> None:
    report = subject.validate_package(CONTAINERFILE_PATH, TEMPLATE_PATH)

    assert report["status"] == (
        "QUERY_V3_CODE_ONLY_PACKAGING_VALID_RUNTIME_BLOCKED"
    )
    assert report["runtime_execution_ready"] is False
    assert len(report["blocking_reasons"]) == 2
    assert report["image_built"] is False
    assert report["image_pushed"] is False
    assert report["deployed"] is False
    assert report["production_queried"] is False
    assert report["authority_granted"] is False
    assert report["containerfile"]["runtime_source_count"] == 10
    assert report["containerfile"]["schema_source_count"] == 24
    assert report["runtime_template"]["writable_mount_targets"] == [
        "/var/lib/c-fast-t1-readiness"
    ]


def test_parent_child_and_audit_reach_help_in_real_subprocesses() -> None:
    scripts = ROOT / "scripts"
    query_parent = scripts / "commodity_c_fast_t1_query_v3.py"
    query_child = scripts / "commodity_c_fast_t1_query_child_v3.py"
    audit = scripts / "commodity_c_fast_l1_l5_audit.py"
    parent_bootstrap = (
        "import runpy,site;"
        f"site.addsitedir({str(scripts)!r});"
        f"runpy.run_path({str(query_parent)!r},run_name='__main__')"
    )
    commands = (
        (
            [str(RUNTIME_PYTHON), "-I", "-c", parent_bootstrap, "--help"],
            "--query-release",
        ),
        (
            [str(RUNTIME_PYTHON), "-I", str(query_child), "--help"],
            "--audit-invocation",
        ),
        ([str(RUNTIME_PYTHON), "-I", str(audit), "--help"], "--manifest"),
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
    environment = {
        **os.environ,
        "PYTHONPATH": "/INVALID_POISON_MUST_NOT_ENTER_SYS_PATH",
    }
    completed = subprocess.run(
        [
            str(RUNTIME_PYTHON),
            "-I",
            "-c",
            (
                "import sys;"
                "assert "
                "'/INVALID_POISON_MUST_NOT_ENTER_SYS_PATH' not in sys.path"
            ),
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr


def test_rejects_missing_query_child_copy(tmp_path: Path) -> None:
    containerfile, _template = _copy_artifacts(tmp_path)
    text = containerfile.read_text(encoding="utf-8")
    text = "\n".join(
        line
        for line in text.splitlines()
        if "COPY scripts/commodity_c_fast_t1_query_child_v3.py " not in line
    )
    containerfile.write_text(text + "\n", encoding="utf-8")

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="COPY allowlist/order",
    ):
        subject.validate_containerfile(containerfile)


@pytest.mark.parametrize(
    "forbidden_source",
    [
        "scripts/commodity_c_fast_t1_query_v3_sign_release.py",
        "scripts/commodity_c_fast_t1_build_registry_provenance_sign.py",
        "scripts/commodity_c_fast_p0_sign_acceptance_v2.py",
    ],
)
def test_rejects_signing_tools_in_runtime(
    tmp_path: Path,
    forbidden_source: str,
) -> None:
    containerfile, _template = _copy_artifacts(tmp_path)
    with containerfile.open("a", encoding="utf-8") as handle:
        handle.write(f"\nCOPY {forbidden_source} ./{forbidden_source}\n")

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="COPY allowlist/order",
    ):
        subject.validate_containerfile(containerfile)


def test_rejects_legacy_or_direct_script_entrypoint(tmp_path: Path) -> None:
    containerfile, _template = _copy_artifacts(tmp_path)
    expected = "ENTRYPOINT " + json.dumps(subject.ENTRYPOINT)
    legacy = "ENTRYPOINT " + json.dumps(
        [
            "/usr/local/bin/python3.12",
            "-I",
            "/opt/c-fast-t1/scripts/commodity_c_fast_t1_one_shot.py",
        ]
    )
    text = containerfile.read_text(encoding="utf-8").replace(expected, legacy)
    containerfile.write_text(text, encoding="utf-8")

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="isolated ENTRYPOINT",
    ):
        subject.validate_containerfile(containerfile)


def test_rejects_silently_marking_blocked_template_ready(
    tmp_path: Path,
) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    metadata = payload["x-c-fast-t1-query-v3-runtime"]
    metadata["runtime_execution_ready"] = True
    metadata["template_state"] = "READY"
    _write_template(template, payload)

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="metadata/authority boundary",
    ):
        subject.validate_runtime_template(template)


def test_rejects_broad_git_source_root_runtime_mount(tmp_path: Path) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    command = _service(payload)["command"]
    source_index = command.index("--source-root") + 1
    command[source_index] = "/run/c-fast-t1-query-v3-source"
    _service(payload)["volumes"].append(
        {
            "type": "bind",
            "source": (
                "${C_FAST_T1_QUERY_V3_SOURCE_ROOT:"
                "?required_exact_source_checkout}"
            ),
            "target": "/run/c-fast-t1-query-v3-source",
            "read_only": True,
        }
    )
    _write_template(template, payload)

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="broad git source root",
    ):
        subject.validate_runtime_template(template)


def test_rejects_broad_input_directory_mount(tmp_path: Path) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    volumes = _service(payload)["volumes"]
    volumes[1] = {
        "type": "bind",
        "source": (
            "${C_FAST_T1_QUERY_V3_INPUT_DIR:"
            "?required_private_readonly_input_directory}"
        ),
        "target": "/run/c-fast-t1-query-v3-input",
        "read_only": True,
    }
    _write_template(template, payload)

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="exact-file mount targets",
    ):
        subject.validate_runtime_template(template)


def test_rejects_query_release_outside_packet_custody(
    tmp_path: Path,
) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    command = _service(payload)["command"]
    release_index = command.index("--query-release") + 1
    command[release_index] = "/run/c-fast-t1-query-v3-input/query-release.json"
    _write_template(template, payload)

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="escaped its fixed mount",
    ):
        subject.validate_runtime_template(template)


def test_rejects_writable_l3_or_readonly_packet_custody(
    tmp_path: Path,
) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    volumes = _service(payload)["volumes"]
    l3_consume = next(
        volume
        for volume in volumes
        if "L3_CONSUME_BASENAME" in volume["target"]
    )
    l3_consume["read_only"] = False
    packet_custody = next(
        volume
        for volume in volumes
        if volume["target"] == "/var/lib/c-fast-t1-readiness"
    )
    packet_custody["read_only"] = True
    _write_template(template, payload)

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="only packet custody",
    ):
        subject.validate_runtime_template(template)


def test_rejects_missing_failure_sensitive_command_flag(
    tmp_path: Path,
) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    command = _service(payload)["command"]
    index = command.index("--outcome")
    del command[index : index + 2]
    _write_template(template, payload)

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="command shape",
    ):
        subject.validate_runtime_template(template)


def test_rejects_duplicate_template_key(tmp_path: Path) -> None:
    _containerfile, template = _copy_artifacts(tmp_path)
    raw = template.read_text(encoding="utf-8")
    raw = raw.replace(
        '"code_only_template": true,',
        '"code_only_template": true, "code_only_template": true,',
        1,
    )
    template.write_text(raw, encoding="utf-8")

    with pytest.raises(
        subject.QueryV3PackagingError,
        match="duplicate JSON key",
    ):
        subject.validate_runtime_template(template)


def test_validation_report_is_private_create_only(tmp_path: Path) -> None:
    report = subject.validate_package(CONTAINERFILE_PATH, TEMPLATE_PATH)
    output = tmp_path / "validation.json"

    subject.write_report_create_only(output, report)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(
        subject.QueryV3PackagingError,
        match="create-only write failed",
    ):
        subject.write_report_create_only(output, report)
