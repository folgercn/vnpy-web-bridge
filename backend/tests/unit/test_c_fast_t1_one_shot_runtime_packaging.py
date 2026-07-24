from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "scripts/c_fast_t1/validate_one_shot_runtime.py"
TEMPLATE_PATH = (
    ROOT / "docs/operations/c-fast-t1-one-shot-runtime.template.yml"
)
CONTAINERFILE_PATH = ROOT / "scripts/c_fast_t1/Containerfile.one-shot"
SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-one-shot-runtime-validation-v1.schema.json"
)

spec = importlib.util.spec_from_file_location(
    "c_fast_t1_validate_one_shot_runtime",
    SCRIPT_PATH,
)
assert spec is not None and spec.loader is not None
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


def _copy_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    template = tmp_path / "runtime.yml"
    containerfile = tmp_path / "Containerfile.one-shot"
    shutil.copyfile(TEMPLATE_PATH, template)
    shutil.copyfile(CONTAINERFILE_PATH, containerfile)
    return template, containerfile


def _load_template(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_template(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_repository_runtime_contract_passes_and_matches_schema() -> None:
    report = subject.validate_runtime(TEMPLATE_PATH, CONTAINERFILE_PATH)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    assert list(Draft202012Validator(schema).iter_errors(report)) == []
    assert report["status"] == "PASS"
    assert report["deployment_mutation_authorized"] is False
    assert report["production_query_authorized"] is False
    assert report["database_mutations"] == 0
    assert report["orders_sent"] == 0
    assert report["positions_modified"] == 0
    assert report["dispatch_changed"] is False


def test_rejects_missing_one_shot_runner_copy(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    text = containerfile.read_text(encoding="utf-8")
    text = "\n".join(
        line
        for line in text.splitlines()
        if not line.startswith(
            "COPY scripts/commodity_c_fast_t1_one_shot.py "
        )
    )
    containerfile.write_text(text + "\n", encoding="utf-8")

    with pytest.raises(
        subject.RuntimeValidationError,
        match="instruction sequence",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_signing_tool_in_runtime_image(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    with containerfile.open("a", encoding="utf-8") as handle:
        handle.write(
            "\nCOPY scripts/commodity_c_fast_t1_sign_release.py "
            "./scripts/commodity_c_fast_t1_sign_release.py\n"
        )

    with pytest.raises(
        subject.RuntimeValidationError,
        match="instruction sequence",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_lowercase_docker_instruction_bypass(
    tmp_path: Path,
) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    with containerfile.open("a", encoding="utf-8") as handle:
        handle.write(
            "\ncopy scripts /opt/c-fast-t1/unreviewed\n"
            "user 0:0\n"
            'entrypoint ["/bin/sh"]\n'
        )

    with pytest.raises(
        subject.RuntimeValidationError,
        match="instruction sequence",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_unfrozen_buildkit_parser_directive(
    tmp_path: Path,
) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    original = containerfile.read_text(encoding="utf-8")
    containerfile.write_text(
        "# SyNtAx=example.invalid/unreviewed-frontend:latest\n" + original,
        encoding="utf-8",
    )

    with pytest.raises(
        subject.RuntimeValidationError,
        match="parser directives are forbidden",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_missing_cryptography_dependency(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    text = containerfile.read_text(encoding="utf-8").replace(
        '      "cryptography==48.0.0" \\\n',
        "",
    )
    containerfile.write_text(text, encoding="utf-8")

    with pytest.raises(
        subject.RuntimeValidationError,
        match="instruction sequence",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_missing_compiled_bytecode_cleanup(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    text = containerfile.read_text(encoding="utf-8")
    text = text.replace(
        "    && find /opt/c-fast-t1 -type f "
        "\\( -name '*.pyc' -o -name '*.pyo' \\) -delete \\\n",
        "",
    )
    containerfile.write_text(text, encoding="utf-8")

    with pytest.raises(
        subject.RuntimeValidationError,
        match="instruction sequence",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_writer_dsn_or_trade_capability(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    service = payload["services"]["c-fast-t1-one-shot"]
    service["environment"]["QUESTDB_PG_DSN"] = "postgresql://writer.invalid/qdb"
    _write_template(template, payload)

    with pytest.raises(
        subject.RuntimeValidationError,
        match="one-shot service",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_network_or_custody_mount_drift(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    service = payload["services"]["c-fast-t1-one-shot"]
    service["networks"] = ["default"]
    service["volumes"][-1]["read_only"] = True
    _write_template(template, payload)

    with pytest.raises(
        subject.RuntimeValidationError,
        match="one-shot service",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_independent_image_reference_and_digest(
    tmp_path: Path,
) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    service = payload["services"]["c-fast-t1-one-shot"]
    service["image"] = "${C_FAST_T1_RUNTIME_IMAGE:?mutable_or_unbound}"
    _write_template(template, payload)

    with pytest.raises(
        subject.RuntimeValidationError,
        match="one-shot service",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_host_custody_alias(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    service = payload["services"]["c-fast-t1-one-shot"]
    service["volumes"][-1]["source"] = (
        "${C_FAST_T1_CUSTODY_DIR:?arbitrary_host_alias}"
    )
    _write_template(template, payload)

    with pytest.raises(
        subject.RuntimeValidationError,
        match="one-shot service",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_duplicate_template_key(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    template.write_text(
        '{"services": {}, "services": {}, "networks": {}, '
        '"x-c-fast-t1-one-shot-runtime": {}}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        subject.RuntimeValidationError,
        match="duplicate JSON key",
    ):
        subject.validate_runtime(template, containerfile)


def test_rejects_symlinked_runtime_template(tmp_path: Path) -> None:
    template = tmp_path / "runtime.yml"
    template.symlink_to(TEMPLATE_PATH)
    containerfile = tmp_path / "Containerfile.one-shot"
    shutil.copyfile(CONTAINERFILE_PATH, containerfile)

    with pytest.raises(
        subject.RuntimeValidationError,
        match="must not be a symlink",
    ):
        subject.validate_runtime(template, containerfile)


def test_cli_output_is_create_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "validation.json"
    args = [
        "--template",
        str(TEMPLATE_PATH),
        "--containerfile",
        str(CONTAINERFILE_PATH),
        "--json-output",
        str(output),
    ]

    assert subject.main(args) == 0
    assert subject.main(args) == 2
    assert output.stat().st_mode & 0o777 == 0o600
    assert (
        "cannot create runtime validation output"
        in capsys.readouterr().err
    )
