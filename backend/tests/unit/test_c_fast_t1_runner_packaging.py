from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "scripts/c_fast_t1/validate_packaging.py"
TEMPLATE_PATH = (
    ROOT
    / "docs/operations/c-fast-t1-readonly-override.template.yml"
)
CONTAINERFILE_PATH = ROOT / "scripts/c_fast_t1/Containerfile"
SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-runner-packaging-validation-v1.schema.json"
)

spec = importlib.util.spec_from_file_location(
    "c_fast_t1_validate_packaging",
    SCRIPT_PATH,
)
assert spec is not None and spec.loader is not None
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


def _copy_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    template = tmp_path / "override.yml"
    containerfile = tmp_path / "Containerfile"
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


def test_repository_packaging_contract_passes_and_matches_schema() -> None:
    report = subject.validate_packaging(
        TEMPLATE_PATH,
        CONTAINERFILE_PATH,
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(report))

    assert errors == []
    assert report["status"] == "PASS"
    assert report["activation_allowed"] is False
    assert report["authority_granted"] is False
    assert report["production_queried"] is False
    assert report["database_mutations"] == 0
    assert report["orders_sent"] == 0


def test_rejects_direct_readonly_password(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    environment = payload["services"]["questdb"]["environment"]
    environment["QDB_PG_READONLY_PASSWORD"] = "not-a-real-secret"
    _write_template(template, payload)

    with pytest.raises(
        subject.PackagingValidationError,
        match="dedicated readonly environment",
    ):
        subject.validate_packaging(template, containerfile)


@pytest.mark.parametrize(
    ("forbidden_key", "value"),
    [
        ("QDB_PG_SECURITY_READONLY", "true"),
        ("QDB_READONLY", "true"),
        ("QUESTDB_PG_DSN", "postgresql://example.invalid/qdb"),
    ],
)
def test_rejects_global_readonly_or_writer_configuration(
    tmp_path: Path,
    forbidden_key: str,
    value: str,
) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    environment = payload["services"]["questdb"]["environment"]
    environment[forbidden_key] = value
    _write_template(template, payload)

    with pytest.raises(
        subject.PackagingValidationError,
        match="dedicated readonly environment",
    ):
        subject.validate_packaging(template, containerfile)


def test_rejects_activatable_or_networked_runner(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    payload = _load_template(template)
    runner = payload["services"]["c-fast-t1-audit-package"]
    runner["entrypoint"] = [
        "python",
        "/opt/c-fast-t1/scripts/commodity_c_fast_l1_l5_audit.py",
    ]
    runner["network_mode"] = "default"
    _write_template(template, payload)

    with pytest.raises(
        subject.PackagingValidationError,
        match="packaging-only runner",
    ):
        subject.validate_packaging(template, containerfile)


def test_rejects_containerfile_broad_copy(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    with containerfile.open("a", encoding="utf-8") as file:
        file.write("\nCOPY . /opt/c-fast-t1/unreviewed\n")

    with pytest.raises(
        subject.PackagingValidationError,
        match="forbidden fragment",
    ):
        subject.validate_packaging(template, containerfile)


def test_rejects_containerfile_runnable_entrypoint(tmp_path: Path) -> None:
    template, containerfile = _copy_artifacts(tmp_path)
    text = containerfile.read_text(encoding="utf-8").replace(
        'ENTRYPOINT ["/bin/false"]',
        (
            'ENTRYPOINT ["python", '
            '"/opt/c-fast-t1/scripts/commodity_c_fast_l1_l5_audit.py"]'
        ),
    )
    containerfile.write_text(text, encoding="utf-8")

    with pytest.raises(
        subject.PackagingValidationError,
        match="missing frozen lines",
    ):
        subject.validate_packaging(template, containerfile)


def test_rejects_duplicate_template_key(tmp_path: Path) -> None:
    _, containerfile = _copy_artifacts(tmp_path)
    template = tmp_path / "duplicate.yml"
    template.write_text(
        '{"services": {}, "services": {}, "secrets": {}, '
        '"x-c-fast-t1-preparation-only": {}}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        subject.PackagingValidationError,
        match="duplicate JSON key",
    ):
        subject.validate_packaging(template, containerfile)


def test_rejects_symlinked_template(tmp_path: Path) -> None:
    template = tmp_path / "override.yml"
    template.symlink_to(TEMPLATE_PATH)
    containerfile = tmp_path / "Containerfile"
    shutil.copyfile(CONTAINERFILE_PATH, containerfile)

    with pytest.raises(
        subject.PackagingValidationError,
        match="must not be a symlink",
    ):
        subject.validate_packaging(template, containerfile)


def test_cli_output_is_create_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "validation.json"

    first = subject.main(
        [
            "--template",
            str(TEMPLATE_PATH),
            "--containerfile",
            str(CONTAINERFILE_PATH),
            "--json-output",
            str(output),
        ]
    )
    second = subject.main(
        [
            "--template",
            str(TEMPLATE_PATH),
            "--containerfile",
            str(CONTAINERFILE_PATH),
            "--json-output",
            str(output),
        ]
    )

    assert first == 0
    assert second == 2
    assert output.stat().st_mode & 0o777 == 0o600
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert "cannot create validation output" in capsys.readouterr().err
