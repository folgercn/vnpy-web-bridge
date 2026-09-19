"""Minimal local one-shot v2 execution bridge for Research Lab (#554).

Bridges Protocol v2 Task/Spec admission to existing local execution
capability (#544 data_quality validation) and produces verified
ExperimentRun, ArtifactManifest, and ResultEvidence records.
"""

from __future__ import annotations

import argparse
import builtins
import copy
import shutil
import sys
import tarfile
import types
from pathlib import Path
from typing import Any
from uuid import uuid4

from research_lab.contracts import v2
from research_lab.database import ResultStore
from research_lab.reports import write_v2_report

_DQ_DIR = Path(__file__).resolve().parents[2] / "research/phase0_data_quality"

CONTROLLED_INPUT_SHA256 = "fa9a07c2cd55dc04e3300b01ef6ae0fabfb9d0c2b8813796758612cec6a8da19"
CONTROLLED_PROVENANCE_SOURCE_SHA256 = "f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351"
CONTROLLED_SOURCE_BASE_REVISION = "4c4691c3f1491d54b4a2f84aa24192e33552db67"

CONTROLLED_IMMUTABLE_FILES: dict[str, str] = {
    "case.py": "e754ba79168a6fa665d71dcafc8f29199e858ef48c5b93e3ad357a753290e6a4",
    "quality.py": "6d2a1299c656f8d97d1530cba9c7d3da806554a779df2586806081b6857ed67d",
    "method.json": "6838c60f0053949b1b578d42a911c343ae2e97f220ccf180941d6ac6d65480f0",
    "criteria.json": "c660bc45ba17469631716c501d0b0e94b8020ae2860f477f430ebd50018bf13f",
    "spec.schema.json": "8d3c049668f515d68d76e4905eb7028fb00f8287b108dac1b772884aae38d3ec",
    "handoff.schema.json": "c0fcbc74b53f1c6f5563edc426793ae35a9fa951780a53c6a8cbd2b2e96579ba",
    "payload.schema.json": "b68c33f015c7d1d37d0c4d62016a8cac9f51eba4acceccab626879be621a68cc",
    "provenance.json": "3176a911c55fb0cd2a0f72c8893ef2a947274671af544351096bb08774e758a9",
    "input.csv": "fa9a07c2cd55dc04e3300b01ef6ae0fabfb9d0c2b8813796758612cec6a8da19",
}


def _load_controlled_modules() -> tuple[types.ModuleType, types.ModuleType]:
    """Load the frozen capability without consulting or changing bare-module caches."""
    quality_path = _DQ_DIR / "quality.py"
    case_path = _DQ_DIR / "case.py"

    def read_controlled(path: Path) -> bytes:
        raw = path.read_bytes()
        if v2.sha(raw) != CONTROLLED_IMMUTABLE_FILES[path.name]:
            raise ImportError(f"Controlled module hash mismatch: {path}")
        return raw

    quality = types.ModuleType("_research_lab_v2_controlled_quality")
    quality.__file__ = str(quality_path)
    exec(compile(read_controlled(quality_path), str(quality_path), "exec"), quality.__dict__)  # noqa: S102

    original_import = builtins.__import__

    def case_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "quality":
            return quality
        return original_import(name, globals, locals, fromlist, level)

    case = types.ModuleType("_research_lab_v2_controlled_case")
    case.__file__ = str(case_path)
    case.__dict__["__builtins__"] = {**vars(builtins), "__import__": case_import}
    exec(compile(read_controlled(case_path), str(case_path), "exec"), case.__dict__)  # noqa: S102
    if case.quality is not quality:
        raise ImportError("Controlled case did not bind controlled quality")
    return case, quality


case, quality = _load_controlled_modules()


def _validate_caller_materials_directory(
    materials_dir: Path,
    task_dict: dict[str, Any],
    spec_dict: dict[str, Any],
    raw_bytes: bytes,
    prov_dict: dict[str, Any] | None,
) -> None:
    """Validate caller-provided materials directory before creating any staging.

    Ensures all immutable reference files, source_base_revision, and Task/Spec/Input/Provenance
    are authentic, uncorrupted, and conform to the single source of truth.
    """
    m_path = materials_dir.resolve()
    if not m_path.is_dir():
        raise FileNotFoundError(
            f"Materials directory does not exist or is not a directory: {materials_dir}"
        )

    for fname in ("task.json", "spec.json", "input.csv", "provenance.json"):
        if not (m_path / fname).is_file():
            raise FileNotFoundError(
                f"Missing required material file in {materials_dir}: {fname}"
            )

    # 1. Verification of preparation.json if present
    prep_path = m_path / "preparation.json"
    if prep_path.is_file():
        prep = case.read(prep_path)
        base_rev = prep.get("source_base_revision")
        if base_rev != CONTROLLED_SOURCE_BASE_REVISION:
            raise ValueError(
                f"Invalid preparation.source_base_revision: expected {CONTROLLED_SOURCE_BASE_REVISION}, "
                f"got {base_rev}. Fabricating source revision is prohibited."
            )
        prep_files = prep.get("files", {})
        for fname, expected_sha in CONTROLLED_IMMUTABLE_FILES.items():
            if fname in prep_files and prep_files[fname] != expected_sha:
                raise ValueError(
                    f"Tampered immutable material in {materials_dir}: preparation hash for {fname} mismatch "
                    f"(expected {expected_sha}, got {prep_files[fname]})"
                )

    # 2. Strong verification of immutable material files in materials_dir against repository baseline
    for fname, expected_sha in CONTROLLED_IMMUTABLE_FILES.items():
        file_path = m_path / fname
        if file_path.is_file():
            actual_sha = case.sha(file_path.read_bytes())
            if actual_sha != expected_sha:
                raise ValueError(
                    f"Tampered immutable material in {materials_dir}: {fname} hash mismatch "
                    f"(expected {expected_sha}, got {actual_sha})"
                )

    # 3. Single source of truth verification:
    m_task = v2.parse((m_path / "task.json").read_bytes())
    m_spec = v2.parse((m_path / "spec.json").read_bytes())
    m_raw = (m_path / "input.csv").read_bytes()
    m_prov = v2.parse((m_path / "provenance.json").read_bytes())

    if v2.canonical(task_dict) != v2.canonical(m_task):
        raise ValueError(
            f"Task argument mismatch with {m_path / 'task.json'}: single source of truth violated."
        )
    if v2.canonical(spec_dict) != v2.canonical(m_spec):
        raise ValueError(
            f"Spec argument mismatch with {m_path / 'spec.json'}: single source of truth violated."
        )
    if raw_bytes != m_raw:
        raise ValueError(
            f"Input data argument mismatch with {m_path / 'input.csv'}: single source of truth violated."
        )
    if prov_dict is not None and v2.canonical(prov_dict) != v2.canonical(m_prov):
        raise ValueError(
            f"Provenance argument mismatch with {m_path / 'provenance.json'}: single source of truth violated."
        )


def _admit_before_execution(
    task: dict[str, Any],
    spec: dict[str, Any],
    raw_bytes: bytes,
    output_dir: Path,
    definitions: v2.Definitions,
    provenance: dict[str, Any] | None = None,
) -> None:
    """Strict fail-closed pre-execution admission gate.

    Verifies Task/Spec schemas, content hashes, exact task-spec range/field/universe
    bindings, registered method/criteria catalogue, complete provenance schema,
    and input snapshot SHA256 before any execution begins.
    """
    # 1. Profile / Stage check
    exp_type = spec.get("experiment_type")
    res_stage = spec.get("research_stage")
    if exp_type != "data_quality" or res_stage != "validation":
        raise ValueError(
            f"Unsupported execution profile: ({exp_type!r}, {res_stage!r}). "
            "Phase 1A only admits ('data_quality', 'validation')."
        )
    if task.get("research_type") != "data_quality":
        raise ValueError(f"Task research_type must be 'data_quality', got {task.get('research_type')!r}")

    # 2. Frozen validator: check Task/Spec schemas, hashes, method registration & metric bindings
    v2.validate_spec(spec, task, definitions)

    # 3. Method catalogue registration and implementation check
    checks = spec.get("quality_checks", [])
    if len(checks) != 1:
        raise ValueError(f"Expected exactly 1 quality check, got {len(checks)}")
    check = checks[0]
    if check.get("check_id") != "source_order" or check.get("implementation_ref") != quality.METHOD:
        raise ValueError(f"Unknown quality check: {check}")
    method_def = definitions.method(check["implementation_ref"])
    if method_def.get("id") != quality.METHOD:
        raise ValueError(f"Method ID mismatch: {method_def.get('id')}")

    # 4. Criteria catalogue registration and spec criteria compatibility check
    if spec.get("candidate_decision_criteria") != {"max_allowed_timestamp_reversals": 0}:
        raise ValueError(f"Spec candidate_decision_criteria mismatch: {spec.get('candidate_decision_criteria')}")
    criteria_entries = [
        e
        for e in definitions.entries
        if e["kind"] == "criteria" and (e["name"], e["revision"]) == ("phase0-date-order-criteria", "rev.1")
    ]
    if len(criteria_entries) != 1:
        raise ValueError("phase0-date-order-criteria (rev.1) not found in definitions catalogue")
    _, criterion_def = definitions.resolve(
        "criteria",
        {
            "name": "phase0-date-order-criteria",
            "revision": "rev.1",
            "content_hash": criteria_entries[0]["content_hash"],
            "locator": criteria_entries[0]["locator"],
        },
    )
    if criterion_def.get("maximum") != 0 or criterion_def.get("metric") != quality.METRIC["metric_name"]:
        raise ValueError(f"Criterion definition mismatch in catalogue: {criterion_def}")

    # 5. Exact Task/Spec binding constraints (conforming to #544 case.admission and public execute_spec handoff)
    req = spec.get("dataset_requirements", {})
    task_data = task.get("data_requirements", {})

    # Field binding
    if req.get("required_fields") != quality.FIELDS:
        raise ValueError(
            f"Spec required_fields mismatch: expected {quality.FIELDS}, got {req.get('required_fields')}"
        )
    if task_data.get("fields") != quality.FIELDS:
        raise ValueError(
            f"Task fields mismatch: expected {quality.FIELDS}, got {task_data.get('fields')}"
        )

    # Time range exact binding
    time_range = req.get("time_range", {})
    spec_start = time_range.get("start", "")[:10]
    spec_end = time_range.get("end", "")[:10]
    if spec_start != task_data.get("date_start"):
        raise ValueError(
            f"Task/Spec date_start mismatch: spec has {spec_start}, task has {task_data.get('date_start')}"
        )
    if spec_end != task_data.get("date_end_exclusive"):
        raise ValueError(
            f"Task/Spec date_end_exclusive mismatch: spec has {spec_end}, task has {task_data.get('date_end_exclusive')}"
        )
    if task_data != {
        "products": ["rb"],
        "date_start": "2023-01-03",
        "date_end_exclusive": "2023-02-01",
        "fields": quality.FIELDS,
    }:
        raise ValueError(f"Task data_requirements mismatch with controlled baseline: {task_data}")

    # Universe binding
    if req.get("universe") != task_data.get("products") or req.get("universe") != ["rb"]:
        raise ValueError(
            f"Task/Spec universe mismatch: spec has {req.get('universe')}, task has {task_data.get('products')}"
        )

    # Controlled specification modes
    if req.get("snapshot_selection_mode") != "fixed_snapshot":
        raise ValueError("snapshot_selection_mode must be fixed_snapshot")
    if req.get("provider_kind") != "local_derived_subset":
        raise ValueError("provider_kind must be local_derived_subset")
    if req.get("normalization_rule_version") != "phase0.date-column-as-utc-label.rev1":
        raise ValueError("normalization_rule_version mismatch")
    if req.get("pit_constraints") != (
        "No historical receipt or PIT certification. source_official_day is a date label, not arrival time."
    ):
        raise ValueError("pit_constraints mismatch")
    if spec.get("holdout_policy") != {
        "mode": "not_used",
        "reason": "Historical derived rows; date-order audit only; no confirmation or PIT claim.",
    }:
        raise ValueError("holdout_policy mismatch")
    if spec.get("validation_config") != {"method": "full_sample_scan"}:
        raise ValueError("validation_config mismatch")

    # 6. Input snapshot byte verification & Controlled baseline boundary check (Codex Review Issue C)
    expected_snapshot_sha = req.get("snapshot_sha256")
    actual_snapshot_sha = v2.sha(raw_bytes)
    if actual_snapshot_sha != expected_snapshot_sha:
        raise ValueError(
            f"Input snapshot SHA256 mismatch: expected {expected_snapshot_sha}, "
            f"got {actual_snapshot_sha}. Execution aborted before computation."
        )
    if actual_snapshot_sha != CONTROLLED_INPUT_SHA256:
        raise ValueError(
            f"Input snapshot SHA256 {actual_snapshot_sha} does not match controlled #544 baseline data "
            f"({CONTROLLED_INPUT_SHA256}). Arbitrary raw data injection is prohibited."
        )

    # 7. Provenance binding and schema verification (Codex Review Issue B & C)
    if provenance is None:
        raise ValueError("provenance is required and must bind actual source data")

    # Pre-scan schema validation against phase0-payload.schema.json dataset_metadata.source
    payload_schema = v2.parse(v2.safe_read(v2.DEFINITIONS, "phase0-payload.schema.json"))
    source_schema = payload_schema["$defs"]["dataset_metadata"]["properties"]["source"]
    try:
        v2.schema_check(provenance, source_schema)
    except Exception as exc:
        raise ValueError(
            f"Provenance violates phase0-payload dataset_metadata.source schema: {exc}"
        ) from exc

    if provenance.get("source_sha256") != CONTROLLED_PROVENANCE_SOURCE_SHA256:
        raise ValueError(
            f"Provenance source_sha256 mismatch: expected {CONTROLLED_PROVENANCE_SOURCE_SHA256}, "
            f"got {provenance.get('source_sha256')}"
        )

    proj_prefix = provenance.get("projection", "").split(";", 1)[0].strip()
    expected_proj = ",".join(req.get("universe", []))
    if proj_prefix != expected_proj:
        raise ValueError(f"Provenance projection mismatch: expected {expected_proj}, got {proj_prefix}")
    if not (isinstance(provenance.get("source_bytes"), int) and provenance["source_bytes"] > 0):
        raise ValueError(
            f"Invalid provenance source_bytes: {provenance.get('source_bytes')}"
        )

    # 8. Pre-execution exclusivity check: output directory must NOT exist
    if output_dir.exists():
        raise FileExistsError(
            f"Target directory {output_dir} already exists. Overwriting existing runs is strictly prohibited."
        )


def _validate_with_public_handoff(
    output_dir: Path,
    task: dict[str, Any],
    spec: dict[str, Any],
) -> None:
    """Independently re-consume execution results via the frozen public v2.validate_handoff API."""
    run = v2.parse((output_dir / "run.json").read_bytes())
    manifest = v2.parse((output_dir / "manifest.json").read_bytes())
    evidence = v2.parse((output_dir / "evidence.json").read_bytes())

    request = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"handoff-{run['run_id']}",
        "message_kind": "request",
        "operation": "execute_spec",
        "sender_role": "research",
        "recipient_role": "execution",
        "context_refs": {
            "research_task": v2.check_record(task, "research_task"),
            "experiment_spec": v2.check_record(spec, "experiment_spec"),
        },
        "artifact_requirements": {
            "role_profile_ref": v2.ROLE_PROFILE,
            "required_roles": sorted(v2.COMMON | v2.TYPED["data_quality"]),
            "exact_refs": [],
        },
        "expected_outputs": [
            {"object_type": "experiment_run", "schema_version": "research_lab.run.v2"},
            {"object_type": "artifact_manifest", "schema_version": "research_lab.artifact_manifest.v2"},
            {"object_type": "result_evidence", "schema_version": "research_lab.evidence.v2"},
        ],
    }

    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"response-{run['run_id']}",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": "completed",
        "output_refs": [
            v2.check_record(run, "experiment_run"),
            v2.check_record(manifest, "artifact_manifest"),
            v2.check_record(evidence, "result_evidence"),
        ],
    }

    objects = {
        "research_task": task,
        "experiment_spec": spec,
        "experiment_run": run,
        "artifact_manifest": manifest,
        "result_evidence": evidence,
    }

    # Frozen public API consumption
    v2.validate_handoff(request, objects, response, root=output_dir)


class V2ExecutionBridge:
    """Minimal local one-shot v2 execution bridge.

    Strictly supports only ('data_quality', 'validation').
    Directly reuses existing #544 local execution capability while enforcing
    fail-closed pre-execution admission and post-execution public handoff validation.
    """

    def __init__(self, definitions: v2.Definitions | None = None, result_store: ResultStore | None = None) -> None:
        self.definitions = definitions or v2.Definitions()
        self.result_store = result_store

    def execute(
        self,
        task: dict[str, Any] | Path | str,
        spec: dict[str, Any] | Path | str,
        input_data: bytes | Path | str,
        output_dir: Path | str,
        *,
        provenance: dict[str, Any] | Path | str | None = None,
        materials_dir: Path | str | None = None,
    ) -> dict[str, Any]:
        """Execute a data_quality validation experiment under Protocol v2 rules."""
        target_dir = Path(output_dir).resolve()
        task_dict = self._load_dict(task)
        spec_dict = self._load_dict(spec)
        raw_bytes = self._load_bytes(input_data)
        prov_dict = self._load_dict(provenance) if provenance is not None else None

        # 1. Pre-staging fail-closed checks: validate caller materials and admission before any staging
        if materials_dir is not None:
            _validate_caller_materials_directory(
                materials_dir=Path(materials_dir),
                task_dict=task_dict,
                spec_dict=spec_dict,
                raw_bytes=raw_bytes,
                prov_dict=prov_dict,
            )

        # Fail-closed pre-execution admission gate (aborts BEFORE any staging or computation starts)
        _admit_before_execution(
            task=task_dict,
            spec=spec_dict,
            raw_bytes=raw_bytes,
            output_dir=target_dir,
            definitions=self.definitions,
            provenance=prov_dict,
        )

        # 2. Capture into isolated private staging snapshot
        repo_root = Path(v2.ROOT)
        tmp_base = repo_root / "tmp"
        tmp_base.mkdir(parents=True, exist_ok=True)
        staged_path = tmp_base / f"stage-{uuid4().hex}"
        staged_path.mkdir(parents=True, exist_ok=True)

        try:
            # Assemble from trusted repository baseline template
            archive_path = repo_root / "research/phase0_data_quality/prepared-inputs.tar.gz"
            with tarfile.open(archive_path) as tf:
                tf.extractall(staged_path, filter="data")

            # Write captured Task, Spec, Input, Provenance into isolated private staging
            staged_path.joinpath("task.json").write_text(case.canonical(task_dict) + "\n")
            staged_path.joinpath("spec.json").write_text(case.canonical(spec_dict) + "\n")
            staged_path.joinpath("input.csv").write_bytes(raw_bytes)
            if prov_dict is not None:
                staged_path.joinpath("provenance.json").write_text(case.canonical(prov_dict) + "\n")

            # Synchronize preparation.json for this snapshot:
            # source_base_revision and immutable files are locked to trusted baseline;
            # task.json and spec.json bind exact snapshot hashes.
            prep = case.read(staged_path / "preparation.json")
            prep["source_base_revision"] = CONTROLLED_SOURCE_BASE_REVISION
            for k, expected_sha in CONTROLLED_IMMUTABLE_FILES.items():
                prep["files"][k] = expected_sha
            prep["files"]["task.json"] = case.sha(staged_path.joinpath("task.json").read_bytes())
            prep["files"]["spec.json"] = case.sha(staged_path.joinpath("spec.json").read_bytes())
            staged_path.joinpath("preparation.json").write_text(case.canonical(prep) + "\n")

            # Dual admission check on the captured snapshot itself:
            # a) frozen v2 pre-admission on snapshot
            _admit_before_execution(
                task=v2.parse(staged_path.joinpath("task.json").read_bytes()),
                spec=v2.parse(staged_path.joinpath("spec.json").read_bytes()),
                raw_bytes=staged_path.joinpath("input.csv").read_bytes(),
                output_dir=target_dir,
                definitions=self.definitions,
                provenance=v2.parse(staged_path.joinpath("provenance.json").read_bytes()),
            )
            # b) case.admission check on snapshot
            case.admission(staged_path)

            # 3. Execute the exact captured snapshot via local capability (#544 case.run_case)
            case.run_case(staged_path, target_dir)
        finally:
            if staged_path.exists():
                shutil.rmtree(staged_path, ignore_errors=True)
            try:
                tmp_base.rmdir()
            except OSError:
                pass

        # 4. Independent re-consumption via public validate_handoff API
        _validate_with_public_handoff(target_dir, task_dict, spec_dict)

        run_record = v2.parse((target_dir / "run.json").read_bytes())
        manifest_record = v2.parse((target_dir / "manifest.json").read_bytes())
        evidence_record = v2.parse((target_dir / "evidence.json").read_bytes())
        stored_result = None
        report_path = None
        if self.result_store is not None:
            stored_result = self.result_store.save_v2(target_dir)
            temp_report_path = write_v2_report(self.result_store.config.artifacts_dir, stored_result)
            report_record = self.result_store.save_v2_report(stored_result, temp_report_path)
            report_path = Path(report_record["report_location"])

        return {
            "run": run_record,
            "manifest": manifest_record,
            "evidence": evidence_record,
            "output_dir": target_dir,
            "run_status": run_record["run_status"],
            "process_exit_code": run_record["process_exit_code"],
            "stored_result": stored_result,
            "report_path": report_path,
        }

    def execute_from_materials(
        self,
        materials_dir: Path | str,
        output_dir: Path | str,
    ) -> dict[str, Any]:
        """Convenience loader from a materials directory containing task.json, spec.json, input.csv, provenance.json."""
        mdir = Path(materials_dir).resolve()
        task_path = mdir / "task.json"
        spec_path = mdir / "spec.json"
        input_path = mdir / "input.csv"
        prov_path = mdir / "provenance.json"

        if not task_path.is_file():
            raise FileNotFoundError(f"Missing task.json in {materials_dir}")
        if not spec_path.is_file():
            raise FileNotFoundError(f"Missing spec.json in {materials_dir}")
        if not input_path.is_file():
            raise FileNotFoundError(f"Missing input.csv in {materials_dir}")
        if not prov_path.is_file():
            raise FileNotFoundError(f"Missing provenance.json in {materials_dir}")

        return self.execute(
            task=task_path,
            spec=spec_path,
            input_data=input_path,
            output_dir=output_dir,
            provenance=prov_path,
            materials_dir=mdir,
        )

    def _load_dict(self, obj: dict[str, Any] | Path | str) -> dict[str, Any]:
        if isinstance(obj, dict):
            return copy.deepcopy(obj)
        path = Path(obj)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {obj}")
        return v2.parse(path.read_bytes())

    def _load_bytes(self, obj: bytes | Path | str) -> bytes:
        if isinstance(obj, bytes):
            return obj
        path = Path(obj)
        if not path.is_file():
            raise FileNotFoundError(f"Input file not found: {obj}")
        return path.read_bytes()


def execute_v2_spec(
    task: dict[str, Any] | Path | str,
    spec: dict[str, Any] | Path | str,
    input_data: bytes | Path | str,
    output_dir: Path | str,
    *,
    provenance: dict[str, Any] | Path | str | None = None,
    definitions: v2.Definitions | None = None,
    result_store: ResultStore | None = None,
) -> dict[str, Any]:
    """Functional entrypoint for V2ExecutionBridge.execute."""
    bridge = V2ExecutionBridge(definitions=definitions, result_store=result_store)
    return bridge.execute(
        task=task,
        spec=spec,
        input_data=input_data,
        output_dir=output_dir,
        provenance=provenance,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Protocol v2 local one-shot execution bridge")
    parser.add_argument("--task", help="Path to research_task JSON")
    parser.add_argument("--spec", help="Path to experiment_spec JSON")
    parser.add_argument("--input", help="Path to input data (e.g. CSV)")
    parser.add_argument("--provenance", help="Path to provenance JSON")
    parser.add_argument("--materials", help="Path to materials directory containing task, spec, input, provenance")
    parser.add_argument("--output", required=True, help="Path to output run directory")
    args = parser.parse_args()

    bridge = V2ExecutionBridge()
    try:
        if args.materials:
            result = bridge.execute_from_materials(args.materials, args.output)
        else:
            if not (args.task and args.spec and args.input and args.provenance):
                parser.error("Must provide --materials or all of --task, --spec, --input, --provenance")
            result = bridge.execute(
                task=args.task,
                spec=args.spec,
                input_data=args.input,
                output_dir=args.output,
                provenance=args.provenance,
            )
        print(v2.canonical({
            "run_id": result["run"]["run_id"],
            "run_status": result["run_status"],
            "scientific_fingerprint": result["run"]["scientific_fingerprint"],
        }))
        return result["process_exit_code"]
    except Exception as exc:  # noqa: BLE001 - CLI entrypoint catches all exceptions
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
