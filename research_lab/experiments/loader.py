from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from research_lab.schemas import ExperimentSpec, SweepSpec, ValidationSpec


class ExperimentLoadError(ValueError):
    pass


def load_experiment(path: Path | str) -> ExperimentSpec:
    source = Path(path)
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExperimentLoadError(f"cannot read experiment YAML: {source}") from exc
    if not isinstance(payload, dict):
        raise ExperimentLoadError("experiment YAML must contain a mapping")
    try:
        return ExperimentSpec.model_validate(payload)
    except ValidationError as exc:
        raise ExperimentLoadError("experiment YAML does not match v1 schema") from exc


def load_sweep(path: Path | str) -> SweepSpec:
    source = Path(path)
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExperimentLoadError(f"cannot read sweep YAML: {source}") from exc
    if not isinstance(payload, dict):
        raise ExperimentLoadError("sweep YAML must contain a mapping")
    try:
        return SweepSpec.model_validate(payload)
    except ValidationError as exc:
        raise ExperimentLoadError("sweep YAML does not match v1 schema") from exc


def load_validation(path: Path | str) -> ValidationSpec:
    source = Path(path)
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExperimentLoadError(f"cannot read validation YAML: {source}") from exc
    if not isinstance(payload, dict):
        raise ExperimentLoadError("validation YAML must contain a mapping")
    try:
        return ValidationSpec.model_validate(payload)
    except ValidationError as exc:
        raise ExperimentLoadError("validation YAML does not match v1 schema") from exc
