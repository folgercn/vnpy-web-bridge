from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, TypeVar

from research_lab.alpha_database import AlphaDatabase
from research_lab.config import ResearchLabConfig
from research_lab.schemas import ExperimentSpec, ResearchMaterial, ResearchProposal, ResearchTask


Artifact = TypeVar("Artifact", ResearchMaterial, ResearchProposal, ResearchTask)
_DIRECTORIES = {
    ResearchMaterial: "materials", ResearchProposal: "proposals", ResearchTask: "tasks",
}


class AstraDiscovery:
    """Local, deterministic, evidence-bound research proposal generator.

    It persists explicit input material and produces reviewable proposal/task
    artifacts. It does not retrieve information, run experiments, create a
    queue, select candidates, or make promotion, deployment, or trading decisions.
    """

    def __init__(self, config: ResearchLabConfig) -> None:
        self.config = config
        self.root = config.root / "astra_discovery"
        for directory in _DIRECTORIES.values():
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.alpha_database = AlphaDatabase(config)

    @classmethod
    def local(cls, root: Path | str) -> "AstraDiscovery":
        return cls(ResearchLabConfig(Path(root)))

    def ingest(self, material: ResearchMaterial) -> ResearchMaterial:
        """Store a supplied local research record; this method never fetches data."""
        return self._save(material, material.material_id)

    def get_material(self, material_id: str, *, content_hash: str | None = None) -> ResearchMaterial | None:
        """Load one material version; callers must name a hash when versions coexist."""
        items = [item for item in self._all(ResearchMaterial) if item.material_id == material_id]
        if content_hash is not None:
            return next((item for item in items if item.content_hash == content_hash), None)
        if len(items) > 1:
            raise ValueError("multiple material versions found; content_hash is required")
        return items[0] if items else None

    def query_materials(self, *, source_kind: str | None = None, factor_name: str | None = None) -> list[ResearchMaterial]:
        return [item for item in self._all(ResearchMaterial) if (
            (source_kind is None or item.source_kind == source_kind)
            and (factor_name is None or factor_name in item.factor_names)
        )]

    def get_proposal(self, proposal_id: str, *, content_hash: str | None = None) -> ResearchProposal | None:
        """Load one proposal version; callers must name a hash when versions coexist."""
        return self._get(ResearchProposal, proposal_id, content_hash=content_hash)

    def query_proposals(self, *, material_id: str | None = None, status: str | None = None) -> list[ResearchProposal]:
        return [item for item in self._all(ResearchProposal) if (
            (material_id is None or item.material_id == material_id)
            and (status is None or item.status == status)
        )]

    def get_task(self, task_id: str, *, content_hash: str | None = None) -> ResearchTask | None:
        """Load one task version; callers must name a hash when versions coexist."""
        return self._get(ResearchTask, task_id, content_hash=content_hash)

    def query_tasks(self, *, proposal_id: str | None = None, status: str | None = None) -> list[ResearchTask]:
        return [item for item in self._all(ResearchTask) if (
            (proposal_id is None or item.proposal_id == proposal_id)
            and (status is None or item.status == status)
        )]

    def discover(self, material: ResearchMaterial) -> tuple[ResearchProposal, ResearchTask]:
        """Ingest material then derive idempotent evidence-linked proposal and task."""
        stored = self.ingest(material)
        proposal = self._proposal(stored)
        stored_proposal = self._save(proposal, proposal.proposal_id)
        task = self._task(stored, stored_proposal)
        return stored_proposal, self._save(task, task.task_id)

    def _proposal(self, material: ResearchMaterial) -> ResearchProposal:
        factors = list(dict.fromkeys(material.factor_names))
        ideas = [idea for idea in self.alpha_database.query_ideas() if set(idea.factor_names) & set(factors)]
        experiments = [record for factor in factors for record in self.alpha_database.query_experiments(factor_name=factor)]
        failures = [pattern for factor in factors for pattern in self.alpha_database.query_failure_patterns(factor_name=factor)]
        literature = [reference for factor in factors for reference in self.alpha_database.query_literature(factor_name=factor)]
        reasons = _missing_proposal_fields(material)
        critical_failures = [pattern for pattern in failures if pattern.severity == "critical"]
        reasons.extend(f"HISTORICAL_CRITICAL_FAILURE:{pattern.pattern_id}" for pattern in critical_failures)
        notes = [f"{pattern.pattern_id}: {pattern.summary}" for pattern in failures]
        discovery_input_hash = _hash({
            "material_content_hash": material.content_hash,
            "idea_hashes": sorted(idea.content_hash for idea in ideas),
            "experiment_hashes": sorted(record.content_hash for record in experiments),
            "failure_hashes": sorted(pattern.content_hash for pattern in failures),
            "literature_hashes": sorted(reference.content_hash for reference in literature),
        })
        return ResearchProposal(
            proposal_id=_identity("proposal", material.material_id, material.content_hash, discovery_input_hash),
            material_id=material.material_id, material_content_hash=material.content_hash,
            title=material.title, hypothesis=material.hypothesis, economic_logic=material.economic_logic,
            expected_edge=material.expected_edge, required_data=material.required_data,
            validation_plan=material.validation_plan, factor_names=factors,
            evidence=[f"material:{material.material_id}", *material.evidence],
            related_idea_ids=_unique(idea.idea_id for idea in ideas),
            related_experiment_ids=_unique(record.experiment_id for record in experiments),
            related_failure_pattern_ids=_unique(pattern.pattern_id for pattern in failures),
            related_literature_ids=_unique(reference.reference_id for reference in literature),
            failed_pattern_notes=_unique(notes), status="blocked" if reasons else "ready",
            blocked_reasons=_unique(reasons), created_at=material.created_at,
        )

    def _task(self, material: ResearchMaterial, proposal: ResearchProposal) -> ResearchTask:
        reasons = list(proposal.blocked_reasons)
        experiment: ExperimentSpec | None = None
        if material.experiment is None:
            reasons.append("MISSING_EXPERIMENT_SPEC: supply an explicit ExperimentSpec to create a runnable task.")
        else:
            try:
                experiment = ExperimentSpec.model_validate(material.experiment)
            except Exception as exc:
                reasons.append(f"INVALID_EXPERIMENT_SPEC: {exc}")
        if experiment is not None and proposal.factor_names and experiment.factor.name not in proposal.factor_names:
            reasons.append("EXPERIMENT_FACTOR_MISMATCH: ExperimentSpec.factor.name is not linked to the proposal material.")
        if reasons:
            experiment = None
        return ResearchTask(
            task_id=_identity("task", proposal.proposal_id, proposal.content_hash), proposal_id=proposal.proposal_id,
            proposal_content_hash=proposal.content_hash,
            status="blocked" if reasons else "ready",
            experiment=experiment, evidence=proposal.evidence,
            blocked_reasons=_unique(reasons), created_at=proposal.created_at,
        )

    def _save(self, artifact: Artifact, identity: str) -> Artifact:
        model = type(artifact)
        for existing in self._all(model):
            if self._identity(existing) == identity and _semantic_hash(existing) == _semantic_hash(artifact):
                return existing
        stored = artifact.model_copy(update={"content_hash": ""})
        content_hash = _hash(stored.model_dump(mode="json", exclude={"content_hash"}))
        stored = stored.model_copy(update={"content_hash": content_hash})
        path = self.root / _DIRECTORIES[model] / f"{identity}--{content_hash}.json"
        if not path.exists():
            _atomic_write(path, json.dumps(stored.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        return stored

    def _get(self, model: type[Artifact], identity: str, *, content_hash: str | None = None) -> Artifact | None:
        items = [item for item in self._all(model) if self._identity(item) == identity]
        if content_hash is not None:
            return next((item for item in items if item.content_hash == content_hash), None)
        if len(items) > 1:
            raise ValueError("multiple artifact versions found; content_hash is required")
        return items[0] if items else None

    def _all(self, model: type[Artifact]) -> list[Artifact]:
        result: list[Artifact] = []
        for path in sorted((self.root / _DIRECTORIES[model]).glob("*.json")):
            item = model.model_validate_json(path.read_text(encoding="utf-8"))
            expected = _hash(item.model_dump(mode="json", exclude={"content_hash"}))
            if item.content_hash != expected or not path.stem.endswith(f"--{item.content_hash}"):
                raise ValueError(f"artifact integrity error: content hash mismatch: {path}")
            result.append(item)
        return result

    @staticmethod
    def _identity(item: Artifact) -> str:
        if isinstance(item, ResearchMaterial):
            return item.material_id
        if isinstance(item, ResearchProposal):
            return item.proposal_id
        return item.task_id


def _missing_proposal_fields(material: ResearchMaterial) -> list[str]:
    fields = {
        "hypothesis": material.hypothesis, "economic_logic": material.economic_logic,
        "expected_edge": material.expected_edge, "required_data": material.required_data,
        "validation_plan": material.validation_plan,
    }
    reasons = [f"MISSING_{name.upper()}: explicit {name} is required for a research proposal." for name, value in fields.items() if not value]
    if not material.factor_names:
        reasons.append("MISSING_FACTOR_NAMES: explicit candidate factors are required for a research proposal.")
    return reasons


def _identity(prefix: str, *parts: str) -> str:
    text = "-".join((prefix, *parts))
    if len(text) <= 128:
        return text
    return f"{text[:111]}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}"


def _hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _semantic_hash(item: Artifact) -> str:
    return _hash(item.model_dump(mode="json", exclude={"content_hash", "created_at"}))


def _unique(items: Any) -> list[str]:
    return list(dict.fromkeys(items))


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
