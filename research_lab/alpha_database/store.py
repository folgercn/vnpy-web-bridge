from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import quote

from research_lab.config import ResearchLabConfig
from research_lab.schemas import (
    AlphaIdea, CriticReview, ExperimentRecord, ExperimentResult, FactorKnowledge,
    FailurePattern, LiteratureReference, ValidationResult,
)

if TYPE_CHECKING:
    from research_lab.database import ResultStore

Asset = TypeVar("Asset", AlphaIdea, ExperimentRecord, FailurePattern, FactorKnowledge, LiteratureReference)
_ASSET_PATH = {
    AlphaIdea: "ideas",
    ExperimentRecord: "experiments",
    FailurePattern: "failure_patterns",
    FactorKnowledge: "factors",
    LiteratureReference: "literature",
}


def _asset_filename(value: str) -> str:
    """Encode every legal identity without lossy filename normalization."""
    return quote(value, safe="._-")


class AlphaDatabase:
    """Git-trackable Markdown and JSON research assets.

    This is a filesystem projection of existing Research Lab results, rather
    than a second execution database.  It does not select, promote, deploy,
    or trade candidates.
    """

    def __init__(
        self, config: ResearchLabConfig, *, result_store: ResultStore | None = None,
        created_commit: str | None = None,
    ) -> None:
        self.config = config
        # Injection keeps tests and offline research runs deterministic. The
        # fallback is deliberately explicit rather than guessing a repository.
        self.created_commit = created_commit or "unavailable"
        self.root = config.root / "alpha_database"
        for directory in _ASSET_PATH.values():
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        if result_store is not None:
            self.sync_from_result_store(result_store)

    def sync_from_result_store(self, store: ResultStore) -> tuple[int, int]:
        """Idempotently project persisted experiment and Critic history.

        The SQLite ResultStore remains the execution index; this writes only
        reviewable JSON/Markdown projections and therefore never requires a
        historical experiment to be run again.
        """
        experiments = store.query()
        for result in experiments:
            self.archive_experiment(result)
        reviews = store.query_critic_reviews()
        for review in reviews:
            self.archive_critic_review(review, validation=store.get_validation(review.validation_id))
        return len(experiments), len(reviews)

    def archive_experiment(self, result: ExperimentResult) -> ExperimentRecord:
        record = ExperimentRecord(
            experiment_id=result.experiment_id,
            status=result.status,
            strategy_name=result.strategy_name,
            factor_name=result.factor_name,
            created_at=result.created_at,
            result_artifact=result.artifact_location,
            report_location=result.report_location,
            error_code=result.error_code,
            error_message=result.error_message,
            metrics=result.metrics.model_dump() if result.metrics else None,
        )
        self.save_experiment(record)
        feature_lineage, dataset_lineage = self._result_lineage(result)
        self._update_factor(
            record.factor_name, record.experiment_id, record.strategy_name,
            feature_lineage=feature_lineage, dataset_lineage=dataset_lineage,
        )
        if result.status == "failed":
            self.save_failure_pattern(FailurePattern(
                pattern_id=f"{result.experiment_id}-failure",
                source_kind="experiment",
                source_id=result.experiment_id,
                strategy_name=result.strategy_name,
                factor_name=result.factor_name,
                category=result.error_code or "BACKTEST_FAILED",
                severity="critical",
                summary=result.error_message or "Experiment failed without a recorded error message.",
                evidence=[f"error_code={result.error_code or 'BACKTEST_FAILED'}"],
            ))
        return record

    def archive_critic_review(
        self, review: CriticReview, *, validation: ValidationResult | None = None,
    ) -> list[FailurePattern]:
        strategy_name, factor_name = self._validation_lineage(validation)
        feature_lineage, dataset_lineage = self._validation_asset_lineage(validation)
        patterns: list[FailurePattern] = []
        for finding in review.findings:
            if finding.assessment == "pass":
                continue
            pattern = FailurePattern(
                pattern_id=f"{review.review_id}-{finding.category}",
                source_kind="critic_review",
                source_id=review.review_id,
                strategy_name=strategy_name,
                factor_name=factor_name,
                category=finding.category,
                severity="critical" if finding.severity == "critical" else "warning",
                summary=finding.summary,
                evidence=[*finding.evidence, *finding.required_additional_tests],
            )
            self.save_failure_pattern(pattern)
            patterns.append(pattern)
        if factor_name:
            self._update_factor(
                factor_name, validation_result_id=review.validation_id,
                feature_lineage=feature_lineage, dataset_lineage=dataset_lineage,
            )
        return patterns

    def save_idea(self, idea: AlphaIdea) -> AlphaIdea:
        return self._save(idea, idea.idea_id)

    def save_experiment(self, record: ExperimentRecord) -> ExperimentRecord:
        return self._save(record, record.experiment_id)

    def save_failure_pattern(self, pattern: FailurePattern) -> FailurePattern:
        saved = self._save(pattern, pattern.pattern_id)
        if saved.factor_name:
            self._update_factor(saved.factor_name, failure_pattern_id=saved.pattern_id)
        return saved

    def save_factor_knowledge(self, knowledge: FactorKnowledge) -> FactorKnowledge:
        return self._save(knowledge, knowledge.factor_name)

    def save_literature_reference(self, reference: LiteratureReference) -> LiteratureReference:
        saved = self._save(reference, reference.reference_id)
        for factor_name in saved.factor_names:
            self._update_factor(factor_name, literature_reference_id=saved.reference_id)
        return saved

    def get_experiment(self, experiment_id: str) -> ExperimentRecord | None:
        return self._load(ExperimentRecord, experiment_id)

    def get_factor_knowledge(self, factor_name: str) -> FactorKnowledge | None:
        return self._load(FactorKnowledge, factor_name)

    def query_experiments(
        self, *, strategy_name: str | None = None, factor_name: str | None = None,
        status: str | None = None,
    ) -> list[ExperimentRecord]:
        records = self._all(ExperimentRecord)
        return [record for record in records if (
            (strategy_name is None or record.strategy_name == strategy_name)
            and (factor_name is None or record.factor_name == factor_name)
            and (status is None or record.status == status)
        )]

    def query_failure_patterns(
        self, *, category: str | None = None, factor_name: str | None = None,
        source_id: str | None = None,
    ) -> list[FailurePattern]:
        patterns = self._all(FailurePattern)
        return [pattern for pattern in patterns if (
            (category is None or pattern.category == category)
            and (factor_name is None or pattern.factor_name == factor_name)
            and (source_id is None or pattern.source_id == source_id)
        )]

    def query_factor_knowledge(self, *, factor_name: str | None = None) -> list[FactorKnowledge]:
        records = self._all(FactorKnowledge)
        return [record for record in records if factor_name is None or record.factor_name == factor_name]

    def query_ideas(self, *, factor_name: str | None = None) -> list[AlphaIdea]:
        records = self._all(AlphaIdea)
        return [record for record in records if factor_name is None or factor_name in record.factor_names]

    def query_literature(self, *, factor_name: str | None = None) -> list[LiteratureReference]:
        records = self._all(LiteratureReference)
        return [record for record in records if factor_name is None or factor_name in record.factor_names]

    def _update_factor(
        self, factor_name: str, experiment_id: str | None = None, strategy_name: str | None = None,
        failure_pattern_id: str | None = None, feature_lineage: list[dict[str, Any]] | None = None,
        dataset_lineage: list[dict[str, Any]] | None = None, literature_reference_id: str | None = None,
        validation_result_id: str | None = None,
    ) -> None:
        current = self.get_factor_knowledge(factor_name) or FactorKnowledge(factor_name=factor_name)
        updated = current.model_copy(update={
            "created_at": datetime.now(timezone.utc),
            "experiment_ids": _append_unique(current.experiment_ids, experiment_id),
            "strategy_names": _append_unique(current.strategy_names, strategy_name),
            "failure_pattern_ids": _append_unique(current.failure_pattern_ids, failure_pattern_id),
            "feature_lineage": _append_unique_mapping(current.feature_lineage, feature_lineage or []),
            "dataset_lineage": _append_unique_mapping(current.dataset_lineage, dataset_lineage or []),
            "literature_reference_ids": _append_unique(current.literature_reference_ids, literature_reference_id),
            "validation_result_ids": _append_unique(current.validation_result_ids, validation_result_id),
        })
        self.save_factor_knowledge(updated)

    def _save(self, asset: Asset, identity: str) -> Asset:
        directory = self.root / _ASSET_PATH[type(asset)]
        stored = asset.model_copy(update={
            "created_commit": asset.created_commit or self.created_commit,
            "integrity_version": "content-hash.v2",
        })
        for existing in self._all(type(asset)):
            if (
                _identity_for(existing) == identity
                and existing.integrity_version == "content-hash.v2"
                and _semantic_hash(existing) == _semantic_hash(stored)
            ):
                return existing
        payload = stored.model_dump(mode="json", exclude={"content_hash"})
        content_hash = _content_hash(payload)
        stored = stored.model_copy(update={"content_hash": content_hash})
        base_path = directory / f"{_asset_filename(identity)}--{content_hash}"
        json_path = base_path.with_suffix(".json")
        if not json_path.exists():
            self._write_json(json_path, stored.model_dump(mode="json"))
            self._write_text(base_path.with_suffix(".md"), self._markdown(stored))
        return stored

    def _load(self, model: type[Asset], identity: str) -> Asset | None:
        matches = [asset for asset in self._all(model) if _identity_for(asset) == identity]
        if not matches:
            return None
        return max(matches, key=lambda asset: (asset.created_at, asset.content_hash))

    def _all(self, model: type[Asset]) -> list[Asset]:
        directory = self.root / _ASSET_PATH[model]
        assets: list[Asset] = []
        for path in sorted(directory.glob("*.json")):
            asset = model.model_validate_json(path.read_text(encoding="utf-8"))
            self._verify_asset(path, asset)
            assets.append(asset)
        return assets

    @staticmethod
    def _verify_asset(path: Path, asset: Asset) -> None:
        """Verify v2 assets fully while retaining pre-v2 historical reads."""
        if not asset.content_hash:
            return
        if asset.integrity_version == "content-hash.v2":
            expected = _content_hash(asset.model_dump(mode="json", exclude={"content_hash"}))
        else:
            # PR #533's first content-addressed format did not cover timestamps.
            # Keep those assets readable, but never create another one that way.
            expected = _content_hash(asset.model_dump(
                mode="json", exclude={"content_hash", "created_at", "integrity_version"},
            ))
        if asset.content_hash != expected or not path.stem.endswith(f"--{asset.content_hash}"):
            raise ValueError(f"asset integrity error: content hash mismatch: {path}")

    @staticmethod
    def _validation_lineage(validation: ValidationResult | None) -> tuple[str | None, str | None]:
        if validation is None or not validation.folds:
            return None, None
        result = validation.folds[0].in_sample
        return result.strategy_name, result.factor_name

    @staticmethod
    def _result_lineage(result: ExperimentResult) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        features = result.details.get("features")
        if not isinstance(features, list) or not all(isinstance(item, dict) for item in features):
            return [], []
        feature_lineage = [dict(item) for item in features]
        dataset_lineage = [
            {"input_data_identity": item["input_data_identity"]}
            for item in feature_lineage if isinstance(item.get("input_data_identity"), str)
        ]
        return feature_lineage, dataset_lineage

    @classmethod
    def _validation_asset_lineage(cls, validation: ValidationResult | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if validation is None:
            return [], []
        features: list[dict[str, Any]] = []
        datasets: list[dict[str, Any]] = []
        for fold in validation.folds:
            for result in (fold.in_sample, fold.out_of_sample):
                result_features, result_datasets = cls._result_lineage(result)
                features = _append_unique_mapping(features, result_features)
                datasets = _append_unique_mapping(datasets, result_datasets)
        return features, datasets

    @staticmethod
    def _markdown(asset: Asset) -> str:
        payload: dict[str, Any] = asset.model_dump(mode="json")
        title = payload.get("title") or payload.get("experiment_id") or payload.get("pattern_id") or payload.get("factor_name")
        summary = _structured_summary(asset)
        lines = [f"# {title}", "", "This is a local research asset. It is not a promotion, deployment, or trading decision.", ""]
        for field in ("hypothesis", "evidence", "conclusion", "next_action"):
            lines.extend((f"## {field}", "", summary[field], ""))
        lines.extend(("## asset", "", "```json", json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2), "```", ""))
        return "\n".join(lines)

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        AlphaDatabase._write_text(path, json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n")

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        temporary_path = path.with_suffix(path.suffix + ".tmp")
        try:
            temporary_path.write_text(content, encoding="utf-8")
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)


def _append_unique(items: list[str], value: str | None) -> list[str]:
    return items if value is None or value in items else [*items, value]


def _append_unique_mapping(items: list[dict[str, Any]], values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    combined = list(items)
    encoded = {json.dumps(item, sort_keys=True, separators=(",", ":")) for item in combined}
    for value in values:
        key = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if key not in encoded:
            combined.append(value)
            encoded.add(key)
    return combined


def _content_hash(payload: object) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _semantic_hash(asset: Asset) -> str:
    """Stable deduplication identity for idempotent ResultStore projection."""
    return _content_hash(asset.model_dump(
        mode="json", exclude={"content_hash", "created_at", "created_commit", "integrity_version"},
    ))


def _structured_summary(asset: Asset) -> dict[str, str]:
    unavailable = "unavailable: this asset does not record it. Required evidence: record it in the source research result."
    if isinstance(asset, AlphaIdea):
        return {
            "hypothesis": asset.hypothesis,
            "evidence": unavailable,
            "conclusion": unavailable,
            "next_action": "required evidence: run a recorded experiment or validation against this idea.",
        }
    if isinstance(asset, ExperimentRecord):
        evidence = json.dumps(asset.metrics, ensure_ascii=False, sort_keys=True) if asset.metrics else (
            "unavailable: no performance metrics were recorded. Required evidence: persisted experiment metrics."
        )
        return {"hypothesis": unavailable, "evidence": evidence, "conclusion": f"recorded experiment status: {asset.status}.", "next_action": unavailable}
    if isinstance(asset, FailurePattern):
        evidence = "\n".join(f"- {item}" for item in asset.evidence) if asset.evidence else (
            "unavailable: no failure evidence was recorded. Required evidence: source logs, metrics, or validation findings."
        )
        return {"hypothesis": unavailable, "evidence": evidence, "conclusion": asset.summary, "next_action": "required evidence: reproduce or test the recorded failure condition."}
    if isinstance(asset, LiteratureReference):
        evidence = f"citation: {asset.citation}" + (f"\nsource: {asset.url}" if asset.url else "\nsource unavailable: a URL was not recorded.")
        return {"hypothesis": unavailable, "evidence": evidence, "conclusion": unavailable, "next_action": "required evidence: review the cited source against a recorded experiment or validation."}
    return {"hypothesis": unavailable, "evidence": unavailable, "conclusion": unavailable, "next_action": "required evidence: link a recorded experiment, validation, failure pattern, or literature source."}


def _identity_for(asset: Asset) -> str:
    if isinstance(asset, AlphaIdea):
        return asset.idea_id
    if isinstance(asset, ExperimentRecord):
        return asset.experiment_id
    if isinstance(asset, FailurePattern):
        return asset.pattern_id
    if isinstance(asset, FactorKnowledge):
        return asset.factor_name
    return asset.reference_id
