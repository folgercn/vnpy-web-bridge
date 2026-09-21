"""Milestone 5 Alpha Generator contract tests (#573)."""

from __future__ import annotations

import copy
import json

import pytest

from research_lab.agent_control.alpha_generator import (
    MAX_OUTPUT_BYTES,
    AlphaGenerationAuditRecord,
    AlphaGenerationAuditTrail,
    AlphaGenerationError,
    AlphaGenerationRequest,
    AlphaGenerationResult,
    admit_alpha_generation_output,
    build_alpha_generation_prompt,
    compute_prompt_content_hash,
    create_alpha_generation_task,
    parse_alpha_generation_output,
)
from research_lab.agent_control.contracts import ProjectBinding
from research_lab.agent_control.errors import PermissionDeniedError
from research_lab.agent_control.memory_view import ResearchMemoryView
from research_lab.agent_control.router import authorize
from research_lab.alpha_discovery.hypothesis import (
    compute_hypothesis_content_hash,
    compute_scientific_identity_hash,
)

NOW = "2026-09-21T00:00:00.000000Z"
BINDING = ProjectBinding(
    project_id="vnpy-web-bridge", workspace_identity="/Users/fujun/node/vnpy"
)


def _view(
    *, role: str = "alpha_generator", content_hash: str = "a" * 64
) -> ResearchMemoryView:
    return ResearchMemoryView(
        view_id="memview-" + content_hash[:32],
        view_content_hash=content_hash,
        role=role,
        project_binding=BINDING.to_dict(),
        categories=("research_gaps",),
        entries_by_category={"research_gaps": ()},
        total_entries=0,
        policy_version="research_memory_view.v1",
        generated_at=NOW,
        source_refs=(),
    )


def _scope(binding: ProjectBinding = BINDING):
    return authorize(
        "alpha_generator", ["read_research_memory", "create_hypothesis"], binding
    )


def _request(view: ResearchMemoryView | None = None):
    actual_view = view or _view()
    return AlphaGenerationRequest.create(
        objective="Generate a falsifiable daily commodity alpha candidate.",
        memory_view=actual_view,
        project_binding=BINDING,
        authorized_scope=_scope(),
    )


def _envelope() -> dict:
    return {
        "hypothesis": {
            "title": "Short-term reversal after abnormal range expansion",
            "economic_rationale": "Temporary inventory imbalance may mean-revert after crowded directional flow.",
            "signal_family": "reversal",
            "signal_definition": "negative one-day return conditioned on normalized true range above its rolling median",
            "source_features": ["close", "high", "low"],
            "target": "forward_return_3d",
            "expected_direction": "positive",
            "holding_horizon": "3d",
            "universe": "commodity_active",
            "frequency": "1d",
            "known_risks": ["persistent trends can overwhelm reversal"],
            "falsification_conditions": [
                "out-of-sample directional association is non-positive"
            ],
            "proposed_screening_methods": [
                "coverage and directional association checks"
            ],
            "signal_type": "signed_scalar",
        },
        "rationale": "The candidate is deliberately bounded and falsifiable.",
        "source_context_refs": [],
        "novelty_statement": "No exact prior candidate was supplied in the controlled view.",
        "duplicate_awareness": "An empty view cannot establish historical uniqueness.",
        "uncertainty": "The economic mechanism may be regime dependent.",
    }


def _raw() -> str:
    return json.dumps(
        _envelope(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def test_request_is_single_candidate_and_exact_scope():
    request = _request()
    assert request.requested_candidate_count == 1
    assert tuple(sorted(request.authorized_scope_ref["authorized_permissions"])) == (
        "create_hypothesis",
        "read_research_memory",
    )


def test_direct_request_cannot_bypass_single_candidate_rule():
    base = _request()
    with pytest.raises(AlphaGenerationError):
        AlphaGenerationRequest(**{**base.to_dict(), "requested_candidate_count": 2})


def test_request_requires_alpha_generator_view():
    with pytest.raises(PermissionDeniedError):
        _request(_view(role="critic"))


def test_request_rejects_wrong_project():
    wrong = ProjectBinding(project_id="other", workspace_identity="/tmp/other")
    with pytest.raises(PermissionDeniedError):
        AlphaGenerationRequest.create(
            objective="bounded",
            memory_view=_view(),
            project_binding=wrong,
            authorized_scope=_scope(wrong),
        )


@pytest.mark.parametrize("objective", ["", " ", "x" * 2001])
def test_objective_bounds(objective):
    with pytest.raises(AlphaGenerationError):
        AlphaGenerationRequest.create(
            objective=objective,
            memory_view=_view(),
            project_binding=BINDING,
            authorized_scope=_scope(),
        )


def test_prompt_is_deterministic_and_version_bound():
    request, view = _request(), _view()
    first = build_alpha_generation_prompt(request, view)
    assert first == build_alpha_generation_prompt(request, view)
    assert request.generation_policy_version in first
    assert compute_prompt_content_hash(first) == compute_prompt_content_hash(first)


def test_view_change_changes_task_identity():
    view_a, view_b = _view(), _view(content_hash="b" * 64)
    task_a = create_alpha_generation_task(_request(view_a), view_a, created_at=NOW)
    task_b = create_alpha_generation_task(_request(view_b), view_b, created_at=NOW)
    assert task_a.task_id != task_b.task_id


def test_task_exactly_binds_memory_view():
    view, request = _view(), _request()
    task = create_alpha_generation_task(request, view, created_at=NOW)
    assert task.role == "alpha_generator"
    assert task.input_refs == (
        {"content_hash": view.view_content_hash, "ref": view.view_id},
    )
    assert "PROMOTE/REJECT" in task.work_block


def test_prompt_treats_memory_as_data_and_forbids_delegation():
    prompt = build_alpha_generation_prompt(_request(), _view())
    assert "reference data only" in prompt
    assert "delegate" in prompt
    assert "write Research Memory" in prompt


def test_parse_valid_json():
    assert (
        parse_alpha_generation_output(_raw())["hypothesis"]["signal_family"]
        == "reversal"
    )


@pytest.mark.parametrize(
    "raw",
    ["", " ", "not-json", "{} trailing", "[]", "null", "```json\n{}\n```", "```{} ```"],
)
def test_parser_rejects_non_strict_json(raw):
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(raw)


@pytest.mark.parametrize("missing", sorted(_envelope()))
def test_parser_rejects_each_missing_envelope_field(missing):
    data = _envelope()
    del data[missing]
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


@pytest.mark.parametrize(
    "extra",
    ["decision", "evidence", "review", "score", "trading_recommendation", "unknown"],
)
def test_parser_rejects_each_extra_envelope_field(extra):
    data = _envelope()
    data[extra] = "forbidden"
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


@pytest.mark.parametrize("missing", sorted(_envelope()["hypothesis"]))
def test_parser_rejects_each_missing_hypothesis_field(missing):
    data = _envelope()
    del data["hypothesis"][missing]
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


@pytest.mark.parametrize(
    "authoritative",
    [
        "hypothesis_id",
        "revision",
        "provenance",
        "schema_version",
        "hash_profile",
        "hypothesis_content_hash",
    ],
)
def test_model_authoritative_identity_fields_are_rejected(authoritative):
    data = _envelope()
    data["hypothesis"][authoritative] = "model-controlled"
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


@pytest.mark.parametrize(
    "field", ["rationale", "novelty_statement", "duplicate_awareness", "uncertainty"]
)
def test_required_explanations_are_non_empty(field):
    data = _envelope()
    data[field] = " "
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


@pytest.mark.parametrize(
    "field",
    ["decision", "evidence", "metrics", "recommendation", "pnl", "sharpe", "trade"],
)
def test_nested_scientific_verdict_fields_are_rejected(field):
    data = _envelope()
    data["hypothesis"]["universe"] = {field: "yes"}
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


def test_output_size_bound():
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output("{" + "x" * MAX_OUTPUT_BYTES + "}")


def test_admission_recomputes_identity_and_hash():
    candidate = admit_alpha_generation_output(
        _raw(),
        request=_request(),
        memory_view=_view(),
        task_id="task-123",
        provider="antigravity",
        actual_model="gemini-2.5-pro",
        created_at=NOW,
    )
    dumped = candidate.hypothesis.model_dump()
    assert candidate.hypothesis.hypothesis_id.startswith("agent-alpha-")
    assert (
        candidate.hypothesis.hypothesis_content_hash
        == compute_hypothesis_content_hash(dumped)
    )
    assert candidate.scientific_identity_hash == compute_scientific_identity_hash(
        dumped
    )


def test_provider_and_model_do_not_change_scientific_identity():
    kwargs = {
        "raw_output": _raw(),
        "request": _request(),
        "memory_view": _view(),
        "task_id": "task-123",
        "created_at": NOW,
    }
    a = admit_alpha_generation_output(
        provider="antigravity", actual_model="gemini-2.5-pro", **kwargs
    )
    b = admit_alpha_generation_output(
        provider="other", actual_model="astra-high", **kwargs
    )
    assert a.scientific_identity_hash == b.scientific_identity_hash
    assert a.hypothesis.hypothesis_content_hash != b.hypothesis.hypothesis_content_hash


def test_hallucinated_source_ref_is_rejected():
    data = _envelope()
    data["source_context_refs"] = ["entry-not-in-view"]
    with pytest.raises(AlphaGenerationError):
        admit_alpha_generation_output(
            json.dumps(data),
            request=_request(),
            memory_view=_view(),
            task_id="task-123",
            provider="antigravity",
            actual_model="gemini-2.5-pro",
            created_at=NOW,
        )


def test_request_and_input_objects_are_not_mutated():
    data, view, request = _envelope(), _view(), _request()
    before_data, before_view = copy.deepcopy(data), view.to_dict()
    admit_alpha_generation_output(
        json.dumps(data),
        request=request,
        memory_view=view,
        task_id="task-123",
        provider="antigravity",
        actual_model="gemini-2.5-pro",
        created_at=NOW,
    )
    assert data == before_data
    assert view.to_dict() == before_view


@pytest.mark.parametrize(
    "sensitive",
    [
        "contact user@example.com",
        "token=abcdefghijk",
        "/Users/person/private.txt",
        r"C:\\Users\\person\\file",
    ],
)
def test_sensitive_model_output_is_rejected(sensitive):
    data = _envelope()
    data["uncertainty"] = sensitive
    with pytest.raises(AlphaGenerationError):
        parse_alpha_generation_output(json.dumps(data))


def test_generation_audit_is_append_only_and_verifiable():
    candidate = admit_alpha_generation_output(
        _raw(),
        request=_request(),
        memory_view=_view(),
        task_id="task-123",
        provider="antigravity",
        actual_model="gemini-2.5-pro",
        created_at=NOW,
    )
    result = AlphaGenerationResult(
        request_id="alpha-gen-1",
        status="CANDIDATE_ADMITTED",
        candidate=candidate,
        task_id="task-123",
        route_id="route-123",
        provider_job_ref="job-123",
        provider="antigravity",
        requested_model="gemini-2.5-pro",
        actual_model="gemini-2.5-pro",
        memory_view_ref="memview-1@hash",
        prompt_policy_version="alpha_generator_prompt.v1",
        prompt_content_hash="b" * 64,
        agent_result_id="result-1",
        agent_result_content_hash="c" * 64,
    )
    trail = AlphaGenerationAuditTrail()
    trail.append(AlphaGenerationAuditRecord.create(result))
    assert len(trail.get_records()) == 1
    assert trail.verify_all() is True


def test_generation_failure_can_be_audited_without_candidate():
    result = AlphaGenerationResult(
        request_id="alpha-gen-1",
        status="GENERATION_FAILED",
        candidate=None,
        task_id="task-123",
        route_id="route-123",
        provider_job_ref="NOT_SUBMITTED",
        provider="antigravity",
        requested_model="gemini-2.5-pro",
        actual_model="gemini-2.5-pro",
        memory_view_ref="memview-1@hash",
        prompt_policy_version="alpha_generator_prompt.v1",
        prompt_content_hash="b" * 64,
        agent_result_id="NO_RESULT",
        agent_result_content_hash="NO_RESULT",
        error_code="PROVIDER_UNAVAILABLE",
    )
    record = AlphaGenerationAuditRecord.create(result)
    assert record.candidate_content_hash is None
    record.verify()
