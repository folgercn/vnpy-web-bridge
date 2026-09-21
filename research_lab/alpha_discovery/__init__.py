"""Alpha Discovery MVP: AlphaHypothesis, Cheap Screening Pipeline, Critic Gate, and Research Memory (#562)."""

from research_lab.alpha_discovery.critic_gate import (
    CriticDecision,
    CriticFinding,
    CriticGate,
    validate_critic_decision,
)
from research_lab.alpha_discovery.engine import (
    AlphaDiscoveryEngine,
    DiscoveryBatchResult,
    DiscoveryItemResult,
)
from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    compute_hypothesis_content_hash,
    compute_scientific_identity_hash,
    compute_semantic_hash,
    compute_structured_key,
    is_exact_duplicate,
    is_potentially_related,
    is_valid_revision,
    validate_hypothesis,
)
from research_lab.alpha_discovery.planner import ScreeningPlanner
from research_lab.alpha_discovery.research_memory import (
    ReadOnlyResearchMemoryReader,
    ResearchMemory,
    ResearchMemoryRecord,
)
from research_lab.alpha_discovery.screening import (
    MethodExecutionResult,
    ScreeningPipeline,
    ScreeningPipelineReport,
    SequentialScreeningExecutor,
    build_protocol_v2_spec,
    build_protocol_v2_task,
)
from research_lab.alpha_discovery.screening_plan import (
    DatasetRequirements,
    PlanProvenance,
    ScreeningMethodRequest,
    ScreeningPlan,
    compute_plan_content_hash,
    validate_screening_plan,
)

__all__ = [
    "AlphaDiscoveryEngine",
    "AlphaHypothesis",
    "CriticDecision",
    "CriticFinding",
    "CriticGate",
    "DatasetRequirements",
    "DiscoveryBatchResult",
    "DiscoveryItemResult",
    "MethodExecutionResult",
    "PlanProvenance",
    "ReadOnlyResearchMemoryReader",
    "ResearchMemory",
    "ResearchMemoryRecord",
    "ScreeningMethodRequest",
    "ScreeningPipeline",
    "ScreeningPipelineReport",
    "ScreeningPlan",
    "ScreeningPlanner",
    "SequentialScreeningExecutor",
    "build_protocol_v2_spec",
    "build_protocol_v2_task",
    "compute_hypothesis_content_hash",
    "compute_plan_content_hash",
    "compute_scientific_identity_hash",
    "compute_semantic_hash",
    "compute_structured_key",
    "is_exact_duplicate",
    "is_potentially_related",
    "is_valid_revision",
    "validate_critic_decision",
    "validate_hypothesis",
    "validate_screening_plan",
]
