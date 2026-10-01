"""Exercise optional real-source capabilities in fresh, isolated interpreters."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_signal_binding import _build_synthetic_source_days, _build_valid_hypothesis

ROOT = Path(__file__).resolve().parents[3]

CHILD = r'''
import builtins
import hashlib
import json
import sys
from pathlib import Path

root, work, missing = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(root))
original_import = builtins.__import__
blocked = []
def without_optional(name, *args, **kwargs):
    if name.split('.')[0] == missing:
        blocked.append(name)
        raise ModuleNotFoundError('test missing ' + missing, name=missing)
    return original_import(name, *args, **kwargs)
builtins.__import__ = without_optional

from research_lab.alpha_discovery import AlphaDiscoveryEngine, AlphaHypothesis, ResearchMemory
from research_lab.alpha_discovery.signal_binding import SignalBindingError, SyntheticTestEvidence, precheck_candidate_real_data
from research_lab.agent_control.contracts import ProjectBinding
from research_lab.agent_control.discovery_integration import DiscoveryIntegrationOrchestrator
from research_lab.config import ResearchLabConfig
from research_lab.database.result_store import ResultStore

assert 'research_lab.alpha_discovery.real_source_time' not in sys.modules
payload = json.loads((work / 'inputs.json').read_bytes())
hypothesis = payload['hypothesis']
provenance = work / 'synthetic.json'
provenance.write_text(json.dumps({'source_days': payload['source_days']}))
synthetic_sha = hashlib.sha256(provenance.read_bytes()).hexdigest()
report = precheck_candidate_real_data(
    hypothesis, provenance, work / 'synthetic-output', provenance_sha256=synthetic_sha,
    synthetic_test_evidence=SyntheticTestEvidence('synthetic-offline-test-fixture-v1'),
)
assert report['precheck_status'] == 'PRECHECK_PASS'
assert report['derived_snapshot']['row_count'] == 4

# A non-real request continues to produce its ordinary controlled gate error.
try:
    precheck_candidate_real_data(hypothesis, provenance, work / 'untrusted-output', provenance_sha256=synthetic_sha)
except SignalBindingError as exc:
    assert exc.reason == 'MISSING_MARKET_EFFECTIVE_TIME' or exc.reason == 'UNVERIFIED_MARKET_TIME_AUTHORITY'
else:
    raise AssertionError('self-attested source was accepted')

non_real_blocked_count = len(blocked)

# Real-source admission requires optional dependencies and must stop before Engine.
real_days = [dict(day) for day in payload['source_days']]
for day in real_days:
    day.pop('market_time_authority')
    day.pop('market_effective_time')
real_provenance = work / 'real.json'
real_provenance.write_text(json.dumps({'source_days': real_days}))
real_sha = hashlib.sha256(real_provenance.read_bytes()).hexdigest()
try:
    precheck_candidate_real_data(
        hypothesis, real_provenance, work / 'real-output', provenance_sha256=real_sha,
        real_source_bundle_root=work / 'bundle', official_rules_root=work / 'rules',
    )
except SignalBindingError as exc:
    assert exc.reason == 'REAL_SOURCE_DEPENDENCY_UNAVAILABLE', exc.reason
else:
    raise AssertionError('missing capability was accepted')

store = ResultStore(ResearchLabConfig(work / 'store'))
memory = ResearchMemory(store)
engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=work / 'engine')
engine_calls = []
def forbidden_engine(*args, **kwargs):
    engine_calls.append(True)
    raise AssertionError('Engine called after source admission failure')
engine.run_single = forbidden_engine
binding = ProjectBinding(project_id='optional-dependency-test', workspace_identity=str(root))
result = DiscoveryIntegrationOrchestrator(engine, allow_synthetic_passthrough=False).integrate_candidate(
    AlphaHypothesis.model_validate(hypothesis), snapshot_path=Path(report['derived_snapshot']['path']),
    dataset_binding={
        'provenance_path': str(real_provenance), 'provenance_sha256': real_sha,
        'real_source_bundle_root': str(work / 'bundle'), 'official_rules_root': str(work / 'rules'),
    }, project_binding=binding, expected_binding=binding, auto_supplemental=False,
)
assert result.engineering_status == 'ADMISSION_FAILED', result
assert result.error_code == 'REAL_SOURCE_DEPENDENCY_UNAVAILABLE', result
assert result.scientific_decision is None
assert result.critic_decision is None
assert not result.run_refs and not result.evidence_refs and not result.memory_records
assert not engine_calls
assert len(memory.find_by_hypothesis_id(hypothesis['hypothesis_id'])) == 0
assert not list((work / 'engine').rglob('*.csv'))
assert not list((work / 'real-output').rglob('*.csv'))
assert len(blocked) > non_real_blocked_count
print('optional=' + missing + ': import/synthetic pass; real admission blocked before Engine/Critic/Memory')
'''


@pytest.mark.parametrize("missing", ["cryptography", "fcntl"])
def test_missing_real_source_dependency_is_isolated(tmp_path: Path, missing: str) -> None:
    (tmp_path / "inputs.json").write_text(json.dumps({
        "hypothesis": _build_valid_hypothesis(), "source_days": _build_synthetic_source_days(),
    }))
    completed = subprocess.run(
        [sys.executable, "-I", "-c", CHILD, str(ROOT), str(tmp_path), missing],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert f"optional={missing}: import/synthetic pass" in completed.stdout
