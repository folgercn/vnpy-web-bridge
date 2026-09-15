"""Focused tests for this single offline case, not other research types."""
import copy
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

import case
import pytest
import quality

HERE = Path(__file__).parent


def overwrite(path, value):
    path.write_text(case.canonical(value) + '\n')


def rebind(m, spec=None):
    if spec is not None:
        overwrite(m / 'spec.json', case.seal(spec, 'spec_content_hash'))
    prep = case.read(m / 'preparation.json')
    prep['files'] = {p.name: case.sha(p.read_bytes()) for p in m.iterdir() if p.name != 'preparation.json'}
    overwrite(m / 'preparation.json', prep)


@pytest.fixture
def materials(tmp_path):
    m = tmp_path / 'materials'
    with tarfile.open(HERE / 'prepared-inputs.tar.gz') as tf:
        tf.extractall(m, filter='data')
    return m


@pytest.fixture
def bundle(materials, tmp_path):
    b = tmp_path / 'bundle'
    case.run_case(materials, b)
    return b


def test_spec_drives_range_and_repeat(materials, tmp_path):
    a, b, c = (tmp_path / name for name in ('a', 'b', 'c'))
    case.run_case(materials, a)
    case.run_case(materials, b)
    av, bv = case.verify(a), case.verify(b)
    assert av['facts'] == bv['facts'] and av['scientific_fingerprint'] == bv['scientific_fingerprint']
    assert av['run_id'] != bv['run_id']
    spec = case.read(materials / 'spec.json')
    spec['revision'] = 'rev.2'
    spec['dataset_requirements']['time_range']['end'] = '2023-01-10T00:00:00.000000Z'
    rebind(materials, spec)
    case.run_case(materials, c)
    assert 0 < case.verify(c)['facts']['row_count'] < av['facts']['row_count']
    with pytest.raises(FileExistsError):
        case.run_case(materials, a)


def test_defects_and_strict_parameter(materials, tmp_path):
    # Synthetic copy only; preserve the real bundled historical bytes.
    raw = b'source_official_day,product,exact_contract\n2023-01-04,rb,SHFE.rb2305\n2023-01-04,rb,SHFE.rb2305\n2023-01-03,rb,SHFE.rb2305\n'
    (materials / 'input.csv').write_bytes(raw)
    spec = case.read(materials / 'spec.json')
    spec['dataset_requirements']['snapshot_sha256'] = case.sha(raw)
    rebind(materials, spec)
    a = tmp_path / 'defects'
    case.run_case(materials, a)
    result = case.verify(a)
    assert result['run_status'] == 'COMPLETED'
    assert result['facts'] == {'row_count': 3, 'comparison_count': 2, 'timestamp_monotonicity_violations': 2, 'duplicate_key_excess_rows': 1, 'source_order_reversals': 1}
    spec['revision'] = 'rev.2'
    spec['quality_checks'][0]['parameters'] = [{'name': 'strict', 'value_type': 'boolean', 'unit': 'dimensionless', 'value': False}]
    rebind(materials, spec)
    b = tmp_path / 'nonstrict'
    case.run_case(materials, b)
    assert case.verify(b)['facts']['timestamp_monotonicity_violations'] == 1


@pytest.mark.parametrize('mutation', ['missing_input', 'input_hash', 'method', 'metric', 'unknown_parameter', 'range', 'task', 'criteria'])
def test_reject_before_execution(materials, tmp_path, mutation):
    spec = case.read(materials / 'spec.json')
    if mutation == 'missing_input':
        (materials / 'input.csv').unlink()
    elif mutation == 'input_hash':
        spec['dataset_requirements']['snapshot_sha256'] = 'a' * 64
    elif mutation == 'method':
        spec['quality_checks'][0]['implementation_ref'] = 'unknown'
    elif mutation == 'metric':
        spec['metric_specifications'][0]['calculation_definition'] = 'invented formula'
    elif mutation == 'unknown_parameter':
        spec['quality_checks'][0]['parameters'] = [{'name': 'other', 'value_type': 'boolean', 'unit': 'dimensionless', 'value': True}]
    elif mutation == 'range':
        spec['dataset_requirements']['time_range']['start'] = spec['dataset_requirements']['time_range']['end']
    elif mutation == 'task':
        spec['task_content_hash'] = 'a' * 64
    elif mutation == 'criteria':
        c = case.read(materials / 'criteria.json')
        c['maximum'] = 999
        overwrite(materials / 'criteria.json', c)
    rebind(materials, spec)
    b = tmp_path / 'rejected'
    with pytest.raises((ValueError, OSError)):
        case.run_case(materials, b)
    assert not b.exists()


def test_started_failure_kept(materials, tmp_path):
    b = tmp_path / 'failed'
    with patch.object(quality, 'scan', side_effect=RuntimeError('injected test-only calculation failure')):
        run = case.run_case(materials, b)
    assert run['run_status'] == 'FAILED'
    assert case.verify(b)['facts'] is None
    assert case.read(b / 'payload/failure_diagnostics.json')['error_type'] == 'RuntimeError'
    assert case.read(b / 'review-request.json')['review_scope'] == 'failure_diagnosis'


@pytest.mark.parametrize('mutation', ['missing', 'corrupt', 'symlink', 'evidence_fact', 'role', 'time'])
def test_bad_delivery(bundle, mutation):
    if mutation == 'missing':
        (bundle / 'payload/quality_anomalies.json').unlink()
    elif mutation == 'corrupt':
        (bundle / 'payload/quality_summary.json').write_bytes(b'{}')
    elif mutation == 'symlink':
        p = bundle / 'payload/quality_summary.json'
        content = p.read_bytes()
        p.unlink()
        elsewhere = bundle.parent / 'elsewhere.json'
        elsewhere.write_bytes(content)
        p.symlink_to(elsewhere)
    elif mutation == 'evidence_fact':
        e = case.read(bundle / 'evidence.json')
        e['typed_metrics'][0]['value'] += 1
        overwrite(bundle / 'evidence.json', case.seal(e, 'evidence_content_hash'))
        request = case.read(bundle / 'review-request.json')
        request['context_refs']['result_evidence']['content_hash'] = e['evidence_content_hash']
        overwrite(bundle / 'review-request.json', request)
    elif mutation == 'role':
        m = case.read(bundle / 'manifest.json')
        m['entries'] = m['entries'][:-1]
        overwrite(bundle / 'manifest.json', case.seal(m, 'manifest_content_hash'))
    elif mutation == 'time':
        r = case.read(bundle / 'run.json')
        r['timing']['started_at'] = '2000-01-01T00:00:00.000000Z'
        overwrite(bundle / 'run.json', case.seal(r, 'run_content_hash'))
    with pytest.raises((ValueError, OSError)):
        case.verify(bundle)


def add_test_review(b, wrong=False):
    e, request = case.read(b / 'evidence.json'), case.read(b / 'review-request.json')
    criteria = copy.deepcopy(request['criteria_ref'])
    if wrong:
        criteria['revision'] = 'rev.2'
    review = case.seal({'schema_version': 'research_lab.review.v2', 'hash_profile': case.PROFILE,
        'review_id': 'review-test-only', 'revision': 'rev.1', 'evidence_id': e['evidence_id'], 'evidence_content_hash': e['evidence_content_hash'],
        'reviewer': 'synthetic test reviewer, not independent acceptance', 'reviewed_at': case.stamp(), 'criteria_ref': criteria,
        'recommendation': 'accept', 'reason': 'Test fixture only.'}, 'review_content_hash')
    case.save(b / 'review.json', review)
    case.save(b / 'review-response.json', case.review_response(request, review))


def test_review_criteria_binding(bundle):
    add_test_review(bundle, wrong=True)
    with pytest.raises(ValueError, match='criteria_ref'):
        case.verify(bundle, require_review=True)


def test_clean_directory_consumer_and_replay(bundle, tmp_path):
    clean = tmp_path / 'clean'
    shutil.copytree(bundle, clean)
    add_test_review(clean)
    result = subprocess.run([sys.executable, str(clean / 'materials/case.py'), 'verify', '--bundle', str(clean), '--require-review'], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    replay = tmp_path / 'replay'
    result = subprocess.run([sys.executable, str(clean / 'materials/case.py'), 'run', '--inputs', str(clean / 'materials'), '--bundle', str(replay)], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert case.verify(replay)['facts'] == case.verify(clean)['facts']


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":1e2}', b'{"a":-0}', b'{"a":NaN}', b'{"a":"\\ud800"}', b'{"a":9007199254740992}'])
def test_strict_json(raw):
    with pytest.raises(ValueError):
        case.parse(raw)


def test_upstream_positive_hash_vectors():
    vectors = case.read(HERE.parents[1] / 'docs/research-lab/protocol-v2-hash-vectors.json')
    for vector in vectors['positive']:
        value = case.parse(vector['raw_json'].encode())
        if vector['self_hash_field'] is not None:
            value.pop(vector['self_hash_field'], None)
        assert case.canonical(value) == vector['canonical_utf8'], vector['name']
        assert case.digest(value) == vector['sha256'], vector['name']
