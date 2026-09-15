"""Real archived objects and adversarial copies; no new research execution."""
import copy
import tarfile
from pathlib import Path

import pytest
from jsonschema import ValidationError

from research_lab.contracts import v2


@pytest.fixture
def bundle(tmp_path):
    archive = v2.ROOT / 'research/phase0_data_quality/bundles/validation-rev1-ci.tar.gz'
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            relative = member.name
            assert not relative.startswith('/') and '..' not in Path(relative).parts
            assert member.isfile() or member.isdir()
            if member.isfile():
                target = tmp_path / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.extractfile(member).read())
    return tmp_path


def load(root, name):
    return v2.parse(v2.safe_read(root, name + '.json'))


def records(root):
    return {k: load(root, p) for k, p in [('research_task', 'materials/task'),
            ('experiment_spec', 'materials/spec'), ('experiment_run', 'run'),
            ('artifact_manifest', 'manifest'), ('result_evidence', 'evidence'), ('review', 'review')]}


def reseal(obj, prefix):
    obj[prefix + '_content_hash'] = v2.digest({k: v for k, v in obj.items() if k != prefix + '_content_hash'})


def test_real_archived_chain(bundle):
    obj = records(bundle)
    assert v2.validate_spec(obj['experiment_spec'], obj['research_task']) == {'source_order': {'strict': True}}
    payload = v2.validate_manifest(bundle, obj['artifact_manifest'], obj['experiment_run'])
    assert payload['quality_summary']['comparison_count'] == 179
    assert v2.validate_handoff(load(bundle, 'review-request'), obj, load(bundle, 'review-response'))


@pytest.mark.parametrize('mutation', ['role', 'duplicate', 'path', 'hash', 'schema_hash', 'schema_name', 'missing', 'shard', 'debug', 'unavailable', 'unknown_field'])
def test_manifest_rejects(bundle, mutation):
    obj = records(bundle); manifest = obj['artifact_manifest']; entry = manifest['entries'][0]
    if mutation == 'role':
        manifest['entries'].pop()
    elif mutation == 'duplicate':
        manifest['entries'][1]['artifact_id'] = entry['artifact_id']
    elif mutation == 'path':
        entry['relative_path'] = '../escape.json'
    elif mutation == 'hash':
        entry['content_sha256'] = '0' * 64
    elif mutation == 'schema_hash':
        entry['content_schema_ref']['content_hash'] = '0' * 64
    elif mutation == 'schema_name':
        entry['content_schema_ref']['name'] = 'unknown'
    elif mutation == 'missing':
        (bundle / entry['relative_path']).unlink()
    elif mutation == 'shard':
        extra = copy.deepcopy(entry); extra['artifact_id'] = 'shard2'; extra['relative_path'] = 'shard2.json'
        manifest['entries'].append(extra)
    elif mutation == 'debug':
        entry['classification'] = 'debug'
    elif mutation == 'unavailable':
        entry['availability'] = 'unavailable'
    else:
        manifest['verified'] = True
    reseal(manifest, 'manifest')
    with pytest.raises((ValueError, ValidationError, OSError)):
        v2.validate_manifest(bundle, manifest, obj['experiment_run'])


@pytest.mark.parametrize('mutation', ['method', 'parameter', 'unit', 'range', 'metric', 'snapshot', 'task'])
def test_spec_rejects(bundle, mutation):
    obj = records(bundle); spec = obj['experiment_spec']; task = obj['research_task']
    if mutation == 'method':
        spec['quality_checks'][0]['implementation_ref'] = 'missing.rev1'
    elif mutation in ('parameter', 'unit'):
        spec['quality_checks'][0]['parameters'] = [{'name': 'wrong' if mutation == 'parameter' else 'strict', 'value_type': 'boolean', 'value': True, 'unit': 'wrong' if mutation == 'unit' else 'dimensionless'}]
    elif mutation == 'range':
        spec['dataset_requirements']['time_range']['end'] = spec['dataset_requirements']['time_range']['start']
    elif mutation == 'metric':
        spec['metric_specifications'][0]['calculation_definition'] = 'different formula'
    elif mutation == 'snapshot':
        spec['dataset_requirements']['snapshot_sha256'] = None
    else:
        spec['task_id'] = 'other-task'
    reseal(spec, 'spec')
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_spec(spec, task)


@pytest.mark.parametrize('mutation', ['criteria', 'context', 'response', 'payload_ref', 'evidence_ref', 'output'])
def test_handoff_rejects(bundle, mutation):
    obj = records(bundle); request = load(bundle, 'review-request'); response = load(bundle, 'review-response')
    if mutation == 'criteria':
        obj['review']['criteria_ref']['revision'] = 'rev.2'; reseal(obj['review'], 'review')
        response['output_refs'][0] = v2.check_record(obj['review'], 'review')
    elif mutation == 'context':
        request['context_refs']['experiment_run']['content_hash'] = '0' * 64
    elif mutation == 'response':
        response['in_reply_to'] = 'other'
    elif mutation == 'payload_ref':
        request['artifact_requirements']['exact_refs'][0]['content_sha256'] = '0' * 64
    elif mutation == 'evidence_ref':
        obj['result_evidence']['run_id'] = 'other'; reseal(obj['result_evidence'], 'evidence')
        request['context_refs']['result_evidence'] = v2.check_record(obj['result_evidence'], 'result_evidence')
    else:
        response['output_refs'][0]['content_hash'] = '0' * 64
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, obj, response)


def test_no_links_or_external_schemas(bundle):
    (bundle / 'link.json').symlink_to(bundle / 'run.json')
    with pytest.raises(OSError):
        v2.safe_read(bundle, 'link.json')
    with pytest.raises(ValueError, match='external schema'):
        v2.schema_check({}, {'$ref': 'https://example.com/schema.json'})


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":-0}', b'{"a":9007199254740992}'])
def test_profile_rejects(raw):
    with pytest.raises(ValueError):
        v2.parse(raw)


def test_rehashed_invalid_payload_rejected(bundle):
    obj = records(bundle); manifest = obj['artifact_manifest']
    entry = next(e for e in manifest['entries'] if e['role'] == 'quality_summary')
    raw = v2.canonical({'unexpected': 0}).encode()
    (bundle / entry['relative_path']).write_bytes(raw)
    entry.update(content_sha256=v2.sha(raw), byte_length=len(raw)); reseal(manifest, 'manifest')
    with pytest.raises(ValidationError):
        v2.validate_manifest(bundle, manifest, obj['experiment_run'])


def test_both_sides_cannot_invent_criteria(bundle):
    obj = records(bundle); request = load(bundle, 'review-request'); response = load(bundle, 'review-response')
    request['criteria_ref']['content_hash'] = '0' * 64
    obj['review']['criteria_ref'] = copy.deepcopy(request['criteria_ref']); reseal(obj['review'], 'review')
    response['output_refs'][0] = v2.check_record(obj['review'], 'review')
    with pytest.raises(ValueError, match='definition reference mismatch'):
        v2.validate_handoff(request, obj, response)


def test_failed_manifest_diagnostic_delivery(bundle):
    obj = records(bundle); run = obj['experiment_run']; manifest = obj['artifact_manifest']
    run['run_status'] = 'FAILED'; reseal(run, 'run'); manifest['run_content_hash'] = run['run_content_hash']
    template = copy.deepcopy(manifest['entries'][0])
    for entry in manifest['entries']:
        if entry['role'] in ('quality_summary', 'quality_anomalies'):
            for name in ('relative_path', 'media_type', 'byte_length', 'content_sha256', 'producer'):
                entry.pop(name)
            entry.update(availability='unavailable', coverage='none', unavailable_reason='execution_interrupted')
    definition = next(e for e in v2.Definitions().entries if e.get('role') == 'failure_diagnostics')
    template.update(artifact_id='failure', role='failure_diagnostics', relative_path='failure.json',
                    content_schema_ref={k: definition[k] for k in ('name', 'revision', 'content_hash', 'locator')})
    raw = v2.canonical({'error_type': 'ValueError', 'message': 'synthetic failure', 'stage': 'quality_scan'}).encode()
    (bundle / 'failure.json').write_bytes(raw); template.update(content_sha256=v2.sha(raw), byte_length=len(raw))
    manifest['entries'].append(template); reseal(manifest, 'manifest')
    assert 'failure' in v2.validate_manifest(bundle, manifest, run)
    manifest['entries'].pop(); reseal(manifest, 'manifest')
    with pytest.raises(ValueError, match='missing required role'):
        v2.validate_manifest(bundle, manifest, run)


@pytest.mark.parametrize('field', ['reviewer', 'reviewed_at', 'recommendation', 'reason'])
def test_incomplete_self_hashed_review_rejected(bundle, field):
    obj = records(bundle); request = load(bundle, 'review-request'); response = load(bundle, 'review-response')
    obj['review'].pop(field); reseal(obj['review'], 'review')
    response['output_refs'][0] = v2.check_record(obj['review'], 'review')
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, obj, response)


@pytest.mark.parametrize('kind,field,prefix', [('research_task','objective','task'), ('experiment_run','timing','run'), ('result_evidence','typed_metrics','evidence')])
def test_incomplete_control_rejected(bundle, kind, field, prefix):
    obj = records(bundle); request = load(bundle, 'review-request')
    obj[kind].pop(field); reseal(obj[kind], prefix)
    request['context_refs'][kind] = v2.check_record(obj[kind], kind)
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, obj)
