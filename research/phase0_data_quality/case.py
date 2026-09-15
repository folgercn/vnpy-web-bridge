"""Manual, offline, one-case execution and independent bundle consumption."""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import quality
from jsonschema import Draft202012Validator, FormatChecker

PROFILE = "research-json-v1"
ROLES = ["dataset_metadata", "method_definition", "environment_lock", "replay_instructions",
         "quality_summary", "quality_anomalies"]
ROLE_PROFILE = "research_lab.artifact_roles.v2.candidate1"
CODE = ["case.py", "quality.py"]
SHA = re.compile(r"[a-f0-9]{64}\Z")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(x):
    if x is None:
        return "null"
    if type(x) is bool:
        return "true" if x else "false"
    if type(x) is int:
        require(abs(x) <= 9007199254740991, "unsafe integer")
        return str(x)
    if isinstance(x, str):
        require(not any(0xd800 <= ord(c) <= 0xdfff for c in x), "surrogate")
        return '"' + ''.join('\\"' if c == '"' else '\\\\' if c == '\\' else
                              f'\\u{ord(c):04x}' if ord(c) < 32 else c for c in x) + '"'
    if isinstance(x, list):
        return '[' + ','.join(map(canonical, x)) + ']'
    if isinstance(x, dict):
        require(all(isinstance(k, str) and k and all(32 <= ord(c) <= 126 for c in k) for k in x), "invalid key")
        return '{' + ','.join(canonical(k) + ':' + canonical(x[k]) for k in sorted(x)) + '}'
    raise ValueError("non-profile value")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(x):
    return sha(canonical(x).encode())


def parse(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "duplicate key")
            result[k] = v
        return result
    def integer(s):
        require(s != "-0", "negative zero")
        return int(s)
    def invalid(s):
        raise ValueError("non-integer JSON number: " + s)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer,
                       parse_float=invalid, parse_constant=invalid)
    canonical(value)
    return value


def read(path):
    return parse(Path(path).read_bytes())


def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write((canonical(obj) + '\n').encode())
        f.flush()
        os.fsync(f.fileno())


def seal(obj, field):
    obj[field] = digest({k: v for k, v in obj.items() if k != field})
    return obj


def check_hash(obj, field):
    require(obj.get("hash_profile") == PROFILE, "hash profile")
    require(isinstance(obj.get(field), str) and SHA.fullmatch(obj[field]), "missing hash")
    require(obj[field] == digest({k: v for k, v in obj.items() if k != field}), "record hash mismatch: " + field)


def keys(obj, expected):
    require(isinstance(obj, dict) and set(obj) == set(expected.split()), "closed fields: " + expected)


def stamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def time_value(s):
    require(isinstance(s, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', s), "UTC microsecond timestamp")
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)


FORMATS = FormatChecker()
@FORMATS.checks("date-time", raises=ValueError)
def timestamp_format(s):
    time_value(s)
    return True


def schema_check(obj, schema):
    Draft202012Validator(schema, format_checker=FORMATS).validate(obj)


def safe_read(root, relative):
    require(isinstance(relative, str) and all(re.fullmatch(r'[a-z0-9][a-z0-9._-]*', p)
            and p not in ('.', '..') for p in relative.split('/')), "unsafe path")
    path = Path(root)
    require(not path.is_symlink(), "symlink root")
    for part in relative.split('/'):
        path = path / part
        require(not path.is_symlink(), "symlink path")
    require(path.is_file(), "missing file: " + relative)
    return path.read_bytes()


def admission(materials):
    m = Path(materials)
    prepared = read(m / 'preparation.json')
    keys(prepared, 'prepared_at files source_base_revision')
    time_value(prepared['prepared_at'])
    for name, expected in prepared['files'].items():
        require(sha(safe_read(m, name)) == expected, 'prepared material hash mismatch: ' + name)
    essential = {'task.json', 'spec.json', 'criteria.json', 'method.json', 'input.csv',
                 'provenance.json', 'spec.schema.json', 'handoff.schema.json', 'payload.schema.json', *CODE}
    require(set(prepared['files']) == essential, 'preparation inventory')
    for name in CODE:
        require(sha(Path(__file__).with_name(name).read_bytes()) == prepared['files'][name], 'actual implementation mismatch')
    task, spec, criteria, method = (read(m / (n + '.json')) for n in ('task', 'spec', 'criteria', 'method'))
    keys(task, 'schema_version hash_profile task_id revision research_type objective data_requirements task_content_hash')
    check_hash(task, 'task_content_hash')
    require(task['schema_version'] == 'research_lab.task.v2' and task['research_type'] == 'data_quality', 'task type')
    schema_check(spec, read(m / 'spec.schema.json'))
    check_hash(spec, 'spec_content_hash')
    require((spec['task_id'], spec['task_revision'], spec['task_content_hash']) ==
            (task['task_id'], task['revision'], task['task_content_hash']), 'task reference')
    require(spec['research_stage'] == 'validation' and spec['experiment_type'] == 'data_quality', 'only validation data_quality')
    require(spec.get('trial_kind_proposal') is None and spec.get('seed_proposal') is None, 'no stochastic/retry proposal')
    require(spec['validation_config'] == {'method': 'full_sample_scan'}, 'unsupported scan')
    require(spec['holdout_policy'] == {'mode': 'not_used', 'reason': 'Historical derived rows; date-order audit only; no confirmation or PIT claim.'}, 'holdout scope')
    req = spec['dataset_requirements']
    keys(req, 'provider_kind dataset_reference_uri snapshot_selection_mode snapshot_sha256 universe frequencies time_range required_fields pit_constraints normalization_rule_version')
    require(req['provider_kind'] == 'local_derived_subset' and req['dataset_reference_uri'] == 'candidate://phase0/derived-rb-dates', 'unsupported source')
    require(req['snapshot_selection_mode'] == 'fixed_snapshot' and req['snapshot_sha256'] == sha(safe_read(m, 'input.csv')), 'input hash')
    require(req['required_fields'] == quality.FIELDS and req['frequencies'] == ['1d'], 'input definition')
    require(req['normalization_rule_version'] == 'phase0.date-column-as-utc-label.rev1', 'normalization')
    require(req['pit_constraints'] == 'No historical receipt or PIT certification. source_official_day is a date label, not arrival time.', 'PIT scope')
    start, end = (time_value(req['time_range'][k]) for k in ('start', 'end'))
    require(start < end and all(t.hour == t.minute == t.second == t.microsecond == 0 for t in (start, end)), 'date-label boundaries')
    require(req['universe'] and len(set(req['universe'])) == len(req['universe']) and set(req['universe']) <= set(task['data_requirements']['products']), 'universe')
    require(task['data_requirements'] == {'products': ['rb'], 'date_start': '2023-01-03', 'date_end_exclusive': '2023-02-01', 'fields': quality.FIELDS}, 'task requirements')
    require('2023-01-03' <= start.isoformat()[:10] < end.isoformat()[:10] <= '2023-02-01', 'task date boundary')
    checks = spec['quality_checks']
    require(len(checks) == 1 and checks[0]['implementation_ref'] == quality.METHOD and checks[0]['check_id'] == 'source_order', 'unknown method')
    require(checks[0].get('failure_action') == 'record', 'defects must be recorded')
    parameters = checks[0]['parameters']
    require(parameters in ([], [{'name': 'strict', 'value_type': 'boolean', 'unit': 'dimensionless', 'value': True}],
                           [{'name': 'strict', 'value_type': 'boolean', 'unit': 'dimensionless', 'value': False}]), 'parameters')
    require(spec['metric_specifications'] == [quality.METRIC], 'metric definition mismatch')
    require(spec['candidate_decision_criteria'] == {'max_allowed_timestamp_reversals': 0}, 'Spec criteria')
    keys(method, 'id revision source_sha256 parameter_definition metric')
    require(method == {'id': quality.METHOD, 'revision': 'rev.1', 'source_sha256': prepared['files']['quality.py'],
                       'parameter_definition': {'strict': {'type': 'boolean', 'unit': 'dimensionless', 'default': True}}, 'metric': quality.METRIC}, 'method binding')
    keys(criteria, 'id revision metric maximum minimum_comparisons scope')
    require(criteria == {'id': 'phase0-date-order-criteria', 'revision': 'rev.1', 'metric': quality.METRIC['metric_name'],
                         'maximum': 0, 'minimum_comparisons': 1, 'scope': 'date order only; not calendar completeness, PIT or protocol freeze'}, 'criteria definition')
    return prepared, task, spec, criteria, method


def environment():
    packages = {}
    for name in ('jsonschema', 'attrs', 'referencing', 'rpds-py', 'jsonschema-specifications'):
        dist = importlib.metadata.distribution(name)
        files = {str(p): sha(dist.locate_file(p).read_bytes()) for p in dist.files or []
                 if str(p).endswith(('.py', '.so', '.json')) and dist.locate_file(p).is_file()}
        packages[name] = {'version': dist.version, 'files_hash': digest(files)}
    return {'python': platform.python_version(), 'implementation': platform.python_implementation(),
            'platform': platform.system(), 'machine': platform.machine(),
            'executable_sha256': sha(Path(sys.executable).read_bytes()), 'dependencies': packages,
            'stdlib_hashes': {x.__name__: sha(Path(x.__file__).read_bytes()) for x in (csv, json, hashlib)},
            'limit': 'Interpreter, selected stdlib and dependency files; not a hermetic OS image.'}


def computation(prepared, spec, env):
    return {'hash_profile': PROFILE, 'fingerprint_schema_version': 'phase0.data_quality.fingerprint.rev1',
            'code_revision': prepared['source_base_revision'],
            'source_diff_fingerprint': digest({n: prepared['files'][n] for n in CODE}),
            'dependency_lock_hash': digest(env), 'raw_bytes_sha256': spec['dataset_requirements']['snapshot_sha256'],
            'resolved_parameters': {'strict': next((p['value'] for p in spec['quality_checks'][0]['parameters']), True)},
            'random_seed': None, 'method_definition_sha256': prepared['files']['method.json'],
            'scientific_time': spec['dataset_requirements']['time_range'], 'universe': spec['dataset_requirements']['universe'],
            'normalization_rule_version': spec['dataset_requirements']['normalization_rule_version'],
            'calendar_rule': None, 'receipt_evidence': None, 'holdout_usage_state': 'not_applicable'}


def artifact_refs(manifest):
    return [{'manifest_id': manifest['manifest_id'], 'manifest_revision': manifest['revision'],
             'manifest_content_hash': manifest['manifest_content_hash'], 'artifact_id': e['artifact_id'],
             'role': e['role'], 'content_sha256': e['content_sha256']} for e in manifest['entries'] if e['availability'] == 'present']


def object_ref(obj, typ, prefix, revision=False):
    r = {'object_type': typ, 'object_id': obj[prefix + '_id'], 'content_hash': obj[prefix + '_content_hash']}
    if revision:
        r['revision'] = obj['revision']
    return r


def handoff(task, spec, run, manifest, evidence, criteria):
    return {'schema_version': 'research_lab.agent_handoff.v2', 'handoff_id': 'handoff-' + run['run_id'],
            'message_kind': 'request', 'operation': 'review_evidence', 'sender_role': 'execution', 'recipient_role': 'critic',
            'context_refs': {slot: object_ref(obj, slot, prefix, rev) for slot, obj, prefix, rev in [
                ('research_task', task, 'task', True), ('experiment_spec', spec, 'spec', True),
                ('experiment_run', run, 'run', False), ('artifact_manifest', manifest, 'manifest', True),
                ('result_evidence', evidence, 'evidence', False)]},
            'artifact_requirements': {'role_profile_ref': ROLE_PROFILE, 'required_roles': ROLES + ([] if run['run_status'] == 'COMPLETED' else ['failure_diagnostics']), 'exact_refs': artifact_refs(manifest)},
            'expected_outputs': [{'object_type': 'review', 'schema_version': 'research_lab.review.v2'}],
            'review_scope': 'research_assessment' if run['run_status'] == 'COMPLETED' else 'failure_diagnosis',
            'criteria_ref': {'id': criteria['id'], 'revision': criteria['revision'], 'content_hash': digest(criteria)}}


def run_case(materials, bundle):
    materials, bundle = Path(materials), Path(bundle)
    prepared, task, spec, criteria, method = admission(materials)
    raw = safe_read(materials, 'input.csv')  # stable bytes bound BEFORE calculation
    env = environment()
    comp = computation(prepared, spec, env)
    bundle.mkdir(parents=True, exist_ok=False)
    shutil.copytree(materials, bundle / 'materials')
    admission(bundle / 'materials')
    require(safe_read(bundle / 'materials', 'input.csv') == raw, 'input changed during capture')
    locked = {'locked_at': stamp(), 'preparation_sha256': sha(safe_read(materials, 'preparation.json')),
              'resolved_computation_manifest': comp, 'scientific_fingerprint': digest(comp)}
    save(bundle / 'input-lock.json', locked)
    started = stamp()
    failure = None
    try:
        summary, anomalies = quality.scan(raw, spec)
    except Exception as exc:  # noqa: BLE001 -- archive calculation failures; never convert to success
        failure = {'error_type': type(exc).__name__, 'message': str(exc), 'stage': 'quality_scan'}
        summary = anomalies = None
    finished = stamp()
    run = seal({'schema_version': 'research_lab.run.v2', 'hash_profile': PROFILE, 'run_id': 'run-' + uuid4().hex,
                'spec_id': spec['spec_id'], 'spec_revision': spec['revision'], 'spec_content_hash': spec['spec_content_hash'],
                'run_status': 'FAILED' if failure else 'COMPLETED',
                'trial_context': {'research_stage': 'validation', 'trial_kind': None, 'retry_of_run_id': None, 'holdout_usage_state': 'not_applicable'},
                'resolved_computation_manifest': comp, 'scientific_fingerprint': digest(comp),
                'input_lock_sha256': sha((bundle / 'input-lock.json').read_bytes()),
                'timing': {'started_at': started, 'completed_at': finished}, 'process_exit_code': 1 if failure else 0}, 'run_content_hash')
    save(bundle / 'run.json', run)
    payloads = {'dataset_metadata': {'snapshot_sha256': sha(raw), 'byte_length': len(raw), 'fields': quality.FIELDS,
                                   'source': read(materials / 'provenance.json'), 'time_range': spec['dataset_requirements']['time_range'],
                                   'receipt_evidence': None, 'calendar_evidence': None},
                'method_definition': method, 'environment_lock': env,
                'replay_instructions': {'entry': 'materials/case.py', 'command': 'python materials/case.py run --inputs materials --bundle NEW_DIRECTORY',
                                        'comparison': 'exact quality_summary and quality_anomalies; new Run ID/times; no new independent samples',
                                        'requirements': 'Python and jsonschema dependencies declared by environment_lock; input and source included'},
                'quality_summary': summary, 'quality_anomalies': anomalies}
    if failure:
        payloads['failure_diagnostics'] = failure
    definition = read(materials / 'payload.schema.json')
    entries = []
    for role, content in payloads.items():
        schema_ref = {'name': 'phase0.' + role, 'revision': 'rev.1', 'content_hash': digest(definition['$defs'][role]), 'locator': 'materials/payload.schema.json#/$defs/' + role}
        entry = {'artifact_id': role, 'role': role, 'classification': 'supporting' if role == 'quality_anomalies' else 'required', 'content_schema_ref': schema_ref}
        if content is None:
            entry.update(availability='unavailable', coverage='none', unavailable_reason='execution_interrupted')
        else:
            schema_check(content, definition['$defs'][role])
            relative = 'payload/' + role + '.json'
            save(bundle / relative, content)
            data = (bundle / relative).read_bytes()
            entry.update(availability='present', coverage='complete', relative_path=relative, media_type='application/json',
                         byte_length=len(data), content_sha256=sha(data), producer={'component': 'phase0_data_quality', 'version': prepared['files']['case.py']})
        entries.append(entry)
    manifest = seal({'schema_version': 'research_lab.artifact_manifest.v2', 'hash_profile': PROFILE,
                     'manifest_id': 'manifest-' + run['run_id'], 'revision': 'rev.1', 'run_id': run['run_id'],
                     'run_content_hash': run['run_content_hash'], 'experiment_type': 'data_quality', 'artifact_profile': ROLE_PROFILE,
                     'entries': entries}, 'manifest_content_hash')
    save(bundle / 'manifest.json', manifest)
    evidence = seal({'schema_version': 'research_lab.evidence.v2', 'hash_profile': PROFILE, 'evidence_id': 'evidence-' + run['run_id'],
                     'run_id': run['run_id'], 'run_content_hash': run['run_content_hash'], 'run_status_snapshot': run['run_status'],
                     'execution_status': run['run_status'], 'typed_metrics': None if failure else [{'metric': quality.METRIC, 'value': summary[quality.METRIC['metric_name']], 'sample_count': summary['comparison_count']}],
                     'missing_reason': 'execution_failed' if failure else None,
                     'manifest_id': manifest['manifest_id'], 'manifest_revision': manifest['revision'], 'manifest_content_hash': manifest['manifest_content_hash'],
                     'supporting_artifacts': artifact_refs(manifest)}, 'evidence_content_hash')
    save(bundle / 'evidence.json', evidence)
    request = handoff(task, spec, run, manifest, evidence, criteria)
    schema_check(request, read(materials / 'handoff.schema.json'))
    save(bundle / 'review-request.json', request)
    verify(bundle)
    return run


def verify(bundle, require_review=False):
    b = Path(bundle)
    prepared, task, spec, criteria, method = admission(b / 'materials')
    load = lambda name: parse(safe_read(b, name + '.json'))
    run, manifest, evidence, request, lock = (load(n) for n in ('run', 'manifest', 'evidence', 'review-request', 'input-lock'))
    keys(run, 'schema_version hash_profile run_id spec_id spec_revision spec_content_hash run_status trial_context resolved_computation_manifest scientific_fingerprint input_lock_sha256 timing process_exit_code run_content_hash')
    keys(manifest, 'schema_version hash_profile manifest_id revision run_id run_content_hash experiment_type artifact_profile entries manifest_content_hash')
    keys(evidence, 'schema_version hash_profile evidence_id run_id run_content_hash run_status_snapshot execution_status typed_metrics missing_reason manifest_id manifest_revision manifest_content_hash supporting_artifacts evidence_content_hash')
    for obj, kind in ((run, 'run'), (manifest, 'manifest'), (evidence, 'evidence')):
        check_hash(obj, kind + '_content_hash')
    require(run['schema_version'] == 'research_lab.run.v2' and manifest['schema_version'] == 'research_lab.artifact_manifest.v2' and evidence['schema_version'] == 'research_lab.evidence.v2', 'object versions')
    require(run['run_status'] in ('COMPLETED', 'FAILED'), 'terminal state')
    require(re.fullmatch('run-[a-f0-9]{32}', run['run_id']), 'run ID')
    require(run['trial_context'] == {'research_stage': 'validation', 'trial_kind': None, 'retry_of_run_id': None, 'holdout_usage_state': 'not_applicable'}, 'trial context')
    require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) == (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Spec binding')
    require(manifest['revision'] == 'rev.1' and manifest['manifest_id'] == 'manifest-' + run['run_id'], 'manifest identity')
    require(manifest['experiment_type'] == 'data_quality' and manifest['artifact_profile'] == ROLE_PROFILE, 'artifact profile')
    for obj in (manifest, evidence):
        require((obj['run_id'], obj['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Run binding')
    require(evidence['evidence_id'] == 'evidence-' + run['run_id'] and evidence['execution_status'] == evidence['run_status_snapshot'] == run['run_status'], 'Evidence state')
    require((evidence['manifest_id'], evidence['manifest_revision'], evidence['manifest_content_hash']) == (manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash']), 'Manifest binding')
    schema_check(request, read(b / 'materials/handoff.schema.json'))
    require(request == handoff(task, spec, run, manifest, evidence, criteria), 'handoff reference/profile/criteria mismatch')
    definition = read(b / 'materials/payload.schema.json')
    expected_roles = ROLES + (['failure_diagnostics'] if run['run_status'] == 'FAILED' else [])
    entries = manifest['entries']
    require([e['role'] for e in entries] == expected_roles, 'missing/duplicate/unknown required role')
    contents, paths = {}, set()
    for e in entries:
        role = e['role']
        common = 'artifact_id role classification content_schema_ref availability coverage '
        physical = 'relative_path media_type byte_length content_sha256 producer'
        keys(e, common + (physical if e['availability'] == 'present' else 'unavailable_reason'))
        require(e['artifact_id'] == role and e['classification'] == ('supporting' if role == 'quality_anomalies' else 'required'), 'artifact identity/classification')
        require(e['content_schema_ref'] == {'name': 'phase0.' + role, 'revision': 'rev.1', 'content_hash': digest(definition['$defs'][role]), 'locator': 'materials/payload.schema.json#/$defs/' + role}, 'content definition reference')
        if e['availability'] == 'unavailable':
            require(run['run_status'] == 'FAILED' and role in ('quality_summary', 'quality_anomalies') and e['coverage'] == 'none' and e['unavailable_reason'] == 'execution_interrupted', 'unavailable role')
            contents[role] = None
            continue
        require(e['availability'] == 'present' and e['coverage'] == 'complete', 'incomplete role')
        require(e['relative_path'] == 'payload/' + role + '.json' and e['relative_path'] not in paths, 'payload path/uniqueness')
        paths.add(e['relative_path'])
        data = safe_read(b, e['relative_path'])
        require(type(e['byte_length']) is int and len(data) == e['byte_length'] and sha(data) == e['content_sha256'], 'payload corrupt')
        require(e['media_type'] == 'application/json' and e['producer'] == {'component': 'phase0_data_quality', 'version': prepared['files']['case.py']}, 'producer/media')
        content = parse(data)
        schema_check(content, definition['$defs'][role])
        contents[role] = content
    require(evidence['supporting_artifacts'] == artifact_refs(manifest), 'Evidence artifacts')
    require(contents['method_definition'] == method, 'actual method definition')
    raw = safe_read(b / 'materials', 'input.csv')
    require(contents['dataset_metadata'] == {'snapshot_sha256': sha(raw), 'byte_length': len(raw), 'fields': quality.FIELDS,
            'source': read(b / 'materials/provenance.json'), 'time_range': spec['dataset_requirements']['time_range'],
            'receipt_evidence': None, 'calendar_evidence': None}, 'dataset metadata')
    comp = computation(prepared, spec, contents['environment_lock'])
    require(run['resolved_computation_manifest'] == comp and run['scientific_fingerprint'] == digest(comp), 'scientific fingerprint')
    keys(lock, 'locked_at preparation_sha256 resolved_computation_manifest scientific_fingerprint')
    require(lock['resolved_computation_manifest'] == comp and lock['scientific_fingerprint'] == digest(comp) and lock['preparation_sha256'] == sha(safe_read(b / 'materials', 'preparation.json')), 'input lock binding')
    require(run['input_lock_sha256'] == sha(safe_read(b, 'input-lock.json')), 'lock bytes')
    keys(run['timing'], 'started_at completed_at')
    require(time_value(prepared['prepared_at']) <= time_value(lock['locked_at']) <= time_value(run['timing']['started_at']) <= time_value(run['timing']['completed_at']), 'execution order')
    if run['run_status'] == 'COMPLETED':
        actual, anomalies = quality.scan(raw, spec)
        require(contents['quality_summary'] == actual and contents['quality_anomalies'] == anomalies, 'recomputed facts mismatch')
        require(evidence['typed_metrics'] == [{'metric': quality.METRIC, 'value': actual[quality.METRIC['metric_name']], 'sample_count': actual['comparison_count']}] and evidence['missing_reason'] is None and run['process_exit_code'] == 0, 'Evidence metrics')
    else:
        require(contents['quality_summary'] is None and contents['quality_anomalies'] is None and evidence['typed_metrics'] is None and evidence['missing_reason'] == 'execution_failed' and run['process_exit_code'] == 1, 'FAILED cannot have fabricated complete metrics')
    if require_review or (b / 'review.json').exists():
        review = load('review')
        keys(review, 'schema_version hash_profile review_id revision review_content_hash evidence_id evidence_content_hash reviewer reviewed_at criteria_ref recommendation reason')
        check_hash(review, 'review_content_hash')
        require(review['schema_version'] == 'research_lab.review.v2' and review['revision'] == 'rev.1' and isinstance(review['review_id'], str) and review['review_id'], 'Review identity')
        require((review['evidence_id'], review['evidence_content_hash']) == (evidence['evidence_id'], evidence['evidence_content_hash']), 'Review Evidence reference')
        require(review['criteria_ref'] == request['criteria_ref'], 'Review criteria_ref mismatch')
        require(review['recommendation'] in ('accept', 'improve', 'reject') and isinstance(review['reason'], str) and review['reason'] and isinstance(review['reviewer'], str) and review['reviewer'], 'Review fields')
        require(time_value(review['reviewed_at']) >= time_value(run['timing']['completed_at']), 'Review time')
        response = load('review-response')
        schema_check(response, read(b / 'materials/handoff.schema.json'))
        require(response == review_response(request, review), 'Review response correlation')
    return {'run_id': run['run_id'], 'run_status': run['run_status'], 'facts': contents['quality_summary'],
            'scientific_fingerprint': run['scientific_fingerprint'], 'review_present': (b / 'review.json').exists()}


def review_response(request, review):
    return {'schema_version': 'research_lab.agent_handoff.v2', 'handoff_id': 'response-' + review['review_id'],
            'message_kind': 'response', 'operation': 'review_evidence', 'sender_role': 'critic', 'recipient_role': 'execution',
            'context_refs': request['context_refs'], 'in_reply_to': request['handoff_id'], 'status': 'completed',
            'output_refs': [object_ref(review, 'review', 'review', True)], 'review_scope': request['review_scope']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['run', 'verify'])
    p.add_argument('--inputs', type=Path)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--require-review', action='store_true')
    args = p.parse_args()
    try:
        if args.action == 'run':
            require(args.inputs is not None, '--inputs required')
            result = run_case(args.inputs, args.bundle)
            print(canonical({'run_id': result['run_id'], 'run_status': result['run_status']}))
            return result['process_exit_code']
        print(canonical(verify(args.bundle, args.require_review)))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('REJECTED: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
