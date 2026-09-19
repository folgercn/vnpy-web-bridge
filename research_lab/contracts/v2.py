"""Read-only v2 contract validation against repository-pinned definitions.

Passing these checks never authorizes execution or certifies scientific validity.
"""
import hashlib
import json
import os
import re
import stat
import weakref
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
DEFINITIONS = ROOT / 'docs/research-lab/definitions'
PROFILE = 'research-json-v1'
ROLE_PROFILE = 'research_lab.artifact_roles.v2.candidate1'
SINGLE_CONTRACT_PROFILE = 'research_lab.single_contract_backtest.v1'
SINGLE_CONTRACT_PAYLOAD_PREFIX = 'research_lab.single_contract.'
SINGLE_CONTRACT_CRITERIA_ID = 'research_lab.single_contract_backtest.review_evidence.criteria'
COMMON = {'dataset_metadata', 'method_definition', 'environment_lock', 'replay_instructions'}
TYPED = {'data_quality': {'quality_summary', 'quality_anomalies'},
         'statistical_factor': {'statistical_summary', 'sample_feature_target', 'daily_ic_series'},
         'trading_backtest': {'backtest_summary', 'trade_blotter', 'equity_curve'}}
OBJECTS = {'research_task': ('task', 'research_lab.task.v2', True),
           'experiment_spec': ('spec', 'research_lab.experiment.v2', True),
           'experiment_run': ('run', 'research_lab.run.v2', False),
           'artifact_manifest': ('manifest', 'research_lab.artifact_manifest.v2', True),
           'result_evidence': ('evidence', 'research_lab.evidence.v2', False),
           'review': ('review', 'research_lab.review.v2', True)}
REVISE_SPEC_544_SOURCE_ANCHOR = {
    'research_task': {
        'object_type': 'research_task',
        'object_id': 'task-phase0-rb-date-order',
        'revision': 'rev.1',
        'content_hash': '006fd80ec74c4ecc713271a6980e3df838aca2f02c51361a5c1a5702d5097443',
    },
    'experiment_spec': {
        'object_type': 'experiment_spec',
        'object_id': 'spec-phase0-rb-date-order',
        'revision': 'rev.1',
        'content_hash': 'bd4cba75ee4688305344b3665fba29d712029a6b465c81ce6ef937ea3a1acde5',
    },
    'experiment_run': {
        'object_type': 'experiment_run',
        'object_id': 'run-3bc9fae4eaed4ff291af0c732c0f7871',
        'content_hash': '7f3139ed2a9035afa6d9cbe671e0a5d89545635f9103340172dfd77b365326ce',
    },
    'artifact_manifest': {
        'object_type': 'artifact_manifest',
        'object_id': 'manifest-run-3bc9fae4eaed4ff291af0c732c0f7871',
        'revision': 'rev.1',
        'content_hash': '41ac809f40c4d4e4f40bfffa88c6b0dcaf3362d207453cfdfad8dcedaf038e6f',
    },
    'result_evidence': {
        'object_type': 'result_evidence',
        'object_id': 'evidence-run-3bc9fae4eaed4ff291af0c732c0f7871',
        'content_hash': '279e63699a7758814e204dcaaf1be570b147174b12619d66f3346945620d4acf',
    },
    'review': {
        'object_type': 'review',
        'object_id': 'review-independent-run-3bc9fae4eaed4ff291af0c732c0f7871',
        'revision': 'rev.1',
        'content_hash': 'a7dce82c45f9d02603c37f83a2850243f32223b0f2381f133583fde7960e39bf',
    },
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    if value is None:
        return 'null'
    if type(value) is bool:
        return 'true' if value else 'false'
    if type(value) is int:
        require(abs(value) <= 9007199254740991, 'unsafe integer')
        return str(value)
    if isinstance(value, str):
        require(not any(0xd800 <= ord(c) <= 0xdfff for c in value), 'surrogate')
        return '"' + ''.join('\\"' if c == '"' else '\\\\' if c == '\\' else
                             f'\\u{ord(c):04x}' if ord(c) < 32 else c for c in value) + '"'
    if isinstance(value, list):
        return '[' + ','.join(map(canonical, value)) + ']'
    require(isinstance(value, dict), 'non-profile value')
    require(all(isinstance(k, str) and k and all(32 <= ord(c) <= 126 for c in k) for k in value), 'invalid key')
    return '{' + ','.join(canonical(k) + ':' + canonical(value[k]) for k in sorted(value)) + '}'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value).encode('utf-8'))


DECIMAL = re.compile(r'(?:0|-?0\.[0-9]*[1-9]|-?[1-9][0-9]*(?:\.[0-9]*[1-9])?)')
FIELD_TYPES = {'decimal', 'timestamp'}
POSITIVE_HASH_VECTOR_NAMES = frozenset({
    'basic', 'reordered', 'null', 'missing', 'array', 'array_reordered',
    'unicode_control', 'unicode_composed', 'unicode_decomposed', 'decimal', 'utc',
    'integer_bounds', 'self_hash', 'upstream_change',
})
NEGATIVE_HASH_VECTOR_NAMES = frozenset({
    'float', 'exponent', 'negative_zero', 'nonfinite', 'out_of_range', 'duplicate',
    'surrogate', 'non_ascii_key', 'decimal_trailing_zero', 'decimal_negative_zero',
    'timestamp_offset', 'timestamp_invalid_date', 'timestamp_precision',
})
NEGATIVE_HASH_VECTOR_FIELD_TYPES = {
    'float': {},
    'exponent': {},
    'negative_zero': {},
    'nonfinite': {},
    'out_of_range': {},
    'duplicate': {},
    'surrogate': {},
    'non_ascii_key': {},
    'decimal_trailing_zero': {'a': 'decimal'},
    'decimal_negative_zero': {'a': 'decimal'},
    'timestamp_offset': {'a': 'timestamp'},
    'timestamp_invalid_date': {'a': 'timestamp'},
    'timestamp_precision': {'a': 'timestamp'},
}


def validate_field_type_declarations(field_types):
    require(isinstance(field_types, dict), 'field types')
    for field, kind in field_types.items():
        require(isinstance(field, str), 'typed field name')
        require(kind in FIELD_TYPES, 'unknown field type')


def validate_field_type_metadata(value, field_types):
    """Check declarations against parsed values before testing negative inputs."""
    require(isinstance(value, dict), 'typed hash value must be an object')
    validate_field_type_declarations(field_types)
    for field in field_types:
        require(field in value, 'unknown typed field')
        require(isinstance(value[field], str), 'typed field must be a string')


def validate_field_types(value, field_types):
    """Validate explicitly declared root fields without inferring ordinary strings."""
    validate_field_type_metadata(value, field_types)
    for field, kind in field_types.items():
        item = value[field]
        if kind == 'decimal':
            require(DECIMAL.fullmatch(item) is not None, 'decimal')
        else:
            time_value(item)


def hash_json(raw, field_types=None, self_hash_field=None):
    """Return canonical UTF-8 and SHA-256 for one research-json-v1 value.

    ``field_types`` applies only to declared root fields.  ``self_hash_field``
    removes exactly that root field after validation; nested names remain hashed.
    """
    require(isinstance(raw, bytes), 'raw JSON bytes')
    try:
        value = parse(raw)
    except UnicodeDecodeError as error:
        raise ValueError('invalid UTF-8') from error
    field_types = {} if field_types is None else field_types
    validate_field_types(value, field_types)
    if self_hash_field is not None:
        require(isinstance(self_hash_field, str) and self_hash_field in value,
                'self hash field')
        value = {key: item for key, item in value.items() if key != self_hash_field}
    output = canonical(value)
    return output.encode('utf-8'), sha(output.encode('utf-8'))


def validate_hash_vectors(vectors):
    """Verify the repository-pinned research-json-v1 interoperability vectors."""
    require(isinstance(vectors, dict) and set(vectors) ==
            {'profile', 'status', 'positive', 'negative'}, 'hash vector envelope')
    require(vectors['profile'] == PROFILE and vectors['status'] == 'DRAFT_UNFROZEN',
            'hash vector profile/status')
    positive_fields = {'name', 'raw_json', 'field_types', 'self_hash_field',
                       'canonical_utf8', 'sha256'}
    negative_fields = {'name', 'raw_json', 'field_types', 'expected'}
    require(isinstance(vectors['positive'], list) and isinstance(vectors['negative'], list),
            'hash vector collections')
    names = set()
    for vector in vectors['positive']:
        require(isinstance(vector, dict) and set(vector) == positive_fields,
                'positive hash vector fields')
        require(isinstance(vector['name'], str) and vector['name'] not in names,
                'duplicate hash vector name')
        names.add(vector['name'])
        require(isinstance(vector['raw_json'], str) and
                isinstance(vector['canonical_utf8'], str) and
                re.fullmatch(r'[a-f0-9]{64}', vector['sha256']) is not None,
                'positive hash vector values')
        try:
            raw = vector['raw_json'].encode('utf-8')
            expected = vector['canonical_utf8'].encode('utf-8')
        except UnicodeEncodeError as error:
            raise ValueError('invalid vector UTF-8') from error
        actual, actual_hash = hash_json(raw, vector['field_types'], vector['self_hash_field'])
        require(actual == expected and actual_hash == vector['sha256'],
                'positive hash vector mismatch')
    require(len(vectors['positive']) == len(POSITIVE_HASH_VECTOR_NAMES) and
            {item['name'] for item in vectors['positive']} == POSITIVE_HASH_VECTOR_NAMES,
            'positive hash vector set')
    for vector in vectors['negative']:
        require(isinstance(vector, dict) and set(vector) == negative_fields,
                'negative hash vector fields')
        require(isinstance(vector['name'], str) and vector['name'] not in names,
                'duplicate hash vector name')
        names.add(vector['name'])
        require(isinstance(vector['raw_json'], str) and
                vector['expected'] == 'reject_before_hash', 'negative hash vector values')
        require(vector['name'] in NEGATIVE_HASH_VECTOR_FIELD_TYPES and
                vector['field_types'] == NEGATIVE_HASH_VECTOR_FIELD_TYPES[vector['name']],
                'negative hash vector field types')
        try:
            raw = vector['raw_json'].encode('utf-8')
        except UnicodeEncodeError as error:
            raise ValueError('invalid vector UTF-8') from error
        validate_field_type_declarations(vector['field_types'])
        try:
            parsed = parse(raw)
        except ValueError:
            continue
        validate_field_type_metadata(parsed, vector['field_types'])
        try:
            hash_json(raw, vector['field_types'])
        except ValueError:
            continue
        raise ValueError('negative hash vector accepted')
    require(len(vectors['negative']) == len(NEGATIVE_HASH_VECTOR_NAMES) and
            {item['name'] for item in vectors['negative']} == NEGATIVE_HASH_VECTOR_NAMES,
            'negative hash vector set')
    return True


def parse(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate key')
            result[k] = v
        return result
    def integer(text):
        require(text != '-0', 'negative zero')
        return int(text)
    def invalid(text):
        raise ValueError('non-integer number: ' + text)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_int=integer,
                       parse_float=invalid, parse_constant=invalid)
    canonical(value)
    return value


def safe_read(root, relative):
    """Open beneath a caller-selected root, no links, one stable byte read."""
    require(isinstance(relative, str) and all(re.fullmatch(r'[a-z0-9][a-z0-9._-]*', p)
            and p not in ('.', '..') for p in relative.split('/')), 'unsafe path')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode), 'not a regular file')
            raw = stream.read()
            after = os.fstat(stream.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file changed during read')
            return raw
    finally:
        os.close(fd)


def time_value(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', value), 'UTC timestamp')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)


FORMATS = FormatChecker()
@FORMATS.checks('date-time', raises=ValueError)
def date_time(value):
    time_value(value)
    return True


def schema_check(value, schema):
    def check_refs(item):
        if isinstance(item, dict):
            for key, sub in item.items():
                if key in ('$ref', '$dynamicRef'):
                    require(isinstance(sub, str) and sub.startswith('#/'), 'external schema reference')
                check_refs(sub)
        elif isinstance(item, list):
            for sub in item:
                check_refs(sub)
    check_refs(schema)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FORMATS).validate(value)


def check_record(obj, kind):
    prefix, version, revision = OBJECTS[kind]
    require(obj.get('schema_version') == version and obj.get('hash_profile') == PROFILE, 'object version/profile')
    require(isinstance(obj.get(prefix + '_id'), str) and obj[prefix + '_id'], 'object id')
    if revision:
        require(re.fullmatch(r'rev\.[1-9][0-9]*', obj.get('revision', '')), 'revision')
    field = prefix + '_content_hash'
    require(obj.get(field) == digest({k: v for k, v in obj.items() if k != field}), 'record hash: ' + kind)
    return {'object_type': kind, 'object_id': obj[prefix + '_id'], 'content_hash': obj[field],
            **({'revision': obj['revision']} if revision else {})}


class Definitions:
    """A checked-in finite catalogue, never a bundle-selected registry or download."""
    def __init__(self):
        self.catalogue = parse(safe_read(DEFINITIONS, 'catalogue.json'))
        require(self.catalogue['schema_version'] == 'research_lab.definition_catalogue.v1', 'catalogue version')
        self.entries = self.catalogue['entries']
        ids = [(e['kind'], e['name'], e['revision']) for e in self.entries]
        require(len(ids) == len(set(ids)), 'conflicting definition identities')

    def resolve(self, kind, ref):
        require(set(ref) == {'name', 'revision', 'content_hash', 'locator'}, 'definition reference fields')
        found = [e for e in self.entries if e['kind'] == kind and e['name'] == ref['name'] and e['revision'] == ref['revision']]
        require(len(found) == 1, 'unknown definition/version')
        entry = found[0]
        require(ref['content_hash'] == entry['content_hash'] and ref['locator'] == entry['locator'], 'definition reference mismatch')
        definition = parse(safe_read(DEFINITIONS, entry['file']))
        for component in entry['pointer']:
            definition = definition[component]
        require(digest(definition) == entry['content_hash'], 'definition hash mismatch')
        return entry, definition

    def method(self, name):
        found = [e for e in self.entries if e['kind'] == 'method' and e['name'] == name]
        require(len(found) == 1, 'unknown method')
        entry = found[0]
        ref = {k: entry[k] for k in ('name', 'revision', 'content_hash', 'locator')}
        _, definition = self.resolve('method', ref)
        require(sha(safe_read(ROOT, entry['source_path'])) == definition['source_sha256'], 'method source hash')
        require(definition['id'] == name and definition['revision'] == entry['revision'], 'method identity')
        return definition


def validate_spec(spec, task, definitions=None):
    """Machine checks for bound methods. No execution, PIT or confirmation approval."""
    definitions = definitions or Definitions()
    schema_check(spec, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))
    if spec['experiment_type'] == 'trading_backtest':
        if spec.get('backtest_profile') == SINGLE_CONTRACT_PROFILE:
            task_schema = 'single-contract-backtest-control.schema.json'
        elif spec.get('method_id') == 'phase0.issue481_minimal_causal_replay.rev1' and spec.get('corrected_events') == 603:
            task_schema = 'issue481-backtest-control.schema.json'
        else:
            raise ValueError('unsupported trading_backtest profile')
    elif spec['experiment_type'] == 'statistical_factor':
        task_schema = 'trend20-control.schema.json'
    else:
        task_schema = 'phase0-control.schema.json'
    schema_check(task, parse(safe_read(DEFINITIONS, task_schema))['$defs']['research_task'])
    check_record(spec, 'experiment_spec')
    check_record(task, 'research_task')
    require((spec['task_id'], spec['task_revision'], spec['task_content_hash']) ==
            (task['task_id'], task['revision'], task['task_content_hash']), 'Task reference')
    require(task['research_type'] == spec['experiment_type'], 'Task type')
    require(spec['research_stage'] != 'confirmation', 'unsupported confirmation admission: exposure evidence not verified')
    if spec['experiment_type'] == 'trading_backtest':
        if spec.get('backtest_profile') == SINGLE_CONTRACT_PROFILE:
            req = spec['dataset_requirements']
            task_data = task['data_requirements']
            require(req['product'] == task_data['product'], 'product mismatch')
            require(req['exact_contract'] == task_data['exact_contract'], 'exact_contract mismatch')
            require(time_value(req['time_range']['start']) < time_value(req['time_range']['end']), 'reversed range')
            require(req['snapshot_sha256'] == task_data['snapshot_sha256'], 'snapshot hash mismatch')
            require(req['snapshot_locator'] == task_data['snapshot_locator'], 'snapshot locator mismatch')
            require(req['provenance'] == task_data['provenance'], 'snapshot provenance mismatch')
            locator = req['snapshot_locator']
            target_path = Path(locator) if os.path.isabs(locator) else ROOT / locator
            require(target_path.is_file() and not target_path.is_symlink(), 'physical snapshot file missing or not regular file')
            raw_bytes = target_path.read_bytes()
            require(sha(raw_bytes) == req['snapshot_sha256'], 'physical snapshot sha256 mismatch')
            return {'profile': SINGLE_CONTRACT_PROFILE}
        method = definitions.method(spec['method_id'])
        require(method['corrected_events'] == spec['corrected_events'] == 603, 'Issue481 corrected events')
        return {'method': method}
    req = spec['dataset_requirements']
    require(time_value(req['time_range']['start']) < time_value(req['time_range']['end']), 'reversed range')
    require(req['snapshot_selection_mode'] == 'fixed_snapshot' and re.fullmatch(r'[a-f0-9]{64}', req.get('snapshot_sha256') or ''), 'unbound snapshot')
    require(len(set(req['universe'])) == len(req['universe']), 'duplicate universe')
    if spec['experiment_type'] == 'statistical_factor':
        return validate_trend20_spec(spec, definitions)
    require(spec['experiment_type'] == 'data_quality', 'unsupported method profile: no registered implementation')
    resolved = {}
    metrics = []
    for check in spec['quality_checks']:
        require(check['check_id'] not in resolved, 'duplicate check')
        method = definitions.method(check['implementation_ref'])
        declarations = method['parameter_definition']
        values = {k: p['default'] for k, p in declarations.items()}
        seen = set()
        for p in check['parameters']:
            name = p['name']
            require(name in declarations and name not in seen, 'unknown/duplicate parameter')
            seen.add(name)
            definition = declarations[name]
            require(p['unit'] == definition['unit'] and p['value_type'] == definition['type'], 'parameter unit/type')
            schema_check(p['value'], {'type': definition['type']})
            values[name] = p['value']
        resolved[check['check_id']] = values
        metrics.append(method['metric'])
    require(spec['metric_specifications'] == metrics, 'metric definition mismatch')
    return resolved



def validate_trend20_spec(spec, definitions):
    """Fail-closed admission for the one retrospective Trend20 profile."""
    require(spec['research_stage'] == 'exploration', 'unsupported statistical stage')
    feature, target = spec['feature_specification'], spec['target_specification']
    require(feature['implementation_ref'] == 'phase0.trend20_same_exact_contract.feature.rev1', 'unknown feature method')
    require(target['implementation_ref'] == 'phase0.trend20_same_exact_contract.forward5_log_return.rev1', 'unknown target method')
    require(feature.get('parameters') == [{'name': 'lookback_official_days', 'value_type': 'integer', 'value': 20, 'unit': 'official_day'}], 'feature parameters')
    require(target['horizon_trading_days'] == 6 and target['return_interval'] == 't+1_to_t+6_same_exact_contract' and target['target_type'] == 'forward_log_return', 'target definition')
    require(spec['split_and_leakage_control'] == {'method': 'retrospective_exploration_no_split', 'train_window_days': 1, 'test_window_days': 1, 'step_size_days': 1, 'leakage_mitigation': {'purging_rule': 'overlapping_labels_retained_and_disclosed', 'embargo_days': 0}}, 'statistical split definition')
    req = spec['dataset_requirements']
    require(req['universe'] == ['ag', 'au', 'cu', 'rb', 'ru', 'sc'] and req['snapshot_sha256'] == 'f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351', 'Trend20 dataset binding')
    require(req['time_range'] == {'start': '2023-01-03T00:00:00.000000Z', 'end': '2024-12-31T00:00:00.000000Z'}, 'Trend20 time range')
    feature_method, target_method = definitions.method(feature['implementation_ref']), definitions.method(target['implementation_ref'])
    require(feature_method['parameters'] == {'lookback_official_days': 20} and target_method['parameters'] == {'start_offset_official_days': 1, 'end_offset_official_days': 6}, 'registered Trend20 parameters')
    expected_metrics = {
        'ic_pearson_cross_sectional': {'calculation_definition_version': 'phase0.trend20.daily_pearson_ic.rev1', 'unit': 'correlation', 'sample_scope': 'daily cross sections with at least four samples', 'precision_rule': 'Round published decimal to 12 places, ROUND_HALF_EVEN; do not round daily inputs.', 'calculation_definition': 'Pearson correlation of same-day Trend20 feature and t+1..t+6 same-contract forward log return, then mean unrounded daily values.', 'undefined_policy': 'null_with_reason_not_zero'},
        'top_bottom_spread': {'calculation_definition_version': 'phase0.trend20.top2_bottom2.rev1', 'unit': 'log_return', 'sample_scope': 'daily cross sections with at least four samples', 'precision_rule': 'Round published decimal to 12 places, ROUND_HALF_EVEN; do not round daily inputs.', 'calculation_definition': 'Mean unrounded daily top2 minus bottom2 same-contract forward log-return spread.', 'undefined_policy': 'null_with_reason_not_zero'},
    }
    metrics = spec['metric_specifications']
    require(len(metrics) == 2 and {m['metric_name'] for m in metrics} == set(expected_metrics), 'Trend20 metrics')
    for metric in metrics:
        require({k: v for k, v in metric.items() if k != 'metric_name'} == expected_metrics[metric['metric_name']], 'Trend20 metric definition')
    return {'feature': feature_method, 'target': target_method}


def validate_statistical_payloads(entries, contents):
    by_role = {entry['role']: contents[entry['artifact_id']] for entry in entries if entry['artifact_id'] in contents}
    summary = by_role['statistical_summary']
    require(summary['method_id'] == 'phase0.trend20_same_exact_contract.rev1', 'summary method')
    require(summary['precision'] == 'half_even_12_decimal_places_from_unrounded_daily_values', 'summary precision')
    require(summary['label_overlap'] and summary['significance_test'] == 'not_performed', 'summary limitations')
    daily = by_role['daily_ic_series']
    require(daily['metric'] == 'daily_cross_sectional_pearson_ic' and daily['precision'] == summary['precision'], 'daily IC definition')
    samples = by_role['sample_feature_target']
    require(samples['fields'] == ['official_day', 'product', 'exact_contract', 'feature_log_return', 'forward_log_return', 'split'], 'sample fields')
    require(samples['units'] == {'feature_log_return': 'log_return', 'forward_log_return': 'log_return'}, 'sample units')

class _VerifiedPayloads(dict):
    """Payload mapping returned by ``validate_manifest`` for one manifest."""

    def __init__(self, contents, manifest, entries):
        super().__init__(contents)
        self._manifest_ref = (
            manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash'],
        )
        self._entry_refs = {
            entry['artifact_id']: (entry['content_sha256'], entry['byte_length'])
            for entry in entries if entry['availability'] == 'present'
        }
        self._content_digests = {
            artifact_id: digest(content) for artifact_id, content in contents.items()
        }


_VERIFIED_PAYLOAD_REFS = []


def _remember_verified_payloads(payloads):
    _VERIFIED_PAYLOAD_REFS[:] = [ref for ref in _VERIFIED_PAYLOAD_REFS if ref() is not None]
    _VERIFIED_PAYLOAD_REFS.append(weakref.ref(payloads))
    return payloads


def _is_verified_payloads(payloads):
    _VERIFIED_PAYLOAD_REFS[:] = [ref for ref in _VERIFIED_PAYLOAD_REFS if ref() is not None]
    return any(ref() is payloads for ref in _VERIFIED_PAYLOAD_REFS)


def validate_manifest(root, manifest, run, definitions=None, *, task=None, spec=None):
    definitions = definitions or Definitions()
    schema_check(manifest, parse(safe_read(ROOT, 'docs/schemas/research-artifact-manifest-v2.schema.json')))
    is_single_contract = False
    if manifest['experiment_type'] == 'trading_backtest':
        if manifest.get('artifact_profile') == SINGLE_CONTRACT_PROFILE:
            run_schema = 'single-contract-backtest-control.schema.json'
            expected_prefix = SINGLE_CONTRACT_PAYLOAD_PREFIX
            is_single_contract = True
        elif manifest.get('artifact_profile') == ROLE_PROFILE:
            entries_list = manifest.get('entries', [])
            has_issue481 = any(e.get('content_schema_ref', {}).get('name', '').startswith('phase0.issue481.') for e in entries_list)
            has_single_contract = any(e.get('content_schema_ref', {}).get('name', '').startswith(SINGLE_CONTRACT_PAYLOAD_PREFIX) for e in entries_list)
            if has_issue481 and not has_single_contract:
                run_schema = 'issue481-backtest-control.schema.json'
                expected_prefix = 'phase0.issue481.'
                is_single_contract = False
            elif has_single_contract and not has_issue481:
                run_schema = 'single-contract-backtest-control.schema.json'
                expected_prefix = SINGLE_CONTRACT_PAYLOAD_PREFIX
                is_single_contract = True
            else:
                raise ValueError('unsupported/mixed trading_backtest manifest profile')
        else:
            raise ValueError('unsupported trading_backtest artifact profile')
    elif manifest['experiment_type'] == 'statistical_factor':
        run_schema = 'trend20-control.schema.json'
        expected_prefix = 'phase0.trend20.'
    else:
        run_schema = 'phase0-control.schema.json'
        expected_prefix = 'phase0.'
    run_definition = 'experiment_run'
    schema_check(run, parse(safe_read(DEFINITIONS, run_schema))['$defs'][run_definition])
    check_record(manifest, 'artifact_manifest')
    check_record(run, 'experiment_run')
    require(run['run_status'] in ('COMPLETED', 'FAILED'), 'nonterminal run')
    require((manifest['run_id'], manifest['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Run reference')
    if is_single_contract and run['run_status'] == 'FAILED':
        required = COMMON | {'failure_diagnostics'}
    else:
        required = COMMON | TYPED[manifest['experiment_type']]
        if run['run_status'] == 'FAILED':
            required |= {'failure_diagnostics'}
    entries = manifest['entries']
    require(required <= {e['role'] for e in entries}, 'missing required role')
    for field in ('artifact_id', 'relative_path'):
        values = [e[field] for e in entries if field in e]
        require(len(values) == len(set(values)), 'duplicate ' + field)
    roles, contents = set(), {}
    for e in entries:
        entry, definition = definitions.resolve('payload', e['content_schema_ref'])
        require(entry['role'] == e['role'], 'schema role mismatch')
        expected_name = expected_prefix + e['role']
        require(entry['name'] == expected_name, 'profile payload definition mismatch')
        # Registered rev.1 definitions specify one complete file, no implicit shards.
        require(e['role'] not in roles, 'unsupported/duplicate shard')
        roles.add(e['role'])
        if e['availability'] == 'unavailable':
            require(run['run_status'] == 'FAILED' and e['role'] != 'failure_diagnostics', 'unavailable required output')
            continue
        require(e['coverage'] == 'complete', 'unsupported partial payload definition')
        require(e['media_type'] == 'application/json', 'unsupported media')
        raw = safe_read(root, e['relative_path'])
        require(len(raw) == e['byte_length'] and sha(raw) == e['content_sha256'], 'payload bytes mismatch')
        content = parse(raw)
        schema_check(content, definition)
        contents[e['artifact_id']] = content
    if manifest['experiment_type'] == 'statistical_factor':
        require(spec is not None and task is not None and spec['experiment_type'] == 'statistical_factor', 'statistical manifest requires Task and Spec')
        validate_spec(spec, task, definitions)
        require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) == (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Trend20 Run Spec reference')
        require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']), 'Trend20 scientific fingerprint')
        metadata = next(contents[e['artifact_id']] for e in entries if e['role'] == 'dataset_metadata')
        require(metadata['snapshot_sha256'] == spec['dataset_requirements']['snapshot_sha256'], 'Trend20 payload snapshot')
        validate_statistical_payloads(entries, contents)
    if manifest['experiment_type'] == 'trading_backtest':
        require(spec is not None and task is not None and spec['experiment_type'] == 'trading_backtest', 'backtest manifest requires Task and Spec')
        validate_spec(spec, task, definitions)
        if is_single_contract:
            require(spec.get('backtest_profile') == SINGLE_CONTRACT_PROFILE, 'SingleContract Spec profile mismatch')
            require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) == (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'SingleContract Run Spec reference')
            require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']), 'SingleContract scientific fingerprint')
            requirements = spec['dataset_requirements']
            computation = run['resolved_computation_manifest']
            task_data = task['data_requirements']
            metadata = next(contents[e['artifact_id']] for e in entries if e['role'] == 'dataset_metadata')
            require(task_data['product'] == requirements['product'] == computation['product'] == metadata['product'], 'SingleContract product binding')
            require(task_data['exact_contract'] == requirements['exact_contract'] == computation['exact_contract'] == metadata['exact_contract'], 'SingleContract exact contract binding')
            require(task_data['snapshot_sha256'] == requirements['snapshot_sha256'] == computation['snapshot_sha256'] == metadata['snapshot_sha256'], 'SingleContract snapshot sha256 binding')
            require(computation['snapshot_byte_length'] == metadata['snapshot_byte_length'], 'SingleContract snapshot byte length binding')
            require(task_data['snapshot_locator'] == requirements['snapshot_locator'] == computation['snapshot_locator'] == metadata['snapshot_locator'], 'SingleContract snapshot locator binding')
            require(task_data['provenance'] == requirements['provenance'] == computation['provenance'] == metadata['provenance'], 'SingleContract provenance binding')
            locator = requirements['snapshot_locator']
            target_path = Path(locator) if os.path.isabs(locator) else ROOT / locator
            require(target_path.is_file() and not target_path.is_symlink(), 'SingleContract physical snapshot file missing or not regular file')
            raw_bytes = target_path.read_bytes()
            require(sha(raw_bytes) == requirements['snapshot_sha256'], 'SingleContract physical snapshot sha256 mismatch')
            require(len(raw_bytes) == computation['snapshot_byte_length'], 'SingleContract physical snapshot byte length mismatch')
            if run['run_status'] == 'COMPLETED':
                summary = next(contents[e['artifact_id']] for e in entries if e['role'] == 'backtest_summary')
                blotter = next(contents[e['artifact_id']] for e in entries if e['role'] == 'trade_blotter')
                curve = next(contents[e['artifact_id']] for e in entries if e['role'] == 'equity_curve')
                require(summary['product'] == blotter['product'] == curve['product'] == requirements['product'], 'SingleContract payload product mismatch')
                require(summary['exact_contract'] == blotter['exact_contract'] == curve['exact_contract'] == requirements['exact_contract'], 'SingleContract payload exact contract mismatch')
                require('accounts' not in summary and 'accounts' not in blotter and 'accounts' not in curve, 'artificial multi-account padding forbidden')
                for t in blotter.get('trades', []):
                    require(isinstance(t.get('volume'), int) and t['volume'] > 0, 'invalid trade volume')
                points = curve.get('points', [])
                if points:
                    pts_time = [p['timestamp'] for p in points]
                    require(pts_time == sorted(pts_time), 'equity curve timestamps must be sorted')
            else:
                diagnostics = next(contents[e['artifact_id']] for e in entries if e['role'] == 'failure_diagnostics')
                require(diagnostics.get('error_type') and diagnostics.get('error_message'), 'failure diagnostics empty')
        else:
            require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) == (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Issue481 Run Spec reference')
            require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']), 'Issue481 scientific fingerprint')
            requirements = spec['dataset_requirements']
            computation = run['resolved_computation_manifest']
            task_data = task['data_requirements']
            summary = next(contents[e['artifact_id']] for e in entries if e['role'] == 'backtest_summary')
            blotter = next(contents[e['artifact_id']] for e in entries if e['role'] == 'trade_blotter')
            metadata = next(contents[e['artifact_id']] for e in entries if e['role'] == 'dataset_metadata')
            require(task_data['products'] == requirements['products'] == computation['products'] == metadata['products'], 'Issue481 product binding')
            require(task_data['input_snapshots'] == requirements['input_snapshots'] == computation['input_snapshots'] == metadata['input_snapshots'], 'Issue481 input snapshot binding')
            require(requirements['snapshot_sha256'] == computation['snapshot_sha256'] == metadata['snapshot_sha256'], 'Issue481 curve snapshot binding')
            require(task_data['dev_dates'] == computation['dev_dates'] == [requirements['time_range']['start'][:10], requirements['time_range']['end'][:10]], 'Issue481 DEV date binding')
            require(task_data['warmup_from'] == requirements['warmup_from'] == computation['warmup_from'], 'Issue481 warmup binding')
            require(spec['cost_model'] == computation['cost_scenarios']['fee_model'], 'Issue481 cost binding')
            require(summary['accounts'] == summary['products'] == blotter['accounts'] == ['ag', 'au', 'cu', 'rb', 'ru', 'sc'], 'account products')
            curve = next(contents[e['artifact_id']] for e in entries if e['role'] == 'equity_curve')
            require(curve['accounts'] == summary['accounts'], 'equity account coverage')
            expected = {(path, scenario, product) for path in ('CANDIDATE', 'PAIRED') for scenario in ('PRIMARY_2S', 'STRESS_5S') for product in summary['accounts']}
            def identities(value):
                rows = value['account_identities']
                actual = {(row['path'], row['scenario'], row['product']) for row in rows}
                require(len(rows) == len(actual) == 24 and actual == expected, 'account identity coverage')
                require(all(row['account_id'] == ':'.join((row['path'], row['scenario'], row['product'])) for row in rows), 'account identity format')
            identities(summary)
            identities(blotter)
            identities(curve)
            metrics = summary['account_metrics']
            metric_ids = {row['account_id'] for row in metrics}
            require(len(metrics) == len(metric_ids) == 24 and metric_ids == {':'.join(row) for row in expected}, 'account metric coverage')
            require(all(row['account_id'] == ':'.join((row['path'], row['scenario'], row['product'])) for row in metrics), 'account metric identity')
            point_ids = {point['account_id'] for point in curve['points']}
            require(point_ids == {':'.join(row) for row in expected}, 'missing equity account')
            point_times = {}
            for point in curve['points']:
                require(point['account'] == point['product'] and point['account_id'] == ':'.join((point['path'], point['scenario'], point['product'])), 'equity account identity')
                time_value(point['official_day'] + 'T00:00:00.000000Z')
                require('2023-01-03' <= point['official_day'] < '2025-01-01', 'equity DEV range')
                point_times.setdefault(point['account_id'], []).append(point['official_day'])
            require(all(times == sorted(times) and len(times) == len(set(times)) for times in point_times.values()), 'equity point order')
            by_account = {}
            for item in blotter['fills']:
                require(item['account'] == item['product'] and item['account_id'] == ':'.join((item['path'], item['scenario'], item['product'])), 'fill account identity')
                require(item['exact_contract'].startswith(item['product']) and len(item['exact_contract']) > len(item['product']), 'exact contract product')
                by_account.setdefault(item['account_id'], []).append(item['fill_sequence'])
            require(all(values == sorted(values) and len(values) == len(set(values)) for values in by_account.values()), 'fill order')
    return _remember_verified_payloads(_VerifiedPayloads(contents, manifest, entries))


def _validate_problem_response(response):
    """Validate the shared non-delivery response contract."""
    require(response['status'] in ('blocked', 'rejected', 'incomplete', 'unsupported'), 'response status')
    require('output_refs' not in response, 'noncompleted output reference')
    problem = response.get('problem')
    require(isinstance(problem, dict), 'problem definition')
    expected_codes = {
        'blocked': {'dependency_unavailable', 'execution_outcome_unknown'},
        'rejected': {'invalid_input'},
        'incomplete': {'missing_delivery'},
        'unsupported': {'capability_unsupported'},
    }
    require(problem.get('code') in expected_codes[response['status']], 'problem status/code')
    require(bool(problem.get('reason')), 'problem reason')
    require(isinstance(problem.get('affected_items'), list) and len(problem['affected_items']) >= 1,
            'problem affected items')
    require(bool(problem.get('resume_condition')), 'problem resume condition')
    require(problem.get('execution_outcome') in ('not_started', 'known', 'unknown'),
            'problem execution outcome')
    require((problem['execution_outcome'] == 'unknown') == (
        response['status'] == 'blocked' and problem['code'] == 'execution_outcome_unknown'
    ), 'problem unknown outcome/status')


def _present_artifact_refs(manifest):
    return [{**{key: manifest[value] for key, value in (
        ('manifest_id', 'manifest_id'), ('manifest_revision', 'revision'),
        ('manifest_content_hash', 'manifest_content_hash'))},
        **{key: entry[key] for key in ('artifact_id', 'role', 'content_sha256')}}
        for entry in manifest['entries'] if entry['availability'] == 'present']


def _resolve_manifest_payload(manifest, definitions, role, *, payloads, root):
    """Read one present payload with the same provenance checks for both inputs."""
    entry = next((item for item in manifest['entries'] if item['role'] == role), None)
    require(entry is not None and entry['availability'] == 'present',
            'missing required payload: ' + role)
    _, definition = definitions.resolve('payload', entry['content_schema_ref'])
    if payloads is not None:
        require(isinstance(payloads, _VerifiedPayloads) and _is_verified_payloads(payloads),
                'verified payloads required')
        require(payloads._manifest_ref == (
            manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash'],
        ), 'verified payload manifest mismatch')
        artifact_id = entry['artifact_id']
        require(payloads._entry_refs.get(artifact_id) == (
            entry['content_sha256'], entry['byte_length'],
        ), 'verified payload reference mismatch: ' + role)
        require(artifact_id in payloads and artifact_id in payloads._content_digests,
                'missing verified payload content for ' + role)
        content = payloads[artifact_id]
        require(payloads._content_digests[artifact_id] == digest(content),
                'verified payload content mutated: ' + role)
        schema_check(content, definition)
        return content
    if root is not None:
        require('relative_path' in entry, 'missing relative_path for ' + role)
        raw = safe_read(root, entry['relative_path'])
        require(len(raw) == entry['byte_length'] and sha(raw) == entry['content_sha256'],
                'payload bytes mismatch: ' + role)
        content = parse(raw)
        schema_check(content, definition)
        return content
    raise ValueError('verified payloads or root required for ' + role)


def _parse_revision_number(rev_str):
    require(isinstance(rev_str, str) and rev_str.startswith('rev.') and
            rev_str[4:].isdigit() and int(rev_str[4:]) >= 1, 'invalid revision')
    return int(rev_str[4:])


def _validate_problem_context(request, objects, response, operation):
    """Allow a problem report to retain only request references it can verify."""
    response_refs = response['context_refs']
    if not response_refs:
        return
    request_refs = request.get('context_refs')
    require(isinstance(request_refs, dict), f'{operation} problem context')
    require(set(response_refs) <= set(request_refs), f'{operation} problem response context')
    for kind, reference in response_refs.items():
        require(kind in objects and reference == request_refs[kind] == check_record(objects[kind], kind),
                f'{operation} problem context reference: ' + kind)


def _validate_execute_problem_context(request, objects, response):
    return _validate_problem_context(request, objects, response, 'execute_spec')


def _validate_execute_spec_handoff(request, objects, response, schema, *, payloads, root):
    """Offline delivery check for the one registered data-quality execution profile."""
    # A problem report may describe an unresolvable request without pretending it
    # had a valid Task/Spec admission.  Do not inspect future delivery objects.
    if response is not None and isinstance(response, dict) and response.get('status') != 'completed':
        schema_check(response, schema)
        require(isinstance(request, dict) and request.get('schema_version') == 'research_lab.agent_handoff.v2' and
                request.get('message_kind') == 'request' and
                request.get('operation') == 'execute_spec' and
                (request.get('sender_role'), request.get('recipient_role')) == ('research', 'execution'),
                'execute_spec problem request')
        require(isinstance(request.get('handoff_id'), str) and request['handoff_id'],
                'execute_spec problem correlation')
        require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'] and
                response['operation'] == 'execute_spec' and
                (response['sender_role'], response['recipient_role']) == ('execution', 'research'),
                'execute_spec problem response')
        _validate_problem_response(response)
        if (response['status'], response['problem']['code']) == ('rejected', 'invalid_input'):
            _validate_execute_problem_context(request, objects, response)
            return True
        schema_check(request, schema)
        if (response['status'], response['problem']['code']) == ('unsupported', 'capability_unsupported'):
            _validate_execute_problem_context(request, objects, response)
            return True

    schema_check(request, schema)
    require(request['message_kind'] == 'request', 'execute_spec request')
    require((request['sender_role'], request['recipient_role']) == ('research', 'execution'),
            'execute_spec request direction')
    required_request_objects = {'research_task', 'experiment_spec'}
    require(required_request_objects <= set(objects), 'missing execute_spec request context')
    task, spec = objects['research_task'], objects['experiment_spec']
    spec_profile = (spec.get('experiment_type'), spec.get('research_stage'))
    is_single_contract = (
        spec_profile == ('trading_backtest', 'validation') and
        spec.get('backtest_profile') == SINGLE_CONTRACT_PROFILE
    )
    require(spec_profile == ('data_quality', 'validation') or is_single_contract,
            'unsupported execute_spec profile')
    definitions = Definitions()
    resolved = validate_spec(spec, task, definitions)
    require(set(request['context_refs']) == required_request_objects, 'execute_spec request context set')
    for kind in required_request_objects:
        require(request['context_refs'][kind] == check_record(objects[kind], kind),
                'context reference: ' + kind)
    required_roles = COMMON | TYPED[spec['experiment_type']]
    requirements = request['artifact_requirements']
    require(requirements['role_profile_ref'] == ROLE_PROFILE, 'execute_spec role profile')
    require(len(requirements['required_roles']) == len(set(requirements['required_roles'])) and
            set(requirements['required_roles']) == required_roles, 'execute_spec required roles')
    require(requirements['exact_refs'] == [], 'execute_spec future artifact references')
    expected = [
        {'object_type': 'experiment_run', 'schema_version': 'research_lab.run.v2'},
        {'object_type': 'artifact_manifest', 'schema_version': 'research_lab.artifact_manifest.v2'},
        {'object_type': 'result_evidence', 'schema_version': 'research_lab.evidence.v2'},
    ]
    require(request['expected_outputs'] == expected, 'execute_spec expected outputs')
    if response is None:
        return True

    schema_check(response, schema)
    require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'],
            'response correlation')
    require(response['operation'] == request['operation'] and
            (response['sender_role'], response['recipient_role']) == ('execution', 'research'),
            'execute_spec response direction')
    require(response['context_refs'] == request['context_refs'], 'execute_spec response context')
    if response['status'] != 'completed':
        _validate_problem_response(response)
        return True
    required_delivery = {'experiment_run', 'artifact_manifest', 'result_evidence'}
    require(required_delivery <= set(objects), 'missing execute_spec delivery')
    run, manifest, evidence = (objects['experiment_run'], objects['artifact_manifest'],
                               objects['result_evidence'])
    if is_single_contract:
        control_defs = parse(safe_read(DEFINITIONS, 'single-contract-backtest-control.schema.json'))['$defs']
        evidence_defs = parse(safe_read(DEFINITIONS, 'review-evidence.schema.json'))['$defs']
    else:
        control_defs = parse(safe_read(DEFINITIONS, 'phase0-control.schema.json'))['$defs']
        evidence_defs = None

    for kind, obj in objects.items():
        if kind == 'result_evidence' and evidence_defs is not None:
            schema_check(obj, {'$defs': evidence_defs, '$ref': '#/$defs/single_contract_result_evidence'})
        elif kind in control_defs:
            schema_check(obj, control_defs[kind])
        elif kind == 'experiment_spec':
            schema_check(obj, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))
        elif kind == 'artifact_manifest':
            schema_check(obj, parse(safe_read(ROOT, 'docs/schemas/research-artifact-manifest-v2.schema.json')))
    require(run['run_status'] in ('COMPLETED', 'FAILED'), 'nonterminal run')
    require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) ==
            (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Run Spec reference')
    require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']),
            'scientific fingerprint')
    require(time_value(run['timing']['started_at']) <= time_value(run['timing']['completed_at']),
            'Run time order')
    require(run['process_exit_code'] == (0 if run['run_status'] == 'COMPLETED' else 1),
            'Run exit status')
    computation = run['resolved_computation_manifest']
    requirements_spec = spec['dataset_requirements']
    if is_single_contract:
        require(computation['profile'] == SINGLE_CONTRACT_PROFILE, 'Run profile binding')
        require(computation['product'] == requirements_spec['product'], 'Run product binding')
        require(computation['exact_contract'] == requirements_spec['exact_contract'], 'Run exact_contract binding')
        require(computation['snapshot_sha256'] == requirements_spec['snapshot_sha256'], 'Run snapshot hash binding')
    else:
        require(computation['raw_bytes_sha256'] == requirements_spec['snapshot_sha256'] and
                computation['resolved_parameters'] == resolved['source_order'] and
                computation['scientific_time'] == requirements_spec['time_range'] and
                computation['universe'] == requirements_spec['universe'] and
                computation['normalization_rule_version'] == requirements_spec['normalization_rule_version'],
                'Run data-quality Spec binding')
        require(requirements_spec['universe'] == task['data_requirements']['products'] and
                requirements_spec['time_range']['start'][:10] == task['data_requirements']['date_start'] and
                requirements_spec['time_range']['end'][:10] == task['data_requirements']['date_end_exclusive'],
                'Task data-quality range binding')
        require(computation['holdout_usage_state'] == 'not_applicable' and
                run['trial_context'] == {'research_stage': 'validation', 'trial_kind': None,
                                         'retry_of_run_id': None, 'holdout_usage_state': 'not_applicable'},
                'Run data-quality metadata')
    verified = validate_manifest(root, manifest, run, definitions, task=task, spec=spec) if root is not None else payloads
    require(isinstance(verified, _VerifiedPayloads) and _is_verified_payloads(verified),
            'verified payloads required')
    require(verified._manifest_ref == (manifest['manifest_id'], manifest['revision'],
                                       manifest['manifest_content_hash']), 'verified payload manifest mismatch')
    require((evidence['run_id'], evidence['run_content_hash']) ==
            (run['run_id'], run['run_content_hash']), 'Evidence Run reference')
    require((evidence['manifest_id'], evidence['manifest_revision'], evidence['manifest_content_hash']) ==
            (manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash']),
            'Evidence Manifest reference')
    require(evidence['run_status_snapshot'] == evidence['execution_status'] == run['run_status'],
            'Evidence status')
    require(manifest['experiment_type'] == spec['experiment_type'] and
            manifest['artifact_profile'] == requirements['role_profile_ref'],
            'Manifest delivery metadata')
    present = _present_artifact_refs(manifest)
    require(evidence['supporting_artifacts'] == present, 'Evidence artifact references')
    actual_roles = {item['role'] for item in present}
    manifest_roles = {entry['role'] for entry in manifest['entries']}
    if is_single_contract and run['run_status'] == 'FAILED':
        expected_roles = COMMON | {'failure_diagnostics'}
    else:
        expected_roles = required_roles | ({'failure_diagnostics'} if run['run_status'] == 'FAILED' else set())
    require(expected_roles <= manifest_roles,
            'execute_spec delivered roles')
    if run['run_status'] == 'FAILED':
        diagnostic = next((entry for entry in manifest['entries'] if entry['role'] == 'failure_diagnostics'), None)
        require(diagnostic is not None and diagnostic['availability'] == 'present', 'failure diagnostics delivery')
        require(evidence['typed_metrics'] is None and evidence['missing_reason'] == 'execution_failed',
                'FAILED evidence delivery')
    else:
        require(actual_roles == required_roles, 'unexpected completed delivery role')
    contents = {
        entry['role']: _resolve_manifest_payload(manifest, definitions, entry['role'],
                                                 payloads=verified, root=None)
        for entry in manifest['entries'] if entry['availability'] == 'present'
    }
    if is_single_contract:
        metadata = contents['dataset_metadata']
        require(metadata['snapshot_sha256'] == computation['snapshot_sha256'] == requirements_spec['snapshot_sha256'],
                'single-contract dataset metadata binding')
        require(metadata['product'] == computation['product'] == requirements_spec['product'],
                'single-contract dataset product binding')
        require(metadata['exact_contract'] == computation['exact_contract'] == requirements_spec['exact_contract'],
                'single-contract dataset exact contract binding')
        if run['run_status'] == 'COMPLETED':
            summary = contents['backtest_summary']
            metrics = evidence['typed_metrics']
            require(metrics is not None and metrics['profile'] == SINGLE_CONTRACT_PROFILE, 'SingleContract evidence profile')
            require(metrics['net_pnl'] == summary['net_pnl'] and metrics['total_fees'] == summary['total_fees'] and metrics['trade_count'] == summary['total_trades'],
                    'SingleContract evidence facts')
    else:
        metadata, method_definition = contents['dataset_metadata'], contents['method_definition']
        method_entry = next(entry for entry in manifest['entries'] if entry['role'] == 'method_definition')
        method = definitions.method(spec['quality_checks'][0]['implementation_ref'])
        require(method_definition == method and
                computation['method_definition_sha256'] == method_entry['content_sha256'],
                'data-quality method binding')
        require(metadata['snapshot_sha256'] == computation['raw_bytes_sha256'] == requirements_spec['snapshot_sha256'] and
                metadata['time_range'] == computation['scientific_time'] == requirements_spec['time_range'] and
                metadata['fields'] == requirements_spec['required_fields'] and
                metadata['source']['projection'].split(';', 1)[0].strip() == ','.join(computation['universe']),
                'data-quality dataset metadata binding')
        if run['run_status'] == 'COMPLETED':
            summary, anomalies = contents['quality_summary'], contents['quality_anomalies']
            require(summary is not None and anomalies is not None, 'missing data quality payload')
            metrics = evidence['typed_metrics']
            require(isinstance(metrics, list) and len(metrics) == 1 and
                    metrics[0]['metric'] == spec['metric_specifications'][0] and
                    metrics[0]['sample_count'] == summary['comparison_count'] and
                    metrics[0]['value'] == summary['timestamp_monotonicity_violations'],
                    'Evidence data quality facts')
    require(response['output_refs'] == [check_record(run, 'experiment_run'),
                                        check_record(manifest, 'artifact_manifest'),
                                        check_record(evidence, 'result_evidence')],
            'execute_spec output references')
    return True


def _dq_registered_fields(definitions):
    """Derive authoritative registered field list for phase0 data_quality from catalogue."""
    entry = next(e for e in definitions.entries if e['kind'] == 'payload' and e['name'] == 'phase0.dataset_metadata')
    ref = {k: entry[k] for k in ('name', 'revision', 'content_hash', 'locator')}
    _, schema = definitions.resolve('payload', ref)
    return schema['properties']['fields']['const']


def _validate_dq_spec_dataset_requirements(requirements_spec, task, definitions):
    """Validate data_quality dataset_requirements against task and registered DQ method."""
    task_data = task['data_requirements']
    req_fields = requirements_spec.get('required_fields')
    require(isinstance(req_fields, list) and 'source_official_day' in req_fields,
            'data-quality spec missing source_official_day')
    registered_fields = _dq_registered_fields(definitions)
    require(isinstance(req_fields, list) and
            all(f in req_fields for f in registered_fields) and
            req_fields == registered_fields,
            'data-quality spec registered method field contract')
    require(req_fields == task_data.get('fields'),
            'Task data-quality required fields binding')
    task_start = task_data.get('date_start')
    task_end = task_data.get('date_end_exclusive')
    time_range = requirements_spec.get('time_range') or {}
    start = time_range.get('start')
    end = time_range.get('end')
    require(requirements_spec.get('universe') == task_data.get('products') and
            isinstance(task_start, str) and isinstance(task_end, str) and
            task_start < task_end and
            isinstance(start, str) and isinstance(end, str) and
            start[:10] < end[:10] and
            start == f"{task_start}T00:00:00.000000Z" and
            end == f"{task_end}T00:00:00.000000Z",
            'Task data-quality range binding')


def _validate_prepare_spec_handoff(request, objects, response, schema):
    """Offline delivery check for prepare_spec in data_quality/validation."""
    if response is not None and isinstance(response, dict) and response.get('status') != 'completed':
        schema_check(response, schema)
        require(isinstance(request, dict) and request.get('schema_version') == 'research_lab.agent_handoff.v2' and
                request.get('message_kind') == 'request' and
                request.get('operation') == 'prepare_spec' and
                (request.get('sender_role'), request.get('recipient_role')) == ('research', 'research'),
                'prepare_spec problem request')
        require(isinstance(request.get('handoff_id'), str) and request['handoff_id'],
                'prepare_spec problem correlation')
        require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'] and
                response['operation'] == 'prepare_spec' and
                (response['sender_role'], response['recipient_role']) == ('research', 'research'),
                'prepare_spec problem response')
        require(response.get('handoff_id') != request['handoff_id'],
                'response handoff_id must differ from request')
        _validate_problem_response(response)
        if (response['status'], response['problem']['code']) == ('rejected', 'invalid_input'):
            _validate_problem_context(request, objects, response, 'prepare_spec')
            return True
        schema_check(request, schema)
        if (response['status'], response['problem']['code']) == ('unsupported', 'capability_unsupported'):
            _validate_problem_context(request, objects, response, 'prepare_spec')
            return True

    schema_check(request, schema)
    require(request['message_kind'] == 'request', 'prepare_spec request')
    require((request['sender_role'], request['recipient_role']) == ('research', 'research'),
            'prepare_spec request direction')
    require(set(request['context_refs']) == {'research_task'}, 'unsupported prepare_spec context')
    require('research_task' in objects, 'missing research_task')
    task = objects['research_task']
    controls = parse(safe_read(DEFINITIONS, 'phase0-control.schema.json'))['$defs']
    schema_check(task, controls['research_task'])
    require(task.get('research_type') == 'data_quality', 'unsupported prepare_spec task research_type')
    require(request['context_refs']['research_task'] == check_record(task, 'research_task'),
            'context reference: research_task')
    requirements = request['artifact_requirements']
    require(requirements['role_profile_ref'] == ROLE_PROFILE, 'prepare_spec role profile')
    require(requirements['required_roles'] == [], 'prepare_spec required roles must be empty')
    require(requirements['exact_refs'] == [], 'prepare_spec exact refs must be empty')
    require(request['expected_outputs'] == [
        {'object_type': 'experiment_spec', 'schema_version': 'research_lab.experiment.v2'}
    ], 'prepare_spec expected outputs')
    if response is None:
        return True

    schema_check(response, schema)
    require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'],
            'response correlation')
    require(response.get('handoff_id') != request['handoff_id'],
            'response handoff_id must differ from request')
    require(response['operation'] == 'prepare_spec' and
            (response['sender_role'], response['recipient_role']) == ('research', 'research'),
            'prepare_spec response direction')
    require(response['context_refs'] == request['context_refs'], 'prepare_spec response context')
    if response['status'] != 'completed':
        _validate_problem_response(response)
        return True

    require(len(response.get('output_refs', [])) == 1 and
            response['output_refs'][0]['object_type'] == 'experiment_spec',
            'prepare_spec output reference')
    require('experiment_spec' in objects, 'missing experiment_spec delivery')
    spec = objects['experiment_spec']
    require((spec.get('experiment_type'), spec.get('research_stage')) == ('data_quality', 'validation'),
            'unsupported prepare_spec profile')
    schema_check(spec, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))
    require(response['output_refs'][0] == check_record(spec, 'experiment_spec'), 'output reference mismatch')
    definitions = Definitions()
    validate_spec(spec, task, definitions)
    _validate_dq_spec_dataset_requirements(spec['dataset_requirements'], task, definitions)
    return True


def _validate_revise_spec_handoff(request, objects, response, schema, *, payloads, root):
    """Offline delivery check for revise_spec in data_quality/validation."""
    if response is not None and isinstance(response, dict) and response.get('status') != 'completed':
        schema_check(response, schema)
        require(isinstance(request, dict) and request.get('schema_version') == 'research_lab.agent_handoff.v2' and
                request.get('message_kind') == 'request' and
                request.get('operation') == 'revise_spec' and
                (request.get('sender_role'), request.get('recipient_role')) == ('critic', 'research'),
                'revise_spec problem request')
        require(isinstance(request.get('handoff_id'), str) and request['handoff_id'],
                'revise_spec problem correlation')
        require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'] and
                response['operation'] == 'revise_spec' and
                (response['sender_role'], response['recipient_role']) == ('research', 'critic'),
                'revise_spec problem response')
        require(response.get('handoff_id') != request['handoff_id'],
                'response handoff_id must differ from request')
        _validate_problem_response(response)
        if (response['status'], response['problem']['code']) == ('rejected', 'invalid_input'):
            _validate_problem_context(request, objects, response, 'revise_spec')
            return True
        schema_check(request, schema)
        if (response['status'], response['problem']['code']) == ('unsupported', 'capability_unsupported'):
            _validate_problem_context(request, objects, response, 'revise_spec')
            return True

    schema_check(request, schema)
    require(request['message_kind'] == 'request', 'revise_spec request')
    require((request['sender_role'], request['recipient_role']) == ('critic', 'research'),
            'revise_spec request direction')
    required_request_objects = {'research_task', 'experiment_spec', 'experiment_run',
                                'artifact_manifest', 'result_evidence', 'review'}
    require(set(request['context_refs']) == required_request_objects, 'revise_spec request context set')
    require(required_request_objects <= set(objects), 'missing revise_spec request context')
    task = objects['research_task']
    old_spec = objects['experiment_spec']
    run = objects['experiment_run']
    manifest = objects['artifact_manifest']
    evidence = objects['result_evidence']
    review = objects['review']

    controls = parse(safe_read(DEFINITIONS, 'phase0-control.schema.json'))['$defs']
    schema_check(task, controls['research_task'])
    schema_check(run, controls['experiment_run'])
    schema_check(evidence, controls['result_evidence'])
    schema_check(review, controls['review'])
    schema_check(old_spec, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))
    schema_check(manifest, parse(safe_read(ROOT, 'docs/schemas/research-artifact-manifest-v2.schema.json')))

    for kind in required_request_objects:
        require(request['context_refs'][kind] == check_record(objects[kind], kind),
                'context reference: ' + kind)

    require(task.get('research_type') == 'data_quality', 'unsupported revise_spec task research_type')
    require((old_spec.get('experiment_type'), old_spec.get('research_stage')) == ('data_quality', 'validation'),
            'unsupported revise_spec profile')
    require(run['run_status'] == 'COMPLETED' and run['process_exit_code'] == 0,
            'revise_spec requires COMPLETED run')
    require(request['expected_outputs'] == [
        {'object_type': 'experiment_spec', 'schema_version': 'research_lab.experiment.v2'}
    ], 'revise_spec expected outputs')

    definitions = Definitions()
    resolved_old = validate_spec(old_spec, task, definitions)
    requirements_spec = old_spec['dataset_requirements']
    require(requirements_spec['universe'] == task['data_requirements']['products'] and
            requirements_spec['time_range']['start'][:10] == task['data_requirements']['date_start'] and
            requirements_spec['time_range']['end'][:10] == task['data_requirements']['date_end_exclusive'],
            'Task data-quality range binding')

    require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) ==
            (old_spec['spec_id'], old_spec['revision'], old_spec['spec_content_hash']),
            'Run Spec reference')
    require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']),
            'scientific fingerprint')
    require(time_value(run['timing']['started_at']) <= time_value(run['timing']['completed_at']),
            'Run time order')
    computation = run['resolved_computation_manifest']
    require(computation['raw_bytes_sha256'] == requirements_spec['snapshot_sha256'] and
            computation['resolved_parameters'] == resolved_old['source_order'] and
            computation['scientific_time'] == requirements_spec['time_range'] and
            computation['universe'] == requirements_spec['universe'] and
            computation['normalization_rule_version'] == requirements_spec['normalization_rule_version'],
            'Run data-quality Spec binding')
    require(computation['holdout_usage_state'] == 'not_applicable' and
            run['trial_context'] == {'research_stage': 'validation', 'trial_kind': None,
                                     'retry_of_run_id': None, 'holdout_usage_state': 'not_applicable'},
            'Run data-quality metadata')

    verified = validate_manifest(root, manifest, run, definitions, task=task, spec=old_spec) if root is not None else payloads
    require(isinstance(verified, _VerifiedPayloads) and _is_verified_payloads(verified),
            'verified payloads or root required')
    require(verified._manifest_ref == (manifest['manifest_id'], manifest['revision'],
                                       manifest['manifest_content_hash']),
            'verified payload manifest mismatch')

    require((manifest['run_id'], manifest['run_content_hash']) == (run['run_id'], run['run_content_hash']),
            'Manifest Run reference')
    require(manifest['experiment_type'] == old_spec['experiment_type'] and
            manifest['artifact_profile'] == ROLE_PROFILE,
            'Manifest data-quality delivery metadata')

    require((evidence['run_id'], evidence['run_content_hash']) == (run['run_id'], run['run_content_hash']),
            'Evidence Run reference')
    require((evidence['manifest_id'], evidence['manifest_revision'], evidence['manifest_content_hash']) ==
            (manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash']),
            'Evidence Manifest reference')
    require(evidence['run_status_snapshot'] == evidence['execution_status'] == run['run_status'],
            'Evidence status')

    present = _present_artifact_refs(manifest)
    require(evidence['supporting_artifacts'] == present, 'Evidence artifact references')
    actual_roles = {item['role'] for item in present}
    required_roles = COMMON | TYPED['data_quality']
    require(actual_roles == required_roles, 'unexpected completed delivery role')

    requirements = request['artifact_requirements']
    require(requirements['role_profile_ref'] == manifest['artifact_profile'], 'revise_spec role profile')
    requested_roles = set(requirements['required_roles'])
    require(requested_roles == required_roles and len(requirements['required_roles']) == len(required_roles),
            'revise_spec required roles')
    require(requirements['exact_refs'] == present, 'revise_spec exact artifact references')

    contents = {
        entry['role']: _resolve_manifest_payload(manifest, definitions, entry['role'],
                                                 payloads=verified, root=None)
        for entry in manifest['entries'] if entry['availability'] == 'present'
    }
    metadata, method_definition = contents['dataset_metadata'], contents['method_definition']
    method_entry = next(entry for entry in manifest['entries'] if entry['role'] == 'method_definition')
    method = definitions.method(old_spec['quality_checks'][0]['implementation_ref'])
    require(method_definition == method and
            computation['method_definition_sha256'] == method_entry['content_sha256'],
            'data-quality method binding')
    require(metadata['snapshot_sha256'] == computation['raw_bytes_sha256'] == requirements_spec['snapshot_sha256'] and
            metadata['time_range'] == computation['scientific_time'] == requirements_spec['time_range'] and
            metadata['fields'] == requirements_spec['required_fields'] and
            metadata['source']['projection'].split(';', 1)[0].strip() == ','.join(computation['universe']),
            'data-quality dataset metadata binding')
    summary, anomalies = contents['quality_summary'], contents['quality_anomalies']
    require(summary is not None and anomalies is not None, 'missing data quality payload')
    metrics = evidence['typed_metrics']
    require(isinstance(metrics, list) and len(metrics) == 1 and
            metrics[0]['metric'] == old_spec['metric_specifications'][0] and
            metrics[0]['sample_count'] == summary['comparison_count'] and
            metrics[0]['value'] == summary['timestamp_monotonicity_violations'],
            'Evidence data quality facts')

    require((review['evidence_id'], review['evidence_content_hash']) ==
            (evidence['evidence_id'], evidence['evidence_content_hash']),
            'Review Evidence reference')
    criteria = review['criteria_ref']
    candidates = [e for e in definitions.entries if e['kind'] == 'criteria' and
                  (e['name'], e['revision']) == (criteria['id'], criteria['revision'])]
    require(len(candidates) == 1, 'unknown criteria definition')
    _, criterion = definitions.resolve('criteria', {
        'name': criteria['id'], 'revision': criteria['revision'],
        'content_hash': criteria['content_hash'], 'locator': candidates[0]['locator'],
    })
    require(criterion['id'] == 'phase0-date-order-criteria', 'criteria profile')
    require(time_value(review['reviewed_at']) >= time_value(run['timing']['completed_at']),
            'Review time order')

    for kind, expected_ref in REVISE_SPEC_544_SOURCE_ANCHOR.items():
        require(request['context_refs'][kind] == expected_ref,
                f'#544 source identity anchor mismatch: {kind}')

    if response is None:
        return True

    schema_check(response, schema)
    require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'],
            'response correlation')
    require(response.get('handoff_id') != request['handoff_id'],
            'response handoff_id must differ from request')
    require(response['operation'] == 'revise_spec' and
            (response['sender_role'], response['recipient_role']) == ('research', 'critic'),
            'revise_spec response direction')
    require(response['context_refs'] == request['context_refs'], 'revise_spec response context')
    if response['status'] != 'completed':
        _validate_problem_response(response)
        return True

    require(len(response.get('output_refs', [])) == 1 and
            response['output_refs'][0]['object_type'] == 'experiment_spec',
            'revise_spec output reference')
    new_spec = objects.get('revised_experiment_spec')
    require(new_spec is not None, 'missing revised_experiment_spec')
    require(new_spec is not old_spec, 'revised spec cannot be identical object to old spec')
    require(new_spec != old_spec, 'revised spec cannot be identical content to old spec')

    require(new_spec['spec_id'] == old_spec['spec_id'], 'revised spec must have same spec_id')
    old_rev = _parse_revision_number(old_spec['revision'])
    new_rev = _parse_revision_number(new_spec['revision'])
    require(new_rev > old_rev, 'revised spec revision must strictly increase')

    require((new_spec.get('experiment_type'), new_spec.get('research_stage')) == ('data_quality', 'validation'),
            'unsupported revised spec profile')
    require(new_spec['experiment_type'] == old_spec['experiment_type'] and
            new_spec['research_stage'] == old_spec['research_stage'],
            'revised spec cannot change type or stage')

    schema_check(new_spec, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))

    require(new_spec['task_id'] == task['task_id'] == old_spec['task_id'],
            'revised spec task_id mismatch')
    require(new_spec['task_revision'] == task['revision'] == old_spec['task_revision'],
            'revised spec task_revision mismatch')
    require(new_spec['task_content_hash'] == task['task_content_hash'] == old_spec['task_content_hash'],
            'revised spec task_content_hash mismatch')

    require(response['output_refs'][0] == check_record(new_spec, 'experiment_spec'),
            'output reference mismatch')
    validate_spec(new_spec, task, definitions)
    _validate_dq_spec_dataset_requirements(new_spec['dataset_requirements'], task, definitions)
    return True


def validate_handoff(request, objects, response=None, *, payloads=None, root=None):
    """Fail-closed offline admission for registered review, execute, prepare, and revise profiles."""
    schema = parse(safe_read(ROOT, 'docs/research-lab/agent-contract/agent-handoff.schema.json'))
    if isinstance(request, dict):
        op = request.get('operation')
        if op == 'execute_spec':
            return _validate_execute_spec_handoff(request, objects, response, schema,
                                                  payloads=payloads, root=root)
        if op == 'prepare_spec':
            return _validate_prepare_spec_handoff(request, objects, response, schema)
        if op == 'revise_spec':
            return _validate_revise_spec_handoff(request, objects, response, schema,
                                                 payloads=payloads, root=root)
    schema_check(request, schema)
    return _validate_review_handoff(request, objects, response, payloads=payloads, root=root)


def _validate_review_handoff(request, objects, response=None, *, payloads=None, root=None):
    """Fail-closed offline review consumption for three registered profiles only."""
    schema = parse(safe_read(ROOT, 'docs/research-lab/agent-contract/agent-handoff.schema.json'))
    schema_check(request, schema)
    require(request['message_kind'] == 'request' and request['operation'] == 'review_evidence', 'unsupported cross-object operation')
    required_objects = {'research_task', 'experiment_spec', 'experiment_run', 'artifact_manifest', 'result_evidence'}
    require(required_objects <= set(objects), 'missing review context')
    spec, task = objects['experiment_spec'], objects['research_task']
    profile = (spec.get('experiment_type'), spec.get('research_stage'))
    supported = {('data_quality', 'validation'), ('statistical_factor', 'exploration'), ('trading_backtest', 'validation')}
    require(profile in supported, 'unsupported cross-object profile')
    is_single_contract = (
        profile == ('trading_backtest', 'validation') and
        spec.get('backtest_profile') == SINGLE_CONTRACT_PROFILE
    )
    if is_single_contract:
        controls_file = 'single-contract-backtest-control.schema.json'
    elif profile[0] == 'trading_backtest':
        controls_file = 'issue481-backtest-control.schema.json'
    elif profile[0] == 'statistical_factor':
        controls_file = 'trend20-control.schema.json'
    else:
        controls_file = 'phase0-control.schema.json'
    controls = parse(safe_read(DEFINITIONS, controls_file))['$defs']
    profile_schema = None
    if profile[0] != 'data_quality':
        profile_schema = parse(safe_read(DEFINITIONS, 'review-evidence.schema.json'))['$defs']
    for kind, obj in objects.items():
        if kind in ('research_task', 'experiment_run'):
            schema_check(obj, controls[kind])
        elif kind == 'result_evidence' and profile_schema is not None:
            if is_single_contract:
                name = 'single_contract_result_evidence'
            elif profile[0] == 'trading_backtest':
                name = 'issue481_result_evidence'
            else:
                name = 'trend20_result_evidence'
            schema_check(obj, {'$defs': profile_schema, '$ref': '#/$defs/' + name})
        elif kind in parse(safe_read(DEFINITIONS, 'phase0-control.schema.json'))['$defs']:
            schema_check(obj, parse(safe_read(DEFINITIONS, 'phase0-control.schema.json'))['$defs'][kind])
        elif kind == 'experiment_spec':
            schema_check(obj, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))
        elif kind == 'artifact_manifest':
            schema_check(obj, parse(safe_read(ROOT, 'docs/schemas/research-artifact-manifest-v2.schema.json')))
        else:
            raise ValueError('unsupported control object')
    definitions = Definitions()
    criteria = request['criteria_ref']
    candidates = [e for e in definitions.entries if e['kind'] == 'criteria' and (e['name'], e['revision']) == (criteria['id'], criteria['revision'])]
    require(len(candidates) == 1, 'unknown criteria definition')
    _, criterion = definitions.resolve('criteria', {'name': criteria['id'], 'revision': criteria['revision'], 'content_hash': criteria['content_hash'], 'locator': candidates[0]['locator']})
    if is_single_contract:
        expected_criteria = SINGLE_CONTRACT_CRITERIA_ID
    else:
        expected_criteria = {('data_quality', 'validation'): 'phase0-date-order-criteria', ('statistical_factor', 'exploration'): 'phase0.trend20.review_evidence.criteria', ('trading_backtest', 'validation'): 'phase0.issue481.review_evidence.criteria'}[profile]
    require(criterion['id'] == expected_criteria, 'criteria profile')
    for kind, ref in request['context_refs'].items():
        require(kind in objects and ref == check_record(objects[kind], kind), 'context reference: ' + kind)
    require(set(request['context_refs']) == required_objects, 'review context set')
    validate_spec(spec, task, definitions)
    run, manifest, evidence = objects['experiment_run'], objects['artifact_manifest'], objects['result_evidence']
    require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) == (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Run Spec reference')
    require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']), 'scientific fingerprint')
    if profile[0] == 'data_quality':
        require(time_value(run['timing']['started_at']) <= time_value(run['timing']['completed_at']), 'Run time order')
        require(run['process_exit_code'] == (0 if run['run_status'] == 'COMPLETED' else 1), 'Run exit status')
    elif profile[0] == 'trading_backtest':
        if is_single_contract:
            require(time_value(run['timing']['started_at']) <= time_value(run['timing']['completed_at']), 'Run time order')
            require(run['process_exit_code'] == (0 if run['run_status'] == 'COMPLETED' else 1), 'Run exit status')
        else:
            require(run['run_status'] == 'COMPLETED' and run['process_exit_code'] == 3 and run['resolved_computation_manifest']['stop_reason'] == 'STOP_ECONOMIC_GATE', 'Issue481 stop status')
    else:
        require(run['run_status'] == 'COMPLETED' and run['process_exit_code'] == 0, 'Trend20 run status')
    require((manifest['run_id'], manifest['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Manifest Run reference')
    require(manifest['experiment_type'] == spec['experiment_type'], 'Manifest Spec type')
    if is_single_contract:
        prefix = SINGLE_CONTRACT_PAYLOAD_PREFIX
    else:
        prefix = {'data_quality': 'phase0.', 'statistical_factor': 'phase0.trend20.', 'trading_backtest': 'phase0.issue481.'}[profile[0]]
    for entry in manifest['entries']:
        definition, _ = definitions.resolve('payload', entry['content_schema_ref'])
        require(definition['role'] == entry['role'] and definition['name'] == prefix + entry['role'], 'profile payload definition')
    require((evidence['run_id'], evidence['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Evidence Run reference')
    require((evidence['manifest_id'], evidence['manifest_revision'], evidence['manifest_content_hash']) == (manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash']), 'Evidence Manifest reference')
    require(evidence['run_status_snapshot'] == evidence['execution_status'] == run['run_status'], 'Evidence status')
    present = [{**{k: manifest[v] for k, v in [('manifest_id', 'manifest_id'), ('manifest_revision', 'revision'), ('manifest_content_hash', 'manifest_content_hash')]}, **{k: e[k] for k in ('artifact_id', 'role', 'content_sha256')}} for e in manifest['entries'] if e['availability'] == 'present']
    require(evidence['supporting_artifacts'] == present and request['artifact_requirements']['exact_refs'] == present, 'Evidence artifact references')
    require(request['artifact_requirements']['role_profile_ref'] == manifest['artifact_profile'], 'role profile')
    if is_single_contract and run['run_status'] == 'FAILED':
        required_roles = COMMON | {'failure_diagnostics'}
    else:
        required_roles = COMMON | TYPED[manifest['experiment_type']]
        if run['run_status'] == 'FAILED':
            required_roles |= {'failure_diagnostics'}
    if profile[0] == 'data_quality' and run['run_status'] == 'FAILED':
        diagnostics = [entry for entry in manifest['entries'] if entry['role'] == 'failure_diagnostics']
        require(len(diagnostics) == 1 and diagnostics[0]['availability'] == 'present', 'failure diagnostics delivery')
    requested_roles = set(request['artifact_requirements']['required_roles'])
    present_roles = {ref['role'] for ref in present}
    require(requested_roles == required_roles and required_roles <= {e['role'] for e in manifest['entries']}, 'handoff required roles')
    require(present_roles == (required_roles if run['run_status'] == 'COMPLETED' else {e['role'] for e in manifest['entries'] if e['availability'] == 'present'}), 'handoff exact role references')
    scope = 'research_assessment' if run['run_status'] == 'COMPLETED' else 'failure_diagnosis'
    require(request['review_scope'] == scope and request['expected_outputs'] == [{'object_type': 'review', 'schema_version': 'research_lab.review.v2'}], 'review scope/output')

    if response is not None:
        schema_check(response, schema)
        require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'], 'response correlation')
        require(response['context_refs'] == request['context_refs'] and response['operation'] == request['operation'], 'response context')
        require((response['sender_role'], response['recipient_role']) == (request['recipient_role'], request['sender_role']), 'response direction')
        require(response['review_scope'] == request['review_scope'], 'response review scope')
        if response['status'] != 'completed':
            _validate_problem_response(response)
            return True

    if profile[0] == 'statistical_factor':
        summary = _resolve_manifest_payload(manifest, definitions, 'statistical_summary',
                                            payloads=payloads, root=root)
        metrics = evidence['typed_metrics']
        require(metrics['daily_ic']['unit'] == 'correlation' and metrics['top_bottom_spread']['unit'] == 'log_return', 'Trend20 evidence units')
        require(metrics['daily_ic']['value'] == summary['mean_daily_pearson_ic'], 'Trend20 daily IC value mismatch')
        require(metrics['daily_ic']['precision'] == summary['precision'], 'Trend20 daily IC precision mismatch')
        require(metrics['top_bottom_spread']['value'] == summary['mean_top2_minus_bottom2_forward_log_return'], 'Trend20 top-bottom spread value mismatch')
        require(metrics['top_bottom_spread']['precision'] == summary['precision'], 'Trend20 top-bottom spread precision mismatch')
        require(metrics['metrics_precision'] == summary['precision'], 'Trend20 metrics precision mismatch')
    elif profile[0] == 'trading_backtest':
        if is_single_contract:
            if run['run_status'] == 'COMPLETED':
                summary = _resolve_manifest_payload(manifest, definitions, 'backtest_summary',
                                                    payloads=payloads, root=root)
                metrics = evidence['typed_metrics']
                require(metrics is not None and metrics.get('profile') == SINGLE_CONTRACT_PROFILE, 'SingleContract evidence profile')
                require(metrics['product'] == summary['product'] and metrics['exact_contract'] == summary['exact_contract'], 'SingleContract evidence contract mismatch')
                require(metrics['net_pnl'] == summary['net_pnl'] and metrics['total_fees'] == summary['total_fees'] and metrics['trade_count'] == summary['total_trades'], 'SingleContract evidence metrics mismatch')
            else:
                require(evidence['typed_metrics'] is None, 'failed evidence typed_metrics must be null')
                require(isinstance(evidence.get('missing_reason'), str) and evidence['missing_reason'], 'failed evidence missing_reason required')
        else:
            summary = _resolve_manifest_payload(manifest, definitions, 'backtest_summary',
                                                payloads=payloads, root=root)
            rows = evidence['typed_metrics']['account_metrics']
            expected = {f'{p}:{s}:{x}' for p in ('CANDIDATE', 'PAIRED') for s in ('PRIMARY_2S', 'STRESS_5S') for x in ('ag', 'au', 'cu', 'rb', 'ru', 'sc')}
            require(len(rows) == 24 and {r['account_id'] for r in rows} == expected and all(r['account_id'] == ':'.join((r['path'], r['scenario'], r['product'])) for r in rows), 'Issue481 evidence account metrics')
            summary_rows = summary.get('account_metrics', [])
            summary_by_id = {r['account_id']: r for r in summary_rows}
            require(len(summary_by_id) == 24 and set(summary_by_id) == expected, 'Issue481 summary account metrics')
            for r in rows:
                acc_id = r['account_id']
                s_row = summary_by_id[acc_id]
                for field in ('net_pnl_cny', 'fees_cny', 'trade_count', 'path', 'scenario', 'product'):
                    require(r[field] == s_row[field], f'Issue481 {field} mismatch: {acc_id}')

    if response is not None:
        require(len(response.get('output_refs', [])) == 1 and response['output_refs'][0]['object_type'] == 'review', 'review output')
        review = objects.get('review')
        require(review is not None and response['output_refs'][0] == check_record(review, 'review'), 'output reference')
        require(review['criteria_ref'] == request['criteria_ref'], 'Review criteria mismatch')
        require((review['evidence_id'], review['evidence_content_hash']) == (evidence['evidence_id'], evidence['evidence_content_hash']), 'Review Evidence reference')
        if profile[0] == 'data_quality':
            require(time_value(review['reviewed_at']) >= time_value(run['timing']['completed_at']), 'Review time order')
    return True
