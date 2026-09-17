"""Read-only v2 contract validation against repository-pinned definitions.

Passing these checks never authorizes execution or certifies scientific validity.
"""
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
DEFINITIONS = ROOT / 'docs/research-lab/definitions'
PROFILE = 'research-json-v1'
ROLE_PROFILE = 'research_lab.artifact_roles.v2.candidate1'
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
    task_schema = {'statistical_factor': 'trend20-control.schema.json', 'trading_backtest': 'issue481-backtest-control.schema.json'}.get(spec['experiment_type'], 'phase0-control.schema.json')
    schema_check(task, parse(safe_read(DEFINITIONS, task_schema))['$defs']['research_task'])
    check_record(spec, 'experiment_spec')
    check_record(task, 'research_task')
    require((spec['task_id'], spec['task_revision'], spec['task_content_hash']) ==
            (task['task_id'], task['revision'], task['task_content_hash']), 'Task reference')
    require(task['research_type'] == spec['experiment_type'], 'Task type')
    require(spec['research_stage'] != 'confirmation', 'unsupported confirmation admission: exposure evidence not verified')
    if spec['experiment_type'] == 'trading_backtest':
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

def validate_manifest(root, manifest, run, definitions=None, *, task=None, spec=None):
    definitions = definitions or Definitions()
    schema_check(manifest, parse(safe_read(ROOT, 'docs/schemas/research-artifact-manifest-v2.schema.json')))
    run_schema = {'statistical_factor': 'trend20-control.schema.json', 'trading_backtest': 'issue481-backtest-control.schema.json'}.get(manifest['experiment_type'], 'phase0-control.schema.json')
    run_definition = 'experiment_run'
    schema_check(run, parse(safe_read(DEFINITIONS, run_schema))['$defs'][run_definition])
    check_record(manifest, 'artifact_manifest')
    check_record(run, 'experiment_run')
    require(run['run_status'] in ('COMPLETED', 'FAILED'), 'nonterminal run')
    require((manifest['run_id'], manifest['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Run reference')
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
        expected_name = {'statistical_factor': 'phase0.trend20.', 'trading_backtest': 'phase0.issue481.'}.get(manifest['experiment_type'], 'phase0.') + e['role']
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
        require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) == (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Issue481 Run Spec reference')
        require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']), 'Issue481 scientific fingerprint')
        summary = next(contents[e['artifact_id']] for e in entries if e['role'] == 'backtest_summary')
        blotter = next(contents[e['artifact_id']] for e in entries if e['role'] == 'trade_blotter')
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
            point_times.setdefault(point['account_id'], []).append(point['official_day'])
        require(all(times == sorted(times) and len(times) == len(set(times)) for times in point_times.values()), 'equity point order')
        by_account = {}
        for item in blotter['fills']:
            require(item['account'] == item['product'] and item['account_id'] == ':'.join((item['path'], item['scenario'], item['product'])), 'fill account identity')
            require(item['exact_contract'].startswith(item['product']) and len(item['exact_contract']) > len(item['product']), 'exact contract product')
            by_account.setdefault(item['account_id'], []).append(item['fill_sequence'])
        require(all(values == sorted(values) and len(values) == len(set(values)) for values in by_account.values()), 'fill order')
    return contents


def validate_handoff(request, objects, response=None):
    """Bind real objects, exact payload references, and actual Review criteria."""
    schema = parse(safe_read(ROOT, 'docs/research-lab/agent-contract/agent-handoff.schema.json'))
    schema_check(request, schema)
    require(request['message_kind'] == 'request', 'expected request')
    require(request['operation'] == 'review_evidence', 'unsupported cross-object operation')
    control = parse(safe_read(DEFINITIONS, 'phase0-control.schema.json'))['$defs']
    for kind, obj in objects.items():
        if kind in control:
            schema_check(obj, control[kind])
        elif kind == 'experiment_spec':
            schema_check(obj, parse(safe_read(ROOT, 'docs/schemas/research-experiment-spec-v2.schema.json')))
        elif kind == 'artifact_manifest':
            schema_check(obj, parse(safe_read(ROOT, 'docs/schemas/research-artifact-manifest-v2.schema.json')))
        else:
            raise ValueError('unsupported control object')
    definitions = Definitions()
    criteria = request['criteria_ref']
    candidates = [e for e in definitions.entries if e['kind'] == 'criteria' and
                  (e['name'], e['revision']) == (criteria['id'], criteria['revision'])]
    require(len(candidates) == 1, 'unknown criteria definition')
    definitions.resolve('criteria', {'name': criteria['id'], 'revision': criteria['revision'],
                        'content_hash': criteria['content_hash'], 'locator': candidates[0]['locator']})
    for kind, ref in request['context_refs'].items():
        require(kind in objects and ref == check_record(objects[kind], kind), 'context reference: ' + kind)
    spec, run = objects.get('experiment_spec'), objects.get('experiment_run')
    manifest, evidence = objects.get('artifact_manifest'), objects.get('result_evidence')
    task = objects.get('research_task')
    require(spec and spec['experiment_type'] == 'data_quality' and spec['research_stage'] == 'validation',
            'unsupported cross-object profile')
    if spec and task:
        require((spec['task_id'], spec['task_revision'], spec['task_content_hash']) ==
                (task['task_id'], task['revision'], task['task_content_hash']), 'Spec Task reference')
        require(spec['experiment_type'] == task['research_type'], 'Spec Task type')
    if run:
        require(time_value(run['timing']['started_at']) <= time_value(run['timing']['completed_at']), 'Run time order')
        require(run['scientific_fingerprint'] == digest(run['resolved_computation_manifest']), 'scientific fingerprint')
        require(run['process_exit_code'] == (0 if run['run_status'] == 'COMPLETED' else 1), 'Run exit status')
    if spec and run:
        require((run['spec_id'], run['spec_revision'], run['spec_content_hash']) ==
                (spec['spec_id'], spec['revision'], spec['spec_content_hash']), 'Run Spec reference')
    if manifest and run:
        require((manifest['run_id'], manifest['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Manifest Run reference')
    if manifest and spec:
        require(manifest['experiment_type'] == spec['experiment_type'], 'Manifest Spec type')
    if evidence and manifest and run:
        require((evidence['run_id'], evidence['run_content_hash']) == (run['run_id'], run['run_content_hash']), 'Evidence Run reference')
        require((evidence['manifest_id'], evidence['manifest_revision'], evidence['manifest_content_hash']) ==
                (manifest['manifest_id'], manifest['revision'], manifest['manifest_content_hash']), 'Evidence Manifest reference')
        require(evidence['run_status_snapshot'] == evidence['execution_status'] == run['run_status'], 'Evidence status')
        present = [{**{k: manifest[v] for k, v in [('manifest_id', 'manifest_id'), ('manifest_revision', 'revision'),
                    ('manifest_content_hash', 'manifest_content_hash')]},
                    **{k: e[k] for k in ('artifact_id', 'role', 'content_sha256')}}
                   for e in manifest['entries'] if e['availability'] == 'present']
        require(evidence['supporting_artifacts'] == present, 'Evidence artifact references')
        require(request['artifact_requirements']['exact_refs'] == present, 'handoff artifact references')
        require(request['artifact_requirements']['role_profile_ref'] == manifest['artifact_profile'], 'role profile')
        required = COMMON | TYPED[manifest['experiment_type']]
        if run['run_status'] == 'FAILED':
            required |= {'failure_diagnostics'}
        require(required <= set(request['artifact_requirements']['required_roles']), 'handoff required roles')
        require(request['review_scope'] == ('research_assessment' if run['run_status'] == 'COMPLETED' else 'failure_diagnosis'), 'review scope')
    if response is not None:
        schema_check(response, schema)
        require(response['message_kind'] == 'response' and response['in_reply_to'] == request['handoff_id'], 'response correlation')
        require(response['context_refs'] == request['context_refs'] and response['operation'] == request['operation'], 'response context')
        require((response['sender_role'], response['recipient_role']) == (request['recipient_role'], request['sender_role']), 'response direction')
        for ref in response.get('output_refs', []):
            kind = ref['object_type']
            require(kind in objects and ref == check_record(objects[kind], kind), 'output reference')
            if kind == 'review':
                review = objects[kind]
                require(review['criteria_ref'] == request['criteria_ref'], 'Review criteria mismatch')
                require((review['evidence_id'], review['evidence_content_hash']) ==
                        (evidence['evidence_id'], evidence['evidence_content_hash']), 'Review Evidence reference')
                require(response['review_scope'] == request['review_scope'], 'response review scope')
                require(time_value(review['reviewed_at']) >= time_value(run['timing']['completed_at']), 'Review time order')
    return True
