"""Human preparation only: pin a real projection and save candidates BEFORE run."""
import argparse
import csv
import io
import shutil
import subprocess
from pathlib import Path

import case
import quality

SOURCE_SHA = 'f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351'
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def obj(props):
    return {'type': 'object', 'additionalProperties': False, 'required': list(props), 'properties': props}


def payload_schema(method, provenance):
    text = {'type': 'string'}
    count = {'type': 'integer', 'minimum': 0}
    # Local payload shapes only. Not a new public protocol schema.
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$defs': {
        'quality_summary': obj({k: count for k in ['row_count', 'comparison_count', quality.METRIC['metric_name'], 'duplicate_key_excess_rows', 'source_order_reversals']}),
        'quality_anomalies': {'type': 'array', 'items': obj({'source_row': {'type': 'integer', 'minimum': 2}, 'exact_contract': text, 'day': text,
                            'previous_day': {'type': ['string', 'null']}, 'duplicate': {'type': 'boolean'}, 'reversal': {'type': 'boolean'}, 'metric_violation': {'type': 'boolean'}})},
        'method_definition': {'const': method},
        'dataset_metadata': obj({'snapshot_sha256': text, 'byte_length': count, 'fields': {'const': quality.FIELDS}, 'source': {'const': provenance},
                                'time_range': obj({'start': text, 'end': text}), 'receipt_evidence': {'type': 'null'}, 'calendar_evidence': {'type': 'null'}}),
        'environment_lock': obj({'python': text, 'implementation': text, 'platform': text, 'machine': text, 'executable_sha256': text,
            'dependencies': obj({n: obj({'version': text, 'files_hash': text}) for n in ('jsonschema', 'attrs', 'referencing', 'rpds-py', 'jsonschema-specifications')}),
            'stdlib_hashes': obj({n: text for n in ('csv', 'json', 'hashlib')}), 'limit': text}),
        'replay_instructions': obj({'entry': text, 'command': text, 'comparison': text, 'requirements': text}),
        'failure_diagnostics': obj({'error_type': text, 'message': text, 'stage': {'const': 'quality_scan'}})}}


def prepare(source, dest, end='2023-02-01', revision='rev.1'):
    case.require(end in ('2023-02-01', '2023-01-10'), 'this case supports baseline or short range')
    case.require(revision == ('rev.1' if end == '2023-02-01' else 'rev.2'), 'range revision')
    raw = source.read_bytes()
    case.require(case.sha(raw) == SOURCE_SHA, 'historical source hash differs from #540 input-manifest')
    # Predeclared projection only; preserve original order and duplicates, no sorting.
    rows = csv.DictReader(io.StringIO(raw.decode(), newline=''))
    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=quality.FIELDS, lineterminator='\n')
    writer.writeheader()
    source_rows = []
    for line, row in enumerate(rows, 2):
        if row['product'] == 'rb' and '2023-01-03' <= row['source_official_day'] < '2023-02-01':
            writer.writerow({k: row[k] for k in quality.FIELDS})
            source_rows.append(line)
    dest.mkdir(parents=True, exist_ok=False)
    snapshot = buffer.getvalue().encode()
    (dest / 'input.csv').write_bytes(snapshot)
    provenance = {'source_member': 'curve_contract_daily.csv', 'source_sha256': SOURCE_SHA, 'source_bytes': len(raw),
                  'source_manifest': 'docs/research-lab/phase0-validation/input-manifest.json', 'source_rows': source_rows,
                  'projection': 'rb; 2023-01-03 <= source_official_day < 2023-02-01; three columns; source order; CSV UTF-8 LF',
                  'limit': 'Historical derived table, not exchange original bytes or receipt evidence; source archive remains external; projected snapshot is bundled.'}
    task = case.seal({'schema_version': 'research_lab.task.v2', 'hash_profile': case.PROFILE,
        'task_id': 'task-phase0-rb-date-order', 'revision': 'rev.1', 'research_type': 'data_quality',
        'objective': 'Validate input-driven date-order audit on historical RB derived rows; no calendar/PIT/Alpha claim.',
        'data_requirements': {'products': ['rb'], 'date_start': '2023-01-03', 'date_end_exclusive': '2023-02-01', 'fields': quality.FIELDS}}, 'task_content_hash')
    spec = {'schema_version': 'research_lab.experiment.v2', 'hash_profile': case.PROFILE, 'spec_id': 'spec-phase0-rb-date-order', 'revision': 'rev.1',
        'task_id': task['task_id'], 'task_revision': task['revision'], 'task_content_hash': task['task_content_hash'],
        'experiment_type': 'data_quality', 'research_stage': 'validation', 'trial_kind_proposal': None, 'seed_proposal': None,
        'dataset_requirements': {'provider_kind': 'local_derived_subset', 'dataset_reference_uri': 'candidate://phase0/derived-rb-dates',
            'snapshot_selection_mode': 'fixed_snapshot', 'snapshot_sha256': case.sha(snapshot), 'universe': ['rb'], 'frequencies': ['1d'],
            'time_range': {'start': '2023-01-03T00:00:00.000000Z', 'end': '2023-02-01T00:00:00.000000Z'}, 'required_fields': quality.FIELDS,
            'pit_constraints': 'No historical receipt or PIT certification. source_official_day is a date label, not arrival time.',
            'normalization_rule_version': 'phase0.date-column-as-utc-label.rev1'},
        'quality_checks': [{'check_id': 'source_order', 'implementation_ref': quality.METHOD, 'parameters': [], 'failure_action': 'record'}],
        'validation_config': {'method': 'full_sample_scan'}, 'candidate_decision_criteria': {'max_allowed_timestamp_reversals': 0},
        'metric_specifications': [quality.METRIC], 'rejection_policy': {'forbid_unknown_fields': True, 'reject_unregistered_implementation': True, 'reject_unsupported_data_sources': True},
        'holdout_policy': {'mode': 'not_used', 'reason': 'Historical derived rows; date-order audit only; no confirmation or PIT claim.'}}
    spec['revision'] = revision
    spec['dataset_requirements']['time_range']['end'] = end + 'T00:00:00.000000Z'
    case.seal(spec, 'spec_content_hash')
    criteria = {'id': 'phase0-date-order-criteria', 'revision': 'rev.1', 'metric': quality.METRIC['metric_name'], 'maximum': 0,
                'minimum_comparisons': 1, 'scope': 'date order only; not calendar completeness, PIT or protocol freeze'}
    method = {'id': quality.METHOD, 'revision': 'rev.1', 'source_sha256': case.sha((HERE / 'quality.py').read_bytes()),
              'parameter_definition': {'strict': {'type': 'boolean', 'unit': 'dimensionless', 'default': True}}, 'metric': quality.METRIC}
    for name, value in [('task', task), ('spec', spec), ('criteria', criteria), ('method', method), ('provenance', provenance), ('payload.schema', payload_schema(method, provenance))]:
        case.save(dest / (name + '.json'), value)
    shutil.copyfile(ROOT / 'docs/schemas/research-experiment-spec-v2.schema.json', dest / 'spec.schema.json')
    shutil.copyfile(ROOT / 'docs/research-lab/agent-contract/agent-handoff.schema.json', dest / 'handoff.schema.json')
    for name in case.CODE:
        shutil.copyfile(HERE / name, dest / name)
    lock(dest)


def lock(dest):
    case.save(dest / 'preparation.json', {'prepared_at': case.stamp(),
        'source_base_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'files': {p.name: case.sha(p.read_bytes()) for p in sorted(dest.iterdir()) if p.name != 'preparation.json'}})


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--end', default='2023-02-01')
    p.add_argument('--revision', default='rev.1')
    args = p.parse_args()
    prepare(args.source, args.out, args.end, args.revision)
    print('PREPARED (not executed):', args.out)
