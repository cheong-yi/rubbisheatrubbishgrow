"""Closed source domain and evidence labeling, with no runtime-rules catalog."""
import copy
import hashlib
import io
import json
from pathlib import Path

import pytest

from rerg import raw_derivation, raw_intake, raw_cli
from test_supplied_admission import make_request, supplied_case

ROOT = Path(__file__).resolve().parents[2]


def test_high_level_compiler_uses_explicit_generated_id_map_and_preserves_capture():
    proposal, capture = make_request()
    before = copy.deepcopy((proposal, capture))
    admitted, invalid = raw_derivation._compile_assessment(proposal, capture)
    assert invalid is None
    assert proposal == before[0] and capture == before[1]
    digest = hashlib.sha256(b'alpha').hexdigest()
    text = 'Source-level intended change only.'
    narrative = {'text': text, 'citation_ids': ['ci:00']}
    expected = {
        'contract': 'rerg-foundation/3',
        'candidate': {
            'id': 'ca:candidate', 'source_kind': 'question',
            'locator': 'note:source', 'question': 'How could this source change fit?',
            'citation_ids': [],
        },
        'target': {
            'id': 't:target', 'harness': 'opaque-harness', 'version': '1',
            'surface': 'other_source', 'configuration_digest': 'a' * 64,
        },
        'view': {
            'id': 'v:view', 'target_id': 't:target', 'root_ids': ['r:root'],
            'operation': 'read_supplied_bytes',
            'descriptors': [{
                'id': 'd:descriptor', 'root_id': 'r:root',
                'artifact_id': 'syn:a:source', 'state': 'inspected',
            }],
        },
        'host': {
            'origin': 'synthetic', 'evidence_basis': 'host_attested_unverified',
            'grant_id': 'syn:grant',
            'target_binding': {
                'id': 't:target', 'harness': 'opaque-harness', 'version': '1',
                'surface': 'other_source', 'configuration_digest': 'a' * 64,
            },
            'view_id': 'v:view', 'root_ids': ['r:root'],
            'operation': 'read_supplied_bytes', 'coherence': 'immutable',
            'checks': {'pre': 'pass', 'post': 'pass', 'final': 'pass', 'cleanup': 'pass'},
            'policy': {'allowed': True, 'ready': True},
            'limits': {'decoded_bytes': 5, 'artifact_count': 1, 'limit_hit': False},
        },
        'artifacts': [{
            'id': 'syn:a:source', 'origin': 'synthetic', 'role': 'source',
            'target_id': 't:target', 'view_id': 'v:view',
            'source_identity': 'source', 'source_version': '1',
            'source_sha256': digest, 'representation_sha256': digest,
            'data': 'alpha', 'limitations': [],
        }],
        'citations': [{
            'id': 'ci:00', 'artifact_id': 'syn:a:source',
            'representation_sha256': digest, 'start_byte': 0, 'end_byte': 5,
        }],
        'relations': [{'id': 're:00', 'kind': 'source_present', 'citation_id': 'ci:00'}],
        'needs': [{
            'id': 'n:need', 'statement': 'Preserve cited source.',
            'citation_ids': ['ci:00'], 'load_bearing': True,
            'current_relation_ids': ['re:00'],
        }],
        'approaches': [{
            'id': 'p:route',
            'need_relations': [{'need_id': 'n:need', 'relation_ids': ['re:00'], 'unresolved': None}],
            'lift': {'amount': None, 'unit': 'unknown', 'basis': narrative},
            **{name: narrative for name in (
                'mechanism', 'required_changes', 'constraints', 'dependencies',
                'risks', 'unknowns', 'validation', 'reversibility', 'stop_conditions',
            )},
        }],
        'components': sorted(copy.deepcopy(capture['components']), key=lambda row: row['path']),
    }
    assert admitted == expected


def test_high_level_unknown_span_reserves_citation_without_fabricating_record():
    proposal, capture = make_request()
    span = {'artifact_key': 'unknown', 'start_byte': 0, 'end_byte': 1}
    requirement = {'kind': 'source_present', 'span': span}
    proposal['needs'][0]['current_requirements'] = [requirement]
    proposal['approaches'][0]['coverage'][0]['requirements'] = [requirement]
    admitted, invalid = raw_derivation._compile_assessment(proposal, capture)
    assert invalid is None
    # The retained need/narrative span owns ci:00; the unknown span reserves ci:01.
    assert admitted['citations'][0]['id'] == 'ci:00'
    assert admitted['relations'][0]['citation_id'] == 'ci:01'
    assert all(row['id'] != 'ci:01' for row in admitted['citations'])
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['outcome'] == 'needs_more_facts'
    assert result['gaps'][0] == {'relation_id': 're:00', 'property': 'missing_citation'}


@pytest.mark.parametrize('key', ['a/b', 'x' * 25, 'K'])
def test_high_level_key_grammar_is_exact(key):
    proposal, capture = make_request()
    proposal['candidate']['key'] = key
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'INVALID_FIELD_VALUE'


def test_high_level_unsupported_requirement_does_not_fallback():
    proposal, capture = make_request()
    proposal['needs'][0]['current_requirements'][0] = {'kind': 'event_ordering'}
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'UNSUPPORTED_CONTRACT'


def test_runtime_modules_do_not_reference_derivation_rules_catalog():
    paths = list((ROOT / 'rerg').glob('*.py'))
    assert paths
    for path in paths:
        text = path.read_text(encoding='utf-8')
        assert 'intake-derivation-rules' not in text
        assert 'rules_catalog' not in text
    assert (ROOT / 'tests/rerg/fixtures/raw_recovery_cases.json').is_file()


@pytest.mark.parametrize('path,value', [
    (('target', 'id'), []), (('target', 'harness'), []),
    (('candidate', 'question'), []), (('candidate', 'citation_ids'), 'cite'),
    (('needs', 0, 'id'), []), (('needs', 0, 'statement'), []),
    (('needs', 0, 'citation_ids'), 'cite'), (('needs', 0, 'load_bearing'), 1),
    (('approaches', 0, 'mechanism'), [1]),
    (('approaches', 0, 'unknowns'), {'text': [], 'citation_ids': []}),
    (('approaches', 0, 'constraints'), {'text': 'bounded', 'citation_ids': [1]}),
    (('approaches', 0, 'need_relations'), [{'need_id': 'missing', 'relation_ids': ['present']}]),
])
@pytest.mark.parametrize('failed', [False, True])
def test_structure_is_shared_before_failed_or_successful_evidence(supplied_case, path, value, failed):
    if failed: supplied_case['artifacts'][0]['limitations'] = ['extraction_failed']
    parent = supplied_case
    for key in path[:-1]: parent = parent[key]
    parent[path[-1]] = value
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['kind'] == 'invalid_invocation'
    output = io.StringIO()
    assert raw_cli.main(io.BytesIO(json.dumps(supplied_case).encode()), output) == 2
    assert json.loads(output.getvalue()) == result


@pytest.mark.parametrize('mutation', ['duplicate_need', 'unknown_relation', 'runtime_policy'])
def test_closed_shape_conflict_and_provenance(supplied_case, mutation):
    if mutation == 'duplicate_need': supplied_case['needs'].append(copy.deepcopy(supplied_case['needs'][0]))
    elif mutation == 'unknown_relation': supplied_case['approaches'][0]['need_relations'][0]['relation_ids'] = ['missing']
    else: supplied_case['runtime_policy'] = {}
    assert raw_intake.evaluate_assessment(supplied_case)['kind'] == 'invalid_invocation'


@pytest.mark.parametrize('role', ['runtime', 'validation', 'policy'])
def test_deferred_artifact_roles_are_explicitly_unsupported(supplied_case, role):
    supplied_case['artifacts'][0]['role'] = role
    result = raw_intake.evaluate_assessment(supplied_case)
    assert [row['code'] for row in result['diagnostics']] == ['UNSUPPORTED_CONTRACT']
    assert result['primary_diagnostic']['detail_code'] == 'RELATION_REDUCTION_UNSUPPORTED'


def test_missing_evidence_reference_is_a_gap_not_fabricated_absence(supplied_case):
    supplied_case['relations'][0]['citation_id'] = 'unavailable'
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['kind'] == 'assessment' and result['outcome'] == 'needs_more_facts'
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert result['gaps'] == [
        {'relation_id': 'present', 'property': 'missing_citation'},
        {
            'field_path': '$.relations[0].citation_id',
            'reference_id': 'unavailable',
            'properties': ['missing_citation'],
            'impact': 'required_evidence',
        },
    ]


@pytest.mark.parametrize(
    'field,expected_path,impact',
    [
        ('candidate', '$.candidate.citation_ids[0]', 'optional_provenance'),
        ('need', '$.needs[0].citation_ids[0]', 'required_evidence'),
        ('mechanism', '$.approaches[0].mechanism.citation_ids[0]', 'optional_provenance'),
        ('required_changes', '$.approaches[0].required_changes.citation_ids[0]', 'optional_provenance'),
        ('constraints', '$.approaches[0].constraints.citation_ids[0]', 'optional_provenance'),
        ('dependencies', '$.approaches[0].dependencies.citation_ids[0]', 'optional_provenance'),
        ('risks', '$.approaches[0].risks.citation_ids[0]', 'optional_provenance'),
        ('unknowns', '$.approaches[0].unknowns.citation_ids[0]', 'optional_provenance'),
        ('validation', '$.approaches[0].validation.citation_ids[0]', 'optional_provenance'),
        ('reversibility', '$.approaches[0].reversibility.citation_ids[0]', 'optional_provenance'),
        ('stop_conditions', '$.approaches[0].stop_conditions.citation_ids[0]', 'optional_provenance'),
        ('lift_basis', '$.approaches[0].lift.basis.citation_ids[0]', 'optional_provenance'),
    ],
)
def test_reference_integrity_covers_each_citation_field(
    supplied_case, field, expected_path, impact,
):
    if field == 'candidate':
        supplied_case['candidate']['citation_ids'] = ['ghost']
    elif field == 'need':
        supplied_case['needs'][0]['citation_ids'] = ['ghost']
    elif field == 'lift_basis':
        supplied_case['approaches'][0]['lift']['basis']['citation_ids'] = ['ghost']
    else:
        owner = supplied_case['approaches'][0] if field not in ('candidate', 'need') else supplied_case[field]
        owner[field]['citation_ids'] = ['ghost']
    result = raw_intake.evaluate_assessment(supplied_case)
    expected = {
        'field_path': expected_path,
        'reference_id': 'ghost',
        'properties': ['missing_citation'],
        'impact': impact,
    }
    assert expected in result['gaps']
    if impact == 'required_evidence':
        assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
        assert result['outcome'] == 'needs_more_facts'
    else:
        assert result['outcome'] == 'eligible'


@pytest.mark.parametrize('field', ['left_citation_id', 'right_citation_id'])
def test_source_same_reference_sides_share_the_global_citation_namespace(
    supplied_case, field,
):
    second = copy.deepcopy(supplied_case['artifacts'][0])
    second.update(
        id='syn:second',
        source_identity='second',
        data='beta',
        source_sha256=hashlib.sha256(b'beta').hexdigest(),
        representation_sha256=hashlib.sha256(b'beta').hexdigest(),
    )
    supplied_case['artifacts'].append(second)
    supplied_case['view']['descriptors'].append(
        {'id': 'second-descriptor', 'root_id': 'root', 'artifact_id': 'syn:second', 'state': 'inspected'},
    )
    supplied_case['host']['limits'].update(artifact_count=2, decoded_bytes=9)
    supplied_case['citations'].append({
        'id': 'second-cite',
        'artifact_id': 'syn:second',
        'representation_sha256': second['representation_sha256'],
        'start_byte': 0,
        'end_byte': 4,
    })
    supplied_case['relations'][0] = {
        'id': 'present',
        'kind': 'source_same',
        'left_citation_id': 'ghost' if field == 'left_citation_id' else 'cite',
        'right_citation_id': 'ghost' if field == 'right_citation_id' else 'second-cite',
    }
    result = raw_intake.evaluate_assessment(supplied_case)
    assert {
        'field_path': f'$.relations[0].{field}',
        'reference_id': 'ghost',
        'properties': ['missing_citation'],
        'impact': 'required_evidence',
    } in result['gaps']
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'


@pytest.mark.parametrize('foreign_id', ['syn:source', 'present'])
def test_reference_id_from_another_namespace_is_not_a_valid_citation(
    supplied_case, foreign_id,
):
    supplied_case['needs'][0]['citation_ids'] = [foreign_id]
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['kind'] == 'assessment'
    assert {
        'field_path': '$.needs[0].citation_ids[0]',
        'reference_id': foreign_id,
        'properties': ['missing_citation'],
        'impact': 'required_evidence',
    } in result['gaps']
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'


@pytest.mark.parametrize('bad_id', [1, 'not a citation id'])
def test_malformed_citation_reference_stays_pre_admission(bad_id, supplied_case):
    supplied_case['candidate']['citation_ids'] = [bad_id]
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'INVALID_FIELD_VALUE'


def _duplicate_citation_ids(case, owner, reference_id):
    values = [reference_id, reference_id]
    if owner == 'candidate':
        case['candidate']['citation_ids'] = values
        return '$.candidate.citation_ids'
    if owner == 'need':
        case['needs'][0]['citation_ids'] = values
        return '$.needs[0].citation_ids'
    if owner == 'lift':
        case['approaches'][0]['lift']['basis']['citation_ids'] = values
        return '$.approaches[0].lift.basis.citation_ids'
    case['approaches'][0][owner]['citation_ids'] = values
    return f'$.approaches[0].{owner}.citation_ids'


def _invalid_field_value(path):
    diagnostic = {
        'code': 'INVALID_FIELD_VALUE',
        'field_path': path,
        'detail_code': 'INVALID_FIELD_VALUE',
    }
    return {
        'contract': 'rerg-foundation/3',
        'kind': 'invalid_invocation',
        'authorizing': False,
        'can_execute': False,
        'primary_diagnostic': diagnostic,
        'diagnostics': [diagnostic],
    }


@pytest.mark.parametrize(
    'owner',
    [
        'candidate',
        'need',
        'mechanism',
        'required_changes',
        'constraints',
        'dependencies',
        'risks',
        'unknowns',
        'validation',
        'reversibility',
        'stop_conditions',
        'lift',
    ],
)
@pytest.mark.parametrize('reference_id', ['cite', 'ghost'])
def test_duplicate_citation_ids_are_rejected_per_list(
    supplied_case, owner, reference_id,
):
    path = _duplicate_citation_ids(supplied_case, owner, reference_id)
    before = copy.deepcopy(supplied_case)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result == _invalid_field_value(path)
    assert supplied_case == before


def test_citation_id_reuse_across_fields_remains_valid(supplied_case):
    supplied_case['candidate']['citation_ids'] = ['cite']
    before = copy.deepcopy(supplied_case)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['kind'] == 'assessment'
    assert result['outcome'] == 'eligible'
    assert supplied_case == before


def test_duplicate_citation_definitions_remain_invalid(supplied_case):
    supplied_case['citations'].append(copy.deepcopy(supplied_case['citations'][0]))
    before = copy.deepcopy(supplied_case)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result == _invalid_field_value('$.citations[1].id')
    assert supplied_case == before


def test_citation_table_artifact_association_has_its_own_global_gap(supplied_case):
    supplied_case['citations'][0]['artifact_id'] = 'ghost-artifact'
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert {
        'field_path': '$.citations[0].artifact_id',
        'reference_id': 'ghost-artifact',
        'properties': ['missing_artifact'],
        'impact': 'association_integrity',
    } in result['gaps']


@pytest.mark.parametrize('mutation', ['digest', 'span'])
def test_bad_supplied_citation_record_retains_association_failure(mutation, supplied_case):
    if mutation == 'digest':
        supplied_case['citations'][0]['representation_sha256'] = '0' * 64
    else:
        supplied_case['citations'][0]['end_byte'] = 99
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert {
        'field_path': '$.citations[0].artifact_id',
        'reference_id': 'syn:source',
        'properties': ['invalid_source_association'],
        'impact': 'association_integrity',
    } in result['gaps']


def test_reference_gap_preserves_all_applicable_properties(supplied_case):
    supplied_case['candidate']['citation_ids'] = ['cite']
    supplied_case['artifacts'][0]['limitations'] = ['redacted']
    supplied_case['citations'][0]['representation_sha256'] = '0' * 64
    result = raw_intake.evaluate_assessment(supplied_case)
    assert {
        'field_path': '$.candidate.citation_ids[0]',
        'reference_id': 'cite',
        'properties': ['invalid_source_association', 'limited_evidence'],
        'impact': 'optional_provenance',
    } in result['gaps']


def test_reference_normalization_is_stable_across_declared_order(supplied_case):
    first = copy.deepcopy(supplied_case)
    first['candidate']['citation_ids'] = ['ghost', 'cite']
    second = copy.deepcopy(supplied_case)
    second['candidate']['citation_ids'] = ['cite', 'ghost']
    first_result = raw_intake.evaluate_assessment(first)
    second_result = raw_intake.evaluate_assessment(second)
    assert first_result['input']['candidate']['citation_ids'] == ['cite', 'ghost']
    assert second_result['input']['candidate']['citation_ids'] == ['cite', 'ghost']
    assert raw_intake.canonical_result_bytes(first_result) == raw_intake.canonical_result_bytes(second_result)
    assert {
        'field_path': '$.candidate.citation_ids[1]',
        'reference_id': 'ghost',
        'properties': ['missing_citation'],
        'impact': 'optional_provenance',
    } in first_result['gaps']


@pytest.mark.parametrize('mutation', ['missing_origin', 'synthetic_id', 'source_id', 'host_prefix'])
def test_provenance_tags_cannot_be_inferred_from_names(supplied_case, mutation):
    if mutation == 'missing_origin': del supplied_case['artifacts'][0]['origin']
    elif mutation == 'synthetic_id': supplied_case['artifacts'][0]['id'] = 'not-synthetic'
    elif mutation == 'source_id': supplied_case['artifacts'][0]['origin'] = 'supplied_source'
    else: supplied_case['host']['grant_id'] = 'not-synthetic'
    assert raw_intake.evaluate_assessment(supplied_case)['kind'] == 'invalid_invocation'


def test_consistent_forged_origin_and_manifest_are_not_authenticated(supplied_case):
    synthetic = raw_intake.evaluate_assessment(supplied_case)
    supplied_case['artifacts'][0].update(id='source', origin='supplied_source')
    supplied_case['citations'][0]['artifact_id'] = 'source'
    supplied_case['view']['descriptors'][0]['artifact_id'] = 'source'
    mixed = raw_intake.evaluate_assessment(supplied_case)
    assert mixed['evidence_mode'] == 'mixed'
    supplied_case['host'].update(origin='supplied_source', grant_id='grant')
    supplied_case['components'][0]['sha256'] = 'f' * 64
    forged = raw_intake.evaluate_assessment(supplied_case)
    assert forged['evidence_mode'] == 'supplied_source' and forged['outcome'] == 'eligible'
    assert forged['evidence_basis'] == 'host_attested_unverified'
    assert forged['replay']['status'] == 'input_result_binding_only'
    assert forged['replay']['input_sha256'] != synthetic['replay']['input_sha256']


@pytest.mark.parametrize('data,start,end', [('éx', 1, 2), ('éx', 0, 1), ('éx', 0, 9)])
def test_utf8_splitting_and_out_of_range_spans_are_global_integrity_failures(supplied_case, data, start, end):
    digest = hashlib.sha256(data.encode()).hexdigest()
    supplied_case['artifacts'][0].update(data=data, source_sha256=digest, representation_sha256=digest)
    supplied_case['citations'][0].update(representation_sha256=digest, start_byte=start, end_byte=end)
    supplied_case['host']['limits']['decoded_bytes'] = len(data.encode())
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert {'relation_id': 'present', 'property': 'limited_evidence'} in result['gaps']
    assert {
        'field_path': '$.citations[0].artifact_id',
        'reference_id': 'syn:source',
        'properties': ['invalid_source_association'],
        'impact': 'association_integrity',
    } in result['gaps']
    assert {
        'field_path': '$.relations[0].citation_id',
        'reference_id': 'cite',
        'properties': ['invalid_source_association'],
        'impact': 'required_evidence',
    } in result['gaps']


def test_valid_source_representation_need_not_equal_source_digest(supplied_case):
    supplied_case['artifacts'][0]['source_sha256'] = 'f' * 64
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'eligible'
    assert result['input']['artifacts'][0]['source_sha256'] != result['input']['artifacts'][0]['representation_sha256']
