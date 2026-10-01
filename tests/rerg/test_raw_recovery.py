"""Evidence failures stay visible; unsupported families do not invent recovery."""
import copy

import pytest

from rerg import raw_intake
from test_supplied_admission import supplied_case
from test_engine import CODES, same_case


def test_missing_capture_and_malformed_request_remain_distinct(supplied_case):
    supplied_case['citations'] = []
    first = raw_intake.evaluate_assessment(supplied_case)
    second = raw_intake.evaluate_assessment(supplied_case)
    assert first['outcome'] == 'needs_more_facts' and first['survivors'] == []
    assert first['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert raw_intake.canonical_result_bytes(first) == raw_intake.canonical_result_bytes(second)
    supplied_case['candidate']['paths'] = ['injected']
    malformed = raw_intake.evaluate_assessment(supplied_case)
    assert malformed['kind'] == 'invalid_invocation' and 'outcome' not in malformed


def test_required_unresolved_marker_is_needs_more_facts_without_vacuous_survivor():
    case = same_case('alpha', route='route', peer=False)
    assignment = case['approaches'][0]['need_relations'][0]
    assignment.update(relation_ids=[], unresolved='the required source obligation is not captured')
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['survivors'] == []
    assert result['route_results'] == [{
        'id': 'route',
        'state': 'omitted',
        'reason_codes': [CODES[8]],
        'relation_ids': [],
    }]
    assert result['gaps'] == [{
        'approach_id': 'route',
        'need_id': 'need',
        'property': 'missing_requirement',
    }]
    assert result['reasons'] == [
        {
            'code': CODES[8],
            'scope': {'kind': 'global'},
            'affected_ids': [],
            'details': [],
        },
        {
            'code': CODES[8],
            'scope': {'kind': 'approach', 'id': 'route'},
            'affected_ids': [[4, 0], [5, 0]],
            'details': [],
        },
    ]


def test_partial_required_marker_remains_omitted_even_with_supported_relation():
    case = same_case('alpha', route='route', peer=False)
    assignment = case['approaches'][0]['need_relations'][0]
    assignment['unresolved'] = 'one required obligation remains unverified'
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['survivors'] == []
    assert result['route_results'][0]['state'] == 'omitted'
    assert result['route_results'][0]['reason_codes'] == [CODES[8]]
    assert result['route_results'][0]['relation_ids'] == ['same']
    assert result['gaps'] == [{
        'approach_id': 'route',
        'need_id': 'need',
        'property': 'missing_requirement',
    }]


def test_optional_unresolved_marker_is_diagnostic_without_hiding_supported_route():
    case = same_case('alpha', route='route', peer=False)
    optional = copy.deepcopy(case['needs'][0])
    optional.update(id='optional', load_bearing=False)
    case['needs'].append(optional)
    case['approaches'][0]['need_relations'].append({
        'need_id': 'optional',
        'relation_ids': [],
        'unresolved': 'optional context was not supplied',
    })
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'eligible'
    assert result['survivors'] == ['route']
    assert result['route_results'][0]['state'] == 'supported'
    assert result['route_results'][0]['reason_codes'] == [CODES[8]]
    assert result['gaps'] == [{
        'approach_id': 'route',
        'need_id': 'optional',
        'property': 'missing_requirement',
    }]
    assert not any(row['scope']['kind'] == 'approach' for row in result['reasons'])


def test_reject_precedes_required_unresolved_marker():
    case = same_case('alpha', route='route', peer=False)
    case['approaches'][0]['need_relations'][0].update(
        relation_ids=[],
        unresolved='required obligation is not captured',
    )
    case['host']['policy']['allowed'] = False
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'reject'
    assert result['primary_reason'] == CODES[8]
    assert [row['code'] for row in result['reasons']] == [CODES[8], CODES[8], CODES[9]]


def test_direct_map_calibration_is_not_a_foundation_replay_contract():
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes({'schema_version': 'rerg-raw-result/v1', 'selected': []})


@pytest.mark.parametrize('limitation', ['redacted', 'truncated', 'extraction_failed', 'unsupported', 'outside_view'])
def test_partial_evidence_remains_complete_and_nonpositive(supplied_case, limitation):
    supplied_case['artifacts'][0]['limitations'] = [limitation]
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'needs_more_facts' and result['survivors'] == []
    assert result['input']['artifacts'][0]['limitations'] == [limitation]
    assert result['gaps'][0]['property'] == ('outside_view' if limitation == 'outside_view' else 'limited_evidence')


def test_policy_hold_preserves_independent_missing_fact(supplied_case):
    supplied_case['host']['policy']['ready'] = False
    supplied_case['citations'] = []
    result = raw_intake.evaluate_assessment(supplied_case)
    globals_ = [row['code'] for row in result['reasons'] if row['scope'] == {'kind': 'global'}]
    assert globals_ == [
        'CITATION_OR_HASH_COVERAGE_INSUFFICIENT',
        'LOAD_BEARING_NEED_UNRESOLVED',
        'DEFER_POLICY_OR_NOT_READY',
    ]
    assert result['outcome'] == 'needs_more_facts' and result['gaps']


def test_each_missing_assurance_is_preserved(supplied_case):
    supplied_case['host']['coherence'] = 'unknown'
    supplied_case['host']['checks'] = dict.fromkeys(('pre', 'post', 'final', 'cleanup'), 'unknown')
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['primary_reason'] == 'SNAPSHOT_STALE_OR_CHANGED'
    assert result['reasons'][0]['details'] == sorted(['coherence_assurance', 'pre_assurance', 'post_assurance', 'final_assurance', 'cleanup_assurance'])
    assert result['route_results'][0]['state'] == 'supported'
    assert result['survivors'] == [] and result['gaps'] == []


def test_non_load_bearing_failure_remains_visible_without_omitting_peer():
    case = same_case('beta')
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
        approach['need_relations'].append({
            'need_id': 'optional',
            'relation_ids': ['same'],
            'unresolved': None,
        })
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'eligible' and result['survivors'] == ['global', 'peer']
    assert all(row['state'] == 'supported' for row in result['route_results'])
    assert result['gaps'] == [{'relation_id': 'same', 'property': 'false_requirement'}]
    assert all(row['scope']['kind'] != 'approach' for row in result['reasons'])
    assert all(row['reason_codes'] == ['TARGET_EVIDENCE_CONTRADICTORY'] for row in result['route_results'])


def test_non_load_bearing_need_reference_is_optional_but_visible(supplied_case):
    optional = copy.deepcopy(supplied_case['needs'][0])
    optional.update(id='optional', load_bearing=False, citation_ids=['ghost'])
    supplied_case['needs'].append(optional)
    for approach in supplied_case['approaches']:
        approach['need_relations'].append({
            'need_id': 'optional',
            'relation_ids': ['present'],
            'unresolved': None,
        })
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'eligible'
    assert result['survivors'] == ['route']
    assert {
        'field_path': '$.needs[1].citation_ids[0]',
        'reference_id': 'ghost',
        'properties': ['missing_citation'],
        'impact': 'optional_provenance',
    } in result['gaps']
    assert 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT' not in [
        row['code'] for row in result['reasons']
    ]


@pytest.mark.parametrize('mutation,state,gap', [
    ('contradicted', 'contradicted', 'false_requirement'),
    ('unresolved', 'unresolved', 'missing_citation'),
    ('outside', 'outside_view', 'outside_view'),
])
def test_optional_only_states_remain_diagnostic(mutation, state, gap):
    case = same_case('beta' if mutation == 'contradicted' else 'alpha')
    if mutation == 'unresolved':
        case['citations'] = case['citations'][:1]
    elif mutation == 'outside':
        case['artifacts'][1]['limitations'] = ['outside_view']
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
        approach['need_relations'].append({'need_id': 'optional', 'relation_ids': ['same'], 'unresolved': None})
    result = raw_intake.evaluate_assessment(case)
    assert next(row for row in result['relation_results'] if row['id'] == 'same')['state'] == state
    assert {'relation_id': 'same', 'property': gap} in result['gaps']
    if mutation == 'unresolved':
        assert {
            'field_path': '$.relations[1].right_citation_id',
            'reference_id': 'second-cite',
            'properties': ['missing_citation'],
            'impact': 'optional_provenance',
        } in result['gaps']
    elif mutation == 'outside':
        assert {
            'field_path': '$.relations[1].right_citation_id',
            'reference_id': 'second-cite',
            'properties': ['outside_view'],
            'impact': 'optional_provenance',
        } in result['gaps']
    assert result['outcome'] == 'eligible'
    assert result['survivors'] == ['global', 'peer']
    assert all(row['scope']['kind'] != 'approach' for row in result['reasons'])


@pytest.mark.parametrize('mutation', ['contradicted', 'unresolved', 'outside'])
def test_shared_required_use_wins_for_each_failed_state(mutation):
    case = same_case('beta' if mutation == 'contradicted' else 'alpha')
    if mutation == 'unresolved':
        case['citations'] = case['citations'][:1]
    elif mutation == 'outside':
        case['artifacts'][1]['limitations'] = ['outside_view']
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['same']
        approach['need_relations'].append({'need_id': 'optional', 'relation_ids': ['same'], 'unresolved': None})
    result = raw_intake.evaluate_assessment(case)
    expected = 'TARGET_EVIDENCE_CONTRADICTORY' if mutation == 'contradicted' else 'LOAD_BEARING_NEED_UNRESOLVED'
    assert result['outcome'] == 'needs_more_facts'
    assert result['survivors'] == []
    assert result['primary_reason'] == (
        'TARGET_EVIDENCE_CONTRADICTORY'
        if mutation == 'contradicted'
        else 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    )
    assert all(row['code'] == expected for row in result['reasons'] if row['scope']['kind'] == 'approach')
    expected_gap = {
        'contradicted': 'false_requirement',
        'unresolved': 'missing_citation',
        'outside': 'outside_view',
    }[mutation]
    assert {'relation_id': 'same', 'property': expected_gap} in result['gaps']
    if mutation == 'unresolved':
        assert {
            'field_path': '$.relations[1].right_citation_id',
            'reference_id': 'second-cite',
            'properties': ['missing_citation'],
            'impact': 'required_evidence',
        } in result['gaps']
    elif mutation == 'outside':
        assert {
            'field_path': '$.relations[1].right_citation_id',
            'reference_id': 'second-cite',
            'properties': ['outside_view'],
            'impact': 'required_evidence',
        } in result['gaps']


def test_optional_failure_does_not_hide_independent_integrity_reason():
    case = same_case('beta')
    bad = copy.deepcopy(case['citations'][0])
    bad.update(id='unused', representation_sha256='0' * 64)
    case['citations'].append(bad)
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
        approach['need_relations'].append({'need_id': 'optional', 'relation_ids': ['same'], 'unresolved': None})
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'needs_more_facts'
    assert 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT' in [row['code'] for row in result['reasons']]
    assert next(row for row in result['relation_results'] if row['id'] == 'same')['state'] == 'contradicted'


def test_candidate_role_is_provenance_only_until_used_by_a_relation(supplied_case):
    candidate = supplied_case['artifacts'][0]
    candidate['role'] = 'candidate'
    source = copy.deepcopy(candidate)
    source.update(id='syn:relation', role='source')
    supplied_case['artifacts'].append(source)
    supplied_case['view']['descriptors'].append({
        'id': 'relation-descriptor',
        'root_id': 'root',
        'artifact_id': 'syn:relation',
        'state': 'inspected',
    })
    supplied_case['host']['limits'].update(artifact_count=2, decoded_bytes=10)
    supplied_case['citations'][0]['artifact_id'] = 'syn:source'
    supplied_case['citations'].append({
        'id': 'relation-cite',
        'artifact_id': 'syn:relation',
        'representation_sha256': source['representation_sha256'],
        'start_byte': 0,
        'end_byte': 5,
    })
    supplied_case['relations'][0]['citation_id'] = 'relation-cite'
    supplied_case['needs'][0]['citation_ids'] = []
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'eligible'
    assert not any(
        row.get('reference_id') == 'cite'
        for row in result['gaps']
    )


def test_candidate_role_used_by_relation_is_limited_evidence(supplied_case):
    supplied_case['artifacts'][0]['role'] = 'candidate'
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert next(
        row for row in result['relation_results'] if row['id'] == 'present'
    )['state'] == 'unresolved'
    assert {
        'relation_id': 'present',
        'property': 'limited_evidence',
    } in result['gaps']
    assert {
        'field_path': '$.relations[0].citation_id',
        'reference_id': 'cite',
        'properties': ['limited_evidence'],
        'impact': 'required_evidence',
    } in result['gaps']


def test_source_same_retains_both_reference_failures_in_publishable_optional_route():
    case = same_case('alpha')
    case['relations'][1]['left_citation_id'] = 'ghost-left'
    case['artifacts'][1]['limitations'] = ['outside_view']
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
        approach['need_relations'].append({
            'need_id': 'optional',
            'relation_ids': ['same'],
            'unresolved': None,
        })
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'eligible'
    assert result['survivors'] == ['global', 'peer']
    assert {
        'relation_id': 'same',
        'property': 'missing_citation',
    } in result['gaps']
    assert {
        'field_path': '$.relations[1].left_citation_id',
        'reference_id': 'ghost-left',
        'properties': ['missing_citation'],
        'impact': 'optional_provenance',
    } in result['gaps']
    assert {
        'field_path': '$.relations[1].right_citation_id',
        'reference_id': 'second-cite',
        'properties': ['outside_view'],
        'impact': 'optional_provenance',
    } in result['gaps']
    assert raw_intake.canonical_result_bytes(result)


def test_shared_relation_required_use_remains_admitted():
    case = same_case('beta')
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['same']
        approach['need_relations'].append({'need_id': 'optional', 'relation_ids': ['same'], 'unresolved': None})
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['survivors'] == []
    assert all(row['state'] == 'omitted' for row in result['route_results'])
    assert len([row for row in result['reasons'] if row['scope']['kind'] == 'approach']) == 2
    assert all(row['code'] == 'TARGET_EVIDENCE_CONTRADICTORY' for row in result['reasons'] if row['scope']['kind'] == 'approach')
    assert {'relation_id': 'same', 'property': 'false_requirement'} in result['gaps']


def test_unused_bad_citation_and_associated_missing_artifact_are_global(supplied_case):
    bad = copy.deepcopy(supplied_case['citations'][0])
    bad.update(id='unused', representation_sha256='0' * 64)
    supplied_case['citations'].append(bad)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    assert result['route_results'][0]['state'] == 'supported'
    assert {
        'field_path': '$.citations[1].artifact_id',
        'reference_id': 'syn:source',
        'properties': ['invalid_source_association'],
        'impact': 'association_integrity',
    } in result['gaps']
    supplied_case['artifacts'] = []
    supplied_case['host']['limits'].update(decoded_bytes=0, artifact_count=0)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['primary_reason'] == 'ADMITTED_VIEW_MISSING_FILE'
    assert 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT' in [
        row['code'] for row in result['reasons']
    ]
    assert {'relation_id': 'present', 'property': 'missing_citation'} in result['gaps']
    assert any(
        row.get('impact') == 'association_integrity'
        and row.get('properties') == ['missing_artifact']
        for row in result['gaps']
    )
