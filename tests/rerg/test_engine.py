"""Independent source-byte and charter reason oracles."""
import copy
import hashlib
import io
import itertools
import json

import pytest

from test_supplied_admission import make_case

CODES = (
    'TARGET_IDENTITY_MISMATCH', 'READ_SCOPE_MISMATCH_OR_ESCAPE',
    'SNAPSHOT_STALE_OR_CHANGED', 'ADMITTED_VIEW_MISSING_FILE',
    'RESOURCE_LIMIT_REACHED', 'COVERAGE_INCOMPLETE',
    'CITATION_OR_HASH_COVERAGE_INSUFFICIENT', 'TARGET_EVIDENCE_CONTRADICTORY',
    'LOAD_BEARING_NEED_UNRESOLVED', 'REJECT_UNSUPPORTED_UNSAFE_OR_DISALLOWED',
    'DEFER_POLICY_OR_NOT_READY', 'NO_CHANGE_CURRENT_SURFACE_SUFFICIENT',
    'ELIGIBLE_COVERAGE_CONFIRMED',
)


def evaluate(case):
    from rerg.raw_intake import evaluate_assessment
    return evaluate_assessment(case)


def same_case(right='alpha', route='global', peer=True):
    case = make_case()
    artifact = copy.deepcopy(case['artifacts'][0])
    artifact.update(id='syn:second', source_identity='second', data=right, source_sha256=hashlib.sha256(right.encode()).hexdigest(), representation_sha256=hashlib.sha256(right.encode()).hexdigest())
    case['artifacts'].append(artifact)
    case['view']['descriptors'].append({'id': 'second-descriptor', 'root_id': 'root', 'artifact_id': 'syn:second', 'state': 'inspected'})
    case['host']['limits'].update(artifact_count=2, decoded_bytes=5 + len(right.encode()))
    case['citations'].append({'id': 'second-cite', 'artifact_id': 'syn:second', 'representation_sha256': artifact['representation_sha256'], 'start_byte': 0, 'end_byte': len(right.encode())})
    case['relations'].append({'id': 'same', 'kind': 'source_same', 'left_citation_id': 'cite', 'right_citation_id': 'second-cite'})
    case['approaches'][0]['id'] = route
    case['approaches'][0]['need_relations'][0]['relation_ids'] = ['same']
    if peer:
        other = copy.deepcopy(case['approaches'][0])
        other['id'] = 'peer'
        other['need_relations'][0]['relation_ids'] = ['present']
        case['approaches'].append(other)
    return case


def test_positive_and_invalid_are_distinct_public_results():
    case = make_case()
    result = evaluate(case)
    assert result['outcome'] == 'eligible' and result['survivors'] == ['route']
    assert result['reasons'] == [{'code': CODES[12], 'scope': {'kind': 'global'}, 'affected_ids': [[5, 0]], 'details': []}]
    del case['contract']
    invalid = evaluate(case)
    assert invalid['kind'] == 'invalid_invocation' and 'outcome' not in invalid
    assert invalid['diagnostics'] == [{'code': 'MISSING_REQUIRED_FIELD', 'field_path': '$.contract', 'detail_code': 'MISSING_REQUIRED_FIELD'}]


@pytest.mark.parametrize('mutation,outcome,code', [('current', 'no_change', 11), ('hold', 'defer', 10), ('binding', 'reject', 0), ('missing', 'needs_more_facts', 6)])
def test_each_outcome_requires_evidence(mutation, outcome, code):
    case = make_case()
    if mutation == 'current': case['needs'][0]['current_relation_ids'] = ['present']
    elif mutation == 'hold': case['host']['policy']['ready'] = False
    elif mutation == 'binding': case['host']['target_binding']['id'] = 'other'
    else: case['citations'] = []
    result = evaluate(case)
    assert result['outcome'] == outcome and result['primary_reason'] == CODES[code]
    assert result['survivors'] == []


@pytest.mark.parametrize('count', [4, 8])
def test_all_grounded_alternatives_survive_unranked(count):
    case = make_case()
    case['approaches'] = [dict(copy.deepcopy(case['approaches'][0]), id=f'route-{i}') for i in reversed(range(count))]
    result = evaluate(case)
    assert result['survivors'] == [f'route-{i}' for i in range(count)]


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('mutation,state,gap,local,global_code', [
    ('equal', 'supported', None, None, 12),
    ('unequal', 'contradicted', 'false_requirement', 7, None),
    ('missing_left', 'unresolved', 'missing_citation', 8, 6),
    ('missing_right', 'unresolved', 'missing_citation', 8, 6),
    ('outside', 'outside_view', 'outside_view', 8, 6),
    ('hash', 'unresolved', 'limited_evidence', 8, 6),
    ('span', 'unresolved', 'limited_evidence', 8, 6),
    ('identity', 'contradicted', 'false_requirement', 7, 7),
    ('target', 'supported', None, None, 0),
])
def test_source_same_and_local_global_separation(reverse, mutation, state, gap, local, global_code):
    case = same_case('beta' if mutation in ('unequal', 'identity') else 'alpha')
    if mutation == 'missing_left': case['citations'] = case['citations'][1:]
    elif mutation == 'missing_right': case['citations'] = case['citations'][:1]
    elif mutation == 'outside': case['artifacts'][1]['limitations'] = ['outside_view']
    elif mutation == 'hash': case['citations'][1]['representation_sha256'] = '0' * 64
    elif mutation == 'span': case['citations'][1]['end_byte'] = 99
    elif mutation == 'identity': case['artifacts'][1]['source_identity'] = 'source'
    elif mutation == 'target': case['host']['target_binding']['id'] = 'other'
    if reverse:
        relation = case['relations'][1]
        relation['left_citation_id'], relation['right_citation_id'] = relation['right_citation_id'], relation['left_citation_id']
    result = evaluate(case)
    assert next(row for row in result['relation_results'] if row['id'] == 'same')['state'] == state
    assert result['primary_reason'] == CODES[global_code if global_code is not None else local]
    assert ({'relation_id': 'same', 'property': gap} in result['gaps']) if gap else not result['gaps']
    local_rows = [row for row in result['reasons'] if row['scope'] == {'kind': 'approach', 'id': 'global'}]
    assert [row['code'] for row in local_rows] == ([] if local is None else [CODES[local]])
    if mutation == 'identity':
        assert len([row for row in result['reasons'] if row['code'] == CODES[7]]) == 2
    if global_code == 12:
        assert result['outcome'] == 'eligible'
        assert result['survivors'] == (['global', 'peer'] if mutation == 'equal' else ['peer'])
    elif global_code is None:
        assert result['outcome'] == 'needs_more_facts'
        assert result['survivors'] == []
    else:
        assert result['survivors'] == []


def test_same_code_global_and_literal_global_route_never_merge():
    case = same_case(peer=False)
    case['citations'] = []
    result = evaluate(case)
    rows = [row for row in result['reasons'] if row['code'] == CODES[8]]
    assert [row['scope'] for row in rows] == [{'kind': 'global'}, {'kind': 'approach', 'id': 'global'}]
    assert result['outcome'] == 'needs_more_facts'


def test_same_code_scope_and_identifier_ties_are_canonical():
    case = same_case('alpha')
    case['citations'] = case['citations'][:1]
    case['approaches'][0]['id'] = 'zeta'
    case['approaches'][1]['id'] = 'alpha'
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['same']
    case['needs'][0]['current_relation_ids'] = ['same']
    result = evaluate(case)
    rows = [row for row in result['reasons'] if row['code'] == CODES[8]]
    assert [row['scope'] for row in rows] == [
        {'kind': 'global'},
        {'kind': 'approach', 'id': 'alpha'},
        {'kind': 'approach', 'id': 'zeta'},
    ]
    assert result['primary_reason'] == CODES[6]


def test_approach_only_failure_is_nonpositive_and_publishable():
    result = evaluate(same_case('beta'))
    assert result['outcome'] == 'needs_more_facts'
    assert result['primary_reason'] == CODES[7]
    assert [row['scope'] for row in result['reasons']] == [
        {'kind': 'approach', 'id': 'global'},
    ]
    assert result['survivors'] == []
    assert {row['id']: row['state'] for row in result['route_results']} == {
        'global': 'omitted',
        'peer': 'supported',
    }


def test_required_obligation_marker_omits_route_and_records_gap():
    case = make_case()
    assignment = case['approaches'][0]['need_relations'][0]
    assignment.update(relation_ids=[], unresolved='the required source is unavailable')
    result = evaluate(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['survivors'] == []
    assert result['route_results'] == [{
        'id': 'route',
        'state': 'omitted',
        'reason_codes': [CODES[8]],
        'relation_ids': [],
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
    assert result['gaps'] == [{
        'approach_id': 'route',
        'need_id': 'need',
        'property': 'missing_requirement',
    }]


def test_optional_obligation_marker_remains_visible_without_omitting_route():
    case = make_case()
    case['needs'].append({
        'id': 'optional',
        'statement': 'Optional context.',
        'citation_ids': [],
        'load_bearing': False,
        'current_relation_ids': [],
    })
    case['approaches'][0]['need_relations'].append({
        'need_id': 'optional',
        'relation_ids': [],
        'unresolved': 'optional context is unavailable',
    })
    result = evaluate(case)
    assert result['outcome'] == 'eligible'
    assert result['survivors'] == ['route']
    assert result['route_results'][0] == {
        'id': 'route',
        'state': 'supported',
        'reason_codes': [CODES[8]],
        'relation_ids': ['present'],
    }
    assert result['reasons'] == [{
        'code': CODES[12],
        'scope': {'kind': 'global'},
        'affected_ids': [[5, 0]],
        'details': [],
    }]
    assert result['gaps'] == [{
        'approach_id': 'route',
        'need_id': 'optional',
        'property': 'missing_requirement',
    }]


def test_obligation_and_unresolved_relation_merge_one_local_reason():
    case = same_case('alpha', peer=False)
    case['citations'] = case['citations'][:1]
    case['approaches'][0]['need_relations'][0].update(
        relation_ids=['same'],
        unresolved='the requirement needs another source',
    )
    result = evaluate(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['route_results'][0]['reason_codes'] == [CODES[8]]
    assert [
        row for row in result['reasons']
        if row['scope'] == {'kind': 'approach', 'id': 'global'}
    ] == [{
        'code': CODES[8],
        'scope': {'kind': 'approach', 'id': 'global'},
        'affected_ids': [[2, 1], [4, 0], [5, 0]],
        'details': [],
    }]
    assert {
        'approach_id': 'global',
        'need_id': 'need',
        'property': 'missing_requirement',
    } in result['gaps']


def test_contradiction_remains_separate_from_obligation_marker_reason():
    case = same_case('beta', peer=False)
    case['approaches'][0]['need_relations'][0].update(
        relation_ids=['same'],
        unresolved='the requirement needs another source',
    )
    result = evaluate(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['route_results'][0]['reason_codes'] == [CODES[7], CODES[8]]
    local_rows = [
        row for row in result['reasons']
        if row['scope'] == {'kind': 'approach', 'id': 'global'}
    ]
    assert local_rows == [
        {
            'code': CODES[7],
            'scope': {'kind': 'approach', 'id': 'global'},
            'affected_ids': [[2, 1], [5, 0]],
            'details': [],
        },
        {
            'code': CODES[8],
            'scope': {'kind': 'approach', 'id': 'global'},
            'affected_ids': [[4, 0], [5, 0]],
            'details': [],
        },
    ]


def test_primary_precedence_includes_global_and_approach_scopes():
    case = same_case('beta')
    case['host']['policy']['allowed'] = False
    result = evaluate(case)
    assert result['outcome'] == 'reject'
    assert result['primary_reason'] == CODES[7]
    assert [(row['code'], row['scope']) for row in result['reasons']] == [
        (CODES[7], {'kind': 'approach', 'id': 'global'}),
        (CODES[9], {'kind': 'global'}),
    ]
    assert result['survivors'] == []


@pytest.mark.parametrize('mutation,expected_code', [
    ('contradicted', 7),
    ('unresolved', 8),
    ('outside', 8),
])
def test_required_current_failure_contributes_global_reason(mutation, expected_code):
    case = same_case('beta' if mutation == 'contradicted' else 'alpha')
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
    case['needs'][0]['current_relation_ids'] = ['same']
    if mutation == 'unresolved':
        case['citations'] = case['citations'][:1]
    elif mutation == 'outside':
        case['artifacts'][1]['limitations'] = ['outside_view']
    result = evaluate(case)
    current = [row for row in result['reasons'] if row['scope'] == {'kind': 'global'} and row['code'] == CODES[expected_code]]
    assert current and [2, 1] in current[0]['affected_ids'] and [4, 0] in current[0]['affected_ids']
    assert result['outcome'] == 'needs_more_facts'
    assert result['survivors'] == []

    empty_current = evaluate(make_case())
    assert empty_current['outcome'] == 'eligible'
    assert empty_current['survivors'] == ['route']


def test_required_current_reference_failure_has_a_located_r7_contribution():
    case = make_case()
    case['needs'][0]['current_relation_ids'] = ['present']
    case['relations'][0]['citation_id'] = 'current-ghost'
    result = evaluate(case)
    assert result['outcome'] == 'needs_more_facts'
    assert result['primary_reason'] == CODES[6]
    assert {
        'relation_id': 'present',
        'property': 'missing_citation',
    } in result['gaps']
    assert {
        'field_path': '$.relations[0].citation_id',
        'reference_id': 'current-ghost',
        'properties': ['missing_citation'],
        'impact': 'required_evidence',
    } in result['gaps']


def test_independent_complete_reason_mask_oracle():
    from rerg.safe_path import _reason_outcome
    forbidden = {frozenset((i, j)) for i in (10, 11, 12) for j in range(i)}
    assert len(forbidden) == 33
    for mask in range(8192):
        selected = {i for i in range(13) if mask & (1 << i)}
        codes = [CODES[i] for i in selected]
        if not selected:
            with pytest.raises(ValueError): _reason_outcome(codes)
            continue
        if selected & {0, 1, 9}: expected = 'reject'
        elif any(pair <= selected for pair in forbidden) or selected & set(range(2, 9)): expected = 'needs_more_facts'
        else: expected = {10: 'defer', 11: 'no_change', 12: 'eligible'}[next(iter(selected))]
        assert _reason_outcome(codes) == expected
    with pytest.raises(ValueError): _reason_outcome(['UNKNOWN'])


def test_retired_packets_and_unparseable_input_are_inert():
    from rerg.raw_cli import main
    for source in (b'[]', b'{"outcome":"pilot_first"}', b'bad json'):
        first, second = io.StringIO(), io.StringIO()
        assert main(io.BytesIO(source), first) == main(io.BytesIO(source), second) == 2
        assert first.getvalue() == second.getvalue()
        record = json.loads(first.getvalue())
        assert record['kind'] == 'invalid_invocation'
        assert 'outcome' not in record and 'reasons' not in record
