"""Exact output schema, escaped completeness and independent byte accounting."""
import builtins
import copy
import hashlib
import html
import json
import socket
import subprocess
from pathlib import Path

import pytest

from rerg import raw_intake, raw_derivation, render, path_query
from test_engine import CODES, same_case
from test_supplied_admission import make_case, supplied_case


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def reseal(result):
    if result.get('kind') != 'invalid_invocation' and 'replay' in result:
        result['replay'].pop('result_sha256', None)
        result['replay']['result_sha256'] = hashlib.sha256(encoded(result)).hexdigest()
    return result


def test_renderer_neutralizes_markup_and_preserves_complete_input(supplied_case):
    supplied_case['approaches'][0]['mechanism']['text'] = 'Read @everyone <@123> | `code` & <tag> "quoted" \'apostrophe\''
    result = raw_intake.evaluate_assessment(supplied_case)
    output = render.render_assessment_markdown(result)
    assert output.startswith('# RERG non-authorizing packet\n\n<pre>') and output.endswith('</pre>\n')
    assert '@everyone' not in output and '<@123>' not in output and '<tag>' not in output
    assert 'errors' not in result
    assert '&#124; &#96;code&#96; &amp; &lt;tag&gt;' in output
    payload = output[len('# RERG non-authorizing packet\n\n<pre>'):-len('</pre>\n')]
    assert html.unescape(payload).encode() == raw_intake.canonical_result_bytes(result)
    assert json.loads(html.unescape(payload)) == result
    assert result['authorizing'] is result['can_execute'] is False


def test_renderer_is_stable_without_admission_evaluation_or_effects(supplied_case, monkeypatch):
    result = raw_intake.evaluate_assessment(supplied_case)
    before = copy.deepcopy(result)
    expected = render.render_assessment_markdown(result)
    def forbidden(*args, **kwargs): raise AssertionError('Output crossed the pure serialization boundary')
    for module, name in [(builtins, 'open'), (Path, 'open'), (socket, 'socket'), (subprocess, 'run'), (raw_intake, 'evaluate_assessment'), (raw_intake, '_evaluate_admitted_assessment'), (raw_derivation, '_admit_assessment'), (path_query, '_evaluate_source_relation')]:
        monkeypatch.setattr(module, name, forbidden)
    original = raw_intake.canonical_result_bytes
    calls = []
    def counted(value):
        calls.append(value)
        return original(value)
    monkeypatch.setattr(raw_intake, 'canonical_result_bytes', counted)
    assert render.render_assessment_markdown(result) == expected
    assert len(calls) == 1 and result == before


def test_serialization_reuses_recorded_references_without_reacquisition(supplied_case, monkeypatch):
    result = raw_intake.evaluate_assessment(supplied_case)
    expected = raw_intake.canonical_result_bytes(result)

    def forbidden(*args, **kwargs):
        raise AssertionError('Serialization reacquired supplied evidence')

    for module, name in [
        (raw_intake, 'evaluate_assessment'),
        (raw_intake, '_evaluate_admitted_assessment'),
        (raw_derivation, '_admit_assessment'),
        (path_query, '_resolve_citation_reference'),
        (path_query, '_evaluate_source_relation'),
    ]:
        monkeypatch.setattr(module, name, forbidden)
    before = copy.deepcopy(result)
    assert raw_intake.canonical_result_bytes(result) == expected
    assert render.render_assessment_markdown(result).startswith('# RERG non-authorizing packet')
    assert result == before


@pytest.mark.parametrize('invalid_kind', [False, True])
@pytest.mark.parametrize('mutation', ['contract_missing', 'contract_wrong', 'contract_type', 'kind_missing', 'kind_wrong', 'kind_type', 'extra', 'authority'])
@pytest.mark.parametrize('rebound', [False, True])
def test_output_discriminants_cannot_be_laundered_by_digest(invalid_kind, mutation, rebound):
    case = make_case()
    if invalid_kind: del case['contract']
    result = raw_intake.evaluate_assessment(case)
    if mutation == 'contract_missing': del result['contract']
    elif mutation == 'contract_wrong': result['contract'] = 'rerg-foundation/1'
    elif mutation == 'contract_type': result['contract'] = None
    elif mutation == 'kind_missing': del result['kind']
    elif mutation == 'kind_wrong': result['kind'] = 'assessment' if invalid_kind else 'invalid_invocation'
    elif mutation == 'kind_type': result['kind'] = []
    elif mutation == 'authority': result['authorizing'] = 0
    else: result['outcome' if invalid_kind else 'diagnostics'] = []
    if rebound and 'replay' in result:
        result['replay'].pop('result_sha256', None)
        result['replay']['result_sha256'] = hashlib.sha256(encoded(result)).hexdigest()
    before = copy.deepcopy(result)
    for api in (raw_intake.canonical_result_bytes, render.render_assessment_markdown):
        with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
            api(result)
    assert result == before


@pytest.mark.parametrize('scope', ['global', None, {}, {'kind': 'global', 'id': 'global'}, {'kind': 'approach'}, {'kind': 'approach', 'id': 'absent'}, {'kind': 'approach', 'id': []}, {'kind': 'unknown'}, {'kind': False}, {'kind': 'approach', 'id': 'global', 'extra': None}])
@pytest.mark.parametrize('rebound', [False, True])
def test_tagged_scope_schema_is_closed_without_input_reevaluation(scope, rebound, monkeypatch):
    result = raw_intake.evaluate_assessment(same_case('beta'))
    result['reasons'][-1]['scope'] = copy.deepcopy(scope)
    if rebound: reseal(result)
    def forbidden(*args, **kwargs): raise AssertionError('Scope inferred through reevaluation')
    monkeypatch.setattr(raw_intake, 'evaluate_assessment', forbidden)
    monkeypatch.setattr(raw_derivation, '_admit_assessment', forbidden)
    for api in (raw_intake.canonical_result_bytes, render.render_assessment_markdown):
        with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'): api(result)


@pytest.mark.parametrize('mutation', ['duplicate_scope', 'reason_order', 'reference', 'detail', 'limits', 'input_digest', 'result_digest', 'survivor', 'gap', 'malformed_affected_ids'])
def test_rebound_structural_and_reference_mutations_fail(mutation):
    if mutation == 'reason_order':
        case = same_case('beta')
        case['host']['policy']['allowed'] = False
        result = raw_intake.evaluate_assessment(case)
    else:
        result = raw_intake.evaluate_assessment(same_case('beta'))
    if mutation == 'duplicate_scope': result['reasons'].append(copy.deepcopy(result['reasons'][-1]))
    elif mutation == 'reason_order': result['reasons'].reverse()
    elif mutation == 'reference': result['reasons'][0]['affected_ids'] = [[5, 63]]
    elif mutation == 'detail': result['reasons'][0]['details'] = ['coherence_assurance']
    elif mutation == 'limits': result['limits']['artifact_count'] = True
    elif mutation == 'input_digest': result['replay']['input_sha256'] = '0' * 64
    elif mutation == 'result_digest': result['replay']['result_sha256'] = '0' * 64
    elif mutation == 'survivor': result['survivors'] = ['not-a-route']
    elif mutation == 'malformed_affected_ids': result['reasons'][0]['affected_ids'] = [[]]
    else: result['gaps'] = []
    if mutation != 'result_digest': reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError): raw_intake.canonical_result_bytes(result)


@pytest.mark.parametrize('mutation', [
    'relation_state',
    'route_state',
    'route_diagnostics',
    'route_membership',
    'required_reason',
    'required_gap',
    'incompatible_gap',
    'supported_gap',
])
def test_resealed_recorded_state_contributions_cannot_be_removed(mutation):
    result = raw_intake.evaluate_assessment(same_case('beta'))
    route = result['route_results'][0]
    if mutation == 'relation_state':
        next(row for row in result['relation_results'] if row['id'] == 'same')['state'] = 'supported'
    elif mutation == 'route_state':
        route['state'] = 'supported'
    elif mutation == 'route_diagnostics':
        route['reason_codes'] = []
    elif mutation == 'route_membership':
        route['relation_ids'] = []
    elif mutation == 'required_reason':
        result['reasons'] = [
            row for row in result['reasons']
            if row['scope'].get('kind') != 'approach'
        ]
    elif mutation == 'required_gap':
        result['gaps'] = []
    elif mutation == 'incompatible_gap':
        result['gaps'][0]['property'] = 'outside_view'
    else:
        result['gaps'].append({'relation_id': 'present', 'property': 'false_requirement'})
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


@pytest.mark.parametrize('mutation', [
    'missing',
    'location',
    'impact',
    'property',
    'blocked_property',
    'duplicate',
    'invented',
])
def test_resealed_reference_gap_location_impact_property_and_duplicates_fail(mutation):
    case = make_case()
    case['needs'][0]['citation_ids'] = ['ghost']
    result = raw_intake.evaluate_assessment(case)
    expected = next(
        row for row in result['gaps']
        if row.get('field_path') == '$.needs[0].citation_ids[0]'
    )
    assert expected == {
        'field_path': '$.needs[0].citation_ids[0]',
        'reference_id': 'ghost',
        'properties': ['missing_citation'],
        'impact': 'required_evidence',
    }
    if mutation == 'missing':
        result['gaps'].remove(expected)
    elif mutation == 'location':
        expected['field_path'] = '$.candidate.citation_ids[0]'
    elif mutation == 'impact':
        expected['impact'] = 'optional_provenance'
    elif mutation == 'property':
        expected['properties'] = ['outside_view']
    elif mutation == 'blocked_property':
        expected['properties'] = ['invalid_source_association', 'missing_citation']
    elif mutation == 'duplicate':
        result['gaps'].append(copy.deepcopy(expected))
    else:
        result['gaps'].append({
            'field_path': '$.candidate.citation_ids[0]',
            'reference_id': 'ghost',
            'properties': ['missing_citation'],
            'impact': 'optional_provenance',
        })
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


@pytest.mark.parametrize('property_name', ['missing_citation', 'missing_artifact', 'limited_evidence', 'outside_view'])
def test_resealed_reference_gap_cannot_forge_namespace_failure_at_resolved_location(
    property_name,
):
    result = raw_intake.evaluate_assessment(make_case())
    result['gaps'].append({
        'field_path': '$.needs[0].citation_ids[0]',
        'reference_id': 'cite',
        'properties': [property_name],
        'impact': 'required_evidence',
    })
    result['reasons'] = [{
        'code': CODES[6],
        'scope': {'kind': 'global'},
        'affected_ids': [[4, 0]],
        'details': [],
    }]
    result['primary_reason'] = CODES[6]
    result['outcome'] = 'needs_more_facts'
    result['survivors'] = []
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def _required_marker_result():
    case = make_case()
    case['approaches'][0]['need_relations'][0].update(
        relation_ids=[],
        unresolved='required obligation is not captured',
    )
    return raw_intake.evaluate_assessment(case)


@pytest.mark.parametrize('mutation', [
    'missing',
    'duplicated',
    'mixed',
    'extra',
    'wrong_property',
    'wrong_id',
])
def test_resealed_obligation_gap_shape_and_membership_mutations_fail(mutation):
    result = _required_marker_result()
    expected = {
        'approach_id': 'route',
        'need_id': 'need',
        'property': 'missing_requirement',
    }
    assert result['gaps'] == [expected]
    if mutation == 'missing':
        result['gaps'] = []
    elif mutation == 'duplicated':
        result['gaps'].append(copy.deepcopy(expected))
    elif mutation == 'mixed':
        result['gaps'][0] = {
            'approach_id': 'route',
            'need_id': 'need',
            'property': 'missing_requirement',
            'relation_id': 'present',
        }
    elif mutation == 'extra':
        result['gaps'][0]['extra'] = None
    elif mutation == 'wrong_property':
        result['gaps'][0]['property'] = 'missing_citation'
    else:
        result['gaps'][0]['need_id'] = 'ghost'
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_resealed_obligation_gap_cannot_survive_marker_tampering():
    result = _required_marker_result()
    result['input']['approaches'][0]['need_relations'][0]['unresolved'] = None
    result['replay']['input_sha256'] = hashlib.sha256(
        encoded(result['input'])
    ).hexdigest()
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


@pytest.mark.parametrize('marker', [
    'x' * 510,
    'é' * 255,
    '"' * 255,
    '\\' * 255,
])
def test_unresolved_marker_accepts_exact_512_canonical_utf8_or_escaped_bytes(marker):
    assert len(encoded(marker)) == 512
    case = make_case()
    case['approaches'][0]['need_relations'][0].update(
        relation_ids=[],
        unresolved=marker,
    )
    result = raw_intake.evaluate_assessment(case)
    assert result['kind'] == 'assessment'
    assert result['gaps'] == [{
        'approach_id': 'route',
        'need_id': 'need',
        'property': 'missing_requirement',
    }]


@pytest.mark.parametrize('marker', [
    'x' * 511,
    'é' * 255 + 'x',
    '"' * 255 + 'x',
    '\\' * 255 + 'x',
])
def test_unresolved_marker_rejects_513_canonical_utf8_or_escaped_bytes(marker):
    assert len(encoded(marker)) == 513
    case = make_case()
    case['approaches'][0]['need_relations'][0].update(
        relation_ids=[],
        unresolved=marker,
    )
    result = raw_intake.evaluate_assessment(case)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'INVALID_ENCODING_OR_SIZE'


@pytest.mark.parametrize('failure', [
    'invalid_source_association',
    'limited_evidence',
    'outside_view',
])
def test_resealed_required_reference_failure_keeps_mandatory_r7(failure):
    case = make_case()
    if failure == 'invalid_source_association':
        case['citations'][0]['representation_sha256'] = '0' * 64
    elif failure == 'limited_evidence':
        case['artifacts'][0]['limitations'] = ['redacted']
    else:
        case['artifacts'][0]['limitations'] = ['outside_view']
    result = raw_intake.evaluate_assessment(case)
    target = next(
        row for row in result['gaps']
        if row.get('field_path') == '$.needs[0].citation_ids[0]'
    )
    assert target['impact'] == 'required_evidence' and failure in target['properties']
    assert any(row['code'] == CODES[6] for row in result['reasons'])
    result['reasons'] = [row for row in result['reasons'] if row['code'] != CODES[6]]
    assert result['reasons']
    result['primary_reason'] = result['reasons'][0]['code']
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_recorded_association_failure_is_consistent_across_optional_uses():
    case = make_case()
    case['citations'][0]['end_byte'] = 99
    result = raw_intake.evaluate_assessment(case)
    raw_intake.canonical_result_bytes(result)
    result['gaps'] = [
        row for row in result['gaps']
        if row.get('field_path') != '$.approaches[0].mechanism.citation_ids[0]'
    ]
    reseal(result)
    for api in (raw_intake.canonical_result_bytes, render.render_assessment_markdown):
        with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
            api(result)


def test_resealed_current_reason_requires_need_and_relation_references():
    case = same_case('beta')
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
    case['needs'][0]['current_relation_ids'] = ['same']
    result = raw_intake.evaluate_assessment(case)
    current = next(
        row for row in result['reasons']
        if row['scope'] == {'kind': 'global'} and row['code'] == CODES[7]
    )
    current['affected_ids'].remove([4, 0])
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_resealed_optional_only_contribution_is_rejected():
    case = same_case('beta')
    secondary = copy.deepcopy(case['needs'][0])
    secondary.update(id='optional', load_bearing=False)
    case['needs'].append(secondary)
    for approach in case['approaches']:
        approach['need_relations'][0]['relation_ids'] = ['present']
        approach['need_relations'].append({'need_id': 'optional', 'relation_ids': ['same'], 'unresolved': None})
    result = raw_intake.evaluate_assessment(case)
    result['reasons'].append({
        'code': CODES[7],
        'scope': {'kind': 'approach', 'id': 'global'},
        'affected_ids': [[2, 1], [5, 0]],
        'details': [],
    })
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


@pytest.mark.parametrize('count', [4, 8])
@pytest.mark.parametrize('mutation', ['drop', 'drop_all', 'insert', 'duplicate', 'reorder'])
def test_resealed_survivors_are_exact_unranked_set(count, mutation):
    case = make_case()
    case['approaches'] = [
        dict(copy.deepcopy(case['approaches'][0]), id=f'route-{index}')
        for index in reversed(range(count))
    ]
    result = raw_intake.evaluate_assessment(case)
    expected = [f'route-{index}' for index in range(count)]
    assert result['survivors'] == expected
    if mutation == 'drop':
        result['survivors'] = expected[:-1]
    elif mutation == 'drop_all':
        result['survivors'] = []
    elif mutation == 'insert':
        result['survivors'] = expected + ['route-z']
    elif mutation == 'duplicate':
        result['survivors'] = expected + [expected[-1]]
    else:
        result['survivors'] = list(reversed(expected))
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_resealed_survivor_declared_omitted_route_is_rejected():
    result = raw_intake.evaluate_assessment(same_case('beta'))
    result['survivors'] = ['global']
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_input_permutations_have_one_canonical_result():
    case = make_case()
    permuted = copy.deepcopy(case)
    for field in ('artifacts', 'citations', 'relations', 'needs', 'approaches', 'components'):
        permuted[field].reverse()
    permuted['view']['descriptors'].reverse()
    permuted['view']['root_ids'].reverse()
    permuted['host']['root_ids'].reverse()
    first = raw_intake.evaluate_assessment(case)
    second = raw_intake.evaluate_assessment(permuted)
    assert raw_intake.canonical_result_bytes(first) == raw_intake.canonical_result_bytes(second)


@pytest.mark.parametrize('mutation', ['contradicted', 'unresolved'])
def test_approach_only_nonpositive_packets_publish_with_required_reference_reason(mutation):
    case = same_case('beta' if mutation == 'contradicted' else 'alpha')
    if mutation == 'unresolved':
        case['citations'] = case['citations'][:1]
    result = raw_intake.evaluate_assessment(case)
    assert result['outcome'] == 'needs_more_facts'
    if mutation == 'unresolved':
        assert result['primary_reason'] == CODES[6]
        assert any(
            row['scope']['kind'] == 'global' and row['code'] == CODES[6]
            for row in result['reasons']
        )
    else:
        assert result['primary_reason'] in (CODES[7], CODES[8])
        assert not [row for row in result['reasons'] if row['scope']['kind'] == 'global']
    assert raw_intake.canonical_result_bytes(result)
    assert render.render_assessment_markdown(result).startswith('# RERG non-authorizing packet')


def test_resealed_reason_outcome_and_policy_relationships_fail_closed():
    result = raw_intake.evaluate_assessment(same_case('beta'))
    result['primary_reason'] = CODES[0]
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)

    result = raw_intake.evaluate_assessment(same_case('beta'))
    result['outcome'] = 'eligible'
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)

    policy_case = make_case()
    policy_case['host']['policy']['allowed'] = False
    result = raw_intake.evaluate_assessment(policy_case)
    result['reasons'] = [{
        'code': CODES[12],
        'scope': {'kind': 'global'},
        'affected_ids': [[5, 0]],
        'details': [],
    }]
    result['outcome'] = 'eligible'
    result['survivors'] = ['route']
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_resealed_positive_result_requires_current_or_proposed_support():
    result = raw_intake.evaluate_assessment(make_case())
    result['reasons'] = [{
        'code': CODES[11],
        'scope': {'kind': 'global'},
        'affected_ids': [[4, 0]],
        'details': [],
    }]
    result['outcome'] = 'no_change'
    result['primary_reason'] = CODES[11]
    result['survivors'] = []
    reseal(result)
    with pytest.raises(raw_intake.AssessmentResultError, match='^INVALID_RESULT$'):
        raw_intake.canonical_result_bytes(result)


def test_independent_tagged_reason_and_packet_bound_arithmetic():
    assert len(CODES) == 13 and max(len(code.encode('ascii')) for code in CODES) == 39
    assert raw_intake.MAX_GAPS == 968
    assert raw_intake.MAX_OBLIGATION_GAPS == 32
    assert raw_intake.MAX_RESULT_BYTES == 1_420_081
    assert raw_intake.MAX_MARKDOWN_BYTES == 8_520_529
    K, Q, D = 'REJECT_UNSUPPORTED_UNSAFE_OR_DISALLOWED', 'X' * 32, 'f' * 64
    assert K in CODES and len(K) == 39
    refs = [[kind, index] for kind, count in enumerate([8, 64, 64, 8, 4, 8, 8, 8]) for index in range(count)]
    details = ['coherence_assurance', 'pre_assurance', 'post_assurance', 'final_assurance', 'cleanup_assurance']
    reason = {'code': K, 'scope': {'kind': 'approach', 'id': Q}, 'affected_ids': refs, 'details': details}
    assert len(encoded(refs)) == 1141 and len(encoded(reason)) == 1380
    assert len(encoded({'kind': 'global'})) == 17 and len(encoded(reason['scope'])) == 59
    relation = {'id': Q, 'state': 'outside_view', 'citation_ids': [Q, Q]}
    route = {'id': Q, 'state': 'supported', 'reason_codes': [CODES[7], CODES[8]], 'relation_ids': [Q] * 32}
    gap = {'relation_id': Q, 'property': 'false_requirement'}
    reference_gap = {
        'field_path': '$.' + 'x' * 126,
        'reference_id': 'x' * 32,
        'properties': [
            'invalid_source_association',
            'limited_evidence',
            'missing_artifact',
            'missing_citation',
            'outside_view',
        ],
        'impact': 'association_integrity',
    }
    assert [len(encoded(value)) for value in (relation, route, Q, gap)] == [151, 1278, 34, 81]
    assert len(reference_gap['field_path']) == 128
    assert len(encoded(reference_gap)) == 344
    obligation_gap = {
        'approach_id': 'x' * 32,
        'need_id': 'x' * 32,
        'property': 'missing_requirement',
    }
    assert len(encoded(obligation_gap)) == 128
    ceiling = 'Deterministic canonical-evaluator mechanics over explicitly supplied source evidence and explicitly synthetic fixtures; no native-target feasibility, behavioral usefulness, portability, replacement, default-path, cutover, or production-readiness claim.'
    envelope = {'contract': 'rerg-foundation/3', 'kind': 'assessment', 'authorizing': False, 'can_execute': False, 'evidence_mode': 'supplied_source', 'evidence_basis': 'host_attested_unverified', 'claim_ceiling': ceiling, 'input': None, 'outcome': 'needs_more_facts', 'primary_reason': K, 'reasons': [], 'relation_results': [], 'route_results': [], 'survivors': [], 'gaps': [], 'limits': dict(zip(['input_bytes', 'decoded_evidence_bytes', 'artifact_count', 'citation_count', 'relation_count', 'need_count', 'approach_count'], [1048576, 32768, 8, 64, 64, 4, 8]), limit_hit=False), 'replay': {'input_sha256': D, 'result_sha256': D, 'status': 'input_result_binding_only'}}
    assert len(encoded(envelope)) == 1009
    relation_bound = 1009 - 4 + 1048576 + 29 * 1380 + 28 + 64 * 151 + 63 + 8 * 1278 + 7 + 8 * 34 + 7 + 64 * 81 + 63
    assert relation_bound == 1115113
    bound = relation_bound + 872 * (344 + 1) + 32 * (len(encoded(obligation_gap)) + 1)
    assert bound == 1420081 and 43 + 6 * bound == 8520529
    diagnostic = dict(code='X' * 64, field_path='X' * 128, detail_code='X' * 64)
    invalid = dict(contract='rerg-foundation/3', kind='invalid_invocation', authorizing=False, can_execute=False, primary_diagnostic=None, diagnostics=[])
    assert len(encoded(diagnostic)) == 300 and len(encoded(invalid)) == 143
    assert raw_intake.MAX_INVALID_BYTES == 2846
    assert 143 - 4 + 300 + 8 * 300 + 7 == 2846


def maximal_case(token):
    case = make_case()
    def identifier(prefix, index): return (prefix + str(index)).ljust(32, 'x')
    def narrative(prefix):
        text = prefix
        while len(encoded(text + token)) <= 512: text += token
        while len(encoded(text)) < 512: text += 'x'
        return text
    case['artifacts'], case['citations'], case['relations'] = [], [], []
    case['view']['root_ids'] = [identifier('root', i) for i in range(8)]
    case['host']['root_ids'] = list(case['view']['root_ids'])
    case['view']['descriptors'] = []
    for i in range(8):
        data = str(i) + 'x' * 4095
        digest = hashlib.sha256(data.encode()).hexdigest()
        aid = identifier('syn:artifact', i)
        case['artifacts'].append({'id': aid, 'origin': 'synthetic', 'role': 'source', 'target_id': 'target', 'view_id': 'view', 'source_identity': str(i), 'source_version': '1', 'source_sha256': digest, 'representation_sha256': digest, 'data': data, 'limitations': []})
        case['view']['descriptors'].append({'id': identifier('descriptor', i), 'root_id': case['view']['root_ids'][i], 'artifact_id': aid, 'state': 'inspected'})
        for j in range(8):
            index = i * 8 + j
            cid = identifier('cite', index)
            case['citations'].append({'id': cid, 'artifact_id': aid, 'representation_sha256': digest, 'start_byte': j, 'end_byte': j + 1})
            case['relations'].append({'id': identifier('relation', index), 'kind': 'source_present', 'citation_id': cid})
    refs = [row['id'] for row in case['citations'][:8]]
    case['candidate'].update(question=narrative('question'), locator=narrative('locator'), citation_ids=list(refs))
    case['needs'] = [{'id': identifier('need', i), 'statement': narrative('need' + str(i)), 'citation_ids': list(refs), 'load_bearing': True, 'current_relation_ids': []} for i in range(4)]
    original = case['approaches'][0]
    case['approaches'] = []
    for i in range(8):
        row = copy.deepcopy(original)
        row['id'] = identifier('route', i)
        row['need_relations'] = [{'need_id': need['id'], 'relation_ids': [relation['id'] for relation in case['relations'][j * 8 + (i % 2) * 32:j * 8 + (i % 2) * 32 + 8]], 'unresolved': None} for j, need in enumerate(case['needs'])]
        for field in ('mechanism', 'required_changes', 'constraints', 'dependencies', 'risks', 'unknowns', 'validation', 'reversibility', 'stop_conditions'):
            row[field] = {'text': narrative(str(i) + field), 'citation_ids': list(refs)}
        row['lift']['basis'] = {'text': narrative(str(i) + 'lift'), 'citation_ids': list(refs)}
        case['approaches'].append(row)
    case['host']['limits'].update(decoded_bytes=32768, artifact_count=8)
    return case


def recursive_length(value):
    if type(value) is dict:
        return 2 + max(0, len(value) - 1) + sum(len(encoded(key)) + 1 + recursive_length(child) for key, child in value.items())
    if type(value) is list:
        return 2 + max(0, len(value) - 1) + sum(recursive_length(child) for child in value)
    return len(encoded(value))


@pytest.mark.parametrize('token', ['é', '"', '\\', '@', '<', '`', '|'])
@pytest.mark.parametrize('mutation', ['positive', 'unequal', 'missing', 'outside', 'bad_hash', 'all_missing'])
def test_actual_maximal_results_are_complete_and_fit_bounds(token, mutation):
    case = maximal_case(token)
    if mutation == 'unequal': case['relations'][0].update(kind='source_equals', expected='different')
    elif mutation == 'missing': case['citations'].pop(0)
    elif mutation == 'outside': case['artifacts'][0]['limitations'] = ['outside_view']
    elif mutation == 'bad_hash': case['artifacts'][0]['representation_sha256'] = '0' * 64
    elif mutation == 'all_missing':
        missing_ids = [f'ghost-{index}' for index in range(8)]
        case['candidate']['citation_ids'] = list(missing_ids)
        for need in case['needs']:
            need['citation_ids'] = list(missing_ids)
        for approach in case['approaches']:
            for field in ('mechanism', 'required_changes', 'constraints', 'dependencies', 'risks', 'unknowns', 'validation', 'reversibility', 'stop_conditions'):
                approach[field]['citation_ids'] = list(missing_ids)
            approach['lift']['basis']['citation_ids'] = list(missing_ids)
        for citation in case['citations']:
            citation['artifact_id'] = 'ghost'
        for relation in case['relations']:
            relation_id = relation['id']
            relation.clear()
            relation.update({
                'id': relation_id,
                'kind': 'source_same',
                'left_citation_id': 'ghost',
                'right_citation_id': 'ghost',
            })
        for approach in case['approaches']:
            for assignment in approach['need_relations']:
                assignment['unresolved'] = 'missing requirement'
    before = copy.deepcopy(case)
    result = raw_intake.evaluate_assessment(case)
    assert result['kind'] == 'assessment' and case == before
    assert len(result['relation_results']) == 64 and len(result['route_results']) == 8
    assert result['limits']['decoded_evidence_bytes'] == 32768
    assert all(len(row['relation_ids']) == 32 for row in result['route_results'])
    if mutation == 'all_missing':
        assert len(result['gaps']) == 968
        assert sum('field_path' in row for row in result['gaps']) == 872
        assert sum('relation_id' in row for row in result['gaps']) == 64
        assert sum('approach_id' in row for row in result['gaps']) == 32
    if mutation == 'positive': assert len(result['survivors']) == 8
    serialized = raw_intake.canonical_result_bytes(result)
    assert len(serialized) == recursive_length(result) <= 1420081
    projection = render.render_assessment_markdown(result)
    assert len(projection.encode()) <= 43 + 6 * len(serialized) <= 8520529
    decoded = json.loads(html.unescape(projection[36:-7]))
    assert decoded == result
    for source in case['artifacts']:
        assert next(row for row in decoded['input']['artifacts'] if row['id'] == source['id']) == source
    for source in case['approaches']:
        received = next(row for row in decoded['input']['approaches'] if row['id'] == source['id'])
        for field in ('mechanism', 'required_changes', 'constraints', 'dependencies', 'risks', 'unknowns', 'validation', 'reversibility', 'stop_conditions'):
            assert received[field]['text'] == source[field]['text'] and len(encoded(received[field]['text'])) == 512


def test_over_bound_input_is_invalid_not_truncated():
    case = maximal_case('x')
    case['artifacts'][0]['data'] += 'x'
    result = raw_intake.evaluate_assessment(case)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'INVALID_ENCODING_OR_SIZE'
    assert len(raw_intake.canonical_result_bytes(result)) <= 2846
