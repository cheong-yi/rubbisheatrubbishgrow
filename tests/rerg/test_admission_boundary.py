"""Complete admission precedes evidence failures and caller-data projection."""
import copy
import io
import json

import pytest

from rerg import raw_cli, raw_intake
from test_supplied_admission import make_case, supplied_case, public_docs_case


def invoke(case):
    output = io.StringIO()
    status = raw_cli.main(io.BytesIO(json.dumps(case).encode()), output)
    return status, json.loads(output.getvalue())


def expected(code, path, detail=None):
    return {'code': code, 'field_path': path, 'detail_code': detail or code}


@pytest.mark.parametrize('mode,diagnostics', [
    ('positive', None),
    ('missing', [expected('MISSING_REQUIRED_FIELD', '$.contract')]),
    ('version', [expected('UNSUPPORTED_CONTRACT', '$.contract', 'VERSION_UNSUPPORTED')]),
    ('kind', [expected('INVALID_FIELD_VALUE', '$.kind', 'EXTRA_FIELD')]),
    ('kind_wrong', [expected('INVALID_FIELD_VALUE', '$.kind', 'EXTRA_FIELD')]),
    ('extra', [expected('INVALID_FIELD_VALUE', '$', 'EXTRA_FIELD')]),
    ('kind_extra', [expected('INVALID_FIELD_VALUE', '$', 'EXTRA_FIELD')]),
    ('missing_kind', [expected('MISSING_REQUIRED_FIELD', '$.contract'), expected('INVALID_FIELD_VALUE', '$.kind', 'EXTRA_FIELD')]),
    ('missing_kind_extra', [expected('MISSING_REQUIRED_FIELD', '$.contract'), expected('INVALID_FIELD_VALUE', '$', 'EXTRA_FIELD')]),
    ('version_kind_extra', [expected('UNSUPPORTED_CONTRACT', '$.contract', 'VERSION_UNSUPPORTED'), expected('INVALID_FIELD_VALUE', '$', 'EXTRA_FIELD')]),
])
def test_exact_r3_input_matrix(supplied_case, mode, diagnostics):
    if mode.startswith('missing'): del supplied_case['contract']
    if mode.startswith('version'): supplied_case['contract'] = 'rerg-foundation/1'
    if 'kind' in mode: supplied_case['kind'] = 'other' if mode == 'kind_wrong' else 'assessment'
    if 'extra' in mode: supplied_case['unexpected'] = None
    before = copy.deepcopy(supplied_case)
    python = raw_intake.evaluate_assessment(supplied_case)
    status, wire = invoke(supplied_case)
    assert supplied_case == before and wire == python
    assert wire['contract'] == 'rerg-foundation/3'
    assert wire['authorizing'] is wire['can_execute'] is False
    if diagnostics is None:
        assert status == 0 and wire['outcome'] == 'eligible'
    else:
        assert status == 2 and wire['diagnostics'] == diagnostics
        assert wire['primary_diagnostic'] == diagnostics[0]
        assert set(wire) == {'contract', 'kind', 'authorizing', 'can_execute', 'primary_diagnostic', 'diagnostics'}


@pytest.mark.parametrize('mutation,code,detail', [
    ('absent', 'MISSING_REQUIRED_FIELD', 'MISSING_REQUIRED_FIELD'),
    ('missing', 'MISSING_REQUIRED_FIELD', 'COMPONENT_MISSING'),
    ('duplicate', 'DUPLICATE_FIELD', 'COMPONENT_DUPLICATE'),
    ('path', 'INVALID_FIELD_VALUE', 'COMPONENT_PATH'),
    ('digest', 'INVALID_FIELD_VALUE', 'DIGEST_INVALID'),
    ('data', 'INVALID_FIELD_VALUE', 'EXTRA_FIELD'),
])
def test_component_manifest_is_admission_not_a_gap(supplied_case, mutation, code, detail):
    if mutation == 'absent': del supplied_case['components']
    elif mutation == 'missing': supplied_case['components'].pop()
    elif mutation == 'duplicate': supplied_case['components'][1] = copy.deepcopy(supplied_case['components'][0])
    elif mutation == 'path': supplied_case['components'][0]['path'] = 'rerg/unknown.py'
    elif mutation == 'digest': supplied_case['components'][0]['sha256'] = 'not-a-digest'
    else: supplied_case['components'][0]['data'] = 'not executable'
    status, result = invoke(supplied_case)
    assert status == 2 and result['primary_diagnostic']['code'] == code
    assert result['primary_diagnostic']['detail_code'] == detail
    assert 'reasons' not in result


@pytest.mark.parametrize('path,value', [
    (('candidate', 'source_kind'), 'wrong-kind'),
    (('candidate', 'id'), []),
    (('artifacts', 0, 'role'), 'wrong-role'),
    (('artifacts', 0, 'source_sha256'), 'not-a-digest'),
    (('citations', 0, 'start_byte'), True),
    (('citations', 0, 'start_byte'), -1),
    (('citations', 0, 'end_byte'), 0),
    (('candidate', 'locator'), "password = 'test-secret-marker'"),
    (('host', 'policy', 'allowed'), []),
    (('host', 'limits', 'limit_hit'), 1),
    (('approaches', 0, 'id'), "password = 'test-secret-marker'"),
])
@pytest.mark.parametrize('failed', [False, True])
def test_failed_evidence_cannot_hide_malformed_or_unsafe_peer(supplied_case, path, value, failed):
    if failed: supplied_case['artifacts'][0]['limitations'] = ['extraction_failed']
    parent = supplied_case
    for key in path[:-1]: parent = parent[key]
    parent[path[-1]] = value
    status, result = invoke(supplied_case)
    assert status == 2 and result['kind'] == 'invalid_invocation'
    assert 'test-secret-marker' not in json.dumps(result)
    assert 'outcome' not in result


def test_independent_codes_remain_separate_with_deterministic_representatives(supplied_case):
    supplied_case['candidate']['locator'] = "password = 'test-secret-marker'"
    supplied_case['target']['unexpected'] = True
    supplied_case['candidate']['unexpected'] = True
    status, result = invoke(supplied_case)
    assert status == 2
    assert [row['code'] for row in result['diagnostics']] == ['UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR', 'INVALID_FIELD_VALUE']
    assert result['diagnostics'][1] == expected('INVALID_FIELD_VALUE', '$.candidate', 'EXTRA_FIELD')
    assert 'test-secret-marker' not in json.dumps(result)


@pytest.mark.parametrize('value', [1.2, float('nan'), float('inf'), b'bytes', {1: 'key'}, '\ud800', 2**63])
def test_python_json_domain_rejects_nonportable_values(supplied_case, value):
    supplied_case['candidate']['question'] = value
    before = copy.deepcopy(supplied_case)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['kind'] == 'invalid_invocation' and 'input' not in result
    assert type(supplied_case['candidate']['question']) is type(before['candidate']['question'])


def test_cycles_and_deep_values_are_invalid_without_projection(supplied_case):
    supplied_case['candidate']['question'] = supplied_case
    assert raw_intake.evaluate_assessment(supplied_case)['kind'] == 'invalid_invocation'
    case = make_case()
    nested = []
    for _ in range(33): nested = [nested]
    case['candidate']['question'] = nested
    result = raw_intake.evaluate_assessment(case)
    assert result['primary_diagnostic']['code'] == 'INVALID_ENCODING_OR_SIZE'


def test_public_result_cannot_be_trusted_as_input(supplied_case):
    result = raw_intake.evaluate_assessment(supplied_case)
    result['input']['approaches'][0]['id'] = "password = 'test-secret-marker'"
    rejected = raw_intake.evaluate_assessment(result)
    assert rejected['kind'] == 'invalid_invocation'
    assert 'test-secret-marker' not in json.dumps(rejected)


@pytest.mark.parametrize('kind', ['event_ordering', 'validation', 'preservation', 'transition'])
def test_failed_artifact_does_not_relax_source_ceiling(public_docs_case, kind):
    public_docs_case['artifacts'][0]['limitations'] = ['extraction_failed']
    public_docs_case['relations'][0] = {'id': 'present', 'kind': kind}
    status, result = invoke(public_docs_case)
    assert status == 2
    assert result['diagnostics'] == [expected('UNSUPPORTED_CONTRACT', '$.relations[0].kind', 'RELATION_REDUCTION_UNSUPPORTED')]
