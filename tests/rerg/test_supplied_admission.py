"""Explicit synthetic foundation evidence; never native-record specimens."""
import copy
import hashlib
import io
import json

import pytest

COMPONENTS = ('__init__', '__main__', 'raw_cli', 'raw_intake', 'raw_derivation', 'path_query', 'safe_path', 'render')
LOCAL_PATH_POLICY = 'local_only_not_portable_or_publication_safe'
LOCAL_GJC_PATH = 'Installed GJC executable at /home/a01/.local/bin/gjc'
LOCAL_USERS_GJC_PATH = 'Installed GJC executable at /Users/a01/.local/bin/gjc'
SECRET_FORMS = (
    'password=credential-marker',
    'password=p@ss-word!',
    '{"password":"credential-marker"}',
    'token: credential-marker',
    'api_key = credential-marker',
    'secret_key=credential-marker',
    'access_token=credential-marker',
    'https://user@docs.example.invalid/page',
    'ftp://user:credential-marker@docs.example.invalid/page',
    'https://docs.example.invalid/?api-key=credential-marker',
    'https://docs.example.invalid/?access%5Ftoken=credential-marker',
    'Authorization: Bearer credential-marker',
    'Bearer credential-marker',
    'Captured path /home/a01/.cache/item password=credential-marker',
    '-----BEGIN RSA PRIVATE KEY-----\ncredential-marker\n-----END RSA PRIVATE KEY-----',
)


def make_case():
    data = 'alpha'
    digest = hashlib.sha256(data.encode()).hexdigest()
    target = {'id': 'target', 'harness': 'opaque-harness', 'version': '1', 'surface': 'other_source', 'configuration_digest': 'a' * 64}
    narrative = {'text': 'Source-level intended change only.', 'citation_ids': ['cite']}
    approach = {name: copy.deepcopy(narrative) for name in ('mechanism', 'required_changes', 'constraints', 'dependencies', 'risks', 'unknowns', 'validation', 'reversibility', 'stop_conditions')}
    approach.update(id='route', need_relations=[{'need_id': 'need', 'relation_ids': ['present'], 'unresolved': None}], lift={'amount': None, 'unit': 'unknown', 'basis': copy.deepcopy(narrative)})
    return {
        'contract': 'rerg-foundation/3',
        'candidate': {'id': 'candidate', 'source_kind': 'question', 'locator': 'note:source', 'question': 'How could this source change fit?', 'citation_ids': []},
        'target': target,
        'view': {'id': 'view', 'target_id': 'target', 'root_ids': ['root'], 'operation': 'read_supplied_bytes', 'descriptors': [{'id': 'descriptor', 'root_id': 'root', 'artifact_id': 'syn:source', 'state': 'inspected'}]},
        'host': {'origin': 'synthetic', 'evidence_basis': 'host_attested_unverified', 'grant_id': 'syn:grant', 'target_binding': copy.deepcopy(target), 'view_id': 'view', 'root_ids': ['root'], 'operation': 'read_supplied_bytes', 'coherence': 'immutable', 'checks': dict.fromkeys(('pre', 'post', 'final', 'cleanup'), 'pass'), 'policy': {'allowed': True, 'ready': True}, 'limits': {'decoded_bytes': len(data.encode()), 'artifact_count': 1, 'limit_hit': False}},
        'artifacts': [{'id': 'syn:source', 'origin': 'synthetic', 'role': 'source', 'target_id': 'target', 'view_id': 'view', 'source_identity': 'source', 'source_version': '1', 'source_sha256': digest, 'representation_sha256': digest, 'data': data, 'limitations': []}],
        'citations': [{'id': 'cite', 'artifact_id': 'syn:source', 'representation_sha256': digest, 'start_byte': 0, 'end_byte': len(data.encode())}],
        'relations': [{'id': 'present', 'kind': 'source_present', 'citation_id': 'cite'}],
        'needs': [{'id': 'need', 'statement': 'Preserve cited source.', 'citation_ids': ['cite'], 'load_bearing': True, 'current_relation_ids': []}],
        'approaches': [approach],
        'components': [{'path': 'rerg/' + name + '.py', 'sha256': 'b' * 64} for name in COMPONENTS],
    }


def make_request():
    """Return the complete high-level proposal/capture pair for make_case."""
    case = make_case()
    span = {'artifact_key': 'source', 'start_byte': 0, 'end_byte': 5}
    narrative = {'text': 'Source-level intended change only.', 'citations': [copy.deepcopy(span)]}
    requirement = {'kind': 'source_present', 'span': copy.deepcopy(span)}
    proposal = {
        'contract': 'rerg-assessment-request/1',
        'candidate': {
            'key': 'candidate',
            'source_kind': 'question',
            'locator': 'note:source',
            'question': 'How could this source change fit?',
            'citations': [],
        },
        'target': {
            'key': 'target',
            'harness': 'opaque-harness',
            'version': '1',
            'surface': 'other_source',
            'configuration_digest': 'a' * 64,
        },
        'needs': [{
            'key': 'need',
            'statement': 'Preserve cited source.',
            'citations': [copy.deepcopy(span)],
            'load_bearing': True,
            'current_requirements': [copy.deepcopy(requirement)],
        }],
        'approaches': [{
            'key': 'route',
            'coverage': [{
                'need_key': 'need',
                'requirements': [copy.deepcopy(requirement)],
                'unresolved': None,
            }],
            'lift': {
                'amount': None,
                'unit': 'unknown',
                'basis': copy.deepcopy(narrative),
            },
            **{
                name: copy.deepcopy(narrative)
                for name in (
                    'mechanism', 'required_changes', 'constraints', 'dependencies',
                    'risks', 'unknowns', 'validation', 'reversibility',
                    'stop_conditions',
                )
            },
        }],
    }
    capture = {
        'target': copy.deepcopy(proposal['target']),
        'view': {
            'key': 'view',
            'target_key': 'target',
            'root_keys': ['root'],
            'operation': 'read_supplied_bytes',
            'descriptors': [{
                'key': 'descriptor',
                'root_key': 'root',
                'artifact_key': 'source',
                'state': 'inspected',
            }],
        },
        'host': {
            'origin': 'synthetic',
            'evidence_basis': 'host_attested_unverified',
            'grant_id': 'syn:grant',
            'view_key': 'view',
            'root_keys': ['root'],
            'operation': 'read_supplied_bytes',
            'coherence': 'immutable',
            'checks': dict.fromkeys(('pre', 'post', 'final', 'cleanup'), 'pass'),
            'policy': {'allowed': True, 'ready': True},
            'limits': {'limit_hit': False},
        },
        'artifacts': [{
            'key': 'source',
            'origin': 'synthetic',
            'role': 'source',
            'target_key': 'target',
            'view_key': 'view',
            'source_identity': 'source',
            'source_version': '1',
            'source_sha256': case['artifacts'][0]['source_sha256'],
            'data': 'alpha',
            'limitations': [],
        }],
        'components': copy.deepcopy(case['components']),
    }
    return proposal, capture


def _resize_request_spans(proposal, end_byte):
    def visit(value):
        if isinstance(value, dict):
            if value.get('artifact_key') == 'source':
                value['start_byte'] = 0
                value['end_byte'] = end_byte
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(proposal)


def _set_request_data(proposal, capture, data):
    digest = hashlib.sha256(data.encode('utf-8')).hexdigest()
    artifact = capture['artifacts'][0]
    artifact['data'] = data
    artifact['source_sha256'] = digest
    _resize_request_spans(proposal, len(data.encode('utf-8')))
    return digest


def _set_invocation_data(case, data):
    digest = hashlib.sha256(data.encode('utf-8')).hexdigest()
    artifact = case['artifacts'][0]
    artifact['data'] = data
    artifact['source_sha256'] = digest
    artifact['representation_sha256'] = digest
    case['host']['limits']['decoded_bytes'] = len(data.encode('utf-8'))
    for citation in case['citations']:
        citation['representation_sha256'] = digest
        citation['start_byte'] = 0
        citation['end_byte'] = len(data.encode('utf-8'))
    return digest


def _local_path_request(*, include_policy=True, policy=LOCAL_PATH_POLICY, path_text=LOCAL_GJC_PATH):
    proposal, capture = make_request()
    proposal['target']['harness'] = path_text
    capture['target']['harness'] = path_text
    capture['artifacts'][0]['source_identity'] = path_text
    _set_request_data(proposal, capture, path_text)
    if include_policy:
        capture['host']['local_path_policy'] = policy
    return proposal, capture


def _local_path_invocation(*, include_policy=True, policy=LOCAL_PATH_POLICY, path_text=LOCAL_GJC_PATH):
    case = make_case()
    case['target']['harness'] = path_text
    case['host']['target_binding']['harness'] = path_text
    case['artifacts'][0]['source_identity'] = path_text
    _set_invocation_data(case, path_text)
    if include_policy:
        case['host']['local_path_policy'] = policy
    return case


@pytest.fixture
def supplied_case():
    return make_case()


@pytest.fixture
def public_docs_case():
    case = make_case()
    case['candidate']['source_kind'] = 'url'
    case['candidate']['locator'] = 'https://docs.example.invalid/source'
    return case


def call_cli(case):
    from rerg.raw_cli import main
    output = io.StringIO()
    code = main(io.BytesIO(json.dumps(case).encode()), output)
    return code, json.loads(output.getvalue())


def test_supplied_source_positive_is_synthetic_not_native(supplied_case):
    code, result = call_cli(supplied_case)
    assert code == 0 and result['outcome'] == 'eligible'
    assert result['survivors'] == ['route']
    assert result['evidence_mode'] == 'synthetic'
    assert result['evidence_basis'] == 'host_attested_unverified'
    assert result['authorizing'] is result['can_execute'] is False


@pytest.mark.parametrize('field', ['now', 'target_capture', 'candidate_capture', 'controller_envelope', 'assessment', 'satisfied'])
def test_legacy_handoff_is_not_an_admission_alias(supplied_case, field):
    supplied_case[field] = None
    code, result = call_cli(supplied_case)
    assert code == 2 and result['kind'] == 'invalid_invocation'
    assert 'outcome' not in result and 'reasons' not in result


@pytest.mark.parametrize('mutation,reason', [('digest', 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'), ('citation', 'LOAD_BEARING_NEED_UNRESOLVED'), ('target', 'TARGET_IDENTITY_MISMATCH'), ('excluded', 'COVERAGE_INCOMPLETE'), ('uninspected', 'COVERAGE_INCOMPLETE'), ('limited', 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT')])
def test_supplied_admission_preserves_binding(supplied_case, mutation, reason):
    if mutation == 'digest': supplied_case['artifacts'][0]['representation_sha256'] = '0' * 64
    elif mutation == 'citation': supplied_case['citations'] = []
    elif mutation == 'target': supplied_case['artifacts'][0]['target_id'] = 'other'
    elif mutation in ('excluded', 'uninspected'): supplied_case['view']['descriptors'][0]['state'] = 'excluded' if mutation == 'excluded' else 'failed'
    else: supplied_case['artifacts'][0]['limitations'] = ['redacted']
    code, result = call_cli(supplied_case)
    assert code == 0 and result['survivors'] == []
    assert reason in [row['code'] for row in result['reasons'] if row['scope'] == {'kind': 'global'}]


def test_official_docs_are_only_explicit_source_bytes(public_docs_case):
    code, result = call_cli(public_docs_case)
    assert code == 0 and result['outcome'] == 'eligible'
    assert 'no native-target feasibility' in result['claim_ceiling']


@pytest.mark.parametrize('kind', ['event_ordering', 'validation', 'transition'])
def test_docs_cannot_establish_native_behavior(public_docs_case, kind):
    public_docs_case['relations'][0] = {'id': 'present', 'kind': kind}
    code, result = call_cli(public_docs_case)
    assert code == 2 and result['primary_diagnostic']['code'] == 'UNSUPPORTED_CONTRACT'


@pytest.mark.parametrize('value', ["password = 'synthetic-marker'", 'https://user:synthetic-marker@docs.example.invalid/page'])
def test_supplied_handoff_rejects_secrets_and_authenticated_locators(public_docs_case, value):
    public_docs_case['candidate']['locator'] = value
    code, result = call_cli(public_docs_case)
    assert code == 2 and 'synthetic-marker' not in json.dumps(result)


@pytest.mark.parametrize('fixture', ['supplied_case', 'public_docs_case'])
def test_supplied_admission_replays_without_io(request, fixture, monkeypatch):
    import builtins
    import socket
    import subprocess
    from pathlib import Path
    from rerg import raw_intake, render, path_query
    case = request.getfixturevalue(fixture)
    before = copy.deepcopy(case)
    def forbidden(*args, **kwargs):
        raise AssertionError('Pure assessment attempted host effects')
    with monkeypatch.context() as patch:
        for module, name in [(builtins, 'open'), (Path, 'read_bytes'), (Path, 'read_text'), (subprocess, 'run'), (subprocess, 'Popen'), (socket, 'socket'), (socket, 'create_connection'), (path_query, '_validate_adapter_receipt')]:
            patch.setattr(module, name, forbidden)
        result = raw_intake.evaluate_assessment(case)
        assert render.render_assessment_markdown(result).startswith('# RERG non-authorizing packet')
        assert raw_intake.canonical_result_bytes(result) == raw_intake.canonical_result_bytes(raw_intake.evaluate_assessment(case))
    assert case == before


def test_failed_evidence_does_not_hide_bad_peer(supplied_case):
    supplied_case['artifacts'][0]['limitations'] = ['extraction_failed']
    supplied_case['artifacts'][0]['representation_sha256'] = '0' * 64
    code, result = call_cli(supplied_case)
    assert code == 0 and result['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'
    supplied_case['candidate']['question'] = "password = 'synthetic-marker'"
    code, result = call_cli(supplied_case)
    assert code == 2 and 'synthetic-marker' not in json.dumps(result)


@pytest.mark.parametrize('path_text', [LOCAL_GJC_PATH, LOCAL_USERS_GJC_PATH])
def test_local_path_policy_preserves_bounded_paths_and_replay_signal(path_text):
    from rerg import raw_derivation, raw_intake

    proposal, capture = _local_path_request(path_text=path_text)
    data = path_text
    digest = hashlib.sha256(data.encode('utf-8')).hexdigest()
    end_byte = len(data.encode('utf-8'))
    before = copy.deepcopy((proposal, capture))
    admitted, invalid = raw_derivation._compile_assessment(proposal, capture)

    assert invalid is None
    assert (proposal, capture) == before
    assert admitted['host']['local_path_policy'] == LOCAL_PATH_POLICY
    assert admitted['target']['harness'] == path_text
    assert admitted['host']['target_binding']['harness'] == path_text
    assert admitted['artifacts'][0]['source_identity'] == path_text
    assert admitted['artifacts'][0]['data'] == data
    assert admitted['artifacts'][0]['source_sha256'] == digest
    assert admitted['artifacts'][0]['representation_sha256'] == digest
    assert all(
        row['start_byte'] == 0
        and row['end_byte'] == end_byte
        and row['representation_sha256'] == digest
        for row in admitted['citations']
    )

    admitted_before = copy.deepcopy(admitted)
    result = raw_intake.evaluate_assessment(admitted)
    assert admitted == admitted_before
    assert result['input']['host']['local_path_policy'] == LOCAL_PATH_POLICY
    assert result['input']['target']['harness'] == path_text
    assert result['input']['host']['target_binding']['harness'] == path_text
    assert result['input']['artifacts'][0]['data'] == data
    assert result['input']['artifacts'][0]['source_identity'] == path_text
    assert result['input']['artifacts'][0]['source_sha256'] == digest
    assert result['input']['artifacts'][0]['representation_sha256'] == digest
    assert all(
        row['start_byte'] == 0
        and row['end_byte'] == end_byte
        and row['representation_sha256'] == digest
        for row in result['input']['citations']
    )
    assert result['replay']['input_sha256'] == hashlib.sha256(
        json.dumps(result['input'], ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
    assert raw_intake.canonical_result_bytes(result)
    assert raw_intake.evaluate_assessment(result['input']) == result
    tampered_input = copy.deepcopy(result['input'])
    del tampered_input['host']['local_path_policy']
    assert raw_intake.evaluate_assessment(tampered_input)['kind'] == 'invalid_invocation'


def test_local_path_policy_schema_is_optional_and_procedurally_closed():
    from rerg import raw_derivation

    low_host = raw_derivation.INVOCATION_SCHEMA['$defs']['host']
    assessment_host = raw_derivation.ASSESSMENT_SCHEMA['$defs']['assessment_host']
    for schema in (low_host, assessment_host):
        assert schema['additionalProperties'] is False
        assert schema['properties']['local_path_policy'] == {
            'type': 'string', 'const': LOCAL_PATH_POLICY,
        }
        assert 'local_path_policy' not in schema['required']

    low = make_case()
    low['host']['local_path_policy'] = LOCAL_PATH_POLICY
    assert raw_derivation._check_input(low) == []
    proposal, capture = make_request()
    capture['host']['local_path_policy'] = LOCAL_PATH_POLICY
    assert raw_derivation._request_check_input({'proposal': proposal, 'capture': capture}) == []
    assert raw_derivation._check_input(make_case()) == []
    assert raw_derivation._request_check_input({'proposal': proposal, 'capture': make_request()[1]}) == []

    low['host']['unexpected'] = True
    assert any(path == '$.host' and detail == 'EXTRA_FIELD'
               for _, path, detail in raw_derivation._check_input(low))
    capture['host']['unexpected'] = True
    assert any(path == '$.capture.host' and detail == 'EXTRA_FIELD'
               for _, path, detail in raw_derivation._request_check_input({'proposal': proposal, 'capture': capture}))


@pytest.mark.parametrize('path_text', [LOCAL_GJC_PATH, LOCAL_USERS_GJC_PATH])
def test_local_paths_remain_strict_without_the_capture_signal(path_text):
    from rerg import raw_derivation, raw_intake

    low = _local_path_invocation(include_policy=False, path_text=path_text)
    expected_low_paths = {
        '$.target.harness', '$.host.target_binding.harness',
        '$.artifacts[0].source_identity', '$.artifacts[0].data',
    }
    low_errors = raw_derivation._check_input(low)
    assert expected_low_paths <= {
        path for code, path, _ in low_errors
        if code == 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR'
    }
    assert raw_intake.evaluate_assessment(low)['kind'] == 'invalid_invocation'

    proposal, capture = _local_path_request(include_policy=False, path_text=path_text)
    expected_high_paths = {
        '$.proposal.target.harness', '$.capture.target.harness',
        '$.capture.artifacts[0].source_identity', '$.capture.artifacts[0].data',
    }
    high_errors = raw_derivation._request_check_input({'proposal': proposal, 'capture': capture})
    assert expected_high_paths <= {
        path for code, path, _ in high_errors
        if code == 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR'
    }
    assert raw_intake.evaluate_proposal(proposal, capture)['kind'] == 'invalid_invocation'


@pytest.mark.parametrize('policy', [None, False, 'portable_or_publication_safe', 0])
def test_invalid_local_path_policy_never_enables_paths(policy):
    from rerg import raw_derivation, raw_intake

    low = _local_path_invocation(policy=policy)
    low_errors = raw_derivation._check_input(low)
    assert any(path == '$.host.local_path_policy' for _, path, _ in low_errors)
    assert any(
        code == 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR' and path == '$.artifacts[0].data'
        for code, path, _ in low_errors
    )
    low_result = raw_intake.evaluate_assessment(low)
    assert low_result['kind'] == 'invalid_invocation'
    assert LOCAL_GJC_PATH not in json.dumps(low_result)

    proposal, capture = _local_path_request(policy=policy)
    high_errors = raw_derivation._request_check_input({'proposal': proposal, 'capture': capture})
    assert any(path == '$.capture.host.local_path_policy' for _, path, _ in high_errors)
    assert any(
        code == 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR' and path == '$.capture.artifacts[0].data'
        for code, path, _ in high_errors
    )
    high_result = raw_intake.evaluate_proposal(proposal, capture)
    assert high_result['kind'] == 'invalid_invocation'
    assert LOCAL_GJC_PATH not in json.dumps(high_result)


@pytest.mark.parametrize('field', ['candidate_question', 'artifact_version', 'source_equals_expected'])
def test_local_path_policy_does_not_allow_paths_in_other_fields(field):
    from rerg import raw_derivation

    proposal, capture = make_request()
    capture['host']['local_path_policy'] = LOCAL_PATH_POLICY
    if field == 'candidate_question':
        proposal['candidate']['question'] = LOCAL_GJC_PATH
        expected_path = '$.proposal.candidate.question'
    elif field == 'artifact_version':
        capture['artifacts'][0]['source_version'] = LOCAL_GJC_PATH
        expected_path = '$.capture.artifacts[0].source_version'
    else:
        for requirement in (
            proposal['needs'][0]['current_requirements'],
            proposal['approaches'][0]['coverage'][0]['requirements'],
        ):
            requirement[0] = {
                'kind': 'source_equals',
                'span': copy.deepcopy(requirement[0]['span']),
                'expected': LOCAL_GJC_PATH,
            }
        expected_path = '$.proposal.needs[0].current_requirements[0].expected'
    errors = raw_derivation._request_check_input({'proposal': proposal, 'capture': capture})
    assert any(
        code == 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR' and path == expected_path
        for code, path, _ in errors
    )

    low = make_case()
    low['host']['local_path_policy'] = LOCAL_PATH_POLICY
    if field == 'candidate_question':
        low['candidate']['question'] = LOCAL_GJC_PATH
        expected_low_path = '$.candidate.question'
    elif field == 'artifact_version':
        low['artifacts'][0]['source_version'] = LOCAL_GJC_PATH
        expected_low_path = '$.artifacts[0].source_version'
    else:
        low['relations'][0].update(kind='source_equals', expected=LOCAL_GJC_PATH)
        expected_low_path = '$.relations[0].expected'
    low_errors = raw_derivation._check_input(low)
    assert any(
        code == 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR' and path == expected_low_path
        for code, path, _ in low_errors
    )


@pytest.mark.parametrize('local_mode', [False, True])
@pytest.mark.parametrize('secret', SECRET_FORMS)
def test_secrets_are_rejected_from_allowed_data_in_both_modes(local_mode, secret):
    from rerg import raw_intake

    low = make_case()
    if local_mode:
        low['host']['local_path_policy'] = LOCAL_PATH_POLICY
    _set_invocation_data(low, secret)
    low_before = copy.deepcopy(low)
    low_result = raw_intake.evaluate_assessment(low)
    assert low_result['kind'] == 'invalid_invocation'
    assert 'credential-marker' not in json.dumps(low_result)
    assert low == low_before

    proposal, capture = make_request()
    if local_mode:
        capture['host']['local_path_policy'] = LOCAL_PATH_POLICY
    _set_request_data(proposal, capture, secret)
    request_before = copy.deepcopy((proposal, capture))
    high_result = raw_intake.evaluate_proposal(proposal, capture)
    assert high_result['kind'] == 'invalid_invocation'
    assert 'credential-marker' not in json.dumps(high_result)
    assert (proposal, capture) == request_before


@pytest.mark.parametrize('local_mode', [False, True])
@pytest.mark.parametrize('data', [
    'user = ordinary_user',
    'username = "ordinary_user"',
    'pass = true',
    'auth = enabled',
])
def test_ordinary_assignment_names_preserve_evidence(local_mode, data):
    from rerg import raw_intake

    low = make_case()
    proposal, capture = make_request()
    if local_mode:
        low['host']['local_path_policy'] = LOCAL_PATH_POLICY
        capture['host']['local_path_policy'] = LOCAL_PATH_POLICY
    _set_invocation_data(low, data)
    _set_request_data(proposal, capture, data)
    before = copy.deepcopy((low, proposal, capture))

    low_result = raw_intake.evaluate_assessment(low)
    high_result = raw_intake.evaluate_proposal(proposal, capture)

    for result in (low_result, high_result):
        assert result['kind'] == 'assessment'
        assert result['input']['artifacts'][0]['data'] == data
        assert result['input']['artifacts'][0]['representation_sha256'] == (
            hashlib.sha256(data.encode('utf-8')).hexdigest()
        )
        assert result['authorizing'] is False
        assert result['can_execute'] is False
    assert (low, proposal, capture) == before
