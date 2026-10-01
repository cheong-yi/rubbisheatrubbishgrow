"""Transport, ordinary module entrypoints and controlled internal faults."""
import copy
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

from rerg import raw_cli, raw_intake
from test_supplied_admission import make_case, supplied_case

CANDIDATE = Path(__file__).resolve().parents[2]


def invoke_bytes(data):
    output = io.StringIO()
    status = raw_cli.main(io.BytesIO(data), output)
    return status, json.loads(output.getvalue())


@pytest.mark.parametrize('nested', [False, True])
def test_duplicate_fields_reject_without_last_value_wins(nested):
    case = json.dumps(make_case()).encode()
    data = case.replace(b'"contract": "rerg-foundation/3"', b'"contract":"rerg-foundation/3","contract":"rerg-foundation/2"')
    if nested:
        data = data.replace(b'"source_kind": "question"', b'"source_kind":"question","source_kind":"note"')
    status, result = invoke_bytes(data)
    assert status == 2
    assert [row['code'] for row in result['diagnostics']] == ['UNSUPPORTED_CONTRACT', 'DUPLICATE_FIELD']
    assert result['primary_diagnostic']['detail_code'] == 'VERSION_UNSUPPORTED'


@pytest.mark.parametrize('data', [b'\xff', b'\xef\xbb\xbf{}', b'{"x":"\\ud800"}', b'{"x":NaN}', b'{"x":1.5}', b'{} {}', b'[]', b'null'])
def test_encoding_json_domain_and_malformed_transport(data):
    status, result = invoke_bytes(data)
    assert status == 2 and result['kind'] == 'invalid_invocation'
    assert 'outcome' not in result and 'input' not in result
    assert result['authorizing'] is result['can_execute'] is False


def test_exact_wire_limit_counts_whitespace(supplied_case):
    data = json.dumps(supplied_case).encode()
    for size in (1048575, 1048576):
        status, result = invoke_bytes(data + b' ' * (size - len(data)))
        assert status == 0 and result['outcome'] == 'eligible'
    status, result = invoke_bytes(data + b' ' * (1048577 - len(data)))
    assert status == 2 and result['primary_diagnostic']['code'] == 'INVALID_ENCODING_OR_SIZE'


def test_exact_depth_limit_and_quoted_delimiters():
    for depth in (31, 32):
        value, invalid = raw_cli._decode(b'[' * depth + b'0' + b']' * depth)
        assert invalid is None and value
    value, invalid = raw_cli._decode(b'[' * 33 + b'0' + b']' * 33)
    assert value is None and invalid['primary_diagnostic']['code'] == 'INVALID_ENCODING_OR_SIZE'
    value, invalid = raw_cli._decode(b'{"x":"[\\\"{]"}')
    assert invalid is None and value == {'x': '["{]'}


def test_argv_is_rejected_before_stdin_access():
    class NoRead:
        def read(self, *args): raise AssertionError('argv branch read stdin')
    output = io.StringIO()
    assert raw_cli.main(NoRead(), output, argv=['--help']) == 2
    assert json.loads(output.getvalue())['diagnostics'] == [{'code': 'INVALID_FIELD_VALUE', 'field_path': '$', 'detail_code': 'INVOCATION_ARGUMENTS'}]


@pytest.mark.parametrize('fault', ['input', 'evaluation', 'serialization', 'output', 'error_reporting'])
def test_io_and_unexpected_faults_exit_one_without_invented_envelope(fault, monkeypatch, capsys):
    source, destination = io.BytesIO(json.dumps(make_case()).encode()), io.StringIO()
    def broken(*args, **kwargs): raise OSError('synthetic-private-marker')
    if fault == 'input': source = type('BrokenInput', (), {'read': broken})()
    elif fault in ('evaluation', 'error_reporting'): monkeypatch.setattr(raw_intake, 'evaluate_assessment', broken)
    elif fault == 'serialization': monkeypatch.setattr(raw_intake, 'canonical_result_bytes', broken)
    else:
        class PartialOutput:
            def write(self, value):
                destination.write(value[:5])
                raise OSError('synthetic-private-marker')
        assert raw_cli.main(source, PartialOutput()) == 1
        assert destination.getvalue() and capsys.readouterr().err == 'RERG_INTERNAL_ERROR\n'
        return
    if fault == 'error_reporting': monkeypatch.setattr(sys, 'stderr', type('BrokenError', (), {'write': broken})())
    assert raw_cli.main(source, destination) == 1
    assert destination.getvalue() == ''
    if fault != 'error_reporting': assert capsys.readouterr().err == 'RERG_INTERNAL_ERROR\n'


@pytest.mark.parametrize('module', ['rerg', 'rerg.raw_cli'])
@pytest.mark.parametrize('mutation,outcome', [('positive', 'eligible'), ('current', 'no_change'), ('hold', 'defer'), ('binding', 'reject'), ('missing', 'needs_more_facts'), ('invalid', None)])
def test_ordinary_modules_match_python_canonical_result(module, mutation, outcome):
    case = make_case()
    if mutation == 'current': case['needs'][0]['current_relation_ids'] = ['present']
    elif mutation == 'hold': case['host']['policy']['ready'] = False
    elif mutation == 'binding': case['host']['target_binding']['id'] = 'other'
    elif mutation == 'missing': case['citations'] = []
    elif mutation == 'invalid': case['contract'] = 'rerg-foundation/1'
    result = raw_intake.evaluate_assessment(case)
    child = subprocess.run([sys.executable, '-S', '-B', '-m', module], input=json.dumps(case).encode(), cwd=CANDIDATE, capture_output=True, timeout=10)
    assert child.returncode == (2 if outcome is None else 0) and child.stderr == b''
    assert child.stdout == raw_intake.canonical_result_bytes(result) + b'\n'
    assert result.get('outcome') == outcome


@pytest.mark.parametrize('module', ['rerg', 'rerg.raw_cli'])
@pytest.mark.parametrize('mode', ['missing', 'kind', 'kind_wrong', 'extra', 'kind_extra', 'missing_kind', 'missing_kind_extra', 'version_kind_extra'])
def test_input_matrix_through_both_ordinary_modules(module, mode):
    case = make_case()
    if mode.startswith('missing'): del case['contract']
    if mode.startswith('version'): case['contract'] = 'rerg-foundation/2'
    if 'kind' in mode: case['kind'] = 'wrong' if mode == 'kind_wrong' else 'assessment'
    if 'extra' in mode: case['unexpected'] = None
    result = raw_intake.evaluate_assessment(case)
    child = subprocess.run([sys.executable, '-S', '-B', '-m', module], input=json.dumps(case).encode(), cwd=CANDIDATE, capture_output=True, timeout=10)
    assert child.returncode == 2 and child.stderr == b''
    assert child.stdout == raw_intake.canonical_result_bytes(result) + b'\n'


@pytest.mark.parametrize('version', ['rerg-foundation/1', 'rerg-foundation/2', 'rerg-foundation/4'])
@pytest.mark.parametrize('module', ['rerg', 'rerg.raw_cli'])
def test_unsupported_versions_rejected_without_compatibility(version, module):
    case = make_case()
    case['contract'] = version
    result = raw_intake.evaluate_assessment(case)
    assert result['kind'] == 'invalid_invocation'
    assert result['contract'] == 'rerg-foundation/3'
    assert result['primary_diagnostic']['code'] == 'UNSUPPORTED_CONTRACT'
    child = subprocess.run(
        [sys.executable, '-S', '-B', '-m', module],
        input=json.dumps(case).encode(),
        cwd=CANDIDATE,
        capture_output=True,
        timeout=10,
    )
    assert child.returncode == 2 and child.stderr == b''
    assert child.stdout == raw_intake.canonical_result_bytes(result) + b'\n'


@pytest.mark.parametrize('module', ['direct', 'rerg', 'rerg.raw_cli'])
@pytest.mark.parametrize('invalid', [False, True])
@pytest.mark.parametrize('mutation', ['contract', 'kind', 'extra', 'scope'])
def test_malformed_internal_result_is_not_a_wire_invocation(module, invalid, mutation, monkeypatch, capsys):
    case = make_case()
    if invalid: del case['contract']
    result = raw_intake.evaluate_assessment(case)
    if mutation == 'contract': result['contract'] = 'rerg-foundation/1'
    elif mutation == 'kind': result.pop('kind')
    elif mutation == 'extra': result['unexpected'] = None
    elif not invalid: result['reasons'][0]['scope'] = 'global'
    else: result['diagnostics'][0]['scope'] = 'global'
    monkeypatch.setattr(raw_intake, 'evaluate_assessment', lambda invocation: result)
    source, output = io.BytesIO(json.dumps(make_case()).encode()), io.StringIO()
    if module == 'direct':
        assert raw_cli.main(source, output) == 1
    else:
        if module == 'rerg.raw_cli':
            monkeypatch.delitem(sys.modules, module)
        monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(source, encoding='utf-8'))
        monkeypatch.setattr(sys, 'stdout', output)
        monkeypatch.setattr(sys, 'argv', [module])
        with pytest.raises(SystemExit) as error: runpy.run_module(module, run_name='__main__', alter_sys=True)
        assert error.value.code == 1
    assert output.getvalue() == ''
    assert capsys.readouterr().err == 'RERG_INTERNAL_ERROR\n'


@pytest.mark.parametrize('path', [('host', 'limits'), ('host', 'checks'), ('host', 'policy'), ('host', 'target_binding'), ('approaches', 0, 'lift'), ('approaches', 0, 'mechanism'), ('citations', 0), ('view', 'descriptors', 0), ('components', 0)])
def test_failed_evidence_does_not_hide_peer_nested_shapes(supplied_case, path):
    supplied_case['artifacts'][0]['limitations'] = ['extraction_failed']
    row = supplied_case
    for key in path: row = row[key]
    row['unexpected'] = "password = 'test-secret-marker'"
    status, result = invoke_bytes(json.dumps(supplied_case).encode())
    assert status == 2 and 'test-secret-marker' not in json.dumps(result)


def test_capture_budget_limit_is_admitted_not_malformed(supplied_case):
    supplied_case['host']['limits']['limit_hit'] = True
    status, result = invoke_bytes(json.dumps(supplied_case).encode())
    assert status == 0 and result['primary_reason'] == 'RESOURCE_LIMIT_REACHED'
    supplied_case['host']['limits']['limit_hit'] = 1
    assert invoke_bytes(json.dumps(supplied_case).encode())[0] == 2
