"""Candidate foundation integration; not consumer-cutover or replacement proof."""
import copy
import importlib.util
import inspect
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

import rerg as engine
from rerg import raw_cli, raw_intake
from rerg.render import render_assessment_markdown
from test_host_workflow import captured_case
from test_supplied_admission import supplied_case, public_docs_case

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('fixture', ['captured_case', 'supplied_case', 'public_docs_case'])
@pytest.mark.parametrize('mutation,expected', [('positive', 'eligible'), ('current', 'no_change'), ('hold', 'defer'), ('disallowed', 'reject'), ('missing', 'needs_more_facts')])
@pytest.mark.parametrize('module', ['rerg', 'rerg.raw_cli'])
def test_alternate_cwd_explicit_origin_replay(request, fixture, mutation, expected, module, tmp_path):
    case = request.getfixturevalue(fixture)
    if mutation == 'current': case['needs'][0]['current_relation_ids'] = [case['relations'][0]['id']]
    elif mutation == 'hold': case['host']['policy']['ready'] = False
    elif mutation == 'disallowed': case['host']['policy']['allowed'] = False
    elif mutation == 'missing': case['citations'] = []
    before = copy.deepcopy(case)
    dependencies = [path for path in sys.path if path and not Path(path).is_relative_to(ROOT)]
    bootstrap = 'import importlib.util,json,runpy,sys;sys.path[:]=json.loads(sys.argv[1]);module=sys.argv[2];import rerg as engine;assert engine.__file__==sys.path[0]+"/rerg/__init__.py";assert importlib.util.find_spec("rerg.raw_cli").origin==sys.path[0]+"/rerg/raw_cli.py";assert importlib.util.find_spec("rerg.__main__").origin==sys.path[0]+"/rerg/__main__.py";sys.argv=[module];runpy.run_module(module,run_name="__main__",alter_sys=True)'
    command = [sys.executable, '-I', '-S', '-B', '-c', bootstrap, json.dumps([str(ROOT)] + dependencies), module]
    first = subprocess.run(command, input=json.dumps(case).encode(), capture_output=True, cwd=tmp_path, timeout=30)
    second = subprocess.run(command, input=json.dumps(case).encode(), capture_output=True, cwd=tmp_path, timeout=30)
    assert first.returncode == second.returncode == 0 and first.stderr == second.stderr == b''
    assert first.stdout == second.stdout
    result = raw_intake.evaluate_assessment(case)
    assert result['contract'] == 'rerg-foundation/3'
    assert result['outcome'] == expected
    assert first.stdout == raw_intake.canonical_result_bytes(result) + b'\n'
    assert render_assessment_markdown(result) == render_assessment_markdown(json.loads(first.stdout))
    assert case == before


def test_default_rejects_argv_without_reading_or_echoing():
    class Unreadable:
        def read(self, *args): raise AssertionError('argv triggered input')
    output = io.StringIO()
    assert raw_cli.main(Unreadable(), output, argv=['--request', 'synthetic-private-path']) == 2
    assert json.loads(output.getvalue())['primary_diagnostic']['detail_code'] == 'INVOCATION_ARGUMENTS'
    assert 'synthetic-private-path' not in output.getvalue()


@pytest.mark.parametrize('legacy', [
    {'contract': 'rerg-foundation/2'},
    {'schema_version': 'rerg-operator-request/v1', 'request': {}},
    {'mode': 'packet', 'candidates': []},
    {'schema_version': 'rerg-raw-result/v1', 'selected': []},
    {'primitive_map': {}, 'paths': ['caller-selected']},
])
def test_default_rejects_legacy_protocols_without_translation(legacy):
    output = io.StringIO()
    assert raw_cli.main(io.BytesIO(json.dumps(legacy).encode()), output) == 2
    result = json.loads(output.getvalue())
    assert result['kind'] == 'invalid_invocation' and result['authorizing'] is result['can_execute'] is False
    for api in (raw_intake.canonical_result_bytes, render_assessment_markdown):
        with pytest.raises(raw_intake.AssessmentResultError): api(legacy)


@pytest.mark.parametrize('module', [
    'rerg.operator',
    'rerg.operator_cli',
    'rerg.operator_contract',
])
def test_retired_operator_modules_have_no_redirect(module):
    assert importlib.util.find_spec(module) is None


def test_exact_public_exports_and_positional_api_contract():
    assert engine.__all__ == (
        'evaluate_assessment', 'evaluate_proposal', 'canonical_result_bytes',
        'render_assessment_markdown',
    )
    assert engine.evaluate_assessment is raw_intake.evaluate_assessment
    assert engine.evaluate_proposal is raw_intake.evaluate_proposal
    assert engine.canonical_result_bytes is raw_intake.canonical_result_bytes
    assert engine.render_assessment_markdown is render_assessment_markdown
    assert not hasattr(raw_intake, '_evaluate_proposal')
    proposal_signature = inspect.signature(engine.evaluate_proposal)
    assert tuple(proposal_signature.parameters) == ('proposal', 'capture')
    assert all(
        parameter.kind is inspect.Parameter.POSITIONAL_ONLY
        for parameter in proposal_signature.parameters.values()
    )
    documentation = inspect.getdoc(engine.evaluate_proposal).lower()
    assert 'pure' in documentation and 'non-authorizing' in documentation
    assert 'closed invalid-invocation envelope' in documentation
    invalid = engine.evaluate_proposal({}, {})
    assert set(invalid) == {
        'contract', 'kind', 'authorizing', 'can_execute',
        'primary_diagnostic', 'diagnostics',
    }
    assert invalid['kind'] == 'invalid_invocation'
    assert invalid['authorizing'] is invalid['can_execute'] is False
    for name in (
        'AssessmentResultError', 'evaluate_raw_candidate', 'canonical_raw_result',
        'render_adoption_markdown', 'compose_operator', 'run_operator_json',
        'render_operator_yaml',
    ):
        assert not hasattr(engine, name)
    for api in (engine.evaluate_assessment, engine.canonical_result_bytes, engine.render_assessment_markdown):
        with pytest.raises(TypeError): api()
        with pytest.raises(TypeError): api({}, {})
        with pytest.raises(TypeError): api(invocation={})
    for args, kwargs in (((), {}), (({},), {}), ((), {'invocation': {}})):
        with pytest.raises(TypeError): engine.evaluate_proposal(*args, **kwargs)
