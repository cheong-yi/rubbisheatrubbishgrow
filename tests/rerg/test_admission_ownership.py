"""Best-effort ownership regressions for the fixed RERG public surface.

Covered public paths and adversarial controls show no known hidden acquisition,
execution, or alternate evaluation in this tested implementation. This is not
an exhaustive Python safety or fail-closed proof.
"""
import ast
import builtins
import copy
import importlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess

import pytest

from rerg import path_query, raw_cli, raw_derivation, raw_intake, render
from test_supplied_admission import make_case, make_request, supplied_case


RETIRED = {
    'raw_intake': 'evaluate_raw_candidate _evaluate_raw_candidate canonical_raw_result canonical_adoption_bytes _validate_request _empty_result _blocker'.split(),
    'raw_derivation': 'RawDerivationError derive_evidence validate_envelope_shape validate_semantic_envelope _envelope_structure _record _strings _records _record_list _adoption_normalize _capture_without_retention _adoption_digest _validate_supplied_capture_shapes _capture_failure_shape _validate_artifact_shape _admit_artifact _supplied_evidence _adoption_evidence validate_adoption_assessment _admit_adoption_assessment'.split(),
    'path_query': '_adoption_refs _adoption_unknowns _captured_question_map adapt_target_map'.split(),
    'safe_path': '_approach_ids _closed_failure evaluate_safe_paths _select_admitted_paths'.split(),
    'render': 'RenderValidationError _markdown_cell _neutralize_mentions render_adoption_markdown'.split(),
}
HOST_SURFACES = {
    '_safe', '_validate_adapter_receipt', '_validate_followup_request',
    '_validate_followup_receipt', '_receipt_source_hashes',
    '_followup_eligible_paths', '_select_rankings',
}
ROOT = Path(__file__).resolve().parents[2]
CORE_MODULES = (
    '__init__', '__main__', 'raw_cli', 'raw_intake',
    'raw_derivation', 'path_query', 'safe_path', 'render',
)
PUBLIC_ROOTS = (
    'rerg.evaluate_assessment',
    'rerg.evaluate_proposal',
    'rerg.canonical_result_bytes',
    'rerg.render_assessment_markdown',
    'python -m rerg',
    'python -m rerg.raw_cli',
)


def spy_owned_operations(monkeypatch):
    """Count owned work only; route/reason projections are not evaluations."""
    counts = {}
    for module, name in (
        (raw_derivation, '_admit_assessment'),
        (raw_intake, '_evaluate_admitted_assessment'),
        (path_query, '_evaluate_source_relation'),
        (path_query, '_resolve_citation_reference'),
    ):
        original = getattr(module, name)
        counts[name] = 0

        def counted(*args, _name=name, _original=original, **kwargs):
            counts[_name] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, counted)
    return counts


def spy_high_level_operations(monkeypatch):
    """Count the compiler handoff and its one authoritative evaluation."""
    counts = {}
    for module, name in (
        (raw_derivation, '_compile_assessment'),
        (raw_derivation, '_admit_assessment'),
        (raw_intake, '_evaluate_admitted_assessment'),
    ):
        original = getattr(module, name)
        counts[name] = 0

        def counted(*args, _name=name, _original=original, **kwargs):
            counts[_name] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, counted)
    return counts


def _expected_owned_counts(case):
    relation_ids = []
    for relation in case['relations']:
        relation_ids.extend(
            [relation['left_citation_id'], relation['right_citation_id']]
            if relation['kind'] == 'source_same'
            else [relation['citation_id']]
        )
    return {
        '_admit_assessment': 1,
        '_evaluate_admitted_assessment': 1,
        '_evaluate_source_relation': len(case['relations']),
        '_resolve_citation_reference': len(set(relation_ids)),
    }


def test_high_level_compiler_owns_one_admission_and_evaluation(monkeypatch):
    proposal, capture = make_request()
    before = copy.deepcopy((proposal, capture))
    counts = spy_high_level_operations(monkeypatch)
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['kind'] == 'assessment'
    assert counts == {
        '_compile_assessment': 1,
        '_admit_assessment': 1,
        '_evaluate_admitted_assessment': 1,
    }
    assert (proposal, capture) == before


def test_invalid_high_level_compilation_never_reaches_evaluation(monkeypatch):
    proposal, capture = make_request()
    del proposal['contract']
    counts = spy_high_level_operations(monkeypatch)
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['kind'] == 'invalid_invocation'
    assert set(result) == {
        'contract', 'kind', 'authorizing', 'can_execute',
        'primary_diagnostic', 'diagnostics',
    }
    assert result['authorizing'] is result['can_execute'] is False
    assert counts == {
        '_compile_assessment': 1,
        '_admit_assessment': 0,
        '_evaluate_admitted_assessment': 0,
    }


@pytest.mark.parametrize('malformed_need', [None, {'key': 'need'}], ids=['nonobject', 'partial'])
@pytest.mark.parametrize('requirements', [[], None], ids=['empty', 'null'])
@pytest.mark.parametrize('unresolved', [None, 'missing'], ids=['none', 'missing'])
def test_malformed_need_before_coverage_fails_closed_without_admission(
    malformed_need, requirements, unresolved, monkeypatch,
):
    proposal, capture = make_request()
    proposal['needs'].insert(0, copy.deepcopy(malformed_need))
    coverage = proposal['approaches'][0]['coverage'][0]
    coverage['requirements'] = copy.deepcopy(requirements)
    coverage['unresolved'] = unresolved
    before = copy.deepcopy((proposal, capture))
    counts = spy_high_level_operations(monkeypatch)

    result = raw_intake.evaluate_proposal(proposal, capture)

    assert set(result) == {
        'contract', 'kind', 'authorizing', 'can_execute',
        'primary_diagnostic', 'diagnostics',
    }
    assert result['kind'] == 'invalid_invocation'
    assert result['authorizing'] is result['can_execute'] is False
    assert counts == {
        '_compile_assessment': 1,
        '_admit_assessment': 0,
        '_evaluate_admitted_assessment': 0,
    }
    assert (proposal, capture) == before


def test_high_level_compiler_is_stateless_and_effect_free(monkeypatch):
    first_proposal, first_capture = make_request()
    second_proposal, second_capture = copy.deepcopy((first_proposal, first_capture))
    before = copy.deepcopy((first_proposal, first_capture))

    def forbidden(*args, **kwargs):
        raise AssertionError('High-level compiler crossed the pure boundary')

    for module, name in (
        (builtins, 'open'),
        (Path, 'read_bytes'),
        (Path, 'read_text'),
        (Path, 'resolve'),
        (socket, 'socket'),
        (socket, 'create_connection'),
        (subprocess, 'run'),
        (subprocess, 'Popen'),
    ):
        monkeypatch.setattr(module, name, forbidden)
    first = raw_intake.evaluate_proposal(first_proposal, first_capture)
    second = raw_intake.evaluate_proposal(second_proposal, second_capture)
    assert first == second
    assert (first_proposal, first_capture) == before
    assert (second_proposal, second_capture) == before


def test_public_assessment_owns_one_admission_and_evaluation(supplied_case, monkeypatch):
    counts = spy_owned_operations(monkeypatch)
    before = copy.deepcopy(supplied_case)
    assert raw_intake.evaluate_assessment(supplied_case)['outcome'] == 'eligible'
    assert counts == _expected_owned_counts(supplied_case)
    assert supplied_case == before


def test_cli_assessment_owns_one_admission_and_evaluation(supplied_case, monkeypatch):
    counts = spy_owned_operations(monkeypatch)
    assert raw_cli.main(io.BytesIO(json.dumps(supplied_case).encode()), io.StringIO()) == 0
    assert counts == _expected_owned_counts(supplied_case)


def test_invalid_input_never_reaches_admitted_spine(supplied_case, monkeypatch):
    del supplied_case['contract']
    counts = spy_owned_operations(monkeypatch)
    assert raw_intake.evaluate_assessment(supplied_case)['kind'] == 'invalid_invocation'
    assert counts['_admit_assessment'] == 1
    assert all(value == 0 for name, value in counts.items() if name != '_admit_assessment')


def test_result_handoff_is_readmitted_not_trusted(supplied_case, monkeypatch):
    result = raw_intake.evaluate_assessment(supplied_case)
    result['outcome'] = 'eligible'
    counts = spy_owned_operations(monkeypatch)
    assert raw_intake.evaluate_assessment(result)['kind'] == 'invalid_invocation'
    assert counts['_admit_assessment'] == 1
    assert all(value == 0 for name, value in counts.items() if name != '_admit_assessment')


@pytest.mark.parametrize('mutation', ['positive', 'current', 'hold', 'mismatch', 'missing', 'invalid', 'version'])
def test_forbidden_host_and_retired_calls_never_reached(mutation, monkeypatch):
    case = make_case()
    if mutation == 'current':
        case['needs'][0]['current_relation_ids'] = ['present']
    elif mutation == 'hold':
        case['host']['policy']['ready'] = False
    elif mutation == 'mismatch':
        case['host']['target_binding']['id'] = 'other'
    elif mutation == 'missing':
        case['citations'] = []
    elif mutation == 'invalid':
        case['candidate']['question'] = []
    elif mutation == 'version':
        case['contract'] = 'rerg-foundation/2'
    modules = {
        name: importlib.import_module('rerg.' + name)
        for name in RETIRED
    }
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError('Forbidden acquisition/evaluator path')

    with pytest.raises(AssertionError):
        forbidden()
    calls.clear()
    for name in HOST_SURFACES:
        monkeypatch.setattr(path_query, name, forbidden)
    monkeypatch.setattr(raw_intake, '_adoption_time', forbidden)
    for name, names in RETIRED.items():
        for symbol in names:
            assert not hasattr(modules[name], symbol)
            monkeypatch.setattr(modules[name], symbol, forbidden, raising=False)
    for module, symbol in (
        (builtins, 'open'), (Path, 'read_bytes'), (Path, 'read_text'),
        (Path, 'resolve'), (socket, 'socket'), (socket, 'create_connection'),
        (subprocess, 'run'), (subprocess, 'Popen'),
    ):
        monkeypatch.setattr(module, symbol, forbidden)
    before = copy.deepcopy(case)
    result = raw_intake.evaluate_assessment(case)
    assert raw_intake.canonical_result_bytes(result)
    assert render.render_assessment_markdown(result)
    output = io.StringIO()
    assert raw_cli.main(io.BytesIO(json.dumps(case).encode()), output) == (
        2 if result['kind'] == 'invalid_invocation' else 0
    )
    assert case == before and not calls


def test_serialization_and_render_are_projection_only(supplied_case, monkeypatch):
    result = raw_intake.evaluate_assessment(supplied_case)
    expected = raw_intake.canonical_result_bytes(result)

    def forbidden(*args, **kwargs):
        raise AssertionError('Output crossed the pure serialization boundary')

    for module, name in (
        (builtins, 'open'), (Path, 'read_bytes'), (Path, 'read_text'),
        (socket, 'socket'), (subprocess, 'run'), (subprocess, 'Popen'),
        (raw_intake, 'evaluate_assessment'),
        (raw_intake, '_evaluate_admitted_assessment'),
        (raw_derivation, '_admit_assessment'),
        (path_query, '_evaluate_source_relation'),
        (path_query, '_resolve_citation_reference'),
    ):
        monkeypatch.setattr(module, name, forbidden)
    before = copy.deepcopy(result)
    assert raw_intake.canonical_result_bytes(result) == expected
    assert render.render_assessment_markdown(result).startswith('# RERG non-authorizing packet')
    assert result == before


def test_high_level_publication_does_not_reenter_assessment(monkeypatch):
    proposal, capture = make_request()
    result = raw_intake.evaluate_proposal(proposal, capture)
    expected = raw_intake.canonical_result_bytes(result)

    def forbidden(*args, **kwargs):
        raise AssertionError('Publication crossed the pure projection boundary')

    for module, name in (
        (raw_intake, 'evaluate_proposal'),
        (raw_intake, '_evaluate_admitted_assessment'),
        (raw_derivation, '_compile_assessment'),
        (raw_derivation, '_admit_assessment'),
        (path_query, '_evaluate_source_relation'),
        (path_query, '_resolve_citation_reference'),
    ):
        monkeypatch.setattr(module, name, forbidden)
    assert raw_intake.canonical_result_bytes(result) == expected
    assert render.render_assessment_markdown(result).startswith(
        '# RERG non-authorizing packet'
    )


def test_cli_argument_branch_does_not_read_or_assess(monkeypatch):
    class NoRead:
        def read(self, *args):
            raise AssertionError('argv branch read stdin')

    def forbidden(*args, **kwargs):
        raise AssertionError('argv branch assessed input')

    monkeypatch.setattr(raw_intake, 'evaluate_assessment', forbidden)
    output = io.StringIO()
    assert raw_cli.main(NoRead(), output, argv=['--help']) == 2
    assert json.loads(output.getvalue())['primary_diagnostic']['detail_code'] == 'INVOCATION_ARGUMENTS'


@pytest.mark.parametrize('kind', ['valid', 'decode_invalid', 'shape_invalid'])
def test_cli_bounded_stream_and_status_boundary(kind, supplied_case, monkeypatch):
    if kind == 'shape_invalid':
        del supplied_case['contract']
    payload = b'{' if kind == 'decode_invalid' else json.dumps(supplied_case).encode()
    reads = []

    class SuppliedStream(io.BytesIO):
        def read(self, size):
            reads.append(size)
            assert size == raw_cli.MAX_INPUT_BYTES + 1, 'CLI read must be bounded'
            return super().read(size)

    counts = spy_owned_operations(monkeypatch)
    output = io.StringIO()
    assert raw_cli.main(SuppliedStream(payload), output) == (0 if kind == 'valid' else 2)
    assert reads == [raw_cli.MAX_INPUT_BYTES + 1]
    packet = json.loads(output.getvalue())
    assert packet['kind'] == ('assessment' if kind == 'valid' else 'invalid_invocation')
    if kind == 'valid':
        assert counts == _expected_owned_counts(supplied_case)
    else:
        assert counts['_admit_assessment'] == (1 if kind == 'shape_invalid' else 0)
        assert all(value == 0 for name, value in counts.items() if name != '_admit_assessment')


def test_cli_unexpected_failure_has_fixed_status_and_stderr(monkeypatch):
    def broken(invocation):
        raise RuntimeError('private detail must not be emitted')

    monkeypatch.setattr(raw_intake, 'evaluate_assessment', broken)
    stderr, output = io.StringIO(), io.StringIO()
    monkeypatch.setattr(raw_cli.sys, 'stderr', stderr)
    assert raw_cli.main(io.BytesIO(json.dumps(make_case()).encode()), output) == 1
    assert output.getvalue() == ''
    assert stderr.getvalue() == 'RERG_INTERNAL_ERROR\n'


def test_renderer_presents_the_canonical_return_value(monkeypatch):
    marker = object()
    calls = []

    def canonical(value):
        calls.append(value)
        return b'<&@'

    monkeypatch.setattr(raw_intake, 'canonical_result_bytes', canonical)
    assert render.render_assessment_markdown(marker) == (
        '# RERG non-authorizing packet\n\n<pre>&lt;&amp;&#64;</pre>\n'
    )
    assert calls == [marker]


def _parse_sources(sources):
    assert tuple(sources) == CORE_MODULES, 'source census must remain the eight fixed modules'
    return {name: ast.parse(sources[name], filename=name + '.py') for name in CORE_MODULES}


def _function(tree, name):
    matches = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    assert len(matches) == 1, f'expected one {name} definition'
    return matches[0]


def _calls(node):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)]


def _call_target(call):
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return ast.unparse(call.func)
    return None


def _guard(tree):
    guards = []
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == '__name__'
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
        ):
            guards.append(node)
    assert len(guards) == 1, 'each executable module must have one exact name guard'
    return guards[0]


def _assert_forbidden_source_edges(trees):
    forbidden_names = {
        'getattr', 'setattr', 'hasattr', 'globals', 'locals', 'vars', 'dir',
        '__getattribute__', '__getattr__', '__setattr__', '__delattr__', '__dir__',
        'eval', 'exec', 'compile', '__import__', 'import_module', 'open',
        'input', 'breakpoint', 'getenv', 'environ', 'getpass',
        'credential', 'credentials', 'repository_target_adapter',
        'git_worktree_inventory', 'source_parser', 'workspace_scan',
    }
    forbidden_modules = {
        'importlib', 'repository_target_adapter', 'git_worktree_inventory',
        'source_parser', 'workspace_scan', 'os', 'subprocess', 'socket',
        'requests', 'urllib', 'http', 'ssl', 'keyring', 'boto3', 'botocore',
    }
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert node.id not in forbidden_names, f'forbidden name {node.id}'
            elif isinstance(node, ast.Attribute):
                assert node.attr not in forbidden_names or ast.unparse(node) == 're.compile', (
                    f'forbidden attribute {node.attr}'
                )
            elif isinstance(node, ast.Import):
                assert not any(
                    part in forbidden_modules
                    for alias in node.names
                    for part in alias.name.split('.')
                ), 'forbidden import'
                assert not any(
                    alias.asname in forbidden_names
                    for alias in node.names
                ), 'forbidden import alias'
            elif isinstance(node, ast.ImportFrom):
                assert not forbidden_modules.intersection((node.module or '').split('.')), 'forbidden import'
                assert not any(
                    alias.name in forbidden_names or alias.asname in forbidden_names
                    for alias in node.names
                ), 'forbidden import alias'


def _assert_designated_spine(trees):
    for symbol, owner in (
        ('_compile_assessment', 'raw_derivation'),
        ('_compile_assessment_validated', 'raw_derivation'),
        ('_admit_assessment', 'raw_derivation'),
        ('_evaluate_admitted_assessment', 'raw_intake'),
        ('evaluate_proposal', 'raw_intake'),
    ):
        definitions = [
            module for module, tree in trees.items() for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == symbol
        ]
        assert definitions == [owner], f'one designated {symbol} definition'
    intake = trees['raw_intake']
    evaluator = _function(intake, 'evaluate_assessment')
    direct = [_call_target(call) for call in _calls(evaluator)]
    assert direct == ['raw_derivation._admit_assessment', '_evaluate_admitted_assessment'], (
        'assessment must call admission once, then only its designated evaluator'
    )
    admission = next(
        statement for statement in evaluator.body
        if isinstance(statement, ast.Assign)
        and isinstance(statement.value, ast.Call)
        and _call_target(statement.value) == 'raw_derivation._admit_assessment'
    )
    assert isinstance(admission.targets[0], ast.Tuple)
    assert [item.id for item in admission.targets[0].elts] == ['admitted', 'invalid']
    assert [ast.unparse(arg) for arg in admission.value.args] == ['invocation']
    assert not admission.value.keywords
    branch = next(statement for statement in evaluator.body if isinstance(statement, ast.If))
    assert ast.unparse(branch.test) == 'invalid is not None'
    assert len(branch.body) == 1 and isinstance(branch.body[0], ast.Return)
    assert ast.unparse(branch.body[0].value) == 'invalid'
    assert not branch.orelse
    tail = evaluator.body[evaluator.body.index(branch) + 1:]
    assert len(tail) == 1 and isinstance(tail[0], ast.Return)
    assert ast.unparse(tail[0].value) == '_evaluate_admitted_assessment(admitted)'

    proposal_evaluator = _function(intake, 'evaluate_proposal')
    assert [argument.arg for argument in proposal_evaluator.args.posonlyargs] == [
        'proposal', 'capture',
    ]
    assert not proposal_evaluator.args.args and not proposal_evaluator.args.kwonlyargs
    documentation = ast.get_docstring(proposal_evaluator).lower()
    assert 'pure' in documentation
    assert 'non-authorizing' in documentation
    assert 'closed invalid-invocation envelope' in documentation
    direct = [_call_target(call) for call in _calls(proposal_evaluator)]
    assert direct == ['raw_derivation._compile_assessment', '_evaluate_admitted_assessment'], (
        'high-level assessment must compile once, then only its designated evaluator'
    )
    compilation = next(
        statement for statement in proposal_evaluator.body
        if isinstance(statement, ast.Assign)
        and isinstance(statement.value, ast.Call)
        and _call_target(statement.value) == 'raw_derivation._compile_assessment'
    )
    assert isinstance(compilation.targets[0], ast.Tuple)
    assert [item.id for item in compilation.targets[0].elts] == ['admitted', 'invalid']
    assert [ast.unparse(arg) for arg in compilation.value.args] == ['proposal', 'capture']
    assert not compilation.value.keywords
    proposal_branch = next(
        statement for statement in proposal_evaluator.body if isinstance(statement, ast.If)
    )
    assert ast.unparse(proposal_branch.test) == 'invalid is not None'
    assert len(proposal_branch.body) == 1 and isinstance(proposal_branch.body[0], ast.Return)
    assert ast.unparse(proposal_branch.body[0].value) == 'invalid'
    assert not proposal_branch.orelse
    proposal_tail = proposal_evaluator.body[proposal_evaluator.body.index(proposal_branch) + 1:]
    assert len(proposal_tail) == 1 and isinstance(proposal_tail[0], ast.Return)
    assert ast.unparse(proposal_tail[0].value) == '_evaluate_admitted_assessment(admitted)'

    compiler = _function(trees['raw_derivation'], '_compile_assessment')
    compiler_targets = {_call_target(call) for call in _calls(compiler)}
    assert not compiler_targets & {
        'path_query._evaluate_source_relation',
        'path_query._resolve_citation_reference',
        '_evaluate_source_relation',
        '_resolve_citation_reference',
    }, 'compiler must not evaluate or resolve supplied source predicates'
    assert not any(
        _call_target(call) == '_admit_assessment' for call in _calls(compiler)
    ), 'compiler wrapper must not duplicate admission'
    compiler_helpers = [
        call for call in _calls(compiler)
        if _call_target(call) == '_compile_assessment_validated'
    ]
    assert len(compiler_helpers) == 1
    assert [ast.unparse(arg) for arg in compiler_helpers[0].args] == ['proposal', 'capture']
    validated = _function(trees['raw_derivation'], '_compile_assessment_validated')
    validated_targets = {_call_target(call) for call in _calls(validated)}
    assert not validated_targets & {
        'path_query._evaluate_source_relation',
        'path_query._resolve_citation_reference',
    }, 'compiler must not evaluate or resolve supplied source predicates'
    compiler_calls = [
        call for call in _calls(validated)
        if _call_target(call) == '_admit_assessment'
    ]
    assert len(compiler_calls) == 1
    assert len(compiler_calls[0].args) == 1
    assert ast.unparse(compiler_calls[0].args[0]) == 'invocation'
    assert [keyword.arg for keyword in compiler_calls[0].keywords] == ['diagnostic_paths']
    assert ast.unparse(compiler_calls[0].keywords[0].value) == 'prov'

    callers = []
    spine_targets = {
        'raw_derivation._compile_assessment', '_compile_assessment',
        'raw_derivation._compile_assessment_validated', '_compile_assessment_validated',
        'raw_derivation._admit_assessment', '_admit_assessment',
        'raw_intake._evaluate_admitted_assessment',
        '_evaluate_admitted_assessment',
    }
    for module, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in _calls(node):
                target = _call_target(call)
                if target in spine_targets:
                    callers.append((module, node.name, target))
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            statements = (
                statement.body
                if isinstance(statement, ast.ClassDef)
                else (statement,)
            )
            for initializer in statements:
                if isinstance(initializer, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for call in _calls(initializer):
                    target = _call_target(call)
                    if target in spine_targets:
                        callers.append((module, '<module>', target))
    assert callers == [
        ('raw_intake', 'evaluate_assessment', 'raw_derivation._admit_assessment'),
        ('raw_intake', 'evaluate_assessment', '_evaluate_admitted_assessment'),
        ('raw_intake', 'evaluate_proposal', 'raw_derivation._compile_assessment'),
        ('raw_intake', 'evaluate_proposal', '_evaluate_admitted_assessment'),
        ('raw_derivation', '_compile_assessment', '_compile_assessment_validated'),
        ('raw_derivation', '_compile_assessment_validated', '_admit_assessment'),
    ], 'no alternate direct compiler/admission/evaluator caller is covered'


def _assert_root_delegation(trees):
    init = trees['__init__']
    imports = {
        (node.module, alias.name, alias.asname)
        for node in init.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert imports == {
        ('raw_intake', 'evaluate_assessment', None),
        ('raw_intake', 'evaluate_proposal', None),
        ('raw_intake', 'canonical_result_bytes', None),
        ('render', 'render_assessment_markdown', None),
    }, 'public exports must remain the four designated APIs'
    exported = next(node for node in init.body if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == '__all__' for target in node.targets
    ))
    assert ast.literal_eval(exported.value) == (
        'evaluate_assessment', 'evaluate_proposal', 'canonical_result_bytes',
        'render_assessment_markdown'
    )
    assert set(PUBLIC_ROOTS) == {
        'rerg.evaluate_assessment',
        'rerg.evaluate_proposal',
        'rerg.canonical_result_bytes',
        'rerg.render_assessment_markdown',
        'python -m rerg',
        'python -m rerg.raw_cli',
    }

    canonical = _function(trees['raw_intake'], 'canonical_result_bytes')
    canonical_calls = {_call_target(call) for call in _calls(canonical)}
    assert not canonical_calls & {
        'evaluate_assessment', 'raw_intake.evaluate_assessment',
        'evaluate_proposal', 'raw_intake.evaluate_proposal',
        '_evaluate_admitted_assessment', 'raw_derivation._admit_assessment',
        'raw_derivation._compile_assessment', '_compile_assessment',
        'path_query._evaluate_source_relation',
        'path_query._resolve_citation_reference',
    }, 'serialization cannot re-enter assessment or supplied-byte resolution'

    renderer = _function(trees['render'], 'render_assessment_markdown')
    render_calls = [_call_target(call) for call in _calls(renderer)]
    assert render_calls.count('raw_intake.canonical_result_bytes') == 1, (
        'renderer must delegate exactly once to canonical_result_bytes'
    )
    assert not any(target in {
        'evaluate_assessment', 'raw_intake.evaluate_assessment',
        'evaluate_proposal', 'raw_intake.evaluate_proposal',
        '_evaluate_admitted_assessment', 'raw_derivation._admit_assessment',
        'raw_derivation._compile_assessment', '_compile_assessment',
        'path_query._evaluate_source_relation',
        'path_query._resolve_citation_reference',
    } for target in render_calls)

    cli = _function(trees['raw_cli'], 'main')
    cli_calls = [_call_target(call) for call in _calls(cli)]
    assert cli_calls.count('raw_intake.evaluate_assessment') == 1, (
        'CLI must delegate exactly once to evaluate_assessment'
    )
    assert cli_calls.count('raw_intake.canonical_result_bytes') == 1, (
        'CLI must serialize exactly once through canonical_result_bytes'
    )
    assert cli_calls.count('_decode') == 1
    assert cli_calls.count('destination.write') == 1
    assert cli_calls.count('sys.stderr.write') == 1
    reads = [call for call in _calls(cli) if _call_target(call) == 'source.read']
    assert len(reads) == 1 and len(reads[0].args) == 1
    assert ast.unparse(reads[0].args[0]) == 'MAX_INPUT_BYTES + 1'
    statuses = [
        node.value for node in ast.walk(cli) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'status' for target in node.targets)
    ]
    assert len(statuses) == 1 and ast.unparse(statuses[0]) == (
        "2 if result['kind'] == 'invalid_invocation' else 0"
    ), 'CLI status must distinguish invalid from admitted results'
    assert any(
        isinstance(node, ast.Constant) and node.value == 'RERG_INTERNAL_ERROR' + chr(10)
        for node in ast.walk(cli)
    ), 'unexpected CLI failures retain fixed stderr reporting'

    for module in ('__main__', 'raw_cli'):
        guard = _guard(trees[module])
        assert guard.test.comparators[0].value == '__main__', (
            'module guard must compare __name__ with __main__'
        )
        assert len(guard.body) == 1 and isinstance(guard.body[0], ast.Raise)
        raised = guard.body[0].exc
        assert isinstance(raised, ast.Call) and _call_target(raised) == 'SystemExit'
        assert len(raised.args) == 1 and ast.unparse(raised.args[0]) == 'main(argv=sys.argv[1:])'


def check_pure_sources(sources):
    """Check concrete ownership seams without claiming a general Python proof."""
    trees = _parse_sources(sources)
    _assert_forbidden_source_edges(trees)
    _assert_designated_spine(trees)
    _assert_root_delegation(trees)


def source_bundle():
    return {
        name: (ROOT / 'rerg' / (name + '.py')).read_text()
        for name in CORE_MODULES
    }


def test_no_retired_host_or_second_evaluator_subgraph():
    check_pure_sources(source_bundle())


@pytest.mark.parametrize('injection', [
    '\ndef alternate(x):\n    return _evaluate_admitted_assessment(x)\n',
    '\ndef alternate(x):\n    return raw_derivation._admit_assessment(x)\n',
    '\ndef alternate(proposal, capture):\n    return raw_derivation._compile_assessment(proposal, capture)\n',
    '\nfrom repository_target_adapter import adapt_repository_target\n',
    '\ndef alternate(x):\n    return getattr(x, "evaluator")()\n',
])
def test_bounded_static_checker_rejects_known_unsafe_mutations(injection):
    sources = source_bundle()
    check_pure_sources(sources)
    sources['raw_intake'] += injection
    expected = (
        'forbidden import' if 'repository_target_adapter' in injection
        else 'forbidden name getattr' if 'getattr' in injection
        else 'no alternate direct compiler/admission/evaluator caller is covered'
    )
    with pytest.raises(AssertionError, match=expected):
        check_pure_sources(sources)


@pytest.mark.parametrize('injection', [
    '\nimport os\n',
    '\nfrom os import getenv\n',
    '\nimport subprocess as runner\n',
    '\nfrom socket import socket as connect\n',
])
def test_bounded_static_checker_rejects_effectful_imports(injection):
    sources = source_bundle()
    check_pure_sources(sources)
    sources['raw_intake'] += injection
    with pytest.raises(AssertionError, match='forbidden import'):
        check_pure_sources(sources)


def test_checker_rejects_designated_spine_bypass():
    sources = source_bundle()
    check_pure_sources(sources)
    sources['raw_intake'] = sources['raw_intake'].replace(
        'return _evaluate_admitted_assessment(admitted)',
        "return {'outcome': 'eligible'}",
    )
    with pytest.raises(AssertionError, match='assessment must call admission once'):
        check_pure_sources(sources)


def test_checker_rejects_high_level_spine_bypass():
    sources = source_bundle()
    check_pure_sources(sources)
    prefix, separator, suffix = sources['raw_intake'].partition(
        '\ndef evaluate_proposal'
    )
    assert separator
    suffix = suffix.replace(
        'return _evaluate_admitted_assessment(admitted)',
        "return {'outcome': 'eligible'}",
        1,
    )
    sources['raw_intake'] = prefix + separator + suffix
    with pytest.raises(AssertionError, match='high-level assessment must compile once'):
        check_pure_sources(sources)


def test_checker_rejects_cli_delegation_mutation():
    sources = source_bundle()
    check_pure_sources(sources)
    sources['raw_cli'] = sources['raw_cli'].replace(
        'raw_intake.evaluate_assessment(invocation)',
        'raw_intake.canonical_result_bytes(invocation)',
    )
    with pytest.raises(AssertionError, match='CLI must delegate exactly once to evaluate_assessment'):
        check_pure_sources(sources)


def test_checker_rejects_cli_status_mutation():
    sources = source_bundle()
    check_pure_sources(sources)
    sources['raw_cli'] = sources['raw_cli'].replace(
        "status = 2 if result['kind'] == 'invalid_invocation' else 0",
        "status = 0 if result['kind'] == 'invalid_invocation' else 2",
    )
    with pytest.raises(AssertionError, match='CLI status must distinguish'):
        check_pure_sources(sources)


def test_checker_rejects_renderer_delegation_mutation():
    sources = source_bundle()
    check_pure_sources(sources)
    sources['render'] = sources['render'].replace(
        'raw_intake.canonical_result_bytes(result)',
        'raw_intake.evaluate_assessment(result)',
    )
    with pytest.raises(AssertionError, match='canonical_result_bytes'):
        check_pure_sources(sources)


def test_checker_rejects_module_guard_mutation():
    sources = source_bundle()
    check_pure_sources(sources)
    sources['__main__'] = sources['__main__'].replace(
        'if __name__ == "__main__":',
        'if __name__ == "__not_main__":',
    )
    with pytest.raises(AssertionError, match='__main__'):
        check_pure_sources(sources)


@pytest.mark.parametrize('name', ['engine', 'query', 'fake_transport', 'primitive_map', 'hermes_adapter', 'dependency_discovery', 'contracts', 'validator'])
def test_legacy_and_generic_runtime_modules_remain_absent(name):
    assert importlib.util.find_spec('rerg.' + name) is None
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module('rerg.' + name)


@pytest.mark.parametrize('name', ['render_mermaid', 'render_markdown', 'render_discord_card'])
def test_packet_only_rendering_remains_absent(name):
    assert not hasattr(render, name)


@pytest.mark.parametrize('name', ['load_schema', 'schema_registry', 'validate_artifact', 'validate_fixture_cases'])
def test_no_generic_contract_callable(name):
    import rerg
    assert not hasattr(rerg, name) and name not in rerg.__all__


@pytest.mark.parametrize('name', ['operator-request', 'operator-result', 'capability-path-graph'])
def test_archived_schema_does_not_restore_runtime_contract(name):
    assert (ROOT / 'schemas/rerg' / (name + '.schema.json')).is_file()
    output = io.StringIO()
    assert raw_cli.main(
        io.BytesIO(json.dumps({'schema_version': 'rerg/v1', 'artifact_type': name}).encode()),
        output,
    ) == 2
    assert json.loads(output.getvalue())['kind'] == 'invalid_invocation'
