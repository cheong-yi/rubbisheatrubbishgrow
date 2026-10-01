"""Host acquisition stays separate from synthetic foundation assessment."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from rerg import raw_intake
from rerg.repository_target_adapter import adapt_repository_target
from test_supplied_admission import make_case, make_request

NOW = '2026-09-01T00:00:00.000000Z'


def _search_recipe():
    text = (Path(__file__).parents[2] / 'docs/rerg-adoption-workflow.md').read_text()
    marker = '```python\n# bounded-followup-search'
    assert marker in text, 'Executable bounded host search recipe is missing'
    source = '# bounded-followup-search' + text.split(marker, 1)[1].split('```', 1)[0]
    namespace = {}
    exec(compile(source, '<workflow-bounded-search>', 'exec'), namespace)
    return namespace


@pytest.fixture
def captured_case():
    # A new synthetic source invocation, not a conversion of adapter receipts.
    return make_case()


def rebind(case):
    for artifact in case['artifacts']:
        artifact['representation_sha256'] = hashlib.sha256(artifact['data'].encode()).hexdigest()
    by_id = {artifact['id']: artifact for artifact in case['artifacts']}
    for citation in case['citations']:
        artifact = by_id.get(citation['artifact_id'])
        if artifact is not None:
            citation['representation_sha256'] = artifact['representation_sha256']
    case['host']['limits']['decoded_bytes'] = sum(len(artifact['data'].encode()) for artifact in case['artifacts'])
    case['host']['limits']['artifact_count'] = len(case['artifacts'])
    return case


def alternatives(case, count=2):
    original = case['approaches'][0]
    case['approaches'] = [dict(copy.deepcopy(original), id='route-' + str(index)) for index in range(count)]
    return case


@pytest.fixture
def host_case(tmp_path):
    # Actual host receipt setup is local to acquisition tests, never an RERG input.
    subprocess.run(['git', 'init', '-q'], cwd=tmp_path, check=True)
    subprocess.run(['git', '-c', 'user.name=RERG Test', '-c', 'user.email=rerg@example.invalid', 'commit', '--allow-empty', '-qm', 'test-owned root'], cwd=tmp_path, check=True)
    (tmp_path / 'inspect.ts').write_text('export function inspect(value: string) { return value.length; }\n')
    question = 'Can the existing inspection function provide string length without executing input?'
    statement = 'Inspect a string and return its length without executing the string.'
    context = {'target': 'test-product@1', 'load_bearing_needs': [{'need_id': 'length', 'statement': statement}]}
    collected = adapt_repository_target(target_context=context, target_repository_root=tmp_path, question=question, now=NOW)
    return {'target_capture': {'target': 'test-product@1', 'binding': collected['receipt'], 'passages': collected['passages'], 'failures': collected['failures']}, 'request': {'question': question}, 'controller_envelope': {'inferred_needs_constraints': [{'need_id': 'length', 'statement': statement, 'load_bearing': True}]}, 'now': NOW}


def _collect_for_case(root, case, paths):
    context = {'target': case['target_capture']['target'], 'load_bearing_needs': [{'need_id': item['need_id'], 'statement': item['statement']} for item in case['controller_envelope']['inferred_needs_constraints'] if item['load_bearing']]}
    arguments = dict(target_context=context, target_repository_root=root, question=case['request']['question'], now=case['now'])
    prior = adapt_repository_target(**arguments)
    final = adapt_repository_target(**arguments, followup={'prior_receipt': prior['receipt'], 'missing_fact': 'Which additional implementation supports this behavior?', 'need_ids': ['length'], 'paths': paths})
    case['target_capture'].update(binding=final['receipt'], passages=final['passages'], failures=final['failures'])
    return prior, final


def test_compiler_keeps_requested_and_captured_surfaces_independent():
    proposal, capture = make_request()
    proposal['target']['surface'] = 'installed_runtime'
    capture['target']['surface'] = 'repository_snapshot'
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['kind'] == 'assessment'
    assert result['outcome'] == 'reject'
    assert result['primary_reason'] == 'TARGET_IDENTITY_MISMATCH'
    assert result['input']['target']['surface'] == 'installed_runtime'
    assert result['input']['host']['target_binding']['surface'] == 'repository_snapshot'


def test_static_producer_identity_is_preserved_without_runtime_proof():
    proposal, capture = make_request()
    proposal['needs'][0]['current_requirements'] = []
    capture['target']['surface'] = 'repository_snapshot'
    proposal['target']['surface'] = 'repository_snapshot'
    capture['artifacts'][0].update(
        source_identity='static-producer/revision',
        source_version='rev-2026-09-01',
        source_sha256='f' * 64,
    )
    result = raw_intake.evaluate_proposal(proposal, capture)
    assert result['outcome'] == 'eligible'
    artifact = result['input']['artifacts'][0]
    assert artifact['source_identity'] == 'static-producer/revision'
    assert artifact['source_version'] == 'rev-2026-09-01'
    assert artifact['source_sha256'] == 'f' * 64
    assert 'no native-target feasibility' in result['claim_ceiling']


def test_workflow_executes_content_search_without_answer_bearing_filenames(tmp_path, host_case):
    (tmp_path / 'a.ts').write_text('export const unused = true;\n')
    body = 'export function inspect(value: string) { return value.length; }\n'
    (tmp_path / 'b.ts').write_text(body)
    question = host_case['request']['question']
    context = {'target': 'test-product@1', 'load_bearing_needs': [{'need_id': 'length', 'statement': host_case['controller_envelope']['inferred_needs_constraints'][0]['statement']}]}
    collected = adapt_repository_target(target_context=context, target_repository_root=tmp_path, question=question, now=NOW)
    assert 'b.ts' not in {p['source_path'] for p in collected['passages']}
    found = _search_recipe()['bounded_literal_search'](tmp_path, collected['receipt'], ['a.ts', 'b.ts'], ['value.length'], 'Inspect the two additional synthetic modules for the requested length API.')
    assert found['paths'] == ['b.ts'] and found['attempts'] == 2
    assert found['bytes'] == len(body.encode()) + len(b'export const unused = true;\n')
    assert 'value.length' not in json.dumps(found) and found['unsearched_count'] == 1
    final = adapt_repository_target(target_context=context, target_repository_root=tmp_path, question=question, now=NOW, followup={'prior_receipt': collected['receipt'], 'missing_fact': 'Additional implementation of the length API', 'need_ids': ['length'], 'paths': found['paths']})
    assert 'b.ts' in {p['source_path'] for p in final['passages']}
    # Acquisition output is deliberately not passed through a semantic adapter.
    assert raw_intake.evaluate_assessment(final)['kind'] == 'invalid_invocation'


@pytest.mark.parametrize('mutation,reason', [
    ('structure', 'FOLLOWUP_SOURCE'),
    ('total_bytes', 'FOLLOWUP_ACCOUNTING'),
    ('prior_time', 'FOLLOWUP_BINDING'),
    ('paths', 'FOLLOWUP_PATHS'),
])
def test_followup_receipt_revalidates_without_io_and_rejects_tampering(
    tmp_path, host_case, monkeypatch, mutation, reason,
):
    import builtins
    import socket
    from rerg.path_query import _validate_adapter_receipt, MapBindingError
    (tmp_path / 'z.ts').write_text('export function measure(value: string) { return value.length; }\n')
    _, final = _collect_for_case(tmp_path, host_case, ['z.ts'])
    arguments = dict(target='test-product@1', question=host_case['request']['question'], now=NOW, need_ids=['length'], statements=[host_case['controller_envelope']['inferred_needs_constraints'][0]['statement']])
    def no_io(*args, **kwargs): raise AssertionError('Receipt revalidation performed I/O')
    with monkeypatch.context() as spy:
        for module, name in [(builtins, 'open'), (Path, 'read_bytes'), (Path, 'resolve'), (subprocess, 'run'), (subprocess, 'check_output'), (socket, 'create_connection')]:
            spy.setattr(module, name, no_io)
        _validate_adapter_receipt(final['receipt'], **arguments)
        changed = copy.deepcopy(final['receipt'])
        changed['followup']['missing_fact'] = 'A bounded explanatory fact.'
        _validate_adapter_receipt(changed, **arguments)
        changed = copy.deepcopy(final['receipt'])
        followup = changed['followup']
        if mutation == 'structure': del followup['sources'][0]['language']
        elif mutation == 'total_bytes': followup['total_bytes'] += 1
        elif mutation == 'prior_time': followup['prior_receipt']['captured_at'] = '2027-01-01T00:00:00Z'
        else: followup['paths'] = ['../z.ts']
        with pytest.raises(MapBindingError) as caught:
            _validate_adapter_receipt(changed, **arguments)
        assert caught.value.reasons == (reason,)


def test_adapter_projection_rejects_changed_captured_bytes_preserves_matching_peer(
    tmp_path, host_case, monkeypatch,
):
    import builtins
    import socket
    from rerg import repository_target_adapter

    (tmp_path / 'inspect_peer.ts').write_text(
        'export function inspectPeer(value: string) { return value.length; }\n'
    )
    context = {
        'target': host_case['target_capture']['target'],
        'load_bearing_needs': [{
            'need_id': 'length',
            'statement': host_case['controller_envelope']['inferred_needs_constraints'][0]['statement'],
        }],
    }
    arguments = dict(
        target_context=context,
        target_repository_root=tmp_path,
        question=host_case['request']['question'],
        now=NOW,
    )
    matching = adapt_repository_target(**arguments)
    matching_paths = {item['source_path'] for item in matching['passages']}
    assert matching['failures'] == [] and matching_paths == {'inspect.ts', 'inspect_peer.ts'}

    original_projection = repository_target_adapter._captured_repository_passages
    projection_calls = []

    def corrupt_at_projection(receipt, captured_sources):
        projection_calls.append(True)
        source_paths = sorted(captured_sources)
        assert source_paths == ['inspect.ts', 'inspect_peer.ts']
        changed_path = source_paths[0]
        original_bytes = bytes(captured_sources[changed_path])
        changed_bytes = original_bytes.replace(b'length', b'width', 1)
        assert changed_bytes != original_bytes
        source_digest = next(
            source['sha256']
            for source in receipt['sources']
            if source['relative_posix_path'] == changed_path
        )
        assert source_digest == hashlib.sha256(original_bytes).hexdigest()
        assert hashlib.sha256(changed_bytes).hexdigest() != source_digest
        corrupted_sources = dict(captured_sources)
        corrupted_sources[changed_path] = changed_bytes

        def no_io(*args, **kwargs):
            raise AssertionError('captured-byte projection performed I/O')

        with monkeypatch.context() as spy:
            for module, name in [
                (builtins, 'open'),
                (Path, 'read_bytes'),
                (Path, 'resolve'),
                (subprocess, 'run'),
                (subprocess, 'check_output'),
                (socket, 'create_connection'),
            ]:
                spy.setattr(module, name, no_io)
            return original_projection(receipt, corrupted_sources)

    monkeypatch.setattr(
        repository_target_adapter,
        '_captured_repository_passages',
        corrupt_at_projection,
    )
    changed = adapt_repository_target(**arguments)
    assert projection_calls == [True]
    assert {item['source_path'] for item in changed['passages']} == {'inspect_peer.ts'}
    assert changed['failures'] == [{
        'code': 'SOURCE_CHANGED',
        'artifact_id': 'target:inspect.ts',
        'missing_fact': 'A safe source excerpt is unavailable.',
        'decision_blocked': 'Use of this source as implementation evidence.',
    }]


def test_explicit_empty_search_scope_is_no_evidence(tmp_path, host_case):
    ns = _search_recipe()
    def no_read(*args, **kwargs): pytest.fail('empty scope must not read source bytes')
    ns['_read_regular_source'] = no_read
    found = ns['bounded_literal_search'](tmp_path, host_case['target_capture']['binding'], [], ['value.length'], 'No additional files are in the explicitly selected scope.')
    assert found['paths'] == [] and found['failures'] == []
    assert found['bytes'] == 0 and found['attempts'] == 0 and found['unsearched_count'] == 1


def test_failed_followup_retains_capture_failure_without_synthetic_upgrade(tmp_path, host_case):
    (tmp_path / 'z.py').write_text("password = 'synthetic unsafe value'\n")
    _, final = _collect_for_case(tmp_path, host_case, ['z.py'])
    assert not final['receipt']['followup']['sources']
    assert final['failures'] and final['failures'][0]['missing_fact']
    assert 'synthetic unsafe value' not in json.dumps(final)
    assert raw_intake.evaluate_assessment(final)['kind'] == 'invalid_invocation'


@pytest.mark.parametrize('kind', ['queries', 'needle_bytes', 'path_count', 'scope', 'duplicate', 'excluded'])
def test_search_recipe_rejects_limits_before_read(tmp_path, host_case, kind):
    ns = _search_recipe()
    paths, needles, basis = ['inspect.ts'], ['return'], 'Whole one-file synthetic scope.'
    if kind == 'queries': needles = ['a'] * 5
    elif kind == 'needle_bytes': needles = ['é' * 129]
    elif kind == 'path_count': paths = ['inspect.ts'] * 129
    elif kind == 'scope': basis = ''
    elif kind == 'duplicate': paths *= 2
    else: paths = ['.env']
    def no_read(*args, **kwargs): pytest.fail('invalid scope was read')
    ns['_read_regular_source'] = no_read
    found = ns['bounded_literal_search'](tmp_path, host_case['target_capture']['binding'], paths, needles, basis)
    assert found['paths'] == [] and found['failures'] and found['attempts'] == 0


def test_search_recipe_charges_failed_read_and_stops(tmp_path, host_case):
    ns = _search_recipe()
    read = ns['_read_regular_source']
    def failed(root, path, budget):
        read(root, path, budget)
        raise ValueError('synthetic failure after bytes consumed')
    ns['_read_regular_source'] = failed
    found = ns['bounded_literal_search'](tmp_path, host_case['target_capture']['binding'], ['inspect.ts'], ['return'], 'Whole synthetic scope.')
    assert found['attempts'] == 1 and found['bytes'] == 8_388_608
    assert found['paths'] == [] and found['failures'] == ['SEARCH_READ_FAILED']


def test_search_recipe_checks_deadline_after_read(tmp_path, host_case, monkeypatch):
    ns = _search_recipe()
    clock = [0]
    monkeypatch.setattr(ns['time'], 'monotonic', lambda: clock[0])
    read = ns['_read_regular_source']
    def slow(root, path, budget):
        result = read(root, path, budget)
        clock[0] = 31
        return result
    ns['_read_regular_source'] = slow
    found = ns['bounded_literal_search'](tmp_path, host_case['target_capture']['binding'], ['inspect.ts'], ['return'], 'Whole synthetic scope.')
    assert found['bytes'] > 0 and found['paths'] == [] and found['failures'] == ['SEARCH_DEADLINE']


@pytest.mark.parametrize('kind', ['hits', 'output', 'bytes', 'symlink'])
def test_search_recipe_stops_at_remaining_boundaries(tmp_path, host_case, kind):
    if kind == 'hits':
        paths = [f'z{i}.py' for i in range(5)]
        for path in paths: (tmp_path / path).write_text('# needle\n')
    elif kind == 'output':
        paths = [f"{'z' * 180}{i}.py" for i in range(128)]
        for path in paths: (tmp_path / path).write_text('x=1\n')
    elif kind == 'bytes':
        paths = ['z.txt']
        (tmp_path / 'z.txt').write_bytes(b'x' * 8_388_609)
    else:
        paths = ['z.py']
        (tmp_path / 'z.py').write_text('x=1\n')
    prior, _ = _collect_for_case(tmp_path, host_case, [])
    if kind == 'symlink':
        (tmp_path / 'z.py').unlink()
        (tmp_path / 'z.py').symlink_to('inspect.ts')
    found = _search_recipe()['bounded_literal_search'](tmp_path, prior['receipt'], paths, ['needle'], 'Entire explicitly selected synthetic scope.')
    assert found['paths'] == [] and found['failures']
    assert len(json.dumps(found, ensure_ascii=False).encode('utf-8')) <= 16_384
    assert found['failures'][0] == {'hits': 'SEARCH_HIT_LIMIT', 'output': 'SEARCH_OUTPUT_LIMIT', 'bytes': 'SEARCH_READ_FAILED', 'symlink': 'SEARCH_READ_FAILED'}[kind]
    if kind == 'symlink': assert found['attempts'] == 1 and found['bytes'] == 8_388_608


def test_same_length_resealed_source_cannot_reuse_prior_result_binding(captured_case):
    result = raw_intake.evaluate_assessment(captured_case)
    changed = copy.deepcopy(result)
    changed['input']['artifacts'][0]['data'] = 'omega'
    rebind(changed['input'])
    with pytest.raises(raw_intake.AssessmentResultError): raw_intake.canonical_result_bytes(changed)
    captured_case['relations'][0].update(kind='source_equals', expected='alpha')
    captured_case['artifacts'][0]['data'] = 'omega'
    rejected = raw_intake.evaluate_assessment(rebind(captured_case))
    assert rejected['outcome'] == 'needs_more_facts' and rejected['survivors'] == []


def test_valid_source_excerpt_with_distinct_source_digest_is_not_behavior_proof(captured_case):
    captured_case['artifacts'][0]['source_sha256'] = 'f' * 64
    result = raw_intake.evaluate_assessment(captured_case)
    assert result['outcome'] == 'eligible'
    assert 'no native-target feasibility' in result['claim_ceiling']


def test_current_sufficiency_and_policy_holds_do_not_invent_recipes(captured_case):
    captured_case['needs'][0]['current_relation_ids'] = ['present']
    assert raw_intake.evaluate_assessment(captured_case)['outcome'] == 'no_change'
    captured_case['host']['policy']['ready'] = False
    result = raw_intake.evaluate_assessment(captured_case)
    assert result['outcome'] == 'defer' and result['survivors'] == []
    assert 'dogfood_recipe' not in result and 'minimal_safe_path' not in result


def test_no_burden_ranking_or_caller_authority(captured_case):
    case = alternatives(captured_case, 8)
    first = raw_intake.evaluate_assessment(case)
    case['approaches'].reverse()
    second = raw_intake.evaluate_assessment(case)
    assert raw_intake.canonical_result_bytes(first) == raw_intake.canonical_result_bytes(second)
    assert len(first['survivors']) == 8
    for field in ('declared_rank', 'winner', 'selected', 'score'):
        changed = copy.deepcopy(case)
        changed[field] = 'route-0'
        assert raw_intake.evaluate_assessment(changed)['kind'] == 'invalid_invocation'


def test_sanitization_labels_cannot_admit_secret_source(captured_case):
    captured_case['artifacts'][0]['data'] = "password = 'synthetic-test-sensitive-value'"
    result = raw_intake.evaluate_assessment(rebind(captured_case))
    assert result['kind'] == 'invalid_invocation'
    assert 'synthetic-test-sensitive-value' not in json.dumps(result)


@pytest.mark.parametrize('field', ['now', 'evaluation_time', 'retention', 'display', 'replay', 'dogfood_recipe'])
def test_retired_metadata_is_not_a_side_channel(captured_case, field):
    captured_case[field] = '2026-09-01T08:00:00+08:00'
    result = raw_intake.evaluate_assessment(captured_case)
    assert result['kind'] == 'invalid_invocation'
    assert '2026-09-01' not in json.dumps(result)





def test_publication_excludes_operational_archive():
    root = Path(__file__).resolve().parents[2]
    excluded = 'docs/rerg-fresh-harness-cold-start-plan.md'
    assert not (root / excluded).exists()
    manifest = json.loads((root / 'source-manifest.json').read_text())
    assert all(
        row['source'] != excluded and row['destination'] != excluded
        for row in manifest['files']
    )
    assert excluded not in (root / 'docs/rerg-adoption-workflow.md').read_text()

















@pytest.mark.parametrize('empty_current,outcome', [(False, 'no_change'), (True, 'eligible')])
def test_live_workflow_example_executes_new_public_contract(empty_current, outcome):
    text = (Path(__file__).resolve().parents[2] / 'docs/rerg-adoption-workflow.md').read_text()
    source = text.split('```python\n# high-level-assessment\n', 1)[1].split('```', 1)[0]
    proposal, capture = make_request()
    if empty_current:
        proposal['needs'][0]['current_requirements'] = []
    namespace = {'proposal': proposal, 'capture': capture}
    exec(compile(source, '<foundation-workflow>', 'exec'), namespace)
    assert namespace['result']['outcome'] == outcome
    assert namespace['canonical_packet'] == raw_intake.canonical_result_bytes(namespace['result'])
