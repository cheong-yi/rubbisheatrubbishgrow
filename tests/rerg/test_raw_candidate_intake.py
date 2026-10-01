"""A raw question never supplies answer authority or acquires target evidence."""
import builtins
import copy
import socket
import subprocess
from pathlib import Path

import pytest

from rerg import canonical_result_bytes, raw_derivation, raw_intake, safe_path
from test_supplied_admission import make_request, supplied_case


def _request():
    proposal, capture = make_request()
    return {"proposal": copy.deepcopy(proposal), "capture": copy.deepcopy(capture)}


def _compiled(request):
    admitted, invalid = raw_derivation._compile_assessment(
        request["proposal"], request["capture"]
    )
    assert invalid is None
    return admitted


def _evaluate(request):
    return raw_intake.evaluate_proposal(
        request["proposal"], request["capture"]
    )


def test_single_filter_receives_only_admitted_input(supplied_case, monkeypatch):
    calls = []
    original = safe_path._assess_routes
    def counted(invocation, relations):
        calls.append((invocation, relations))
        return original(invocation, relations)
    monkeypatch.setattr(safe_path, '_assess_routes', counted)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'eligible' and len(calls) == 1
    assert calls[0][0] == result['input'] and calls[0][1] == result['relation_results']
    for forbidden in ('capabilities', 'paths', 'rank', 'answer', 'winner', 'selected', 'score'):
        case = copy.deepcopy(supplied_case)
        case['candidate'][forbidden] = []
        rejected = raw_intake.evaluate_assessment(case)
        assert rejected['kind'] == 'invalid_invocation' and 'survivors' not in rejected
    assert len(calls) == 1


def test_duplicate_ids_are_invalid_but_declared_binding_conflict_is_admitted(supplied_case):
    duplicate = copy.deepcopy(supplied_case)
    duplicate['citations'].append(copy.deepcopy(duplicate['citations'][0]))
    assert raw_intake.evaluate_assessment(duplicate)['kind'] == 'invalid_invocation'
    supplied_case['artifacts'][0]['target_id'] = 'other'
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'reject' and result['primary_reason'] == 'TARGET_IDENTITY_MISMATCH'
    assert result['survivors'] == []


def test_raw_input_hash_binds_locator_and_source_bytes(supplied_case):
    original = raw_intake.evaluate_assessment(supplied_case)
    supplied_case['candidate']['locator'] = 'note:other'
    changed = raw_intake.evaluate_assessment(supplied_case)
    assert original['replay']['input_sha256'] != changed['replay']['input_sha256']
    supplied_case['artifacts'][0]['representation_sha256'] = '0' * 64
    assert raw_intake.evaluate_assessment(supplied_case)['primary_reason'] == 'CITATION_OR_HASH_COVERAGE_INSUFFICIENT'


def test_pure_assessment_cannot_acquire_or_select_a_target(supplied_case, monkeypatch):
    from rerg import repository_target_adapter, render
    before = copy.deepcopy(supplied_case)
    def forbidden(*args, **kwargs): raise AssertionError('Pure evaluator attempted host acquisition')
    for owner, name in [(repository_target_adapter, 'adapt_repository_target'), (builtins, 'open'), (Path, 'read_bytes'), (Path, 'read_text'), (subprocess, 'run'), (subprocess, 'Popen'), (socket, 'socket'), (socket, 'create_connection')]:
        monkeypatch.setattr(owner, name, forbidden)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'eligible'
    assert render.render_assessment_markdown(result)
    assert supplied_case == before and result['input']['target'] == supplied_case['target']


@pytest.mark.parametrize('root_kind', ['missing', 'symlink'])
def test_host_missing_or_linked_root_still_fails_closed(tmp_path, root_kind, supplied_case):
    from rerg.repository_target_adapter import adapt_repository_target
    target = tmp_path / 'missing'
    if root_kind == 'symlink':
        actual = tmp_path / 'real'
        actual.mkdir()
        target.symlink_to(actual, target_is_directory=True)
    captured = adapt_repository_target(target_context={'target': 'test-product@1', 'load_bearing_needs': [{'need_id': 'need', 'statement': 'Inspect source.'}]}, target_repository_root=target, question='Which source is present?', now='2026-09-01T00:00:00.000000Z')
    assert captured['receipt']['limitations'] == ['NO_LOCAL_SOURCE_ROOT']
    assert captured['passages'] == []
    # Independent mechanics fixture, not an adapter-receipt translation.
    supplied_case['artifacts'] = []
    supplied_case['view']['descriptors'][0]['state'] = 'missing'
    supplied_case['host']['limits'].update(decoded_bytes=0, artifact_count=0)
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == 'needs_more_facts' and result['survivors'] == []
    assert result['primary_reason'] == 'ADMITTED_VIEW_MISSING_FILE'


def test_external_locator_and_harness_labels_do_not_dispatch(supplied_case):
    supplied_case['candidate'].update(source_kind='url', locator='https://example.invalid/evidence')
    original = raw_intake.evaluate_assessment(supplied_case)
    supplied_case['target']['harness'] = 'another-opaque-harness'
    supplied_case['host']['target_binding']['harness'] = 'another-opaque-harness'
    result = raw_intake.evaluate_assessment(supplied_case)
    assert result['outcome'] == original['outcome'] == 'eligible'
    assert result['relation_results'] == original['relation_results']
    assert result['input']['target']['id'] == supplied_case['target']['id']


def test_high_level_compiler_evaluator_and_serializer_each_run_once(monkeypatch):
    request = _request()
    calls = {'compiler': 0, 'evaluate': 0, 'canonical': 0}
    original_compile = raw_derivation._compile_assessment
    original_evaluate = raw_intake._evaluate_admitted_assessment
    original_canonical = raw_intake.canonical_result_bytes

    def compile(proposal, capture):
        calls['compiler'] += 1
        return original_compile(proposal, capture)

    def evaluate(invocation):
        calls['evaluate'] += 1
        return original_evaluate(invocation)

    def canonical(result):
        calls['canonical'] += 1
        return original_canonical(result)

    monkeypatch.setattr(raw_derivation, '_compile_assessment', compile)
    monkeypatch.setattr(raw_intake, '_evaluate_admitted_assessment', evaluate)
    monkeypatch.setattr(raw_intake, 'canonical_result_bytes', canonical)
    result = _evaluate(request)
    assert result['kind'] == 'assessment'
    assert raw_intake.canonical_result_bytes(result)
    assert calls == {'compiler': 1, 'evaluate': 1, 'canonical': 1}


def test_high_level_result_matches_independent_low_level_result_and_canonical_bytes():
    request = _request()
    request['proposal']['needs'][0]['current_requirements'] = []
    high_level = _evaluate(request)
    low_level = raw_intake.evaluate_assessment(_compiled(request))
    assert high_level == low_level
    assert canonical_result_bytes(high_level) == canonical_result_bytes(low_level)


@pytest.mark.parametrize(
    'mutation, expected',
    [
        ('eligible', 'eligible'),
        ('no_change', 'no_change'),
        ('defer', 'defer'),
        ('reject', 'reject'),
        ('needs_more_facts', 'needs_more_facts'),
    ],
)
def test_high_level_all_five_outcomes(mutation, expected):
    request = _request()
    request['proposal']['needs'][0]['current_requirements'] = []
    if mutation == 'no_change':
        span = {'artifact_key': 'source', 'start_byte': 0, 'end_byte': 5}
        request['proposal']['needs'][0]['current_requirements'] = [
            {'kind': 'source_present', 'span': span}
        ]
    elif mutation == 'defer':
        request['capture']['host']['policy']['ready'] = False
    elif mutation == 'reject':
        request['capture']['target']['surface'] = 'installed_runtime'
    elif mutation == 'needs_more_facts':
        request['capture']['view']['descriptors'][0]['state'] = 'missing'
        request['capture']['artifacts'] = []
    result = _evaluate(request)
    assert result['outcome'] == expected


def test_high_level_invalid_request_is_admitted_as_diagnostic_envelope():
    request = _request()
    request['proposal']['candidate']['source_kind'] = 'invalid'
    result = _evaluate(request)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'INVALID_FIELD_VALUE'
    assert result['contract'] == raw_derivation.CONTRACT


def test_missing_coverage_gets_required_marker():
    request = _request()
    request['proposal']['needs'][0]['current_requirements'] = []
    request['proposal']['approaches'][0]['coverage'] = []
    result = _evaluate(request)
    assert result['kind'] == 'assessment'
    assert any(
        row.get('property') == 'missing_requirement'
        for row in result['gaps']
    )


def test_capture_target_surface_mismatch_is_rejected():
    request = _request()
    request['proposal']['needs'][0]['current_requirements'] = []
    request['capture']['target']['surface'] = 'installed_runtime'
    result = _evaluate(request)
    assert result['outcome'] == 'reject'
    assert result['primary_reason'] == 'TARGET_IDENTITY_MISMATCH'


def test_high_level_oversized_capture_fails_closed():
    request = _request()
    request['capture']['artifacts'][0]['data'] = 'a' * 4097
    result = _evaluate(request)
    assert result['kind'] == 'invalid_invocation'
    assert result['primary_diagnostic']['code'] == 'INVALID_ENCODING_OR_SIZE'


def test_high_level_input_is_immutable_and_stateless():
    request = _request()
    before = copy.deepcopy(request)
    first = _evaluate(request)
    first['input']['candidate']['locator'] = 'changed-outside-result'
    second = _evaluate(request)
    assert request == before
    assert second['input']['candidate']['locator'] == before['proposal']['candidate']['locator']


def test_high_level_invalid_privacy_does_not_echo_secret():
    request = _request()
    request['proposal']['candidate']['locator'] = "password = 'raw-private-marker'"
    request['proposal']['candidate']['source_kind'] = 'invalid'
    result = _evaluate(request)
    encoded = repr(result)
    assert 'raw-private-marker' not in encoded


def test_tampered_high_level_result_is_rejected_by_canonical_serializer():
    result = _evaluate(_request())
    result['outcome'] = 'reject'
    with pytest.raises(raw_intake.AssessmentResultError):
        canonical_result_bytes(result)
