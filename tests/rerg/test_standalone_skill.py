"""Skill-source coherence checks, not native invoking-harness behavior proof."""
from pathlib import Path


def test_local_skill_uses_ordinary_surface_and_correct_result_identity():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'skills/rerg/SKILL.md').read_text()
    assert 'evaluate_proposal(proposal, capture)' in text
    assert 'python3 -m rerg.assessment_cli' in text
    assert 'rerg-assess' in text
    assert 'rerg_assess' not in text
    assert 'input.host.local_path_policy' in text
    assert 'source_present' in text and 'source_equals' in text and 'source_same' in text
    assert 'secrets remain' in text and 'unconditionally rejected' in text
    assert 'authorizing=false' in text and 'can_execute=false' in text
    assert 'not installed' in text or 'not an installed' in text
    assert 'non-canonical' in text
    for outcome in ('eligible', 'no_change', 'defer', 'reject', 'needs_more_facts'):
        assert outcome in text


def test_live_workflow_declares_standalone_scope_without_new_evaluator():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'docs/rerg-adoption-workflow.md').read_text()
    assert 'from rerg import evaluate_proposal' in text
    assert 'python3 -m rerg.assessment_cli' in text
    assert 'rerg_assess' not in text
    normalized = ' '.join(text.split())
    assert 'byte predicates' in normalized or 'byte-predicate' in normalized
    assert 'ASSESSMENT_SCHEMA' in text and 'INVOCATION_SCHEMA' in text
    assert 'not' in text and 'product completion' in text
