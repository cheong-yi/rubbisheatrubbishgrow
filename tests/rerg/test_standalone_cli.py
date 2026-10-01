"""Ordinary standalone proposal transport; no host authentication claim."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from rerg import canonical_result_bytes, evaluate_proposal
from rerg import assessment_cli, raw_cli, raw_derivation
from test_supplied_admission import make_request


@pytest.mark.parametrize('mutation,outcome', [
    ('positive', 'eligible'), ('current', 'no_change'), ('hold', 'defer'),
    ('disallowed', 'reject'), ('missing', 'needs_more_facts'),
])
def test_proposal_cli_matches_library_and_foundation(mutation, outcome):
    proposal, capture = make_request()
    if mutation != 'current':
        proposal['needs'][0]['current_requirements'] = []
    if mutation == 'hold':
        capture['host']['policy']['ready'] = False
    elif mutation == 'disallowed':
        capture['host']['policy']['allowed'] = False
    elif mutation == 'missing':
        proposal['approaches'][0]['coverage'] = []
    record = {'proposal': proposal, 'capture': capture}
    before = copy.deepcopy(record)
    expected = evaluate_proposal(proposal, capture)
    assert expected['outcome'] == outcome
    output = io.StringIO()
    assert assessment_cli.main(io.BytesIO(json.dumps(record).encode()), output) == 0
    assert output.getvalue().encode() == canonical_result_bytes(expected) + b'\n'
    foundation = io.StringIO()
    assert raw_cli.main(io.BytesIO(json.dumps(expected['input']).encode()), foundation) == 0
    assert foundation.getvalue() == output.getvalue()
    assert record == before
    assert expected['authorizing'] is expected['can_execute'] is False


@pytest.mark.parametrize('data', [
    b'{}', b'[]', b'null', b'{"proposal":{},"capture":{},"extra":1}',
    b'{"proposal":{},"capture":{},"capture":{}}', b'\xff', b'{',
    b'[' * 33 + b']' * 33, b' ' * (raw_cli.MAX_INPUT_BYTES + 1),
])
def test_invalid_closed_transport(data):
    output = io.StringIO()
    assert assessment_cli.main(io.BytesIO(data), output) == 2
    result = json.loads(output.getvalue())
    assert result['kind'] == 'invalid_invocation'
    assert result['authorizing'] is result['can_execute'] is False


def test_argv_does_not_read_or_echo_and_console_retains_argv(monkeypatch):
    class Unreadable:
        def read(self, *_):
            raise AssertionError('argv must precede input')
    output = io.StringIO()
    assert assessment_cli.main(Unreadable(), output, argv=['private-argument']) == 2
    assert 'private-argument' not in output.getvalue()
    monkeypatch.setattr(sys, 'argv', ['rerg-assess', 'private-argument'])
    monkeypatch.setattr(sys, 'stdout', io.StringIO())
    assert assessment_cli.entrypoint() == 2


def test_io_failure_emits_fixed_error_only(capsys):
    class Broken:
        def read(self, *_):
            raise OSError('synthetic-private-detail')
    assert assessment_cli.main(Broken(), io.StringIO()) == 1
    assert capsys.readouterr().err == 'RERG_INTERNAL_ERROR\n'


def test_dispatch_calls_same_evaluator_once_without_acquisition(monkeypatch):
    import builtins
    import socket

    proposal, capture = make_request()
    source = io.BytesIO(json.dumps({'proposal': proposal, 'capture': capture}).encode())
    calls = []
    original = assessment_cli.raw_intake.evaluate_proposal

    def evaluate(*args):
        calls.append(copy.deepcopy(args))
        return original(*args)

    def forbidden(*args, **kwargs):
        raise AssertionError('unexpected acquisition')

    monkeypatch.setattr(assessment_cli.raw_intake, 'evaluate_proposal', evaluate)
    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    output = io.StringIO()
    assert assessment_cli.main(source, output) == 0
    assert calls == [(proposal, capture)]
    calls.clear()
    assert assessment_cli.main(io.BytesIO(b'{}'), io.StringIO()) == 2
    assert calls == []


def test_secret_is_rejected_without_echo():
    proposal, capture = make_request()
    capture['artifacts'][0]['data'] = 'password=synthetic-private-detail'
    output = io.StringIO()
    assert assessment_cli.main(
        io.BytesIO(json.dumps({'proposal': proposal, 'capture': capture}).encode()), output,
    ) == 2
    assert 'synthetic-private-detail' not in output.getvalue()
    assert json.loads(output.getvalue())['kind'] == 'invalid_invocation'


def test_module_cli_runs_from_independent_cwd(tmp_path):
    proposal, capture = make_request()
    root = Path(__file__).resolve().parents[2]
    bootstrap = (
        'import runpy,sys;sys.path.insert(0,sys.argv[1]);'
        'sys.argv=["rerg.assessment_cli"];'
        'runpy.run_module("rerg.assessment_cli",run_name="__main__")'
    )
    result = subprocess.run(
        [sys.executable, '-I', '-S', '-B', '-c', bootstrap, str(root)],
        input=json.dumps({'proposal': proposal, 'capture': capture}).encode(),
        capture_output=True, cwd=tmp_path, timeout=30,
    )
    assert result.returncode == 0 and result.stderr == b''
    assert result.stdout == canonical_result_bytes(evaluate_proposal(proposal, capture)) + b'\n'


def test_declared_core_identities_preserve_extracted_bytes():
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / 'source-manifest.json').read_text())
    source_hashes = {row['destination']: row['source_sha256'] for row in manifest['files']}
    for component in raw_derivation.COMPONENTS:
        assert hashlib.sha256((root / component).read_bytes()).hexdigest() == source_hashes[component]
