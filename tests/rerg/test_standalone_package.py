"""Offline wheel proof, not installation into a live invoking harness."""
import configparser
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from rerg import canonical_result_bytes, evaluate_proposal
from test_supplied_admission import make_request


@pytest.fixture(scope='module')
def wheel(tmp_path_factory):
    root = Path(__file__).resolve().parents[2]
    work = tmp_path_factory.mktemp('wheel')
    build = subprocess.run(
        [sys.executable, '-c',
         'from setuptools.build_meta import build_wheel;'
         'import sys;print(build_wheel(sys.argv[1]))', str(work)],
        cwd=root, capture_output=True, timeout=60,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    archives = list(work.glob('*.whl'))
    assert len(archives) == 1
    unpacked = work / 'unpacked'
    with zipfile.ZipFile(archives[0]) as archive:
        names = archive.namelist()
        assert not any(name.startswith('plugins/') for name in names)
        archive.extractall(unpacked)
    return root, unpacked


def test_wheel_contains_exact_core_skill_and_console_binding(wheel):
    root, unpacked = wheel
    for source in (root / 'rerg').glob('*.py'):
        assert (unpacked / 'rerg' / source.name).read_bytes() == source.read_bytes()
    skill = unpacked / 'rerg-0.1.0.data/data/share/rerg/skills/rerg/SKILL.md'
    assert skill.read_bytes() == (root / 'skills/rerg/SKILL.md').read_bytes()
    config = configparser.ConfigParser()
    config.read(unpacked / 'rerg-0.1.0.dist-info/entry_points.txt')
    assert config['console_scripts']['rerg-assess'] == 'rerg.assessment_cli:entrypoint'


@pytest.mark.parametrize('module', ['rerg', 'rerg.raw_cli', 'rerg.assessment_cli'])
@pytest.mark.parametrize('invalid', [False, True])
def test_wheel_public_clis_without_checkout_or_site_packages(wheel, tmp_path, module, invalid):
    _, unpacked = wheel
    proposal, capture = make_request()
    expected = evaluate_proposal(proposal, capture)
    record = {'proposal': proposal, 'capture': capture} if module == 'rerg.assessment_cli' else expected['input']
    if invalid:
        record = {}
    bootstrap = (
        'import runpy,sys;sys.path.insert(0,sys.argv[1]);'
        'import rerg;assert rerg.__file__==sys.argv[1]+"/rerg/__init__.py";'
        'module=sys.argv[2];sys.argv=[module];'
        'runpy.run_module(module,run_name="__main__")'
    )
    result = subprocess.run(
        [sys.executable, '-I', '-S', '-B', '-c', bootstrap, str(unpacked), module],
        input=json.dumps(record).encode(), capture_output=True, cwd=tmp_path, timeout=30,
    )
    assert result.stderr == b''
    assert result.returncode == (2 if invalid else 0)
    if invalid:
        assert json.loads(result.stdout)['kind'] == 'invalid_invocation'
    else:
        assert result.stdout == canonical_result_bytes(expected) + b'\n'
