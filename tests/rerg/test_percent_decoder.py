"""Focused behavior tests for percent decoding and credential screening."""
from __future__ import annotations

import random
import re
from urllib.parse import unquote, urlsplit

import pytest

from rerg import raw_derivation


@pytest.mark.parametrize('byte_value', range(256))
def test_percent_decoder_matches_unquote_for_every_byte(byte_value):
    encoded = f'%{byte_value:02X}'
    assert raw_derivation._percent_decode(encoded) == unquote(encoded)


@pytest.mark.parametrize('value', [
    '%C3%A9',
    '%E2%82%AC',
    '%F0%9F%8C%8D',
    '%C3%28',
    '%E2%28%A1',
    '%F0%9F%92',
    '%ED%A0%80',
    '雪%C3%A9🙂',
    'π%E2%82%AC雪',
    '%e2%82%Ac',
    '%GG%41%F0%9F%92',
    'prefix%G1middle%41suffix%',
    '%C3%A9%incomplete',
    '%',
    '%2',
    '%G0',
    '%0G',
    '%%41',
])
def test_percent_decoder_matches_unquote_for_utf8_unicode_and_malformed_runs(value):
    assert raw_derivation._percent_decode(value) == unquote(value)


def test_percent_decoder_preserves_plus_literals_and_does_not_recurse():
    assert raw_derivation._percent_decode('a+b%2Bc') == 'a+b+c'
    assert raw_derivation._percent_decode('%252F') == '%2F'
    assert raw_derivation._percent_decode('%2525') == '%25'
    assert raw_derivation._percent_decode('雪%252F🙂') == '雪%2F🙂'


def _generated_percent_corpus():
    rng = random.Random(0x46DEC0DE)
    pieces = (
        'plain', '雪', '🙂', '+', '/', '%00', '%25', '%2f', '%41',
        '%C3', '%A9', '%E2%82%AC', '%F0%9F%8C%8D', '%FF', '%GG', '%', '%2',
    )
    return tuple(
        ''.join(rng.choice(pieces) for _ in range(rng.randint(1, 9)))
        for _ in range(96)
    )


@pytest.mark.parametrize('value', _generated_percent_corpus())
def test_percent_decoder_matches_unquote_for_bounded_deterministic_corpus(value):
    assert raw_derivation._percent_decode(value) == unquote(value)


# This test-only reference captures the inherited urllib-based screening,
# including its one decoded pass and URL extraction before authority parsing.
_OLD_PRIVATE_KEY_RE = re.compile(r'-----BEGIN [^\n]*PRIVATE KEY-----', re.IGNORECASE)
_OLD_CREDENTIAL_NAME = (
    r'(?:github[_-]?token|aws[_-]?(?:(?:secret[_-])?access[_-]?key(?:[_-]?id)?|'
    r'session[_-]?token)|api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?token|'
    r'client[_-]?secret|refresh[_-]?token|id[_-]?token|password|passwd|secret|token|'
    r'authorization)'
)
_OLD_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf'''(?ix)(?<![A-Za-z0-9_])["']?(?P<key>{_OLD_CREDENTIAL_NAME})["']?\s*\]?\s*[:=]\s*'''
    rf'''(?P<value>"[^"\r\n]+"|'[^'\r\n]+'|[^\s"']+)'''
)
_OLD_QUERY_CREDENTIAL_RE = re.compile(
    r'(?i)[?&](?:api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|'
    r'refresh[_-]?token|id[_-]?token|token|password|passwd|secret)='
)
_OLD_AUTHORIZATION_BEARER_RE = re.compile(
    r'''(?i)\bauthorization\b["']?\s*\]?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._~+/-=]+'''
)
_OLD_BEARER_RE = re.compile(r'(?i)\bbearer\s+["\']?\S+')
_OLD_URL_USERINFO_RE = re.compile(r'''(?i)(?:\b[a-z][a-z0-9+.-]*:)?//[^\s/?#@]*@''')
_OLD_URL_RE = re.compile(r'''(?i)(?:\b[a-z][a-z0-9+.-]*:)?//[^\s<>"']+''')


def _old_contains_secret(value):
    for text in (value, unquote(value)):
        if (
            _OLD_PRIVATE_KEY_RE.search(text)
            or _OLD_QUERY_CREDENTIAL_RE.search(text)
            or _OLD_AUTHORIZATION_BEARER_RE.search(text)
            or _OLD_BEARER_RE.search(text)
            or _OLD_URL_USERINFO_RE.search(text)
            or _OLD_CREDENTIAL_ASSIGNMENT_RE.search(text)
        ):
            return True
        for match in _OLD_URL_RE.finditer(text):
            try:
                parsed = urlsplit(match.group())
                if parsed.username is not None or parsed.password is not None:
                    return True
            except ValueError:
                continue
    return False


@pytest.mark.parametrize(('value', 'old_result', 'current_result'), [
    ('password=credential-marker', True, True),
    ('{"password":"credential-marker"}', True, True),
    ('https://docs.example.invalid/?api-key=credential-marker', True, True),
    ('Authorization: Bearer credential-marker', True, True),
    ('Bearer credential-marker', True, True),
    ('https://user:credential-marker@docs.example.invalid/page', True, True),
    ('//user@docs.example.invalid/page', True, True),
    ('pass%77ord=credential-marker', True, True),
    ('password%3Dcredential-marker', True, True),
    ('https://docs.example.invalid/?%74oken=credential-marker', True, True),
    ('https://user%3Acredential-marker%40docs.example.invalid/page', True, True),
    ('https://docs.example.invalid/?%74oken=credential-marker%FF', True, True),
    ('https://docs.example.invalid/?%74oken=credential-marker%', True, True),
    ('%2?%74oken=credential-marker', True, True),
    # Decoding remains single-pass: this becomes password%3D..., not an
    # assignment. Recursive decoding would change this legacy nonsecret result.
    ('password%253Dcredential-marker', False, False),
    ('username=ordinary_user', False, False),
    ('auth=enabled', False, False),
    ('https://docs.example.invalid/ordinary%40segment', False, False),
    ('//user:credential-marker@[malformed', True, True),
    ('See https://user:credential-marker@docs.example.invalid/page now.', True, True),
    ('https://docs.example.invalid/path@ordinary', False, False),
    ('https://docs.example.invalid/?name=@ordinary', False, False),
    ('relative/path/to/source.txt', False, False),
])
def test_secret_screening_differential_preserves_legacy_rules_and_decodes_once(
    value, old_result, current_result,
):
    assert _old_contains_secret(value) is old_result
    assert raw_derivation._contains_secret(value) is current_result


@pytest.mark.parametrize('allow_local_paths', [False, True])
@pytest.mark.parametrize('value', [
    'relative/path/to/source.txt',
    '/tmp/rerg/source.txt',
    'https://docs.example.invalid/ordinary%40segment',
])
def test_text_accepts_ordinary_paths_in_both_local_modes(
    allow_local_paths, value,
):
    raw_derivation._text(value, allow_local_paths=allow_local_paths)


@pytest.mark.parametrize(('allow_local_paths', 'accepted'), [(False, False), (True, True)])
def test_text_local_path_mode_only_controls_local_home_paths(allow_local_paths, accepted):
    value = '/home/example/workspace/source.txt'
    if accepted:
        raw_derivation._text(value, allow_local_paths=allow_local_paths)
    else:
        with pytest.raises(raw_derivation.EnvelopeValidationError):
            raw_derivation._text(value, allow_local_paths=allow_local_paths)
