"""Bounded JSON transport; admission failures are not assessment outcomes."""
from __future__ import annotations

import json
import sys

from . import raw_derivation, raw_intake

MAX_INPUT_BYTES = 1_048_576
MAX_DEPTH = 32


class _ObjectPairs(list):
    """Decoder-only representation retaining duplicate occurrences."""


def _bounded_depth(text):
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif char in ']}':
            depth -= 1
    return True


def _collapse(value, duplicates):
    if type(value) is _ObjectPairs:
        result = {}
        for key, child in value:
            normalized = _collapse(child, duplicates)
            if key in result:
                duplicates.append(('DUPLICATE_FIELD', '$', 'DUPLICATE_FIELD'))
            else:
                result[key] = normalized
        return result
    if type(value) is list:
        return [_collapse(child, duplicates) for child in value]
    return value


def _decode(data):
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        return None, raw_derivation._invalid([('INVALID_ENCODING_OR_SIZE', '$', 'INVALID_ENCODING_OR_SIZE')])
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        return None, raw_derivation._invalid([('INVALID_ENCODING_OR_SIZE', '$', 'INVALID_ENCODING_OR_SIZE')])
    if not _bounded_depth(text):
        return None, raw_derivation._invalid([('INVALID_ENCODING_OR_SIZE', '$', 'INVALID_ENCODING_OR_SIZE')])
    try:
        parsed = json.loads(text, object_pairs_hook=_ObjectPairs)
    except (ValueError, RecursionError):
        return None, raw_derivation._invalid([('INVALID_FIELD_VALUE', '$', 'INVALID_FIELD_VALUE')])
    duplicates = []
    value = _collapse(parsed, duplicates)
    if duplicates:
        errors = raw_derivation._check_input(value)
        if type(parsed) is _ObjectPairs:
            for key, child in parsed:
                if key == 'contract' and child != raw_derivation.CONTRACT:
                    errors.append(('UNSUPPORTED_CONTRACT', '$.contract', 'VERSION_UNSUPPORTED'))
        return None, raw_derivation._invalid(errors + duplicates)
    return value, None


def main(stdin=None, stdout=None, *, argv=()) -> int:
    try:
        destination = sys.stdout if stdout is None else stdout
        if argv:
            result = raw_derivation._invalid([('INVALID_FIELD_VALUE', '$', 'INVOCATION_ARGUMENTS')])
        else:
            source = sys.stdin.buffer if stdin is None else stdin
            invocation, invalid = _decode(source.read(MAX_INPUT_BYTES + 1))
            result = invalid if invalid is not None else raw_intake.evaluate_assessment(invocation)
        encoded = raw_intake.canonical_result_bytes(result).decode('utf-8') + '\n'
        status = 2 if result['kind'] == 'invalid_invocation' else 0
        destination.write(encoded)
        return status
    except Exception:
        try:
            sys.stderr.write('RERG_INTERNAL_ERROR\n')
        except Exception:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main(argv=sys.argv[1:]))
