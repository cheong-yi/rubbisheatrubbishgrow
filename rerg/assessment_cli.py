"""Bounded proposal/capture transport over the single neutral evaluator."""
from __future__ import annotations

import sys

from . import raw_cli, raw_derivation, raw_intake


def main(stdin=None, stdout=None, *, argv=()) -> int:
    """Read one closed proposal/capture record; never capture or grant authority."""
    try:
        destination = sys.stdout if stdout is None else stdout
        if argv:
            result = raw_derivation._invalid([
                ('INVALID_FIELD_VALUE', '$', 'INVOCATION_ARGUMENTS'),
            ])
        else:
            source = sys.stdin.buffer if stdin is None else stdin
            record, invalid = raw_cli._decode(source.read(raw_cli.MAX_INPUT_BYTES + 1))
            if invalid is not None:
                result = invalid
            elif type(record) is not dict or set(record) != {'proposal', 'capture'}:
                result = raw_derivation._invalid([
                    ('INVALID_FIELD_VALUE', '$', 'INVALID_FIELD_VALUE'),
                ])
            else:
                result = raw_intake.evaluate_proposal(record['proposal'], record['capture'])
        destination.write(raw_intake.canonical_result_bytes(result).decode('utf-8') + '\n')
        return 2 if result['kind'] == 'invalid_invocation' else 0
    except Exception:
        try:
            sys.stderr.write('RERG_INTERNAL_ERROR\n')
        except Exception:
            pass
        return 1


def entrypoint() -> int:
    """Console entrypoint retaining the no-arguments transport contract."""
    return main(argv=sys.argv[1:])


if __name__ == '__main__':
    raise SystemExit(entrypoint())
