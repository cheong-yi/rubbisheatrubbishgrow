"""Default bounded stdin/stdout entry for non-authorizing raw adoption."""

import sys
from .raw_cli import main


if __name__ == "__main__":
    raise SystemExit(main(argv=sys.argv[1:]))
