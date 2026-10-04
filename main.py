"""SentinelFW entry point.

Run from the project directory:

    python3 main.py --help

or install the ``sentinelfw`` command (see pyproject.toml / README).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow ``python3 main.py`` from anywhere by making the project root importable.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cli.interface import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())