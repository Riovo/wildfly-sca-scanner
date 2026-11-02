"""Pytest configuration: adds scripts/suppressions/ to sys.path.

This lets test files import suppression modules directly (e.g. `from model import Suppression`,
`from convert_to_trivy import convert`) without needing package installs or relative imports.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "suppressions"))
