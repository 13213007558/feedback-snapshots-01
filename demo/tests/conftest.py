import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO))

import scenario  # noqa: E402


@pytest.fixture(scope="session")
def fixture_paths(tmp_path_factory):
    directory = tmp_path_factory.mktemp("fixtures")
    return scenario.build(directory)
