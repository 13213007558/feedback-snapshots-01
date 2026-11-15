"""Run upstream tests with subprocesses using this same virtualenv."""
import os, pathlib, sys
import pytest
os.environ["PATH"] = str(pathlib.Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
raise SystemExit(pytest.main(["-q", "-o", "addopts=", "tests", "--ignore=tests/test_cli.py"]))
