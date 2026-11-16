import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_core.py', 'tests/test_utils.py']]))
