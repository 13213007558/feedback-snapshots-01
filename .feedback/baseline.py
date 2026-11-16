import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_unit.py', 'tests/test_session_authentication.py', 'tests/test_relative_path.py', 'tests/test_uaerrors.py']]))
