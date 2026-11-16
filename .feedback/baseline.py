import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_ber.py', 'tests/test_der.py', 'tests/test_per.py', 'tests/test_uper.py', 'tests/test_oer.py', 'tests/test_constraints_checker.py']]))
