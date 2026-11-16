import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/encoding', 'tests/security']]))
