import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_aiosasl.py', 'tests/test_stringprep.py', 'tests/test_unicode_version.py']]))
