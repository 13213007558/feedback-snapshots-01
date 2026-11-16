import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_message.py', 'tests/test_name.py', 'tests/test_tsig.py', 'tests/test_edns.py']]))
