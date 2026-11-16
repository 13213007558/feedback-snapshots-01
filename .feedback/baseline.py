import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_aioimaplib_clocked.py', 'tests/test_aioimaplib_capabilities.py', 'tests/test_utils.py', '--asyncio-mode=auto']]))
