import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_primitive_data', 'tests/test_pdu', 'tests/test_invalid_tag_handling.py', '--asyncio-mode=auto']]))
