import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_double_ratchet.py::test_migrations', 'tests/test_kdf_chain.py', 'tests/test_symmetric_key_ratchet.py', '--asyncio-mode=auto']]))
