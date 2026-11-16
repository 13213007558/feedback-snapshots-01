import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'test/test_core.py', 'test/test_asn1rt.py', 'test/test_mobile.py', '-k', 'not perf']]))
