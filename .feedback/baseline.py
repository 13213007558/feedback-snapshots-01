import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, *['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_parser.py', 'tests/test_receiver.py', 'tests/test_channel.py', 'tests/test_task.py', 'tests/test_proxy_headers.py']]))
