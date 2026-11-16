# Local preparation: smda

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/testCandidateSafeguards.py', 'tests/testSmdaReportPickle.py', 'tests/testAbsoluteDataRefs.py', 'tests/testArmReturns.py'].
Original upstream: https://github.com/danielplohmann/smda, commit 2a943f97923e3d6381e2b6b9792f0b25a7a6f5f6.

Broader upstream verification: 2693 passed, 1 skipped (155.21 seconds). The quick baseline is the four deterministic suites listed above.
