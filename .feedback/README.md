# Local preparation: bacnet

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_primitive_data', 'tests/test_pdu', 'tests/test_invalid_tag_handling.py'].
Original upstream: https://github.com/JoelBender/BACpypes3, commit eeb75e9f986703fde1c611d3d63d330bdf33c870.
