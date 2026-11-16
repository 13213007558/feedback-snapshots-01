# Local preparation: modbus

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['test/framer', 'test/pdu', 'test/datastore'].
Original upstream: https://github.com/pymodbus-dev/pymodbus, commit 38c24848339c74f95768b62f7c492b327719689e.

Fast baseline selection: ['-m', 'pytest', '-o', 'addopts=', '-q', 'test/framer', 'test/pdu', '--asyncio-mode=auto']. The earlier broader baseline passed; its log and timings are retained in the local batch preparation receipts.

Final fast command: ['-m', 'pytest', '-o', 'addopts=', '-q', 'test/framer/test_framer.py', 'test/pdu/test_decoders.py', 'test/pdu/test_register_read_messages.py', 'test/pdu/test_register_write_messages.py', '--asyncio-mode=auto'].

The full 1050-case scope passed in 110.328 seconds. The original autouse system-health fixture waits 0.1 seconds per case; it is preserved. The quick baseline selects fragmented RTU framing, malformed PDU rejection, complicated framing and write validation: ['-m', 'pytest', '-o', 'addopts=', '-q', 'test/framer/test_framer.py', 'test/pdu/test_decoders.py', 'test/pdu/test_register_write_messages.py', '-k', 'rtu_partial_request_waits_for_more_data or decode_bad_frame or invalid_write_multiple_registers_request or test_decode_complicated or test_register_write_exception', '--asyncio-mode=auto'].
