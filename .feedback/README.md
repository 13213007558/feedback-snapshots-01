# Local preparation: Scapy

Python 3.12. Install the fixed editable checkout with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. This runs existing IPFIX/NetFlow, IGMP, BGP, OSPF, DHCPv4 and UDS UTscapy campaigns in forced non-root mode; no packet is sent, no live capture or vehicle hardware is used. Optional external integrations are outside the baseline.
Upstream: https://github.com/secdev/scapy at 0e2f6ba2669dc9c6487d7c0a4220b3c3dfd6d4ef.

DHCP baseline runs upstream cases 0–5 (packet/option handling). Case 6 documents the interactive dhcpd alias and requires optional IPython, unrelated to the offline analysis tasks. Its missing optional dependency is retained in the first baseline log.
