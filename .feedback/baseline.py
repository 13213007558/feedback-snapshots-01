import subprocess
import sys

campaigns = [
    ("test/scapy/layers/netflow.uts", ""),
    ("test/scapy/layers/igmp.uts", ""),
    ("test/contrib/bgp.uts", "load_contrib('bgp')"),
    ("test/contrib/ospf.uts", "load_contrib('ospf')"),
    ("test/scapy/layers/dhcp.uts", ""),
    ("test/contrib/automotive/uds.uts", ""),
]
for campaign, preexec in campaigns:
    args = [sys.executable, "-m", "scapy.tools.UTscapy", "-N", "-q", "-t", campaign]
    if campaign.endswith("dhcp.uts"):
        args += ["-n", "0-5"]
    if preexec:
        args += ["-P", preexec]
    subprocess.run(args, check=True)
