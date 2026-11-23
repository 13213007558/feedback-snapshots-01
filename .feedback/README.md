# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import dpkt, io; out=io.BytesIO(); writer=dpkt.pcap.Writer(out,linktype=dpkt.pcap.DLT_EN10MB); frame=bytes(dpkt.ethernet.Ethernet(dst=b'"'"'123456'"'"',src=b'"'"'ABCDEF'"'"',type=0x9000,data=b'"'"'DATA'"'"')); writer.writepkt(frame,ts=8.5); out.seek(0); ts,data=next(iter(dpkt.pcap.Reader(out))); assert ts==8.5 and dpkt.ethernet.Ethernet(data).data==b'"'"'DATA'"'"'; print('"'"'Synthetic capture round trip passed'"'"')'
```
