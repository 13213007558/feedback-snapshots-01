#!/usr/bin/env python3
"""Dump the PFCP endpoint-allocation evidence artifact as JSON.

Usage (from the repository root):
    PYTHONPATH=. .venv/bin/python tools/pfcp_endpoint_audit_demo.py [output.json]

With no argument the artifact is printed to stdout.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pfcp_audit.artifacts import build_artifact


def main() -> int:
    artifact = build_artifact()
    text = json.dumps(artifact, indent=2, sort_keys=False)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(text + '\n')
        print('wrote %s' % sys.argv[1])
    else:
        print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
