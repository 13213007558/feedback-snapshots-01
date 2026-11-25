#!/usr/bin/env python3
"""Convenience launcher: ``.venv/bin/python audit_proof_demo.py``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_proof.simulation import main

if __name__ == "__main__":
    raise SystemExit(main())
