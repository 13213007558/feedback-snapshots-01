"""Ordinary script (no inline metadata) swapped in at the same path."""

from __future__ import annotations

import sys


def main() -> None:
    print(f"ordinary-job ran on python {sys.version_info.major}.{sys.version_info.minor}")
    print("ordinary-job needs no third-party dependencies")


if __name__ == "__main__":
    main()
