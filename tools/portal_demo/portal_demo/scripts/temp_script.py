# /// script
# requires-python = ">=3.12"
# dependencies = ["setuptools==84.2.1"]
# ///
"""Temporary single-file script with PEP 723 inline metadata."""

from __future__ import annotations

import sys

import setuptools


def main() -> None:
    print(f"temp-script ran on python {sys.version_info.major}.{sys.version_info.minor}")
    print(f"temp-script imported setuptools {setuptools.__version__}")


if __name__ == "__main__":
    main()
