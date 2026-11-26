"""Command-line entry: ``python -m deploy_demo [--workdir DIR] [--big-mb N]``."""

from __future__ import annotations

import argparse
from pathlib import Path

from deploy_demo.demo import run_demo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=None)
    parser.add_argument("--big-mb", type=int, default=8)
    args = parser.parse_args()
    run_demo(args.workdir, big_mb=args.big_mb)


if __name__ == "__main__":
    main()
