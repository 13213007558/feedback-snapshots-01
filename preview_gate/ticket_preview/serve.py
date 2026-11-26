"""Run the preview gate over a real loopback HTTP socket.

    .venv/bin/python -m ticket_preview.serve --port 8077

(Run from the ``preview_gate`` directory so ``ticket_preview`` is importable,
or use ``preview_gate/run_preview.sh``.)  Some sandboxes forbid bind(); the
verification driver then exercises the very same WSGI callable in-process.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from wsgiref.simple_server import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ticket_preview.wsgi_app import DEFAULT_DATA_DIR, create_default_app  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Ticket preview gate server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8077)
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    args = parser.parse_args(argv)

    app = create_default_app(args.data_dir)
    try:
        httpd = make_server(args.host, args.port, app)
    except PermissionError as exc:
        print(
            f"bind({args.host}:{args.port}) blocked: {exc}. "
            "Run this in a shell that permits local socket binding.",
            file=sys.stderr,
        )
        return 2

    print(f"ticket preview gate on http://{args.host}:{args.port}")
    print(f"  preview:  http://{args.host}:{args.port}/tickets/WO-2026-224/preview")
    print("  internal: add header 'X-Staff-Role: staff'")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
