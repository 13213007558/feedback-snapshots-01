#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Tests for the gunicornc CLI's handling of policy errors."""

import socket
import threading

from gunicorn.ctl import cli
from gunicorn.ctl.client import ControlClient
from gunicorn.ctl.protocol import ControlProtocol


def _serve_once(monkeypatch, reply):
    """Point ControlClient at a socketpair that answers one request."""
    server_end, client_end = socket.socketpair(socket.AF_UNIX,
                                               socket.SOCK_STREAM)

    def reply_once():
        try:
            message = ControlProtocol.read_message(server_end)
            reply["id"] = message["id"]
            ControlProtocol.write_message(server_end, reply)
        finally:
            server_end.close()

    thread = threading.Thread(target=reply_once, daemon=True)
    thread.start()

    def connect(self):
        self._sock = client_end

    monkeypatch.setattr(ControlClient, "connect", connect)
    monkeypatch.setattr(ControlClient, "close", lambda self: None)
    return thread


def test_permission_denied_exits_with_2(monkeypatch, capsys):
    _serve_once(monkeypatch, {
        "status": "error",
        "error": "Role 'monitor' may not run 'reload'",
        "code": "permission_denied",
    })

    status = cli.run_command("/nonexistent.sock", "reload")

    assert status == 2
    captured = capsys.readouterr()
    assert "Permission denied" in captured.err


def test_unknown_command_exits_with_1(monkeypatch, capsys):
    _serve_once(monkeypatch, {
        "status": "error",
        "error": "Unknown command: frobnicate",
        "code": "unknown_command",
    })

    status = cli.run_command("/nonexistent.sock", "frobnicate")

    assert status == 1
    captured = capsys.readouterr()
    assert "Unknown command" in captured.err
    assert "Permission denied" not in captured.err
