"""Local HTTPS index + artifact server stand-in.

One process serves two virtual hosts (Host header based):

* ``index.corp.example``  - authenticated PEP 503 simple index (basic auth),
  linking every artifact to ``files.corp.example`` so index fetch and file
  download demonstrably hit different hosts;
* ``files.corp.example``  - approved artifact destination, same corporate CA.

A second instance can be started with the unapproved CA certificate to
represent a redirect destination outside the rolled-out trust anchor.

All requests are appended to an access log file, which becomes the
plan-stage/download-stage evidence.
"""

from __future__ import annotations

import base64
import http.server
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class ServerHandle:
    host: str
    port: int
    thread: threading.Thread
    httpd: http.server.HTTPServer
    access_log: Path


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "CorpIndex/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def _record(self, status: int) -> None:
        auth = self.headers.get("Authorization", "-")
        line = (
            f"{self.server.server_name} {self.command} {self.path} "
            f"host={self.headers.get('Host', '-')} auth={auth} status={status}\n"
        )
        with self.server.access_log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def _unauthorized(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="corp-index"')
        self.end_headers()
        self._record(401)

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._record(status)

    def do_GET(self) -> None:  # noqa: N802
        host = (self.headers.get("Host") or "").split(":")[0]
        if host == "index.corp.example":
            self._serve_index()
        elif host == "files.corp.example":
            self._serve_artifact()
        else:
            self._send_bytes(404, b"unknown host\n", "text/plain")

    def _serve_index(self) -> None:
        expected = "Basic " + base64.b64encode(
            f"{self.server.basic_user}:{self.server.basic_password}".encode()
        ).decode()
        if self.headers.get("Authorization") != expected:
            self._unauthorized()
            return
        root = self.server.artifact_root
        links = []
        for wheel in sorted(root.glob("*.whl")):
            links.append(
                f'<a href="https://files.corp.example:{self.server.artifact_port}'
                f'/files/{wheel.name}">{wheel.name}</a>'
            )
        for sdist in sorted(root.glob("*.tar.gz")):
            links.append(
                f'<a href="https://files.corp.example:{self.server.artifact_port}'
                f'/files/{sdist.name}">{sdist.name}</a>'
            )
        body = (
            "<!DOCTYPE html><html><body><h1>Simple Index</h1>"
            + "".join(links)
            + "</body></html>"
        ).encode()
        self._send_bytes(200, body, "text/html")

    def _serve_artifact(self) -> None:
        name = urlparse(self.path).path.removeprefix("/files/")
        target = (self.server.artifact_root / name).resolve()
        if self.server.artifact_root.resolve() not in target.parents or not target.is_file():
            self._send_bytes(404, b"not found\n", "text/plain")
            return
        self._send_bytes(200, target.read_bytes(), "application/octet-stream")


class _Server(http.server.HTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[http.server.BaseHTTPRequestHandler],
        *,
        server_pem: Path,
        artifact_root: Path,
        access_log: Path,
        basic_user: str,
        basic_password: str,
        artifact_port: int,
        server_name: str,
    ) -> None:
        super().__init__(server_address, handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(server_pem))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)
        self.artifact_root = artifact_root
        self.access_log_path = access_log
        self.basic_user = basic_user
        self.basic_password = basic_password
        self.artifact_port = artifact_port
        self.server_name = server_name


def serve(
    *,
    bind_host: str,
    port: int,
    server_pem: Path,
    artifact_root: Path,
    access_log: Path,
    basic_user: str,
    basic_password: str,
    artifact_port: int,
    server_name: str,
) -> ServerHandle:
    httpd = _Server(
        (bind_host, port),
        _Handler,
        server_pem=server_pem,
        artifact_root=artifact_root,
        access_log=access_log,
        basic_user=basic_user,
        basic_password=basic_password,
        artifact_port=artifact_port,
        server_name=server_name,
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return ServerHandle(
        host=bind_host, port=httpd.server_address[1], thread=thread, httpd=httpd, access_log=access_log
    )
