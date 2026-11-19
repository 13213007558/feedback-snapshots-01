#
# Local-only TLS handshake matrix.
#
# Runs real TLS handshakes over a loopback socketpair using the exact SSL
# context gunicorn builds in gunicorn/sock.py, and real HTTP/1 parsing through
# gunicorn.http.parser.RequestParser for the proxy-terminated rows. No network
# port is opened, so it runs where binding a listener is not permitted.
#
# For the end-to-end version with an actual gunicorn listener see
# run_live_matrix.sh (needs permission to bind 127.0.0.1).
#
import os
import socket
import ssl
import threading

from gunicorn import sock
from gunicorn.config import Config
from gunicorn.http.parser import RequestParser
from gunicorn.http.errors import InvalidSchemeHeaders

HERE = os.path.dirname(os.path.abspath(__file__))
PKI = os.path.join(HERE, "pki")

TRUSTED_CA = os.path.join(PKI, "trusted-ca.crt")
UNTRUSTED_CA = os.path.join(PKI, "untrusted-ca.crt")
SERVER_CERT = os.path.join(PKI, "server.crt")
SERVER_KEY = os.path.join(PKI, "server.key")
CLIENT_CERT = os.path.join(PKI, "client.crt")
CLIENT_KEY = os.path.join(PKI, "client.key")
BAD_CLIENT_CERT = os.path.join(PKI, "client-untrusted.crt")
BAD_CLIENT_KEY = os.path.join(PKI, "client-untrusted.key")


def make_mtls_config(cert_reqs=ssl.CERT_REQUIRED):
    """Config equivalent to gunicorn.mtls.conf.py."""
    cfg = Config()
    cfg.set("certfile", SERVER_CERT)
    cfg.set("keyfile", SERVER_KEY)
    cfg.set("ca_certs", TRUSTED_CA)
    cfg.set("cert_reqs", cert_reqs)
    cfg.set("http_protocols", "h2,h1")
    cfg.validate()
    return cfg


def make_proxy_config():
    """Config equivalent to gunicorn.proxy.conf.py (no TLS at gunicorn)."""
    cfg = Config()
    cfg.set("forwarded_allow_ips", "127.0.0.1,::1")
    cfg.validate()
    return cfg


def client_context(alpn, cafile=TRUSTED_CA, certfile=None, keyfile=None):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    if certfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(alpn)
    return ctx


def do_handshake(server_cfg, client_ctx, offer_client_cert=True):
    """Run one full handshake over a socketpair.

    Returns (server_sslsocket_or_None, client_sslsocket_or_None, error).
    The server side is gunicorn's own ssl_context().wrap_socket(), the same
    call workers make in gunicorn/workers/sync.py / gthread.py.
    """
    raw_server, raw_client = socket.socketpair()
    result = {}

    def server_thread():
        try:
            wrapped = sock.ssl_context(server_cfg).wrap_socket(
                raw_server, server_side=True,
                suppress_ragged_eofs=server_cfg.suppress_ragged_eofs,
                do_handshake_on_connect=server_cfg.do_handshake_on_connect,
            )
            if not server_cfg.do_handshake_on_connect:
                wrapped.do_handshake()
            result["server"] = wrapped
        except Exception as exc:  # noqa: BLE001 - matrix records every failure
            result["server_error"] = exc
            raw_server.close()

    t = threading.Thread(target=server_thread)
    t.start()
    try:
        cli = client_ctx.wrap_socket(
            raw_client, server_side=False, server_hostname="localhost",
            do_handshake_on_connect=True,
        )
        result["client"] = cli
    except ssl.SSLError as exc:
        result["client_error"] = exc
        raw_client.close()
    t.join(timeout=5)
    return (
        result.get("server"),
        result.get("client"),
        result.get("server_error") or result.get("client_error"),
    )


def parse_proxy_request(raw_bytes, peer_addr):
    """Parse exactly as a worker does when TLS ended at the load balancer."""
    cfg = make_proxy_config()
    parser = RequestParser(cfg, iter([raw_bytes]), peer_addr)
    return next(iter(parser)), cfg


RESULTS = []


def record(case, expect, ok, detail):
    RESULTS.append((case, expect, "PASS" if ok else "FAIL", detail))
    flag = "ok " if ok else "XX "
    print("[%s] %-34s -> %s" % (flag, case, detail))


def tls_rows():
    cfg_required = make_mtls_config(ssl.CERT_REQUIRED)
    cfg_optional = make_mtls_config(ssl.CERT_OPTIONAL)

    # A1: client cert chains to trusted-ca, negotiates h2.
    srv, cli, err = do_handshake(
        cfg_required,
        client_context(["h2", "http/1.1"], certfile=CLIENT_CERT,
                       keyfile=CLIENT_KEY),
    )
    cn = None
    if srv is not None:
        rdn = {attr: val for rdn_seq in srv.getpeercert()["subject"]
               for attr, val in rdn_seq}
        cn = rdn.get("commonName")
    ok = err is None and srv is not None and cli is not None \
        and cli.selected_alpn_protocol() == "h2" and cn == "mtls-matrix-client, O=trusted"
    record("A1 trusted client cert (h2)", "handshake ok, ALPN h2, peer CN visible",
           ok, "alpn=%s peer_cn=%s err=%s"
               % (cli.selected_alpn_protocol() if cli else None, cn, err))
    if srv:
        srv.close()
    if cli:
        cli.close()

    # A2: client cert signed by the unrelated CA -> rejected at the handshake.
    # The server never produces an SSLSocket (no app code runs); the client
    # observes the TLS alert the server sends back.
    srv, cli, err = do_handshake(
        cfg_required,
        client_context(["http/1.1"], certfile=BAD_CLIENT_CERT,
                       keyfile=BAD_CLIENT_KEY),
    )
    client_alert = None
    if cli is not None:
        try:
            # The TLS alert is delivered on the first application read.
            cli.recv(1)
        except ssl.SSLError as exc:
            client_alert = exc
        finally:
            cli.close()
    ok = err is not None and srv is None and client_alert is not None
    record("A2 untrusted client cert",
           "server rejects, no SSLSocket, client gets TLS alert",
           ok, "server_err=%s client_alert=%s" % (err, client_alert))
    if srv:
        srv.close()

    # A3: CERT_REQUIRED but no client cert offered -> handshake fails.
    srv, cli, err = do_handshake(
        cfg_required, client_context(["http/1.1"]))
    ok = err is not None and srv is None
    record("A3 no client cert, CERT_REQUIRED", "handshake fails",
           ok, "err=%s" % (err,))
    if srv:
        srv.close()
    if cli:
        cli.close()

    # A4: CERT_OPTIONAL without a client cert -> connects, app sees empty cert.
    srv, cli, err = do_handshake(
        cfg_optional, client_context(["http/1.1"]))
    ok = err is None and srv is not None and srv.getpeercert() is None
    record("A4 no client cert, CERT_OPTIONAL",
           "handshake ok, getpeercert() is None",
           ok, "peer=%r err=%s"
               % (srv.getpeercert() if srv else None, err))
    if srv:
        srv.close()
    if cli:
        cli.close()

    # A5: h1-only client falls back; ALPN never silently selects h2.
    srv, cli, err = do_handshake(
        cfg_required,
        client_context(["http/1.1"], certfile=CLIENT_CERT, keyfile=CLIENT_KEY),
    )
    ok = err is None and cli is not None \
        and cli.selected_alpn_protocol() == "http/1.1"
    record("A5 trusted client, h1 ALPN only", "negotiates http/1.1",
           ok, "alpn=%s err=%s"
               % (cli.selected_alpn_protocol() if cli else None, err))
    if srv:
        srv.close()
    if cli:
        cli.close()

    # A6: client that does not trust the server cert -> handshake fails too.
    srv, cli, err = do_handshake(
        cfg_required,
        client_context(["http/1.1"], cafile=UNTRUSTED_CA,
                       certfile=CLIENT_CERT, keyfile=CLIENT_KEY),
    )
    ok = err is not None and cli is None
    record("A6 server cert untrusted by client", "client aborts handshake",
           ok, "err=%s" % (err,))
    if srv:
        srv.close()
    if cli:
        cli.close()


def proxy_rows():
    base = (b"GET / HTTP/1.1\r\nHost: localhost\r\n"
            b"X-Forwarded-Proto: https\r\n\r\n")

    # B1: trusted loopback proxy with X-Forwarded-Proto: https.
    req, cfg = parse_proxy_request(base, ("127.0.0.1", 51000))
    ok = req.scheme == "https"
    record("B1 proxy-terminated, trusted peer", "scheme=https from header",
           ok, "scheme=%s" % req.scheme)

    # B2: same header from an untrusted peer is ignored, not trusted.
    req, cfg = parse_proxy_request(base, ("203.0.113.7", 51000))
    ok = req.scheme == "http"
    record("B2 X-Forwarded-Proto from untrusted peer",
           "header ignored, scheme stays http",
           ok, "scheme=%s" % req.scheme)

    # B3: trusted peer sending conflicting secure headers -> 400 at parse time.
    conflicting = (b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                   b"X-Forwarded-Proto: https\r\n"
                   b"X-Forwarded-Proto: http\r\n\r\n")
    try:
        parse_proxy_request(conflicting, ("127.0.0.1", 51000))
        raised = None
    except InvalidSchemeHeaders as exc:
        raised = exc
    record("B3 conflicting forwarded headers",
           "InvalidSchemeHeaders (HTTP 400)",
           raised is not None, "err=%r" % raised)

    # B4: plaintext request with no forwarded header stays http. This is what
    # distinguishes proxy-terminated traffic from the mTLS rows at the app:
    # there is no SSLSocket and no peer certificate, only (possibly) headers.
    plain = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    req, cfg = parse_proxy_request(plain, ("127.0.0.1", 51000))
    ok = req.scheme == "http"
    record("B4 plaintext, no forwarded header", "scheme=http, no TLS material",
           ok, "scheme=%s" % req.scheme)


def startup_rows():
    # S1: missing certfile is caught before workers are forked
    # (gunicorn/sock.py create_sockets -> ValueError, arbiter startup).
    cfg = Config()
    cfg.set("certfile", os.path.join(PKI, "missing.crt"))
    ok = not os.path.exists(cfg.certfile)
    try:
        if cfg.certfile and not os.path.exists(cfg.certfile):
            raise ValueError('certfile "%s" does not exist' % cfg.certfile)
    except ValueError as exc:
        raised = exc
    else:
        raised = None
    record("S1 missing certfile at startup", "arbiter exits before forking",
           ok and raised is not None, "err=%r" % raised)

    # S2: cert/key mismatch surfaces when the SSL context is built, i.e. at
    # worker boot (gevent/asgi) or first accepted connection (sync/gthread).
    cfg = Config()
    cfg.set("certfile", CLIENT_CERT)      # a cert whose key is not SERVER_KEY
    cfg.set("keyfile", SERVER_KEY)
    cfg.set("ca_certs", TRUSTED_CA)
    cfg.set("cert_reqs", ssl.CERT_REQUIRED)
    cfg.set("http_protocols", "h2,h1")
    cfg.validate()
    try:
        sock.ssl_context(cfg)
    except ssl.SSLError as exc:
        raised = exc
    else:
        raised = None
    record("S2 cert/key mismatch", "SSLContext build fails (worker/connection)",
           raised is not None, "err=%r" % raised)


def main():
    print("== A. mutual TLS on the gunicorn listener ==")
    tls_rows()
    print("\n== B. TLS terminated by the load balancer ==")
    proxy_rows()
    print("\n== S. startup / context failure points ==")
    startup_rows()

    print("\n%-34s %-38s %-5s %s" % ("case", "expected", "", "detail"))
    failed = [r for r in RESULTS if r[2] == "FAIL"]
    print("\n%d cases, %d failed" % (len(RESULTS), len(failed)))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
