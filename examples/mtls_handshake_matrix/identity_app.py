#
# Identity-dumping app used by the local mTLS / TLS-termination matrix.
#
# It reports exactly the identity material an application can depend on in
# each deployment shape. Nothing here invents headers: every field comes from
# the WSGI environ gunicorn builds, and the certificate fields come from the
# real SSLSocket gunicorn hands over as environ["gunicorn.socket"].
#
import json
import ssl


def _peer_cert_material(environ):
    """What the listener itself established about the TLS peer.

    Returns None whenever the connection is not TLS at gunicorn, which is the
    whole point of the proxy-terminated case: gunicorn cannot see a client
    certificate there because no TLS session exists on its socket.
    """
    sock = environ.get("gunicorn.socket")
    if not isinstance(sock, ssl.SSLSocket):
        return None
    return {
        "selected_alpn_protocol": sock.selected_alpn_protocol(),
        "version": sock.version(),
        "cipher": (sock.cipher() or [None])[0],
        # Parsed chain ending at the trust anchor; empty for a plaintext peer.
        "getpeercert": sock.getpeercert(),
        # DER bytes, suitable for fingerprinting or forwarding to an auditor.
        "getpeercert_der_present": bool(sock.getpeercert(binary_form=True)),
    }


def app(environ, start_response):
    forwarded_headers = {
        key: value
        for key, value in environ.items()
        if key.startswith("HTTP_X_FORWARDED_")
    }
    payload = {
        "wsgi.url_scheme": environ.get("wsgi.url_scheme"),
        "remote_addr": environ.get("REMOTE_ADDR"),
        "server_protocol": environ.get("SERVER_PROTOCOL"),
        "listener_tls": _peer_cert_material(environ),
        "forwarded_headers_seen": forwarded_headers,
    }
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    start_response("200 OK", [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
    ])
    return [body]
