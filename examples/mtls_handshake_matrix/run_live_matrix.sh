#!/usr/bin/env bash
#
# End-to-end version of the matrix against two real gunicorn listeners:
#   :8443 mutual TLS (gunicorn.mtls.conf.py)
#   :8080 plain HTTP behind a notional load balancer (gunicorn.proxy.conf.py)
#
# Everything stays on loopback. Requires permission to bind 127.0.0.1; the
# sandbox used to build this package denies that, in which case run
# handshake_matrix.py instead (same gunicorn SSL/parser code, socketpair only).
#
set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", 0))
except OSError:
    sys.exit("cannot bind 127.0.0.1 here; run handshake_matrix.py instead")
finally:
    s.close()
PY

GUNICORN="$(cd ../.. && pwd)/.venv/bin/gunicorn"
[ -x "$GUNICORN" ] || GUNICORN="gunicorn"
PKI=pki
MTLS_PORT=8443
HTTP_PORT=8080
TMP="$(mktemp -d "${TMPDIR:-/tmp}/mtls-matrix.XXXXXX")"
trap 'kill "${MTLS_PID:-0}" "${HTTP_PID:-0}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== starting listeners =="
"$GUNICORN" -c gunicorn.mtls.conf.py -b 127.0.0.1:"$MTLS_PORT" \
    --workers 1 -k gthread --threads 2 identity_app:app \
    --pid "$TMP/mtls.pid" --daemon --error-logfile "$TMP/mtls.log"
MTLS_PID=$(cat "$TMP/mtls.pid")
"$GUNICORN" -c gunicorn.proxy.conf.py -b 127.0.0.1:"$HTTP_PORT" \
    --workers 1 -k gthread --threads 2 identity_app:app \
    --pid "$TMP/http.pid" --daemon --error-logfile "$TMP/http.log"
HTTP_PID=$(cat "$TMP/http.pid")
sleep 1

hr() { printf '\n--- %s ---\n' "$1"; }

hr "A1 trusted client cert, h2 via ALPN"
curl -sS --http2 --cacert "$PKI/trusted-ca.crt" \
     --cert "$PKI/client.crt" --key "$PKI/client.key" \
     "https://127.0.0.1:$MTLS_PORT/" ; echo
# ALPN on the wire:
openssl s_client -connect 127.0.0.1:"$MTLS_PORT" -alpn h2 \
    -CAfile "$PKI/trusted-ca.crt" \
    -cert "$PKI/client.crt" -key "$PKI/client.key" </dev/null 2>/dev/null \
    | grep -E "ALPN|Verify return code"

hr "A2 untrusted client cert (expect handshake failure, alert unknown CA)"
curl -sS --cacert "$PKI/trusted-ca.crt" \
     --cert "$PKI/client-untrusted.crt" --key "$PKI/client-untrusted.key" \
     "https://127.0.0.1:$MTLS_PORT/" 2>&1 || true

hr "A3 no client cert while CERT_REQUIRED (expect handshake failure)"
curl -sS --cacert "$PKI/trusted-ca.crt" \
     "https://127.0.0.1:$MTLS_PORT/" 2>&1 || true

hr "A5 trusted client forced to HTTP/1.1"
curl -sS --http1.1 --cacert "$PKI/trusted-ca.crt" \
     --cert "$PKI/client.crt" --key "$PKI/client.key" \
     "https://127.0.0.1:$MTLS_PORT/" ; echo

hr "B1 proxy-terminated: trusted loopback peer sets X-Forwarded-Proto"
curl -sS -H "X-Forwarded-Proto: https" \
     "http://127.0.0.1:$HTTP_PORT/" ; echo

hr "B2 same header from a non-loopback peer would be ignored (forwarded_allow_ips)"
# Cannot spoof the source IP with curl; demonstrate the parser rule directly:
python3 - <<'PY'
from handshake_matrix import parse_proxy_request
req, _ = parse_proxy_request(
    b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-Proto: https\r\n\r\n",
    ("203.0.113.7", 51000))
print("scheme from untrusted peer:", req.scheme)
PY

hr "B4 plaintext request, no forwarded header (no TLS material at the app)"
curl -sS "http://127.0.0.1:$HTTP_PORT/" ; echo
