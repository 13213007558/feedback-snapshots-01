#!/usr/bin/env bash
# Build a self-contained, loopback-only PKI for the mTLS / TLS-termination
# handshake matrix. Nothing here is ever used outside this machine.
#
# Outputs under pki/:
#   trusted-ca.crt/.key        CA the Gunicorn listener is configured to trust
#   server.crt/.key            server cert issued by trusted-ca (CN=localhost)
#   client.crt/.key            client cert issued by trusted-ca (mTLS pass)
#   untrusted-ca.crt/.key      a second, unrelated CA
#   client-untrusted.crt/.key  client cert issued by untrusted-ca (mTLS fail)
set -euo pipefail
cd "$(dirname "$0")/pki"

DAYS=3650
run() { echo "+ $*"; "$@"; }

# --- two independent root CAs -------------------------------------------------
run openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
    -subj "/CN=mtls-matrix-trusted-ca" \
    -keyout trusted-ca.key -out trusted-ca.crt

run openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
    -subj "/CN=mtls-matrix-untrusted-ca" \
    -keyout untrusted-ca.key -out untrusted-ca.crt

# --- server certificate (SAN=localhost / 127.0.0.1), signed by trusted-ca ----
run openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=localhost" \
    -keyout server.key -out server.csr
cat > server.ext <<'EXT'
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
EXT
run openssl x509 -req -in server.csr -CA trusted-ca.crt -CAkey trusted-ca.key \
    -CAcreateserial -days "$DAYS" -sha256 -extfile server.ext \
    -out server.crt
rm server.csr server.ext

# --- trusted client certificate ----------------------------------------------
run openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=mtls-matrix-client, O=trusted" \
    -keyout client.key -out client.csr
run openssl x509 -req -in client.csr -CA trusted-ca.crt -CAkey trusted-ca.key \
    -CAcreateserial -days "$DAYS" -sha256 -out client.crt
rm client.csr

# --- client certificate from the unrelated CA --------------------------------
run openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=mtls-matrix-client, O=untrusted" \
    -keyout client-untrusted.key -out client-untrusted.csr
run openssl x509 -req -in client-untrusted.csr \
    -CA untrusted-ca.crt -CAkey untrusted-ca.key \
    -CAcreateserial -days "$DAYS" -sha256 -out client-untrusted.crt
rm client-untrusted.csr

chmod 600 *.key
echo
echo "PKI ready in: $PWD"
ls -1
