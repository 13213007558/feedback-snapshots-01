#
# Wiring A: mutual TLS terminated on the Gunicorn listener itself.
#
# Run (loopback only):
#   gunicorn -c gunicorn.mtls.conf.py identity_app:app
#
# The listener owns the whole TLS session, so gunicorn -- not a proxy --
# validates the client certificate against trusted-ca.crt.
#
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PKI = os.path.join(HERE, "pki")

# Server identity presented to every client.
certfile = os.path.join(PKI, "server.crt")
keyfile = os.path.join(PKI, "server.key")

# Client certificate policy:
#   ssl.CERT_REQUIRED  -> handshake aborts when the client offers no cert or
#                         a cert that does not chain to ca_certs.
#   ssl.CERT_OPTIONAL  -> handshake succeeds without a client cert; the app
#                         then sees getpeercert() == {} and can decide itself.
import ssl as _ssl
cert_reqs = _ssl.CERT_REQUIRED

# Trust anchor for client cert chain validation. Passing cafile also makes
# ssl.create_default_context(Purpose.CLIENT_AUTH) verify the chain, dates and
# hostname-independent path; gunicorn never validates a client SAN hostname.
ca_certs = os.path.join(PKI, "trusted-ca.crt")

# ALPN: gthread (or gevent/asgi) is required for h2; the sync worker ignores
# h2 and logs a warning. Order is server preference.
http_protocols = "h2,h1"

# Hardening beyond the defaults; see NewSSLContext in gunicorn/config.py.
def ssl_context(conf, default_ssl_context_factory):
    context = default_ssl_context_factory()
    context.minimum_version = _ssl.TLSVersion.TLSv1_2
    return context
