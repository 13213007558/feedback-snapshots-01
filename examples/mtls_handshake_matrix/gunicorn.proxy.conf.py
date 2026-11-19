#
# Wiring B: TLS terminated by a load balancer / proxy in front of gunicorn.
#
# Run (loopback only):
#   gunicorn -c gunicorn.proxy.conf.py identity_app:app
#
# Gunicorn listens on plain HTTP. It has no certfile/keyfile, so cfg.is_ssl is
# false, no SSLContext is ever built, and environ["gunicorn.socket"] is a raw
# socket rather than an SSLSocket. Identity from the edge arrives as headers,
# and only from peers this instance trusts.
#

# Trust the local proxy only. Peers outside this list have their
# X-Forwarded-* secure-scheme headers ignored (see _peer_trusted_for_forwarded
# in gunicorn/http/message.py); conflicting values from a trusted peer raise
# InvalidSchemeHeaders and the request fails with 400.
forwarded_allow_ips = "127.0.0.1,::1"

# Defaults shown for documentation; these are the built-in values.
secure_scheme_headers = {
    "X-FORWARDED-PROTOCOL": "ssl",
    "X-FORWARDED-PROTO": "https",
    "X-FORWARDED-SSL": "on",
}

# The listener is plaintext, so there is no TLS ALPN: gunicorn only sets ALPN
# when cfg.is_ssl is true (see gunicorn/sock.py::_get_alpn_protocols). Leave
# the default HTTP/1.1 unless the edge is configured to speak cleartext h2c.
# http_protocols = "h2,h1"
# http2_cleartext = "prior-knowledge"  # only accepted from forwarded_allow_ips
http_protocols = "h1"
http2_cleartext = "off"

# If the edge also relays the original L4 endpoint, enable PROXY protocol and
# read REMOTE_ADDR / PROXY_PROTOCOL from the environ instead of X-Forwarded-For.
# proxy_protocol = "v2"
