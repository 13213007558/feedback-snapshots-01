- [SSL](#ssl)
    - [Establishing a Secure Connection](#establishing-a-secure-connection)
    - [Verifying SSL against a Different Host](#verifying-ssl-against-a-different-host)

# SSL

## Establishing a Secure Connection

```python
from opensearchpy import OpenSearch

host = 'localhost'
port = 9200
auth = ('admin', 'admin') # For testing only. Don't store credentials in code.

# Provide a CA bundle if you use intermediate CAs with your root CA.
# If this is not given, the CA bundle is discovered from the first available
# following options:
# - OpenSSL environment variables SSL_CERT_FILE and SSL_CERT_DIR
# - certifi bundle (https://pypi.org/project/certifi/)
# - default behavior of the connection backend (most likely system certs)
ca_certs_path = '/full/path/to/root-ca.pem'

# Optional client certificates if you don't want to use HTTP basic authentication.
# client_cert_path = '/full/path/to/client.pem'
# client_key_path = '/full/path/to/client-key.pem'

# Create the client with SSL/TLS enabled
client = OpenSearch(
    hosts = [{'host': host, 'port': port}],
    http_compress = True, # enables gzip compression for request bodies
    http_auth = auth,
    # client_cert = client_cert_path,
    # client_key = client_key_path,
    use_ssl = True,
    verify_certs = True,
    ssl_assert_hostname = False, # Hostname verification is disabled here, but by default, it will remain enabled.
    ssl_show_warn = False,
    ca_certs = ca_certs_path
)
```
When `ssl_assert_hostname` is set to None, verification is conducted using server hostname, effectively equivalent to not setting ssl_assert_hostname.


## Verifying SSL against a different host

When the server you’re connecting to presents a different certificate than the hostname, you can use ssl_assert_hostname:

```python
from opensearchpy import OpenSearch

host = 'localhost'
port = 9200
auth = ('admin', 'admin')
ca_certs_path = '/full/path/to/root-ca.pem'

client = OpenSearch(
    hosts = [{'host': host, 'port': port}],
    http_compress = True, 
    http_auth = auth,
    use_ssl = True,
    verify_certs = True,
    ssl_assert_hostname = "ssl.com", # Indicate the host name to assert against. By default, it is equal to the server hostname.
    ssl_show_warn = False,
    ca_certs = ca_certs_path
)
```

## Rotating the CA without restarting the client

When the cluster switches to a new CA, the application can load a new
connection policy and atomically replace the live connection pool. New
requests use the new policy while requests that were already delegated to the
old pool finish there. The old pool is closed only after its last in-flight
request returns.

```python
from opensearchpy import ConnectionPolicy, ConnectionPolicyError

def load_company_ca_policy():
    # Read the rotated bundle at reload time, not at process start.
    return ConnectionPolicy(
        hosts=[{"host": "search.internal", "port": 9200}],
        generation="company-ca-2026",
        options={
            "use_ssl": True,
            "verify_certs": True,
            "ca_certs": "/etc/company/company-ca.pem",
        },
    )

try:
    pool = client.transport.reload_connection_policy(load_company_ca_policy)
except ConnectionPolicyError:
    # Loading or validating the new policy failed: the previous pool is
    # still active and keeps serving.
    log.exception("CA rotation failed; keeping the current connection pool")
else:
    log.info("Now using connection generation %s", pool.generation)
```

The policy may be a `ConnectionPolicy`, a mapping with the same fields, or a
zero-argument callable that returns one. The replacement connections are
built and validated before the swap, so a missing CA file, an invalid
`ssl_context`, or a bad host entry raises `ConnectionPolicyError` without
affecting the current pool.

Every connection and pool exposes a `generation` (and a human-readable
`generation_label`), which makes it possible to tell which policy served a
given request. Requests pick their pool once, before the first attempt, and
keep it for all retries of that request.

`AsyncTransport.reload_connection_policy()` provides the same behaviour for
`AsyncOpenSearch`.
