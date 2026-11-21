- [Authentication](#authentication)
  - [IAM Authentication](#iam-authentication)
  - [IAM Authentication with a Synchronous Client](#iam-authentication-with-a-synchronous-client)
  - [IAM Authentication with an Async Client](#iam-authentication-with-an-async-client)
  - [Refreshing Credentials with a Credential Provider](#refreshing-credentials-with-a-credential-provider)
    - [Credentials on Retries](#credentials-on-retries)
  - [IAM Authentication via Tunnel](#iam-authentication-via-tunnel)
  - [Kerberos](#kerberos)

# Authentication

OpenSearch allows you to use different methods for the authentication via `connection_class` and `http_auth` parameters.

## IAM Authentication

This library supports IAM-based authentication when communicating with OpenSearch clusters running in Amazon Managed OpenSearch and OpenSearch Serverless.

## IAM Authentication with a Synchronous Client

For `Urllib3HttpConnection` use `Urllib3AWSV4SignerAuth`, and for `RequestHttpConnection` use `RequestsAWSV4SignerAuth`.

```python
from opensearchpy import OpenSearch, Urllib3HttpConnection, Urllib3AWSV4SignerAuth
import boto3

host = '' # cluster endpoint, for example: my-test-domain.us-east-1.es.amazonaws.com
region = 'us-west-2'
service = 'es' # 'aoss' for OpenSearch Serverless
credentials = boto3.Session().get_credentials()
auth = Urllib3AWSV4SignerAuth(credentials, region, service)

client = OpenSearch(
    hosts = [{'host': host, 'port': 443}],
    http_auth = auth,
    use_ssl = True,
    verify_certs = True,
    connection_class = Urllib3HttpConnection,
    pool_maxsize = 20
)

index_name = 'test-index'

q = 'miller'

query = {
    'size': 5,
    'query': {
        'multi_match': {
            'query': q,
            'fields': ['title^2', 'director']
        }
    }
}

response = client.search(
    body = query,
    index = index_name
)

print('\nSearch results:')
print(response)
```

## IAM Authentication with an Async Client

Use `AsyncOpenSearch` with the `AsyncHttpConnection` connection class and the async `AWSV4SignerAsyncAuth` signer.

```python
from opensearchpy import AsyncOpenSearch, AsyncHttpConnection, AWSV4SignerAsyncAuth
import boto3

host = '' # cluster endpoint, for example: my-test-domain.us-east-1.es.amazonaws.com
region = 'us-west-2'
service = 'es' # 'aoss' for OpenSearch Serverless
credentials = boto3.Session().get_credentials()
auth = AWSV4SignerAsyncAuth(credentials, region, service)

client = AsyncOpenSearch(
    hosts = [{'host': host, 'port': 443}],
    http_auth = auth,
    use_ssl = True,
    verify_certs = True,
    connection_class = AsyncHttpConnection
)

async def search():
    index_name = 'test-index'

    q = 'miller'
    query = {
        'size': 5,
        'query': {
            'multi_match': {
                'query': q,
                'fields': ['title^2', 'director']
            }
        }
    }

    response = await client.search(
        body = query,
        index = index_name
    )

    print(response)

search()
```

## Refreshing Credentials with a Credential Provider

When credentials are short-lived (for example STS assume-role or web-identity sessions), pass a `CredentialProvider` instead of a static credentials object. The provider is asked for credentials once per outgoing request and the returned credentials are immediately frozen, so every request is signed with one consistent credential view even if the provider rotates credentials while the request is being signed or retried.

```python
from opensearchpy import OpenSearch, Urllib3HttpConnection, Urllib3AWSV4SignerAuth, CredentialProvider, CredentialProviderError
import boto3

class BotoCredentialProvider(CredentialProvider):
    def __init__(self):
        self._session = boto3.Session()

    def get_credentials(self):
        # Refresh the session (or re-assume the role) when the previous
        # credentials have expired. Raising here surfaces a
        # CredentialProviderError to the application instead of sending an
        # unsigned or partially signed request.
        return self._session.get_credentials()

host = '' # cluster endpoint, for example: my-test-domain.us-east-1.es.amazonaws.com
region = 'us-west-2'
service = 'es' # 'aoss' for OpenSearch Serverless
auth = Urllib3AWSV4SignerAuth(BotoCredentialProvider(), region, service)

client = OpenSearch(
    hosts = [{'host': host, 'port': 443}],
    http_auth = auth,
    use_ssl = True,
    verify_certs = True,
    connection_class = Urllib3HttpConnection,
)

try:
    client.info()
except CredentialProviderError:
    # The provider was temporarily unavailable; retry the operation later.
    pass
```

A plain callable returning credentials is accepted as well:

```python
auth = Urllib3AWSV4SignerAuth(lambda: boto3.Session().get_credentials(), region, service)
```

### Credentials on Retries

Retries of the same request reuse the frozen credentials resolved for the first attempt, keeping every attempt identical (`reuse_credentials_on_retry=True`, the default). Pass `reuse_credentials_on_retry=False` to force a fresh credential resolution from the provider before each retry. The same option is available on `RequestsAWSV4SignerAuth` and `AWSV4SignerAsyncAuth`.

```python
auth = Urllib3AWSV4SignerAuth(
    BotoCredentialProvider(),
    region,
    service,
    reuse_credentials_on_retry=False,
)
```

## IAM Authentication via Tunnel

If you're accessing OpenSearch via SSH or SSM tunnel, then you need to specify the Host to be used for signing the AWS requests by passing a "Host" header, like so:


```python
from opensearchpy import OpenSearch, RequestsHttpConnection, RequestsAWSV4SignerAuth, AsyncOpenSearch, AsyncHttpConnection, AWSV4SignerAsyncAuth
import boto3

host = 'localhost' # local endpoint used by the SSH/SSM tunnel
port = 8443
signature_host = 'my-test-domain.eu-west-1.es.amazonaws.com:443' # this needs to be the real host provided by AWS
region = 'eu-west-1'
service = 'es' # 'aoss' for OpenSearch Serverless
credentials = boto3.Session().get_credentials()

# Sync
client = OpenSearch(
    hosts = [{'host': host, 'port': port, 'headers': {'host': signature_host}}],
    http_auth = RequestsAWSV4SignerAuth(credentials, region, service),
    use_ssl = True,
    verify_certs = True,
    connection_class = RequestsHttpConnection,
    pool_maxsize = 20
)

# Async
async_client = AsyncOpenSearch(
    hosts = [{'host': host, 'port': port, 'headers': {'host': signature_host}}],
    http_auth = AWSV4SignerAsyncAuth(credentials, region, service),
    use_ssl = True,
    verify_certs = True,
    connection_class = AsyncHttpConnection
)

```

## Kerberos

There are several python packages that provide Kerberos support over HTTP, such as [requests-kerberos](http://pypi.org/project/requests-kerberos) and [requests-gssapi](https://pypi.org/project/requests-gssapi). The following example shows how to setup Kerberos authentication. 

Note that some of the parameters, such as `mutual_authentication` might depend on the server settings.

```python
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_kerberos import HTTPKerberosAuth, OPTIONAL

client = OpenSearch(
    ['htps://...'],
    use_ssl=True,
    verify_certs=True,
    http_auth=HTTPKerberosAuth(mutual_authentication=OPTIONAL)
)

health = client.cluster.health()
```
