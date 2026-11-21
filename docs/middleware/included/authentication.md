# Authentication

The `Faraday::Request::Authorization` middleware allows you to automatically add an `Authorization` header
to your requests. It also features a handy helper to manage Basic authentication.
**Please note the way you use this middleware in Faraday 1.x is different**,
examples are available at the bottom of this page.

```ruby
Faraday.new(...) do |conn|
  conn.request :authorization, 'Bearer', 'authentication-token'
end
```

### With a proc

You can also provide a proc, which will be evaluated on each request:

```ruby
Faraday.new(...) do |conn|
  conn.request :authorization, 'Bearer', -> { MyAuthStorage.get_auth_token }
end
```

If the proc takes an argument, it will receive the forwarded `env` (see [The Env Object](getting-started/env-object.md)):

```ruby
Faraday.new(...) do |conn|
  conn.request :authorization, 'Bearer', ->(env) { MyAuthStorage.get_auth_token(env) }
end
```

### With a credential provider

For credentials that are issued inside the application and can be rotated while
requests are in flight, pass a `Faraday::Request::Authorization::CredentialProvider`
instead of a proc. The middleware asks the provider for an *explicit* decision for
each request, and asks again when a request is retried, so a rotated or revoked
credential is reconfirmed before anything is sent again.

Subclass `CredentialProvider` and implement `#fetch_credential(env, state)`,
returning either an approved or a denied `CredentialResult`:

```ruby
class TokenProvider < Faraday::Request::Authorization::CredentialProvider
  def fetch_credential(env, state)
    token = TokenStore.current
    if token.usable?(env)
      # The version is pinned for the whole request, including retries.
      Faraday::Request::Authorization::CredentialResult
        .approved(token.value, version: token.version)
    else
      Faraday::Request::Authorization::CredentialResult
        .denied('token has been rotated')
    end
  end
end

Faraday.new(...) do |conn|
  conn.request :authorization, 'Bearer', TokenProvider.new
end
```

A single provider instance can be shared across the connection and therefore across
many concurrent requests. It records, per request id:

- how many times it was consulted (`fetch_count`),
- the credential `version` pinned on the first approved lookup and reused on a
  legitimate retry,
- and whether an outbound attempt happened (`outbound_attempted?`).

When the provider denies a request, the middleware raises
`Faraday::Request::Authorization::CredentialDeniedError` and no credential is sent.
A header set explicitly on the request still takes precedence and the provider is
not consulted for it.

### Basic Authentication

The middleware will automatically Base64 encode your Basic username and password:

```ruby
Faraday.new(...) do |conn|
  conn.request :authorization, :basic, 'username', 'password'
end
```

### Faraday 1.x usage

In Faraday 1.x, the way you use this middleware is slightly different:

```ruby
# Basic Auth request
# Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
Faraday.new(...) do |conn|
  conn.request :basic_auth, 'username', 'password'
end

# Token Auth request
# `options` are automatically converted into `key=value` format
# Authorization: Token authentication-token <options>
Faraday.new(...) do |conn|
  conn.request :token_auth, 'authentication-token', **options
end

# Generic Auth Request
# Authorization: Bearer authentication-token
Faraday.new(...) do |conn|
  conn.request :authorization, 'Bearer', 'authentication-token'
end
```
