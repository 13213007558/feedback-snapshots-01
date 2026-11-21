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

### Basic Authentication

The middleware will automatically Base64 encode your Basic username and password:

```ruby
Faraday.new(...) do |conn|
  conn.request :authorization, :basic, 'username', 'password'
end
```

### Restricting credentials to approved targets

By default the `Authorization` header is added to every request, including requests
sent to an absolute URL on a different host than the connection's. To avoid leaking
credentials to an unauthenticated API reached through the same connection, pass the
`:only` option with one or more approved targets. The decision is made against the
**final URL handed to the adapter**, so relative paths are resolved first.

A string containing a host is matched by origin (`scheme://host:port`, comparing the
components rather than a raw string prefix) and its path prefix; a string without a
host matches a path prefix on any host. A `Regexp` is matched against the full URL.

```ruby
Faraday.new('https://api.example.com') do |conn|
  # Credentials are only sent to https://api.example.com
  conn.request :authorization, 'Bearer', 'authentication-token', only: 'https://api.example.com'
  conn.adapter Faraday.default_adapter
end

conn.get('/profile')                       # includes the Authorization header
conn.get('https://public.example.com/v1')  # no Authorization header
```

`:only` also accepts an array of targets and works with a proc/callable credential:

```ruby
Faraday.new do |conn|
  conn.request :authorization, 'Bearer', -> { MyAuthStorage.token },
               only: ['https://api.example.com/private', %r{\Ahttps://staging\.example\.com/}]
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
