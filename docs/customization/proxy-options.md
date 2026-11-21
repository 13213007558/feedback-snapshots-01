# Proxy Options

Proxy options can be provided to the connection constructor or set on a per-request basis via [RequestOptions](/customization/request-options.md).
All these options are optional.

| Option      | Type        | Default | Description     |
|-------------|-------------|---------|-----------------|
| `:uri`      | URI, String | nil     | Proxy URL.      |
| `:user`     | String      | nil     | Proxy user.     |
| `:password` | String      | nil     | Proxy password. |

## Example

```ruby
# Proxy options can be passed to the connection constructor and will be applied to all requests.
proxy_options = {
  uri: 'http://proxy.example.com:8080',
  user: 'username',
  password: 'password'
}

conn = Faraday.new(proxy: proxy_options) do |faraday|
  # ...
end

# You can then override them on a per-request basis.
conn.get('/foo') do |req|
  req.options.proxy.update(uri: 'http://proxy2.example.com:8080')
end
```

## Approved proxies

Some requests must go through a proxy that the application chose, such as a
company-approved egress proxy, while the rest may use whatever the development
environment provides. Mark those requests with `proxy_required`:

```ruby
conn.get('/internal') do |req|
  req.options.proxy_required = true
end
```

Such a request only uses a proxy declared by the application, either on the
connection (`Faraday.new(proxy: ...)`), in the request options
(`request: { proxy: ... }`), or in the request block
(`req.options.proxy = ...`). A proxy inferred from the environment, e.g. from
`http_proxy`, does not count. If no approved proxy is available, Faraday raises
`Faraday::ProxyRequiredError` before the request reaches the adapter, so a
managed request is never silently sent directly.

Requests without `proxy_required` keep the usual behaviour: an explicit proxy
wins, then the environment proxy, and if neither is present the request goes
directly. The proxy of one request never leaks into the next one.

To require an approved proxy for every request on a connection, set
`proxy_required` on the connection instead:

```ruby
conn = Faraday.new('http://www.example.com',
                   proxy: 'http://proxy.com',
                   proxy_required: true)
```

See `examples/proxy_required.rb` for a runnable walkthrough with two adapters
that record the env each request receives.
