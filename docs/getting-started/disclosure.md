# Disclosure Policy

Faraday can send details about a request to two shared failure channels: the
[`Logger`] middleware and the errors raised by [`RaiseError`]. A **disclosure
policy** lets a connection select, once, which request attributes and error
details those channels may use. It does not change the outbound request, and it
does not change the response object returned to your business code.

## Configuring a policy

Pass a `:disclosure` option to `Faraday.new`:

```ruby
conn = Faraday.new(url: 'https://api.example.com', disclosure: {
  request: %i[method url_path],
  error: %i[message response_body]
}) do |f|
  f.response :logger, nil, { errors: true }
  f.response :raise_error
end
```

The policy is stored with the request defaults, so every request made through
the connection (and every copy made with `Connection#dup`) uses the same rule.
It can also be set later or changed per request:

```ruby
conn.disclosure = { request: %i[method], error: [] }

conn.get('/audit') do |req|
  req.options.disclosure = { request: %i[method url_path], error: %i[message] }
end
```

### Request attributes

`request` selects what the logger may write for the request and what
`RaiseError` may attach to `error.response[:request]`:

| Attribute  | Meaning |
|------------|---------|
| `method`   | HTTP method (`:get`, `:post`, ...) |
| `url`      | Full URL, including the query string |
| `url_path` | Path only, without the query string |
| `params`   | Decoded query parameters |
| `headers`  | Request headers |
| `body`     | Request body |

`request_headers` and `request_body` are accepted as aliases for `headers` and
`body`.

### Error details

`error` selects what the logger may write for a failure and what is kept on the
raised error's response:

| Detail             | Meaning |
|--------------------|---------|
| `message`          | The exception message in the Logger output |
| `response_headers` | Response headers |
| `response_body`    | Response body |
| `wrapped_exception`| Class and message of `Faraday::Error#wrapped_exception` |
| `backtrace`        | Exception backtrace |

`headers`, `body` and `exception` are accepted as aliases for
`response_headers`, `response_body` and `wrapped_exception`.

The response status and the exception class are always disclosed. They are what
makes a failure identifiable, so they are never subject to the policy.

### Omitted and empty selections

* An omitted dimension keeps the historical behavior of the middleware for that
  dimension.
* An explicit empty array (`request: []` or `error: []`) selects nothing for
  that dimension. The response status and the error class are still kept.
* Unknown attribute names raise `ArgumentError` when the policy is configured.
* `disclosure: true` is shorthand for `{ request: [], error: [] }`, the strict
  policy.

## What changes

For a request with the policy shown above:

```ruby
conn.get('/orders?token=secret') do |req|
  req.headers['Authorization'] = 'Bearer secret'
end
# Logger (with bodies and errors enabled):
#   request: GET /orders
#   response: Status 404
# RaiseError:
#   Faraday::ResourceNotFound
#   error.response_status  # => 404
#   error.response_body    # => "..." (selected)
#   error.response_headers # => nil   (not selected)
#   error.response[:request] # => { method: :get, url_path: "/orders" }
```

A successful request still returns the original response: `response.body`,
`response.headers`, `response.env.request_headers` and the URL with its query
string are all available to your code. Only the logger output is projected.

For an error, the response attached to the exception is a new, projected
`Faraday::Response`; the original response object is not modified, so middleware
that reads it (for example a retry middleware) keeps seeing the real data. The
error class and `response_status` are unchanged, so existing `rescue` clauses
continue to work.

## Interplay with `include_request: false`

`RaiseError`'s `include_request: false` remains a hard opt-out. When it is set,
no request attributes are attached to errors or used in error messages, even if
the policy selects some. The logger is unaffected by `include_request`; it
follows only the disclosure policy.

## Related

* [Logging](middleware/included/logging.md)
* [Raising Errors](middleware/included/raising-errors.md)

[`Logger`]: /middleware/included/logging.md
[`RaiseError`]: /middleware/included/raising-errors.md
