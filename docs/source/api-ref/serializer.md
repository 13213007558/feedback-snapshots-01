# serializer

```{eval-rst}
.. autoclass:: opensearchpy.JSONSerializer
```

```{eval-rst}
.. autoclass:: opensearchpy.serializer.Deserializer
```

```{eval-rst}
.. autoclass:: opensearchpy.serializer.Serializer
```

## Response media types

Each request can declare the response media types it accepts through the
`allowed_mimetypes` argument on a client method (for example
`client.search(allowed_mimetypes=("application/json",))`),
`client.http.get(...)`, or `Transport.perform_request(...)`. The value is a
collection of media type strings, or a mapping of media type to a decoder to
use for that one operation. It is a local client setting and is never sent to
the server as a query parameter or header.

Client methods default to JSON only, except `cat` endpoints and
`nodes.hot_threads`, which also accept `text/plain` because they answer with
text unless `format=json` is requested. Plugin namespaces keep the decoders
registered on the client available. Passing `None` explicitly also keeps every
registered decoder available. A response whose declared type is not allowed
raises `UnsupportedResponseFormatError`, a subclass of `SerializationError`,
without calling any decoder.

Media type comparison ignores parameters such as `charset` and
`application/vnd.elasticsearch+json` is treated as `application/json`. When a
response has no `Content-Type`, the declared policy is applied to the client's
configured default media type (`application/json` unless changed with
`default_mimetype=`). Responses to `HEAD` and empty response bodies keep their
existing behavior.

