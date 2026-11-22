# Search Result Diagnostics

Operational troubleshooting often needs a small, reviewable excerpt of a search
response. The helpers in `opensearchpy.helpers.diagnostics` collect such an
excerpt through a passive wrapper around an existing result stream. They never
issue `search`, `scroll` or `clear_scroll` calls themselves, never read a page
ahead of the application and never keep complete documents.

## Configuring The Summary

Only explicitly listed field paths are copied. Dotted paths address nested
values, and no wildcards are expanded:

```python
from opensearchpy import DiagnosticConfig

config = DiagnosticConfig(
    fields=("title", "status", "request.user.name"),
    max_samples=3,   # stop retaining samples after this many
    max_errors=8,    # bound the value-free error list
)
```

If any configured field fails to decode, that record is not sampled at all.
The summary records only the record index, the field path and the exception
class -- never the offending value.

## Sampling A Paginated Scan

```python
from opensearchpy import helpers

stream = helpers.scan_with_summary(
    client,
    index="orders-*",
    fields=("title", "status"),
    max_samples=2,
    query={"query": {"match_all": {}}},
)

for hit in stream:
    process(hit)  # real, unmodified hit

logger.info("search summary: %s", stream.summary.to_dict())
```

`scan_with_summary` accepts the same keyword arguments as
`helpers.scan`, so pagination, `scroll`, `size` and `scroll_kwargs` keep their
usual meaning. The sampler observes a hit only when the application asks for
it; stopping early leaves later pages unread.

## Wrapping Any Result Stream

Use `sample_results` for synchronous iterators and `async_sample_results` for
asynchronous ones:

```python
from opensearchpy.helpers import async_sample_results

stream = async_sample_results(
    async_search.scan(), fields=("title",), max_samples=2
)
async for hit in stream:
    await process(hit)
```

The same bounded summary is available on the async sampler through
`stream.summary.to_dict()`.
