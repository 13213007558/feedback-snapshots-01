- [Bulk Indexing](#bulk-indexing)
  - [Line-Delimited JSON](#line-delimited-json)
  - [Bulk Helper](#bulk-helper)
  - [Parallel Bulk](#parallel-bulk)
  - [Data Generator](#data-generator)

# Bulk Indexing

The [Bulk API](https://opensearch.org/docs/latest/api-reference/document-apis/bulk/) lets you add, update, or delete multiple documents in a single request.

## Line-Delimited JSON

The `bulk` API accepts line-delimited JSON. This method requires the caller to evaluate the return value and parse errors in the case of a failure or partial success. See [samples/bulk/bulk_ld.py](../samples/bulk/bulk_ld.py) for a working sample.

```python
from opensearchpy import OpenSearch

client = OpenSearch(...)

docs = '''
{"index": {"_index": "index-2022-06-08", "_id": "1"}}
{"name": "foo"} 
{"index": {"_index": "index-2022-06-09", "_id": "2"}}
{"name": "bar"}
{"index": {"_index": "index-2022-06-10", "_id": "3"}}
{"name": "baz"}
'''

response = client.bulk(docs)
if response["errors"]:
    print(f"There were errors!")
else:
    print(f"Bulk-inserted {len(response['items'])} items.")
```

The client can also serialize an array of data into bulk-delimited JSON for you. See [samples/bulk/bulk_array.py](../samples/bulk/bulk_array.py) for a working sample.

```python
data = [
    { "index": { "_index": "index-2022-06-08", "_id": 1 }},
    { "name": "foo"}, 
    { "index": { "_index": "index-2022-06-09", "_id": 2 }},
    { "name": "bar"},
    { "index": { "_index": "index-2022-06-10", "_id": 3 }},
    { "name": "baz"}
]

response = client.bulk(body=data)
if response["errors"]:
    print(f"There were errors!")
    for item in response["items"]:
        print(f"{item['index']['status']}: {item['index']['error']['type']}")
else:
    print(f"Bulk-inserted {len(response['items'])} items.")
```

## Bulk Helper

A helper can generate the line-delimited JSON for you from a Python array that contains `_index` and `_id` fields, and parse errors. The `helpers.bulk` implementation will raise `BulkIndexError` if any error occurs. This may indicate a partially successful result. See [samples/bulk/bulk_helpers.py](../samples/bulk/bulk_helpers.py) for a working sample.

```python
from opensearchpy import OpenSearch, helpers

client = OpenSearch(...)

docs = [
    { "_index": "words", "_id": "word1", "word": "foo" },
    { "_index": "words", "_id": "word2", "word": "bar" },
    { "_index": "words", "_id": "word3", "word": "baz" },
]

response = helpers.bulk(client, docs, max_retries=3)
print(response)
```

### Restricting target indexes

Import jobs can pass `allowed_indexes` to make the helper verify the real
target of every action before it is sent. A per-action `_index` takes
precedence over the `index` keyword, just as it does for the bulk API. The
option accepts a single index name, a collection of names, or a callable that
receives the resolved index name and returns a boolean.

```python
helpers.bulk(
    client,
    docs,
    index="import-batch-42",
    allowed_indexes={"import-batch-42"},
)
```

Unapproved actions are removed from the chunk before `client.bulk` is called.
With the default `raise_on_error=True`, approved actions in a mixed chunk are
still sent (and keep normal `429` retries), then a `BulkAuthorizationError`
lists the rejected actions. With `raise_on_error=False`, each rejected action
is reported as a failed item with status `403` instead.

## Parallel Bulk

Bulk helpers support `parallel_bulk` which has options to turn off exceptions, chunk size, etc.

```python
succeeded = []
failed = []
for success, item in helpers.parallel_bulk(client, 
    actions=data, 
    chunk_size=10, 
    raise_on_error=False,
    raise_on_exception=False,
    max_chunk_bytes=20 * 1024 * 1024,
    request_timeout=60):
    
    if success:
        succeeded.append(item)
    else:
        failed.append(item)

if len(failed) > 0:
    print(f"There were {len(failed)} errors:")
    for item in failed:
        print(f"{item['index']['error']}: {item['index']['exception']}")

if len(succeeded) > 0:
    print(f"Bulk-inserted {len(succeeded)} items.")
```

## Data Generator

Use a data generator function with bulk helpers instead of building arrays.

```python
def _generate_data():
    for i in range(100):
        yield {"_index": index_name, "_id": i, "value": i}

succeeded = []
failed = []
for success, item in helpers.parallel_bulk(client, actions=_generate_data()):
    if success:
        succeeded.append(item)
    else:
        failed.append(item)

if len(failed) > 0:
    print(f"There were {len(failed)} errors:")
    for item in failed:
        print(item["index"]["error"])

if len(succeeded) > 0:
    print(f"Bulk-inserted {len(succeeded)} items (streaming_bulk).")
```

