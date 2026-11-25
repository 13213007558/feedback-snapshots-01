---
order: 3
---

# Available result backends

Result backends are used to store execution results.
This includes:

- return value;
- Execution time in seconds.

## Built-in result backends

### DummyResultBackend

This result backend doesn't do anything. It doesn't store results and cannot be used in cases,
where you need actual results.

This broker will always return `None` for any return_value. Please be careful.

### SecureResultBackend

`SecureResultBackend` separates the state that queue consumers may see from
exception messages and return values that can contain customer data. It writes a
`PublicTaskStatus` to the public sink and keeps full details in a separate,
access-controlled diagnostic sink with a short TTL.

```python
import os

from taskiq import InMemoryBroker, SecureResultBackend

result_backend = SecureResultBackend(
    admin_token=os.environ["TASKIQ_ADMIN_TOKEN"],
    diagnostic_ttl_seconds=60,
)
broker = InMemoryBroker().with_result_backend(result_backend)

status = await task.get_public_status()
# status.status == "failure" | "retrying" | "success"
# status.failure_category is a stable value such as "validation"

redacted_result = await task.get_result()
admin_result = await task.get_admin_result(
    admin_token=os.environ["TASKIQ_ADMIN_TOKEN"],
)
```

Ordinary results contain only the coarse category and a safe placeholder error.
Admin queries require `admin_token` or a short-lived grant. A successful retry
overwrites the public status with `success`; the separate failure diagnostic
remains available to admins only until its TTL expires. Set
`purge_diagnostics_on_success=True` to delete it immediately after success.

The first backend argument can be either a `RecordSink` or a classic
`AsyncResultBackend`. Use separate public and diagnostic sinks in production so
ordinary consumers cannot read the diagnostic store.

## Official result backends

These result backends are not part of the core Taskiq library. But they are maintained by Taskiq developers. You can install them as a separate package.

### Redis result backend

Project link: [taskiq-redis](https://pypi.org/project/taskiq-redis/).

```bash
pip install taskiq-redis
```

### NATS result backend

Project link: [taskiq-nats](https://github.com/taskiq-python/taskiq-nats).

```bash
pip install taskiq-nats
```

### S3 result backend

Project link: [taskiq-sqs](https://github.com/taskiq-python/taskiq-sqs). Provides `S3ResultBackend`.

```bash
pip install taskiq-sqs
```

## Third-party result backends

These result backends are not part of the core Taskiq library. They are maintained by other open‑source contributors. You can install them as separate packages.

### PostgreSQL result backend

Project link: [taskiq-postgresql](https://github.com/z22092/taskiq-postgresql).

```bash
pip install taskiq-postgresql
```

### S3 result backend

Project link: [taskiq-aio-sqs](https://github.com/vonsteer/taskiq-aio-sqs).

```bash
pip install taskiq-aio-sqs
```

### YDB result backend

Project link: [taskiq-ydb](https://github.com/danfimov/taskiq-ydb).

```bash
pip install taskiq-ydb
```
