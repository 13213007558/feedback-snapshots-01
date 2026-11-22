# Connections and Transactions

Databases handles database connection pooling and transaction management
with minimal fuss. It'll automatically deal with acquiring and releasing
connections to the pool as needed, and supports a simple transaction API
that transparently handles the use of either transactions or savepoints.

## Connecting and disconnecting

You can control the database connection pool with an async context manager:

```python
async with Database(DATABASE_URL) as database:
    ...
```

Or by using the explicit `.connect()` and `.disconnect()` methods:

```python
database = Database(DATABASE_URL)
await database.connect()
...
await database.disconnect()
```

Connections within this connection pool are acquired for each new `asyncio.Task`.

If you're integrating against a web framework, then you'll probably want
to hook into framework startup or shutdown events. For example, with
[Starlette][starlette] you would use the following:

```python
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
```

## Connection options

The PostgreSQL and MySQL backends provide a few connection options for SSL
and for configuring the connection pool.

```python
# Use an SSL connection.
database = Database('postgresql+asyncpg://localhost/example?ssl=true')

# Use a connection pool of between 5-20 connections.
database = Database('mysql+aiomysql://localhost/example?min_size=5&max_size=20')
```

You can also use keyword arguments to pass in any connection options.
Available keyword arguments may differ between database backends.

```python
database = Database('postgresql+asyncpg://localhost/example', ssl=True, min_size=5, max_size=20)
```

Keyword arguments override URL query parameters. That means the two sources
can disagree without any error by default: the URL may say `ssl=false` while
the application passes `ssl=True`, and only the keyword argument takes effect.

## Connection validation

When a deployment must prove that a connection uses an approved transport, pass
a `validator` to `Database(...)`. Rules run during `connect()` — before the
backend opens a pool — and receive the driver that will actually be used plus
the effective options after both configuration sources are merged.

```python
from databases import (
    Database,
    RequireTLS,
    TLSConfigurationError,
    UnsupportedDriverError,
)

database = Database(
    'postgresql://localhost/example?ssl=verify-full',
    validator=RequireTLS(allowed_modes={"verify-full"}),
)
```

`RequireTLS` rejects:

* a URL whose requested driver is not the driver the backend would use (for
  example an unknown `postgresql+driver` that silently falls back to `asyncpg`);
* backends that cannot carry TLS, such as SQLite;
* URL/application options that disagree about the TLS setting;
* a missing TLS setting, or one whose mode is not approved.

The error is raised before any connection is created and leaves the
`Database` disconnected. A connection with no `validator` is unchanged, so
plain SQLite usage never runs TLS checks.

For finer control, pass any callable that accepts a
`ConnectionValidationContext` and raises `ConnectionValidationError` (or a
subclass such as `TLSConfigurationError` / `UnsupportedDriverError`) to reject
the connection. The context exposes `driver`, `requested_driver`, `options`,
`url_options`, and `application_options`.

```python
def approved_transport(context):
    if context.driver not in {"asyncpg", "aiopg"}:
        raise UnsupportedDriverError("driver not approved", driver=context.driver)
    if context.options.get("ssl") != "verify-full":
        raise TLSConfigurationError("unapproved TLS mode", driver=context.driver)

database = Database(DATABASE_URL, validator=approved_transport, ssl="verify-full")
```

For a fake driver that records what it received, `.backend` and
`.connection_options()` expose the selected backend and its effective options
after construction, without opening a connection.

## Transactions

Transactions are managed by async context blocks.

A transaction can be acquired from the database connection pool:

```python
async with database.transaction():
    ...
```

It can also be acquired from a specific database connection:

```python
async with database.connection() as connection:
    async with connection.transaction():
        ...
```

For a lower-level transaction API:

```python
transaction = await database.transaction()
try:
    ...
except:
    await transaction.rollback()
else:
    await transaction.commit()
```

You can also use `.transaction()` as a function decorator on any async function:

```python
@database.transaction()
async def create_users(request):
    ...
```

Transaction state is tied to the connection used in the currently executing asynchronous task.
If you would like to influence an active transaction from another task, the connection must be
shared. This state is _inherited_ by tasks that share the same connection:

```python
async def add_excitement(connnection: databases.core.Connection, id: int):
    await connection.execute(
        "UPDATE notes SET text = CONCAT(text, '!!!') WHERE id = :id",
        {"id": id}
    )


async with Database(database_url) as database:
    async with database.transaction():
        # This note won't exist until the transaction closes...
        await database.execute(
            "INSERT INTO notes(id, text) values (1, 'databases is cool')"
        )
        # ...but child tasks can use this connection now!
        await asyncio.create_task(add_excitement(database.connection(), id=1))

    await database.fetch_val("SELECT text FROM notes WHERE id=1")
    # ^ returns: "databases is cool!!!"
```

Nested transactions are fully supported, and are implemented using database savepoints:

```python
async with databases.Database(database_url) as db:
    async with db.transaction() as outer:
        # Do something in the outer transaction
        ...

        # Suppress to prevent influence on the outer transaction
        with contextlib.suppress(ValueError):
            async with db.transaction():
                # Do something in the inner transaction
                ...

                raise ValueError('Abort the inner transaction')

    # Observe the results of the outer transaction,
    # without effects from the inner transaction.
    await db.fetch_all('SELECT * FROM ...')
```

Transaction isolation-level can be specified if the driver backend supports that:

```python
async with database.transaction(isolation="serializable"):
    ...
```

[starlette]: https://github.com/encode/starlette
