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
Child tasks do **not** inherit access to an active transaction. Each task acquires its own
connection, and transaction state is only visible to the task that started it.

If a child task needs to share the parent's transaction, the parent must authorize it
explicitly by issuing a handoff:

```python
async def add_excitement(handoff, id: int):
    # The handoff must be used from the single task it is delegated to.
    async with handoff:
        await database.execute(
            "UPDATE notes SET text = text || '!!!' WHERE id = :id",
            {"id": id},
        )

async with Database(database_url) as database:
    async with database.transaction() as transaction:
        # This note won't exist outside the transaction until it commits...
        await database.execute(
            "INSERT INTO notes(id, text) VALUES (1, 'databases is cool')"
        )
        # ...but the delegated task can read and write it through the handoff.
        await asyncio.create_task(
            add_excitement(transaction.handoff(), id=1)
        )

    await database.fetch_val("SELECT text FROM notes WHERE id=1")
    # ^ returns: "databases is cool!!!"
```

A handoff behaves like a capability:

* `transaction.handoff()` may only be called by the task that owns the active
  transaction.
* The handoff is bound to the first task that uses it. Passing it to a sibling
  or reusing it from another task raises `TransactionNotAuthorized`.
* The delegated task may run queries on the transaction's connection, but it
  cannot commit or roll back. Commit and rollback always belong to the owner.
* The handoff is revoked when the owning transaction closes. Using it afterwards
  raises `TransactionHandoffError`.

Without a handoff, a child task that receives the parent's `Connection` and tries
to use it raises `TransactionNotAuthorized`, and reads through `database` go
through the child's own connection and therefore do not see the parent's
uncommitted changes. A connection that has been released cannot be used at all;
doing so raises `ConnectionNotAcquired`.

Databases configured with `force_rollback=True` are the exception: they
intentionally expose one shared connection and transaction to every task, so
that all work is rolled back on disconnect.

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
