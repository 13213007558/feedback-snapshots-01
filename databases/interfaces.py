import typing
from collections.abc import Sequence

from sqlalchemy.sql import ClauseElement


class DatabaseBackend:
    #: The concrete async driver used by this backend. Backends that are
    #: selected from a bare dialect URL (for example ``postgresql://``)
    #: should define this so callers can see the driver that was actually
    #: chosen, not just the driver spelled in the URL.
    driver: typing.Optional[str] = None

    #: Whether this backend can carry a TLS-protected transport. ``None``
    #: means the backend has not declared its capability; validation rules
    #: that require TLS should treat that as unsupported.
    supports_tls: typing.Optional[bool] = None

    async def connect(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def disconnect(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    def connection(self) -> "ConnectionBackend":
        raise NotImplementedError()  # pragma: no cover

    def connection_options(self) -> typing.Dict[str, typing.Any]:
        """
        Return the connection options this backend will pass to its driver.

        Backends merge URL query parameters and application-supplied keyword
        arguments in their own constructors. This method exposes the effective
        result without opening a connection. The default implementation is
        suitable for backends that store the URL as ``_database_url`` and the
        keyword arguments as ``_options``.
        """
        options = self.application_options()
        database_url = getattr(self, "_database_url", None)
        merged = dict(getattr(database_url, "options", {}) or {})
        merged.update(options)
        return merged

    def application_options(self) -> typing.Dict[str, typing.Any]:
        """
        Return the keyword arguments supplied by the application.

        These are the values that override URL query parameters in the
        built-in backends. They are kept separate from
        :meth:`connection_options` so validation rules can tell which
        configuration source supplied a value.
        """
        return dict(getattr(self, "_options", {}) or {})


class ConnectionBackend:
    async def acquire(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def release(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def fetch_all(self, query: ClauseElement) -> typing.List["Record"]:
        raise NotImplementedError()  # pragma: no cover

    async def fetch_one(self, query: ClauseElement) -> typing.Optional["Record"]:
        raise NotImplementedError()  # pragma: no cover

    async def fetch_val(
        self, query: ClauseElement, column: typing.Any = 0
    ) -> typing.Any:
        row = await self.fetch_one(query)
        return None if row is None else row[column]

    async def execute(self, query: ClauseElement) -> typing.Any:
        raise NotImplementedError()  # pragma: no cover

    async def execute_many(self, queries: typing.List[ClauseElement]) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def iterate(
        self, query: ClauseElement
    ) -> typing.AsyncGenerator[typing.Mapping, None]:
        raise NotImplementedError()  # pragma: no cover
        # mypy needs async iterators to contain a `yield`
        # https://github.com/python/mypy/issues/5385#issuecomment-407281656
        yield True  # pragma: no cover

    def transaction(self) -> "TransactionBackend":
        raise NotImplementedError()  # pragma: no cover

    @property
    def raw_connection(self) -> typing.Any:
        raise NotImplementedError()  # pragma: no cover


class TransactionBackend:
    async def start(
        self, is_root: bool, extra_options: typing.Dict[typing.Any, typing.Any]
    ) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def commit(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def rollback(self) -> None:
        raise NotImplementedError()  # pragma: no cover


class Record(Sequence):
    @property
    def _mapping(self) -> typing.Mapping:
        raise NotImplementedError()  # pragma: no cover

    def __getitem__(self, key: typing.Any) -> typing.Any:
        raise NotImplementedError()  # pragma: no cover
