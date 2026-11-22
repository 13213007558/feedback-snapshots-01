import typing
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field

from databases.interfaces import DatabaseBackend

if typing.TYPE_CHECKING:  # pragma: no cover
    from databases.core import Database, DatabaseURL

__all__ = [
    "ConnectionValidationContext",
    "ConnectionValidationError",
    "ConnectionValidator",
    "RequireTLS",
    "TLSConfigurationError",
    "TLSRule",
    "UnsupportedDriverError",
]


class ConnectionValidationError(Exception):
    """
    Raised before a backend opens a connection when a validation rule rejects
    the selected driver or its effective configuration.
    """

    def __init__(
        self,
        message: str,
        *,
        driver: typing.Optional[str] = None,
        option: typing.Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.driver = driver
        self.option = option


class UnsupportedDriverError(ConnectionValidationError):
    """The selected driver cannot provide the required transport."""


class TLSConfigurationError(ConnectionValidationError):
    """The effective TLS configuration is missing, conflicting, or unapproved."""


@dataclass(frozen=True)
class ConnectionValidationContext:
    """
    The connection a rule is about to approve.

    ``driver`` is the driver the backend will actually use. It is not simply
    the value from the URL: bare URLs such as ``postgresql://`` are resolved to
    a concrete backend driver, and an unrecognized ``dialect+driver`` URL falls
    back to the dialect's default backend. ``requested_driver`` keeps the value
    spelled in the URL so a rule can reject that fallback.

    ``options`` is the effective configuration after application keyword
    arguments have been merged over URL query parameters. ``url_options`` and
    ``application_options`` retain both sources so a rule can detect overrides.
    """

    database: "Database"
    url: "DatabaseURL"
    backend: DatabaseBackend
    driver: str
    requested_driver: str
    options: typing.Dict[str, typing.Any]
    url_options: typing.Dict[str, typing.Any]
    application_options: typing.Dict[str, typing.Any]

    @property
    def driver_mismatch(self) -> bool:
        return bool(self.requested_driver) and self.requested_driver != self.driver


class ConnectionValidator(typing.Protocol):
    """
    A callable invoked with a :class:`ConnectionValidationContext` before the
    backend opens a connection.

    Raise :class:`ConnectionValidationError` (or a subclass) to reject the
    connection. For convenience, returning ``False`` is also treated as a
    rejection; returning ``None`` or ``True`` accepts it.
    """

    def __call__(self, context: ConnectionValidationContext) -> typing.Any: ...


ValidatorInput = typing.Union[
    ConnectionValidator,
    typing.Iterable[ConnectionValidator],
    None,
]

_TRUE_TLS_MODES = frozenset({"true", "1", "yes", "on", "required", "require"})
_FALSE_TLS_MODES = frozenset({"false", "0", "no", "off", "disable", "disabled"})
_DEFAULT_TLS_MODES = frozenset({"require", "verify-ca", "verify-full"})
_KNOWN_TLS_DRIVERS = frozenset({"asyncpg", "aiopg", "aiomysql", "asyncmy"})

_MISSING = object()


def normalize_validators(
    validators: ValidatorInput,
) -> typing.Tuple[ConnectionValidator, ...]:
    """Normalize a single rule or iterable of rules into a tuple."""
    if validators is None:
        return ()
    if callable(validators):
        return (typing.cast(ConnectionValidator, validators),)
    if isinstance(validators, (str, bytes)):
        raise TypeError(
            "validator must be a callable or an iterable of callables, not a string"
        )

    try:
        rules = tuple(validators)
    except TypeError as exc:
        raise TypeError(
            "validator must be a callable or an iterable of callables"
        ) from exc

    for rule in rules:
        if not callable(rule):
            raise TypeError("every connection validator must be callable")
    return rules


def _tls_mode(value: typing.Any) -> str:
    """
    Reduce a driver TLS value to a comparable mode name.

    Unknown values become ``"custom"`` so the default policy refuses them, but
    a custom rule can still inspect them directly from the context.
    """
    if value is None:
        return "disabled"
    if isinstance(value, bool):
        return "require" if value else "disabled"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_TLS_MODES:
            return "require"
        if normalized in _FALSE_TLS_MODES:
            return "disabled"
        return normalized
    if isinstance(value, MappingABC):
        if not value:
            return "disabled"
        mode = value.get("mode")
        if isinstance(mode, str):
            return _tls_mode(mode)
        return "custom"
    return "custom"


@dataclass(frozen=True)
class RequireTLS:
    """
    Require an explicit, approved TLS configuration on the selected driver.

    A rule instance can be passed directly to ``Database(..., validator=...)``
    or included in a list of validators. It checks, in order:

    * the URL did not request a driver that the backend silently replaced;
    * the backend/driver declares TLS support;
    * URL and application options do not disagree about the TLS setting;
    * the effective setting is present and one of ``allowed_modes``.

    SQLite and other drivers without TLS support are rejected. A plain SQLite
    connection with no validator configured is not affected and never runs
    these checks.
    """

    option: str = "ssl"
    allowed_modes: typing.AbstractSet[str] = field(
        default_factory=lambda: _DEFAULT_TLS_MODES
    )
    reject_overrides: bool = True
    enforce_driver: bool = True
    allow_custom: bool = False

    def __post_init__(self) -> None:
        normalized = frozenset(_tls_mode(mode) for mode in self.allowed_modes)
        if not normalized:
            raise ValueError("allowed_modes must not be empty")
        object.__setattr__(self, "allowed_modes", normalized)

    def __call__(self, context: ConnectionValidationContext) -> None:
        driver = context.driver or context.requested_driver

        if self.enforce_driver and context.driver_mismatch:
            raise UnsupportedDriverError(
                "Requested driver {requested!r} would not be used; this backend "
                "selects {driver!r}. Refusing to open a validated connection "
                "over a different transport.".format(
                    requested=context.requested_driver, driver=context.driver
                ),
                driver=context.driver,
                option=self.option,
            )

        supports_tls = getattr(context.backend, "supports_tls", None)
        if supports_tls is None:
            supports_tls = driver in _KNOWN_TLS_DRIVERS
        if not supports_tls:
            raise UnsupportedDriverError(
                "Driver {driver!r} does not support TLS connections; a "
                "validated connection requires an approved TLS transport.".format(
                    driver=driver
                ),
                driver=driver,
                option=self.option,
            )

        if self.reject_overrides:
            url_value = context.url_options.get(self.option, _MISSING)
            application_value = context.application_options.get(self.option, _MISSING)
            if url_value is not _MISSING and application_value is not _MISSING:
                if _tls_mode(url_value) != _tls_mode(application_value):
                    raise TLSConfigurationError(
                        "Conflicting {option!r} settings: the URL requests "
                        "{url_value!r} while application options request "
                        "{application_value!r}. Refusing to guess which "
                        "configuration is approved.".format(
                            option=self.option,
                            url_value=url_value,
                            application_value=application_value,
                        ),
                        driver=driver,
                        option=self.option,
                    )

        if self.option not in context.options:
            raise TLSConfigurationError(
                "Driver {driver!r} received no {option!r} setting. A validated "
                "connection requires an explicit TLS configuration.".format(
                    driver=driver, option=self.option
                ),
                driver=driver,
                option=self.option,
            )

        mode = _tls_mode(context.options[self.option])
        if mode == "custom" and self.allow_custom:
            return
        if mode not in self.allowed_modes:
            raise TLSConfigurationError(
                "Driver {driver!r} received {option}={value!r}, which resolves "
                "to TLS mode {mode!r}; approved modes are {allowed!r}.".format(
                    driver=driver,
                    option=self.option,
                    value=context.options[self.option],
                    mode=mode,
                    allowed=sorted(self.allowed_modes),
                ),
                driver=driver,
                option=self.option,
            )


#: Convenience alias for callers that prefer the rule-oriented name.
TLSRule = RequireTLS
