"""
Optional TLS policy support for PostgreSQL connections.

A `PostgresTLSPolicy` lets an application approve a single host and a single
CA for a connection pool. Every connection created by the pool then verifies
the certificate chain against the approved CA and matches the certificate
against the approved hostname.
"""
import ssl
import typing
from urllib.parse import parse_qsl

if typing.TYPE_CHECKING:  # pragma: no cover
    from databases.core import DatabaseURL


class TLSPolicyError(ValueError):
    """
    Raised when a TLS policy cannot be applied to a connection configuration,
    for example because of conflicting settings, an unconfirmable driver,
    or a target host that does not match the approved host.
    """


# Query/keyword options that influence the transport security of a connection.
TRANSPORT_OPTIONS = frozenset(
    {"ssl", "sslmode", "sslrootcert", "sslcert", "sslkey", "sslcrl"}
)

_SSL_ENABLE_VALUES = {"true", "1", "yes", "on", "require", "verify-ca", "verify-full"}
_SSL_DISABLE_VALUES = {"false", "0", "no", "off", "disable"}
_SSLMODE_VERIFY_VALUES = {"require", "verify-ca", "verify-full"}


class PostgresTLSPolicy:
    """
    An approved TLS policy for a PostgreSQL connection pool.

    `hostname` is the single host the application approves connecting to, and
    `ca` is the path to the PEM file holding the approved CA certificate.
    """

    def __init__(self, hostname: str, ca: str) -> None:
        if not hostname:
            raise ValueError("PostgresTLSPolicy requires a hostname.")
        if not ca:
            raise ValueError("PostgresTLSPolicy requires a CA file.")
        self.hostname = hostname
        self.ca = ca

    def create_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.ca
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(hostname={self.hostname!r}, ca={self.ca!r})"


def resolve_postgres_tls(
    policy: PostgresTLSPolicy,
    database_url: "DatabaseURL",
    keyword_options: typing.Dict[str, typing.Any],
) -> ssl.SSLContext:
    """
    Validate a connection configuration against an approved TLS policy and
    return the SSL context that the driver must use for new connections.

    Raises `TLSPolicyError`, identifying the source of the problem, before
    any pool is created when the configuration conflicts with the policy or
    cannot be confirmed.
    """
    url_settings = _url_transport_settings(database_url)
    keyword_settings = {
        key: value
        for key, value in keyword_options.items()
        if key in TRANSPORT_OPTIONS
    }

    hostname = database_url.hostname
    if not hostname:
        raise TLSPolicyError(
            "TLS policy cannot confirm the target host: the connection URL "
            f"{database_url.obscure_password!r} does not include a hostname."
        )
    if hostname != policy.hostname:
        raise TLSPolicyError(
            f"TLS policy approves host {policy.hostname!r} but the connection "
            f"URL targets host {hostname!r}."
        )

    for key, value in url_settings.items():
        _check_transport_setting(policy, key, value, source="connection URL")
    for key, value in keyword_settings.items():
        _check_transport_setting(policy, key, value, source="keyword argument")

    return policy.create_ssl_context()


def _url_transport_settings(database_url: "DatabaseURL") -> typing.Dict[str, str]:
    settings: typing.Dict[str, str] = {}
    query = database_url.components.query
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key not in TRANSPORT_OPTIONS:
            continue
        if key in settings:
            raise TLSPolicyError(
                "TLS policy cannot confirm the transport settings: option "
                f"{key!r} is repeated in the connection URL."
            )
        settings[key] = value
    return settings


def _check_transport_setting(
    policy: PostgresTLSPolicy, key: str, value: typing.Any, source: str
) -> None:
    if key == "ssl":
        if value is True:
            return
        if value is False or isinstance(value, ssl.SSLContext):
            raise _conflict(policy, key, value, source)
        normalized = str(value).lower()
        if normalized in _SSL_ENABLE_VALUES:
            return
        if normalized in _SSL_DISABLE_VALUES:
            raise _conflict(policy, key, value, source)
        raise TLSPolicyError(
            "TLS policy cannot confirm the transport settings: "
            f"{_setting(key, value, source)}."
        )
    if key == "sslmode":
        if str(value).lower() in _SSLMODE_VERIFY_VALUES:
            return
        raise _conflict(policy, key, value, source)
    if key == "sslrootcert":
        if str(value) == policy.ca:
            return
        raise TLSPolicyError(
            f"TLS policy conflict: {_setting(key, value, source)} but the "
            f"policy approves CA {policy.ca!r}."
        )
    # 'sslcert', 'sslkey' and 'sslcrl' are managed by the policy itself.
    raise TLSPolicyError(
        f"TLS policy conflict: {_setting(key, value, source)}; the policy "
        "manages the certificate configuration."
    )


def _setting(key: str, value: typing.Any, source: str) -> str:
    return f"{source} sets {key}={value!r}"


def _conflict(
    policy: PostgresTLSPolicy, key: str, value: typing.Any, source: str
) -> TLSPolicyError:
    return TLSPolicyError(
        f"TLS policy conflict: {_setting(key, value, source)}, which would "
        "disable the certificate and hostname verification approved for "
        f"host {policy.hostname!r}."
    )
