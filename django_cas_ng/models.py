from importlib import import_module

from cas import CASError
from django.conf import settings
from django.db import models
from django.http import HttpRequest
from requests import RequestException

from .utils import get_cas_client, get_user_from_session

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


SESSION_KEY_MAXLENGTH = 736
SERVICE_URL_MAXLENGTH = 1024


class ProxyError(ValueError):
    """A transient failure while talking to the CAS server.

    The request never reached a definitive allow/deny decision (for example a
    network timeout or a connection reset), so the caller is allowed to retry
    the very same request.
    """


class ProxyDenied(PermissionError):
    """A definitive, non-retryable ineligibility decision.

    The current browser session is not allowed to delegate to the requested
    service, or it has been terminated by a (single) logout in the meantime.
    Retrying the same request keeps failing with this error.
    """


class ProxyGrantingTicket(models.Model):
    class Meta:
        unique_together = ('session_key', 'user')
    session_key = models.CharField(
        max_length=SESSION_KEY_MAXLENGTH,
        blank=True, null=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="+",
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )
    pgtiou = models.CharField(max_length=255, null=True, blank=True)
    pgt = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateTimeField(auto_now_add=True)

    @classmethod
    def clean_deleted_sessions(cls) -> None:
        for pgt in cls.objects.all():
            session = SessionStore(session_key=pgt.session_key)
            user = get_user_from_session(session)
            if not user.is_authenticated:
                pgt.delete()

    @classmethod
    def allow_service(cls, request: HttpRequest, service: str) -> None:
        """Grant the current browser session the right to delegate to
        ``service``.

        Grants are scoped to a single browser session rather than to the user
        as a whole, so every session of a CAS user can be assigned its own set
        of services. Re-granting the same service is idempotent.
        """
        session_key = request.session.session_key[:SESSION_KEY_MAXLENGTH]
        SessionServiceGrant.objects.get_or_create(
            session_key=session_key,
            service=service[:SERVICE_URL_MAXLENGTH],
        )

    @classmethod
    def retrieve_pt(cls, request: HttpRequest, service: str) -> str:
        """Return a Proxy Ticket for ``service`` on behalf of the session that
        owns ``request``.

        Admission is decided entirely from the current browser session:

        * the requested ``service`` must have been granted to this session
          before any call is made to the remote CAS server, so the exact target
          service stays under control;
        * the session must still be alive both before the call and once the CAS
          answer comes back. A single logout landing while the CAS server is
          answering therefore invalidates the result and the ticket is never
          handed over to a dead session;
        * transport problems raise :class:`ProxyError`, which the caller may
          retry, while every ineligibility decision raises
          :class:`ProxyDenied`, which a retry cannot turn into a success.
        """
        session_key = request.session.session_key[:SESSION_KEY_MAXLENGTH]

        try:
            pgt_record = cls.objects.get(
                user=request.user,
                session_key=session_key,
            )
        except cls.DoesNotExist:
            raise ProxyDenied(
                "INVALID_TICKET",
                "No proxy granting ticket found for this HttpRequest object",
            )

        if not SessionServiceGrant.objects.filter(
            session_key=session_key, service=service
        ).exists():
            raise ProxyDenied(
                "SERVICE_NOT_AUTHORIZED",
                "This session is not allowed to delegate to the requested "
                "service",
            )

        session = SessionStore(session_key=session_key)
        if not session.exists(session_key):
            raise ProxyDenied(
                "SESSION_TERMINATED",
                "The browser session has been logged out",
            )

        client = get_cas_client(service_url=service, request=request)
        try:
            proxy_ticket = client.get_proxy_ticket(pgt_record.pgt)
        except CASError as error:
            # A definitive answer from the CAS server (bad PGT, rejected
            # service, ...). Retrying the same request cannot change it.
            raise ProxyDenied(*error.args)
        except RequestException as error:
            # The request never completed (timeout, connection reset, ...).
            # Nothing was decided, so the caller may retry.
            raise ProxyError(error)

        # The CAS server may answer after a single logout already destroyed the
        # session. Re-check before handing the ticket over so it can never be
        # delivered to a session that no longer exists.
        if not session.exists(session_key):
            raise ProxyDenied(
                "SESSION_TERMINATED",
                "The browser session was logged out before the proxy ticket "
                "could be delivered",
            )

        return proxy_ticket


class SessionServiceGrant(models.Model):
    """A service that a single browser session is allowed to delegate to.

    Rows are scoped by ``session_key`` so each of a user's browser sessions
    gets an independent, precise allow-list of target services.
    """

    session_key = models.CharField(
        max_length=SESSION_KEY_MAXLENGTH, db_index=True)
    service = models.CharField(max_length=SERVICE_URL_MAXLENGTH)

    class Meta:
        unique_together = ('session_key', 'service')

    @classmethod
    def clean_deleted_sessions(cls) -> None:
        for grant in cls.objects.all():
            session = SessionStore(session_key=grant.session_key)
            user = get_user_from_session(session)
            if not user.is_authenticated:
                grant.delete()


class SessionTicket(models.Model):
    session_key = models.CharField(max_length=SESSION_KEY_MAXLENGTH)
    ticket = models.CharField(max_length=1024)

    @classmethod
    def clean_deleted_sessions(cls) -> None:
        for st in cls.objects.all():
            session = SessionStore(session_key=st.session_key)
            user = get_user_from_session(session)
            if not user.is_authenticated:
                st.delete()
