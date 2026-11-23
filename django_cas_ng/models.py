from importlib import import_module

from cas import CASError
from django.conf import settings
from django.db import models
from django.http import HttpRequest

from .utils import (
    get_auth_session_id,
    get_cas_client,
    get_user_from_session,
    live_auth_session_ids,
)

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


SESSION_KEY_MAXLENGTH = 736
AUTH_SESSION_ID_MAXLENGTH = 64


class ProxyError(ValueError):
    pass


class ProxyGrantingTicket(models.Model):
    class Meta:
        unique_together = ('session_key', 'user')
    session_key = models.CharField(
        max_length=SESSION_KEY_MAXLENGTH,
        blank=True, null=True)
    auth_session_id = models.CharField(
        max_length=AUTH_SESSION_ID_MAXLENGTH,
        blank=True, null=True, db_index=True)
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
        # Build the set of live authentication sessions once for the table
        # instead of resolving every ticket separately.
        live_ids = live_auth_session_ids()
        for pgt in cls.objects.all():
            if pgt.auth_session_id:
                if pgt.auth_session_id in live_ids:
                    continue
                pgt.delete()
                continue
            session = SessionStore(session_key=pgt.session_key)
            user = get_user_from_session(session)
            if not user.is_authenticated:
                pgt.delete()

    @classmethod
    def retrieve_pt(cls, request: HttpRequest, service: str) -> str:
        """`request` should be the current HttpRequest object
        `service` a string representing the service for witch we want to
        retrieve a ticket.
        The function return a Proxy Ticket or raise `ProxyError`
        """
        auth_session_id = get_auth_session_id(request.session)
        try:
            if auth_session_id:
                pgt = cls.objects.get(
                    user=request.user,
                    auth_session_id=auth_session_id,
                ).pgt
            else:
                pgt = cls.objects.get(
                    user=request.user,
                    session_key=request.session.session_key[:SESSION_KEY_MAXLENGTH]
                ).pgt
        except cls.DoesNotExist:
            raise ProxyError(
                "INVALID_TICKET",
                "No proxy ticket found for this HttpRequest object"
            )
        else:
            client = get_cas_client(service_url=service, request=request)
            try:
                return client.get_proxy_ticket(pgt)
            # change CASError to ProxyError nicely
            except CASError as error:
                raise ProxyError(*error.args)
            # just embed other errors
            except Exception as e:
                raise ProxyError(e)


class SessionTicket(models.Model):
    session_key = models.CharField(max_length=SESSION_KEY_MAXLENGTH)
    auth_session_id = models.CharField(
        max_length=AUTH_SESSION_ID_MAXLENGTH,
        blank=True, null=True, db_index=True)
    ticket = models.CharField(max_length=1024)

    @classmethod
    def clean_deleted_sessions(cls) -> None:
        live_ids = live_auth_session_ids()
        for st in cls.objects.all():
            if st.auth_session_id:
                if st.auth_session_id in live_ids:
                    continue
                st.delete()
                continue
            session = SessionStore(session_key=st.session_key)
            user = get_user_from_session(session)
            if not user.is_authenticated:
                st.delete()
