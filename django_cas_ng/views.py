"""CAS login/logout replacement views"""


from datetime import timedelta
from importlib import import_module
from typing import Any, Optional, Set
from urllib import parse as urllib_parse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from .models import SESSION_KEY_MAXLENGTH, ProxyGrantingTicket, SessionTicket
from .signals import cas_user_logout
from .utils import (
    AUTH_SESSION_ID_KEY,
    RedirectException,
    get_auth_session_id,
    get_cas_client,
    get_protocol,
    get_redirect_url,
    get_service_url,
    get_session_keys_for_auth_session,
    get_user_from_session,
    new_auth_session_id,
)

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

__all__ = ['LoginView', 'LogoutView', 'CallbackView']


def clean_next_page(request, next_page):
    """Validate a redirect, rejecting non-local URLs by default."""
    if not next_page:
        return next_page
    if settings.CAS_CHECK_NEXT and not is_local_url(request.build_absolute_uri('/'), next_page):
        raise RedirectException("Non-local url is forbidden to be redirected to.")
    return next_page


def is_local_url(host_url, url):
    """
    :param host_url: is an absolute host url, say https://site.com/
    :param url: is any url
    :return: Is :url: local to :host_url:?
    """
    url = url.strip()
    parsed_url = urllib_parse.urlparse(url)
    if not parsed_url.netloc:
        return True
    parsed_host = urllib_parse.urlparse(host_url)
    if parsed_url.netloc != parsed_host.netloc:
        return False
    if parsed_url.scheme != parsed_host.scheme and parsed_url.scheme:
        return False
    url_path = parsed_url.path if parsed_url.path.endswith('/') else parsed_url.path + '/'
    host_path = parsed_host.path if parsed_host.path.endswith('/') else parsed_host.path + '/'
    return url_path.startswith(host_path)


def _get_login_next_page(request):
    """Choose and validate the configured or requested login redirect."""
    next_url = settings.CAS_LOGIN_NEXT_PAGE or request.GET.get('next')
    return clean_next_page(request, next_url)


class LoginView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().dispatch(request, *args, **kwargs)

    def successful_login(self, request: HttpRequest, next_page: str) -> HttpResponse:
        """
        This method is called on successful login. Override this method for
        custom post-auth actions (i.e, to add a cookie with a token).

        :param request:
        :param next_page:
        :return:
        """
        return HttpResponseRedirect(next_page)

    def post(self, request: HttpRequest) -> HttpResponse:
        next_page = clean_next_page(request, request.POST.get('next', settings.CAS_REDIRECT_URL))
        service_url = get_service_url(request, next_page)
        client = get_cas_client(service_url=service_url, request=request)

        if request.POST.get('logoutRequest'):
            clean_sessions(client, request)
            return HttpResponseRedirect(next_page)

        return HttpResponseRedirect(client.get_login_url())

    def get(self, request: HttpRequest) -> HttpResponse:
        """
        Forwards to CAS login URL or verifies CAS ticket

        :param request:
        :return:
        """
        next_page = _get_login_next_page(request)

        required = request.GET.get('required', False)

        service_url = get_service_url(request, next_page)
        client = get_cas_client(service_url=service_url, request=request)

        if not next_page and settings.CAS_STORE_NEXT and 'CASNEXT' in request.session:
            next_page = request.session['CASNEXT']
            request.session['CASNEXT'] = None

        if not next_page:
            next_page = get_redirect_url(request)

        if request.user.is_authenticated:
            if settings.CAS_LOGGED_MSG is not None:
                message = settings.CAS_LOGGED_MSG % request.user.get_username()
                messages.success(request, message)
            return self.successful_login(request=request, next_page=next_page)

        ticket = request.GET.get('ticket')
        if not ticket:
            if settings.CAS_STORE_NEXT:
                request.session['CASNEXT'] = next_page
            return HttpResponseRedirect(client.get_login_url())

        user = authenticate(ticket=ticket,
                            service=service_url,
                            request=request)
        pgtiou = request.session.get("pgtiou")
        if user is not None:
            auth_login(request, user)

            # from https://code.djangoproject.com/ticket/19147
            if not request.session.session_key:
                request.session.save()

            # Truncate session key to a max of its value length.
            # When using the signed_cookies session backend, the
            # session key can potentially be longer than this.
            session_key = request.session.session_key[:SESSION_KEY_MAXLENGTH]

            if not request.session.exists(session_key):
                request.session.create()
                session_key = request.session.session_key[:SESSION_KEY_MAXLENGTH]

            # One successful CAS login is one authentication session.  The
            # identity travels with the session data, so later key rotations
            # (cycle_key) do not detach the service ticket from its session.
            # Recording a fresh identity also keeps a new login independent
            # from older service tickets and proxy authorization.
            auth_session_id = new_auth_session_id()
            request.session[AUTH_SESSION_ID_KEY] = auth_session_id
            # Persist now so a logout arriving on another request can resolve
            # this authentication session even before this response finishes.
            if request.session.session_key:
                request.session.save()
            session_key = request.session.session_key[:SESSION_KEY_MAXLENGTH]

            # Update only the row for this authentication session, or a legacy
            # row that has no identity yet.  A previous login in the same
            # Django session keeps its own row, so its logout notice can still
            # be matched and reported.
            st = SessionTicket.objects.filter(
                auth_session_id=auth_session_id).first()
            if st is None:
                st = SessionTicket.objects.filter(
                    session_key=session_key,
                    auth_session_id__isnull=True,
                ).first()
            if st is None:
                SessionTicket.objects.create(
                    session_key=session_key,
                    auth_session_id=auth_session_id,
                    ticket=ticket
                )
            else:
                st.ticket = ticket
                st.session_key = session_key
                st.auth_session_id = auth_session_id
                st.save()

            if pgtiou and settings.CAS_PROXY_CALLBACK:
                # Delete old PGT
                ProxyGrantingTicket.objects.filter(
                    user=user,
                    session_key=session_key
                ).delete()
                # Set new PGT ticket
                try:
                    pgt = ProxyGrantingTicket.objects.get(pgtiou=pgtiou)
                    pgt.user = user
                    pgt.session_key = session_key
                    pgt.auth_session_id = auth_session_id
                    pgt.save()
                except ProxyGrantingTicket.DoesNotExist:
                    pass

            if settings.CAS_LOGIN_MSG is not None:
                name = user.get_username()
                message = settings.CAS_LOGIN_MSG % name
                messages.success(request, message)

            return self.successful_login(request=request, next_page=next_page)

        if settings.CAS_RETRY_LOGIN or required:
            return HttpResponseRedirect(client.get_login_url())

        raise PermissionDenied(_('Login failed.'))


class LogoutView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        """
        Redirects to CAS logout page

        :param request:
        :return:
        """
        next_url = getattr(
            settings,
            "CAS_LOGOUT_NEXT_PAGE",
            request.GET.get("next"),
        )
        next_page = clean_next_page(request, next_url)

        # Resolve the CAS authentication session behind this Django session.
        # The key may have been rotated, so the identity stored in session data
        # is what links us to the service ticket and proxy granting ticket.
        session_key = None
        if request.session and request.session.session_key:
            session_key = request.session.session_key[:SESSION_KEY_MAXLENGTH]
        auth_session_id = None
        if request.session:
            auth_session_id = get_auth_session_id(request.session)
        ticket = _find_ticket(auth_session_id, session_key)

        # send logout signal before the session is cleaned up
        cas_user_logout.send(
            sender="manual",
            user=request.user,
            session=request.session,
            ticket=ticket,
            auth_session_id=auth_session_id,
        )

        # clean every session belonging to this authentication session
        _delete_authentication_session(auth_session_id, session_key)
        auth_logout(request)
        next_page = next_page or get_redirect_url(request)
        if settings.CAS_LOGOUT_COMPLETELY:
            if next_page.lower().startswith(("https://", "http://")):
                redirect_url = next_page
            else:
                if hasattr(settings, 'CAS_ROOT_PROXIED_AS') and settings.CAS_ROOT_PROXIED_AS:
                    protocol, host, _, _, _, _ = urllib_parse.urlparse(settings.CAS_ROOT_PROXIED_AS)
                else:
                    protocol = get_protocol(request)
                    host = request.get_host()

                redirect_url = urllib_parse.urlunparse(
                    (protocol, host, next_page, '', '', ''),
                )
            client = get_cas_client(request=request)
            return HttpResponseRedirect(client.get_logout_url(redirect_url))

        # This is in most cases pointless if not CAS_RENEW is set. The user will
        # simply be logged in again on next request requiring authorization.
        return HttpResponseRedirect(next_page)

    def post(self, request: HttpRequest) -> HttpResponse:
        return self.get(request)


class CallbackView(View):
    """
    Read PGT and PGTIOU sent by CAS
    """

    @method_decorator(csrf_exempt)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().dispatch(request, *args, **kwargs)

    def post(self, request: HttpRequest) -> HttpResponse:
        if request.POST.get('logoutRequest'):
            clean_sessions(get_cas_client(request=request), request)
            return HttpResponse("{}\n".format(_('ok')), content_type="text/plain")

        return HttpResponseBadRequest('Missing logoutRequest')

    def get(self, request: HttpRequest) -> HttpResponse:
        pgtid = request.GET.get('pgtId')
        pgtiou = request.GET.get('pgtIou')

        pgt = ProxyGrantingTicket.objects.create(pgtiou=pgtiou, pgt=pgtid)
        pgt.save()

        ProxyGrantingTicket.objects.filter(
            session_key=None,
            date__lt=(timezone.now() - timedelta(seconds=60))
        ).delete()

        return HttpResponse("{}\n".format(_('ok')), content_type="text/plain")


def _find_ticket(
    auth_session_id: Optional[str],
    session_key: Optional[str],
) -> Optional[str]:
    """Return the service ticket for an authentication session, if known."""
    if auth_session_id:
        ticket = SessionTicket.objects.filter(
            auth_session_id=auth_session_id,
        ).values_list('ticket', flat=True).first()
        if ticket:
            return ticket
    if session_key:
        return SessionTicket.objects.filter(
            session_key=session_key,
        ).values_list('ticket', flat=True).first()
    return None


def _get_authentication_session(
    session_keys: Set[str],
    fallback_key: Optional[str],
    auth_session_id: Optional[str] = None,
):
    """
    Load a session belonging to an authentication session.

    Prefer a live session that still has a user, because the key recorded when
    the ticket was redeemed may have been rotated away.  The returned session
    keeps its loaded data, so it can be passed to logout receivers after the
    underlying row has been removed.  When the authentication session has no
    stored session left (for example a newer login replaced it in the same
    Django session), return an empty store instead of the newer session.
    """
    for key in sorted(session_keys):
        session = SessionStore(session_key=key)
        if get_user_from_session(session).is_authenticated:
            return session
    for key in sorted(session_keys):
        session = SessionStore(session_key=key)
        if session.load():
            return session
    if auth_session_id is not None:
        return SessionStore()
    return SessionStore(session_key=fallback_key)


def _delete_authentication_session(
    auth_session_id: Optional[str],
    session_key: Optional[str],
    session_keys: Optional[Set[str]] = None,
) -> Set[str]:
    """
    End one CAS authentication session and remove its authorization data.

    The session identity, not the current Django session key, is authoritative:
    keys may have been rotated since the ticket was redeemed.  All known
    session keys for the identity are deleted so no copy keeps the user logged
    in.  Rows are removed before the sessions so a redelivered logout
    notification cannot find (and report) the same authentication session
    again; the returned set contains the keys that were deleted.
    """
    session_keys = set(session_keys or ())
    session_keys.update(
        get_session_keys_for_auth_session(auth_session_id, session_key))

    tickets = SessionTicket.objects.all()
    if auth_session_id:
        tickets = tickets.filter(
            Q(auth_session_id=auth_session_id)
            | Q(session_key__in=session_keys, auth_session_id__isnull=True))
    elif session_key:
        tickets = tickets.filter(session_key=session_key)
    else:
        tickets = tickets.none()
    session_keys.update(tickets.values_list('session_key', flat=True))
    tickets.delete()

    pgts = ProxyGrantingTicket.objects.all()
    if auth_session_id:
        pgts = pgts.filter(
            Q(auth_session_id=auth_session_id)
            | Q(session_key__in=session_keys, auth_session_id__isnull=True))
    elif session_key:
        pgts = pgts.filter(session_key=session_key)
    else:
        pgts = pgts.none()
    session_keys.update(pgts.values_list('session_key', flat=True))
    pgts.delete()

    deleted_keys = {key for key in session_keys if key}
    for key in deleted_keys:
        SessionStore(session_key=key).delete(key)
    return deleted_keys


def clean_sessions(client, request):
    if not hasattr(client, 'get_saml_slos'):
        return

    logout_request = request.POST.get('logoutRequest')
    if not logout_request:
        return

    for slo in client.get_saml_slos(logout_request) or []:
        ticket = slo.text
        if not ticket:
            continue

        st = SessionTicket.objects.filter(ticket=ticket).first()
        if st is None:
            continue

        session_key = st.session_key
        auth_session_id = st.auth_session_id
        session_keys = get_session_keys_for_auth_session(
            auth_session_id, session_key)
        session = _get_authentication_session(
            session_keys, session_key, auth_session_id)
        user = get_user_from_session(session)

        # Claim the ticket before notifying.  A redelivered notification (or
        # one processed concurrently) then finds no ticket and stays silent, so
        # consumers see exactly one end per authentication session.
        claim = SessionTicket.objects.filter(pk=st.pk)
        if auth_session_id:
            claim = SessionTicket.objects.filter(
                auth_session_id=auth_session_id)
        deleted, _ = claim.delete()
        if not deleted:
            continue

        _delete_authentication_session(
            auth_session_id, session_key, session_keys)

        cas_user_logout.send(
            sender='slo',
            user=user,
            session=session,
            ticket=ticket,
            auth_session_id=auth_session_id,
        )
