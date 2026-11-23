
Proxy Granting Ticket
---------------------

If you want your application to be able to issue Proxy Ticket to authenticate against some other CAS application,
setup the CAS_PROXY_CALLBACK parameter.
Allow on the CAS config django_cas_ng to act as a Proxy application.
Then after a user has logged in using the CAS, you can retrieve a Proxy Ticket as follow:

..  code-block:: python

    from django_cas_ng.models import ProxyGrantingTicket

    def my_pretty_view(request, ...):
        proxy_ticket = ProxyGrantingTicket.retrieve_pt(request, service)

where ``service`` is the service url for which you want a proxy ticket.

Per-session authorized services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A single CAS user can own several browser sessions at the same time. Proxy
tickets are therefore authorized per session, not for the user as a whole.
Before a session is allowed to delegate to a service, grant it the exact
target service url:

..  code-block:: python

    from django_cas_ng.models import ProxyGrantingTicket

    ProxyGrantingTicket.allow_service(request, service)

The grant is stored against the current session key and is idempotent: a
service only needs to be granted once per session. ``retrieve_pt`` checks the
grant of the session that owns the request and refuses any service that was
not explicitly granted to that session, even if another session of the same
user is allowed to use it.

The session is also re-checked while the CAS server answers. When a single
logout terminates the session before the proxy ticket is delivered, the
result is discarded instead of being handed to the dead session, and the
service grants of that session are removed.

Errors and retries
^^^^^^^^^^^^^^^^^^

``retrieve_pt`` distinguishes two failure classes so callers know whether a
retry is meaningful:

* ``django_cas_ng.models.ProxyError``: a transient transport failure (timeout,
  connection reset, ...). No decision was made, so the same request may be
  retried.
* ``django_cas_ng.models.ProxyDenied``: a definitive ineligibility decision,
  such as an unauthorized service (``SERVICE_NOT_AUTHORIZED``), a missing
  proxy granting ticket (``INVALID_TICKET``) or a session that has been logged
  out (``SESSION_TERMINATED``). Retrying the same request keeps failing.

..  code-block:: python

    from django_cas_ng.models import ProxyDenied, ProxyError, ProxyGrantingTicket

    try:
        proxy_ticket = ProxyGrantingTicket.retrieve_pt(request, service)
    except ProxyError:
        # Transient transport problem: safe to retry the same request.
        proxy_ticket = ProxyGrantingTicket.retrieve_pt(request, service)
    except ProxyDenied:
        # Definitive decision: do not retry, surface the ineligibility.
        raise

