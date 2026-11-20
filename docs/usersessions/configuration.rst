Configuration
=============

Available settings:

``USERSESSIONS_ADAPTER`` (default: ``"allauth.usersessions.adapter.DefaultUserSessionsAdapter"``)
  Specifies the adapter class to use, allowing you to alter certain
  default behaviour.

``USERSESSIONS_TRACK_ACTIVITY`` (default: ``False``)
  Whether or not user sessions are kept updated. User sessions are created at
  login time, but as the user continues to access the site the IP address might
  change. Enabling this setting makes sure that the session is kept track of,
  meaning, the IP address, user agent and last seen timestamp are all kept up to
  date. Cookie-based requests require
  ``allauth.usersessions.middleware.UserSessionsMiddleware`` to be installed.
  Headless app requests, including the Django REST framework and Django Ninja
  integrations, also track activity for authenticated sessions. JWT access tokens
  require ``HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED`` for activity tracking in
  these integrations; stateless access token validation does not access the
  session. Successful JWT refreshes also update the session's activity.

Ending a session always takes precedence over activity tracking. If a session is
ended while a request from that session is still in flight, the ending is
remembered so that the late request -- and any later request presenting the same
session -- cannot resurrect the session nor bring its activity record back. The
ended session stays out of the session list, and authentication using that
session is rejected. These markers are kept in the Django cache for the duration
of ``SESSION_COOKIE_AGE``; ensure the configured cache backend (``CACHES``)
persists values, as ``django.core.cache.backends.dummy.DummyCache`` does not.
