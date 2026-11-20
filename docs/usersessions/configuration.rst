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

``USERSESSIONS_CLIENT_IP_POLICY`` (default: ``"full"``)
  Determines how much of the client IP address is stored on the user session
  record, and therefore what is shown on the session management page and in the
  headless API:

  * ``"full"``: the IP address as determined by the account adapter is stored
    unchanged.
  * ``"masked"``: only a coarse, network level address is kept, zeroing the host
    part (IPv4 keeps the first three octets, e.g. ``203.0.113.42`` becomes
    ``203.0.113.0``; IPv6 keeps the first 48 bits, e.g.
    ``2001:db8:abcd:1234::1`` becomes ``2001:db8:abcd::``). This preserves a
    rough geographic clue without retaining the exact address.
  * ``"none"``: the IP address is not stored at all (the field is kept empty).

``USERSESSIONS_USER_AGENT_POLICY`` (default: ``"full"``)
  Determines how much of the client user agent is stored on the user session
  record:

  * ``"full"``: the complete user agent string is stored.
  * ``"device"``: only a coarse device category is stored, one of ``Desktop``,
    ``Mobile``, ``Tablet``, ``Crawler`` or ``Unknown``. The full user agent
    string is never persisted.
  * ``"none"``: the user agent is not stored at all (the field is kept empty).

  Both policies are applied at write time, so the raw IP address and full user
  agent never reach the database when ``"masked"``/``"device"`` or ``"none"``
  are configured. Existing records are redacted by the shipped data migration.
  When tightening the policy later on, run the
  ``usersessions_redact_clients`` management command to re-apply the configured
  policy to all historical records. Note that the opaque, server side session
  key is always retained: it is what allows the user to identify and end a
  specific session, regardless of how much client information is displayed.

