.. currentmodule:: flask_session

Security
==========

.. warning::

  Flask is a micro-framework and does not provide all security features out of the box. It is important to configure security settings for your application.
  
Flask configuration
--------------------

Please refer to documentation for `Flask`_, `OWASP`_, and other resources such as `MDN`_ for the latest information on best practice.

Consider the following Flask configurations in production:

.. list-table::
   :header-rows: 1
   :align: left

   * - Setting
     - Consideration
   * - SESSION_COOKIE_SECURE
     - Set to ``True`` if your application is served over HTTPS.
   * - SESSION_COOKIE_NAME
     - Use ``__Secure-`` or ``__Host-`` prefix according to MDN docs.
   * - SESSION_COOKIE_SAMESITE
     - Use ``Lax`` or ``Strict``

You can use a security plugin such as `Flask-Talisman`_ to set these and more.

Storage
------------------

Take care to secure your storage and storage client connection. For example, setup SSL/TLS and storage authentication.
  

Session fixation
------------------

Session fixation is an attack that permits an attacker to hijack a valid user session. The attacker can fixate a user's session by providing them with a session identifier. The attacker can then use the session identifier to impersonate the user.
As one tool among others that can mitigate session fixation, is regenerating the session identifier when a user logs in. This can be done by calling the :meth:`flask.Flask.session_interface.regenerate` method. This method is defined in :class:`flask_session.base.ServerSideSession`.

.. code-block:: python

    @app.route('/login')
    def login():
        # your login logic ...
        app.session_interface.regenerate(session)
        # your response ...


Read-only endpoints
-------------------

Some endpoints only need to inspect the session (for example status, health or
reporting endpoints) and must not extend its lifetime or update the backend.
Configure ``SESSION_READONLY_ENDPOINTS`` to mark such endpoints as read-only
per Flask endpoint name, wildcard pattern, regular expression or callable.

A read-only request:

- can read session data as usual, and the response still sends
  ``Vary: Cookie`` when the session is accessed;
- never writes to the session backend, so neither the stored data nor its TTL
  changes and no session cookie is issued;
- raises :class:`~flask_session.base.ReadOnlySessionError` if business code
  attempts to modify the session. The error message identifies the endpoint and
  the exact rule that blocked the write.

Endpoints that are not selected by a rule remain fully writable, including
routes explicitly configured by the application.

.. _Flask: https://flask.palletsprojects.com/en/2.3.x/security/#set-cookie-options
.. _MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
.. _OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
.. _Flask-Talisman: https://github.com/wntrblm/flask-talisman