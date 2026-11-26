Creating a Provider
===================

.. contents::
   :depth: 2

1. Create an OIDC provider
--------------------------
If you don't have an OAuth2.0 Provider, you can follow the instructions at
:doc:`OAuth2.0 Creating a Provider </oauth2/server>`. Then, follow the
migration step below.

2. Migrate your OAuth2.0 provider into an OIDC provider
-------------------------------------------------------

If you have a OAuth2.0 provider running and want to upgrade to OIDC, you can
upgrade it by replacing one line of code:

.. code-block:: python

    from oauthlib.oauth2 import Server
    from oauthlib.oauth2 import RequestValidator

Into

.. code-block:: python

    from oauthlib.openid import Server
    from oauthlib.openid import RequestValidator

Then, you have to implement the new `RequestValidator` methods as
shown below.  Note also that a new :doc:`UserInfo endpoint </oauth2/oidc/userinfo>` can be defined
and needs a new controller into your webserver.

3. Extend RequestValidator
--------------------------

A couple of methods must be implemented in your validator subclass if
you wish to support OpenID Connect:

.. autoclass:: oauthlib.openid.RequestValidator
   :members:

Live consent for shared subjects
--------------------------------
Two applications of the same organization can share one OIDC login (and one
subject) while the user approves identity data and ordinary APIs separately.
When the user withdraws a permission for one application, refresh tokens that
application already holds must stop re-issuing that permission, while the
other application of the same subject keeps working.

Implement :meth:`~oauthlib.oauth2.RequestValidator.get_current_scopes` to
report the scopes currently approved for the application bound to a
presented token. It receives the token, a hint (``"refresh_token"`` or
``"access_token"``) and the request, so the lookup is naturally per client.
The refresh grant then issues only the intersection of the token's original
scopes and this result, refuses an explicit request for a withdrawn scope
with ``invalid_scope``, and stops adding an ``id_token`` once ``openid`` is
withdrawn. Resource validation refuses a protected resource whose required
scope was withdrawn, and introspection reports the retained ``scope``.

The hook is optional: returning ``None`` (the default) preserves the previous
behaviour in which the originally granted scopes are used.

.. code-block:: python

    def get_current_scopes(self, token, token_type_hint, request, *args,
                           **kwargs):
        grant = load_token(token, token_type_hint)
        if grant is None:
            return None
        # One row per (client_id, subject): another client of the same user
        # has its own consent and is not affected by this withdrawal.
        return current_consent_scopes(grant.client_id, grant.user)

Preconfigured all-in-one servers
--------------------------------

.. autoclass:: oauthlib.openid.connect.core.endpoints.pre_configured.Server
   :members:
