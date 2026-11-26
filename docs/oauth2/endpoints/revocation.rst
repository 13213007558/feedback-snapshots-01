================
Token revocation
================

Revocation endpoints invalidate access and refresh tokens upon client request.
They are commonly part of the authorization endpoint.

.. code-block:: python

    # Initial setup
    from your_validator import your_validator
    server = WebApplicationServer(your_validator)

    # Token revocation
    uri = 'https://example.com/revoke_token'
    headers, body, http_method = {}, 'token=sldafh309sdf', 'POST'

    headers, body, status = server.create_revocation_response(uri,
        headers=headers, body=body, http_method=http_method)

    from your_framework import http_response
    http_response(body, status=status, headers=headers)


Operational delegation
----------------------

Revocation uses the same client authentication as introspection, followed by a
separate, current delegation check.  The endpoint resolves the token's actual
owning project with ``RequestValidator.get_token_project`` and calls
``RequestValidator.validate_revocation_delegation(token, token_type_hint,
request)`` (``request.delegation_action`` is ``"revoke"``).

Only an affirmative result calls ``RequestValidator.revoke_token`` and changes
real storage.  A ``False``/``None`` result still produces the RFC 7009 empty
``200`` response, indistinguishable from an accepted revocation, but leaves
storage untouched.  Authorized revocation stays repeatable and idempotent.
Delegation is re-evaluated on every request, so a removed grant cannot be
exercised by reusing an earlier successful client authentication.


.. autoclass:: oauthlib.oauth2.RevocationEndpoint
    :members:
