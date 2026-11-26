===================
Token introspection
===================

Introspect endpoints read opaque access and/or refresh tokens upon client
request. Also known as tokeninfo.

.. code-block:: python

    # Initial setup
    from your_validator import your_validator
    server = WebApplicationServer(your_validator)

    # Token revocation
    uri = 'https://example.com/introspect'
    headers, body, http_method = {}, 'token=sldafh309sdf', 'POST'

    headers, body, status = server.create_introspect_response(uri,
        headers=headers, body=body, http_method=http_method)

    from your_framework import http_response
    http_response(body, status=status, headers=headers)


Operational delegation
----------------------

Client authentication only proves *which* internal tool is calling.  It does
not prove that the tool may introspect a particular project's tokens.  After
the normal client authentication, the endpoint resolves the token's actual
owning project with ``RequestValidator.get_token_project`` (exposed on the
request as ``request.token_project``) and checks the *current* delegation with
``RequestValidator.validate_introspection_delegation(token, token_type_hint,
request)``.  ``request.delegation_action`` is ``"introspect"``.

Return a collection of claim names from that hook (or from
``RequestValidator.get_introspection_allowed_fields``) to disclose only the
approved fields.  Return ``False``/``None`` and the endpoint answers
``200 {"active": false}`` without calling ``introspect_token`` -- the same
normalized response as for an unknown token, so token existence or ownership
of another project is never disclosed.  The delegation is evaluated on every
request, so withdrawing a grant takes effect immediately even when the client
authentication result is unchanged.


.. autoclass:: oauthlib.oauth2.IntrospectEndpoint
    :members:
