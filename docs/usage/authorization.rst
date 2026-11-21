Field Authorization
-------------------

The same schema is often shared between requests with different privileges. Which
fields a request may access can therefore only be decided at execution time, based on
the authenticated runtime context and the concrete runtime type of the resolved value.

GraphQL-core supports this with an optional *field authorizer* that is consulted for
every field **before its resolver runs**. A field that is not authorized is omitted
from the result without ever calling its resolver, so authorization cannot be bypassed
by filtering the response after execution. Allowed fields keep their normal
nullability behavior.

Authorizer interface
~~~~~~~~~~~~~~~~~~~~

A field authorizer is any object implementing the
:class:`~graphql.FieldAuthorizer` protocol. It receives the
:class:`~graphql.GraphQLResolveInfo` of the field that is about to be resolved, whose
``context`` carries the authenticated runtime context, ``parent_type`` the object type
that owns the field, and ``field_name`` the actual schema field name (independent of any
response alias)::

    from graphql import graphql_sync


    class ContextAuthorizer:
        def authorize_field(self, info):
            if info.field_name == "ssn":
                return info.context["role"] == "admin"
            return True

The method returns ``True`` to run the field as usual, or ``False`` to skip it. It may
also return an awaitable resolving to a boolean for asynchronous authorization.

Built-in authorizers
~~~~~~~~~~~~~~~~~~~~

Two concrete authorizers are included.

:class:`~graphql.RuleBasedFieldAuthorizer` takes per-type rules. A rule is either a
boolean or a callable invoked with the field name and owning type::

    from graphql import RuleBasedFieldAuthorizer

    authorizer = RuleBasedFieldAuthorizer(
        {"Query": True, "User": lambda field_name, _type: field_name != "ssn"}
    )

:class:`~graphql.AllowListFieldAuthorizer` grants only the fields on an allow list of
``(type_name, field_name)`` pairs (dot-separated strings such as ``"User.id"`` are also
accepted). The check applies to the concrete runtime object type, which makes it safe
with interfaces and unions::

    from graphql import AllowListFieldAuthorizer

    authorizer = AllowListFieldAuthorizer(
        [("Query", "viewer"), ("User", "id"), ("User", "nickname")]
    )

Built-in meta fields such as ``__typename`` are always allowed. Every other field is
denied unless ``default_decision`` is changed.

Enabling authorization
~~~~~~~~~~~~~~~~~~~~~~

Pass the authorizer through the ``field_authorizer`` argument of any execution entry
point, such as :func:`graphql_sync`::

    result = graphql_sync(
        schema,
        "{ viewer { id nickname ssn } }",
        root_value=root_value,
        context_value={"role": "user"},
        field_authorizer=authorizer,
    )

Given the allow list above, the ``ssn`` resolver never runs and the field is omitted::

    result.data  # {'viewer': {'id': '1', 'nickname': 'Ada'}}

The same argument is accepted by :func:`graphql`, :func:`~graphql.execute`,
:func:`~graphql.execute_sync`,
:func:`~graphql.experimental_execute_incrementally`, :func:`~graphql.subscribe` and
:meth:`~graphql.Executor.build`.
