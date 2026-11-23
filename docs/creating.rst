.. currentmodule:: jsonschema.validators

.. _creating-validators:

=======================================
Creating or Extending Validator Classes
=======================================

.. autofunction:: create
    :noindex:

.. autofunction:: extend
    :noindex:

.. autofunction:: validator_for
    :noindex:

.. autofunction:: validates
    :noindex:


Isolating Extensions Between Projects
-------------------------------------

Multiple applications can share a single process while each authoring its own
JSON Schema extensions -- for instance a keyword with the same name but a
different meaning per project.
Pass a ``registration_scope_setup`` callable to `create` (or `extend`) to
give a validator class its own registration scope, so the classes it may
switch to are never decided by any other project:

.. code-block:: python

    from jsonschema import validators

    def scope_for(scope):
        return scope.approve(
            "http://json-schema.org/draft-07/schema#",
            validators.Draft7Validator,
        )

    ProjectValidator = validators.extend(
        validators.Draft202012Validator,
        validators={"x-acl": my_extension},
        registration_scope_setup=scope_for,
    )

The returned scope always approves the validator's own dialect, and every
additional dialect is opted in explicitly.  The scope follows the validator
through `Validator.evolve`, through :kw:`$ref` resolution (whether the target
declares its own :kw:`$schema` or not) and through annotation evaluation such
as ``unevaluatedProperties``.

A schema which declares a dialect the scope has not approved raises
`jsonschema.exceptions.UnapprovedDialect` rather than silently switching to a
different validator, so an unapproved extension cannot relax checks.

Validator classes created without a ``registration_scope_setup`` keep the
previous behavior: :kw:`$schema` is resolved against the process-wide
registry of known drafts.

The `RegistrationScope` class itself is available from
`jsonschema.validators` for introspection or for building a scope directly.


Creating Validation Errors
--------------------------

Any validating function that validates against a subschema should call
``descend``, rather than ``iter_errors``. If it recurses into the
instance, or schema, it should pass one or both of the ``path`` or
``schema_path`` arguments to ``descend`` in order to properly maintain
where in the instance or schema respectively the error occurred.

The Validator Protocol
----------------------

``jsonschema`` defines a `protocol <typing.Protocol>`, `jsonschema.protocols.Validator` which can be used in type annotations to describe the type of a validator.

For full details, see `validator-protocol`.
