.. _field_level_disclosure_policy:

Restricting fields before they are read
=======================================

Public APIs often serialize ORM objects whose attributes are more than plain
columns: a property may lazy-load a relationship, decrypt a value, or call
another service. For those objects, *removing a key from the result* is not the
same as *never reading the attribute*. A redaction that runs after the field has
been serialized has already paid the read cost and, more importantly, has
already disclosed the value to every hook in between.

This page compares the two places a disclosure policy can be enforced and shows
how to verify that a sensitive attribute was never read.

Where the value is read
-----------------------

Serialization visits fields in ``Schema.dump_fields`` and
reads each attribute through a single accessor:

#. `Schema.dump <marshmallow.Schema.dump>` invokes ``pre_dump`` hooks, then
   calls ``Schema._serialize``.
#. ``Schema._serialize`` loops over
   ``self.dump_fields`` and calls
   ``field_obj.serialize(attr_name, obj, accessor=self.get_attribute)``.
#. `Field.serialize <marshmallow.fields.Field.serialize>` calls
   `Field.get_value <marshmallow.fields.Field.get_value>` when
   ``_CHECK_ATTRIBUTE`` is true, falling back to ``dump_default`` only when the
   accessor returns ``missing``.
#. `Field.get_value <marshmallow.fields.Field.get_value>` resolves the internal
   key (``self.attribute or attr``) and calls the accessor.
#. The accessor is `Schema.get_attribute <marshmallow.Schema.get_attribute>`,
   which by default calls `utils.get_value <marshmallow.utils.get_value>`.
#. `utils.get_value <marshmallow.utils.get_value>` performs ``obj[key]`` when
   the object supports ``__getitem__``, then ``getattr(obj, key, default)``.

Three consequences follow from that order:

- ``dump_fields`` is computed once, in ``Schema.__init__``, by
  ``_init_fields``. A field removed from ``dump_fields`` is never visited, so
  its attribute is never read. ``exclude`` and ``only`` act here.
- The accessor is called *before* the value exists, so a guard placed in
  `Schema.get_attribute <marshmallow.Schema.get_attribute>` is the last point
  that can still prevent the read.
- `Field.serialize <marshmallow.fields.Field.serialize>` skips the accessor
  entirely when ``_CHECK_ATTRIBUTE`` is false. `Method
  <marshmallow.fields.Method>`, `Function <marshmallow.fields.Function>`, and
  `Constant <marshmallow.fields.Constant>` set it to false and receive the
  object directly.

``post_dump`` runs after every attribute has been read, so it can remove a key
from the output but cannot prevent the read.

Two paths sit outside the per-field accessor and must be audited separately:

- ``pre_dump`` hooks run before the field loop and receive the whole object.
  A hook that touches a sensitive property defeats both strategies below.
- A field class that overrides `Field.get_value
  <marshmallow.fields.Field.get_value>` decides how it reads the object and may
  ignore the ``accessor`` argument. Such a field defeats an access guard.

Instantiation-time filtering
----------------------------

Pass the disallowed field names to the schema constructor, or compute them in
``on_bind_field``:

.. code-block:: python

    schema = UserSchema(exclude=("ssn",))
    # or
    class UserSchema(Schema):
        name = fields.Str()
        ssn = fields.Str()

        def on_bind_field(self, field_name, field_obj):
            if not can_read(field_name):
                field_obj.load_only = True

``load_only`` is the supported way to disable a field for serialization without
dropping it from ``load``. Setting it in ``on_bind_field`` works because
``_bind_field`` runs before ``_init_fields`` partitions fields into
``load_fields``/``dump_fields``.

What this buys and what it costs:

- The field is absent from ``dump_fields``, so
  ``Schema._serialize`` never touches the object
  for it. This is the cheapest and safest option when the decision is known
  before dumping.
- The decision is fixed for the schema instance's lifetime. ``dump_fields`` is
  not rebuilt per call, so a policy that depends on the request must either
  build a schema per request or use an access guard.
- A ``Nested`` field is still visited, and its own schema performs its own
  filtering. Excluding ``profile.secret`` propagates through
  ``_normalize_nested_options`` and ``Nested.schema``, so the child attribute is
  never read. Excluding only ``profile`` removes the whole nested read.
- Both the constructor argument and ``Meta.exclude`` are validated during
  ``Schema.__init__``; an unknown field name raises ``ValueError``. That is
  useful for catching typos in a policy list.

Attribute-access guard
----------------------

Override `Schema.get_attribute <marshmallow.Schema.get_attribute>` and return
``missing`` (or raise) before delegating:

.. code-block:: python

    class UserSchema(Schema):
        name = fields.Str()
        ssn = fields.Str()

        def get_attribute(self, obj, attr, default):
            if not can_read(attr):
                return missing
            return super().get_attribute(obj, attr, default)

- ``attr`` is the *internal* key, i.e. ``field.attribute or field.name``. A
  field declared as ``hidden = fields.Str(attribute="ssn")`` calls the accessor
  with ``"ssn"``. Keying the policy on the public field name would let the read
  through.
- Returning ``missing`` lets ``dump_default`` apply, which is how to emit a
  placeholder such as ``"<redacted>"`` without reading the real value. To omit
  the key, return ``missing`` with no ``dump_default``.
- Raising from the accessor fails closed and prevents the read, but the
  exception propagates through `Schema.dump <marshmallow.Schema.dump>`; use it
  only if a denial should abort the response.
- The guard is per schema instance. A nested schema has its own
  ``get_attribute``; a guard on the outer schema only prevents the outer read.
  Put the policy in a shared base schema and inherit it in every schema that can
  reach the object.
- A guard is evaluated for every field on every dump, so it is the right place
  for a request-scoped policy (read the tenant or actor from
  `Context <marshmallow.experimental.context.Context>`). It has no effect on
  `Method <marshmallow.fields.Method>`, `Function
  <marshmallow.fields.Function>`, or `Constant
  <marshmallow.fields.Constant>` fields, because those bypass
  `Field.get_value <marshmallow.fields.Field.get_value>`. It also has no effect
  on a field class that overrides `Field.get_value
  <marshmallow.fields.Field.get_value>` and ignores the accessor. Do not expose
  a sensitive attribute through any of those while relying on the guard.

Choosing between them
---------------------

Use instantiation-time filtering when the set of readable fields is known when
the schema is constructed (role at schema-build time, a schema per endpoint, or
a static ``Meta.exclude``). It guarantees zero reads, is enforced by
``_init_fields``, and costs nothing per field.

Use the access guard when the decision depends on the request, the object, or
data that is only available at dump time. It also guarantees zero reads, but it
must be repeated on every nested schema, must key on the internal attribute
name, and does not protect `Method <marshmallow.fields.Method>` or `Function
<marshmallow.fields.Function>` fields.

Whichever is used, do not rely on ``post_dump`` for disclosure control. It can
make the output look correct while the value has already been read, cached, or
passed to a logging hook.

Verifying that the getter never ran
-----------------------------------

A result-only assertion cannot distinguish "removed from the output" from
"never read". Use an object whose attribute is a property that records each
access, and assert on that counter:

.. code-block:: python

    from marshmallow import Schema, fields, missing

    class Model:
        def __init__(self):
            self.name = "alice"
            self.ssn_reads = 0

        @property
        def ssn(self):
            self.ssn_reads += 1
            return "123-45-6789"

    class GuardedSchema(Schema):
        name = fields.Str()
        ssn = fields.Str()

        def get_attribute(self, obj, attr, default):
            if attr == "ssn":
                return missing
            return super().get_attribute(obj, attr, default)

    model = Model()
    result = GuardedSchema().dump(model)
    assert result == {"name": "alice"}
    assert model.ssn_reads == 0

The same test against ``post_dump`` passes the result assertion but fails the
counter (``ssn_reads == 1``). That is the acceptance criterion: assert both the
shape of the output and that the property was not evaluated. No database is
needed; the property stands in for a lazy relationship or a decrypting column.

``tests/test_serialization.py`` contains these checks for ``exclude``,
``only``, ``load_only``, the access guard, ``post_dump``, ``pre_dump``,
``Method``/``Function`` fields, nested schemas, and a ``Context``-scoped
policy.
