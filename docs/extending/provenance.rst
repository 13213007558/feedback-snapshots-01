Tracking field provenance
=========================

Applications often need to know where a loaded value came from: the caller's
payload, a field default, or server-side processing. This is especially useful
for audit logs, where an API may allow an application to send a "source" marker
but values submitted through the API must still be recognized as external.

Pass ``provenance=True`` to `Schema.load <marshmallow.Schema.load>` to get a
`LoadProvenance <marshmallow.provenance.LoadProvenance>` collector alongside the
data:

.. code-block:: python

    from marshmallow import Schema, fields

    class AddressSchema(Schema):
        zip_code = fields.Str(data_key="zipCode", load_default="00000")
        city = fields.Str(required=True)

    class UserSchema(Schema):
        name = fields.Str(data_key="Name")
        email = fields.Email(data_key="UserName", attribute="contact")
        address = fields.Nested(AddressSchema, data_key="homeAddress")
        role = fields.Str(load_default="member")

    data, provenance = UserSchema().load(
        {"Name": "Mick", "UserName": "mick@example.com", "homeAddress": {"city": "SP"}},
        provenance=True,
    )

``data`` has exactly the same shape as without provenance:

.. code-block:: python

    {'name': 'Mick',
     'contact': 'mick@example.com',
     'address': {'zip_code': '00000', 'city': 'SP'},
     'role': 'member'}

Sources are read by output path or by external alias, including nested paths:

.. code-block:: python

    provenance.by_path("contact")             # FieldSource.INPUT
    provenance.by_path("address.zip_code")    # FieldSource.DEFAULT
    provenance.by_alias("homeAddress.zipCode")  # FieldSource.DEFAULT
    provenance.as_dict()                      # JSON-serializable mapping

`FieldSource <marshmallow.provenance.FieldSource>` has three values:

- ``INPUT``: the value was present in the original payload. Even if a
  ``pre_load`` processor rewrites it, it is still external input.
- ``DEFAULT``: the input did not contain the field and a ``load_default`` (on
  the field or on a nested schema) produced the value.
- ``PROCESSOR``: the value was absent from the original payload and was added
  by a server-side processor, such as ``pre_load`` or ``post_load``.

Values added by a field-level ``post_load`` keep the source determined at
mapping time: values that arrived in the input stay ``INPUT``.

.. note::

    Provenance is recorded independently of the data. The loaded dictionary is
    never modified, so it can be stored or returned in its original format.

.. note::

    If you already have a collector, pass it directly instead of ``True``:

    .. code-block:: python

        provenance = LoadProvenance()
        data = UserSchema().load(payload, provenance=provenance)

Enabling provenance never changes which values are mapped: fields with no
``load_default`` and no input stay absent, defaults still apply, and
required-field validation is unchanged.

Auditing an application-supplied marker
---------------------------------------

A common requirement is to let applications stamp a value (for example a
``source`` marker) while making sure values submitted through the API are
recognized as external. Provenance answers this without trusting the payload:
a marker that arrived in the request is ``INPUT``; one the server filled in is
``PROCESSOR``.

.. code-block:: python

    class AuditSchema(Schema):
        source = fields.Str()
        user = fields.Nested(AddressSchema, data_key="contact")

        @pre_load
        def default_source(self, data, **kwargs):
            data = dict(data)
            data.setdefault("source", "server")
            return data

    data, provenance = AuditSchema().load(
        {"source": "app-x", "contact": {"city": "SP"}}, provenance=True
    )
    provenance.by_alias("source")  # FieldSource.INPUT -> from the caller

    data, provenance = AuditSchema().load(
        {"contact": {"city": "SP"}}, provenance=True
    )
    provenance.by_alias("source")  # FieldSource.PROCESSOR -> filled by server
    provenance.by_alias("contact.zipCode")  # FieldSource.DEFAULT

The returned ``data`` keeps the business schema's normal shape; provenance is
side-channel information suitable for an audit record.

Source summary:

==============================  ===========================================
Situation                       Source
==============================  ===========================================
Present in the caller payload   ``INPUT``
Absent input; ``load_default``  ``DEFAULT``
Added by ``pre_load``           ``PROCESSOR``
Added by ``post_load``          ``PROCESSOR``
==============================  ===========================================
