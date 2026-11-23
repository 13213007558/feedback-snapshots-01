.. _diagnostics:

Response diagnostics
====================

Federation login incidents are easier to handle when a support ticket can
show *which local trust material verified the response*, *which processing
stage failed* and *whether an identity was finally published*.  PySAML2 can
attach that evidence as a structured diagnostic while it processes an
authentication response.

The diagnostic is deliberately share-safe.  It is built from an allow-list of
fields and never stores SAML attributes, attribute values, response XML,
NameIDs or raw account identifiers.  Only an issuer entity ID, a metadata
source label, a SHA-256 metadata version, a certificate fingerprint, counters
and the stage/outcome pairs are exposed.

Usage
-----

Create a :class:`saml2.diagnostics.ResponseDiagnostics` instance and pass it
to the response parser::

    from saml2.diagnostics import ResponseDiagnostics
    from saml2.response import authn_response

    diagnostics = ResponseDiagnostics(request_id=request_id)
    response = authn_response(
        sp_config,
        [acs_url],
        outstanding_queries=outstanding,
        diagnostics=diagnostics,
    )
    response.loads(saml_response_xml, decode=False)
    response.verify()

    ticket_payload = response.diagnostics.to_json()

For SP code that uses
:meth:`saml2.client_base.Base.parse_authn_request_response`, pass the optional
``diagnostics`` keyword and read the attached
``response.diagnostics`` afterwards.

If no instance is supplied, a fresh diagnostic is still attached and filled
in, which is useful for logging and tests.

Recorded stages
---------------

The diagnostic records these stages in processing order:

``request_binding``
    Whether ``InResponseTo`` matches an AuthnRequest this SP actually issued.
``signature_verification``
    Whether the XML signature verified, which node was signed, and which
    certificate/metadata version confirmed it.
``response_validation``
    The ``InResponseTo``, destination and status checks.
``assertion_selection``
    The assertion count and signature/validation status of the selected
    assertion.
``attribute_mapping``
    How many asserted attributes were mapped to local names.  A response with
    two asserted attributes of which only one maps is recorded as a failure,
    without recording the attribute names.
``identity_issuance``
    Whether a NameID was available for the application to publish.

Earlier stages are kept when a later stage fails, so a ticket can prove both
what succeeded and where processing actually stopped.

Trust material versions
-----------------------

Each metadata source that contains a signing certificate for the issuer is
reported with a ``version`` (SHA-256 of the metadata document) and the
fingerprint of the certificate it contributes.  When the same visible issuer
is trusted through two revisions of local metadata, the two diagnostics carry
different ``version`` and ``certificate_sha256`` values and the
``signature_verification`` stage names the version that actually verified the
signature.

Testing contract
----------------

The regression tests in ``tests/test_45_response_diagnostics.py`` generate
their own certificates, metadata and signed responses locally.  They perform
two checks around a trust-material change - one that fails at attribute
mapping and one that fully succeeds - and assert that:

* the trust-material version and certificate differ between the two checks;
* the failed check names ``attribute_mapping`` as the failure stage while
  retaining the signature and assertion evidence;
* identity publication is false for the failed check and true for the
  successful one;
* the public object, its JSON/ticket serialization and its ``repr`` contain
  none of the synthetic privacy markers embedded in the test response.
