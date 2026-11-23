.. _howto_federation:

Federation trust: static signatures, MDQ, retirement and rotation
==================================================================

When a deployment trusts some entities from a statically signed metadata file
and discovers others on demand through an MDQ service, three operational
requirements must hold at the same time:

* A signing key that operations has confirmed as **retired** stays rejected,
  even when a later MDQ query fails because of a short network fault.
* A key **rotation** runs through a dual-key window in which both the old and
  the new key are accepted. Each verification uses an explicit, immutable
  *trust view* captured for that request.
* The three possible MDQ outcomes are distinct states and never overwrite one
  another:

  - a failed query (timeout, connection error, 5xx, unverifiable record)
    retains the last authoritative state;
  - an explicit deletion (HTTP 404) records a tombstone;
  - a fresh, validly signed record (HTTP 200), including one that carries two
    keys, atomically replaces the previous record.

The implementation lives in :mod:`saml2.federation`. It only depends on the
standard library and ``cryptography``, so signature material can be produced
and verified without an external xmlsec binary.

Trust anchors
-------------

Metadata signatures are pinned to SHA-256 certificate fingerprints. Build a
federation anchor and an entity key locally::

    from saml2.federation import (
        certificate_fingerprint,
        generate_signing_material,
    )

    anchor_key, anchor_cert = generate_signing_material("federation-anchor")
    entity_key, entity_cert = generate_signing_material("idp-signing")
    anchors = {certificate_fingerprint(anchor_cert)}

Signing a metadata record
-------------------------

``sign_entity_descriptor`` adds an enveloped XML signature to an
``EntityDescriptor`` element tree::

    from xml.etree import ElementTree as ET
    from saml2.federation import sign_entity_descriptor

    root = ET.fromstring(entity_descriptor_xml_text)
    signed_xml = sign_entity_descriptor(root, anchor_key, anchor_cert)

Static source
-------------

A static source verifies the document signature once and keeps operator
declared retirements outside the signed document so they cannot be undone by
remote failures::

    from saml2.federation import StaticTrustSource

    static = StaticTrustSource(
        "local-file",
        signed_xml,
        anchors,
        retired_fingerprints={"https://sp.example/entity": {retired_fp}},
    )

MDQ client and the three outcomes
---------------------------------

``MdqClient`` keeps one cache entry per entity whose state is one of
``MdqOutcome.RECORD``, ``MdqOutcome.DELETED`` or ``MdqOutcome.UNAVAILABLE``.
A failed query never mutates an existing record or tombstone; only a 200 or
404 response changes the authoritative state::

    from saml2.federation import MdqClient, MdqOutcome

    mdq = MdqClient("http://mdq.federation.test", anchors)
    outcome = mdq.query("https://idp.example/entity")
    assert outcome == MdqOutcome.RECORD

Combined resolver, retirement and verification
----------------------------------------------

``FederationTrustResolver`` consults static sources first, then MDQ. A
retirement recorded through ``retire`` is durable across outages, and
``verify_with_view`` lets an in-flight request pin itself to the trust view it
started with::

    from saml2.federation import FederationTrustResolver, KeyRetired

    resolver = FederationTrustResolver(static_sources=[static], mdq_client=mdq)
    view = resolver.trust_view("https://idp.example/entity")

    resolver.retire("https://idp.example/entity", old_key_fp)
    resolver.verify_with_view(view, new_key_fp, signature, signed_bytes)

    try:
        resolver.verify("https://idp.example/entity", old_key_fp, signature, signed_bytes)
    except KeyRetired:
        # The retirement is enforced even while MDQ is unreachable.
        pass

Acceptance scenarios are exercised in ``tests/test_95_federation_trust.py``.
