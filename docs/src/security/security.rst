:mod:`ndn.security` package
============================

Introduction
------------

The :mod:`ndn.security` package provides signers, validators, keychains, and
TPM integrations.

Signer
------

A :class:`Signer` supplies signature metadata and computes a packet signature.

.. autoclass:: ndn.encoding.Signer
  :members:

Validator
---------

An application validator is an async callable with three arguments: a
:class:`FormalName`, :class:`SignaturePtrs`, and packet-context dictionary. It
returns :class:`ValidResult`. ``PASS`` and ``ALLOW_BYPASS`` accept a packet;
``FAIL`` and ``TIMEOUT`` reject it.

The digest and known-key validator factories exported from
:mod:`ndn.security` follow this contract.

Cascade validation
~~~~~~~~~~~~~~~~~~

.. autoclass:: ndn.security.CascadeChecker
  :members:

.. autoclass:: ndn.security.PublicKeyStorage
  :members:

.. autoclass:: ndn.security.MemoryKeyStorage
  :members:

Keychain
--------

A :class:`Keychain` contains identities, their keys, and certificates.

.. autoclass:: ndn.security.keychain.Keychain
  :members:

KeychainDigest
~~~~~~~~~~~~~~

.. automodule:: ndn.security.keychain.keychain_digest
  :members:

KeychainSqlite3
~~~~~~~~~~~~~~~

This is the default persistent keychain.

.. automodule:: ndn.security.keychain.keychain_sqlite3
  :members:

Signer selection contract
~~~~~~~~~~~~~~~~~~~~~~~~~

``KeychainSqlite3.get_signer(sign_args)`` resolves a signer in this order.
Each mode pins both the ``KeyLocator`` written into the packet and the private
key that actually computes the signature (whose counterpart is the public key
stored in the PIB):

============================  ======================================  =================================================
``sign_args`` selection       KeyLocator                              Private key used
============================  ======================================  =================================================
``no_signature: True``        none                                    no signature (returns ``None``)
``digest_sha256: True``       none (digest signature)                 SHA-256 digest, no key
explicit ``key_locator``      the given name                          the key selected below (cert/key/default)
explicit ``cert``             the certificate name                    that certificate's key
explicit ``key``              the key's default certificate name      that key
explicit ``identity``         its default key's default certificate   that identity's default key
no selector (default)         default identity/key/cert               the default identity's default key
============================  ======================================  =================================================

Rules consumers can rely on:

1. **Explicit is stable.** A given ``cert`` or ``key`` always resolves to the
   same key regardless of the current default identity. Repeated identical
   calls return the cached signer instance.
2. **Default follows the PIB.** The no-selector path re-reads the default
   identity/key/cert from the database on every call, so switching the default
   changes subsequent signatures.
3. **KeyLocator is not the key.** An explicit ``key_locator`` only sets the
   name placed in the packet; it never selects the private key. Two distinct
   keys can publish under the identical KeyLocator. Namespace policies must
   therefore fetch the key/cert named (or otherwise trusted) and verify the
   signature cryptographically — matching the KeyLocator string alone is not a
   security check.

Signer caching and invalidation
+++++++++++++++++++++++++++++++

Signers are cached on the keychain keyed by the triple
``(TPM key name, KeyLocator name, with_signature_time)``. The TPM key name is
part of the key precisely because the KeyLocator alone is not unique: caching
by KeyLocator only could hand back a signer backed by another identity's
private key after a default change.

The cache is cleared on every state change that can alter default resolution:
``set_default_identity``, ``set_default_key``, ``set_default_cert``,
``del_identity``, ``del_key`` and ``del_cert``. After a deletion a fresh
``get_signer`` call raises ``KeyError``; however, a signer object already held
by the application retains its in-memory private key and remains usable until
the application drops the reference. Rotate long-lived held signers after key
operations.

The executable form of this contract lives in
``tests/integration/signer_cache_test.py``.
