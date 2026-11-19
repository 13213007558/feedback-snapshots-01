Digital Signature Algorithms
============================

The JWT specification supports several algorithms for cryptographic signing.
This library currently supports:

* HS256 - HMAC using SHA-256 hash algorithm (default)
* HS384 - HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm
* ES256 - ECDSA signature algorithm using SHA-256 hash algorithm
* ES256K - ECDSA signature algorithm with secp256k1 curve using SHA-256 hash algorithm
* ES384 - ECDSA signature algorithm using SHA-384 hash algorithm
* ES512 - ECDSA signature algorithm using SHA-512 hash algorithm
* RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm
* RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm
* RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm
* PS256 - RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256
* PS384 - RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384
* PS512 - RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512
* EdDSA - Both Ed25519 signature using SHA-512 and Ed448 signature using SHA-3 are supported. Ed25519 and Ed448 provide 128-bit and 224-bit security respectively.

Minimum Key Length Requirements
-------------------------------

PyJWT enforces minimum key lengths per industry standards. Keys below these
minimums will trigger an ``InsecureKeyLengthWarning`` by default, or raise
``InvalidKeyError`` if ``enforce_minimum_key_length`` is enabled.

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Algorithm
     - Minimum Key Length
     - Standard
   * - HS256
     - 32 bytes (256 bits)
     - RFC 7518 Section 3.2
   * - HS384
     - 48 bytes (384 bits)
     - RFC 7518 Section 3.2
   * - HS512
     - 64 bytes (512 bits)
     - RFC 7518 Section 3.2
   * - RS256/384/512
     - 2048 bits
     - NIST SP 800-131A
   * - PS256/384/512
     - 2048 bits
     - NIST SP 800-131A

See :ref:`key-length-validation` for configuration details.

Asymmetric (Public-key) Algorithms
----------------------------------
Usage of RSA (RS\*) and EC (EC\*) algorithms require a basic understanding
of how public-key cryptography is used with regards to digital signatures.
If you are unfamiliar, you may want to read
`this article <https://en.wikipedia.org/wiki/Public-key_cryptography>`_.

When using the RSASSA-PKCS1-v1_5 algorithms, the `key` argument in both
``jwt.encode()`` and ``jwt.decode()`` (``"secret"`` in the examples) is expected to
be either an RSA public or private key in PEM or SSH format. The type of key
(private or public) depends on whether you are signing or verifying a token.

When using the ECDSA algorithms, the ``key`` argument is expected to
be an Elliptic Curve public or private key in PEM format. The type of key
(private or public) depends on whether you are signing or verifying.

Specifying an Algorithm
-----------------------
You can specify which algorithm you would like to use to sign the JWT
by using the `algorithm` parameter:

.. code-block:: pycon

    >>> encoded = jwt.encode({"some": "payload"}, "secret", algorithm="HS512")
    >>> print(encoded)
    eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.WTzLzFO079PduJiFIyzrOah54YaM8qoxH9fLMQoQhKtw3_fMGjImIOokijDkXVbyfBqhMo2GCNu4w9v7UXvnpA

When decoding, you can also specify which algorithms you would like to permit
when validating the JWT by using the `algorithms` parameter which takes a list
of allowed algorithms:

.. code-block:: pycon

    >>> jwt.decode(encoded, "secret", algorithms=["HS512", "HS256"])
    {'some': 'payload'}

In the above case, if the JWT has any value for its alg header other than
HS512 or HS256, the claim will be rejected with an ``InvalidAlgorithmError``.

.. warning::

   Do **not** compute the ``algorithms`` parameter based on the
   ``alg`` from the token itself, or on any other data that an
   attacker may be able to influence, as that might expose you to
   various vulnerabilities (see `RFC 8725 §2.1
   <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
   either hard-code a fixed value for ``algorithms``, or configure it
   in the same place you configure the ``key``. Make sure not to mix
   symmetric and asymmetric algorithms that interpret the ``key`` in
   different ways (e.g. HS\* and RS\*).

Registering Custom Algorithms
-----------------------------

A compatibility layer can plug in its own
:class:`~jwt.algorithms.Algorithm` implementations without touching the
process-global registry. Build a dedicated client with
:meth:`PyJWS.from_algorithms`, passing a mapping of algorithm name to
algorithm object:

.. code-block:: python

    from jwt.algorithms import HMACAlgorithm
    from jwt.api_jws import PyJWS

    class MyMACAlgorithm(HMACAlgorithm):
        pass

    jws = PyJWS.from_algorithms({"MY-MAC": MyMACAlgorithm(HMACAlgorithm.SHA256)})

The mapping is copied, so each client owns an independent registry and may
even shadow a built-in name (such as ``"HS256"``) for itself only.
Registering an algorithm on one client never changes another caller's
allow-list:

.. code-block:: python

    first = PyJWS()
    second = PyJWS()
    first.register_algorithm("MY-MAC", MyMACAlgorithm(HMACAlgorithm.SHA256))

    "MY-MAC" in first.get_algorithms()   # True
    "MY-MAC" in second.get_algorithms()  # False

A :class:`~jwt.api_jwt.PyJWT` client exposes the same surface through its
:attr:`~jwt.api_jwt.PyJWT.jws` property:

.. code-block:: python

    from jwt import PyJWT

    client = PyJWT()
    client.jws.register_algorithm("MY-MAC", MyMACAlgorithm(HMACAlgorithm.SHA256))
    token = client.encode({"hello": "world"}, key, algorithm="MY-MAC")
    client.decode(token, key, algorithms=["MY-MAC"])

To read a :class:`~jwt.api_jwk.PyJWK` whose ``alg`` is a custom (or
same-named) algorithm, pass the same registry to
:meth:`PyJWK.from_dict` / :meth:`PyJWK.from_json`. Without it, the key is
rejected with :class:`~jwt.exceptions.PyJWKError` because the algorithm is
absent from the built-in defaults:

.. code-block:: python

    registry = {"MY-MAC": MyMACAlgorithm(HMACAlgorithm.SHA256)}
    jwk = PyJWK.from_dict(jwk_data, algorithms=registry)

Every custom algorithm remains responsible for validating the keys it
accepts in :meth:`~jwt.algorithms.Algorithm.prepare_key` and
:meth:`~jwt.algorithms.Algorithm.from_jwk`; an unexpected key type should
raise :class:`~jwt.exceptions.InvalidKeyError`.
