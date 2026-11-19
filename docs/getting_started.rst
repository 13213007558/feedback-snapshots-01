Getting Started
===============

This quick start guide assumes knowledge of the `Double Ratchet algorithm <https://signal.org/docs/specifications/doubleratchet/>`_.

Next to a few container classes and interfaces, the four major units of this library are :class:`~doubleratchet.double_ratchet.DoubleRatchet`, :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`, :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet` and :class:`~doubleratchet.kdf_chain.KDFChain`. These classes are structured roughly the same:

* Instances can be created through factory methods (called e.g. ``create``), **NOT** by calling the constructor/``__init__``.
* Instances can be serialized into JSON-friendly data structures.
* When creating a new instance or deserializing an old instance, a set of configuration options has to be passed. Note that it is your responsibility to pass the same configuration when deserializing as you passed when creating the instance.
* Some of the classes are abstract, requiring you to subclass them and to implement one or two abstract methods.
* For some of the interfaces and abstract classes, implementations using recommended cryptographic primitives are available in the :doc:`doubleratchet.recommended <doubleratchet/recommended/package>` package.

The :class:`~doubleratchet.double_ratchet.DoubleRatchet` class offers a thin and simple message en-/decryption API, using and combining all of the other classes under the hood. For details on the configuration, refer to the :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_initial_message` or :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_initial_message` methods of the :class:`~doubleratchet.double_ratchet.DoubleRatchet` class. Take a look at the Double Ratchet Chat example in the python-doubleratchet repository for an example of a full configuration, including the required subclassing and using some of the recommended implementations.

This library implements the core of the Double Ratchet specification and includes a few of the recommended algorithms. This library does currently *not* offer sophisticated decision mechanisms for the deletion of skipped message keys. Skipped message keys are only deleted when the maximum amount is reached and old keys are deleted from the storage in FIFO order. There is no time-based or event-based deletion.

Receive diagnostics
-------------------

When messages arrive out of order, the bounded cache of skipped message keys may evict old keys. Plain
:meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message` then raises
:class:`~doubleratchet.AuthenticationFailedException` for both a corrupted ciphertext and a message whose
key is simply too old. To tell these cases apart, attach a
:class:`~doubleratchet.diagnostics.ReceiveDiagnostics` instance and use
:meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message_with_diagnostics`:

.. code-block:: python

    from doubleratchet import ReceiveDiagnostics, ReceiveStatus

    diagnostics = ReceiveDiagnostics()
    alice_dr.set_receive_diagnostics(diagnostics)
    result = await alice_dr.decrypt_message_with_diagnostics(message, associated_data)

    if result.diagnostic.status is ReceiveStatus.MISSING_HISTORICAL_KEY:
        # The exact (ratchet public key, sending chain length) position has no key anymore.
        eviction_reason = result.diagnostic.reason

Diagnostics report one of ``ACCEPTED``, ``ALREADY_PROCESSED``, ``MISSING_HISTORICAL_KEY`` or
``AUTHENTICATION_FAILED``. They reference only public message positions (ratchet public key and chain
lengths) and eviction reasons; they never contain message keys, plaintext or serialized ratchet state.
Diagnostics are local operational metadata: they are not part of the serialized state, and regular
:meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message` is unaffected whether diagnostics are
attached or not.

A failed authentication never consumes a cached key and never pushes an eviction, because all state changes
are applied only after successful authentication. For messages from superseded Diffie-Hellman chains, the
diagnostics check whether the exact key is still cached; they never infer availability from a single maximum
chain index. If the diagnostics did not observe a position (for example because they were attached later),
they do not claim an eviction: a known older chain yields ``NOT_RETAINED``, while an otherwise unknown
attempt reports the actual authentication outcome.
