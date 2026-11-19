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

Concurrent use of a Double Ratchet instance
-------------------------------------------

All operations on a :class:`~doubleratchet.double_ratchet.DoubleRatchet` instance are serialized internally: ``encrypt_message``, ``decrypt_message``, :meth:`~doubleratchet.double_ratchet.DoubleRatchet.export_model` and :meth:`~doubleratchet.double_ratchet.DoubleRatchet.export_json` take a per-instance lock, so it is safe to await them from multiple tasks. Each operation derives keys from the most recently committed state and commits its result at the end of a critical section. Because of this, two operations can never both succeed from the same starting state and overwrite each other.

The commit rule is *derive on a clone, commit on success*:

* A failed authentication, a decryption failure, a DoS protection rejection, or a cancellation leaves the committed state untouched. Waiting operations then run against the unchanged state and produce their own deterministic result.
* Submitting the same ciphertext concurrently delivers it at most once. The first successful decryption advances the ratchet; later submissions observe the committed state and fail with :class:`~doubleratchet.diffie_hellman_ratchet.DuplicateMessageException` (or an authentication error, depending on the ratchet position) instead of re-delivering the plaintext.
* Legal out-of-order messages continue to use the stored skipped message keys. A skipped key is removed only when the AEAD operation that consumes it succeeds.
* State exports only observe completed operation boundaries: ``export_model`` and ``export_json`` wait for an in-progress operation to commit (or join the current operation when called from the owning task), so an exported snapshot never contains a partially applied send or receive.

To group several operations into one uninterrupted critical section, use the explicit session entry point:

.. code-block:: python

    async with ratchet.session():
        plaintext = await ratchet.decrypt_message(message, associated_data)
        snapshot = await ratchet.export_json()

The session is reentrant for its owning task, so the regular methods can be called inside it. A task that is cancelled while waiting for the session never observes or modifies the state. If the whole application already serializes access per conversation (for example by a single owning task), the internal lock is uncontended and adds no meaningful overhead.

The choice is serialization rather than optimistic commit with conflict resolution for a simple reason: a Double Ratchet step is a *destructive* state transition. Message keys must not be reused, and deriving from a stale snapshot and committing later would silently lose either a successfully delivered message or a ratchet step, and could deliver the same key material twice. There is no safe merge for two independently advanced ratchet states; the only correct conflict policy is to order the operations, which is exactly what the per-instance lock does. The lock is cheap because operations are short and mostly await the AEAD/KDF primitives, and it keeps the failure semantics simple: an operation either commits completely or not at all.
