.. _send_failure_contract:

Send Failure Contract
=====================

Encryption is one step of a larger send operation. A message service usually encrypts a plaintext, hands the
ciphertext to a transport, and only then learns whether the transport accepted it. These steps cannot be
rolled back atomically: deriving a message key advances a ratchet chain, and a ciphertext can leave the
process before the caller knows that the send failed.

This page defines what :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_message` guarantees, what
it cannot know, and how both parties continue after a failure.

The send pipeline
-----------------

:meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_message` performs two state-changing steps:

1. ``next_encryption_key()`` on the Diffie-Hellman ratchet, which captures the header (ratchet public key,
   previous sending chain length, sending chain length) and advances the sending KDF chain by one step.
   Deriving the message key **spends** the sending chain index.
2. ``AEAD.encrypt(plaintext, message_key, associated_data)``, which produces the ciphertext.

Only after both steps does the method return an :class:`~doubleratchet.types.EncryptedMessage`.

The contract
------------

* **Failure before key derivation leaves the chain unchanged.** If the KDF raises or is cancelled, no
  message key exists, so nothing is spent. The next attempt uses the same sending chain index. This covers
  ``ChainNotAvailableException``, a KDF exception, a cancellation while the KDF is running, and a KDF whose
  output does not have the requested length (that is rejected before the chain state is changed).
* **Failure after key derivation spends exactly one index.** Once ``next_encryption_key()`` returned, the
  key is not reused, no matter where the following AEAD call fails and no matter whether a ciphertext was
  produced. The next successful attempt uses the next index. The skipped index stays a gap in the sending
  chain.
* **A returned message is complete and reproducible.** ``encrypt_message`` only returns after the AEAD call
  succeeded. The returned header and ciphertext are self-contained; the ciphertext can be delivered later
  even if the surrounding send operation failed.
* **The library never reports delivery.** A successful ``encrypt_message`` means "a ciphertext exists", not
  "the recipient got it". Only the receiver can confirm delivery, via a reply or an application-level
  acknowledgement.
* **A gap is not an error on the receiving side.** ``decrypt_message`` stores skipped message keys (within
  ``max_num_skipped_message_keys`` and ``dos_protection_threshold``) so that a later message on the same
  chain can still be decrypted. A send that failed after key derivation therefore only costs one skipped
  key, not the session.
* **Operations on one instance are serialized.** ``encrypt_message`` and ``decrypt_message`` hold an
  internal lock while they mutate the ratchet. Without it, a concurrent receive could replace the
  Diffie-Hellman ratchet with a clone that predates a concurrent send, silently rolling the sending chain
  back and handing out the same message key twice. The lock is not part of the serialized state; a
  deserialized instance starts with an unlocked one and must not be used from two event loops at once.

Failure matrix
--------------

.. list-table::
    :header-rows: 1

    * - Failure point
      - Message key spent
      - Sending index
      - Receiver can recover
    * - KDF raises or is cancelled
      - no
      - unchanged
      - nothing to recover
    * - KDF output has the wrong length
      - no
      - unchanged
      - nothing to recover
    * - AEAD raises before producing a ciphertext
      - yes
      - advanced
      - via skipped key
    * - AEAD returns, caller cancels before sending
      - yes
      - advanced
      - via skipped key
    * - Ciphertext sent, transport reports failure
      - yes
      - advanced
      - if it arrived, or via skipped key

Interpreting a skipped index
----------------------------

The sending chain index in the header is the position in the chain, so "the retry got the next index"
locates the failure: an index that jumps by one means a message key was derived before the failure, i.e. the
failure happened at or after the AEAD call (or the AEAD/transport succeeded and only the caller's send
wrapper failed). A retry after a KDF failure keeps the same index.

This is a property of the pipeline, not a bug to paper over. Restoring the ratchet to an earlier state or
reusing the failed attempt's key to make the numbers contiguous would either reuse a message key that may
already have left the process, or desynchronize the receiving chain.

Retrying
--------

Never retry by restoring an older serialized state or by reusing a ciphertext's key to keep the numbering
contiguous. Both can reuse a message key that may already have been used. Retry by calling
``encrypt_message`` again on the live instance:

* If the previous attempt failed before key derivation, the new message has the same index and is the first
  use of that key.
* If it failed after key derivation, the new message has the next index; the abandoned key is never used
  again, and the receiver treats the index as a skipped message.

A ciphertext produced by an attempt that failed afterwards can still be delivered. The receiver will accept
it from its skipped message keys, and will reject it as a duplicate if the retried message already advanced
past that index.

Recovering from a large gap
---------------------------

If more keys are skipped than ``dos_protection_threshold`` allows, ``decrypt_message`` raises
:class:`~doubleratchet.diffie_hellman_ratchet.DoSProtectionException` instead of computing all skipped keys.
The session is not lost: the sender continues ratcheting, and a message that triggers the next
Diffie-Hellman step moves the receiving chain past the gap. Messages inside the gap remain undecryptable,
which is the intended DoS protection. Choose the threshold based on how many sends may fail in a row before
either side sends again.

Reproducible demonstration
--------------------------

``examples/send_failure_contract.py`` runs the scenarios from the failure matrix against a live Alice and Bob
and prints the state of both sides after every step. ``tests/test_send_failure_contract.py`` contains the
same scenarios as assertions, including the concurrent send/receive case.

Library-confirmable vs. external facts
--------------------------------------

The library can confirm:

* that a message key was derived (and therefore spent),
* that the AEAD call succeeded and a ciphertext exists,
* that the internal state is unchanged if an exception was raised before key derivation.

The library cannot confirm:

* that the caller actually transmitted the ciphertext,
* that the recipient received or processed it.

An application that needs "delivered" semantics has to track that separately from a successful
``encrypt_message`` call, for example with an acknowledgement that references the message header.
