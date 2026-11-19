.. _associated_data:

Associated Data Contract
========================

A Double Ratchet message is encrypted with one message key and an AEAD. The AEAD authenticates the
ciphertext and the associated data. It does **not** authenticate the :class:`~doubleratchet.Header`, the
session identity, or the message direction. Those values are only authenticated if the subclass returned
them from ``_build_associated_data``. This page defines a versioned contract that does so without relying
on field concatenation.

What the library already authenticates
--------------------------------------

The library derives the message key from the sending or receiving chain, selected using the header:

* :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_message` obtains a ``(message_key, header)``
  pair from the Diffie-Hellman ratchet, encrypts with ``message_key``, and calls the subclass hook
  ``_build_associated_data(associated_data, header)``.
* :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message` uses
  ``header.ratchet_pub`` and ``header.sending_chain_length`` to select the chain position (or a stored
  skipped message key). It then calls the same hook and passes the result to the AEAD.

Consequently, the key selection is indirectly bound to ``ratchet_pub`` and ``sending_chain_length``:
changing either normally selects a different key, and decryption fails. ``previous_sending_chain_length``
is different. It is only read while crossing a ratchet step. For an ordinary message within a chain, no
code path compares it with the AEAD input. If the subclass omits it, a modified value still decrypts under
the unchanged key, and the receiver can no longer recover messages skipped on the sender's previous chain.
The library cannot detect this because the hook is caller-defined.

The library also does not know:

* which session the instance belongs to,
* which logical direction the message travels,
* which application data or framing should be bound to the message.

The application must supply those values, and they must be the same on both sides for a given message.
"Both sides use the same implementation" is not an argument for uniqueness. The same implementation
receives different field values from the two sides, and injectivity is a property of the encoding, not of
the code.

Session identity to bind
------------------------

:class:`~doubleratchet.associated_data.SessionContext` contains three byte strings:

* ``session_id``: a stable identifier agreed during session setup.
* ``initiator``: a stable identifier of the party that created the session.
* ``responder``: a stable identifier of the other party.

Use globally stable names (for example account or device identifiers), not local role names such as
``me`` and ``peer``. The direction is separate, because the same session carries traffic both ways:

* ``Direction.INITIATOR_TO_RESPONDER`` while the initiator sends,
* ``Direction.RESPONDER_TO_INITIATOR`` while the responder sends.

This prevents reflection: a ciphertext produced for one direction fails in the other, even though both
parties hold the same session state.

Encoding comparison
-------------------

Length-delimited
    Every variable-length field is preceded by its byte length. This is injective when each length
    describes exactly the following field and the total is either self-delimiting or wrapped in a
    length. It handles variable-size identifiers, public keys, and application payloads without a global
    width limit. The canonical contract uses 32-bit lengths for every variable-size field.

Fixed width
    Counters are encoded as unsigned 64-bit big-endian integers, and small enumerations as one or two
    bytes. Fixed width is injective for values that fit, but it is not sufficient for variable-length
    data: a key or identifier whose size can change turns the following field boundary into a guess.
    Reject values that do not fit rather than truncating them.

Structured encoding
    CBOR, protobuf, or JSON with a canonical form can be injective, but only if the whole value is
    framed and the canonical rules cover maps, tags, indefinite lengths, and duplicate keys. Without
    such a profile, two encoders can disagree, and the receiver cannot distinguish a different object
    from a different encoding of the same object. This library does not depend on a structured encoder;
    the byte strings below are the stable contract.

The chosen format never places two variable-length fields next to each other without a length. This is the
property to check when changing the format: for every pair of distinct field tuples, the encodings must
differ before the AEAD is called.

Canonical format
----------------

Session context (``encode_session_context``)::

    "DR-CTX"           6 bytes
    version            1 byte   (1)
    session_id len     4 bytes  (big-endian)
    session_id         N bytes
    initiator len      4 bytes
    initiator          N bytes
    responder len      4 bytes
    responder          N bytes

Application binding passed to ``encrypt_message`` / ``decrypt_message`` (``encode_associated_data``)::

    "DR-ADB"           6 bytes
    version            1 byte   (1)
    context len        4 bytes
    context            N bytes  (the complete session context above)
    direction          1 byte   (0 initiator->responder, 1 responder->initiator)
    application len    4 bytes
    application        N bytes

AEAD associated data (``build_associated_data``)::

    total length       4 bytes  (length of everything below)
    "DR-AAD"           6 bytes
    version            1 byte   (1)
    suite              2 bytes  (application-assigned profile identifier)
    binding len        4 bytes
    binding            N bytes  (the complete application binding above)
    ratchet_pub len    4 bytes
    ratchet_pub        N bytes
    previous_n         8 bytes  (unsigned big-endian)
    n                  8 bytes  (unsigned big-endian)

The outer length makes the associated data self-delimiting. This matters for AEAD implementations such as
:class:`~doubleratchet.recommended.aead_aes_hmac.AEAD`, which authenticate ``associated_data +
ciphertext`` with no separator between the two. If any part of the associated data is derived from
attacker-controlled bytes, a value without a length lets the attacker move whole ciphertext blocks into
the associated data and keep the tag valid; the receiver then decrypts a shorter ciphertext and silently
drops the removed blocks. Within this library the associated data is reconstructed from local state, so
the first line of defence is the boundary-free field encoding above. The outer length additionally keeps
the associated-data/ciphertext boundary explicit, and makes a value with appended bytes fail
:func:`decode_associated_data` instead of being a second encoding of the same object.

``suite`` identifies the complete profile: AEAD, KDFs, header encoding, and this associated data format.
It must be part of the session's negotiated state. Adding a new message encoding without changing the
profile means reusing the old identifier to authenticate a different object.

Byte-level example
------------------

Two sessions are created from the following business fields, with the same header
``ratchet_pub = 111213...30`` (32 bytes), ``previous_n = 3``, ``n = 7``::

    A: session_id="acme/room/1", initiator="2alice", responder="bob", direction=initiator->responder,
       application="hi"
    B: session_id="acme/room/12", initiator="alice", responder="bob", direction=initiator->responder,
       application="hi"

Under naive concatenation, both tuples produce the same bytes::

    A: "acme/room/1"  || "2alice" || "hi"
    B: "acme/room/12" || "alice"  || "hi"
    == 61636d652f726f6f6d2f3132616c6963656869   ("acme/room/12alicehi", 19 bytes)

Appending the header in the order used by the chat example gives a 67-byte AEAD input for both::

    61636d652f726f6f6d2f3132616c6963656869
    1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30
    0000000000000007
    0000000000000003

The AEAD accepts a ciphertext for A as authenticating B, because the authenticated bytes are identical.
Both sides can be running the same code and still disagree about which session the message belongs to.

With the canonical contract, the same two tuples give different 126-byte inputs. Raw bytes for A::

    0000007a44522d4141440100010000003944522d414442010000002744522d435458010000000b
    61636d652f726f6f6d2f310000000632616c69636500000003626f6200000000026869000000
    201112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30000000000000
    00030000000000000007

Raw bytes for B differ only in the two length-prefixed fields, which shift every following byte::

    session_id length  0000000b -> 0000000c
    session_id         61636d652f726f6f6d2f31 -> 61636d652f726f6f6d2f3132
    initiator length   00000006 -> 00000005
    initiator          32616c696365 -> 616c696365

The full B encoding is::

    0000007a44522d4141440100010000003944522d414442010000002744522d435458010000000c
    61636d652f726f6f6d2f313200000005616c69636500000003626f6200000000026869000000
    201112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30000000000000
    00030000000000000007

Hex dump for A, with field boundaries::

    offset  bytes                                   field
    0       0000007a                                total length (122)
    4       44522d414144                            "DR-AAD"
    10      01                                      version
    11      0001                                    suite
    13      00000039                                binding length (57)
    17      44522d414442                            "DR-ADB"
    23      01                                      binding version
    24      00000027                                context length (39)
    28      44522d435458                            "DR-CTX"
    34      01                                      context version
    35      0000000b                                session_id length
    39      61636d652f726f6f6d2f31                  "acme/room/1"
    50      00000006                                initiator length
    54      32616c696365                            "2alice"
    60      00000003                                responder length
    64      626f62                                  "bob"
    67      00                                      direction (initiator->responder)
    68      00000002                                application length
    72      6869                                    "hi"
    74      00000020                                ratchet_pub length
    78      1112131415161718191a1b1c1d1e1f20...30  ratchet_pub
    110     0000000000000003                        previous_sending_chain_length
    118     0000000000000007                        sending_chain_length

Usage
-----

.. code-block:: python

    from doubleratchet import DoubleRatchet, Header
    from doubleratchet.associated_data import (
        Direction,
        SessionContext,
        build_associated_data,
        encode_associated_data
    )

    SUITE = 1  # negotiated with the peer and stored with the session state
    CONTEXT = SessionContext(
        session_id=b"acme/room/1",
        initiator=b"alice",
        responder=b"bob"
    )

    class AppDoubleRatchet(DoubleRatchet):
        @staticmethod
        def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
            return build_associated_data(associated_data, header, suite=SUITE)

    # While sending:
    associated_data = encode_associated_data(CONTEXT, Direction.INITIATOR_TO_RESPONDER, b"chat")
    encrypted = await ratchet.encrypt_message(b"hello", associated_data)

    # While receiving, use the direction of the received message:
    associated_data = encode_associated_data(CONTEXT, Direction.RESPONDER_TO_INITIATOR, b"chat")
    plaintext = await ratchet.decrypt_message(encrypted, associated_data)

Caller checklist
----------------

* Agree ``session_id``, ``initiator``, ``responder``, and ``suite`` during session setup. Store them with
  the Double Ratchet state.
* Derive ``direction`` from the logical sender, not from local role names or transport metadata that the
  attacker controls.
* Call ``encode_associated_data`` with the same context and application data on both sides.
* Return ``build_associated_data(associated_data, header)`` from ``_build_associated_data``. Do not
  concatenate raw fields yourself.
* Reject unknown ``suite`` values before decrypting. A shared identifier is a promise that both sides use
  the same profile, not evidence that they do.
* Keep application data canonical. If it contains several fields, give it its own length-delimited or
  structured encoding. The canonical contract only frames the application value as one byte string.

Compatibility
-------------

The canonical format is a new message format. It changes the AEAD input, so a recipient that expects the
old format rejects the new one with :class:`~doubleratchet.AuthenticationFailedException`, and vice versa.
The library does not try both formats by default: trying a second interpretation after authentication
failure turns a single message into an oracle for downgrade attempts, and a failed trial can consume state
in some implementations.

Old messages remain readable as long as the receiver keeps the old subclass and the old associated data
construction. A deployment can therefore:

1. Stop sending on the old format.
2. Drain and acknowledge old-format messages while the old subclass is still installed.
3. Switch the subclass to the canonical contract.

The subclass is a class-level hook, not session state, so the format is not recorded in
``DoubleRatchetModel``. A process that must read both formats should route by session: keep each session's
format identifier in the application store and instantiate the matching subclass. Do not choose the
subclass by inspecting the ciphertext or by retrying decryption.

A new session is required when:

* the old session has been abandoned, replaced, or re-keyed, because the new context must be agreed by both
  parties and stored with the state;
* the application cannot prove that every peer has drained old-format messages before the new subclass is
  installed;
* the old format's ambiguity is part of the threat model. In that case, treating old messages as
  untrustworthy is the only safe option, and a fresh session avoids carrying unverifiable history forward;
* the ``session_id`` or participant identifiers change. The header's ratchet key is per-chain, not a session
  identifier, and cannot substitute for the agreed context.

A new session is not required merely to add application data fields. As long as the application data
encoding is canonical and both sides agree on it, the same session can carry the new payload, because the
``suite`` already covers the framing rules.
