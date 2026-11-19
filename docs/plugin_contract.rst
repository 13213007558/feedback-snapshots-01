.. _plugin_contract:

AEAD/KDF Plugin Contract
========================

The :class:`~doubleratchet.aead.AEAD` and :class:`~doubleratchet.kdf.KDF` interfaces are the two cryptographic extension points of this library. The :class:`~doubleratchet.double_ratchet.DoubleRatchet` and its internal components call into these plugins at well-defined points and rely on a fixed set of guarantees. This page is the authoritative description of that contract: it defines which side is responsible for input lengths, which form return values must take, what happens to the ratchet state when a plugin fails, and who owns mutable inputs while a call is awaited. Complying and violating implementations can be exercised side by side in ``tests/test_plugin_contract.py``.

Call sites
----------

The KDF plugin is called from exactly one place: :meth:`~doubleratchet.kdf_chain.KDFChain.step`, which backs the root chain and the sending/receiving message chains. The AEAD plugin is called from four places: :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_initial_message`, :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_initial_message`, :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_message` and :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message`. No other code paths invoke the plugins, so conforming to the contract at these call sites is sufficient for a safe replacement.

Input lengths
-------------

* ``KDF.derive(key, data, length)``: the library always passes a ``key`` of exactly 32 bytes (the root chain key, the Diffie-Hellman chain keys and the message keys are all validated or derived to be 32 bytes by the library). ``data`` can be of any length: it is either a Diffie-Hellman shared secret (root chain) or the configured message chain constant. ``length`` is always positive; for use as the root chain or message chain KDF, the implementation must be capable of deriving 64 bytes.
* ``AEAD.encrypt(plaintext, key, associated_data)`` and ``AEAD.decrypt(ciphertext, key, associated_data)``: the library always passes a ``key`` of exactly 32 bytes, derived from the message chains. ``plaintext``, ``ciphertext`` and ``associated_data`` can be of any length, including empty. The associated data is built by ``DoubleRatchet._build_associated_data`` and must be authenticated exactly as passed, without modification.

Return values
-------------

* ``KDF.derive`` must return exactly ``length`` bytes as :class:`bytes`. :meth:`~doubleratchet.kdf_chain.KDFChain.step` validates the type and length of the returned value *before* applying any state changes and raises :class:`ValueError` on violations.
* ``AEAD.encrypt`` must return the ciphertext as :class:`bytes`; ``AEAD.decrypt`` must return the plaintext as :class:`bytes`. The :class:`~doubleratchet.double_ratchet.DoubleRatchet` validates the type of both return values and raises :class:`TypeError` on violations.
* ``AEAD.decrypt`` may only return plaintext after successful authentication. It must signal authentication failure by raising :class:`~doubleratchet.aead.AuthenticationFailedException` and other decryption failures by raising :class:`~doubleratchet.aead.DecryptionFailedException`. It must never swallow a failure and return empty or partial plaintext instead of raising an exception, and it must never convert an internal failure into a successful return. The library cannot detect such semantic violations; they are plugin obligations.

Failure behavior and state
--------------------------

The library follows a compute-first-commit-later discipline at every plugin call site:

* :meth:`~doubleratchet.kdf_chain.KDFChain.step` only advances the chain (key and length) after the KDF has returned valid output.
* :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message` works on an internal clone of the Diffie-Hellman ratchet and only commits state changes (including skipped message key updates) after the AEAD has returned a valid plaintext.
* The encryption call sites (:meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_message` and :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_initial_message`) also work on an internal clone of the Diffie-Hellman ratchet and only commit the advanced sending chain after the AEAD has returned a valid ciphertext.

As a consequence, any exception raised by a plugin propagates to the caller unchanged and the ratchet state remains exactly as it was before the call. It is safe to retry the operation or to replace the plugin after a failure. The library never catches plugin exceptions and never converts them into authentication success or empty plaintext.

Input ownership and async behavior
----------------------------------

All inputs passed to the plugins are immutable :class:`bytes`. The caller must not mutate inputs while a plugin call is awaited (with :class:`bytes` this holds by construction), and the plugin must not retain references to the inputs beyond the duration of the call. Conversely, the library does not retain or reuse plugin return values beyond processing them in the calling method, and it does not modify them. Plugins may perform arbitrary asynchronous work internally; the library only reads the returned value after the await completes.

Recommended implementations
---------------------------

The recommended implementations in the ``doubleratchet.recommended`` package (:class:`~doubleratchet.recommended.aead_aes_hmac.AEAD`, :class:`~doubleratchet.recommended.kdf_hkdf.KDF` and :class:`~doubleratchet.recommended.kdf_separate_hmacs.KDF`) comply with this contract and remain the suggested defaults. Note that :class:`~doubleratchet.recommended.kdf_separate_hmacs.KDF` can only derive outputs whose size is a multiple of the hash function's digest size, based on the length of the KDF data; when using it as the message chain KDF, the message chain constant must be chosen accordingly (e.g. two bytes with SHA-256 to derive 64 bytes).
