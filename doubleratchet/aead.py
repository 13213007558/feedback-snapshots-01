from abc import ABC, abstractmethod


__all__ = [
    "AEAD",
    "AuthenticationFailedException",
    "DecryptionFailedException"
]


class AuthenticationFailedException(Exception):
    """
    Raised by :meth:`AEAD.decrypt` in case of authentication failure.
    """


class DecryptionFailedException(Exception):
    """
    Raised by :meth:`AEAD.decrypt` in case of decryption failure.
    """


class AEAD(ABC):
    """
    Authenticated Encryption with Associated Data (AEAD).

    Plugin contract
    ---------------

    Implementations of this interface are plugged into
    :class:`~doubleratchet.double_ratchet.DoubleRatchet`, which relies on the following guarantees. Refer to
    :ref:`plugin_contract` in the documentation for the full contract.

    * Input lengths: the ``key`` passed to both methods always consists of 32 bytes. ``plaintext``,
      ``ciphertext`` and ``associated_data`` can be of any length, including empty. The associated data must
      be authenticated exactly as passed, without modification.
    * Return values: both methods must return their result as :class:`bytes`. :meth:`decrypt` may only
      return plaintext after successful authentication. It must never swallow a failure and return empty or
      partial plaintext instead of raising an exception.
    * Failure behavior: implementations signal authentication failure by raising
      :class:`AuthenticationFailedException` and other decryption failures by raising
      :class:`DecryptionFailedException`. Any exception raised by the implementation propagates to the
      caller of the :class:`~doubleratchet.double_ratchet.DoubleRatchet` unchanged; the Double Ratchet
      guarantees that its internal state remains untouched in this case, making it safe to retry.
    * Input ownership and async behavior: all inputs are immutable :class:`bytes`. The caller must not
      mutate inputs while a call is awaited, and the implementation must not retain references to the
      inputs beyond the duration of the call.
    """

    @staticmethod
    @abstractmethod
    async def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        """
        Args:
            plaintext: The plaintext to encrypt.
            key: The encryption key, consisting of 32 bytes.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The ciphertext, as :class:`bytes`.
        """

    @staticmethod
    @abstractmethod
    async def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        """
        Args:
            ciphertext: The ciphertext to decrypt.
            key: The decryption key, consisting of 32 bytes.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The plaintext, as :class:`bytes`. Only returned after successful authentication.

        Raises:
            AuthenticationFailedException: if the message could not be authenticated using the associated
                data.
            DecryptionFailedException: if the decryption failed for a different reason (e.g. invalid padding).
        """
