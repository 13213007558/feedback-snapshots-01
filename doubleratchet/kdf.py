from abc import ABC, abstractmethod


__all__ = [
    "KDF"
]


class KDF(ABC):
    """
    A KDF is defined as a cryptographic function that takes a secret and random KDF key and some input data
    and returns output data. The output data is indistinguishable from random provided the key isn't known
    (i.e. a KDF satisfies the requirements of a cryptographic "PRF"). If the key is not secret and random, the
    KDF should still provide a secure cryptographic hash of its key and input data.

    https://signal.org/docs/specifications/doubleratchet/#kdf-chains

    Plugin contract
    ---------------

    Implementations of this interface are plugged into
    :class:`~doubleratchet.kdf_chain.KDFChain`, which relies on the following guarantees. Refer to
    :ref:`plugin_contract` in the documentation for the full contract.

    * Input lengths: the ``key`` passed to :meth:`derive` always consists of 32 bytes. ``data`` can be of
      any length. ``length`` is always positive; for the use as root chain or message chain KDF, the
      implementation must be capable of deriving 64 bytes.
    * Return values: :meth:`derive` must return exactly ``length`` bytes as :class:`bytes`. The
      :class:`~doubleratchet.kdf_chain.KDFChain` validates this before applying any state changes and
      raises :class:`ValueError` on violations.
    * Failure behavior: any exception raised by the implementation propagates to the caller unchanged; the
      KDF chain guarantees that its internal state remains untouched in this case, making it safe to retry
      or to replace the KDF.
    * Input ownership and async behavior: all inputs are immutable :class:`bytes`. The caller must not
      mutate inputs while a call is awaited, and the implementation must not retain references to the
      inputs beyond the duration of the call.
    """

    @staticmethod
    @abstractmethod
    async def derive(key: bytes, data: bytes, length: int) -> bytes:
        """
        Args:
            key: The KDF key, consisting of 32 bytes.
            data: The input data.
            length: The desired size of the output data, in bytes.

        Returns:
            Exactly ``length`` bytes of output data, derived from the KDF key and the input data, as
            :class:`bytes`.
        """
