from __future__ import annotations

import json
from typing import Type, TypeVar, cast

from .kdf import KDF
from .migrations import parse_kdf_chain_model
from .models import KDFChainModel
from .types import JSONObject


__all__ = [
    "KDFChain"
]


KDFChainTypeT = TypeVar("KDFChainTypeT", bound="KDFChain")


class KDFChain:
    """
    The term KDF chain is used when some of the output from a KDF is used as an output key and some is used to
    replace the KDF key, which can then be used with another input.

    https://signal.org/docs/specifications/doubleratchet/#kdf-chains
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__kdf: Type[KDF]
        self.__key: bytes
        self.__length: int

    @classmethod
    def create(cls: Type[KDFChainTypeT], kdf: Type[KDF], key: bytes) -> KDFChainTypeT:
        """
        Args:
            kdf: The KDF to use for the derivation step.
            key: The initial chain key.

        Returns:
            A configured instance of :class:`KDFChain`.
        """

        self = cls()
        self.__kdf = kdf
        self.__key = key
        self.__length = 0

        return self

    @property
    def model(self) -> KDFChainModel:
        """
        Returns:
            The internal state of this :class:`KDFChain` as a pydantic model.
        """

        return KDFChainModel(length=self.__length, key=self.__key)

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`KDFChain` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.model_dump_json()))

    @classmethod
    def from_model(cls: Type[KDFChainTypeT], model: KDFChainModel, kdf: Type[KDF]) -> KDFChainTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`KDFChain`, as produced by
                :attr:`model`.
            kdf: The KDF to use for the derivation step.

        Returns:
            A configured instance of :class:`KDFChain`, with internal state restored from the model.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        self = cls()
        self.__kdf = kdf
        self.__key = model.key
        self.__length = model.length

        return self

    @classmethod
    def from_json(cls: Type[KDFChainTypeT], serialized: JSONObject, kdf: Type[KDF]) -> KDFChainTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a :class:`KDFChain`,
                as produced by :attr:`json`.
            kdf: The KDF to use for the derivation step.

        Returns:
            A configured instance of :class:`KDFChain`, with internal state restored from the serialized data.
        """

        return cls.from_model(parse_kdf_chain_model(serialized), kdf)

    async def step(self, data: bytes, length: int) -> bytes:
        """
        Perform a ratchet step of this KDF chain.

        Args:
            data: The input data.
            length: The desired size of the output data, in bytes.

        Returns:
            ``length`` bytes of output data, derived from the internal KDF key and the input data.

        Raises:
            ValueError: if the configured KDF violates the plugin contract by not returning exactly the
                requested number of bytes as :class:`bytes`. In this case the internal state of this KDF
                chain is left unchanged.

        Note:
            The internal state of this KDF chain is only updated after the KDF has returned valid output.
            If the KDF raises an exception or violates the plugin contract, the exception propagates to the
            caller and the chain does not advance, making it safe to retry or to replace the KDF.
        """

        key_length = len(self.__key)

        output_data = await self.__kdf.derive(self.__key, data, key_length + length)

        if not isinstance(output_data, bytes) or len(output_data) != key_length + length:
            raise ValueError(
                "Plugin contract violation: the KDF was asked to derive"
                f" {key_length + length} bytes, but returned"
                + (
                    f" a value of type {type(output_data).__name__}."
                    if not isinstance(output_data, bytes)
                    else f" {len(output_data)} bytes."
                )
                + " The state of the KDF chain was left unchanged."
            )

        self.__length += 1
        self.__key = output_data[:key_length]

        return output_data[key_length:]

    @property
    def length(self) -> int:
        """
        Returns:
            The length of this KDF chain, i.e. the number of steps that have been performed.
        """

        return self.__length
