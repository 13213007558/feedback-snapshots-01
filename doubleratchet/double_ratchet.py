from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from collections import OrderedDict
import contextlib
import copy
import itertools
import json
from types import TracebackType
from typing import AsyncIterator, Optional, Tuple, Type, TypeVar, cast

from .aead import AEAD
from .diffie_hellman_ratchet import DiffieHellmanRatchet
from .kdf import KDF
from .migrations import parse_double_ratchet_model
from .models import DoubleRatchetModel, SkippedMessageKeyModel
from .types import EncryptedMessage, Header, JSONObject, SkippedMessageKeys


__all__ = [
    "DoubleRatchet",
    "DoubleRatchetSession"
]


DoubleRatchetTypeT = TypeVar("DoubleRatchetTypeT", bound="DoubleRatchet")


class _ReentrantLock:
    """
    An asyncio lock that may be re-acquired by the task that already holds it.

    Reentrancy is required because the public message en-/decryption methods serialize themselves, while a
    :class:`DoubleRatchetSession` allows grouping multiple of these calls into a single critical section.
    """

    def __init__(self) -> None:
        self.__lock = asyncio.Lock()
        self.__owner: Optional["asyncio.Task[object]"] = None
        self.__depth = 0

    async def acquire(self) -> None:
        """
        Acquire the lock, or increase the reentrancy depth if the current task already holds it.
        """

        task = asyncio.current_task()
        if task is not None and self.__owner is task:
            self.__depth += 1
            return

        await self.__lock.acquire()
        self.__owner = task
        self.__depth = 1

    def release(self) -> None:
        """
        Decrease the reentrancy depth and release the lock once it reaches zero.
        """

        if self.__depth == 0:
            raise RuntimeError("The operation lock is not held.")

        self.__depth -= 1
        if self.__depth == 0:
            self.__owner = None
            self.__lock.release()


class DoubleRatchet(ABC):
    """
    Combining the symmetric-key ratchet and the Diffie-Hellman ratchet gives the Double Ratchet.

    https://signal.org/docs/specifications/doubleratchet/#double-ratchet

    Note:
        In this implementation, the Diffie-Hellman ratchet already manages the symmetric-key ratchet
        internally, see :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet` for details. The
        Double Ratchet class adds message en-/decryption and offers a more convenient public API that handles
        lost and out-of-order messages.
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__max_num_skipped_message_keys: int
        self.__skipped_message_keys: SkippedMessageKeys
        self.__aead: Type[AEAD]
        self.__diffie_hellman_ratchet: DiffieHellmanRatchet

    @property
    def _operation_lock(self) -> _ReentrantLock:
        """
        Returns:
            The per-instance operation lock, created lazily on first use.

        Note:
            Lazy creation keeps the lock available even if a subclass overrides ``__init__`` without calling
            ``super().__init__()``. One instance is used per ratchet, so all operations on the same instance
            share the same critical section.
        """

        lock = self.__dict__.get("_operation_lock_instance")
        if lock is None:
            lock = _ReentrantLock()
            self.__dict__["_operation_lock_instance"] = lock

        return cast(_ReentrantLock, lock)

    @contextlib.asynccontextmanager
    async def _operation(self) -> AsyncIterator[None]:
        """
        Run the enclosed block as one serialized operation on this instance.

        Every send, receive and state export takes this lock, which makes concurrent use of a single
        instance safe: one operation at a time derives keys from and commits to the ratchet state. The lock
        is reentrant for the owning task, so operations may be grouped using :meth:`session`.
        """

        await self._operation_lock.acquire()
        try:
            yield
        finally:
            self._operation_lock.release()

    def session(self) -> "DoubleRatchetSession":
        """
        Returns:
            A context manager that groups multiple operations into a single serialized critical section.

        Note:
            This is the explicit concurrency entry point of :class:`DoubleRatchet`. All public operations
            are serialized individually even without a session. Use a session when a caller needs several
            operations (for example a receive and a subsequent state export) to happen without another task
            interleaving.
        """

        return DoubleRatchetSession(self._operation_lock)

    @classmethod
    async def encrypt_initial_message(
        cls: Type[DoubleRatchetTypeT],
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD],
        shared_secret: bytes,
        recipient_ratchet_pub: bytes,
        message: bytes,
        associated_data: bytes
    ) -> Tuple[DoubleRatchetTypeT, EncryptedMessage]:
        """
        Args:
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.
            shared_secret: A shared secret consisting of 32 bytes that was agreed on by means external to this
                protocol.
            recipient_ratchet_pub: The ratchet public key of the recipient.
            message: The initial message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            A configured instance of :class:`DoubleRatchet` ready to send and receive messages together with
            the initial message.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        if len(shared_secret) != 32:
            raise ValueError("The shared secret must consist of 32 bytes.")

        self = cls()
        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__skipped_message_keys = OrderedDict()
        self.__aead = aead
        self.__diffie_hellman_ratchet = await diffie_hellman_ratchet_class.create(
            None,
            recipient_ratchet_pub,
            root_chain_kdf,
            shared_secret,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        message_key, header = await self.__diffie_hellman_ratchet.next_encryption_key()
        ciphertext = await self.__aead.encrypt(
            message,
            message_key,
            self._build_associated_data(associated_data, header)
        )

        return (self, EncryptedMessage(header=header, ciphertext=ciphertext))

    @classmethod
    async def decrypt_initial_message(
        cls: Type[DoubleRatchetTypeT],
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD],
        shared_secret: bytes,
        own_ratchet_priv: bytes,
        message: EncryptedMessage,
        associated_data: bytes
    ) -> Tuple[DoubleRatchetTypeT, bytes]:
        """
        Args:
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.
            shared_secret: A shared secret that was agreed on by means external to this protocol.
            own_ratchet_priv: The ratchet private key to use initially.
            message: The encrypted initial message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            A configured instance of :class:`DoubleRatchet` ready to send and receive messages together with
            the decrypted initial message.

        Raises:
            AuthenticationFailedException: if the message could not be authenticated using the associated
                data.
            DecryptionFailedException: if the decryption failed for a different reason (e.g. invalid padding).
            DoSProtectionException: if a huge number of message keys were skipped that have to be calculated
                first before decrypting the message.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        if len(shared_secret) != 32:
            raise ValueError("The shared secret must consist of 32 bytes.")

        self = cls()
        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__aead = aead
        self.__diffie_hellman_ratchet = await diffie_hellman_ratchet_class.create(
            own_ratchet_priv,
            message.header.ratchet_pub,
            root_chain_kdf,
            shared_secret,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        message_key, skipped_message_keys = \
            await self.__diffie_hellman_ratchet.next_decryption_key(message.header)

        # Even the first message might have skipped message keys. The number of keys can't cross thresholds,
        # thus no FIFO discarding required.
        self.__skipped_message_keys = skipped_message_keys

        return (self, await self.__aead.decrypt(
            message.ciphertext,
            message_key,
            self._build_associated_data(associated_data, message.header)
        ))

    @property
    def sending_chain_length(self) -> int:
        """
        Returns:
            The length of the sending chain of the internal symmetric-key ratchet, as exposed by the internal
            Diffie-Hellman ratchet.
        """

        return self.__diffie_hellman_ratchet.sending_chain_length

    @property
    def receiving_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the receiving chain of the internal symmetric-key ratchet, if it exists, as exposed
            by the internal Diffie-Hellman ratchet.
        """

        return self.__diffie_hellman_ratchet.receiving_chain_length

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        """
        Args:
            associated_data: The associated data to prepend to the output. If the associated data is not
                guaranteed to be a parseable byte sequence, a length value should be prepended to ensure that
                the output is parseable as a unique pair (associated data, header).
            header: The message header to encode in a unique, reversible manner.

        Returns:
            A byte sequence encoding the associated data and the header in a unique, reversible way.
        """

    #################
    # serialization #
    #################

    @property
    def model(self) -> DoubleRatchetModel:
        """
        Returns:
            The internal state of this :class:`DoubleRatchet` as a pydantic model.

        Note:
            The internal state is only ever replaced at operation boundaries, after either a complete send,
            a complete receive, or a restore. Reading this property never observes a partially applied
            operation. When other tasks may use the instance concurrently, prefer :meth:`export_model` or
            :meth:`export_json`, which wait for a completed operation boundary explicitly.
        """

        return DoubleRatchetModel(
            diffie_hellman_ratchet=self.__diffie_hellman_ratchet.model,
            skipped_message_keys=[ SkippedMessageKeyModel(
                ratchet_pub=ratchet_pub,
                index=index,
                message_key=message_key
            ) for (ratchet_pub, index), message_key in self.__skipped_message_keys.items() ]
        )

    async def export_model(self) -> DoubleRatchetModel:
        """
        Returns:
            The internal state of this :class:`DoubleRatchet` as a pydantic model, captured at a completed
            operation boundary.

        Note:
            This method waits until no operation is in progress on this instance (or joins the current
            operation if called from the owning task inside a :meth:`session`). The returned state always
            corresponds to a state in which all preceding sends and receives have been committed completely.
        """

        async with self._operation():
            return self.model

    async def export_json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`DoubleRatchet` as a JSON-serializable Python object, captured
            at a completed operation boundary.

        Note:
            See :meth:`export_model`. The same consistency guarantee applies.
        """

        async with self._operation():
            return self.json

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`DoubleRatchet` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.model_dump_json()))

    @classmethod
    def from_model(
        cls: Type[DoubleRatchetTypeT],
        model: DoubleRatchetModel,
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD]
    ) -> DoubleRatchetTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`DoubleRatchet`, as produced
                by :attr:`model`.
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.

        Returns:
            A configured instance of :class:`DoubleRatchet`, with internal state restored from the model.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating an instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance using
                :meth:`encrypt_initial_message` or :meth:`decrypt_initial_message` without losing information.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        self = cls()
        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__skipped_message_keys = OrderedDict(
            ((smk.ratchet_pub, smk.index), smk.message_key)
            for smk
            in model.skipped_message_keys
        )
        self.__aead = aead
        self.__diffie_hellman_ratchet = diffie_hellman_ratchet_class.from_model(
            model.diffie_hellman_ratchet,
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        return self

    @classmethod
    def from_json(
        cls: Type[DoubleRatchetTypeT],
        serialized: JSONObject,
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD]
    ) -> DoubleRatchetTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a
                :class:`DoubleRatchet`, as produced by :attr:`json`.
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.

        Returns:
            A configured instance of :class:`DoubleRatchet`, with internal state restored from the serialized
            data.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating an instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance using
                :meth:`encrypt_initial_message` or :meth:`decrypt_initial_message` without losing information.
        """

        return cls.from_model(
            parse_double_ratchet_model(serialized),
            diffie_hellman_ratchet_class,
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold,
            max_num_skipped_message_keys,
            aead
        )

    #########################
    # message en/decryption #
    #########################

    async def encrypt_message(self, message: bytes, associated_data: bytes) -> EncryptedMessage:
        """
        Args:
            message: The message to encrypt.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The encrypted message including the header to send to the recipient.

        Note:
            This operation is serialized with all other operations on this instance. The sending chain is
            advanced on a clone and only committed after the AEAD operation succeeded, so a failed or
            cancelled call leaves the ratchet state untouched.
        """

        async with self._operation():
            # Work on a clone so that a failed or cancelled encryption does not consume a message key.
            diffie_hellman_ratchet = copy.deepcopy(self.__diffie_hellman_ratchet)

            message_key, header = await diffie_hellman_ratchet.next_encryption_key()
            ciphertext = await self.__aead.encrypt(
                message,
                message_key,
                self._build_associated_data(associated_data, header)
            )

            # Commit only after the ciphertext has been produced successfully.
            self.__diffie_hellman_ratchet = diffie_hellman_ratchet

            return EncryptedMessage(header=header, ciphertext=ciphertext)

    async def decrypt_message(self, message: EncryptedMessage, associated_data: bytes) -> bytes:
        """
        Args:
            message: The encrypted message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The message plaintext, after decrypting and authenticating the ciphertext.

        Raises:
            AuthenticationFailedException: if the message could not be authenticated using the associated
                data.
            DecryptionFailedException: if the decryption failed for a different reason (e.g. invalid padding).
            DoSProtectionException: if a huge number of message keys were skipped that have to be calculated
                first before decrypting the message.
            DuplicateMessageException: if this message appears to be a duplicate.

        Note:
            This operation is serialized with all other operations on this instance. Each call starts from
            the most recently committed state, so when the same ciphertext is submitted concurrently, only
            the first successful decryption delivers the plaintext. Subsequent calls observe the committed
            state and raise :class:`DuplicateMessageException` (or an authentication error, depending on the
            ratchet position) instead of re-delivering the message.
        """

        # Be careful to only keep changes to the internal state on decryption success. To do so, work with a
        # clone of the Diffie-Hellman ratchet, discard the clone on failure or replace the original with the
        # clone on success.
        # https://signal.org/docs/specifications/doubleratchet/#decrypting-messages

        async with self._operation():
            diffie_hellman_ratchet = copy.deepcopy(self.__diffie_hellman_ratchet)
            skipped_message_keys: Optional[SkippedMessageKeys] = None
            skipped_message_key_key = (message.header.ratchet_pub, message.header.sending_chain_length)

            # Get the message key, either from the skipped message keys or from the Diffie-Hellman ratchet
            # clone.
            message_key: bytes
            try:
                message_key = self.__skipped_message_keys[skipped_message_key_key]
            except KeyError:
                message_key, skipped_message_keys = \
                    await diffie_hellman_ratchet.next_decryption_key(message.header)

            # Decrypt the message (or at least attempt to do so). At this point, the internal state of this
            # instance remains untouched.
            plaintext = await self.__aead.decrypt(
                message.ciphertext,
                message_key,
                self._build_associated_data(associated_data, message.header)
            )

            # Following decryption success, apply relevant changes to the internal state.

            # In case a skipped message key was used, remove it.
            self.__skipped_message_keys.pop(skipped_message_key_key, None)

            # Store new skipped message keys and limit their number.
            if skipped_message_keys is not None:
                self.__skipped_message_keys.update(skipped_message_keys)
                self.__skipped_message_keys = OrderedDict(itertools.islice(
                    self.__skipped_message_keys.items(),
                    max(len(self.__skipped_message_keys) - self.__max_num_skipped_message_keys, 0),
                    None
                ))

            # Store the clone.
            self.__diffie_hellman_ratchet = diffie_hellman_ratchet

            return plaintext


class DoubleRatchetSession:
    """
    A context manager grouping multiple operations on a :class:`DoubleRatchet` into one serialized critical
    section.

    All operations on a :class:`DoubleRatchet` instance are serialized individually. A session additionally
    guarantees that no other task may interleave between the operations performed inside the ``async with``
    block. This is the explicit concurrency entry point: instead of optimistically deriving keys from a
    shared snapshot and resolving conflicts later, the session commits one operation at a time, so two
    operations can never both succeed from the same starting state and overwrite each other.

    The lock is reentrant for the owning task: calling :meth:`DoubleRatchet.encrypt_message`,
    :meth:`DoubleRatchet.decrypt_message`, :meth:`DoubleRatchet.export_model` or
    :meth:`DoubleRatchet.export_json` inside a session does not deadlock. A task that is cancelled while
    waiting for the session never observes or modifies the ratchet state.

    Example:
        ::

            async with ratchet.session():
                plaintext = await ratchet.decrypt_message(message, associated_data)
                snapshot = await ratchet.export_json()
    """

    def __init__(self, lock: _ReentrantLock) -> None:
        self.__lock = lock
        self.__entered = False

    async def __aenter__(self) -> "DoubleRatchetSession":
        await self.__lock.acquire()
        self.__entered = True
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType]
    ) -> None:
        if self.__entered:
            self.__entered = False
            self.__lock.release()
