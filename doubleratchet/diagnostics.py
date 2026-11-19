from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import enum
from typing import Deque, Iterator, Optional, Tuple, TypeVar

from .types import Header


__all__ = [
    "EvictionReason",
    "MessagePosition",
    "ReceiveDiagnostic",
    "ReceiveDiagnostics",
    "ReceiveResult",
    "ReceiveStatus"
]


SkippedMessageKeyPosition = Tuple[bytes, int]

KeyT = TypeVar("KeyT")


class ReceiveStatus(enum.Enum):
    """
    The outcome of a single receive attempt, as observed by the diagnostics.

    The values are intentionally limited to the cases that can be explained from the public message
    position and the local skipped-message-key cache. A failed authentication is reported as such even if
    the message header is old or the identical header was seen before, because the diagnostics only claim
    "already processed" for positions they observed being accepted.
    """

    ACCEPTED = "accepted"
    """
    The message was authenticated and decrypted successfully. If a cached skipped message key was used, it
    was consumed by this attempt.
    """

    ALREADY_PROCESSED = "already_processed"
    """
    The exact message position was processed successfully before. This is reported for replayed messages,
    including replays of messages from chains that have since been superseded.
    """

    MISSING_HISTORICAL_KEY = "missing_historical_key"
    """
    The exact message position has no key available anymore. This is typically caused by FIFO eviction from
    the bounded skipped-message-key cache, and is reported independently of any later (higher) chain index.
    """

    AUTHENTICATION_FAILED = "authentication_failed"
    """
    A key for the message position was available and used, but the ciphertext could not be authenticated or
    decrypted. A failed attempt does not consume or evict any key.
    """


class EvictionReason(enum.Enum):
    """
    Why a historical message key is no longer available.
    """

    EVICTED = "evicted"
    """
    The exact position was present in the skipped-message-key cache and was removed because the cache limit
    was exceeded. This is only reported for positions that the diagnostics observed being evicted.
    """

    NOT_RETAINED = "not_retained"
    """
    The exact position was not present in the diagnostics' bounded history. It was either never stored, was
    evicted before diagnostics were enabled, or its history entry was discarded. No stronger claim is made.
    """


@dataclass(frozen=True)
class MessagePosition:
    """
    The public position of a message inside the conversation, encoded in its header.

    This structure deliberately contains no message key, plaintext or ratchet state. For positions loaded
    from the skipped-message-key cache, :attr:`previous_sending_chain_length` is ``None`` because the cache
    stores keys by ``(ratchet public key, sending chain length)`` only.
    """

    ratchet_pub: bytes
    sending_chain_length: int
    previous_sending_chain_length: Optional[int] = None

    @classmethod
    def from_header(cls, header: Header) -> "MessagePosition":
        """
        Args:
            header: The public header of an encrypted message.

        Returns:
            The position encoded by the header.
        """

        return cls(
            ratchet_pub=header.ratchet_pub,
            sending_chain_length=header.sending_chain_length,
            previous_sending_chain_length=header.previous_sending_chain_length
        )

    @classmethod
    def from_key(cls, key: SkippedMessageKeyPosition) -> "MessagePosition":
        """
        Args:
            key: A key of the skipped-message-key cache.

        Returns:
            The position encoded by the cache key. The previous sending chain length is unknown.
        """

        return cls(ratchet_pub=key[0], sending_chain_length=key[1])

    @property
    def index(self) -> int:
        """
        Returns:
            Alias for :attr:`sending_chain_length`.
        """

        return self.sending_chain_length

    @property
    def key(self) -> SkippedMessageKeyPosition:
        """
        Returns:
            The corresponding skipped-message-key cache key.
        """

        return (self.ratchet_pub, self.sending_chain_length)


@dataclass(frozen=True)
class ReceiveDiagnostic:
    """
    A single, secret-free receive diagnostic.

    The diagnostic references only the public message position and, where applicable, the reason why a
    historical key is unavailable. It never contains message keys, plaintext or serialized ratchet state.
    """

    status: ReceiveStatus
    position: MessagePosition
    reason: Optional[EvictionReason] = None
    evicted: Tuple[MessagePosition, ...] = ()
    cache_size: Optional[int] = None
    cache_limit: Optional[int] = None

    @property
    def outcome(self) -> ReceiveStatus:
        """
        Returns:
            Alias for :attr:`status`.
        """

        return self.status

    @property
    def accepted(self) -> bool:
        """
        Returns:
            Whether the message was authenticated and decrypted successfully.
        """

        return self.status is ReceiveStatus.ACCEPTED


@dataclass(frozen=True)
class ReceiveResult:
    """
    The result of :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_message_with_diagnostics`.

    On success, :attr:`plaintext` contains the decrypted message and :attr:`diagnostic` reports
    :attr:`~ReceiveStatus.ACCEPTED`. On an expected failure, :attr:`plaintext` is ``None`` and the diagnostic
    explains the boundary that was hit. Unexpected errors (for example DoS protection) are propagated as
    exceptions instead.
    """

    plaintext: Optional[bytes]
    diagnostic: ReceiveDiagnostic

    @property
    def status(self) -> ReceiveStatus:
        """
        Returns:
            Alias for ``self.diagnostic.status``.
        """

        return self.diagnostic.status

    @property
    def accepted(self) -> bool:
        """
        Returns:
            Whether the message was authenticated and decrypted successfully.
        """

        return self.diagnostic.accepted

    def __iter__(self) -> Iterator[Optional[bytes] | ReceiveDiagnostic]:
        """
        Allow ``plaintext, diagnostic`` unpacking of the result.
        """

        yield self.plaintext
        yield self.diagnostic


class ReceiveDiagnostics:
    """
    A bounded, in-memory log of secret-free receive diagnostics.

    The log remembers which exact public message positions were accepted and which were evicted from the
    skipped-message-key cache. This allows a later attempt to distinguish ``already processed`` from
    ``missing historical key`` without reconstructing keys or inspecting any secret. Entries are kept in a
    bounded FIFO history; once an entry falls out of that history, the diagnostics conservatively report
    :attr:`~EvictionReason.NOT_RETAINED` instead of claiming knowledge it no longer has.

    Diagnostics are intentionally not part of the serialized Double Ratchet state. They are a local,
    best-effort operational aid and never influence the ratchet's message key state.
    """

    DEFAULT_HISTORY_LIMIT = 1024

    def __init__(self, history_limit: int = DEFAULT_HISTORY_LIMIT) -> None:
        """
        Args:
            history_limit: The maximum number of diagnostic records and remembered positions to keep.

        Raises:
            ValueError: if ``history_limit`` is not positive.
        """

        if history_limit <= 0:
            raise ValueError("The diagnostics history limit must be positive.")

        self.__history_limit = history_limit
        self.__records: Deque[ReceiveDiagnostic] = deque(maxlen=history_limit)
        self.__processed: OrderedDict[SkippedMessageKeyPosition, None] = OrderedDict()
        self.__evicted: OrderedDict[SkippedMessageKeyPosition, None] = OrderedDict()
        self.__known_chains: OrderedDict[bytes, None] = OrderedDict()

    @property
    def history_limit(self) -> int:
        """
        Returns:
            The maximum number of records and remembered positions kept by this instance.
        """

        return self.__history_limit

    @property
    def records(self) -> Tuple[ReceiveDiagnostic, ...]:
        """
        Returns:
            All retained diagnostic records, oldest first.
        """

        return tuple(self.__records)

    @property
    def last(self) -> Optional[ReceiveDiagnostic]:
        """
        Returns:
            The most recent diagnostic record, if any.
        """

        return self.__records[-1] if self.__records else None

    def clear(self) -> None:
        """
        Discard all recorded diagnostics and historical position knowledge.
        """

        self.__records.clear()
        self.__processed.clear()
        self.__evicted.clear()
        self.__known_chains.clear()

    def __len__(self) -> int:
        return len(self.__records)

    def __iter__(self) -> Iterator[ReceiveDiagnostic]:
        return iter(self.__records)

    def register_chain(self, ratchet_pub: bytes) -> None:
        """
        Remember that a Diffie-Hellman ratchet public key belongs to this conversation. The value is public
        and is transmitted in every message header.

        Args:
            ratchet_pub: The ratchet public key to remember.
        """

        self.__remember(self.__known_chains, ratchet_pub)

    def sees_chain(self, ratchet_pub: bytes) -> bool:
        """
        Args:
            ratchet_pub: The ratchet public key to look up.

        Returns:
            Whether this diagnostics instance has observed the chain before.
        """

        return ratchet_pub in self.__known_chains

    def was_processed(self, position: MessagePosition) -> bool:
        """
        Args:
            position: The public message position to look up.

        Returns:
            Whether this exact position was accepted by a previous diagnostic-enabled receive attempt.
        """

        return position.key in self.__processed

    def eviction_reason(self, position: MessagePosition) -> EvictionReason:
        """
        Args:
            position: The public message position to look up.

        Returns:
            :attr:`~EvictionReason.EVICTED` if this exact position was observed being evicted, otherwise
            :attr:`~EvictionReason.NOT_RETAINED`.
        """

        return EvictionReason.EVICTED if position.key in self.__evicted else EvictionReason.NOT_RETAINED

    def record_accepted(
        self,
        position: MessagePosition,
        *,
        evicted: Tuple[MessagePosition, ...] = (),
        cache_size: Optional[int] = None,
        cache_limit: Optional[int] = None
    ) -> ReceiveDiagnostic:
        """
        Record a successfully authenticated and decrypted message.

        Args:
            position: The public position of the accepted message.
            evicted: Positions evicted from the skipped-message-key cache while applying this message.
            cache_size: The skipped-message-key cache size after the message was applied.
            cache_limit: The configured skipped-message-key cache limit.

        Returns:
            The recorded diagnostic.
        """

        self.__remember(self.__processed, position.key)
        self.register_chain(position.ratchet_pub)
        for evicted_position in evicted:
            self.__remember(self.__evicted, evicted_position.key)
        return self.__append(ReceiveDiagnostic(
            status=ReceiveStatus.ACCEPTED,
            position=position,
            evicted=evicted,
            cache_size=cache_size,
            cache_limit=cache_limit
        ))

    def record_already_processed(
        self,
        position: MessagePosition,
        *,
        cache_size: Optional[int] = None,
        cache_limit: Optional[int] = None
    ) -> ReceiveDiagnostic:
        """
        Record an attempt at a position that was accepted successfully before.

        Args:
            position: The public position of the replayed message.
            cache_size: The current skipped-message-key cache size.
            cache_limit: The configured skipped-message-key cache limit.

        Returns:
            The recorded diagnostic.
        """

        return self.__append(ReceiveDiagnostic(
            status=ReceiveStatus.ALREADY_PROCESSED,
            position=position,
            cache_size=cache_size,
            cache_limit=cache_limit
        ))

    def record_missing_historical_key(
        self,
        position: MessagePosition,
        *,
        cache_size: Optional[int] = None,
        cache_limit: Optional[int] = None
    ) -> ReceiveDiagnostic:
        """
        Record an attempt at a position whose exact key is no longer available.

        Args:
            position: The public position of the message.
            cache_size: The current skipped-message-key cache size.
            cache_limit: The configured skipped-message-key cache limit.

        Returns:
            The recorded diagnostic, with :attr:`~ReceiveDiagnostic.reason` set to the best available
            eviction reason.
        """

        return self.__append(ReceiveDiagnostic(
            status=ReceiveStatus.MISSING_HISTORICAL_KEY,
            position=position,
            reason=self.eviction_reason(position),
            cache_size=cache_size,
            cache_limit=cache_limit
        ))

    def record_authentication_failed(
        self,
        position: MessagePosition,
        *,
        cache_size: Optional[int] = None,
        cache_limit: Optional[int] = None
    ) -> ReceiveDiagnostic:
        """
        Record an attempt that had a usable key but failed authentication/decryption.

        Args:
            position: The public position of the message.
            cache_size: The current skipped-message-key cache size; failed attempts leave it unchanged.
            cache_limit: The configured skipped-message-key cache limit.

        Returns:
            The recorded diagnostic.
        """

        return self.__append(ReceiveDiagnostic(
            status=ReceiveStatus.AUTHENTICATION_FAILED,
            position=position,
            cache_size=cache_size,
            cache_limit=cache_limit
        ))

    def __append(self, diagnostic: ReceiveDiagnostic) -> ReceiveDiagnostic:
        self.__records.append(diagnostic)
        return diagnostic

    def __remember(self, store: OrderedDict[KeyT, None], key: KeyT) -> None:
        store[key] = None
        store.move_to_end(key)
        while len(store) > self.__history_limit:
            store.popitem(last=False)
