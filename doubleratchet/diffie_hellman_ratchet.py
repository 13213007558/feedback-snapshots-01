from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict
import enum
import json
from typing import NamedTuple, Optional, Tuple, Type, TypeVar, cast
import warnings

from .kdf import KDF
from .kdf_chain import KDFChain
from .migrations import InconsistentSerializationException, parse_diffie_hellman_ratchet_model
from .models import DiffieHellmanRatchetModel
from .symmetric_key_ratchet import Chain, SymmetricKeyRatchet
from .types import Header, JSONObject, SkippedMessageKeys


__all__ = [
    "DiffieHellmanRatchet",
    "DoSProtectionException",
    "DuplicateMessageException",
    "MessageWorkBudget",
    "OldChainSkipPolicy"
]


class DoSProtectionException(Exception):
    """
    Raised by :meth:`DiffieHellmanRatchet.next_decryption_key` in case the number of skipped message keys to
    calculate crosses the DoS protection threshold or the per-message work budget.
    """


class DuplicateMessageException(Exception):
    """
    Raised by :meth:`DiffieHellmanRatchet.next_decryption_key` in case is seems the message was processed
    before.
    """


@enum.unique
class OldChainSkipPolicy(enum.Enum):
    """
    Policy deciding how to react when a Diffie-Hellman ratchet step is requested by a message header whose
    ``previous_sending_chain_length`` skips more keys of the previous receiving chain than the DoS protection
    threshold allows to calculate.
    """

    WARN = "WARN"
    """
    Skip calculating the excessive skipped message keys of the previous receiving chain (a warning is issued)
    and still perform the ratchet step. This preserves the ability to recover from heavy message loss by
    moving forward through a ratchet step, at the fixed cost of the ratchet step itself.
    """

    RAISE = "RAISE"
    """
    Reject the message with a :class:`DoSProtectionException` instead of silently dropping skipped message
    keys. The ratchet is not moved forward, i.e. recovery from heavy message loss through a ratchet step is
    not possible while this policy is active.
    """


class MessageWorkBudget(NamedTuple):
    """
    Upper bound on the cryptographic work that a single call to
    :meth:`DiffieHellmanRatchet.next_decryption_key` (and thus a single received message) may cause.

    The budget covers *all* work triggered by the message, including skipped message keys that are calculated
    and later discarded because they exceed the storage limit, not just the state that is ultimately retained:

    * Each KDF chain step (root chain step when replacing a chain and message chain step when deriving a
      message key) counts as one KDF derivation.
    * Each Diffie-Hellman ratchet step performs two chain replacements, each of which performs one
      Diffie-Hellman key exchange.
    """

    kdf_derivations: int
    """The maximum total number of KDF derivations performed while handling one message."""

    diffie_hellman_operations: int
    """The maximum total number of Diffie-Hellman key exchanges performed while handling one message."""

    @classmethod
    def from_dos_protection_threshold(cls, dos_protection_threshold: int) -> "MessageWorkBudget":
        """
        Derive a work budget from a DoS protection threshold, covering the work allowed by the default
        behavior.

        A received message can skip message keys in two places: in the previous receiving chain before a
        Diffie-Hellman ratchet step and in the current/new receiving chain. Each branch can contribute up to
        the DoS protection threshold worth of *calculated* message keys (the previous chain is silently
        capped under the default :attr:`OldChainSkipPolicy.WARN` policy, the current chain hard-rejects past
        the threshold). On top of that, a ratchet step performs two root chain steps and the requested
        message key itself costs one message chain step.

        Args:
            dos_protection_threshold: The maximum number of skipped message keys calculated per branch.

        Returns:
            A budget covering the worst case of one received message under the given threshold.
        """

        if dos_protection_threshold < 0:
            raise ValueError("The DoS protection threshold must not be negative.")

        return cls(
            kdf_derivations=2 * dos_protection_threshold + 3,
            diffie_hellman_operations=2
        )


DiffieHellmanRatchetTypeT = TypeVar("DiffieHellmanRatchetTypeT", bound="DiffieHellmanRatchet")


class DiffieHellmanRatchet(ABC):
    """
    As communication partners exchange messages they also exchange new Diffie-Hellman public keys, and the
    Diffie-Hellman output secrets become the inputs to the root chain. The output keys from the root chain
    become new KDF keys for the sending and receiving chains. This is called the Diffie-Hellman ratchet.

    https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet

    Note:
        The specification introduces the symmetric-key ratchet and the Diffie-Hellman ratchet as independent
        units and links them together in the Double Ratchet. This implementation does not follow that
        separation, instead the Diffie-Hellman ratchet manages the symmetric-key ratchet internally, which
        makes the code a little less complicated, as the Double Ratchet doesn't have to forward keys generated
        by the Diffie-Hellman ratchet to the symmetric-key ratchet.
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__own_ratchet_priv: bytes
        self.__other_ratchet_pub: bytes
        self.__root_chain: KDFChain
        self.__dos_protection_threshold: int
        self.__message_work_budget: MessageWorkBudget
        self.__old_chain_skip_policy: OldChainSkipPolicy
        self.__symmetric_key_ratchet: SymmetricKeyRatchet

    @classmethod
    async def create(
        cls: Type[DiffieHellmanRatchetTypeT],
        own_ratchet_priv: Optional[bytes],
        other_ratchet_pub: bytes,
        root_chain_kdf: Type[KDF],
        root_chain_key: bytes,
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        message_work_budget: Optional[MessageWorkBudget] = None,
        old_chain_skip_policy: OldChainSkipPolicy = OldChainSkipPolicy.WARN
    ) -> DiffieHellmanRatchetTypeT:
        """
        Create and configure a Diffie-Hellman ratchet.

        Args:
            own_ratchet_priv: The ratchet private key to use initially with this instance.
            other_ratchet_pub: The ratchet public key of the other party.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            root_chain_key: The key to initialize the root chain with, consisting of 32 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            message_work_budget: The maximum total amount of KDF derivations and Diffie-Hellman operations a
                single received message may cause. Defaults to the worst case allowed by the DoS protection
                threshold (see :meth:`MessageWorkBudget.from_dos_protection_threshold`).
            old_chain_skip_policy: The policy to apply when a ratchet step skips more message keys of the
                previous receiving chain than the DoS protection threshold allows to calculate. The default
                preserves the ability to recover from heavy message loss through a ratchet step.
            message_work_budget: The maximum total amount of KDF derivations and Diffie-Hellman operations a
                single received message may cause. Defaults to the worst case allowed by the DoS protection
                threshold (see :meth:`MessageWorkBudget.from_dos_protection_threshold`).
            old_chain_skip_policy: The policy to apply when a ratchet step skips more message keys of the
                previous receiving chain than the DoS protection threshold allows to calculate. The default
                preserves the ability to recover from heavy message loss through a ratchet step.

        Returns:
            A configured instance of :class:`DiffieHellmanRatchet`, capable of sending and receiving messages.
        """

        if len(root_chain_key) != 32:
            raise ValueError("The initial key for the root chain must consist of 32 bytes.")

        if dos_protection_threshold < 0:
            raise ValueError("The DoS protection threshold must not be negative.")

        if message_work_budget is None:
            message_work_budget = MessageWorkBudget.from_dos_protection_threshold(dos_protection_threshold)

        if message_work_budget.kdf_derivations < 0 or message_work_budget.diffie_hellman_operations < 0:
            raise ValueError("The message work budget must not contain negative limits.")

        self = cls()
        self.__root_chain = KDFChain.create(root_chain_kdf, root_chain_key)
        self.__dos_protection_threshold = dos_protection_threshold
        self.__message_work_budget = message_work_budget
        self.__old_chain_skip_policy = old_chain_skip_policy
        self.__symmetric_key_ratchet = SymmetricKeyRatchet.create(message_chain_kdf, message_chain_constant)

        if own_ratchet_priv is None:
            self.__own_ratchet_priv = self._generate_priv()
            self.__other_ratchet_pub = other_ratchet_pub
            await self.__replace_chain(Chain.SENDING)
        else:
            self.__own_ratchet_priv = own_ratchet_priv
            self.__other_ratchet_pub = other_ratchet_pub
            await self.__replace_chain(Chain.RECEIVING)
            self.__own_ratchet_priv = self._generate_priv()
            await self.__replace_chain(Chain.SENDING)

        return self

    @property
    def sending_chain_length(self) -> int:
        """
        Returns:
            The length of the sending chain of the internal symmetric-key ratchet.
        """

        # Sanity check; the sending chain must exist
        assert self.__symmetric_key_ratchet.sending_chain_length is not None
        return self.__symmetric_key_ratchet.sending_chain_length

    @property
    def receiving_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the receiving chain of the internal symmetric-key ratchet, if it exists.
        """

        return self.__symmetric_key_ratchet.receiving_chain_length

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    def _generate_priv() -> bytes:
        """
        Returns:
            A freshly generated private key, capable of performing Diffie-Hellman key exchanges with the
            public key of another party.

        Note:
            This function is recommended to generate a key pair based on the Curve25519 or Curve448 elliptic
            curves
            (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms).
        """

    @staticmethod
    @abstractmethod
    def _derive_pub(priv: bytes) -> bytes:
        """
        Derive the public key from a private key as generated by :meth:`_generate_priv`.

        Args:
            priv: The private key as returned by :meth:`_generate_priv`.

        Returns:
            The public key corresponding to the private key.
        """

    @staticmethod
    @abstractmethod
    def _perform_diffie_hellman(own_priv: bytes, other_pub: bytes) -> bytes:
        """
        Args:
            own_priv: The own ratchet private key.
            other_pub: The ratchet public key of the other party.

        Returns:
            A shared secret agreed on via Diffie-Hellman. This method is recommended to perform X25519 or
            X448. There is no need to check for invalid public keys
            (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms).
        """

    #################
    # serialization #
    #################

    @property
    def model(self) -> DiffieHellmanRatchetModel:
        """
        Returns:
            The internal state of this :class:`DiffieHellmanRatchet` as a pydantic model.
        """

        return DiffieHellmanRatchetModel(
            own_ratchet_priv=self.__own_ratchet_priv,
            other_ratchet_pub=self.__other_ratchet_pub,
            root_chain=self.__root_chain.model,
            symmetric_key_ratchet=self.__symmetric_key_ratchet.model
        )

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`DiffieHellmanRatchet` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.model_dump_json()))

    @classmethod
    def from_model(
        cls: Type[DiffieHellmanRatchetTypeT],
        model: DiffieHellmanRatchetModel,
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        message_work_budget: Optional[MessageWorkBudget] = None,
        old_chain_skip_policy: OldChainSkipPolicy = OldChainSkipPolicy.WARN
    ) -> DiffieHellmanRatchetTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`DiffieHellmanRatchet`, as
                produced by :attr:`model`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            message_work_budget: The maximum total amount of KDF derivations and Diffie-Hellman operations a
                single received message may cause. Defaults to the worst case allowed by the DoS protection
                threshold (see :meth:`MessageWorkBudget.from_dos_protection_threshold`).
            old_chain_skip_policy: The policy to apply when a ratchet step skips more message keys of the
                previous receiving chain than the DoS protection threshold allows to calculate. The default
                preserves the ability to recover from heavy message loss through a ratchet step.

        Returns:
            A configured instance of :class:`DiffieHellmanRatchet`, with internal state restored from the
            model.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating a
                :class:`~doubleratchet.double_ratchet.DoubleRatchet` instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance without losing
                information.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        self = cls()
        self.__own_ratchet_priv = model.own_ratchet_priv
        self.__other_ratchet_pub = model.other_ratchet_pub
        self.__root_chain = KDFChain.from_model(model.root_chain, root_chain_kdf)
        self.__dos_protection_threshold = dos_protection_threshold
        if message_work_budget is None:
            message_work_budget = MessageWorkBudget.from_dos_protection_threshold(dos_protection_threshold)
        self.__message_work_budget = message_work_budget
        self.__old_chain_skip_policy = old_chain_skip_policy
        self.__symmetric_key_ratchet = SymmetricKeyRatchet.from_model(
            model.symmetric_key_ratchet,
            message_chain_kdf,
            message_chain_constant
        )

        if self.__symmetric_key_ratchet.sending_chain_length is None:
            raise InconsistentSerializationException(
                "The restored internal state does not contain an initialized sending chain."
            )

        return self

    @classmethod
    def from_json(
        cls: Type[DiffieHellmanRatchetTypeT],
        serialized: JSONObject,
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        message_work_budget: Optional[MessageWorkBudget] = None,
        old_chain_skip_policy: OldChainSkipPolicy = OldChainSkipPolicy.WARN
    ) -> DiffieHellmanRatchetTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a
                :class:`DiffieHellmanRatchet`, as produced by :attr:`json`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            message_work_budget: The maximum total amount of KDF derivations and Diffie-Hellman operations a
                single received message may cause. Defaults to the worst case allowed by the DoS protection
                threshold (see :meth:`MessageWorkBudget.from_dos_protection_threshold`).
            old_chain_skip_policy: The policy to apply when a ratchet step skips more message keys of the
                previous receiving chain than the DoS protection threshold allows to calculate. The default
                preserves the ability to recover from heavy message loss through a ratchet step.

        Returns:
            A configured instance of :class:`DiffieHellmanRatchet`, with internal state restored from the
            serialized data.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating a
                :class:`~doubleratchet.double_ratchet.DoubleRatchet` instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance without losing
                information.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        return cls.from_model(
            parse_diffie_hellman_ratchet_model(serialized),
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold,
            message_work_budget,
            old_chain_skip_policy
        )

    ######################
    # ratchet management #
    ######################

    async def __replace_chain(self, chain: Chain) -> None:
        """
        Replace one of the chains of the internal symmetric-key ratchet. The chain key is derived by feeding
        the Diffie-Hellman shared secret to the root chain.

        Args:
            chain: The chain to replace.
        """

        self.__symmetric_key_ratchet.replace_chain(chain, await self.__root_chain.step(
            self._perform_diffie_hellman(self.__own_ratchet_priv, self.__other_ratchet_pub),
            32
        ))

    async def next_encryption_key(self) -> Tuple[bytes, Header]:
        """
        Returns:
            The next (32 bytes) encryption key derived from the sending chain and the corresponding
            Diffie-Hellman ratchet header.
        """

        sending_chain_length = self.__symmetric_key_ratchet.sending_chain_length
        assert sending_chain_length is not None  # sanity check

        previous_sending_chain_length = self.__symmetric_key_ratchet.previous_sending_chain_length or 0

        header = Header(
            ratchet_pub=self._derive_pub(self.__own_ratchet_priv),
            previous_sending_chain_length=previous_sending_chain_length,
            sending_chain_length=sending_chain_length
        )

        next_encryption_key = await self.__symmetric_key_ratchet.next_encryption_key()

        return next_encryption_key, header

    async def next_decryption_key(self, header: Header) -> Tuple[bytes, SkippedMessageKeys]:
        """
        Args:
            header: The Diffie-Hellman ratchet header,

        Returns:
            The next (32 bytes) decryption key derived from the receiving chain and message keys that were
            skipped while deriving the new decryption key.

        Raises:
            DoSProtectionException: if a huge number of message keys were skipped that have to be calculated
                first before decrypting the next message, or if the total KDF/Diffie-Hellman work required by
                this message would exceed the configured :class:`MessageWorkBudget`.
            DuplicateMessageException: if this message appears to be a duplicate.

        Note:
            All budget and threshold checks are performed before any cryptographic work or state change. A
            rejected message therefore leaves the internal state untouched.
        """

        skipped_message_keys: SkippedMessageKeys = OrderedDict()

        # Account for and validate the complete work caused by this message up front, before performing any
        # KDF derivation, Diffie-Hellman operation or state change. The budget covers every skipped message
        # key derivation triggered by the header (including keys later discarded due to storage limits), the
        # root chain steps of a Diffie-Hellman ratchet step and the final message key derivation, not just the
        # state that is retained afterwards.
        performs_ratchet_step = header.ratchet_pub != self.__other_ratchet_pub

        # Skips requested by the header in the previous receiving chain (before a ratchet step). Under the
        # default WARN policy, only ``dos_protection_threshold`` of them are actually calculated (the rest is
        # skipped with a warning to preserve recovery), but the budget still accounts for the requested work.
        old_chain_skipped_keys_requested = 0
        old_chain_skipped_keys_performed = 0
        if performs_ratchet_step:
            receiving_chain_length = self.__symmetric_key_ratchet.receiving_chain_length
            if receiving_chain_length is not None:
                old_chain_skipped_keys_requested = max(
                    header.previous_sending_chain_length - receiving_chain_length,
                    0
                )
                if old_chain_skipped_keys_requested > self.__dos_protection_threshold:
                    if self.__old_chain_skip_policy is OldChainSkipPolicy.RAISE:
                        raise DoSProtectionException(
                            f"More than {self.__dos_protection_threshold} message keys skipped in the"
                            " previous receiving chain. Rejecting the message instead of silently dropping"
                            " skipped message keys."
                        )
                    # This is a warning rather than an exception, to make sure that in case of heavy message
                    # loss, the ratchet is not fully blocked from moving forward/"recovering" through a
                    # ratchet step.
                    warnings.warn(
                        f"More than {self.__dos_protection_threshold} message keys skipped. Not calculating"
                        " all of these message keys to prevent being DoSed."
                    )
                    old_chain_skipped_keys_performed = self.__dos_protection_threshold
                else:
                    old_chain_skipped_keys_performed = old_chain_skipped_keys_requested

        # Determine the skips in the current/new receiving chain. Without a ratchet step the receiving chain
        # already exists and the baseline is its current length. A ratchet step replaces it with a fresh chain
        # starting at length 0, so the post-step baseline is 0 in that case. The duplicate check only applies
        # without a ratchet step: a step installs a fresh chain that can't contain old indices.
        if performs_ratchet_step:
            new_chain_baseline_length = 0
        else:
            new_chain_baseline_length = self.__symmetric_key_ratchet.receiving_chain_length
            assert new_chain_baseline_length is not None  # sanity check
            # A message key requested that was derived before is a duplicate and requires no work.
            if header.sending_chain_length < new_chain_baseline_length:
                raise DuplicateMessageException(
                    f"It seems like this message was already decrypted before. Header: {header}"
                )

        new_chain_skipped_keys = max(header.sending_chain_length - new_chain_baseline_length, 0)
        # Hard limit on the current/new receiving chain, matching the original behavior: without a ratchet
        # step these are skips in the existing chain; after a step the fresh chain starts at length 0, so an
        # over-threshold n is rejected outright. Only the *previous* (discarded) chain gets the soft warning.
        if new_chain_skipped_keys > self.__dos_protection_threshold:
            raise DoSProtectionException(
                f"More than {self.__dos_protection_threshold} message keys skipped. Not calculating all of"
                " these message keys to prevent being DoSed."
            )

        diffie_hellman_operations = 2 if performs_ratchet_step else 0
        # A ratchet step replaces two chains: two root chain KDF steps (one per Diffie-Hellman operation),
        # every skipped message key and the final requested message key each cost one message chain KDF step.
        # The budget counts the work the header requests (including old-chain skips that get capped and keys
        # later discarded on storage), while the loops below only execute the capped, actually performed work.
        kdf_derivations_requested = (
            diffie_hellman_operations
            + old_chain_skipped_keys_requested
            + new_chain_skipped_keys
            + 1
        )
        if (
            kdf_derivations_requested > self.__message_work_budget.kdf_derivations
            or diffie_hellman_operations > self.__message_work_budget.diffie_hellman_operations
        ):
            raise DoSProtectionException(
                "Handling this message would require "
                f"{kdf_derivations_requested} KDF derivations and {diffie_hellman_operations} Diffie-Hellman"
                f" operations, exceeding the per-message work budget of {self.__message_work_budget}."
            )

        # All checks passed; perform the accounted work and apply the state changes.

        # Perform a ratchet step if the ratchet public keys differ
        if performs_ratchet_step:
            # If there is a receiving chain, calculate the bounded number of skipped message keys before
            # replacing the chain
            if self.__symmetric_key_ratchet.receiving_chain_length is not None:
                previous_ratchet_pub = self.__other_ratchet_pub
                old_receiving_chain_length = self.__symmetric_key_ratchet.receiving_chain_length
                assert old_receiving_chain_length is not None  # sanity check
                for _ in range(old_chain_skipped_keys_performed):
                    skipped_message_keys[(previous_ratchet_pub, old_receiving_chain_length)] = \
                        await self.__symmetric_key_ratchet.next_decryption_key()
                    old_receiving_chain_length += 1

            # Perform one full ratchet step, by replacing both the receiving and the sending chains
            self.__other_ratchet_pub = header.ratchet_pub
            await self.__replace_chain(Chain.RECEIVING)
            self.__own_ratchet_priv = self._generate_priv()
            await self.__replace_chain(Chain.SENDING)

        # Once the chains are prepared, forward the receiving chain to the required key. Re-read the actual
        # length: after a ratchet step the freshly installed chain starts at length 0, otherwise this is the
        # same existing chain whose length was used as the baseline above.
        receiving_chain_length = self.__symmetric_key_ratchet.receiving_chain_length
        assert receiving_chain_length is not None  # sanity check

        # Calculate the skipped message keys and keep the receiving chain length updated
        for _ in range(new_chain_skipped_keys):
            skipped_message_keys[(self.__other_ratchet_pub, receiving_chain_length)] = \
                await self.__symmetric_key_ratchet.next_decryption_key()
            receiving_chain_length += 1

        # Finally, derive the requested message key and return it with the skipped message keys
        next_decryption_key = await self.__symmetric_key_ratchet.next_decryption_key()

        return next_decryption_key, skipped_message_keys
