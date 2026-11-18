# -----------------------------------------------------------------------------
# Copyright (C) 2023-2023 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import dataclasses as dc
import enum
import typing
from ... import encoding as enc


__all__ = ['RejectReason', 'RejectedEntry', 'SourceVerifier', 'AllowlistSourceVerifier',
           'BoundedUpdatePolicy', 'EntryInspection']


class RejectReason(enum.Enum):
    """Why a state-vector entry was refused admission into the formal state."""
    UNVERIFIED_SOURCE = 'unverified-source'
    INVALID_SEQ = 'invalid-seq'
    STALE_SEQ = 'stale-seq'
    DUPLICATE_SEQ = 'duplicate-seq'
    JUMP_TOO_LARGE = 'jump-too-large'
    SELF_CONFLICT = 'self-conflict'


@dc.dataclass(frozen=True)
class RejectedEntry:
    """A state-vector entry that was refused, together with the reason."""
    node_id: bytes
    seq_no: int
    reason: RejectReason
    known_seq: int


@dc.dataclass(frozen=True)
class EntryInspection:
    """
    Result of the per-entry admission checks.

    ``accepted`` entries are the only ones allowed to enter the formal state
    (``local_sv``). A rejected entry never updates the state and never triggers
    data fetching, while other entries of the same packet are still processed
    independently.
    """
    accepted: bool
    reason: RejectReason | None = None


# A source verifier answers one question: is this node identity allowed to
# publish into this sync group? It is intentionally synchronous so that the
# sync Interest handler stays non-blocking.
SourceVerifier = typing.Callable[[bytes], bool]
r"""
Pluggable source verification hook.

..  function:: (node_id: bytes) -> bool

    :param node_id: the TLV-encoded node name claimed by a remote entry.
    :return: ``True`` if the identity is allowed to publish into the sync group,
             ``False`` otherwise. Entries for which this returns ``False`` are
             refused with :class:`RejectReason.UNVERIFIED_SOURCE` and never
             enter the formal state.
"""


class AllowlistSourceVerifier:
    """
    Verifier that accepts a fixed, explicitly configured set of node identities.

    Unknown (forged) node identities are rejected. The allowlist contains
    TLV-encoded node names, i.e. the same form used as keys of
    :attr:`SvsInst.local_sv`.
    """

    def __init__(self, allowed_nodes: typing.Iterable[enc.NonStrictName]):
        self._allowed = {enc.Name.to_bytes(node) for node in allowed_nodes}

    def __call__(self, node_id: bytes) -> bool:
        return node_id in self._allowed

    def add(self, node_id: enc.NonStrictName) -> None:
        self._allowed.add(enc.Name.to_bytes(node_id))

    def discard(self, node_id: enc.NonStrictName) -> None:
        self._allowed.discard(enc.Name.to_bytes(node_id))


class BoundedUpdatePolicy:
    """
    Bounded sequence-number update policy.

    Admission of a remote entry requires all of:

    * the sequence number is a non-negative integer;
    * it strictly advances beyond the sequence already confirmed for the node,
      so replayed/duplicate and rolled-back numbers cannot drive fetching;
    * the jump from the confirmed sequence does not exceed ``max_seq_jump``,
      so a single malicious high sequence number cannot trigger an unbounded
      back-fill.

    ``max_seq_jump=None`` disables the jump bound (not recommended).
    """

    def __init__(self, max_seq_jump: int | None = 256):
        if max_seq_jump is not None and max_seq_jump <= 0:
            raise ValueError('max_seq_jump must be a positive integer or None')
        self.max_seq_jump = max_seq_jump

    def inspect(self, node_id: bytes, seq_no: int, known_seq: int) -> EntryInspection:
        if not isinstance(seq_no, int) or isinstance(seq_no, bool) or seq_no < 0:
            return EntryInspection(False, RejectReason.INVALID_SEQ)
        if seq_no == known_seq:
            return EntryInspection(False, RejectReason.DUPLICATE_SEQ)
        if seq_no < known_seq:
            return EntryInspection(False, RejectReason.STALE_SEQ)
        if self.max_seq_jump is not None and seq_no - known_seq > self.max_seq_jump:
            return EntryInspection(False, RejectReason.JUMP_TOO_LARGE)
        return EntryInspection(True)
