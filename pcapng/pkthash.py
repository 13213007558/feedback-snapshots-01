"""
Packet hash verification and editing contract.

This module implements the contract for the packet hash options of the
packet blocks (``epb_hash`` on :py:class:`~pcapng.blocks.EnhancedPacket`,
``pack_hash`` on the obsolete packet block), covering the whole lifecycle
of a packet: reading, in-place modification and writing back.

The contract, in short:

* Declarations using a supported algorithm (CRC32, MD5, SHA-1) are
  verified against the packet bytes and reported as *match*, *mismatch*
  or *malformed* (the declared digest has the wrong size for the
  algorithm).
* Declarations using any other algorithm -- including the ones known to
  the specification but not computable here (2's complement, XOR) -- are
  preserved as-is and reported as *unverified*.
* Verification results are bound to the packet bytes: once the bytes
  change, previous conclusions become stale and must not be presented as
  verified anymore. :py:class:`PacketHashReport` tracks this.
* New hashes for modified packets are only produced by an explicit
  :py:meth:`PacketHashContractMixin.recompute_hashes` call. Unknown
  algorithms can never be recomputed (no forged results), and derived
  declarations *replace* -- never merge with -- the original
  declarations, which stay available separately as ``original_hashes``.
* Only the packet bytes are covered by the hashes: editing unrelated
  options (eg. the comment) does not invalidate verification results.
* On write, declarations that no longer match the packet bytes are
  reported through the :py:mod:`pcapng.strictness` machinery; in "fix"
  mode the stale declarations are dropped from the written output.
"""

import hashlib
import struct
import zlib
from collections import namedtuple
from enum import Enum

from pcapng import strictness
from pcapng.exceptions import StaleHashError

#: Hash algorithm codes, as assigned to the first byte of the ``epb_hash``
#: option by the pcap-ng specification (section 4.3.1).
HASH_ALGO_2S_COMPLEMENT = 0
HASH_ALGO_XOR = 1
HASH_ALGO_CRC32 = 2
HASH_ALGO_MD5 = 3
HASH_ALGO_SHA1 = 4

#: Names of the algorithm codes known to the specification, including the
#: ones this library cannot compute.
KNOWN_HASH_ALGORITHMS = {
    HASH_ALGO_2S_COMPLEMENT: "2s-complement",
    HASH_ALGO_XOR: "xor",
    HASH_ALGO_CRC32: "crc32",
    HASH_ALGO_MD5: "md5",
    HASH_ALGO_SHA1: "sha1",
}


def _crc32(packet_data):
    return struct.pack(">I", zlib.crc32(packet_data) & 0xFFFFFFFF)


def _md5(packet_data):
    return hashlib.md5(packet_data).digest()


def _sha1(packet_data):
    return hashlib.sha1(packet_data).digest()


#: Description of a hash algorithm: ``code`` is the algorithm byte used in
#: the option, ``name`` a human-readable name, ``digest_size`` the size in
#: bytes of the produced digests and ``function`` the callable computing
#: the digest of a packet.
HashAlgorithm = namedtuple(
    "HashAlgorithm", ("code", "name", "digest_size", "function")
)

#: Algorithms this library can compute. Declarations using any other
#: algorithm are preserved but reported as "unverified", and can never be
#: recomputed.
SUPPORTED_HASH_ALGORITHMS = {
    HASH_ALGO_CRC32: HashAlgorithm(HASH_ALGO_CRC32, "crc32", 4, _crc32),
    HASH_ALGO_MD5: HashAlgorithm(HASH_ALGO_MD5, "md5", 16, _md5),
    HASH_ALGO_SHA1: HashAlgorithm(HASH_ALGO_SHA1, "sha1", 20, _sha1),
}


def hash_algorithm_name(code):
    """Return the name of a hash algorithm code, or None if unknown."""
    return KNOWN_HASH_ALGORITHMS.get(code)


class HashStatus(Enum):
    """Possible outcomes of verifying one hash declaration."""

    #: The declared digest matches the packet bytes.
    MATCH = "match"
    #: The declared digest is well-formed but does not match.
    MISMATCH = "mismatch"
    #: The declared digest has the wrong size for its algorithm.
    MALFORMED = "malformed"
    #: The algorithm is not supported; the declaration was kept as-is.
    UNVERIFIED = "unverified"


class HashOrigin(Enum):
    """Where a hash declaration comes from."""

    #: The declaration was read from the capture file.
    ORIGINAL = "original"
    #: The declaration was (re)computed locally from the packet bytes.
    DERIVED = "derived"


class HashEvidence(object):
    """
    A single hash declaration, as immutable evidence.

    :param algorithm: the algorithm code (first byte of the option value)
    :param digest: the declared digest bytes
    :param origin: a :py:class:`HashOrigin` value
    """

    __slots__ = ["algorithm", "digest", "origin"]

    def __init__(self, algorithm, digest, origin=HashOrigin.ORIGINAL):
        self.algorithm = int(algorithm)
        self.digest = bytes(digest)
        self.origin = origin

    @property
    def algorithm_name(self):
        """Name of the hash algorithm, or None if the code is unknown."""
        return hash_algorithm_name(self.algorithm)

    @property
    def supported(self):
        """Whether this library can compute this algorithm."""
        return self.algorithm in SUPPORTED_HASH_ALGORITHMS

    def verify(self, packet_data):
        """
        Verify this declaration against the given packet bytes.

        :returns: a :py:class:`HashCheck`
        """
        algorithm = SUPPORTED_HASH_ALGORITHMS.get(self.algorithm)
        if algorithm is None:
            return HashCheck(self, None, HashStatus.UNVERIFIED)
        computed = algorithm.function(packet_data)
        if len(self.digest) != algorithm.digest_size:
            return HashCheck(self, computed, HashStatus.MALFORMED)
        status = HashStatus.MATCH if computed == self.digest else HashStatus.MISMATCH
        return HashCheck(self, computed, status)

    def __eq__(self, other):
        if not isinstance(other, HashEvidence):
            return NotImplemented
        return (
            self.algorithm == other.algorithm
            and self.digest == other.digest
            and self.origin == other.origin
        )

    def __repr__(self):
        return "{0}(algorithm={1!r}, digest={2!r}, origin={3})".format(
            self.__class__.__name__, self.algorithm, self.digest, self.origin.value
        )


class HashCheck(object):
    """
    The result of verifying one hash declaration against some packet bytes.
    """

    __slots__ = ["evidence", "computed", "status"]

    def __init__(self, evidence, computed, status):
        self.evidence = evidence
        #: The digest computed from the packet bytes, or None when the
        #: algorithm is not supported.
        self.computed = computed
        #: A :py:class:`HashStatus` value.
        self.status = status

    @property
    def algorithm(self):
        return self.evidence.algorithm

    @property
    def algorithm_name(self):
        return self.evidence.algorithm_name

    @property
    def declared(self):
        """The digest as declared (possibly malformed)."""
        return self.evidence.digest

    @property
    def origin(self):
        return self.evidence.origin

    def __repr__(self):
        return "{0}(algorithm={1!r}, status={2})".format(
            self.__class__.__name__, self.algorithm, self.status.value
        )


class PacketHashReport(object):
    """
    The outcome of verifying all hash declarations of a packet.

    A report is bound to the packet bytes at verification time: if the
    bytes change afterwards, the report becomes *stale* and its
    conclusions must no longer be presented as verified.
    """

    __slots__ = ["_packet", "checks", "_fingerprint"]

    def __init__(self, packet, checks):
        self._packet = packet
        #: Tuple of :py:class:`HashCheck` results, one per declaration.
        self.checks = tuple(checks)
        self._fingerprint = packet._hash_fingerprint()

    @property
    def packet(self):
        """The packet this report was computed from."""
        return self._packet

    @property
    def stale(self):
        """Whether the packet bytes changed since verification."""
        return self._fingerprint != self._packet._hash_fingerprint()

    @property
    def valid(self):
        """Whether the report still describes the current packet bytes."""
        return not self.stale

    def assert_fresh(self):
        """Raise :py:exc:`~pcapng.exceptions.StaleHashError` if stale."""
        if self.stale:
            raise StaleHashError(
                "packet bytes changed since these hashes were verified; "
                "verify again or call recompute_hashes()"
            )

    def select(self, status):
        """Return the checks with the given :py:class:`HashStatus`."""
        return tuple(check for check in self.checks if check.status is status)

    @property
    def matched(self):
        return self.select(HashStatus.MATCH)

    @property
    def mismatched(self):
        return self.select(HashStatus.MISMATCH)

    @property
    def malformed(self):
        return self.select(HashStatus.MALFORMED)

    @property
    def unverified(self):
        return self.select(HashStatus.UNVERIFIED)

    @property
    def all_matched(self):
        """Whether the report is fresh and every declaration matched."""
        return not self.stale and all(
            check.status is HashStatus.MATCH for check in self.checks
        )

    def __iter__(self):
        return iter(self.checks)

    def __len__(self):
        return len(self.checks)

    def __repr__(self):
        return "{0}(checks={1!r}, stale={2!r})".format(
            self.__class__.__name__, list(self.checks), self.stale
        )


class PacketHashContractMixin(object):
    """
    Mixin for packet blocks carrying hash declarations (``epb_hash`` /
    ``pack_hash`` options), implementing the verification and editing
    contract described in the :py:mod:`pcapng.pkthash` documentation.

    The hash declarations found when the block is created (usually: read
    from a file) are snapshotted as the *original* evidence and never
    modified afterwards; the live options may later be replaced by
    *derived* declarations through an explicit
    :py:meth:`recompute_hashes` call. The two sets are never mixed.
    """

    __slots__ = []

    #: Name of the option carrying the hash declarations.
    _hash_option_name = None

    def __init__(self, **kwargs):
        super(PacketHashContractMixin, self).__init__(**kwargs)
        self._establish_hash_evidence()

    # -------------------- contract state --------------------

    def _establish_hash_evidence(self):
        """Snapshot the current declarations as the original evidence."""
        self._original_hashes = tuple(
            HashEvidence(algorithm, digest, HashOrigin.ORIGINAL)
            for algorithm, digest in self._iter_hash_declarations()
        )
        self._hash_decl_fingerprint = self._hash_fingerprint()
        self._hashes_derived = False

    def _packet_bytes(self):
        data = self.packet_data
        return bytes(data) if data else b""

    def _hash_fingerprint(self):
        """
        Fingerprint of the bytes covered by the packet hashes.

        Only the packet data is covered -- editing options (eg. the
        comment) does not change the fingerprint.
        """
        return hashlib.sha1(self._packet_bytes()).digest()

    def _iter_hash_declarations(self):
        """Yield ``(algorithm, digest)`` pairs from the live options."""
        if self._hash_option_name is None:
            return
        options = self.options
        code = options._field_names.get(self._hash_option_name)
        if code is None:
            return
        # Note: access ``data`` directly instead of using get_all() to
        # avoid creating an empty entry in the defaultdict.
        for value in options.data.get(code) or ():
            yield _normalize_declaration(value)

    # -------------------- public API --------------------

    @property
    def original_hashes(self):
        """
        The hash declarations as they were when the block was created
        (usually: read from the capture file), as a tuple of
        :py:class:`HashEvidence`. This original evidence is never
        modified, even when the live declarations are recomputed.
        """
        return self._original_hashes

    @property
    def hash_declarations(self):
        """
        The current live hash declarations -- the ones that would be
        written out -- as a tuple of :py:class:`HashEvidence`.
        """
        origin = HashOrigin.DERIVED if self._hashes_derived else HashOrigin.ORIGINAL
        return tuple(
            HashEvidence(algorithm, digest, origin)
            for algorithm, digest in self._iter_hash_declarations()
        )

    @property
    def hashes_derived(self):
        """Whether the live declarations were recomputed locally."""
        return self._hashes_derived

    def verify_hashes(self):
        """
        Verify the live hash declarations against the current packet
        bytes.

        :returns: a :py:class:`PacketHashReport`
        """
        origin = HashOrigin.DERIVED if self._hashes_derived else HashOrigin.ORIGINAL
        checks = [
            HashEvidence(algorithm, digest, origin).verify(self._packet_bytes())
            for algorithm, digest in self._iter_hash_declarations()
        ]
        return PacketHashReport(self, checks)

    def recompute_hashes(self, algorithms=None):
        """
        Explicitly recompute the packet hashes for the current bytes.

        The live declarations are *replaced* by the newly computed ones
        (derived declarations are never merged with the original ones;
        the original evidence stays available as ``original_hashes``).
        Declarations for algorithms this library cannot compute are not
        carried over: new results can never be forged for them.

        :param algorithms:
            the algorithms to compute, as algorithm codes or names.
            Defaults to the supported algorithms among the current
            declarations -- or to all supported algorithms when no
            supported algorithm is currently declared.
        :returns: a :py:class:`PacketHashReport` for the new declarations
        :raises ValueError: if an unsupported algorithm is requested
        """
        if algorithms is None:
            declared = {algorithm for algorithm, _ in self._iter_hash_declarations()}
            algorithms = [
                code for code in SUPPORTED_HASH_ALGORITHMS if code in declared
            ] or list(SUPPORTED_HASH_ALGORITHMS)
        else:
            algorithms = [self._resolve_algorithm(item) for item in algorithms]

        packet_data = self._packet_bytes()
        derived = [
            (code, SUPPORTED_HASH_ALGORITHMS[code].function(packet_data))
            for code in algorithms
        ]
        self.options[self._hash_option_name] = derived
        self._hashes_derived = True
        self._hash_decl_fingerprint = self._hash_fingerprint()
        return self.verify_hashes()

    @staticmethod
    def _resolve_algorithm(item):
        if isinstance(item, str):
            for code, algorithm in SUPPORTED_HASH_ALGORITHMS.items():
                if algorithm.name == item:
                    return code
            raise ValueError(
                "cannot compute hash for unsupported algorithm: {0!r}".format(item)
            )
        code = int(item)
        if code not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                "cannot compute hash for unsupported algorithm code: "
                "{0!r}".format(item)
            )
        return code

    # -------------------- write-out enforcement --------------------

    def _stale_hash_declarations(self):
        """
        Return :py:class:`HashCheck` results for the live declarations
        that no longer match the current packet bytes. Empty when the
        packet bytes did not change since the declarations were
        established.
        """
        declarations = list(self._iter_hash_declarations())
        if not declarations:
            return []
        if self._hash_decl_fingerprint == self._hash_fingerprint():
            # Bytes unchanged since the declarations were established:
            # they still belong to these bytes, keep them as-is.
            return []
        packet_data = self._packet_bytes()
        stale = []
        for algorithm, digest in declarations:
            check = HashEvidence(algorithm, digest).verify(packet_data)
            if check.status is not HashStatus.MATCH:
                stale.append(check)
        if not stale:
            # The declarations were refreshed to match the new bytes.
            self._hash_decl_fingerprint = self._hash_fingerprint()
        return stale

    def _drop_stale_hash_declarations(self, stale):
        doomed = set(
            (check.evidence.algorithm, check.evidence.digest) for check in stale
        )
        kept = [
            (algorithm, digest)
            for algorithm, digest in self._iter_hash_declarations()
            if (algorithm, digest) not in doomed
        ]
        if kept:
            self.options[self._hash_option_name] = kept
        else:
            try:
                del self.options[self._hash_option_name]
            except KeyError:
                pass
        self._hash_decl_fingerprint = self._hash_fingerprint()

    def _encode(self, outstream):
        stale = self._stale_hash_declarations()
        if stale:
            strictness.problem(
                "writing {cls} with {count} stale '{option}' declaration(s): "
                "the packet bytes changed after the hashes were established; "
                "call recompute_hashes() to derive new hashes".format(
                    cls=self.__class__.__name__,
                    count=len(stale),
                    option=self._hash_option_name,
                )
            )
            if strictness.should_fix():
                self._drop_stale_hash_declarations(stale)
        super(PacketHashContractMixin, self)._encode(outstream)


def _normalize_declaration(value):
    """Normalize an option value to an ``(algorithm, digest)`` pair."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        if len(value) < 1:
            raise ValueError("hash declaration is empty")
        return value[0], value[1:]
    algorithm, digest = value[0], value[1]
    return int(algorithm), bytes(digest)
