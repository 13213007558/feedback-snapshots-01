"""Strict, allowlist-based loading of persisted artifacts.

Production environments that must only deserialize pre-approved artifacts can
build an :class:`ApprovedArtifacts` manifest mapping absolute file paths to
cryptographic digests. The manifest is then used to open an artifact through a
file descriptor whose content is verified *before* any deserialization starts.

Keeping the verified file descriptor open (and reusing it for memory mapping)
binds the bytes that were checked to the bytes that are actually consumed,
which closes the time-of-check / time-of-use (TOCTOU) window in which a file
could be swapped after a path-based check.
"""

import contextlib
import hashlib
import hmac
import io
import json
import os

# Size of the chunks streamed through the hasher when verifying an artifact.
_HASH_CHUNK_SIZE = 1024**2


class StrictLoadError(Exception):
    """Base class for failures raised while loading an approved artifact."""


class UnapprovedArtifactError(StrictLoadError):
    """Raised when a requested path is missing from the approved manifest."""


class ArtifactIntegrityError(StrictLoadError):
    """Raised when an artifact's digest does not match its approved digest."""


def _normalize_path(path):
    """Return an absolute, ``str`` path used as a manifest key."""
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    return os.path.abspath(path)


def compute_file_digest(path, hash_name="sha256", chunk_size=_HASH_CHUNK_SIZE):
    """Stream a file from disk and return its hexadecimal digest."""
    hasher = hashlib.new(hash_name, usedforsecurity=False)
    with open(_normalize_path(path), "rb") as fobj:
        for chunk in iter(lambda: fobj.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verified_fd_path(fd):
    """Return the ``/dev/fd`` path reopening a descriptor, or ``None``.

    Memory mapping re-opens a file by name. Referencing the already verified,
    open descriptor through ``/dev/fd`` ensures the mapping points at the exact
    inode that was checked instead of looking the path up again. Windows has no
    equivalent mechanism, in which case ``None`` is returned.
    """
    if os.name == "nt":
        return None
    return f"/dev/fd/{fd}"


class VerifiedArtifact(
    tuple
):
    """Identity of an artifact bound to a verified, open file descriptor."""

    __slots__ = ()

    def __new__(cls, path, fd, device, inode, digest):
        return tuple.__new__(cls, (path, fd, device, inode, digest))

    @property
    def path(self):
        return self[0]

    @property
    def fd(self):
        return self[1]

    @property
    def device(self):
        return self[2]

    @property
    def inode(self):
        return self[3]

    @property
    def digest(self):
        return self[4]

    @property
    def fd_path(self):
        """Path usable to memory-map the verified descriptor."""
        return verified_fd_path(self.fd)


class ApprovedArtifacts:
    """An allowlist of artifacts that may be loaded under strict mode.

    Each entry pairs an absolute path with the expected hexadecimal digest of
    the file's content. Artifacts are verified through a held-open file
    descriptor so the checked bytes cannot be swapped before consumption.

    Parameters
    ----------
    entries: iterable of dict, optional
        Records of the form ``{"path": <str>, "digest": <str>}``. ``(path,
        digest)`` pairs are accepted as well.
    hash_name: str, optional, default='sha256'
        Name of the hashing algorithm used for digests added without an
        explicit digest and for manifest metadata.

    Examples
    --------
    >>> approved = ApprovedArtifacts.from_paths(["model.joblib"])
    >>> obj = strict_load("model.joblib", approved)  # doctest: +SKIP
    """

    def __init__(self, entries=None, hash_name="sha256"):
        # Validate the algorithm name early instead of failing on first use.
        hashlib.new(hash_name, usedforsecurity=False)
        self.hash_name = hash_name
        self._digests = {}
        for record in entries or []:
            self._add_record(record)

    def _add_record(self, record):
        if isinstance(record, dict):
            path = record["path"]
            digest = record["digest"]
        else:
            path, digest = record
        self._digests[_normalize_path(path)] = digest.lower()

    @classmethod
    def from_manifest(cls, manifest):
        """Build an allowlist from a manifest file or an in-memory mapping.

        Parameters
        ----------
        manifest: str, os.PathLike, dict or list
            Either the path of a JSON manifest file, a mapping with an
            ``"artifacts"`` key (and an optional ``"hash_name"`` key), or a
            plain list of records.
        """
        if isinstance(manifest, (str, os.PathLike)):
            with open(manifest, "r", encoding="utf-8") as fobj:
                manifest = json.load(fobj)

        if isinstance(manifest, dict):
            hash_name = manifest.get("hash_name", "sha256")
            records = manifest.get("artifacts", [])
        else:
            hash_name = "sha256"
            records = manifest

        return cls(entries=records, hash_name=hash_name)

    @classmethod
    def from_paths(cls, paths, hash_name="sha256"):
        """Approve existing files by hashing their current content."""
        approved = cls(hash_name=hash_name)
        for path in paths:
            approved.add(path)
        return approved

    def add(self, path, digest=None):
        """Register an artifact, hashing the file when no digest is given."""
        normalized = _normalize_path(path)
        if digest is None:
            digest = compute_file_digest(normalized, hash_name=self.hash_name)
        self._digests[normalized] = digest.lower()
        return normalized

    def contains(self, path):
        """Return whether the normalized path is part of the allowlist."""
        return _normalize_path(path) in self._digests

    def digest_of(self, path):
        """Return the approved digest for a path, or ``None`` if unknown."""
        return self._digests.get(_normalize_path(path))

    def to_manifest(self):
        """Return a JSON-serializable mapping describing the allowlist."""
        return {
            "hash_name": self.hash_name,
            "artifacts": [
                {"path": path, "digest": digest}
                for path, digest in sorted(self._digests.items())
            ],
        }

    def write_manifest(self, manifest_path):
        """Persist the allowlist as a JSON manifest file."""
        with open(manifest_path, "w", encoding="utf-8") as fobj:
            json.dump(self.to_manifest(), fobj, indent=2)

    @contextlib.contextmanager
    def verified_open(self, path):
        """Open an approved artifact and verify its content before yielding.

        The path must be present in the allowlist and the file's streamed
        digest must match the approved digest. Both checks happen before the
        caller receives the file object, so no deserialization can run on
        unapproved or tampered bytes.

        Yields
        ------
        (file object, VerifiedArtifact)
            A buffered binary file object backed by the verified descriptor
            and the identity binding the checked bytes to the open descriptor.
        """
        normalized = _normalize_path(path)
        approved_digest = self._digests.get(normalized)
        if approved_digest is None:
            raise UnapprovedArtifactError(
                f"Artifact {normalized!r} is not in the approved manifest; "
                "refusing to open it."
            )

        fd = os.open(normalized, os.O_RDONLY)
        descriptor_taken_over = False
        try:
            hasher = hashlib.new(self.hash_name, usedforsecurity=False)
            while True:
                chunk = os.read(fd, _HASH_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
            actual_digest = hasher.hexdigest()

            if not hmac.compare_digest(actual_digest, approved_digest):
                raise ArtifactIntegrityError(
                    f"Digest of {normalized!r} is {actual_digest}, but the "
                    f"approved manifest expects {approved_digest}; the "
                    "artifact may have been swapped or tampered with."
                )

            stat_result = os.fstat(fd)
            identity = VerifiedArtifact(
                path=normalized,
                fd=fd,
                device=stat_result.st_dev,
                inode=stat_result.st_ino,
                digest=actual_digest,
            )

            os.lseek(fd, 0, os.SEEK_SET)
            # FileIO takes ownership of the descriptor and closes it on close.
            raw_file = io.FileIO(fd, mode="rb", closefd=True)
            descriptor_taken_over = True
            with io.BufferedReader(raw_file) as fobj:
                yield fobj, identity
        except BaseException:
            if not descriptor_taken_over:
                os.close(fd)
            raise
