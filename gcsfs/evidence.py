"""Pinned, inventory-manifest driven reads for archival evidence packages.

An investigation decides which object versions enter an evidence package from
a storage inventory snapshot taken at approval time. The near-real-time bucket
listing may already expose a newer object under the same name, so reading by
name alone can silently substitute unapproved content.

This module keeps the two concerns separate:

- :class:`EvidenceManifest` parses an approved manifest and remembers, for each
  piece of evidence, the minimum data needed to confirm source and version:
  the bucket, the object name and the generation recorded by the inventory.
- :class:`EvidenceReader` fetches every object at that exact generation via the
  normal GCS read path. Reads never consult the directory listing cache and
  never fall back to the current object, so a same-name object that appears
  later cannot be mixed into the package. When an archived generation can no
  longer be found, the failure is reported back as a gap for the investigation
  side to resolve instead of being silently filled.

The in-use directory cache (``GCSFileSystem.dircache``) is only consulted by
ordinary listing tasks; manifest reads bypass it entirely.
"""

import asyncio
import json

from fsspec.asyn import sync


class EvidenceManifestError(ValueError):
    """Raised when an approved manifest cannot be parsed or validated."""


class EvidenceGenerationMismatchError(Exception):
    """Raised when a read object is not the generation approved by the manifest.

    This protects against a same-name object being silently substituted: the
    media request is already pinned with ``generation=<approved>``, so a match
    failure here means the backend returned metadata for a different version
    than the one the manifest authorized.
    """

    def __init__(self, path, expected_generation, actual_generation):
        super().__init__(
            f"{path}: object generation {actual_generation} does not match "
            f"the manifest-approved generation {expected_generation}"
        )
        self.path = path
        self.expected_generation = expected_generation
        self.actual_generation = actual_generation

    def __reduce__(self):
        return (
            EvidenceGenerationMismatchError,
            (self.path, self.expected_generation, self.actual_generation),
        )


class EvidenceReadError(Exception):
    """Records a piece of evidence that could not be read from the archive.

    The manifest entry is preserved alongside the underlying error so the
    investigation side can reconcile the gap against what was originally read.
    """

    def __init__(self, entry, cause):
        super().__init__(
            f"Evidence {entry.bucket}/{entry.name} at generation "
            f"{entry.generation} could not be read: {cause}"
        )
        self.entry = entry
        self.cause = cause

    def __reduce__(self):
        return EvidenceReadError, (self.entry, self.cause)


class EvidenceEntry:
    """One approved piece of evidence.

    Attributes
    ----------
    bucket: str
        Bucket the object lives in, as recorded by the inventory.
    name: str
        Object name (key) within the bucket.
    generation: str
        Generation approved by the manifest. Stored as a string because GCS
        generations are opaque 64-bit identifiers carried as strings.
    """

    __slots__ = ("bucket", "name", "generation")

    def __init__(self, bucket, name, generation):
        self.bucket = bucket
        self.name = name
        if generation is None or str(generation) == "":
            raise EvidenceManifestError(
                f"Manifest entry for {bucket}/{name} is missing a generation; "
                "an approved generation is required to pin the read."
            )
        self.generation = str(generation)

    @property
    def path(self):
        return f"{self.bucket}/{self.name}"

    def as_dict(self):
        return {"bucket": self.bucket, "name": self.name, "generation": self.generation}

    def __eq__(self, other):
        if not isinstance(other, EvidenceEntry):
            return NotImplemented
        return (
            self.bucket == other.bucket
            and self.name == other.name
            and self.generation == other.generation
        )

    def __repr__(self):
        return (
            f"EvidenceEntry(bucket={self.bucket!r}, name={self.name!r}, "
            f"generation={self.generation!r})"
        )


class EvidenceObject:
    """The bytes of one piece of evidence plus its source/version provenance.

    Only the information needed to confirm which approved version was actually
    read is retained; no full object metadata is carried.
    """

    __slots__ = ("entry", "data")

    def __init__(self, entry, data):
        self.entry = entry
        self.data = data

    @property
    def bucket(self):
        return self.entry.bucket

    @property
    def name(self):
        return self.entry.name

    @property
    def generation(self):
        return self.entry.generation

    @property
    def path(self):
        return self.entry.path

    def __repr__(self):
        return f"EvidenceObject(path={self.path!r}, generation={self.generation!r})"


class EvidenceManifest:
    """A parsed, approved inventory manifest.

    The manifest JSON is intentionally small. Top-level provenance fields
    (``manifest_id``, ``source``) are optional and kept verbatim for auditing;
    the only required content is an ``entries`` list, each entry carrying the
    ``bucket``, ``name`` and ``generation`` of an approved object version::

        {
          "manifest_id": "investigation-2026-11-24",
          "source": "gs://inventory-bucket/reports/report.csv",
          "entries": [
            {"bucket": "evidence-bucket", "name": "case/a.txt", "generation": "131"}
          ]
        }
    """

    def __init__(self, entries, manifest_id=None, source=None, raw=None):
        self.entries = list(entries)
        self.manifest_id = manifest_id
        self.source = source
        self.raw = raw

    @classmethod
    def from_dict(cls, manifest):
        """Build a manifest from an already-decoded JSON dictionary."""
        if not isinstance(manifest, dict):
            raise EvidenceManifestError(
                f"Manifest must be a JSON object, got {type(manifest).__name__}."
            )
        raw_entries = manifest.get("entries")
        if not isinstance(raw_entries, list) or not raw_entries:
            raise EvidenceManifestError(
                "Manifest must contain a non-empty 'entries' list."
            )

        entries = []
        seen = set()
        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                raise EvidenceManifestError(
                    f"Manifest entry at index {index} must be an object."
                )
            bucket = raw_entry.get("bucket")
            name = raw_entry.get("name")
            generation = raw_entry.get("generation")
            if not bucket or not name:
                raise EvidenceManifestError(
                    f"Manifest entry at index {index} must set 'bucket' and 'name'."
                )
            entry = EvidenceEntry(bucket=bucket, name=name, generation=generation)
            identity = (entry.bucket, entry.name, entry.generation)
            if identity in seen:
                raise EvidenceManifestError(
                    f"Duplicate manifest entry for {entry.path} at generation "
                    f"{entry.generation}."
                )
            seen.add(identity)
            entries.append(entry)

        return cls(
            entries=entries,
            manifest_id=manifest.get("manifest_id"),
            source=manifest.get("source"),
            raw=manifest,
        )

    @classmethod
    def from_json(cls, text):
        """Build a manifest from a JSON string or bytes."""
        if isinstance(text, bytes):
            text = text.decode()
        try:
            decoded = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise EvidenceManifestError(f"Manifest is not valid JSON: {error}.")
        return cls.from_dict(decoded)

    @classmethod
    def from_local_file(cls, path):
        """Build a manifest from a local JSON file (a local object stand-in).

        The local file is the investigator's retained copy of the approved
        manifest; reading it does not touch GCS or the directory cache.
        """
        with open(path, "rb") as handle:
            return cls.from_json(handle.read())


class EvidenceReader:
    """Reads evidence objects at the generations pinned by an approved manifest.

    Parameters
    ----------
    gcs_file_system: GCSFileSystem
        Filesystem used for the actual object reads.
    manifest: EvidenceManifest
        The approved manifest describing the allowed versions.
    """

    def __init__(self, gcs_file_system, manifest):
        if not isinstance(manifest, EvidenceManifest):
            raise EvidenceManifestError(
                "EvidenceReader requires an EvidenceManifest instance."
            )
        self.gcs_file_system = gcs_file_system
        self.manifest = manifest

    async def _read_entry(self, entry):
        """Fetch one entry at its pinned generation and verify the version.

        The media request carries the approved generation, and the returned
        metadata is checked against it before the bytes are accepted. Neither
        the directory cache nor an unpinned name-only read is used.
        """
        headers, data = await self.gcs_file_system._call(
            "GET",
            "b/{}/o/{}",
            entry.bucket,
            entry.name,
            alt="media",
            generation=entry.generation,
        )
        actual_generation = self._generation_from_headers(headers)
        if actual_generation is not None and actual_generation != entry.generation:
            raise EvidenceGenerationMismatchError(
                path=entry.path,
                expected_generation=entry.generation,
                actual_generation=actual_generation,
            )
        return EvidenceObject(entry=entry, data=data)

    @staticmethod
    def _generation_from_headers(headers):
        """Extract the object generation from a download response header map."""
        if headers is None:
            return None
        if hasattr(headers, "get"):
            value = headers.get("x-goog-generation")
        else:
            value = None
        if value is None:
            return None
        return str(value)

    async def read_evidence(self):
        """Read every manifest entry, keeping approved reads and missing gaps apart.

        Returns
        -------
        tuple[list[EvidenceObject], list[EvidenceReadError]]
            ``objects`` holds the bytes that matched an approved generation.
            ``gaps`` holds one :class:`EvidenceReadError` per entry whose pinned
            generation could not be read (for example, the archived object was
            deleted). Gaps are returned rather than raised or filled, so the
            investigation side decides how to reconcile them.
        """
        objects = []
        gaps = []
        for entry in self.manifest.entries:
            try:
                objects.append(await self._read_entry(entry))
            except Exception as error:
                gaps.append(EvidenceReadError(entry=entry, cause=error))
        return objects, gaps

    async def read_entry(self, entry):
        """Read a single manifest entry, raising if its generation is unavailable."""
        if not isinstance(entry, EvidenceEntry):
            raise EvidenceManifestError(
                "read_entry expects an EvidenceEntry from the manifest."
            )
        if entry not in self.manifest.entries:
            raise EvidenceManifestError(
                f"Entry {entry.path} at generation {entry.generation} is not "
                "part of the approved manifest."
            )
        return await self._read_entry(entry)

    def read_evidence_sync(self):
        """Synchronous wrapper around :meth:`read_evidence`."""
        return sync(self.gcs_file_system.loop, self.read_evidence)

    def read_entry_sync(self, entry):
        """Synchronous wrapper around :meth:`read_entry`."""
        return sync(self.gcs_file_system.loop, self.read_entry, entry)
