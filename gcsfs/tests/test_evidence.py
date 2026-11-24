import json
import os
from unittest import mock

import pytest

from gcsfs.evidence import (
    EvidenceEntry,
    EvidenceGenerationMismatchError,
    EvidenceManifest,
    EvidenceManifestError,
    EvidenceObject,
    EvidenceReadError,
    EvidenceReader,
)


def make_manifest(entries, **kwargs):
    payload = {
        "manifest_id": "investigation-1",
        "source": "gs://inventory-bucket/reports/2026-11-24.csv",
        "entries": entries,
    }
    payload.update(kwargs)
    return payload


class TestEvidenceManifest:
    def test_from_dict_parses_entries_and_keeps_provenance(self):
        manifest = EvidenceManifest.from_dict(
            make_manifest(
                [
                    {
                        "bucket": "evidence-bucket",
                        "name": "case/a.txt",
                        "generation": "131",
                    }
                ]
            )
        )

        assert manifest.manifest_id == "investigation-1"
        assert manifest.source == "gs://inventory-bucket/reports/2026-11-24.csv"
        assert manifest.entries == [
            EvidenceEntry("evidence-bucket", "case/a.txt", "131")
        ]
        entry = manifest.entries[0]
        assert entry.path == "evidence-bucket/case/a.txt"
        # Generations are opaque identifiers and always retained as strings.
        assert entry.generation == "131"
        assert entry.as_dict() == {
            "bucket": "evidence-bucket",
            "name": "case/a.txt",
            "generation": "131",
        }

    def test_numeric_generation_is_normalized_to_string(self):
        manifest = EvidenceManifest.from_dict(
            make_manifest(
                [{"bucket": "b", "name": "o", "generation": 131}]
            )
        )
        assert manifest.entries[0].generation == "131"

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"entries": []},
            {"entries": "not-a-list"},
            {"entries": [{"bucket": "b", "name": "o"}]},
            {"entries": [{"bucket": "b", "generation": "1"}]},
            {"entries": [{"name": "o", "generation": "1"}]},
        ],
    )
    def test_invalid_manifests_are_rejected(self, payload):
        with pytest.raises(EvidenceManifestError):
            EvidenceManifest.from_dict(payload)

    def test_duplicate_entries_are_rejected(self):
        with pytest.raises(EvidenceManifestError):
            EvidenceManifest.from_dict(
                make_manifest(
                    [
                        {"bucket": "b", "name": "o", "generation": "1"},
                        {"bucket": "b", "name": "o", "generation": "1"},
                    ]
                )
            )

    def test_same_name_different_generations_are_distinct_entries(self):
        manifest = EvidenceManifest.from_dict(
            make_manifest(
                [
                    {"bucket": "b", "name": "o", "generation": "1"},
                    {"bucket": "b", "name": "o", "generation": "2"},
                ]
            )
        )
        assert [entry.generation for entry in manifest.entries] == ["1", "2"]

    def test_from_json_accepts_bytes_and_strings(self):
        payload = make_manifest(
            [{"bucket": "b", "name": "o", "generation": "7"}]
        )
        from_bytes = EvidenceManifest.from_json(json.dumps(payload).encode())
        from_string = EvidenceManifest.from_json(json.dumps(payload))
        assert from_bytes.entries == from_string.entries

    def test_from_json_rejects_garbage(self):
        with pytest.raises(EvidenceManifestError):
            EvidenceManifest.from_json("not json")

    def test_from_local_file_round_trip(self, tmp_path):
        path = os.path.join(tmp_path, "manifest.json")
        with open(path, "w") as handle:
            json.dump(
                make_manifest(
                    [{"bucket": "b", "name": "o", "generation": "9"}]
                ),
                handle,
            )

        manifest = EvidenceManifest.from_local_file(path)
        assert manifest.entries == [EvidenceEntry("b", "o", "9")]
        # The local stand-in retains the full approved document.
        assert manifest.raw["manifest_id"] == "investigation-1"


class TestEvidenceReader:
    @staticmethod
    def make_reader(entries, call_side_effect=None):
        fs = mock.MagicMock()
        fs.dircache = mock.MagicMock()
        fs._call = mock.AsyncMock(side_effect=call_side_effect)
        manifest = EvidenceManifest.from_dict(make_manifest(entries))
        return EvidenceReader(fs, manifest), fs

    @pytest.mark.asyncio
    async def test_read_pins_the_approved_generation_in_the_request(self):
        reader, fs = self.make_reader(
            [{"bucket": "bucket", "name": "case/a.txt", "generation": "131"}],
            call_side_effect=[
                ({"x-goog-generation": "131"}, b"approved bytes")
            ],
        )

        objects, gaps = await reader.read_evidence()

        assert gaps == []
        assert len(objects) == 1
        result = objects[0]
        assert isinstance(result, EvidenceObject)
        assert result.data == b"approved bytes"
        assert result.path == "bucket/case/a.txt"
        assert result.generation == "131"

        fs._call.assert_awaited_once_with(
            "GET",
            "b/{}/o/{}",
            "bucket",
            "case/a.txt",
            alt="media",
            generation="131",
        )
        # The live directory cache is never consulted for manifest reads.
        fs.dircache.__contains__.assert_not_called()
        fs.dircache.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_read_accepts_response_without_generation_header(self):
        # The request itself pins the generation server-side; if the emulator
        # omits the x-goog-generation header the pinned bytes are still trusted.
        reader, fs = self.make_reader(
            [{"bucket": "bucket", "name": "case/a.txt", "generation": "131"}],
            call_side_effect=[({}, b"approved bytes")],
        )

        objects, gaps = await reader.read_evidence()

        assert gaps == []
        assert objects[0].generation == "131"
        assert objects[0].data == b"approved bytes"
        fs._call.assert_awaited_once()
        assert fs._call.await_args.kwargs["generation"] == "131"

    @pytest.mark.asyncio
    async def test_missing_archived_generation_is_reported_as_a_gap(self):
        missing = FileNotFoundError("bucket/case/gone.txt")
        reader, fs = self.make_reader(
            [
                {"bucket": "bucket", "name": "case/kept.txt", "generation": "10"},
                {"bucket": "bucket", "name": "case/gone.txt", "generation": "11"},
            ],
            call_side_effect=[
                ({"x-goog-generation": "10"}, b"kept bytes"),
                missing,
            ],
        )

        objects, gaps = await reader.read_evidence()

        assert [obj.path for obj in objects] == ["bucket/case/kept.txt"]
        assert len(gaps) == 1
        gap = gaps[0]
        assert isinstance(gap, EvidenceReadError)
        assert gap.entry == EvidenceEntry("bucket", "case/gone.txt", "11")
        assert gap.cause is missing
        # The gap is not filled by retrying the name without the generation.
        assert fs._call.await_count == 2
        for call in fs._call.await_args_list:
            assert "generation" in call.kwargs and call.kwargs["generation"]

    @pytest.mark.asyncio
    async def test_generation_mismatch_is_rejected_not_silently_accepted(self):
        # The request asked for generation 131 but metadata reports a newer
        # same-name object (generation 999): the bytes must not enter evidence.
        reader, _fs = self.make_reader(
            [{"bucket": "bucket", "name": "case/a.txt", "generation": "131"}],
            call_side_effect=[
                ({"x-goog-generation": "999"}, b"unapproved new bytes")
            ],
        )

        objects, gaps = await reader.read_evidence()
        assert objects == []
        assert len(gaps) == 1
        assert isinstance(gaps[0].cause, EvidenceGenerationMismatchError)
        mismatch = gaps[0].cause
        assert mismatch.expected_generation == "131"
        assert mismatch.actual_generation == "999"

    @pytest.mark.asyncio
    async def test_read_entry_raises_for_missing_generation(self):
        reader, _fs = self.make_reader(
            [{"bucket": "bucket", "name": "case/gone.txt", "generation": "11"}],
            call_side_effect=[FileNotFoundError("bucket/case/gone.txt")],
        )

        with pytest.raises(FileNotFoundError):
            await reader.read_entry(reader.manifest.entries[0])

    @pytest.mark.asyncio
    async def test_read_entry_rejects_manifest_outsider(self):
        reader, fs = self.make_reader(
            [{"bucket": "bucket", "name": "case/a.txt", "generation": "131"}]
        )
        outsider = EvidenceEntry("bucket", "case/a.txt", "999")

        with pytest.raises(EvidenceManifestError):
            await reader.read_entry(outsider)
        fs._call.assert_not_called()

    def test_reader_requires_a_manifest(self):
        with pytest.raises(EvidenceManifestError):
            EvidenceReader(mock.MagicMock(), {"entries": []})

    def test_sync_wrappers_run_on_the_filesystem_loop(self):
        from fsspec.asyn import get_loop

        fs = mock.MagicMock()
        fs.loop = get_loop()

        async def fake_call(method, path, *args, **kwargs):
            return (
                {"x-goog-generation": kwargs["generation"]},
                b"bytes-" + kwargs["generation"].encode(),
            )

        fs._call = fake_call
        manifest = EvidenceManifest.from_dict(
            make_manifest(
                [
                    {"bucket": "bucket", "name": "a", "generation": "1"},
                    {"bucket": "bucket", "name": "b", "generation": "2"},
                ]
            )
        )
        reader = EvidenceReader(fs, manifest)

        objects, gaps = reader.read_evidence_sync()
        assert gaps == []
        assert [obj.generation for obj in objects] == ["1", "2"]
        assert objects[0].data == b"bytes-1"

        single = reader.read_entry_sync(manifest.entries[1])
        assert single.generation == "2"


class TestManifestRevision:
    """After the inventory manifest is revised, an investigator still holds the
    previously approved local copy. Reads must follow that copy's generations,
    not the new same-name objects in the live directory."""

    @pytest.mark.asyncio
    async def test_old_approved_version_still_readable_while_unapproved_gap_remains(
        self, tmp_path
    ):
        # Revision 1 of the manifest approved gen 131 of a.txt and gen 20 of
        # b.txt. The local stand-in keeps that exact document.
        old_manifest_path = os.path.join(tmp_path, "manifest-v1.json")
        with open(old_manifest_path, "w") as handle:
            json.dump(
                make_manifest(
                    [
                        {"bucket": "bucket", "name": "case/a.txt", "generation": "131"},
                        {"bucket": "bucket", "name": "case/b.txt", "generation": "20"},
                    ],
                    manifest_id="revision-1",
                ),
                handle,
            )

        fs = mock.MagicMock()
        fs.dircache = {}
        # Live directory now advertises newer same-name objects; a naive
        # name-only read would pick these generations instead.
        fs.dircache["bucket/case"] = [
            {
                "name": "bucket/case/a.txt",
                "type": "file",
                "generation": "999",
            },
            {
                "name": "bucket/case/b.txt",
                "type": "file",
                "generation": "888",
            },
        ]
        fs._call = mock.AsyncMock(
            side_effect=[
                # Old approved a.txt generation still retrievable.
                ({"x-goog-generation": "131"}, b"a version one"),
                # The archived b.txt generation was deleted; the newer gen 888
                # must not be used to fill the gap.
                FileNotFoundError("bucket/case/b.txt"),
            ]
        )

        manifest = EvidenceManifest.from_local_file(old_manifest_path)
        reader = EvidenceReader(fs, manifest)
        objects, gaps = await reader.read_evidence()

        assert len(objects) == 1
        assert objects[0].path == "bucket/case/a.txt"
        assert objects[0].generation == "131"
        assert objects[0].data == b"a version one"

        assert len(gaps) == 1
        assert gaps[0].entry == EvidenceEntry("bucket", "case/b.txt", "20")

        # Every read was pinned to the old manifest's generations; the cached
        # listing advertising gens 999/888 never substituted content.
        requested = [call.kwargs["generation"] for call in fs._call.await_args_list]
        assert requested == ["131", "20"]
        assert "999" not in requested and "888" not in requested
