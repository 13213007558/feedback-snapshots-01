import pytest
import fixtures

import dnfile
from dnfile.resource import (
    AssemblyResource,
    FileResource,
    InternalResource,
    ResourceEntryStatus,
    ResourceOrigin,
    ResourceSet,
    ResourceStatus,
)


def test_same_name_internal_and_external_resources_are_distinguished(tmp_path):
    """Embedded and external declarations with one display name stay distinct."""
    path = fixtures.write_manifest_resource_fixture(tmp_path)

    dn = dnfile.dnPE(str(path))
    assert dn.net is not None
    resources = dn.net.resources

    # A display name is not a unique key: all three rows must be retained.
    matching = [rsrc for rsrc in resources if str(rsrc.name) == "sample.resources"]
    assert len(matching) == 3

    by_origin = {rsrc.origin: rsrc for rsrc in matching}
    assert set(by_origin) == {ResourceOrigin.Internal, ResourceOrigin.File, ResourceOrigin.Assembly}

    internal = by_origin[ResourceOrigin.Internal]
    file_rsrc = by_origin[ResourceOrigin.File]
    assembly_rsrc = by_origin[ResourceOrigin.Assembly]

    assert isinstance(internal, InternalResource)
    assert isinstance(file_rsrc, FileResource)
    assert isinstance(assembly_rsrc, AssemblyResource)

    # the embedded bytes are real and readable
    assert internal.status == ResourceStatus.Extracted
    assert internal.extracted is True
    assert isinstance(internal.data, ResourceSet)
    assert internal.data.entries[0].value == 42

    # the external declarations do not borrow the embedded bytes, and no
    # empty placeholder is returned in their place
    for external in (file_rsrc, assembly_rsrc):
        assert external.data is None
        assert external.status == ResourceStatus.ExternalMissing
        assert external.extracted is False
        assert external.complete is False
        assert external.error is not None

    assert file_rsrc.file_name == "sample.resources"
    assert assembly_rsrc.assembly_name == "mscorlib"
    # diagnostics identify the declaring source rather than just the name
    assert "sample.resources" in file_rsrc.error
    assert "mscorlib" in assembly_rsrc.error


def test_external_resource_never_reads_from_sample_path(tmp_path):
    """A declared external file is not opened even when it exists next to the sample."""
    path = fixtures.write_manifest_resource_fixture(tmp_path)

    # a same-named file with plausible content sitting right beside the sample
    (tmp_path / "sample.resources").write_bytes(b"external payload")

    dn = dnfile.dnPE(str(path))
    file_rsrc = next(
        rsrc for rsrc in dn.net.resources if isinstance(rsrc, FileResource)
    )

    assert file_rsrc.data is None
    assert file_rsrc.extracted is False
    assert file_rsrc.status == ResourceStatus.ExternalMissing


def test_external_resource_accepts_explicitly_supplied_content(tmp_path):
    """Content handed in by the caller is attributed as externally supplied."""
    path = fixtures.write_manifest_resource_fixture(tmp_path)

    dn = dnfile.dnPE(str(path))
    file_rsrc = next(
        rsrc for rsrc in dn.net.resources if isinstance(rsrc, FileResource)
    )

    file_rsrc.set_data(b"external payload")
    file_rsrc.parse()

    assert file_rsrc.data == b"external payload"
    assert file_rsrc.status == ResourceStatus.Extracted
    assert file_rsrc.extracted is True
    # the origin is still an external reference
    assert file_rsrc.origin == ResourceOrigin.File


def test_bad_resource_set_entry_does_not_hide_its_source_or_siblings(tmp_path):
    """An undecodable entry fails alone and marks the set as incomplete."""
    path = fixtures.write_bad_entry_resource_fixture(tmp_path)

    dn = dnfile.dnPE(str(path))

    assert any("sample.resources" in warning and "Greeting" in warning
               for warning in dn.get_warnings())

    resource = dn.net.resources[0]
    assert isinstance(resource, InternalResource)
    assert resource.name == "sample.resources"
    assert resource.origin == ResourceOrigin.Internal

    # the readable sibling is still available
    count_entry = resource.data.entries[0]
    assert count_entry.name == "Count"
    assert count_entry.status == ResourceEntryStatus.Decoded
    assert count_entry.value == 42

    bad_entry = resource.data.entries[1]
    assert bad_entry.name == "Greeting"
    assert bad_entry.status == ResourceEntryStatus.Invalid
    assert bad_entry.data is None
    assert bad_entry.error is not None
    # the surviving diagnostic names the declaring resource and entry offsets
    assert bad_entry.source == "InternalResource 'sample.resources' (origin: internal)"
    assert bad_entry.type_code == 0x7F
    assert bad_entry.offset is not None
    assert bad_entry.data_offset is not None

    # a partly decoded set must not look like a complete extraction
    assert resource.data.complete is False
    assert resource.complete is False
    assert resource.status == ResourceStatus.Partial
    assert any("invalid resource type" in p for p in resource.data.problems)


def test_resource_entries_retain_type_and_offsets():
    """Entries expose the decoded type, raw type code, and their offsets."""
    path = fixtures.get_data_path_by_name("minimal-res.exe")

    dn = dnfile.dnPE(str(path))
    resource = dn.net.resources[0]
    assert isinstance(resource, InternalResource)
    assert isinstance(resource.data, ResourceSet)

    count_entry, greeting_entry = resource.data.entries

    assert count_entry.status == ResourceEntryStatus.Decoded
    assert count_entry.type_name == "System.Int32"
    assert count_entry.type_code == 8
    assert count_entry.value == 42
    assert count_entry.offset == 0
    assert count_entry.resource is resource

    assert greeting_entry.status == ResourceEntryStatus.Decoded
    assert greeting_entry.type_name == "System.String"
    assert greeting_entry.type_code == 1
    assert greeting_entry.value == "Hello"
    assert greeting_entry.offset is not None
    assert greeting_entry.offset != count_entry.offset

    assert resource.data.complete is True
    assert resource.complete is True
    assert resource.status == ResourceStatus.Extracted


def test_unreadable_internal_resource_stays_listed_without_content(tmp_path):
    """A declared embedded resource stays in the list when its bytes are missing."""
    path = fixtures.copy_fixture_to_tmp(tmp_path, "minimal-res.exe")

    dn = dnfile.dnPE(str(path))
    length_offset = dn.net.resources[0].file_offset - 4
    # claim far more data than the file holds
    fixtures.patch_bytes(path, length_offset, b"\xff\xff\xff\x7f")
    dn.close()

    dn = dnfile.dnPE(str(path))
    resource = dn.net.resources[0]

    assert isinstance(resource, InternalResource)
    assert resource.name == "sample.resources"
    assert resource.origin == ResourceOrigin.Internal
    # the row is not dropped, but no empty bytes are fabricated
    assert resource.data is None
    assert resource.status == ResourceStatus.Unreadable
    assert resource.extracted is False
    assert resource.complete is False
    assert resource.error is not None
    assert any("sample.resources" in warning and "internal" in warning
               for warning in dn.get_warnings())


def _resources_by_name(path):
    # Normalize the resource list into a name-keyed mapping for direct assertions.
    dn = dnfile.dnPE(path)

    assert dn.net is not None
    assert dn.net.resources is not None

    return dn, {str(rsrc.name): rsrc for rsrc in dn.net.resources}


def test_minimal_resource_fixture_parses():
    """Verify the minimal fixture preserves one named resource and its decoded values."""
    path = fixtures.get_data_path_by_name("minimal-res.exe")

    dn, resources = _resources_by_name(path)

    assert len(resources) == 1

    resource = resources["sample.resources"]
    assert isinstance(resource, InternalResource)
    assert str(resource.name) == "sample.resources"
    assert resource.public is True
    assert resource.private is False
    assert isinstance(resource.data, ResourceSet)

    resource_set = resource.data
    assert resource_set.struct is not None
    assert resource_set.struct.Version == 2
    assert resource_set.struct.NumberOfResources == 2
    assert [entry.name for entry in resource_set.entries] == ["Count", "Greeting"]

    count_entry = resource_set.entries[0]
    greeting_entry = resource_set.entries[1]

    assert count_entry.type_name == "System.Int32"
    assert count_entry.value == 42
    assert greeting_entry.type_name == "System.String"
    assert greeting_entry.value == "Hello"


def test_mal_resource_fixture_parses_modulo_resources():
    """Verify the malware fixture exposes the expected resource set contents."""
    path = fixtures.get_data_path_by_name("387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_")
    # Skip the fixture when it is not present locally; this malware sample is optional.
    if not path.exists():
        raise pytest.xfail("test file 38741504... (DANGER: malware) not found in test fixtures")

    dn, resources = _resources_by_name(path)

    # This fixture is intentionally richer and should expose many internal resources.
    assert len(resources) == 13

    # Modulo.g.resources contains both BAML and SVG stream entries.
    resource = resources["Modulo.g.resources"]
    assert isinstance(resource, InternalResource)
    assert isinstance(resource.data, ResourceSet)

    resource_set = resource.data
    assert resource_set.struct is not None
    assert resource_set.struct.Version == 2
    assert resource_set.struct.NumberOfResources == 24
    assert resource_set.entries[0].name == "windowazulso.baml"
    assert resource_set.entries[0].type_name == "System.Stream"
    assert isinstance(resource_set.entries[0].value, bytes)
    assert resource_set.entries[1].name == "resources/logo001.svg"
    assert resource_set.entries[1].type_name == "System.Stream"
    assert resource_set.entries[1].value.startswith(b"<svg")


def test_mal_resource_fixture_parses_costura_resources():
    """Verify the malware fixture preserves empty, bitmap, and metadata resources."""
    path = fixtures.get_data_path_by_name("7f4ba9fc95b30baf8922a6933a4ff1c6a7fef41fae487bb31014c4963357770f.dll_")
    # Skip the fixture when it is not present locally; this malware sample is optional.
    if not path.exists():
        raise pytest.xfail("test file 7f4ba9fc... (DANGER: malware) not found in test fixtures")

    dn, resources = _resources_by_name(path)

    assert len(resources) == 17

    empty_resource = resources["Principal.oAkJwCmMjdhmZUeQqzIqCrdWUotYSIbbSGPVDSnNwYvKrAJsAhUNUtBRnzYyZvOqQ.resources"]
    assert isinstance(empty_resource, InternalResource)
    assert isinstance(empty_resource.data, ResourceSet)
    assert empty_resource.data.struct is not None
    assert empty_resource.data.struct.NumberOfResources == 0
    assert empty_resource.data.entries == []

    # Principal.Resources.resources is the main resource bundle to validate.
    resource = resources["Principal.Resources.resources"]
    assert isinstance(resource, InternalResource)
    assert isinstance(resource.data, ResourceSet)

    resource_set = resource.data
    assert resource_set.struct is not None
    assert resource_set.struct.Version == 2
    assert resource_set.struct.NumberOfResources == 9
    assert [entry.name for entry in resource_set.entries[:3]] == ["logo9991", "logo998", "logo341"]
    assert resource_set.entries[0].type_name == "System.Drawing.Bitmap"
    assert resource_set.entries[0].value is None

    compressed_resource = resources["costura.metadata"]
    assert isinstance(compressed_resource.data, bytes)
    assert len(compressed_resource.data) > 0
