import base64
import hashlib
import importlib
import sys
import textwrap
from io import BytesIO

import pytest

from installer import install, install_partial
from installer.destinations import WheelDestination
from installer.exceptions import UninstallableDistribution
from installer.records import Hash, RecordEntry, parse_record_file
from installer.sources import WheelSource
from installer.utils import construct_record_file


def _hash_and_size(data):
    digest = hashlib.sha256(data).digest()
    value = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return value, len(data)


class FakeWheelSource(WheelSource):
    def __init__(self, *, distribution, version, regular_files, dist_info_files):
        super().__init__(distribution, version)

        self.dist_info_files = {
            file: textwrap.dedent(content.decode("utf-8"))
            for file, content in dist_info_files.items()
        }
        self.regular_files = {
            file: textwrap.dedent(content.decode("utf-8")).encode("utf-8")
            for file, content in regular_files.items()
        }

        records = [record for record, _, _ in self.get_contents()]
        self.dist_info_files["RECORD"] = "\n".join(
            sorted(
                ",".join([file, "sha256=" + hash_, str(size)])
                for file, hash_, size in records
            )
        )

    @property
    def dist_info_filenames(self):
        return list(self.dist_info_files)

    def read_dist_info(self, filename):
        return self.dist_info_files[filename]

    def validate_record(self):
        return

    def get_contents(self):
        for file, content in sorted(self.regular_files.items()):
            hashed, size = _hash_and_size(content)
            record = (file, f"sha256={hashed}", str(size))
            with BytesIO(content) as stream:
                yield record, stream, False

        for file, text in sorted(self.dist_info_files.items()):
            content = text.encode("utf-8")
            hashed, size = _hash_and_size(content)
            record = (
                self.dist_info_dir + "/" + file,
                f"sha256={hashed}",
                str(size),
            )
            with BytesIO(content) as stream:
                yield record, stream, False


class MemoryDestination(WheelDestination):
    """Keeps every byte written, so tests can read the install back in memory."""

    def __init__(self):
        self.files = {}
        self.records = None
        self.write_file_calls = 0
        self.write_script_calls = 0
        self.finalize_calls = 0

    def write_file(self, scheme, path, stream, is_executable):
        self.write_file_calls += 1
        data = stream.read()
        self.files[(scheme, path)] = data
        hashed, size = _hash_and_size(data)
        return RecordEntry(path, Hash("sha256", hashed), size)

    def write_script(self, name, module, attr, section):
        self.write_script_calls += 1
        from installer.scripts import Script

        script_name, data = Script(name, module, attr, section).generate(
            sys.executable, "posix"
        )
        path = f"bin/{script_name}"
        self.files[("scripts", path)] = data
        hashed, size = _hash_and_size(data)
        return RecordEntry(path, Hash("sha256", hashed), size)

    def finalize_installation(self, scheme, record_file_path, records):
        self.finalize_calls += 1
        self.records = tuple(records)

        def prefix_for(other_scheme):
            if other_scheme == scheme:
                return None
            return other_scheme + "/"

        with construct_record_file(self.records, prefix_for) as stream:
            self.files[(scheme, record_file_path)] = stream.read()

    def read_record(self, scheme, record_file_path):
        rows = self.files[(scheme, record_file_path)].decode("utf-8").splitlines()
        return list(parse_record_file(rows))


@pytest.fixture
def docs_wheel():
    return FakeWheelSource(
        distribution="docdemo",
        version="1.0.0",
        regular_files={
            "docdemo/__init__.py": b"""\
                VALUE = 42

                def main():
                    print("docdemo")
            """,
            "docdemo-1.0.0.data/data/docdemo/notes.txt": b"""\
                optional documentation
            """,
        },
        dist_info_files={
            "top_level.txt": b"""\
                docdemo
            """,
            "WHEEL": b"""\
                Wheel-Version: 1.0
                Generator: magic (1.0.0)
                Root-Is-Purelib: true
                Tag: py3-none-any
            """,
            "METADATA": b"""\
                Metadata-Version: 2.1
                Name: docdemo
                Version: 1.0.0
            """,
        },
    )


@pytest.fixture
def command_wheel():
    return FakeWheelSource(
        distribution="commanddemo",
        version="1.0.0",
        regular_files={
            "commanddemo/__init__.py": b"""\
                def main():
                    print("commanddemo")
            """,
        },
        dist_info_files={
            "top_level.txt": b"""\
                commanddemo
            """,
            "entry_points.txt": b"""\
                [console_scripts]
                commanddemo = commanddemo:main
            """,
            "WHEEL": b"""\
                Wheel-Version: 1.0
                Generator: magic (1.0.0)
                Root-Is-Purelib: true
                Tag: py3-none-any
            """,
            "METADATA": b"""\
                Metadata-Version: 2.1
                Name: commanddemo
                Version: 1.0.0
            """,
        },
    )


def test_optional_documentation_is_omitted_and_reconciled(
    docs_wheel, tmp_path, monkeypatch
):
    destination = MemoryDestination()

    result = install_partial(
        source=docs_wheel,
        destination=destination,
        additional_metadata={},
        approved_schemes=["purelib"],
        optional_schemes=["data"],
    )

    assert result.distribution == "docdemo"
    assert result.approved_schemes == {"purelib"}
    assert len(result.omitted) == 1

    omitted = result.omitted[0]
    assert omitted.scheme == "data"
    assert omitted.path == "docdemo/notes.txt"
    assert (
        omitted.source_path
        == "docdemo-1.0.0.data/data/docdemo/notes.txt"
    )

    record_rows = destination.read_record("purelib", "docdemo-1.0.0.dist-info/RECORD")
    record_paths = [row[0] for row in record_rows]

    assert "docdemo/__init__.py" in record_paths
    assert "docdemo-1.0.0.dist-info/METADATA" in record_paths
    assert not any("notes.txt" in path for path in record_paths)
    assert all((scheme, record.path) in destination.files for scheme, record in result.record_entries)

    # Reconcile omitted members with the RECORD that was actually written.
    omitted_paths = {f"data/{member.path}" for member in result.omitted}
    assert omitted_paths.isdisjoint(record_paths)

    # The approved library is still importable from the in-memory destination.
    for (scheme, path), contents in destination.files.items():
        if scheme != "purelib" or not path.endswith(".py"):
            continue
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)

    monkeypatch.syspath_prepend(str(tmp_path))
    document_module = importlib.import_module("docdemo")
    try:
        assert document_module.VALUE == 42
        assert callable(document_module.main)
    finally:
        monkeypatch.delitem(sys.modules, "docdemo", raising=False)


def test_required_entry_point_fails_before_any_write(command_wheel):
    destination = MemoryDestination()

    # First, a successful partial installation into the very same destination.
    docs_source = FakeWheelSource(
        distribution="tiny",
        version="1.0.0",
        regular_files={"tiny/__init__.py": b"VALUE = 1\n"},
        dist_info_files={
            "WHEEL": b"""\
                Wheel-Version: 1.0
                Root-Is-Purelib: true
                Tag: py3-none-any
            """,
            "METADATA": b"""\
                Metadata-Version: 2.1
                Name: tiny
                Version: 1.0.0
            """,
        },
    )
    first = install_partial(
        source=docs_source,
        destination=destination,
        additional_metadata={},
        approved_schemes=["purelib"],
    )
    assert first.omitted == ()

    before = (
        destination.write_file_calls,
        destination.write_script_calls,
        destination.finalize_calls,
        dict(destination.files),
    )

    with pytest.raises(UninstallableDistribution) as caught:
        install_partial(
            source=command_wheel,
            destination=destination,
            additional_metadata={},
            approved_schemes=["purelib"],
            optional_schemes=["data"],
        )

    after = (
        destination.write_file_calls,
        destination.write_script_calls,
        destination.finalize_calls,
        dict(destination.files),
    )
    assert after == before
    assert destination.records == first.record_entries

    error = caught.value
    assert error.distribution == "commanddemo"
    assert error.version == "1.0.0"
    assert [(item.kind, item.name, item.scheme) for item in error.missing] == [
        ("entry_point", "commanddemo", "scripts"),
    ]
    message = str(error)
    assert "commanddemo" in message
    assert "scripts" in message
    assert "entry point" in message


def test_unapproved_library_is_uninstallable_without_writes(docs_wheel):
    destination = MemoryDestination()

    with pytest.raises(UninstallableDistribution) as caught:
        install_partial(
            source=docs_wheel,
            destination=destination,
            additional_metadata={},
            approved_schemes=["scripts"],
            optional_schemes=["data"],
        )

    assert destination.files == {}
    assert destination.write_file_calls == 0
    assert destination.write_script_calls == 0
    assert destination.finalize_calls == 0

    missing_kinds = {item.kind for item in caught.value.missing}
    assert "library" in missing_kinds
    assert "record" in missing_kinds


def test_missing_completion_record_is_uninstallable(docs_wheel):
    destination = MemoryDestination()

    with pytest.raises(UninstallableDistribution) as caught:
        install_partial(
            source=docs_wheel,
            destination=destination,
            additional_metadata={"INSTALLER": b"partial"},
            approved_schemes=["data"],
            optional_schemes=["data"],
        )

    assert destination.files == {}
    missing = {(item.kind, item.scheme) for item in caught.value.missing}
    assert ("record", "purelib") in missing
    assert ("metadata", "purelib") in missing


def test_explicit_optional_members_can_be_omitted(docs_wheel):
    destination = MemoryDestination()

    result = install_partial(
        source=docs_wheel,
        destination=destination,
        additional_metadata={},
        approved_schemes=["purelib"],
        optional_members=["docdemo-1.0.0.data/data/docdemo/notes.txt"],
    )

    assert len(result.omitted) == 1
    assert result.omitted[0].source_path.endswith("notes.txt")
    assert not any("notes.txt" in path for _, path in destination.files)


def test_partial_install_through_install_entry_point(docs_wheel):
    destination = MemoryDestination()

    result = install(
        source=docs_wheel,
        destination=destination,
        additional_metadata={},
        approved_schemes=["purelib"],
        optional_schemes=["data"],
    )

    assert result is not None
    assert result.omitted[0].scheme == "data"


def test_full_install_without_approval_still_returns_none(docs_wheel):
    destination = MemoryDestination()

    assert (
        install(
            source=docs_wheel,
            destination=destination,
            additional_metadata={},
        )
        is None
    )
    assert ("data", "docdemo/notes.txt") in destination.files
