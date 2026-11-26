import io
import zipfile
from pathlib import Path

import pytest
from installer import install
from installer.destinations import (
    ADMITTED,
    BYTECODE_CURRENT,
    BYTECODE_MISSING,
    BYTECODE_STALE,
    INCOMPLETE,
    NOT_INSTALLED,
    SchemeDictionaryDestination,
    WheelDestination,
    inspect_installation,
)
from installer.exceptions import BytecodeCompilationError
from installer.records import RecordEntry
from installer.scripts import Script
from installer.sources import WheelFile
from installer.utils import SCHEME_NAMES


class TestWheelDestination:
    def test_takes_no_arguments(self):
        WheelDestination()

    def test_raises_not_implemented_error(self):
        destination = WheelDestination()

        with pytest.raises(NotImplementedError):
            destination.write_script(name=None, module=None, attr=None, section=None)

        with pytest.raises(NotImplementedError):
            destination.write_file(
                scheme=None, path=None, stream=None, is_executable=False
            )

        with pytest.raises(NotImplementedError):
            destination.finalize_installation(
                scheme=None,
                record_file_path=None,
                records=None,
            )


class TestSchemeDictionaryDestination:
    @pytest.fixture()
    def destination(self, tmp_path):
        scheme_dict = {}
        for scheme in SCHEME_NAMES:
            full_path = tmp_path / scheme
            if not full_path.exists():
                full_path.mkdir()
            scheme_dict[scheme] = str(full_path)
        return SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")

    @pytest.fixture()
    def destination_overwrite_existing(self, tmp_path):
        scheme_dict = {}
        for scheme in SCHEME_NAMES:
            full_path = tmp_path / scheme
            if not full_path.exists():
                full_path.mkdir()
            scheme_dict[scheme] = str(full_path)
        return SchemeDictionaryDestination(
            scheme_dict, "/my/python", "posix", overwrite_existing=True
        )

    @pytest.mark.parametrize(
        ("scheme", "path", "data", "expected"),
        [
            pytest.param(
                "data", "my_data.bin", b"my data", b"my data", id="normal file"
            ),
            pytest.param(
                "data",
                "data_folder/my_data.bin",
                b"my data",
                b"my data",
                id="normal file in subfolder",
            ),
            pytest.param(
                "scripts",
                "my_script.py",
                b"#!python\nmy script",
                b"#!/my/python\nmy script",
                id="script file",
            ),
            pytest.param(
                "scripts",
                "script_folder/my_script.py",
                b"#!python\nmy script",
                b"#!/my/python\nmy script",
                id="script file in subfolder",
            ),
        ],
    )
    def test_write_file(self, destination, scheme, path, data, expected):
        record = destination.write_file(scheme, path, io.BytesIO(data), False)
        file_data = (Path(destination.scheme_dict[scheme]) / path).read_bytes()
        assert file_data == expected
        assert record.path == path

    def test_write_record_duplicate(self, destination):
        destination.write_file("data", "my_data.bin", io.BytesIO(b"my data"), False)
        with pytest.raises(FileExistsError):
            destination.write_file("data", "my_data.bin", io.BytesIO(b"my data"), False)

    def test_write_record_duplicate_with_overwrite_existing(
        self, destination_overwrite_existing
    ):
        destination_overwrite_existing.write_file(
            "data", "my_data.bin", io.BytesIO(b"my data"), False
        )
        destination_overwrite_existing.write_file(
            "data", "my_data.bin", io.BytesIO(b"my data"), False
        )

    def test_write_script(self, destination):
        script_args = ("my_entrypoint", "my_module", "my_function", "console")
        record = destination.write_script(*script_args)
        file_path = Path(destination.scheme_dict["scripts"]) / "my_entrypoint"

        assert file_path.is_file()

        file_data = file_path.read_bytes()
        _, expected_data = Script(*script_args).generate("/my/python", "posix")

        assert file_data == expected_data
        assert record.path == "my_entrypoint"

    def test_finalize_write_record(self, destination):
        records = [
            (
                "data",
                destination.write_file(
                    "data",
                    "my_data1.bin",
                    io.BytesIO(b"my data 1"),
                    is_executable=False,
                ),
            ),
            (
                "data",
                destination.write_file(
                    "data",
                    "my_data2.bin",
                    io.BytesIO(b"my data 2"),
                    is_executable=False,
                ),
            ),
            (
                "data",
                destination.write_file(
                    "data",
                    "my_data3,my_data4.bin",
                    io.BytesIO(b"my data 3"),
                    is_executable=False,
                ),
            ),
            (
                "scripts",
                destination.write_file(
                    "scripts",
                    "my_script",
                    io.BytesIO(b"my script"),
                    is_executable=True,
                ),
            ),
            (
                "scripts",
                destination.write_file(
                    "scripts",
                    "my_script2",
                    io.BytesIO(b"#!python\nmy script"),
                    is_executable=False,
                ),
            ),
            (
                "scripts",
                destination.write_script(
                    "my_entrypoint", "my_module", "my_function", "console"
                ),
            ),
            ("purelib", RecordEntry("RECORD", None, None)),
        ]

        destination.finalize_installation("purelib", "RECORD", records)
        file_path = Path(destination.scheme_dict["purelib"]) / "RECORD"

        data = file_path.read_bytes()
        expected_data = (
            b"RECORD,,\n"
            b"data/my_data1.bin,sha256=NV0A-M4OPuqTsHjeD6Wth_-UqrpAAAdyplcustFZ8s4,9\n"
            b"data/my_data2.bin,sha256=lP7V8oWLqgyXCbdASNiPdsUogzPUZhht_7F8T5bC3eQ,9\n"
            b'data/my_data3,my_data4.bin",sha256=18krruu1gr01x-WM_9ChSASoHv0mfRAV6-B2bd9sxpo,9\n'
            b"scripts/my_entrypoint,sha256=J1B4YfhSpV2wNetnE4L_T_Z3ssyHKC-dZAaZlg_dDsw,164\n"
            b"scripts/my_script,sha256=M60fWvUSMJkPtw2apUvjWWwOcnRPcVy_zO4-4lpH08o,9\n"
            b"scripts/my_script2,sha256=k9_997kTbTYQm7EXFLclVZL1m2N98rU90QX46XeMvjY,22\n"
        )
        assert all(
            real.endswith(expected)
            for real, expected in zip(
                data.split(b"\n"), expected_data.split(b"\n"), strict=True
            )
        )

    def test_blocking_path_traversal(self, destination):
        with pytest.raises(ValueError):
            destination._path_with_destdir("purelib", "subdir/../../outside.txt")


# --------------------------------------------------------------------------------------
# Bytecode admission and artifact inspection
# --------------------------------------------------------------------------------------
def _make_wheel(path, *, version="1.0.0", broken=False):
    dist_info = f"fancy-{version}.dist-info"
    files = {
        "fancy/__init__.py": b"VALUE = 1\n",
        "fancy/mod.py": (b"def broken(:\n" if broken else b"def ok():\n    return 2\n"),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: fancy\nVersion: {version}\n".encode()
        ),
        f"{dist_info}/RECORD": b"",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


class _Layout:
    def __init__(self, root, levels=(0, 1)):
        self.dest = Path(root) / "dest"
        self.levels = list(levels)
        self.schemes = {scheme: str(self.dest / scheme) for scheme in SCHEME_NAMES}

    def install(self, wheel, *, overwrite=False):
        destination = SchemeDictionaryDestination(
            self.schemes,
            "/my/python",
            "posix",
            bytecode_optimization_levels=self.levels,
            destdir=str(self.dest),
            overwrite_existing=overwrite,
        )
        with WheelFile.open(wheel) as source:
            install(source, destination, {})

    def inspect(self, version="1.0.0"):
        return inspect_installation(
            self.schemes,
            f"fancy-{version}.dist-info/RECORD",
            bytecode_optimization_levels=self.levels,
            destdir=str(self.dest),
        )

    def find(self, suffix):
        return next(self.dest.rglob(suffix))


class TestBytecodeAdmission:
    def test_successful_install_is_admitted(self, tmp_path):
        layout = _Layout(tmp_path)
        layout.install(_make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl"))

        report = layout.inspect()
        assert report.status == ADMITTED
        assert report.distribution == "fancy"
        assert report.version == "1.0.0"
        assert report.issues == ()
        assert {b.state for b in report.bytecode} == {BYTECODE_CURRENT}
        assert {b.optimization_level for b in report.bytecode} == {0, 1}
        assert report.unexpected_bytecode == ()

    def test_failed_compile_is_not_admitted(self, tmp_path):
        layout = _Layout(tmp_path)
        wheel = _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl", broken=True)

        with pytest.raises(BytecodeCompilationError):
            layout.install(wheel)

        assert not (layout.dest / "purelib" / "fancy-1.0.0.dist-info").exists()
        assert layout.inspect().status == NOT_INSTALLED
        # Nothing from the failed job survives, including partial bytecode.
        assert not any(p.suffix == ".py" for p in layout.dest.rglob("*") if p.is_file())

    def test_failed_compile_removes_earlier_files_and_bytecode(self, tmp_path):
        layout = _Layout(tmp_path, levels=[0])
        # First source compiles fine, second fails; both must be cleaned up.
        wheel = _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl", broken=True)
        with pytest.raises(BytecodeCompilationError):
            layout.install(wheel)

        remaining = [p for p in layout.dest.rglob("*") if p.is_file()]
        assert remaining == []

    def test_foreign_pyc_in_temp_dir_is_not_trusted(self, tmp_path):
        layout = _Layout(tmp_path)
        decoy_dir = layout.dest / "purelib" / "fancy" / "__pycache__"
        decoy_dir.mkdir(parents=True)
        (decoy_dir / "decoy.cpython-312.pyc").write_bytes(b"old unrelated cache")

        wheel = _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl", broken=True)
        with pytest.raises(BytecodeCompilationError):
            layout.install(wheel)

        # Only the pre-existing unrelated artifact remains; nothing of this job.
        assert [p.name for p in layout.dest.rglob("*.pyc")] == ["decoy.cpython-312.pyc"]

    def test_existing_stale_pyc_is_replaced(self, tmp_path):
        layout = _Layout(tmp_path, levels=[0])
        wheel = _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl")
        layout.install(wheel)

        pyc = layout.find("fancy/__pycache__/mod.cpython-312.pyc")
        pyc.write_bytes(b"stale bytes from a previous install")

        layout.install(wheel, overwrite=True)
        assert layout.inspect().status == ADMITTED

    def test_stale_and_missing_bytecode_are_incomplete(self, tmp_path):
        layout = _Layout(tmp_path)
        layout.install(_make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl"))

        current = layout.find("fancy/__pycache__/mod.cpython-312.pyc")
        data = bytearray(current.read_bytes())
        data[8:16] = b"\xde\xad\xbe\xef" + bytes(data[12:16])
        current.write_bytes(bytes(data))

        report = layout.inspect()
        assert report.status == INCOMPLETE
        states = {(b.source, b.optimization_level): b.state for b in report.bytecode}
        assert states[("fancy/mod.py", 0)] == BYTECODE_STALE
        assert states[("fancy/__init__.py", 0)] == BYTECODE_CURRENT

        layout.find("fancy/__pycache__/mod.cpython-312.opt-1.pyc").unlink()
        report = layout.inspect()
        assert report.status == INCOMPLETE
        states = {(b.source, b.optimization_level): b.state for b in report.bytecode}
        assert states[("fancy/mod.py", 1)] == BYTECODE_MISSING

    def test_unexpected_bytecode_is_reported_separately(self, tmp_path):
        layout = _Layout(tmp_path, levels=[0])
        layout.install(_make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl"))

        extra = layout.find("fancy/__pycache__/mod.cpython-312.pyc").parent
        (extra / "other.cpython-312.pyc").write_bytes(b"unrelated")
        report = layout.inspect()
        assert [p.name for p in report.unexpected_bytecode] == ["other.cpython-312.pyc"]

    def test_failed_upgrade_preserves_previous_admitted_version(self, tmp_path):
        layout = _Layout(tmp_path)
        good = _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl")
        layout.install(good)
        old_pyc = layout.find("fancy/__pycache__/mod.cpython-312.pyc").read_bytes()

        bad = _make_wheel(
            tmp_path / "fancy-2.0.0-py3-none-any.whl", version="2.0.0", broken=True
        )
        with pytest.raises(BytecodeCompilationError):
            layout.install(bad, overwrite=True)

        # The old version is still the only admitted result.
        report = layout.inspect("1.0.0")
        assert report.status == ADMITTED
        assert report.version == "1.0.0"
        assert layout.find("fancy/__pycache__/mod.cpython-312.pyc").read_bytes() == (
            old_pyc
        )
        assert layout.inspect("2.0.0").status == NOT_INSTALLED

    def test_no_bytecode_requested_needs_no_pyc(self, tmp_path):
        layout = _Layout(tmp_path, levels=[])
        layout.install(_make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl"))

        assert not any(layout.dest.rglob("*.pyc"))
        assert layout.inspect().status == ADMITTED

    def test_inspect_without_destdir(self, tmp_path):
        # Without destdir, scheme paths are the real installation roots.
        schemes = {scheme: str(tmp_path / scheme) for scheme in SCHEME_NAMES}
        for directory in schemes.values():
            Path(directory).mkdir(exist_ok=True)

        destination = SchemeDictionaryDestination(
            schemes,
            "/my/python",
            "posix",
            bytecode_optimization_levels=[0],
        )
        with WheelFile.open(
            _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl")
        ) as source:
            install(source, destination, {})

        report = inspect_installation(
            schemes,
            "fancy-1.0.0.dist-info/RECORD",
            bytecode_optimization_levels=[0],
        )
        assert report.status == ADMITTED
        assert report.distribution == "fancy"
        assert report.version == "1.0.0"

    def test_reinstall_reflects_last_successful_write(self, tmp_path):
        layout = _Layout(tmp_path, levels=[0])
        layout.install(_make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl"))

        newer = _make_wheel(tmp_path / "fancy-2.0.0-py3-none-any.whl", version="2.0.0")
        layout.install(newer, overwrite=True)

        # Re-reading sees the newly admitted version.
        report = layout.inspect("2.0.0")
        assert report.status == ADMITTED
        assert report.version == "2.0.0"
        assert {b.state for b in report.bytecode} == {BYTECODE_CURRENT}

    def test_report_is_reproducible_in_a_fresh_process(self, tmp_path):
        import json
        import subprocess
        import sys

        layout = _Layout(tmp_path, levels=[0])
        layout.install(_make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl"))

        source_root = str(Path(__file__).resolve().parents[1] / "src")
        script = (
            "import json, sys\n"
            f"sys.path.insert(0, {source_root!r})\n"
            "from installer.destinations import inspect_installation\n"
            f"r = inspect_installation({layout.schemes!r}, "
            "'fancy-1.0.0.dist-info/RECORD', "
            f"bytecode_optimization_levels=[0], destdir={str(layout.dest)!r})\n"
            "print(json.dumps({'status': r.status, 'version': r.version, "
            "'official': sorted(r.official_files)}))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["status"] == ADMITTED
        assert payload["version"] == "1.0.0"
        assert payload["official"] == sorted(layout.inspect().official_files)

    def test_record_write_failure_rolls_back_committed_bytecode(self, tmp_path):
        layout = _Layout(tmp_path, levels=[0])
        wheel = _make_wheel(tmp_path / "fancy-1.0.0-py3-none-any.whl")
        destination = SchemeDictionaryDestination(
            layout.schemes,
            "/my/python",
            "posix",
            bytecode_optimization_levels=[0],
            destdir=str(layout.dest),
        )

        original = destination.write_to_fs

        def failing(scheme, path, stream, is_executable):
            if path.endswith("RECORD"):
                raise OSError("disk full")
            return original(scheme, path, stream, is_executable)

        destination.write_to_fs = failing  # type: ignore[method-assign]
        with WheelFile.open(wheel) as source, pytest.raises(OSError, match="disk full"):
            install(source, destination, {})

        assert layout.inspect().status == NOT_INSTALLED
        assert [p for p in layout.dest.rglob("*") if p.is_file()] == []
