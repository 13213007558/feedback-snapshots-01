from __future__ import annotations

import gzip
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO

import pytest

from dissect.regf import ExpansionContext, RegistryHive, regf
from dissect.regf.c_regf import REG_EXPAND_SZ, REG_SZ
from dissect.regf.expand import CYCLE, LIMIT, MERGED, RESOLVED, UNRESOLVED


@pytest.fixture
def machine_context() -> ExpansionContext:
    with gzip.GzipFile(Path(__file__).parent / "_data/SYSTEM.gz", "rb") as fh:
        yield ExpansionContext.from_hives(system_hive=RegistryHive(fh))


def test_machine_context_from_system_hive(machine_context: ExpansionContext) -> None:
    snapshot = machine_context.snapshot()

    # Select\Current == 1 in this hive, so ControlSet001 must have been used.
    assert any("ControlSet001\\Control\\Session Manager\\Environment" in s for s in machine_context.sources)

    windir = snapshot["WINDIR"]
    assert windir.name == "windir"  # original casing kept
    assert windir.value == "%SystemRoot%"
    assert windir.source == "machine"
    assert windir.expandable is True  # REG_EXPAND_SZ in the hive

    driverdata = snapshot["DRIVERDATA"]
    assert driverdata.value == "C:\\Windows\\System32\\Drivers\\DriverData"
    assert driverdata.expandable is False  # REG_SZ in the hive: literal


def test_expand_real_reg_expand_sz_value(machine_context: ExpansionContext) -> None:
    machine_context.add_machine({"SystemRoot": "C:\\Windows"}, origin="caller-provided captured values")

    with gzip.GzipFile(Path(__file__).parent / "_data/SYSTEM.gz", "rb") as fh:
        hive = RegistryHive(fh)
        comspec = hive.open("ControlSet001\\Control\\Session Manager\\Environment").value("ComSpec")
        assert comspec.type == REG_EXPAND_SZ

        report = comspec.expand(machine_context)

        assert report.raw == "%SystemRoot%\\system32\\cmd.exe"
        assert report.value == "C:\\Windows\\system32\\cmd.exe"
        assert report.complete is True
        assert [s.status for s in report.steps] == [RESOLVED]
        assert report.steps[0].variable == "SystemRoot"
        assert report.steps[0].source == "machine"

        # The raw registry data is never modified and stays retrievable.
        assert comspec.value == "%SystemRoot%\\system32\\cmd.exe"
        assert comspec.data


def test_two_users_same_raw_value_different_results() -> None:
    raw = "%USERPROFILE%\\AppData\\Local\\Temp\\capture.tmp"

    def user_context(userprofile: str) -> ExpansionContext:
        with gzip.GzipFile(Path(__file__).parent / "_data/SYSTEM.gz", "rb") as fh:
            context = ExpansionContext.from_hives(system_hive=RegistryHive(fh))
        context.add_user({"USERPROFILE": userprofile})
        return context

    report_alice = user_context("C:\\Users\\alice").expand(raw)
    report_bob = user_context("C:\\Users\\bob").expand(raw)

    assert report_alice.value == "C:\\Users\\alice\\AppData\\Local\\Temp\\capture.tmp"
    assert report_bob.value == "C:\\Users\\bob\\AppData\\Local\\Temp\\capture.tmp"
    assert report_alice.complete and report_bob.complete

    # Both reports carry step-by-step provenance back to their own source.
    assert report_alice.steps[0].source == "user"
    assert "caller-provided captured values" in report_alice.steps[0].origin
    assert "C:\\Users\\alice" in report_alice.explain()
    assert "C:\\Users\\bob" in report_bob.explain()
    assert report_alice.explain() != report_bob.explain()


def test_user_overrides_machine_and_path_is_merged(machine_context: ExpansionContext) -> None:
    machine_context.add_user(
        {"TEMP": "C:\\Users\\alice\\Temp", "Path": "C:\\Users\\alice\\bin"},
        origin="user hive: Environment",
    )

    temp = machine_context.snapshot()["TEMP"]
    assert temp.value == "C:\\Users\\alice\\Temp"
    assert temp.source == "user"  # user value wins over machine %SystemRoot%\TEMP

    path = machine_context.snapshot()["PATH"]
    assert path.source == MERGED
    machine_path, user_path = path.merged_from
    assert path.value == f"{machine_path.value};{user_path.value}"
    assert path.value.endswith(";C:\\Users\\alice\\bin")

    report = machine_context.expand("%TEMP%\\work")
    assert report.value == "C:\\Users\\alice\\Temp\\work"
    assert report.steps[0].source == "user"


def test_variable_names_are_case_insensitive(machine_context: ExpansionContext) -> None:
    machine_context.add_machine({"SystemRoot": "C:\\Windows"})

    for text in ("%windir%", "%WINDIR%", "%WinDir%"):
        report = machine_context.expand(text)
        assert report.value == "C:\\Windows"
        assert report.complete is True

    # The step records the variable as written in the text.
    assert machine_context.expand("%WINDIR%").steps[0].variable == "WINDIR"


def test_missing_variable_stays_unresolved_no_fake_path() -> None:
    context = ExpansionContext.from_values(machine={"SystemRoot": "C:\\Windows"})

    report = context.expand("%SystemRoot%\\system32;%MissingDir%\\bin")

    assert report.value == "C:\\Windows\\system32;%MissingDir%\\bin"
    assert report.complete is False
    assert report.unresolved == ["MissingDir"]
    assert report.steps[-1].status == UNRESOLVED
    assert "%MissingDir%" in report.value  # never a clean-looking fake path

    explanation = report.explain()
    assert "unresolved: MissingDir" in explanation
    assert "complete: False" in explanation


def test_host_environment_is_never_used() -> None:
    context = ExpansionContext()

    # PATH and HOME exist in the host environment of the analysis machine,
    # but an empty offline context must not fall back to them.
    report = context.expand("%PATH%;%HOME%")

    assert report.value == "%PATH%;%HOME%"
    assert report.complete is False
    assert sorted(report.unresolved) == ["HOME", "PATH"]


def test_circular_references_are_bounded() -> None:
    context = ExpansionContext.from_values(
        machine={"A": "%B%\\x", "B": "%A%\\y", "C": "%C%\\z"},
    )

    report = context.expand("%A%")
    assert report.complete is False
    assert report.cycles == ["A"]
    assert "%A%" in report.value  # the circular reference is left verbatim
    assert any(step.status == CYCLE for step in report.steps)

    report = context.expand("%C%")
    assert report.complete is False
    assert report.cycles == ["C"]
    assert report.value == "%C%\\z"


def test_recursion_depth_is_bounded() -> None:
    values = {f"V{i}": f"%V{i + 1}%" for i in range(64)}
    values["V64"] = "end"
    context = ExpansionContext.from_values(machine=values, max_depth=8)

    report = context.expand("%V0%")

    assert report.complete is False
    assert any(step.status == LIMIT for step in report.steps)
    assert "%" in report.value  # partial result, not a fake complete value


def test_reg_sz_is_never_expanded(machine_context: ExpansionContext) -> None:
    machine_context.add_machine({"SystemRoot": "C:\\Windows"})

    # Top level: the same text as REG_SZ is returned verbatim.
    report = machine_context.expand("%SystemRoot%\\system32", value_type=REG_SZ)
    assert report.expanded is False
    assert report.value == "%SystemRoot%\\system32"
    assert report.steps == []

    # Via a registry value of type REG_SZ.
    sz_value = SimpleNamespace(type=REG_SZ, value="%SystemRoot%\\system32", name="Stub")
    report = machine_context.expand_value(sz_value)
    assert report.expanded is False
    assert report.value == "%SystemRoot%\\system32"

    # Nested: a literal (REG_SZ-like) machine value is substituted as-is,
    # its %NAME% text is not re-expanded.
    context = ExpansionContext()
    context.add_machine({"LITERAL": "%SystemRoot%\\literal"}, expandable=False)
    report = context.expand("%LITERAL%")
    assert report.value == "%SystemRoot%\\literal"
    assert report.complete is True


def test_non_string_value_rejected(machine_context: ExpansionContext) -> None:
    dword_value = SimpleNamespace(type=4, value=1, name="Dword")
    with pytest.raises(regf.Error):
        machine_context.expand_value(dword_value)


def test_report_explain_shows_step_by_step_provenance(machine_context: ExpansionContext) -> None:
    machine_context.add_machine({"SystemRoot": "C:\\Windows"}, origin="caller-provided captured values")

    report = machine_context.expand("%ComSpec%")
    explanation = report.explain()

    assert "raw:      %ComSpec%" in explanation
    assert "value:    C:\\Windows\\system32\\cmd.exe" in explanation
    # Step 1 resolves ComSpec from the SYSTEM hive, step 2 resolves the
    # nested SystemRoot from the caller-provided captured values.
    assert "%ComSpec% <- '%SystemRoot%\\\\system32\\\\cmd.exe' [machine: SYSTEM hive" in explanation
    assert "%SystemRoot% <- 'C:\\\\Windows' [machine: caller-provided captured values]" in explanation
