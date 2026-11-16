from __future__ import annotations

import gzip
from io import BytesIO
from pathlib import Path

import pytest

from dissect.regf import RegistryView
from dissect.regf.exceptions import (
    ControlSetNotFoundError,
    MissingContextError,
    MountNotFoundError,
    RegistryKeyNotFoundError,
    UserContextError,
)
from dissect.regf.regf import RegistryHive

from ._hive import HiveNode, build_hive


def make_system(
    current: int, default: int, last_known_good: int, control_sets: tuple[int, ...] = (1, 2)
) -> RegistryHive:
    root = HiveNode("ROOT", root=True)
    select = root.add("Select")
    select.value("Current", 4, current)
    select.value("Default", 4, default)
    select.value("LastKnownGood", 4, last_known_good)

    for number in control_sets:
        control_set = root.add(f"ControlSet{number:03d}")
        services = control_set.add("Services")
        services.add("shared").value("ImagePath", 1, f"system-{number}")
        control_set.add("Control").add("Lsa").value("Source", 1, f"lsa-{number}")

    root.add("MountedDevices").value("\\DosDevices\\C:", 3, b"system-" + str(current).encode())

    return RegistryHive(BytesIO(build_hive(root, "SYSTEM")))


def make_software(marker: str = "software") -> RegistryHive:
    root = HiveNode("ROOT", root=True)
    root.add("Microsoft").add("Windows").add("CurrentVersion").value("ProductName", 1, marker)
    return RegistryHive(BytesIO(build_hive(root, "SOFTWARE")))


def make_user(sid: str, marker: str) -> RegistryHive:
    root = HiveNode("ROOT", root=True)
    root.add("Software").add("Vendor").value("Owner", 1, marker)
    root.add("Environment").value("USERNAME", 1, marker)
    return RegistryHive(BytesIO(build_hive(root, sid)))


def test_current_control_set_uses_select_evidence_of_each_system_hive() -> None:
    first = RegistryView(system=make_system(current=2, default=1, last_known_good=1))
    second = RegistryView(system=make_system(current=1, default=2, last_known_good=2))

    key_first = first.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
    key_second = second.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")

    assert key_first.physical_path == "ControlSet002\\Control\\Lsa"
    assert key_second.physical_path == "ControlSet001\\Control\\Lsa"
    assert key_first.logical_path == "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"

    evidence_first = key_first.selection
    assert evidence_first is not None
    assert (evidence_first.pointer, evidence_first.value, evidence_first.control_set) == ("Current", 2, "ControlSet002")
    assert key_first.to_dict(include_values=True)["hive"]["filename"] == "SYSTEM"


def test_select_pointers_are_not_substitutes() -> None:
    view = RegistryView(system=make_system(current=2, default=1, last_known_good=1))

    assert view.select_control_set("Current").control_set == "ControlSet002"
    assert view.select_control_set("Default").control_set == "ControlSet001"
    assert view.select_control_set("LastKnownGood").control_set == "ControlSet001"

    explicit = view.open("SYSTEM\\ControlSet001\\Control\\Lsa")
    assert explicit.physical_path == "ControlSet001\\Control\\Lsa"
    assert explicit.selection is not None
    assert explicit.selection.pointer is None
    assert explicit.selection.explicit is True
    assert explicit.value("Source").value == "lsa-1"


def test_missing_select_requires_explicit_context() -> None:
    root = HiveNode("ROOT", root=True)
    root.add("ControlSet001").add("Control").add("Lsa")
    view = RegistryView(system=RegistryHive(BytesIO(build_hive(root, "SYSTEM"))))

    with pytest.raises(MissingContextError):
        view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")

    explicit = view.with_control_set(1).open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
    assert explicit.physical_path == "ControlSet001\\Control\\Lsa"
    assert explicit.selection is not None
    assert explicit.selection.explicit is True

    with pytest.raises(ControlSetNotFoundError):
        view.with_control_set(2).open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")


def test_missing_select_value_is_not_replaced_by_another_pointer() -> None:
    root = HiveNode("ROOT", root=True)
    select = root.add("Select")
    select.value("Default", 4, 1)
    select.value("LastKnownGood", 4, 1)
    root.add("ControlSet001")
    view = RegistryView(system=RegistryHive(BytesIO(build_hive(root, "SYSTEM"))))

    with pytest.raises(MissingContextError):
        view.open("HKLM\\SYSTEM\\CurrentControlSet")


def test_select_pointing_to_absent_control_set_is_an_error() -> None:
    view = RegistryView(system=make_system(current=7, default=1, last_known_good=1))

    with pytest.raises(ControlSetNotFoundError) as excinfo:
        view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
    assert "ControlSet007" in str(excinfo.value)


def test_user_context_switch_does_not_pollute_existing_handles() -> None:
    alice = "S-1-5-21-1"
    bob = "S-1-5-21-2"
    view = RegistryView(
        users={alice: make_user(alice, "alice"), bob: make_user(bob, "bob")},
        user=alice,
    )

    alice_key = view.open("HKEY_CURRENT_USER\\Software\\Vendor")
    assert alice_key.value("Owner").value == "alice"
    assert alice_key.source.identifier == alice

    bob_view = view.with_user(bob)
    bob_key = bob_view.open("HKEY_CURRENT_USER\\Software\\Vendor")
    assert bob_key.value("Owner").value == "bob"

    assert alice_key.value("Owner").value == "alice"
    assert alice_key.source.identifier == alice
    assert view.user == alice
    assert bob_view.user == bob


def test_multiple_user_hives_require_context() -> None:
    users = {"S-1-5-21-1": make_user("S-1-5-21-1", "alice"), "S-1-5-21-2": make_user("S-1-5-21-2", "bob")}
    view = RegistryView(users=users)

    with pytest.raises(UserContextError):
        view.open("HKEY_CURRENT_USER\\Software\\Vendor")

    assert view.open("HKU\\S-1-5-21-2\\Software\\Vendor").value("Owner").value == "bob"


def test_software_and_system_are_separate_mounts() -> None:
    view = RegistryView(system=make_system(1, 1, 1), software=make_software("offline-software"))

    software_key = view.open("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
    assert software_key.value("ProductName").value == "offline-software"
    assert software_key.source.role == "SOFTWARE"
    assert software_key.physical_path == "Microsoft\\Windows\\CurrentVersion"

    assert view.open("SOFTWARE\\Microsoft").physical_path == "Microsoft"
    assert view.open("\\REGISTRY\\MACHINE\\SYSTEM\\Select").name == "Select"
    assert "\\REGISTRY\\MACHINE\\SYSTEM" in view.mounts


def test_bare_paths_require_a_recognizable_hive_or_physical_root() -> None:
    view = RegistryView(system=make_system(1, 1, 1))

    with pytest.raises(MountNotFoundError):
        view.open("Random\\Path")

    assert view.open("SYSTEM\\ControlSet001\\Control\\Lsa").physical_path == "ControlSet001\\Control\\Lsa"
    assert view.open("ControlSet001\\Control\\Lsa").physical_path == "ControlSet001\\Control\\Lsa"


def test_missing_hive_context_is_explicit() -> None:
    with pytest.raises(MissingContextError):
        RegistryView().open("HKLM\\SYSTEM\\Select")
    with pytest.raises(MissingContextError):
        RegistryView(system=make_system(1, 1, 1)).open("HKLM\\SOFTWARE\\Microsoft")
    with pytest.raises(UserContextError):
        RegistryView().open("HKEY_CURRENT_USER\\Software")


def test_provenance_expands_to_hive_physical_path_and_selection() -> None:
    view = RegistryView(system=make_system(current=2, default=1, last_known_good=1))
    key = view.open("HKLM\\SYSTEM\\CurrentControlSet\\Services\\shared")
    value = key.value("ImagePath")

    expanded = value.to_dict()
    assert expanded["value"] == "system-2"
    assert expanded["physical_key_path"] == "ControlSet002\\Services\\shared"
    assert expanded["hive"]["identifier"] == "SYSTEM"
    assert expanded["selection"]["pointer"] == "Current"
    assert expanded["selection"]["value"] == 2
    assert expanded["selection"]["control_set"] == "ControlSet002"

    key_dict = key.expand()
    assert key_dict["selection"]["alias"] == "CurrentControlSet"
    assert key_dict["physical_path"] == "ControlSet002\\Services\\shared"


def test_relative_child_open_keeps_source_and_selection() -> None:
    view = RegistryView(system=make_system(current=2, default=1, last_known_good=1))
    key = view.open("HKLM\\SYSTEM\\CurrentControlSet")
    child = key.open("Services\\shared")

    assert child.physical_path == "ControlSet002\\Services\\shared"
    assert child.logical_path == "HKLM\\SYSTEM\\CurrentControlSet\\Services\\shared"
    assert child.selection.control_set == "ControlSet002"

    assert key.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa").physical_path == "ControlSet002\\Control\\Lsa"
    assert key.open("\\REGISTRY\\MACHINE\\SYSTEM\\Select").name == "Select"
    assert [entry.name for entry in key.subkey("Services").subkeys()] == ["shared"]


def test_missing_physical_key_raises_registry_error() -> None:
    view = RegistryView(system=make_system(1, 1, 1))

    with pytest.raises(RegistryKeyNotFoundError):
        view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Missing")


def test_alias_paths_keep_distinct_pointer_evidence() -> None:
    view = RegistryView(system=make_system(current=2, default=1, last_known_good=2))

    current = view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
    default = view.open("HKLM\\SYSTEM\\DefaultControlSet\\Control\\Lsa")
    last_known_good = view.open("HKLM\\SYSTEM\\LastKnownGoodControlSet\\Control\\Lsa")

    assert current.value("Source").value == "lsa-2"
    assert default.value("Source").value == "lsa-1"
    assert last_known_good.value("Source").value == "lsa-2"
    assert [key.selection.pointer for key in (current, default, last_known_good)] == [
        "Current",
        "Default",
        "LastKnownGood",
    ]


def test_explicit_control_set_only_overrides_current_alias() -> None:
    view = RegistryView(system=make_system(current=2, default=1, last_known_good=1), control_set=1)

    assert view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa").value("Source").value == "lsa-1"
    assert view.open("HKLM\\SYSTEM\\DefaultControlSet\\Control\\Lsa").value("Source").value == "lsa-1"
    assert view.open("HKLM\\SYSTEM\\LastKnownGoodControlSet\\Control\\Lsa").value("Source").value == "lsa-1"

    # An explicit Current override must not leak into the other pointers.
    other = RegistryView(system=make_system(current=2, default=1, last_known_good=2), control_set=2)
    assert other.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa").value("Source").value == "lsa-2"
    assert other.open("HKLM\\SYSTEM\\DefaultControlSet\\Control\\Lsa").value("Source").value == "lsa-1"
    assert other.open("HKLM\\SYSTEM\\LastKnownGoodControlSet\\Control\\Lsa").value("Source").value == "lsa-2"

    with pytest.raises(ControlSetNotFoundError):
        RegistryView(system=make_system(current=2, default=1, last_known_good=1), control_set=9)


def test_same_logical_query_across_two_system_hives_hits_correct_source() -> None:
    first = RegistryView(system=make_system(current=2, default=1, last_known_good=1))
    second = RegistryView(system=make_system(current=1, default=2, last_known_good=2))
    query = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\shared"

    first_key = first.open(query)
    second_key = second.open(query)

    assert first_key.value("ImagePath").value == "system-2"
    assert second_key.value("ImagePath").value == "system-1"
    assert first_key.hive is first.system
    assert second_key.hive is second.system
    assert first_key.expand()["selection"]["value"] == 2
    assert second_key.expand()["selection"]["value"] == 1


def test_user_handles_remain_usable_after_switch_and_failed_switch() -> None:
    alice = "S-1-5-21-1"
    bob = "S-1-5-21-2"
    view = RegistryView(users={alice: make_user(alice, "alice"), bob: make_user(bob, "bob")}, user=alice)

    alice_handle = view.open("HKCU\\Environment")
    bob_view = view.with_user(bob)
    bob_handle = bob_view.open("HKCU\\Environment")

    with pytest.raises(UserContextError):
        bob_view.with_user("S-1-5-21-404")

    assert alice_handle.value("USERNAME").value == "alice"
    assert bob_handle.value("USERNAME").value == "bob"
    assert view.open("HKCU\\Environment").value("USERNAME").value == "alice"


def test_real_system_hive_select_evidence() -> None:
    with gzip.open(Path(__file__).parent / "_data" / "SYSTEM.gz", "rb") as fh:
        view = RegistryView(system=RegistryHive(fh))
        evidence = view.current_control_set_evidence

        assert evidence.pointer == "Current"
        assert evidence.value == 1
        assert evidence.control_set == "ControlSet001"
        assert evidence.source is not None
        assert evidence.source.role == "SYSTEM"

        key = view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
        assert key.physical_path == "ControlSet001\\Control\\Lsa"
        assert key.physical_control_set == "ControlSet001"
        assert key.expand()["hive"]["filename"] == "SYSTEM"


def test_mounting_a_user_hive_in_a_new_view_is_isolated() -> None:
    alice = "S-1-5-21-1"
    base = RegistryView(users={alice: make_user(alice, "alice")}, user=alice)
    original = base.open("HKCU\\Software\\Vendor")

    carol = base.with_user_hive("S-1-5-21-3", make_user("S-1-5-21-3", "carol")).with_user("S-1-5-21-3")

    extended = base.with_user_hive("S-1-5-21-3", make_user("S-1-5-21-3", "carol"))

    assert carol.open("HKCU\\Software\\Vendor").value("Owner").value == "carol"
    assert original.value("Owner").value == "alice"
    assert set(extended.users) == {alice, "S-1-5-21-3"}
    assert set(base.users) == {alice}
    assert base.user == alice


def test_view_mount_description() -> None:
    view = RegistryView(
        system=make_system(1, 1, 1),
        software=make_software(),
        users={"S-1-5-21-1": make_user("S-1-5-21-1", "alice")},
    )
    described = view.to_dict()

    assert set(described["mounts"]) == {
        "\\REGISTRY\\MACHINE\\SYSTEM",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        "\\REGISTRY\\USER\\S-1-5-21-1",
    }
    assert described["mounts"]["\\REGISTRY\\MACHINE\\SYSTEM"]["filename"] == "SYSTEM"
    assert described["user"] is None
    assert described["control_set"] is None
