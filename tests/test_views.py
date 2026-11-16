from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest

from dissect.regf import RegistryHive
from dissect.regf.exceptions import RegistryKeyNotFoundError
from dissect.regf.views import (
    LookupContext,
    LookupMode,
    LookupStatus,
    RedirectionPolicy,
    RedirectionRule,
    UnmatchedPolicy,
    ViewKind,
    load_policy,
    resolve_current_control_set,
    resolve_physical,
    resolve_view,
)
from tests.hive_builder import GUID, make_hive, make_hive_without_select

CLSID_PATH = rf"Software\Classes\CLSID\{GUID}"
WOW_CLSID_PATH = rf"Software\Wow6432Node\Classes\CLSID\{GUID}"


@pytest.fixture
def hive() -> RegistryHive:
    return RegistryHive(BytesIO(make_hive()))


def policy() -> RedirectionPolicy:
    return RedirectionPolicy(
        name="test-wow64",
        source="tests/hive_builder.py",
        rules=(
            RedirectionRule(
                name="software-redirect",
                logical_prefix="Software",
                target_prefix="Software\\Wow6432Node",
                shared_prefixes=("Classes",),
                source="synthetic",
            ),
            RedirectionRule(
                name="classes-clsid-redirect",
                logical_prefix="Software\\Classes\\CLSID",
                target_prefix="Software\\Wow6432Node\\Classes\\CLSID",
                source="synthetic",
            ),
        ),
    )


def test_physical_open_is_unchanged(hive: RegistryHive) -> None:
    assert hive.open(CLSID_PATH).value("(Default)").value == "native-64"
    assert hive.open(WOW_CLSID_PATH).value("(Default)").value == "wow-32"


def test_physical_lookup_never_inserts_wow6432node(hive: RegistryHive) -> None:
    result = resolve_physical(hive, CLSID_PATH)

    assert result.status is LookupStatus.FOUND
    assert result.key is not None
    assert result.key.path == CLSID_PATH
    assert result.key.value("(Default)").value == "native-64"

    missing = resolve_physical(hive, r"Software\Wow6432Node\Classes\CLSID")
    assert missing.status is LookupStatus.FOUND
    assert missing.key is not None
    assert missing.key.path == r"Software\Wow6432Node\Classes\CLSID"


def test_explicit_physical_path_is_marked(hive: RegistryHive) -> None:
    default = resolve_physical(hive, CLSID_PATH)
    explicit = resolve_physical(hive, WOW_CLSID_PATH)

    assert default.mode is LookupMode.PHYSICAL
    assert explicit.mode is LookupMode.EXPLICIT_PHYSICAL
    assert explicit.key is not None
    assert explicit.key.value("(Default)").value == "wow-32"


def test_physical_missing_is_not_view_absence(hive: RegistryHive) -> None:
    result = resolve_physical(hive, r"Software\Missing")

    assert result.status is LookupStatus.NOT_FOUND
    assert result.key is None
    assert "says nothing about other hives" in result.notes[0]


def test_logical_wow32_uses_rule_and_physical_target(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=policy(),
        context=LookupContext(hive_role="SOFTWARE", os_arch="amd64", process_bits=32),
    )

    assert result.status is LookupStatus.FOUND
    assert result.key is not None
    assert result.physical_path == WOW_CLSID_PATH
    assert result.key.value("(Default)").value == "wow-32"
    assert result.rules_applied == ("classes-clsid-redirect",)


def test_logical_shared_key_stays_native(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        r"Software\Classes",
        view=ViewKind.WOW32,
        policy=policy(),
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.FOUND
    assert result.physical_path == r"Software\Classes"

    other = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=RedirectionPolicy(
            name="no-clsid-override",
            rules=(policy().rules[0],),
        ),
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert other.status is LookupStatus.FOUND
    assert other.physical_path == CLSID_PATH
    assert other.key is not None
    assert other.key.value("(Default)").value == "native-64"


def test_logical_miss_keeps_other_view_as_evidence(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        r"Software\NativeOnly",
        view=ViewKind.WOW32,
        policy=policy(),
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.NOT_FOUND_IN_VIEW
    assert result.physical_path == r"Software\Wow6432Node\NativeOnly"
    assert [alt.physical_path for alt in result.alternatives] == [r"Software\NativeOnly"]
    assert "not proof" in " ".join(result.notes)


def test_logical_view_does_not_rewrite_explicit_wow_path(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        WOW_CLSID_PATH,
        view=ViewKind.WOW32,
        policy=policy(),
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.RULE_CONFLICT
    assert result.key is None


def test_logical_needs_context_when_rule_cannot_be_decided(hive: RegistryHive) -> None:
    versioned = RedirectionPolicy(
        name="versioned",
        rules=(
            RedirectionRule(
                name="only-win7",
                logical_prefix="Software",
                target_prefix="Software\\Wow6432Node",
                max_os_version=(6, 1),
            ),
        ),
    )

    result = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=versioned,
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.NEEDS_CONTEXT
    assert result.required_context == ("os_version",)

    wrong_version = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=versioned,
        context=LookupContext(hive_role="SOFTWARE", os_version=(10, 0)),
    )

    assert wrong_version.status is LookupStatus.FOUND
    assert wrong_version.physical_path == CLSID_PATH
    assert "does not apply" in " ".join(wrong_version.notes)


def test_logical_uncovered_path_is_out_of_scope(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        "Select",
        view=ViewKind.WOW32,
        policy=policy(),
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.OUT_OF_SCOPE
    assert result.key is None


def test_logical_passthrough_is_explicit_opt_in(hive: RegistryHive) -> None:
    passthrough = RedirectionPolicy(name="pass", rules=(), unmatched=UnmatchedPolicy.PASSTHROUGH)

    result = resolve_view(
        hive,
        "Select",
        view=ViewKind.WOW32,
        policy=passthrough,
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.FOUND
    assert result.physical_path == "Select"


def test_logical_policy_must_match_hive_role(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=policy(),
        context=LookupContext(hive_role="SYSTEM"),
    )

    assert result.status is LookupStatus.OUT_OF_SCOPE
    assert "Supply a policy" in " ".join(result.notes)


def test_absolute_path_requires_external_mapping(hive: RegistryHive) -> None:
    result = resolve_physical(hive, rf"HKLM\SOFTWARE\Classes\CLSID\{GUID}")

    assert result.status is LookupStatus.INVALID_PATH
    assert "hive-relative" in result.notes[0]


def test_current_control_set_uses_select_evidence(hive: RegistryHive) -> None:
    result = resolve_current_control_set(hive)

    assert result.status is LookupStatus.FOUND
    assert result.control_set == "ControlSet001"


def test_current_control_set_without_select_needs_context() -> None:
    hive = RegistryHive(BytesIO(make_hive_without_select()))

    result = resolve_current_control_set(hive)

    assert result.status is LookupStatus.NEEDS_CONTEXT
    assert result.required_context == ("Select\\Current",)


def test_policy_json_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        '{"name": "json-policy", "rules": [{"name": "r", "logical_prefix": "Software", '
        '"target_prefix": "Software\\\\Wow6432Node", "views": ["wow32"], '
        '"min_os_version": [6, 1], "requires": []}]}',
        encoding="utf-8",
    )

    loaded = load_policy(path)

    assert loaded.name == "json-policy"
    assert loaded.rules[0].min_os_version == (6, 1)
    assert loaded.rules[0].views == frozenset({ViewKind.WOW32})


def test_same_specificity_rules_conflict(hive: RegistryHive) -> None:
    conflicting = RedirectionPolicy(
        name="conflict",
        rules=(
            RedirectionRule(name="a", logical_prefix="Software", target_prefix="Software\\Wow6432Node"),
            RedirectionRule(name="b", logical_prefix="SOFTWARE", target_prefix="Software\\Other"),
        ),
    )

    result = resolve_view(
        hive,
        r"Software\NativeOnly",
        view=ViewKind.WOW32,
        policy=conflicting,
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.RULE_CONFLICT
    assert result.rules_applied == ("a", "b")


def test_rule_requiring_process_bits_reports_missing() -> None:
    hive = RegistryHive(BytesIO(make_hive()))
    rule = RedirectionRule(
        name="only-32-bit",
        logical_prefix="Software",
        target_prefix="Software\\Wow6432Node",
        process_bits=32,
    )
    policy = RedirectionPolicy(name="bits", rules=(rule,))

    result = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=policy,
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.NEEDS_CONTEXT
    assert result.required_context == ("process_bits",)


def test_invalid_context_value_is_reported() -> None:
    hive = RegistryHive(BytesIO(make_hive()))
    rule = RedirectionRule(
        name="arch",
        logical_prefix="Software",
        target_prefix="Software\\Wow6432Node",
        os_arch=frozenset({"amd64"}),
    )
    policy = RedirectionPolicy(name="arch-policy", rules=(rule,))

    result = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.WOW32,
        policy=policy,
        context=LookupContext(hive_role="SOFTWARE", os_arch="itanium"),
    )

    assert result.status is LookupStatus.NEEDS_CONTEXT
    assert "unrecognized os_arch" in " ".join(result.notes)


def test_native_view_never_rewrites_but_offers_alternative(hive: RegistryHive) -> None:
    result = resolve_view(
        hive,
        CLSID_PATH,
        view=ViewKind.NATIVE,
        policy=policy(),
        context=LookupContext(hive_role="SOFTWARE"),
    )

    assert result.status is LookupStatus.FOUND
    assert result.physical_path == CLSID_PATH
    assert [alt.view for alt in result.alternatives] == ["wow32"]
    assert result.alternatives[0].physical_path == WOW_CLSID_PATH


def test_physical_root_and_empty_path(hive: RegistryHive) -> None:
    root = resolve_physical(hive, "")
    assert root.status is LookupStatus.FOUND
    assert root.key is hive.root()

    with pytest.raises(RegistryKeyNotFoundError):
        hive.open("Missing")
