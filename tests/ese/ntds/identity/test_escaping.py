from __future__ import annotations

import pytest

from dissect.database.ese.ntds.identity import escape_rdn_value, render_rdn


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        ("a,b", "a\\,b"),
        ("a+b", "a\\+b"),
        ("a=b", "a\\=b"),
        ('quote"', 'quote\\"'),
        ("back\\slash", "back\\\\slash"),
        ("brackets<test>", "brackets\\<test\\>"),
        ("semi;colon", "semi\\;colon"),
        (" leading", "\\ leading"),
        ("trailing ", "trailing\\ "),
        ("#hash", "\\#hash"),
        ("nul\x00end", "nul\\00end"),
        ("new\nline", "new\\0Aline"),
        ("carriage\r", "carriage\\0D"),
        ("tab\there", "tab\\09here"),
        ("del\x7f", "del\\7F"),
        ("middle space", "middle space"),
        ("", ""),
    ],
)
def test_escape_rdn_value(raw: str, expected: str) -> None:
    assert escape_rdn_value(raw) == expected


def test_render_rdn_single_valued() -> None:
    assert render_rdn("cn", ["Users"]) == "cn=Users"


def test_render_rdn_multi_valued_joins_avas() -> None:
    # Multi-valued RDN information must be preserved, not collapsed to a single value.
    assert render_rdn("cn", ["primary", "secondary"]) == "cn=primary+cn=secondary"


def test_render_rdn_escapes_type_and_values() -> None:
    assert render_rdn("cn", ["a,b", " c "]) == "cn=a\\,b+cn=\\ c\\ "
