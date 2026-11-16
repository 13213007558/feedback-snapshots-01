"""Security regression tests for custom JSON CMap resources.

The shipped CMaps are gzip-compressed JSON rather than pickle, but valid
JSON syntax alone does not make the decoded structure safe. These tests
feed malformed yet syntactically valid payloads through the same loading
path used for the bundled resources (a temporary ``CMAP_PATH`` directory)
and verify that ambiguous or out-of-range structures are rejected before
they can enter the global caches. Results are also cross-checked through
the font decoding entry point (``PDFCIDFont``).
"""

import gzip
import io
import json
import os

import pytest

from pdfminer.cmapdb import CMapDataError, CMapDB
from pdfminer.pdffont import PDFCIDFont
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.psparser import PSLiteral


def _write_cmap(tmp_path: str, name: str, payload: object) -> str:
    """Write a gzip-compressed JSON CMap into a CMAP_PATH directory."""
    path = os.path.join(tmp_path, f"{name}.json.gz")
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", compresslevel=9, mtime=0) as gz:
        # ensure_ascii keeps lone-surrogate payloads valid JSON text while
        # preserving the unpaired escape once json.load decodes them.
        gz.write(json.dumps(payload, ensure_ascii=True).encode("utf-8"))
    with open(path, "wb") as fp:
        fp.write(buffer.getvalue())
    return path


@pytest.fixture()
def custom_cmap_path(tmp_path, monkeypatch):
    """Point CMapDB at an isolated directory and keep its caches pristine."""
    cmap_cache = CMapDB._cmap_cache.copy()
    umap_cache = CMapDB._umap_cache.copy()
    CMapDB._cmap_cache.clear()
    CMapDB._umap_cache.clear()
    monkeypatch.setenv("CMAP_PATH", str(tmp_path))
    yield tmp_path
    CMapDB._cmap_cache.clear()
    CMapDB._umap_cache.clear()
    CMapDB._cmap_cache.update(cmap_cache)
    CMapDB._umap_cache.update(umap_cache)


# ---------------------------------------------------------------------------
# Valid resources, including vertical and multi-byte encodings
# ---------------------------------------------------------------------------


def test_loads_valid_multibyte_cmap(custom_cmap_path):
    payload = {
        "IS_VERTICAL": False,
        "CODE2CID": {
            "142": {
                "160": 326,
                "161": 327,
            },
            "65": 7,
        },
    }
    _write_cmap(str(custom_cmap_path), "MultiByte-H", payload)

    cmap = CMapDB.get_cmap("MultiByte-H")
    assert cmap.attrs.get("CMapName") == "MultiByte-H"
    assert list(cmap.decode(b"\x8e\xa0")) == [326]
    assert list(cmap.decode(b"A")) == [7]
    assert not cmap.is_vertical()


def test_loads_valid_vertical_cmap(custom_cmap_path):
    payload = {
        "IS_VERTICAL": True,
        "CODE2CID": {"65": 7},
    }
    _write_cmap(str(custom_cmap_path), "Custom-V", payload)

    cmap = CMapDB.get_cmap("Custom-V")
    assert cmap.is_vertical()
    assert list(cmap.decode(b"A")) == [7]


def test_legacy_character_key_form_is_accepted(custom_cmap_path):
    # Legacy resources encode byte keys as single non-digit characters.
    payload = {"IS_VERTICAL": False, "CODE2CID": {" ": 42}}
    _write_cmap(str(custom_cmap_path), "Legacy-H", payload)

    cmap = CMapDB.get_cmap("Legacy-H")
    assert list(cmap.decode(b" ")) == [42]


def test_loads_valid_unicode_map_horizontal_and_vertical(custom_cmap_path):
    payload = {
        "CID2UNICHR_H": {"1": " ", "2": "A"},
        "CID2UNICHR_V": {"1": "　", "2": "︰"},
    }
    _write_cmap(str(custom_cmap_path), "to-unicode-Custom-Order", payload)

    horizontal = CMapDB.get_unicode_map("Custom-Order", vertical=False)
    vertical = CMapDB.get_unicode_map("Custom-Order", vertical=True)
    assert horizontal.get_unichr(2) == "A"
    assert vertical.get_unichr(2) == "︰"
    assert vertical.is_vertical() and not horizontal.is_vertical()


def test_font_decoding_entry_point_uses_custom_cmap(custom_cmap_path):
    _write_cmap(
        str(custom_cmap_path),
        "FontTest-H",
        {"IS_VERTICAL": False, "CODE2CID": {"65": 100}},
    )
    _write_cmap(
        str(custom_cmap_path),
        "to-unicode-Test-Order",
        {"CID2UNICHR_H": {"100": "X"}, "CID2UNICHR_V": {"100": "︰"}},
    )

    spec = {
        "BaseFont": PSLiteral("TestFont"),
        "Encoding": PSLiteral("FontTest-H"),
        "CIDSystemInfo": {
            "Registry": b"Test",
            "Ordering": b"Order",
        },
    }
    font = PDFCIDFont(PDFResourceManager(), spec)

    assert list(font.decode(b"A")) == [100]
    assert font.to_unichr(100) == "X"


# ---------------------------------------------------------------------------
# Malformed, but syntactically valid, JSON payloads
# ---------------------------------------------------------------------------


def test_rejects_colliding_numeric_key_spellings(custom_cmap_path):
    # Fully valid JSON: "65" and "A" both normalize to byte 65, so two
    # different character encodings would be silently merged otherwise.
    payload = {
        "IS_VERTICAL": False,
        "CODE2CID": {"65": 7, "A": 8},
    }
    _write_cmap(str(custom_cmap_path), "Collision-H", payload)

    with pytest.raises(CMapDataError, match="duplicate byte key"):
        CMapDB.get_cmap("Collision-H")
    assert "Collision-H" not in CMapDB._cmap_cache


def test_rejects_non_canonical_decimal_spelling(custom_cmap_path):
    payload = {"IS_VERTICAL": False, "CODE2CID": {"065": 7, "65": 8}}
    _write_cmap(str(custom_cmap_path), "Canonical-H", payload)

    with pytest.raises(CMapDataError, match="non-canonical"):
        CMapDB.get_cmap("Canonical-H")


def test_rejects_byte_key_out_of_range(custom_cmap_path):
    payload = {"IS_VERTICAL": False, "CODE2CID": {"256": 7}}
    _write_cmap(str(custom_cmap_path), "OobByte-H", payload)

    with pytest.raises(CMapDataError, match="outside 0-255"):
        CMapDB.get_cmap("OobByte-H")


def test_rejects_leaf_with_wrong_type(custom_cmap_path):
    payload = {
        "IS_VERTICAL": False,
        "CODE2CID": {"65": "not-a-cid"},
    }
    _write_cmap(str(custom_cmap_path), "BadLeaf-H", payload)

    with pytest.raises(CMapDataError, match="integer CID"):
        CMapDB.get_cmap("BadLeaf-H")


def test_rejects_boolean_leaf_value(custom_cmap_path):
    # bool is an int subclass; it must not be accepted as a CID.
    payload = {"IS_VERTICAL": False, "CODE2CID": {"65": True}}
    _write_cmap(str(custom_cmap_path), "BoolLeaf-H", payload)

    with pytest.raises(CMapDataError, match="integer CID"):
        CMapDB.get_cmap("BoolLeaf-H")


def test_rejects_cid_out_of_range(custom_cmap_path):
    payload = {"IS_VERTICAL": False, "CODE2CID": {"65": 70000}}
    _write_cmap(str(custom_cmap_path), "OobCid-H", payload)

    with pytest.raises(CMapDataError, match="outside 0-65535"):
        CMapDB.get_cmap("OobCid-H")


def test_rejects_code_tree_too_deep(custom_cmap_path):
    node: object = 1
    for byte in range(CMapDB.MAX_CODE_TREE_DEPTH + 1):
        node = {str(100 + byte): node}
    _write_cmap(
        str(custom_cmap_path),
        "Deep-H",
        {"IS_VERTICAL": False, "CODE2CID": node},
    )

    with pytest.raises(CMapDataError, match="deeper than"):
        CMapDB.get_cmap("Deep-H")


def test_rejects_empty_inner_node(custom_cmap_path):
    payload = {"IS_VERTICAL": False, "CODE2CID": {"65": {}}}
    _write_cmap(str(custom_cmap_path), "EmptyNode-H", payload)

    with pytest.raises(CMapDataError, match="empty CODE2CID node"):
        CMapDB.get_cmap("EmptyNode-H")


def test_rejects_illegal_unicode_value(custom_cmap_path):
    payload = {"CID2UNICHR_H": {"1": "A\ud800B"}}
    _write_cmap(str(custom_cmap_path), "to-unicode-BadSurrogate", payload)

    with pytest.raises(CMapDataError, match="surrogate"):
        CMapDB.get_unicode_map("BadSurrogate")


@pytest.mark.parametrize("value", ["", 65, None, ["A"]])
def test_rejects_non_string_unicode_mapping(custom_cmap_path, value):
    payload = {"CID2UNICHR_H": {"1": value}}
    _write_cmap(str(custom_cmap_path), "to-unicode-BadValue", payload)

    with pytest.raises(CMapDataError, match="non-empty string"):
        CMapDB.get_unicode_map("BadValue")


def test_rejects_duplicate_cid_spelling_in_unicode_map(custom_cmap_path):
    payload = {"CID2UNICHR_H": {"1": "A", "01": "B"}}
    _write_cmap(str(custom_cmap_path), "to-unicode-CidCollision", payload)

    with pytest.raises(CMapDataError):
        CMapDB.get_unicode_map("CidCollision")


def test_rejects_non_boolean_vertical_flag(custom_cmap_path):
    payload = {"IS_VERTICAL": "yes", "CODE2CID": {"65": 7}}
    _write_cmap(str(custom_cmap_path), "BadFlag-H", payload)

    with pytest.raises(CMapDataError, match="IS_VERTICAL"):
        CMapDB.get_cmap("BadFlag-H")


def test_rejects_top_level_non_object(custom_cmap_path):
    _write_cmap(str(custom_cmap_path), "TopLevel-H", ["not", "an", "object"])

    with pytest.raises(CMapDataError, match="top-level"):
        CMapDB.get_cmap("TopLevel-H")


def test_rejects_payload_without_mappings(custom_cmap_path):
    _write_cmap(str(custom_cmap_path), "Empty-H", {"IS_VERTICAL": False})

    with pytest.raises(CMapDataError, match="neither CODE2CID"):
        CMapDB.get_cmap("Empty-H")


def test_rejects_unknown_fields(custom_cmap_path):
    payload = {"IS_VERTICAL": False, "CODE2CID": {"65": 7}, "EVIL": 1}
    _write_cmap(str(custom_cmap_path), "Unknown-H", payload)

    with pytest.raises(CMapDataError, match="unexpected fields"):
        CMapDB.get_cmap("Unknown-H")


def test_rejects_invalid_json_syntax(custom_cmap_path):
    path = os.path.join(str(custom_cmap_path), "Broken-H.json.gz")
    with gzip.open(path, "wb") as gz:
        gz.write(b"{not valid json")

    with pytest.raises(json.JSONDecodeError):
        CMapDB.get_cmap("Broken-H")
    assert "Broken-H" not in CMapDB._cmap_cache


# ---------------------------------------------------------------------------
# Cache isolation and recovery
# ---------------------------------------------------------------------------


def test_failed_load_does_not_poison_cache(custom_cmap_path):
    _write_cmap(
        str(custom_cmap_path),
        "Poison-H",
        {"IS_VERTICAL": False, "CODE2CID": {"256": 7}},
    )

    for _ in range(2):
        with pytest.raises(CMapDataError):
            CMapDB.get_cmap("Poison-H")
    assert "Poison-H" not in CMapDB._cmap_cache

    # Replace the bad resource with a valid one and confirm loading recovers.
    _write_cmap(
        str(custom_cmap_path),
        "Poison-H",
        {"IS_VERTICAL": False, "CODE2CID": {"65": 9}},
    )
    cmap = CMapDB.get_cmap("Poison-H")
    assert list(cmap.decode(b"A")) == [9]
    assert CMapDB._cmap_cache["Poison-H"] is cmap


def test_failed_unicode_load_does_not_poison_cache(custom_cmap_path):
    _write_cmap(
        str(custom_cmap_path),
        "to-unicode-Poison-Order",
        {"CID2UNICHR_H": {"1": "A\ud800"}},
    )

    with pytest.raises(CMapDataError):
        CMapDB.get_unicode_map("Poison-Order")
    assert "Poison-Order" not in CMapDB._umap_cache

    _write_cmap(
        str(custom_cmap_path),
        "to-unicode-Poison-Order",
        {"CID2UNICHR_H": {"1": "A"}, "CID2UNICHR_V": {"1": "B"}},
    )
    assert CMapDB.get_unicode_map("Poison-Order").get_unichr(1) == "A"
