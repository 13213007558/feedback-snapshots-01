from __future__ import annotations

from io import BytesIO

import pytest

from dissect.shellitem.lnk import Lnk
from dissect.shellitem.lnk.encoding import (
    AnsiCodec,
    DecodeStatus,
    EncodingSource,
    TextKind,
    decode_ansi,
)

from .lnk_builder import (
    ansi_link_info,
    build_lnk,
    console_fe_block,
    environment_block,
    tracker_block,
    unicode_link_info,
    unicode_volume_label_link_info,
)

# A multibyte Japanese path encoded with the Japanese ANSI code page (cp932).
CP932_PATH = "C:\\資料\\計画書.txt"
CP932_BYTES = CP932_PATH.encode("cp932")
CP932_UNICODE = CP932_PATH.encode("utf-16-le")
# Distinct cp932 byte strings that an assumed UTF-8 decode would mangle.
NET_NAME_BYTES = "\\\\サーバー\\共有".encode("cp932")


def _parse(data: bytes, **kwargs) -> Lnk:
    return Lnk(BytesIO(data), **kwargs)


def test_ansi_stringdata_is_pending_without_codec() -> None:
    lnk = _parse(build_lnk(is_unicode=False, name_bytes=CP932_BYTES, name_char_count=len(CP932_BYTES)))

    field = lnk.text_fields["stringdata.name_string"]
    assert field.kind == TextKind.ANSI
    assert field.status == DecodeStatus.PENDING
    assert field.codec is None
    assert field.source == EncodingSource.UNKNOWN
    # Raw bytes are always retained verbatim.
    assert field.raw == CP932_BYTES
    assert field.value is None
    # No host-locale or assumed decoding leaks into the stored value.
    assert field.is_pending is True


def test_pending_field_keeps_distinct_targets_distinguishable() -> None:
    first = decode_ansi("a", b"path\xc9", None)
    second = decode_ansi("b", b"path\x89", None)
    # Different byte sequences must never collapse to one display value.
    assert first.raw != second.raw
    assert first.text != second.text
    # latin-1 fallback view is bijective over bytes.
    assert first.text.encode("latin-1") == first.raw


def test_caller_sourced_codec_decodes_ansi_field() -> None:
    codec = AnsiCodec(codec="cp932", provenance="host-inventory:ja-JP", note="collected from endpoint E42")
    lnk = _parse(
        build_lnk(is_unicode=False, name_bytes=CP932_BYTES, name_char_count=len(CP932_BYTES)),
        ansi_codec=codec,
    )

    field = lnk.text_fields["stringdata.name_string"]
    assert field.status == DecodeStatus.DECODED
    assert field.kind == TextKind.ANSI
    assert field.codec == "cp932"
    assert field.source == EncodingSource.CALLER
    assert field.value == CP932_PATH
    assert "collected from endpoint E42" in field.note
    assert "host-inventory:ja-JP" in field.note
    # The decision is explainable per field, not via a file-wide label.
    assert "cp932" in field.explain()


def test_unicode_stringdata_independent_of_codec_and_locale() -> None:
    data = build_lnk(
        is_unicode=True,
        name_bytes=CP932_UNICODE,
        name_char_count=len(CP932_PATH),
    )
    # Even a deliberately wrong caller codec must not touch a UTF-16LE field.
    lnk = _parse(data, ansi_codec=AnsiCodec("cp1252", provenance="irrelevant"))

    field = lnk.text_fields["stringdata.name_string"]
    assert field.kind == TextKind.UTF16
    assert field.codec == "utf-16-le"
    assert field.source == EncodingSource.LINK_FLAG_IS_UNICODE
    assert field.status == DecodeStatus.DECODED
    assert field.value == CP932_PATH


def test_ansi_and_unicode_same_target_decode_to_same_text() -> None:
    ansi_lnk = _parse(
        build_lnk(is_unicode=False, name_bytes=CP932_BYTES, name_char_count=len(CP932_BYTES)),
        ansi_codec=AnsiCodec("cp932", provenance="test"),
    )
    unicode_lnk = _parse(
        build_lnk(is_unicode=True, name_bytes=CP932_UNICODE, name_char_count=len(CP932_PATH)),
    )
    ansi_field = ansi_lnk.text_fields["stringdata.name_string"]
    unicode_field = unicode_lnk.text_fields["stringdata.name_string"]

    assert ansi_field.kind != unicode_field.kind
    assert ansi_field.raw != unicode_field.raw
    assert ansi_field.value == unicode_field.value == CP932_PATH


def test_conflicting_consolefe_is_recorded_not_auto_applied() -> None:
    data = build_lnk(
        is_unicode=False,
        name_bytes=CP932_BYTES,
        name_char_count=len(CP932_BYTES),
        extra_blocks=[console_fe_block(932), console_fe_block(1252)],
    )
    lnk = _parse(data)

    assert lnk.console_fe_code_pages == [932, 1252]
    assert lnk.console_fe_conflict is True
    # ConsoleFE must not implicitly decode any ANSI string.
    field = lnk.text_fields["stringdata.name_string"]
    assert field.status == DecodeStatus.PENDING

    # The caller may deliberately apply a ConsoleFE page, with provenance.
    lnk_applied = _parse(data, ansi_codec=AnsiCodec.from_console_fe(932, note="analyst-confirmed"))
    applied = lnk_applied.text_fields["stringdata.name_string"]
    assert applied.status == DecodeStatus.DECODED
    assert applied.source == EncodingSource.CONSOLE_FE_HINT
    assert applied.value == CP932_PATH
    assert "console-fe-codepage:932" in applied.note


def test_single_consolefe_is_hint_only() -> None:
    data = build_lnk(
        is_unicode=False,
        name_bytes=CP932_BYTES,
        name_char_count=len(CP932_BYTES),
        extra_blocks=[console_fe_block(932)],
    )
    lnk = _parse(data)
    assert lnk.console_fe_code_pages == [932]
    assert lnk.console_fe_conflict is False
    assert lnk.text_fields["stringdata.name_string"].status == DecodeStatus.PENDING


def test_result_stable_across_locales(monkeypatch: pytest.MonkeyPatch) -> None:
    data = build_lnk(
        is_unicode=False,
        name_bytes=CP932_BYTES,
        name_char_count=len(CP932_BYTES),
        link_info=ansi_link_info(NET_NAME_BYTES),
        extra_blocks=[console_fe_block(932), console_fe_block(1252), tracker_block("WORKSTATION".encode("utf-8"))],
    )

    def snapshot(lnk: Lnk) -> list[tuple[str, str, str | None, str, str]]:
        return [
            (name, f.kind.value, f.codec, f.status.value, f.raw.hex()) for name, f in sorted(lnk.text_fields.items())
        ]

    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LANG", "C")
    baseline = snapshot(_parse(data))

    monkeypatch.setenv("LC_ALL", "ja_JP.UTF-8")
    monkeypatch.setenv("LANG", "ja_JP.UTF-8")
    assert snapshot(_parse(data)) == baseline

    monkeypatch.setenv("LC_ALL", "fr_FR.ISO-8859-1")
    monkeypatch.setenv("LANG", "fr_FR.ISO-8859-1")
    assert snapshot(_parse(data)) == baseline


def test_no_file_wide_encoding_label_per_field_basis() -> None:
    data = build_lnk(
        is_unicode=True,
        name_bytes=CP932_UNICODE,
        name_char_count=len(CP932_PATH),
        link_info=ansi_link_info(NET_NAME_BYTES),
        extra_blocks=[environment_block(CP932_BYTES, CP932_UNICODE)],
    )
    lnk = _parse(data)
    fields = lnk.text_fields

    # One file, mixed bases: UTF-16LE by spec/flag, ANSI pending for lack of code page.
    assert fields["stringdata.name_string"].kind == TextKind.UTF16
    assert fields["linkinfo.common_network_relative_link.net_name"].kind == TextKind.ANSI
    assert fields["linkinfo.common_network_relative_link.net_name"].status == DecodeStatus.PENDING
    assert fields["extradata.ENVIRONMENT_PROPS.target_ansi"].status == DecodeStatus.PENDING
    assert fields["extradata.ENVIRONMENT_PROPS.target_unicode"].kind == TextKind.UTF16
    assert fields["extradata.ENVIRONMENT_PROPS.target_unicode"].value == CP932_PATH

    explanations = lnk.explain_text().splitlines()
    assert any("utf-16-le" in line for line in explanations)
    assert any("left undecoded" in line for line in explanations)


def test_unicode_link_info_parses_ansi_and_unicode_offsets() -> None:
    data = build_lnk(
        is_unicode=True,
        name_bytes=CP932_UNICODE,
        name_char_count=len(CP932_PATH),
        link_info=unicode_link_info(CP932_BYTES, CP932_UNICODE, b"sub\\file.txt", "sub\\file.txt".encode("utf-16-le")),
    )
    lnk_default = _parse(data)

    ansi_field = lnk_default.text_fields["linkinfo.local_base_path"]
    assert ansi_field.status == DecodeStatus.PENDING
    assert ansi_field.raw == CP932_BYTES

    unicode_field = lnk_default.text_fields["linkinfo.local_base_path_unicode"]
    assert unicode_field.kind == TextKind.UTF16
    assert unicode_field.value == CP932_PATH

    suffix_uni = lnk_default.text_fields["linkinfo.common_path_suffix_unicode"]
    assert suffix_uni.value == "sub\\file.txt"

    lnk_decoded = _parse(data, ansi_codec=AnsiCodec("cp932", provenance="test"))
    assert lnk_decoded.text_fields["linkinfo.local_base_path"].value == CP932_PATH
    assert lnk_decoded.text_fields["linkinfo.common_path_suffix"].value == "sub\\file.txt"


def test_unicode_volume_label_is_decoded_as_utf16() -> None:
    label = "ボリューム"
    data = build_lnk(
        is_unicode=True,
        name_bytes=CP932_UNICODE,
        name_char_count=len(CP932_PATH),
        link_info=unicode_volume_label_link_info(label.encode("utf-16-le")),
    )
    lnk = _parse(data)
    field = lnk.text_fields["linkinfo.volumeid.volume_label"]
    assert field.kind == TextKind.UTF16
    assert field.codec == "utf-16-le"
    assert field.value == label
    assert field.status == DecodeStatus.DECODED


def test_tracker_machine_id_keeps_raw_bytes_and_interpretation() -> None:
    data = build_lnk(
        is_unicode=False,
        name_bytes=b"plain",
        name_char_count=5,
        extra_blocks=[tracker_block("WS-01".encode("utf-8"))],
    )
    lnk = _parse(data)
    field = lnk.text_fields["extradata.TRACKER_PROPS.machine_id"]
    assert field.status == DecodeStatus.PENDING
    # Raw cstruct field remains byte-comparable for backward compatibility.
    assert lnk.extradata.TRACKER_PROPS.machine_id == b"WS-01" + b"\x00" * 11
    assert field.raw == b"WS-01" + b"\x00" * 11


def test_encoded_text_backward_compatible_equality() -> None:
    field = decode_ansi("x", b"abc", None)
    assert field == b"abc"
    assert field == field.text
    assert len(field) == len(field.text)
    assert field.decode() == field.text


def test_invalid_codec_fails_fast() -> None:
    with pytest.raises(LookupError):
        AnsiCodec(codec="not-a-real-codec")


def test_undecodable_bytes_use_reversible_escapes() -> None:
    # 0x81 is undefined in cp1252; a strict decode fails and must fall back to
    # surrogateescape rather than a lossy replacement marker.
    codec = AnsiCodec("cp1252", provenance="test")
    field = decode_ansi("x", b"a\x81b", codec)
    assert field.status == DecodeStatus.DECODED_WITH_ESCAPES
    # The transformation stays reversible.
    assert field.value.encode("cp1252", errors="surrogateescape") == b"a\x81b"
    # Distinct undecodable byte sequences never share a display value.
    other = decode_ansi("y", b"a\x8db", codec)
    assert field.text != other.text
