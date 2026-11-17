# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import subprocess
import sys

import pytest

from dncil.clr.token import Token, TokenKind, MetadataTable
from dncil.clr.evidence import TokenRequest, TokenResolver, UnresolvedReason


class FakeProvider(TokenResolver):
    def __init__(self, tables=None, user_strings=None):
        super(FakeProvider, self).__init__()
        self.tables = tables or {}
        self.user_strings = user_strings or {}
        self.lookups = []

    def has_table(self, table):
        return bool(self.tables.get(table))

    def table_row_count(self, table):
        rows = self.tables.get(table)
        return len(rows) if rows else 0

    def get_table_row(self, table, rid):
        self.lookups.append((table, rid))
        rows = self.tables.get(table)
        if not rows or rid < 1 or rid > len(rows):
            return None
        return rows[rid - 1]

    def get_user_string(self, rid):
        self.lookups.append(("us", rid))
        return self.user_strings.get(rid)


def request(value, kind, offset=0):
    return TokenRequest(token=Token(value), kind=kind, offset=offset)


def test_same_integer_is_not_shared_across_kinds():
    provider = FakeProvider(
        tables={
            MetadataTable.TypeSpec: ["type-spec"],
            MetadataTable.MethodDef: ["method"],
        }
    )

    tok_result = provider.resolve(request(0x1B000001, TokenKind.InlineTok, 0x10))
    type_result = provider.resolve(request(0x1B000001, TokenKind.InlineType, 0x20))

    assert tok_result.resolved and tok_result.value == "type-spec"
    assert type_result.resolved and type_result.value == "type-spec"
    assert tok_result.offset == 0x10
    assert type_result.offset == 0x20
    assert tok_result.token.value == type_result.token.value == 0x1B000001
    assert provider.cache_keys() == (
        (TokenKind.InlineTok, 0x1B000001),
        (TokenKind.InlineType, 0x1B000001),
    )


def test_kind_mismatch_is_structured_unsolved():
    provider = FakeProvider(tables={MetadataTable.MethodDef: ["method"]})

    result = provider.resolve(request(0x06000001, TokenKind.InlineField, 0x30))

    assert not result.resolved
    assert result.issue.reason == UnresolvedReason.KIND_MISMATCH
    assert result.issue.token.value == 0x06000001
    assert result.issue.table == MetadataTable.MethodDef
    assert result.offset == 0x30


def test_missing_table_and_missing_row_are_distinct():
    provider = FakeProvider(tables={MetadataTable.MethodSpec: ["spec"]})

    present = provider.resolve(request(0x2B000001, TokenKind.InlineMethod))
    missing_row = provider.resolve(request(0x2B000002, TokenKind.InlineMethod))
    absent = FakeProvider().resolve(request(0x0A000001, TokenKind.InlineMethod))

    assert present.resolved
    assert missing_row.issue.reason == UnresolvedReason.MISSING_ROW
    assert missing_row.issue.rid == 0x2
    assert absent.issue.reason == UnresolvedReason.MISSING_TABLE


def test_invalid_table_and_empty_token_are_unresolved():
    provider = FakeProvider(tables={MetadataTable.MethodDef: ["method"]})

    invalid = provider.resolve(request(0xFF000001, TokenKind.InlineTok))
    empty = provider.resolve(request(0x00000000, TokenKind.InlineTok))
    empty_row = provider.resolve(request(0x06000000, TokenKind.InlineTok))

    assert invalid.issue.reason == UnresolvedReason.INVALID_TABLE
    assert empty.issue.reason == UnresolvedReason.EMPTY_TOKEN
    assert empty_row.issue.reason == UnresolvedReason.EMPTY_TOKEN


def test_string_kind_requires_user_string_table():
    provider = FakeProvider(user_strings={1: "hello"})

    ok = provider.resolve(request(0x70000001, TokenKind.InlineString))
    wrong_table = provider.resolve(request(0x0A000001, TokenKind.InlineString))
    missing = provider.resolve(request(0x70000002, TokenKind.InlineString))

    assert ok.resolved and ok.value == "hello"
    assert wrong_table.issue.reason == UnresolvedReason.KIND_MISMATCH
    assert missing.issue.reason == UnresolvedReason.MISSING_USER_STRING


def test_local_var_signature_uses_standalone_sig_table():
    provider = FakeProvider(tables={MetadataTable.StandAloneSig: ["locals"]})

    result = provider.resolve(request(0x11000001, TokenKind.LocalVarSig, 0x0))

    assert result.resolved and result.value == "locals"
    assert result.kind is TokenKind.LocalVarSig
    assert result.offset == 0x0


def test_cache_hit_keeps_per_use_offset():
    provider = FakeProvider(tables={MetadataTable.MethodDef: ["method"]})

    first = provider.resolve(request(0x06000001, TokenKind.InlineTok, 0x10))
    second = provider.resolve(request(0x06000001, TokenKind.InlineTok, 0x40))

    assert first.value == second.value == "method"
    assert first.offset == 0x10
    assert second.offset == 0x40
    assert len(provider.lookups) == 1


def test_optional_adapter_is_not_imported_by_core():
    code = (
        "import sys, dncil.cil.body.reader, dncil.clr.token, dncil.cil.instruction;"
        "assert 'dncil.dnfile.adapter' not in sys.modules;"
        "assert 'dnfile' not in sys.modules"
    )
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def test_instruction_requests_capture_kind_and_location():
    import binascii

    from dncil.cil.body import CilMethodBody
    from dncil.cil.body.reader import CilMethodBodyReaderBytes

    body = CilMethodBody(CilMethodBodyReaderBytes(binascii.unhexlify("1E02280C00000A2A")))
    requests = body.get_token_requests()

    assert len(requests) == 1
    assert requests[0].kind is TokenKind.InlineMethod
    assert requests[0].offset == body.instructions[1].offset
    assert requests[0].token.value == 0x0A00000C


def test_method_body_requests_include_local_signature():
    from tests.managed_pe import build_managed_pe

    dnfile = pytest.importorskip("dnfile")
    from dncil.dnfile import read_method_body

    pe = dnfile.dnPE(data=build_managed_pe())
    row = pe.net.mdtables.MethodDef.rows[0]
    body = read_method_body(pe, row)
    requests = body.get_token_requests()

    kinds = [request.kind for request in requests]
    assert kinds.count(TokenKind.InlineTok) == 2
    assert TokenKind.LocalVarSig in kinds
    local = [request for request in requests if request.kind is TokenKind.LocalVarSig][0]
    assert local.offset == body.offset
    assert local.token.value == body.local_var_sig_tok.value


def test_dnfile_adapter_resolves_interleaved_tokens():
    from tests.managed_pe import build_managed_pe

    dnfile = pytest.importorskip("dnfile")
    from dncil.dnfile import DnfileTokenProvider, read_method_body, resolve_method_body

    pe = dnfile.dnPE(data=build_managed_pe())
    row = pe.net.mdtables.MethodDef.rows[0]
    body = read_method_body(pe, row)
    provider = DnfileTokenProvider(pe)

    results = resolve_method_body(provider, body)

    assert all(result.resolved for result in results)
    by_kind = {}
    for result in results:
        by_kind.setdefault(result.kind, []).append(result)

    assert by_kind[TokenKind.InlineString][0].value == "hi"
    assert by_kind[TokenKind.InlineMethod][0].value.Name == ".ctor"
    assert by_kind[TokenKind.InlineMethod][1].value.Class.row.TypeName.value == "Object"
    assert by_kind[TokenKind.InlineTok][0].value.Signature is not None
    assert by_kind[TokenKind.InlineType][0].value.Signature is not None
    assert by_kind[TokenKind.InlineField][0].value.Name == "Field1"

    # the same integer appears once as InlineTok and once as InlineType
    shared = [
        result
        for result in results
        if result.token.value == 0x1B000001 and result.kind in (TokenKind.InlineTok, TokenKind.InlineType)
    ]
    assert len(shared) == 2
    assert (TokenKind.InlineTok, 0x1B000001) in provider.cache_keys()
    assert (TokenKind.InlineType, 0x1B000001) in provider.cache_keys()


def test_dnfile_adapter_reports_unknown_reference():
    from tests.managed_pe import build_managed_pe

    dnfile = pytest.importorskip("dnfile")
    from dncil.dnfile import DnfileTokenProvider

    pe = dnfile.dnPE(data=build_managed_pe())
    provider = DnfileTokenProvider(pe)

    result = provider.resolve(request(0x0A0000FF, TokenKind.InlineMethod))

    assert not result.resolved
    assert result.issue.reason == UnresolvedReason.MISSING_ROW
    assert result.issue.table == MetadataTable.MemberRef


def test_dnfile_adapter_rejects_token_in_wrong_context():
    from tests.managed_pe import build_managed_pe

    dnfile = pytest.importorskip("dnfile")
    from dncil.dnfile import DnfileTokenProvider

    pe = dnfile.dnPE(data=build_managed_pe())
    provider = DnfileTokenProvider(pe)

    result = provider.resolve(request(0x2B000001, TokenKind.InlineField))

    assert not result.resolved
    assert result.issue.reason == UnresolvedReason.KIND_MISMATCH
    assert result.issue.table == MetadataTable.MethodSpec


def test_report_separates_success_from_unknown():
    provider = FakeProvider(
        tables={MetadataTable.MethodDef: ["method"]},
        user_strings={1: "hello"},
    )
    requests = [
        request(0x06000001, TokenKind.InlineTok, 0x10),
        request(0x0A000001, TokenKind.InlineMethod, 0x20),
        request(0x70000001, TokenKind.InlineString, 0x30),
    ]

    report = provider.report(requests)

    assert not report.complete
    assert [result.offset for result in report.resolved] == [0x10, 0x30]
    assert [result.offset for result in report.unresolved] == [0x20]
    assert report.unresolved[0].issue.reason == UnresolvedReason.MISSING_TABLE
    lines = report.describe()
    assert "unresolved [MISSING_TABLE]" in lines[1]


def test_user_string_token_cannot_be_used_as_metadata_kind():
    provider = FakeProvider(tables={MetadataTable.MethodDef: ["method"]})

    result = provider.resolve(request(0x70000001, TokenKind.InlineTok))

    assert not result.resolved
    assert result.issue.reason == UnresolvedReason.KIND_MISMATCH


def test_operand_type_mapping_includes_all_reference_kinds():
    from dncil.cil.enums import OperandType

    assert TokenKind.from_operand_type(OperandType.InlineTok) is TokenKind.InlineTok
    assert TokenKind.from_operand_type(OperandType.InlineMethod) is TokenKind.InlineMethod
    assert TokenKind.from_operand_type(OperandType.InlineField) is TokenKind.InlineField
    assert TokenKind.from_operand_type(OperandType.InlineType) is TokenKind.InlineType
    assert TokenKind.from_operand_type(OperandType.InlineString) is TokenKind.InlineString
    assert TokenKind.from_operand_type(OperandType.InlineSig) is TokenKind.InlineSig
    assert TokenKind.from_operand_type(OperandType.InlineI) is None
    assert TokenKind.from_operand_type(OperandType.InlineVar) is None
