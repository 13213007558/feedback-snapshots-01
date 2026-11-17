# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import enum
from typing import FrozenSet, Optional


class MetadataTable(enum.IntEnum):
    """ECMA-335 metadata table indexes, see II.22"""

    Module = 0x00
    TypeRef = 0x01
    TypeDef = 0x02
    FieldPtr = 0x03
    Field = 0x04
    MethodPtr = 0x05
    MethodDef = 0x06
    ParamPtr = 0x07
    Param = 0x08
    InterfaceImpl = 0x09
    MemberRef = 0x0A
    Constant = 0x0B
    CustomAttribute = 0x0C
    FieldMarshal = 0x0D
    DeclSecurity = 0x0E
    ClassLayout = 0x0F
    FieldLayout = 0x10
    StandAloneSig = 0x11
    EventMap = 0x12
    EventPtr = 0x13
    Event = 0x14
    PropertyMap = 0x15
    PropertyPtr = 0x16
    Property = 0x17
    MethodSemantics = 0x18
    MethodImpl = 0x19
    ModuleRef = 0x1A
    TypeSpec = 0x1B
    ImplMap = 0x1C
    FieldRva = 0x1D
    EncLog = 0x1E
    EncMap = 0x1F
    Assembly = 0x20
    AssemblyProcessor = 0x21
    AssemblyOS = 0x22
    AssemblyRef = 0x23
    AssemblyRefProcessor = 0x24
    AssemblyRefOS = 0x25
    File = 0x26
    ExportedType = 0x27
    ManifestResource = 0x28
    NestedClass = 0x29
    GenericParam = 0x2A
    MethodSpec = 0x2B
    GenericParamConstraint = 0x2C


# the #US heap is not a metadata table, but its tokens share the same encoding
USER_STRING_TABLE: int = 0x70


class TokenKind(enum.Enum):
    """the use context that constrains how a token may be interpreted"""

    InlineTok = "InlineTok"
    InlineMethod = "InlineMethod"
    InlineField = "InlineField"
    InlineType = "InlineType"
    InlineString = "InlineString"
    InlineSig = "InlineSig"
    LocalVarSig = "LocalVarSig"

    @property
    def expected_tables(self) -> FrozenSet[MetadataTable]:
        """get metadata tables a token of this kind may reference"""
        return _EXPECTED_TABLES[self]

    @property
    def is_user_string(self) -> bool:
        """check if this kind references the user string heap"""
        return self in (TokenKind.InlineString,)

    @classmethod
    def from_operand_type(cls, operand_type: object) -> Optional[TokenKind]:
        """get token kind for a CIL operand type, or None when it carries no token"""
        name: str = getattr(operand_type, "name", str(operand_type))
        return _KINDS_BY_OPERAND_NAME.get(name)


_EXPECTED_TABLES = {
    # ECMA-335 III.1.9: InlineTok may name a type, method, or field
    TokenKind.InlineTok: frozenset(
        {
            MetadataTable.TypeDef,
            MetadataTable.TypeRef,
            MetadataTable.TypeSpec,
            MetadataTable.MethodDef,
            MetadataTable.MethodSpec,
            MetadataTable.MemberRef,
            MetadataTable.Field,
        }
    ),
    # call, callvirt, ldftn, newobj, jmp, ldvirtftn
    TokenKind.InlineMethod: frozenset(
        {
            MetadataTable.MethodDef,
            MetadataTable.MemberRef,
            MetadataTable.MethodSpec,
        }
    ),
    # ldfld, stfld, ldflda, ldsfld, stsfld, ldsflda
    TokenKind.InlineField: frozenset({MetadataTable.Field}),
    # box, unbox, castclass, isinst, newarr, ldobj, stobj, initobj, constrained.
    TokenKind.InlineType: frozenset(
        {
            MetadataTable.TypeDef,
            MetadataTable.TypeRef,
            MetadataTable.TypeSpec,
        }
    ),
    # ldstr references the #US heap, not a metadata table
    TokenKind.InlineString: frozenset(),
    # calli references a StandAloneSig
    TokenKind.InlineSig: frozenset({MetadataTable.StandAloneSig}),
    # the method header's local variable signature
    TokenKind.LocalVarSig: frozenset({MetadataTable.StandAloneSig}),
}

_KINDS_BY_OPERAND_NAME = {
    "InlineTok": TokenKind.InlineTok,
    "InlineMethod": TokenKind.InlineMethod,
    "InlineField": TokenKind.InlineField,
    "InlineType": TokenKind.InlineType,
    "InlineString": TokenKind.InlineString,
    "InlineSig": TokenKind.InlineSig,
}


class Token(object):
    """store managed token"""

    RID_MASK: int = 0x00FFFFFF
    RID_MAX: int = RID_MASK
    TABLE_SHIFT: int = 24

    def __init__(self, value: int):
        self.value: int = value

    @property
    def rid(self) -> int:
        """get token row index"""
        return self.value & Token.RID_MASK

    @property
    def table(self) -> int:
        """get token table index"""
        return self.value >> Token.TABLE_SHIFT

    @property
    def table_name(self) -> str:
        """get token table name, including the non-metadata user string heap"""
        if self.table == USER_STRING_TABLE:
            return "UserString"
        try:
            return MetadataTable(self.table).name
        except ValueError:
            return "Unknown"

    @property
    def is_user_string(self) -> bool:
        """check if token references the #US heap"""
        return self.table == USER_STRING_TABLE

    def __str__(self) -> str:
        return "token(0x%08X)" % self.value

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Token) and self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)


class InvalidToken(Token):
    """store invalid managed token"""

    def __init__(self, value: int):
        super(InvalidToken, self).__init__(value)

    def __str__(self) -> str:
        return "invalid token(0x%08X)" % self.value


class StringToken(Token):
    """store string managed token"""

    def __init__(self, value: int):
        super(StringToken, self).__init__(value)

    def __str__(self) -> str:
        return "string token(0x%08X)" % self.value
