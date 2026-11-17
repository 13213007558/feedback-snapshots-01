# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import abc
import enum
from typing import Dict, List, Optional, Sequence
from dataclasses import dataclass

from dncil.clr.token import Token


class MetadataError(Exception):
    """raised when metadata cannot answer a review question.

    the reviewer treats this as unresolved rather than as evidence that the
    target is safe.
    """


class ReferenceKind(enum.Enum):
    """how a call operand names its target."""

    METHOD_DEF = "MethodDef"
    MEMBER_REF = "MemberRef"
    METHOD_SPEC = "MethodSpec"


@dataclass(frozen=True)
class MethodReference:
    """a method operand resolved against this assembly's metadata.

    ``token`` is the raw operand token. ``module`` is set for MemberRef rows
    whose parent is a ModuleRef, which is how P/Invoke declarations are
    normally referenced. ``generic`` marks MethodSpec instantiation, whose
    concrete target cannot be proven statically without type-flow analysis.
    """

    token: Token
    kind: ReferenceKind
    name: str
    declaring_type: Optional[str] = None
    module: Optional[str] = None
    method_def_token: Optional[Token] = None
    generic: bool = False
    has_generic_params: bool = False

    @property
    def display(self) -> str:
        owner = self.declaring_type or self.module or "<unknown>"
        return f"{owner}::{self.name}"


@dataclass(frozen=True)
class MethodRecord:
    """a MethodDef row that the reviewer may parse."""

    token: Token
    name: str
    declaring_type: str
    rva: int
    has_body: bool
    is_pinvoke: bool
    is_virtual: bool
    is_abstract: bool
    is_generic: bool
    pinvoke_module: Optional[str] = None
    pinvoke_name: Optional[str] = None

    @property
    def display(self) -> str:
        return f"{self.declaring_type}::{self.name}"


class MetadataView(abc.ABC):
    """read-only metadata interface consumed by the reviewer.

    implement this over a PE parser (see ``dncil.analysis.dnfile_adapter``) or
    over a synthetic fixture. it intentionally exposes no loader API.
    """

    @abc.abstractmethod
    def methods(self) -> Sequence[MethodRecord]:
        """return every MethodDef row in the assembly."""

    @abc.abstractmethod
    def method_body(self, method: MethodRecord) -> bytes:
        """return the raw method body bytes for ``method``.

        may raise ``MetadataError`` when there is no readable body.
        """

    @abc.abstractmethod
    def resolve(self, token: Token) -> MethodReference:
        """resolve a method token without following the target.

        raises ``MetadataError`` when the token is malformed or cannot be
        described. the reviewer records that as an unresolved call site.
        """

    def entry_point(self) -> Optional[MethodRecord]:
        """return the assembly entry point, if the metadata exposes one."""
        return None


def token_for(table: int, rid: int) -> Token:
    """build a metadata token from table number and 1-based row id."""
    return Token((table << Token.TABLE_SHIFT) | rid)


def method_def_token(rid: int) -> Token:
    return token_for(0x06, rid)


def method_ref_token(rid: int) -> Token:
    return token_for(0x0A, rid)


def method_spec_token(rid: int) -> Token:
    return token_for(0x2B, rid)


class SyntheticMetadata(MetadataView):
    """in-memory metadata view used by tests and by callers that only have IL.

    rows are appended in order; token RIDs are 1-based and match metadata
    numbering. tokens that were not registered resolve to ``MetadataError``
    rather than to a guessed target.
    """

    def __init__(self) -> None:
        self._methods: List[MethodRecord] = []
        self._bodies: Dict[int, bytes] = {}
        self._member_refs: Dict[int, MethodReference] = {}
        self._method_specs: Dict[int, MethodReference] = {}
        self._entry: Optional[MethodRecord] = None

    def add_method(
        self,
        name: str,
        declaring_type: str,
        body: Optional[bytes],
        *,
        pinvoke_module: Optional[str] = None,
        pinvoke_name: Optional[str] = None,
        virtual: bool = False,
        abstract: bool = False,
        generic: bool = False,
    ) -> MethodRecord:
        rid = len(self._methods) + 1
        record = MethodRecord(
            token=method_def_token(rid),
            name=name,
            declaring_type=declaring_type,
            rva=0,
            has_body=body is not None,
            is_pinvoke=pinvoke_module is not None,
            is_virtual=virtual,
            is_abstract=abstract,
            is_generic=generic,
            pinvoke_module=pinvoke_module,
            pinvoke_name=pinvoke_name,
        )
        self._methods.append(record)
        if body is not None:
            self._bodies[rid] = body
        return record

    def add_module_ref(self, name: str) -> str:
        """register a native module name; returns the name for use in refs."""
        return name

    def add_member_ref(
        self,
        name: str,
        declaring_type: Optional[str],
        *,
        module: Optional[str] = None,
        method_def: Optional[MethodRecord] = None,
        generic: bool = False,
    ) -> MethodReference:
        rid = len(self._member_refs) + 1
        reference = MethodReference(
            token=method_ref_token(rid),
            kind=ReferenceKind.MEMBER_REF,
            name=name,
            declaring_type=declaring_type if module is None else None,
            module=module,
            method_def_token=method_def.token if method_def else None,
            generic=generic,
        )
        self._member_refs[rid] = reference
        return reference

    def add_method_spec(self, name: str, declaring_type: str) -> MethodReference:
        rid = len(self._method_specs) + 1
        reference = MethodReference(
            token=method_spec_token(rid),
            kind=ReferenceKind.METHOD_SPEC,
            name=name,
            declaring_type=declaring_type,
            generic=True,
        )
        self._method_specs[rid] = reference
        return reference

    def set_entry_point(self, method: MethodRecord) -> None:
        self._entry = method

    def methods(self) -> Sequence[MethodRecord]:
        return list(self._methods)

    def method_body(self, method: MethodRecord) -> bytes:
        rid = method.token.rid
        try:
            return self._bodies[rid]
        except KeyError:
            raise MetadataError(f"no method body for {method.display}")

    def resolve(self, token: Token) -> MethodReference:
        if token.table == 0x06:
            for method in self._methods:
                if method.token.rid == token.rid:
                    return MethodReference(
                        token=token,
                        kind=ReferenceKind.METHOD_DEF,
                        name=method.name,
                        declaring_type=method.declaring_type,
                        method_def_token=method.token,
                        generic=method.is_generic,
                    )
            raise MetadataError(f"unresolved MethodDef token 0x{token.value:08X}")

        if token.table == 0x0A:
            try:
                return self._member_refs[token.rid]
            except KeyError:
                raise MetadataError(f"unresolved MemberRef token 0x{token.value:08X}")

        if token.table == 0x2B:
            try:
                reference = self._method_specs[token.rid]
            except KeyError:
                raise MetadataError(f"unresolved MethodSpec token 0x{token.value:08X}")
            return MethodReference(
                token=reference.token,
                kind=reference.kind,
                name=reference.name,
                declaring_type=reference.declaring_type,
                generic=True,
            )

        raise MetadataError(f"token 0x{token.value:08X} is not a method token")

    def entry_point(self) -> Optional[MethodRecord]:
        return self._entry
