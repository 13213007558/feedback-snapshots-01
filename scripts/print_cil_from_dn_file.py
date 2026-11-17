# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dnfile import dnPE

import argparse

import dnfile

from dncil.cil.error import MethodBodyFormatError
from dncil.clr.evidence import TokenResolution
from dncil.dnfile import DnfileTokenProvider, format_resolved_value, read_method_body


def format_operand(operand: Any) -> str:
    """format an instruction operand without following metadata references"""
    if isinstance(operand, str):
        return f'"{operand}"'
    elif isinstance(operand, int):
        return hex(operand)
    elif isinstance(operand, list):
        return f"[{', '.join(['({:04X})'.format(x) for x in operand])}]"
    elif operand is None:
        return ""

    return str(operand)


def main(args):
    pe: dnPE = dnfile.dnPE(args.path)
    provider: DnfileTokenProvider = DnfileTokenProvider(pe)

    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # skip methods that do not have a method body
            continue

        try:
            body = read_method_body(pe, row)
        except MethodBodyFormatError as e:
            print(e)
            continue

        if not body.instructions:
            continue

        print(f"\nMethod: {row.Name}")
        for insn in body.instructions:
            request = insn.get_token_request()
            resolved: str = ""
            if request is not None:
                result: TokenResolution = provider.resolve(request)
                if result.resolved:
                    resolved = " ; " + format_resolved_value(result.value)
                else:
                    resolved = " ; unresolved(%s)" % result.issue.reason.name

            print(
                "{:04X}".format(insn.offset)
                + "    "
                + f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
                + f"{str(insn.opcode) : <15}"
                + format_operand(insn.operand)
                + resolved
            )

        report = provider.report(body.get_token_requests())
        if report.unresolved:
            print("Unresolved references:")
            for line in report.describe(format_resolved_value):
                if "unresolved" in line:
                    print("    " + line)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Print IL from the managed methods of a .NET binary")
    parser.add_argument("path", type=str, help="Full path to .NET binary")

    main(parser.parse_args())
