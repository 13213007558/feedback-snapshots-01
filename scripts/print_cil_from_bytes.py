# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import json
import argparse

from dncil.cil.body import reader
from dncil.cil.error import MethodBodyFormatError


def print_report(body) -> None:
    """print an explicit statement about how much of the method was confirmed"""
    report = body.get_parse_report()
    if report["complete"]:
        print(
            "method body complete: %d bytes, %d instructions"
            % (report["acquired_size"], report["instruction_count"])
        )
        return

    print(
        "method body INCOMPLETE: confirmed through offset 0x%X, %d instructions"
        % (report["confirmed_end"], report["instruction_count"])
    )
    for issue in report["issues"]:
        print(
            "  %s: %s @ offset 0x%X (confirmed prefix ends at 0x%X, unconfirmed 0x%X..0x%X)"
            % (
                issue["kind"],
                issue["reason"],
                issue["error_offset"],
                issue["confirmed_end"],
                issue["unconfirmed_start"],
                issue["unconfirmed_end"],
            )
        )


def main(args):
    with open(args.path, "rb") as f_in:
        dn = f_in.read()

    try:
        dn_body = reader.read_method_body_from_bytes(dn, partial=args.partial)
    except MethodBodyFormatError as e:
        print(e)
        return 1

    for insn in dn_body.instructions:
        print(insn)

    print_report(dn_body)

    if args.json:
        print(json.dumps(dn_body.get_parse_report(), indent=2))

    return 0 if dn_body.is_complete or args.partial else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Print IL from the raw bytes of a managed method")
    parser.add_argument("path", type=str, help="Full path to file containing raw bytes of managed method")
    parser.add_argument(
        "--partial",
        action="store_true",
        help="keep the confirmed instruction prefix when the method body is truncated",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON parse report")

    raise SystemExit(main(parser.parse_args()))
