"""Demonstrate physical, explicit-physical and logical-view registry queries.

Usage::

    python examples/query_views.py HIVE [PATH] [--policy POLICY.json]

The default path targets a key that commonly exists both natively and below
``Wow6432Node``.  Default behaviour is a physical lookup: no path is rewritten.
"""

from __future__ import annotations

import argparse
import json

from dissect.regf import RegistryHive
from dissect.regf.views import (
    ControlSetResolution,
    LookupContext,
    LookupResult,
    RedirectionPolicy,
    ViewKind,
    resolve_current_control_set,
    resolve_physical,
    resolve_view,
)

DEFAULT_PATH = r"Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}"


def show_control_set(result: ControlSetResolution) -> None:
    print("\n== current control set ==")
    print(f"status    : {result.status.value}")
    print(f"control   : {result.control_set}")
    for note in result.notes:
        print(f"note      : {note}")


def show(label: str, result: LookupResult) -> None:
    print(f"\n== {label} ==")
    print(f"requested : {result.requested_path}")
    print(f"mode/view : {result.mode.value}/{result.view.value}")
    print(f"status    : {result.status.value}")
    print(f"physical  : {result.physical_path}")
    if result.key is not None:
        print(f"key.path  : {result.key.path}")
    if result.rules_applied:
        print(f"rules     : {', '.join(result.rules_applied)}")
    if result.required_context:
        print(f"needs     : {', '.join(result.required_context)}")
    for alternative in result.alternatives:
        print(f"alternative: {alternative.view} -> {alternative.physical_path}")
    for note in result.notes:
        print(f"note      : {note}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("hive")
    parser.add_argument("path", nargs="?", default=DEFAULT_PATH)
    parser.add_argument("--policy", help="JSON redirection policy for logical views")
    parser.add_argument("--view", choices=[view.value for view in ViewKind], default=ViewKind.WOW32.value)
    parser.add_argument("--hive-role", default="SOFTWARE")
    parser.add_argument("--os-arch")
    parser.add_argument("--process-bits", type=int)
    parser.add_argument("--os-version", help="major.minor")
    args = parser.parse_args()

    with open(args.hive, "rb") as fh:
        hive = RegistryHive(fh)

        print(f"hive filename in base block: {hive.filename!r} (metadata, not proof of role)")
        print(f"root subkeys: {[key.name for key in hive.root().subkeys()]}")
        show("physical (default)", resolve_physical(hive, args.path))
        physical_path = r"Software\Wow6432Node\Classes\CLSID\{11111111-2222-3333-4444-555555555555}"
        show(f"explicit physical path: {physical_path}", resolve_physical(hive, physical_path))
        show_control_set(resolve_current_control_set(hive))

        if args.policy:
            with open(args.policy, encoding="utf-8") as policy_file:
                raw = json.load(policy_file)
            context = LookupContext(
                hive_role=args.hive_role,
                os_arch=args.os_arch,
                process_bits=args.process_bits,
                os_version=tuple(int(part) for part in args.os_version.split(".")) if args.os_version else None,
                source=f"--policy {args.policy}",
            )
            show(f"logical view {args.view}", resolve_view(
                hive, args.path, view=args.view, policy=RedirectionPolicy.from_dict(raw), context=context
            ))


if __name__ == "__main__":
    main()
