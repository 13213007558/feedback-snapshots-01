# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import argparse
import json
import os
import sys

from ndn.app_support.light_versec import (
    DEFAULT_USER_FNS,
    DiffBounds,
    EQ_CONTRACT,
    EQ_TYPE_CONTRACT,
    LvsDiffError,
    compare_lvs_models,
)


EXIT_NO_NEW = 0
EXIT_NEW = 1
EXIT_REMOVED = 2
EXIT_INCONCLUSIVE = 3
EXIT_ERROR = 4


def add_parser(subparsers):
    parser = subparsers.add_parser(
        'Diff-Lvs', aliases=['diff-lvs'],
        help='compare two LVS models inside a finite scope',
    )
    parser.add_argument('old', metavar='OLD', help='old LVS model file')
    parser.add_argument('new', metavar='NEW', help='new LVS model file')
    parser.add_argument(
        '--component', action='append', default=[], metavar='COMPONENT',
        help='component candidate for pattern variables (repeatable)',
    )
    parser.add_argument(
        '--max-name-len', type=int, default=6, metavar='N',
        help='maximum components in a candidate name (default: 6)',
    )
    parser.add_argument(
        '--max-cert-depth', type=int, default=3, metavar='N',
        help='maximum certificate links to a trust anchor (default: 3)',
    )
    parser.add_argument(
        '--max-evaluations', type=int, default=200000, metavar='N',
        help='abstract evaluation budget (default: 200000)',
    )
    parser.add_argument(
        '--max-names', type=int, default=5000, metavar='N',
        help='candidate-name cap per model (default: 5000)',
    )
    parser.add_argument(
        '--max-examples', type=int, default=5, metavar='N',
        help='witness examples retained per direction (default: 5)',
    )
    parser.add_argument(
        '--data-rule', action='append', default=[], metavar='#RULE',
        help='restrict data names to these LVS rules (repeatable)',
    )
    parser.add_argument(
        '--contract', action='append', default=[], choices=['eq', 'eq_type'],
        help='enable a documented built-in user-function contract '
             '(repeatable; also supplies the Checker implementation)',
    )
    parser.add_argument(
        '--anchor', action='append', default=[], metavar='NAME',
        help='restrict usable trust anchors to this name (repeatable); '
             'without it, any name matching a root rule is treated as an anchor',
    )
    parser.add_argument(
        '--json', action='store_true',
        help='write the machine-readable report instead of text',
    )
    parser.set_defaults(executor=execute)


def _read(path: str) -> str:
    if path == '-':
        return sys.stdin.read()
    with open(os.path.expandvars(path), encoding='utf-8') as handle:
        return handle.read()


def execute(args: argparse.Namespace):
    try:
        old_text = _read(args.old)
        new_text = _read(args.new)
    except OSError as exc:
        print(f'Unable to read model: {exc}', file=sys.stderr)
        return EXIT_ERROR

    contracts = []
    checker_fns = {}
    if 'eq' in args.contract:
        contracts.append(EQ_CONTRACT)
        checker_fns['$eq'] = DEFAULT_USER_FNS['$eq']
    if 'eq_type' in args.contract:
        contracts.append(EQ_TYPE_CONTRACT)
        checker_fns['$eq_type'] = DEFAULT_USER_FNS['$eq_type']

    if not args.component:
        print('At least one --component is required', file=sys.stderr)
        return EXIT_ERROR
    try:
        bounds = DiffBounds(
            components=tuple(args.component),
            max_name_len=args.max_name_len,
            max_cert_depth=args.max_cert_depth,
            max_evaluations=args.max_evaluations,
            max_names=args.max_names,
            max_examples=args.max_examples,
            data_rules=tuple(args.data_rule),
        )
        anchor_names = set(args.anchor)

        def check_anchor(name: str) -> bool:
            return not anchor_names or name in anchor_names

        report = compare_lvs_models(
            old_text,
            new_text,
            bounds,
            old_contracts=contracts,
            new_contracts=contracts,
            old_checker_fns=checker_fns,
            new_checker_fns=checker_fns,
            check_trust_anchor=check_anchor if anchor_names else None,
        )
    except (LvsDiffError, ValueError) as exc:
        print(f'Unable to compare models: {exc}', file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write('\n')
    else:
        print(report.format_text())

    if report.outcome == 'NEW_RELATION_FOUND':
        return EXIT_NEW
    if report.outcome == 'REMOVED_RELATION_FOUND':
        return EXIT_REMOVED
    if report.outcome in ('NO_NEW_RELATION_IN_SCOPE', 'NO_NEW_RELATION'):
        return EXIT_NO_NEW
    return EXIT_INCONCLUSIVE
