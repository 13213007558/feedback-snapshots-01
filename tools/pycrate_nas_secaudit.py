#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright 2026. pycrate contributors.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details.
# *
# *--------------------------------------------------------
# * File Name : pycrate_nas_secaudit.py
# * Created : 2026-11-19
# * Authors : pycrate contributors
# *--------------------------------------------------------
#*/

"""
Offline audit of a captured 5G NAS security mode negotiation.

Reads a JSON transcript (see pycrate_mobile/NASSecAudit.py for the format),
re-decodes every NAS PDU with pycrate, checks the UE security capability
declaration against the algorithm selected in the Security Mode Command, and
reports which fields are cleartext, which are authenticated and which lack the
evidence needed to be called either.

No network access, no key derivation, no attack: the tool only reads a capture
and states what it does and does not prove.

Exit codes:
    0: audit completed, no warning
    1: audit completed with at least one warning
    2: the transcript could not be read or decoded
"""

import sys
import json
import argparse

from pycrate_mobile.NASSecAudit import audit_file, TranscriptError


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='audit a 5G NAS security mode negotiation transcript')
    ap.add_argument('TRANSCRIPT', help='JSON transcript file')
    ap.add_argument('-j', '--json', action='store_true',
                    help='print the report as JSON instead of text')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='print only the conclusion')
    args = ap.parse_args(argv)
    
    try:
        report = audit_file(args.TRANSCRIPT)
    except TranscriptError as err:
        sys.stderr.write('[!] %s\n' % err)
        return 2
    
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif args.quiet:
        print('%s (confirmed downgrade: %s)'
              % (report.conclusion['status'],
                 'yes' if report.conclusion['confirmed_downgrade'] else 'no'))
    else:
        print(report.render())
    
    return 1 if report.warnings else 0


if __name__ == '__main__':
    sys.exit(main())
