#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
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
# * File Name : pycrate_m3ua_audit.py
# * Created : 2026-11-19
# * Authors : pycrate contributors
# *--------------------------------------------------------
#*/

import sys
import json
import argparse

from pycrate_mobile.M3UAAudit import (
    audit_m3ua_transcript,
    format_report,
    parse_hex_transcript,
    )


def main():
    
    parser = argparse.ArgumentParser(
        description='audit an offline M3UA transcript: correlate DATA '
                    'messages with the ASP/AS state actually observed before '
                    'them, without assuming any global network state')
    parser.add_argument('transcript', type=str,
                        help='transcript file, or "-" to read standard input; '
                             'one message per line as "SRC -> DST: HEX" or '
                             'just "HEX"')
    parser.add_argument('-j', '--json', action='store_true', default=False,
                        help='print the full report as JSON')
    parser.add_argument('-s', '--strict-endpoints', action='store_true',
                        default=False,
                        help='fail when a message lacks source or destination, '
                             'since endpoints cannot then be correlated')
    args = parser.parse_args()
    
    if args.transcript == '-':
        text = sys.stdin.read()
    else:
        try:
            fd = open(args.transcript, 'r')
        except Exception as err:
            print('unable to open transcript %s: %s'
                  % (args.transcript, err), file=sys.stderr)
            return 1
        try:
            text = fd.read()
        finally:
            fd.close()
    
    try:
        entries = parse_hex_transcript(text)
    except ValueError as err:
        print('invalid transcript: %s' % err, file=sys.stderr)
        return 1
    
    if args.strict_endpoints:
        missing = [e['line'] for e in entries
                   if e.get('source') is None or e.get('destination') is None]
        if missing:
            print('transcript lines without endpoints: %s'
                  % ', '.join(map(str, missing)), file=sys.stderr)
            return 1
    
    report = audit_m3ua_transcript(entries)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report))
    # exit status reflects only what the capture proves
    return 2 if report['summary']['violations'] else 0


if __name__ == '__main__':
    sys.exit(main())
