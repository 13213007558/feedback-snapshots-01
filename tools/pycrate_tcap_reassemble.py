#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.8
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_tcap_reassemble.py
# * Created : 2026-11-19
# *--------------------------------------------------------
#*/

"""Reassemble offline TCAP dialogues from a capture.

Inputs:

* a scenario JSON file with ``{"src", "dst", "timestamp", "hex"}`` entries
  (or a bare list of such objects);
* a tshark EK JSON file produced with ``-j tcap``; endpoint labels are taken
  from the IPv4 header when present, otherwise from SCCP/MPLS where possible,
  and frames without a known pair are skipped with a warning;
* ``--demo`` to run the built-in scenario, which reproduces the
  single-ID-dictionary merging bug and shows the corrected result.

Output is a human-readable report plus optional JSON.  The report always shows
the association evidence and the unresolved messages, and contrasts the result
with the naive "one ID equals one dialogue" grouping.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pycrate_mobile.TCAPReassembly import (
    DecodeError,
    Reassembler,
    demo_scenario,
    decode_tcap_message,
    load_scenario,
    single_id_groups,
    tid_text,
)


def _ip_pair(raw):
    """Return (src, dst) IPv4 addresses from a hex IPv4 header, or None."""
    try:
        buf = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(buf) < 20:
        return None
    ihl = (buf[0] & 0x0f) * 4
    if ihl < 20 or len(buf) < 20:
        return None
    src = '.'.join(str(b) for b in buf[12:16])
    dst = '.'.join(str(b) for b in buf[16:20])
    return src, dst


def _load_ek(path):
    """Load a tshark EK JSON capture into TcapMessage objects."""
    messages = []
    skipped = []
    with open(path) as fd:
        for lineno, line in enumerate(fd, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            layers = record.get('layers')
            if not isinstance(layers, dict) or 'tcap_raw' not in layers:
                continue
            pair = _ip_pair(layers.get('ip_raw', ''))
            if pair is None:
                skipped.append((lineno, 'no IPv4 header for endpoint pair'))
                continue
            try:
                msg = decode_tcap_message(
                    layers['tcap_raw'], index=len(messages),
                    src=pair[0], dst=pair[1],
                    timestamp=record.get('timestamp'))
            except DecodeError as err:
                skipped.append((lineno, str(err)))
                continue
            messages.append(msg)
    return messages, skipped


def _looks_like_ek(path):
    """Return True if the file looks like tshark EK JSON (one object per line)."""
    with open(path) as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                # could be a pretty-printed scenario; let the scenario loader
                # report the exact problem
                return False
            if isinstance(record, dict) and 'layers' in record:
                return True
            if isinstance(record, dict) and ('messages' in record
                                             or 'scenario' in record
                                             or 'hex' in record):
                return False
            # metadata records such as {"index": {...}} are skipped
    return False


def _load_scenario(path):
    with open(path) as fd:
        data = json.load(fd)
    if isinstance(data, dict):
        data = data.get('messages', data.get('scenario', []))
    return load_scenario(data)


def _format_evidence(evidence):
    return '; '.join('%s (%s)' % (item['code'], item['detail'])
                     for item in evidence)


def render_text(result):
    """Render a human-readable reassembly report."""
    lines = []
    lines.append('== Scopes (transaction IDs are scoped by endpoint pair) ==')
    for scope in result.scopes:
        lines.append('  %-40s messages=%d dialogues=%s'
                     % (' <-> '.join(scope['endpoints']), scope['messages'],
                        ', '.join(scope['dialogues']) or '-'))
    lines.append('')
    lines.append('== Dialogues ==')
    for dia in result.dialogues:
        start, stop = dia.interval()
        lines.append('%s  %s <-> %s' % (dia.dialogue_id,
                                        dia.endpoints[0], dia.endpoints[1]))
        lines.append('  initiator=%s responder=%s state=%s%s confidence=%s'
                     % (dia.initiator or '?', dia.responder or '?',
                        dia.state, ' (unterminated)' if dia.unterminated else '',
                        dia.confidence))
        lines.append('  owned IDs: %s'
                     % (', '.join('%s=%s' % (ep, tid_text(tid))
                                  for ep, tid in sorted(dia.owned.items()))
                        or '-'))
        lines.append('  observation interval: %s .. %s' % (start, stop))
        if dia.abort_cause:
            lines.append('  abort cause: %s' % json.dumps(dia.abort_cause))
        if dia.reused_with:
            lines.append('  ID reused with: %s' % ', '.join(dia.reused_with))
        if dia.uncertainty:
            lines.append('  uncertainty: %s' % '; '.join(dia.uncertainty))
        for msg in dia.messages:
            lines.append('    #%-3d %-10s %-15s -> %-15s otid=%-10s dtid=%-10s'
                         ' link=%s'
                         % (msg.index, msg.kind, msg.src, msg.dst,
                            tid_text(msg.otid) or '-', tid_text(msg.dtid) or '-',
                            msg.link_strength))
            lines.append('          evidence: %s' % _format_evidence(
                [e.to_dict() for e in msg.link_evidence]))
        for msg in dia.late_messages:
            lines.append('    #%-3d %-10s %-15s -> %-15s LATE after %s'
                         % (msg.index, msg.kind, msg.src, msg.dst,
                            dia.end_reason))
            lines.append('          evidence: %s' % _format_evidence(
                [e.to_dict() for e in msg.link_evidence]))
        lines.append('')
    lines.append('== Unresolved messages ==')
    if not result.unresolved:
        lines.append('  none')
    for entry in result.unresolved:
        msg = entry['message']
        lines.append('  #%d %s %s -> %s: %s'
                     % (msg['index'], msg['kind'], msg['src'], msg['dst'],
                        entry['reason']))
        lines.append('    %s' % entry['detail'])
        if entry['candidates']:
            lines.append('    candidates: %s' % ', '.join(entry['candidates']))
    lines.append('')
    lines.append('== Naive single-ID dictionary (why it merges dialogues) ==')
    for group in single_id_groups(result.messages):
        lines.append('  ID %s: messages %s'
                     % (group['id'],
                        ', '.join('#%d' % i for i in group['messages'])))
        lines.append('    actually belongs to dialogues: %s'
                     % (', '.join(group['dialogues']) or 'none'))
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Reassemble offline TCAP dialogues from a capture')
    parser.add_argument('-i', '--input', help='scenario JSON or tshark EK JSON')
    parser.add_argument('-d', '--demo', action='store_true',
                        help='run the built-in demonstration scenario')
    parser.add_argument('-j', '--json', help='write the full result as JSON')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='also print per-message JSON evidence')
    args = parser.parse_args()

    if args.demo:
        messages = load_scenario(demo_scenario())
        skipped = []
    elif args.input:
        try:
            if _looks_like_ek(args.input):
                messages, skipped = _load_ek(args.input)
            else:
                messages, skipped = _load_scenario(args.input), []
        except (IOError, OSError, ValueError, KeyError) as err:
            print('%s: cannot read %s: %s' % (sys.argv[0], args.input, err))
            return 1
    else:
        print('%s: missing -i/--input or -d/--demo' % sys.argv[0])
        return 1

    result = Reassembler().process(messages)
    print(render_text(result))
    if skipped:
        print('\n== Skipped frames ==')
        for lineno, reason in skipped:
            print('  line %d: %s' % (lineno, reason))
    if args.json:
        with open(args.json, 'w') as fd:
            json.dump(result.to_dict(), fd, indent=2, ensure_ascii=False)
        print('\nJSON written to %s' % args.json)
    if args.verbose:
        print('\n== Message detail ==')
        for msg in messages:
            print(json.dumps(msg.to_dict(), indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
