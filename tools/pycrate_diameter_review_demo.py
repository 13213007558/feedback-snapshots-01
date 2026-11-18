#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Description : offline demonstration of the Diameter comprehension review
# *
# * Builds three Diameter authentication messages locally:
# *   1. same AVP code reused by different vendors,
# *   2. unknown optional AVP (M-bit clear),
# *   3. unknown mandatory AVP (M-bit set), including a nested one inside a
# *      grouped AVP,
# * then prints the comprehension verdict, the precise nesting path and the
# * disposition reason of every AVP.  No AAA server is ever contacted: the
# * checker only walks message bytes in memory and retains them verbatim.
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
# * You should have received a copy of the GNU Lesser General Public License
# * along with this library; if not, write to the Free Software Foundation, Inc.,
# * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
# *--------------------------------------------------------
# * File Name : tools/pycrate_diameter_review_demo.py
# *--------------------------------------------------------
#*/

"""Offline Diameter AVP comprehension review demonstration."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pycrate_diameter.DiameterReview import (
    VENDOR_IETF,
    VENDOR_3GPP,
    Disposition,
    Verdict,
    CapRegistry,
    review_message,
    build_avp,
    build_message,
    )

# deliberately tiny, fully controlled capability set for the demo node
CODE_ORIGIN_REALM = 264         # RFC 6733 Origin-Realm, base protocol
CODE_PROXY_INFO = 284           # RFC 6733 Proxy-Info, grouped
CODE_PROXY_HOST = 280           # RFC 6733 Proxy-Host inside Proxy-Info
CODE_COLLIDING = 264            # same number as Origin-Realm, other vendors
CODE_UNKNOWN_OPTIONAL = 999010
CODE_UNKNOWN_MANDATORY = 999011
CODE_UNKNOWN_NESTED = 999020
VENDOR_DEMO = 424242

VERDICT_CN = {
    Verdict.FULLY_UNDERSTOOD: '完整理解',
    Verdict.PARTIALLY_UNDERSTOOD: '部分理解（跳过了未知可选 AVP）',
    Verdict.NOT_UNDERSTOOD: '未理解（存在未知必需 AVP 或结构错误）',
    }

DISPOSITION_CN = {
    Disposition.KNOWN: '已理解',
    Disposition.UNKNOWN_OPTIONAL: '未知可选→按 RFC 6733 4.1.1 忽略',
    Disposition.UNKNOWN_MANDATORY: '未知必需→按 RFC 6733 6.2 拒绝(5010)',
    }


def demo_registry():
    registry = CapRegistry()
    registry.register(CODE_ORIGIN_REALM, VENDOR_IETF, 'Origin-Realm')
    registry.register(CODE_PROXY_INFO, VENDOR_IETF,
                      'Proxy-Info', grouped=True)
    registry.register(CODE_PROXY_HOST, VENDOR_IETF, 'Proxy-Host')
    return registry


def print_observation(obs, indent=2):
    pad = ' ' * indent
    print('%s路径: %s' % (pad, obs.path_str))
    print('%s身份: %s  名称: %s'
          % (pad, obs.identity, obs.name or '<无本地能力>'))
    print('%s标志: V=%d M=%d P=%d | 声明长度=%d 数据=%dB 填充=%dB '
          '线长=%dB'
          % (pad, obs.flag_v, obs.flag_m, obs.flag_p,
             obs.declared_length, obs.data_length, obs.padding_length,
             obs.wire_length))
    print('%s处置: %s' % (pad, DISPOSITION_CN[obs.disposition]))
    print('%s原因: %s' % (pad, obs.reason))
    for nested in obs.nested:
        print_observation(nested, indent + 4)


def report(title, msg, registry):
    print('=' * 78)
    print(title)
    print('-' * 78)
    print('原始字节 (hex, %d 字节, 检查器不做任何改写):' % len(msg))
    print('  ' + msg.hex())
    result = review_message(msg, registry=registry)
    print('命令码: %d  应用ID: %d  R/P/E/T: %d/%d/%d/%d'
          % (result.header['cmd'], result.header['app_id'],
             result.header['R'], result.header['P'],
             result.header['E'], result.header['T']))
    print('pycrate 结构解析: %s' % result.pycrate_structural_decode)
    print('消息体按长度字段完整遍历: %s' % result.body_consumed)
    print('最终判定: %s (%s)'
          % (result.verdict, VERDICT_CN[result.verdict]))
    print('AVP 逐条处置（含嵌套路径）:')
    for obs in result.observations:
        print_observation(obs)
    if result.duplicates:
        print('重复 AVP:')
        for dup in result.duplicates:
            print('  - %s 出现 %d 次（位于 %s，各实例均保留）'
                  % (dup['identity'], dup['count'], dup['path']))
    if result.structural_errors:
        print('结构问题:')
        for err in result.structural_errors:
            print('  - [%s] %s @ %s'
                  % (err['code'], err['detail'], err['path']))
    # prove byte retention (top-level AVP raw spans already include nested
    # AVP bytes, since grouped AVPs are retained as one contiguous span)
    rebuilt_body = b''.join(obs.raw for obs in result.observations)
    assert rebuilt_body == msg[20:], 'retained AVP bytes diverge from body'
    assert result.original == msg, 'retained message bytes diverge'
    print('字节保留校验: 原始消息一致，各 AVP raw 可重建消息体')
    print()
    return result


def main():
    registry = demo_registry()

    # message 1: same numeric code, three vendor namespaces
    msg_vendor = build_message(271, [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_COLLIDING, b'\x00\x01',
                  vendor_id=VENDOR_3GPP, m=1),
        build_avp(CODE_COLLIDING, b'\x00\x02',
                  vendor_id=VENDOR_DEMO, m=0),
        ])
    r1 = report(
        '消息 1：相同代码 264，不同 Vendor-ID'
        '（基础 / 3GPP(10415) / 演示厂商标识）',
        msg_vendor, registry)
    assert r1.verdict == Verdict.NOT_UNDERSTOOD

    # message 2: unknown optional AVP only
    msg_optional = build_message(271, [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_UNKNOWN_OPTIONAL, b'optional-payload', m=0),
        ])
    r2 = report('消息 2：未知可选 AVP（M=0）', msg_optional, registry)
    assert r2.verdict == Verdict.PARTIALLY_UNDERSTOOD

    # message 3: unknown mandatory AVPs, one nested inside Proxy-Info
    grouped_body = b''.join([
        build_avp(CODE_PROXY_HOST, b'proxy.example', m=1),
        build_avp(CODE_UNKNOWN_NESTED, b'nested-mandatory', m=1),
        ])
    msg_mandatory = build_message(271, [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_PROXY_INFO, grouped_body, m=1),
        build_avp(CODE_UNKNOWN_MANDATORY, b'top-mandatory', m=1),
        ])
    r3 = report(
        '消息 3：未知必需 AVP（M=1），含分组 AVP Proxy-Info 内的嵌套实例',
        msg_mandatory, registry)
    assert r3.verdict == Verdict.NOT_UNDERSTOOD
    nested = [obs for obs in r3.unknown_mandatory
              if obs.identity.code == CODE_UNKNOWN_NESTED][0]
    assert nested.path_str.startswith('AVP(code=284')

    print('全部消息均在本地构造与检查，未发起任何网络连接。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
